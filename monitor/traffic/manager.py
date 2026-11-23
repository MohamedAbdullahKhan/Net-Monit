"""Capture manager: owns the running source (live interface, pcap file, NetFlow/IPFIX collector), the engine, persistence and timers."""
import ipaddress
import os
import struct
import threading
import time

from .. import database as db
from . import netutil as N, store, parser as P
from .blacklist import IpBlacklist
import sys
from .capture_linux import PcapWriter as RawPcapOut, RawLinuxSniffer
from .capture_windows import RawWindowsSniffer, npcap_installed
from .engine import Engine, Resolver, ProgramLookup
from .flows import Collector
from .geo import GeoDb
from .notify import Notifier
from .softfilter import compile_filter, FilterError

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data", "traffic")
PCAP_LIMIT = 500 * 1024 * 1024


def interfaces():
    """Capture-capable interfaces with their addresses. psutil is the base (works on every OS without extra software);
    scapy only adds friendly descriptions, and only where it can run (not on Windows without Npcap)."""
    out, seen, addrs, up = [], set(), {}, {}
    try:
        import psutil, socket
        for name, lst in psutil.net_if_addrs().items():
            for a in lst:
                if a.family in (socket.AF_INET, socket.AF_INET6) and a.address:
                    ip = a.address.split("%")[0]
                    try: ipaddress.ip_address(ip)
                    except ValueError: continue
                    addrs.setdefault(name, []).append({"addr": ip, "netmask": a.netmask, "broadcast": getattr(a, "broadcast", None)})
        try: up = {n: st.isup for n, st in psutil.net_if_stats().items()}
        except Exception: up = {}
    except Exception:
        pass
    desc = {}
    if sys.platform != "win32" or _npcap():
        try:
            from scapy.all import conf
            for i in conf.ifaces.values():
                nm = getattr(i, "name", None)
                if nm: desc[nm] = getattr(i, "description", "") or ""
                if nm and nm not in addrs: addrs[nm] = []
        except Exception:
            pass
    for nm, a in addrs.items():
        out.append({"name": nm, "description": desc.get(nm, ""), "addresses": a, "up": up.get(nm, True)})
    out.sort(key=lambda i: (not i["addresses"], not i["up"], i["name"].lower()))
    return out


def _npcap():
    try:
        from .capture_windows import npcap_installed
        return npcap_installed()
    except Exception:
        return False


def _mine(addresses):
    res = []
    for a in addresses or []:
        try:
            ip = ipaddress.ip_address(a["addr"])
            mask = ipaddress.ip_address(a["netmask"]) if a.get("netmask") and ":" not in str(a["netmask"]) == (ip.version == 4) else None
            if ip.version == 6 and a.get("netmask"):
                try: mask = ipaddress.ip_address(a["netmask"])
                except ValueError: mask = None
            bc = ipaddress.ip_address(a["broadcast"]) if a.get("broadcast") else None
            res.append(N.Addr(ip, mask, bc))
        except Exception:
            continue
    return res


class Manager:
    def __init__(self):
        self.lock = threading.RLock(); self.engine = None; self.sid = None; self.source = None
        self.geo = GeoDb(); self.resolver = None; self.programs = None; self.blacklist = None; self.blacklist_path = ""
        self.threads = []; self.stop_evt = threading.Event(); self.sniffer = None; self.collector = None; self.pcap_writer = None
        self.pcap_path = ""; self.filter_mode = ""; self.error = ""; self.state = "idle"; self.finished_note = ""
        self.sinks = []; self.live_notifications = []; self._geo_loaded = False; self.capture_backend = ""

    # ---------------- configuration ----------------
    def settings(self):
        d = {"country_db": "", "asn_db": "", "blacklist": "", "rdns": True, "retention_days": 30, "autostart": None}
        d.update(store.get_setting("config", {}) or {}); return d

    def save_settings(self, new):
        cur = self.settings()
        for k in cur:
            if k in (new or {}): cur[k] = new[k]
        cur["retention_days"] = max(1, min(3650, int(cur["retention_days"] or 30)))
        store.set_setting("config", cur); self._geo_loaded = False; self._prepare(); return cur

    def _prepare(self):
        s = self.settings()
        if not self._geo_loaded:
            self.geo.load(s["country_db"] or None, s["asn_db"] or None); self._geo_loaded = True
        if self.resolver is None: self.resolver = Resolver(self.geo)
        self.resolver.geo = self.geo; self.resolver.rdns = bool(s["rdns"])
        self.resolver.cache.clear()
        path = s["blacklist"] or ""
        if path != self.blacklist_path:
            self.blacklist_path = path; self.blacklist = None
            if path:
                try: self.blacklist = IpBlacklist.from_file(path)
                except Exception as e: self.error = f"blacklist: {e}"
        if self.engine: self.engine.blacklist = self.blacklist

    def blacklist_status(self):
        return {"path": self.blacklist_path, "entries": self.blacklist.count if self.blacklist else 0, "ips": self.blacklist.ips if self.blacklist else 0,
                "cidrs": self.blacklist.cidrs if self.blacklist else 0, "invalid": bool(self.blacklist and self.blacklist.invalid), "info": self.blacklist.info() if self.blacklist else ""}

    # ---------------- lifecycle ----------------
    def start(self, source):
        with self.lock:
            if self.state in ("running", "paused"):
                why = self._dead_reason()
                if not why: raise RuntimeError("A capture is already running. Stop it first.")
                self._fail(why)                       # V12.4: a capture that died must not block the next Start
            self.error = ""; self.finished_note = ""; self._prepare(); st = source.get("type")
            bpf = (source.get("bpf") or "").strip()
            pred = None
            if st in ("device", "pcap"):
                try: pred = compile_filter(bpf)
                except FilterError as e:
                    if st == "pcap": raise ValueError(f"Filter error: {e}")
                    pred = None      # libpcap may still understand it; reported at start
            mine, name = [], ""
            os.makedirs(DATA_DIR, exist_ok=True)
            if st == "device":
                ifs = {i["name"]: i for i in interfaces()}
                name = source.get("iface") or ""
                if name not in ifs: raise ValueError(f"Unknown interface '{name}'.")
                mine = _mine(ifs[name]["addresses"])
            elif st == "pcap":
                p = source.get("path") or ""
                root = os.path.realpath(DATA_DIR)
                if not p or not os.path.realpath(p).startswith(root + os.sep): raise ValueError("Capture files must be uploaded through Net-monit (or placed in its data/traffic folder).")
                if not os.path.isfile(p): raise ValueError("Capture file not found.")
                name = os.path.basename(p); name = name.split("-", 1)[1] if name.split("-", 1)[0].isdigit() and "-" in name else name
            elif st == "flows":
                try: fport = int(source["port"]) if source.get("port") not in (None, "") else 2055
                except (TypeError, ValueError): raise ValueError("Port must be a number between 1 and 65535.")
                name = f"NetFlow/IPFIX :{fport}"
                for i in interfaces(): mine += _mine(i["addresses"])
            else:
                raise ValueError("source type must be device, pcap or flows")
            self.sid = store.create_session(st, name, bpf)
            self.programs = None
            if st == "device": self.programs = ProgramLookup(); self.programs.start()
            notifier = Notifier(lambda: self.sid, store.list_favorites, self.sinks)
            self.engine = Engine(self.sid, name, mine, self.blacklist, self.resolver, self.programs, notifier, live=(st != "pcap"))
            self.source = dict(source, name=name); self.stop_evt = threading.Event(); self.threads = []; self.state = "running"
            try:
                if st == "device": self._start_device(name, bpf, pred, bool(source.get("export_pcap")))
                elif st == "pcap": self._spawn(self._run_pcap, source["path"], pred)
                else: self._start_flows(fport, source.get("bind") or "0.0.0.0", source.get("allow") or [])
            except Exception:
                self.state = "idle"; store.update_session(self.sid, status="failed", ended_ts=time.time()); raise
            if st != "pcap":
                self._spawn(self._ticker); self._spawn(self._persist_loop)
            return self.status()

    def _spawn(self, fn, *a):
        t = threading.Thread(target=fn, args=a, daemon=True, name="traffic-" + fn.__name__); t.start(); self.threads.append(t)

    def _start_device(self, iface, bpf, soft_pred, export):
        eng = self.engine; written = [0]
        # Backend: Linux = native AF_PACKET; Windows = Npcap through scapy when installed, otherwise built-in raw sockets (no extra software);
        # macOS/other = scapy (BPF devices).
        if sys.platform.startswith("linux"): backend = "linux"
        elif sys.platform == "win32": backend = "scapy" if npcap_installed() else "winraw"
        else: backend = "scapy"
        self.capture_backend = {"linux": "Linux native capture", "winraw": "Windows built-in capture (no Npcap needed)", "scapy": "Npcap / libpcap"}[backend]
        if export:
            self.pcap_path = os.path.join(DATA_DIR, f"capture-{self.sid}.pcap")
            self.pcap_writer = RawPcapOut(self.pcap_path, 101 if backend == "winraw" else 1)
            store.update_session(self.sid, pcap_path=self.pcap_path)

        def handle(raw, link, ts, wirelen=None, pred=None):
            try:
                p = P.parse(raw, link, wirelen or len(raw))
                if p is None or (pred and not pred(p)): return
                eng.feed_packet(p, ts)
                if self.pcap_writer and written[0] < PCAP_LIMIT:
                    self.pcap_writer.write(raw, ts, wirelen); written[0] += len(raw)
            except Exception as e:
                eng.errors.append(str(e)[:200])

        # Filter engine: the built-in filter whenever it understands the expression (same behaviour on every OS, no tcpdump/libpcap needed);
        # native BPF only for expressions it does not know, and only when libpcap (Npcap) or tcpdump is really present.
        pred = None; native_filter = None
        if bpf:
            if soft_pred is not None: pred = soft_pred; self.filter_mode = "built-in"
            else:
                native_ok = False
                if backend == "scapy":
                    try:
                        import shutil
                        from scapy.all import conf
                        native_ok = bool(conf.use_pcap) or bool(shutil.which("tcpdump"))
                    except Exception: pass
                if not native_ok:
                    raise RuntimeError("This filter uses syntax the built-in filter does not know. Use simple filters such as: "
                                       "tcp port 443, host 10.0.0.5, udp and not port 53, net 192.168.0.0/16")
                native_filter = bpf; self.filter_mode = "BPF (libpcap)"
        else: self.filter_mode = "none"
        if backend == "linux":
            sn = RawLinuxSniffer(iface, lambda raw, link, ts: handle(raw, link, ts, None, pred))
            try: sn.start()
            except PermissionError: raise RuntimeError("Permission denied: run Net-monit as root (or give it CAP_NET_RAW).")
            except OSError as e: raise RuntimeError(f"Cannot capture on '{iface}': {e}")
        elif backend == "winraw":
            ifs = {i["name"]: i for i in interfaces()}
            addrs = [a["addr"] for a in ifs.get(iface, {}).get("addresses", [])]
            sn = RawWindowsSniffer(addrs, lambda raw, link, ts: handle(raw, link, ts, None, pred))
            try: sn.start()
            except PermissionError as e: raise RuntimeError(str(e))
            except OSError as e: raise RuntimeError(str(e))
        else:
            from scapy.all import AsyncSniffer
            def cb(pkt):
                cls = pkt.__class__.__name__
                link = P.LINK_ETHERNET if cls == "Ether" else P.LINK_NULL if cls == "Loopback" else 113 if cls == "CookedLinux" else 276 if cls == "CookedLinuxV2" else P.LINK_RAW
                raw = bytes(pkt); handle(raw, link, time.time(), getattr(pkt, "wirelen", None) or len(raw), pred)
            try:
                sn = AsyncSniffer(iface=iface, filter=native_filter, store=False, prn=cb); sn.start(); time.sleep(0.6)
                if not sn.running and getattr(sn, "exception", None): raise sn.exception
                if not sn.running: raise RuntimeError("capture did not start")
            except PermissionError:
                raise RuntimeError("Permission denied: run Net-monit as Administrator.")
            except RuntimeError: raise
            except Exception as e: raise RuntimeError(f"Cannot capture on '{iface}': {e}")
        self.sniffer = sn

    def _start_flows(self, port, bind, allow=()):
        if not 1 <= port <= 65535: raise ValueError("Port must be between 1 and 65535.")
        for a in allow:
            try: ipaddress.ip_address(str(a).strip())
            except ValueError: raise ValueError(f"'{a}' is not a valid exporter IP address.")
        c = Collector(port, self.engine.feed_flow, bind, allow)
        try: c.open()
        except OSError as e: raise RuntimeError(f"Cannot listen on UDP {bind}:{port}: {e}")
        c.start(); self.collector = c; self.threads.append(c)

    def _run_pcap(self, path, pred):
        eng = self.engine
        try:
            from scapy.utils import RawPcapReader, RawPcapNgReader
            with open(path, "rb") as f: magic = f.read(4)
            ng = magic == b"\x0a\x0d\x0d\x0a"
            rdr = (RawPcapNgReader if ng else RawPcapReader)(path); n = 0
            link = getattr(rdr, "linktype", None)
            if not ng and link not in P.SUPPORTED_LINKS: raise ValueError(f"Unsupported link type {link}")
            for data, meta in rdr:
                if self.stop_evt.is_set(): break
                while self.state == "paused" and not self.stop_evt.is_set(): time.sleep(0.1)
                if ng:
                    lt = meta.linktype if hasattr(meta, "linktype") else meta[0]
                    ts = ((meta.tshigh << 32) + meta.tslow) / float(meta.tsresol) if hasattr(meta, "tshigh") else time.time()
                    wl = getattr(meta, "wirelen", None) or len(data)
                else:
                    lt = link; ts = meta.sec + meta.usec / (1e9 if getattr(meta, "usec", 0) > 999999 and False else 1e6); wl = meta.wirelen
                p = P.parse(data, lt, wl)
                if p is None or (pred and not pred(p)): continue
                eng.feed_packet(p, ts); n += 1
                if n % 20000 == 0: self.engine.fill_programs()
            eng.finish()
            self.finished_note = f"Read {n:,} packets from {os.path.basename(path)}."
        except Exception as e:
            self.error = f"{type(e).__name__}: {e}"; eng.errors.append(self.error)
        finally:
            self._persist(final=True)                       # save first, then announce 'finished' (readers must never see a half-saved session)
            if self.state in ("running", "paused"): self.state = "finished"

    def _ticker(self):
        while not self.stop_evt.is_set():
            self.engine.advance(time.time()); self.engine.fill_programs(); self.stop_evt.wait(0.5)

    def _persist_loop(self):
        while not self.stop_evt.wait(30):
            self._persist()

    def _persist(self, final=False):
        eng, sid = self.engine, self.sid
        if not eng or not sid: return
        try:
            with eng.lock:
                t = list(eng.tot); series = list(eng.series); conns = sorted(eng.conns.values(), key=lambda i: -i.bytes)[:3000]
                rows = []
                for i in conns:
                    d = i.as_dict(); h = eng.host_of(i.addr); d.update(host=h["name"], country=h["country"], asn=h["asn"], asn_name=h["asn_name"]); rows.append(d)
                n = len(eng.conns)
            mins = {}
            for sec, ib, ob, ip, op in series:
                m = sec - sec % 60; a = mins.setdefault(m, [0, 0, 0, 0]); a[0] += ib; a[1] += ob; a[2] += ip; a[3] += op
            store.save_minutes(sid, [(m, *v) for m, v in mins.items()]); store.save_conns(sid, rows)
            kw = dict(in_bytes=t[0], out_bytes=t[1], in_packets=t[2], out_packets=t[3], connections=n)
            if final: kw.update(ended_ts=time.time(), status="finished" if self.state != "failed" else "failed")
            store.update_session(sid, **kw)
        except Exception as e:
            eng.errors.append(f"persist: {e}")

    def stop(self):
        with self.lock:
            if self.state == "idle": return self.status()
            self.stop_evt.set()
            for o in (self.sniffer, self.collector):
                try:
                    if o is not None: o.stop()
                except Exception: pass
            if self.programs: self.programs.stop()
            if self.pcap_writer:
                try: self.pcap_writer.close()
                except Exception: pass
            for t in self.threads:
                if t is not threading.current_thread() and t.is_alive() and not isinstance(t, Collector): t.join(timeout=3)
            if self.engine and self.source and self.source.get("type") != "pcap": self.engine.finish()
            self.state = "stopped"; self._persist(final=True)
            self.sniffer = self.collector = self.pcap_writer = None
            return self.status()

    # ---------------- V12.4: a capture that stopped by itself must never leave the page stuck ----------------
    def _dead_reason(self):
        """'' while the capture is really alive; otherwise why a capture marked running/paused is not (capture thread/collector gone)."""
        if self.state not in ("running", "paused"): return ""
        t = (self.source or {}).get("type")
        try:
            if t == "device":
                sn = self.sniffer
                if sn is None: return "the capture object is gone"
                if getattr(sn, "running", True) is False: return str(getattr(sn, "exception", "") or "the capture thread ended")
                ths = getattr(sn, "threads", None)
                if ths and not any(x.is_alive() for x in ths): return "all capture threads ended"
            elif t == "flows":
                c = self.collector
                if c is None or not c.is_alive(): return "the NetFlow collector stopped"
            elif t == "pcap":
                if not any(x.is_alive() for x in self.threads): return "the file reader ended"
        except Exception:
            return ""
        return ""

    def _fail(self, why):
        with self.lock:
            try: self.stop()
            except Exception: pass
            self.state = "failed"; self.error = f"The capture stopped unexpectedly: {why}"

    def reset(self):
        """Force everything back to idle (Reset button): stops whatever is left and clears the state."""
        with self.lock:
            try: self.stop()
            except Exception: pass
            self.state = "idle"; self.error = ""; self.sniffer = self.collector = self.pcap_writer = None
            self.threads = []; self.stop_evt = threading.Event()
            return self.status()

    def pause(self, on=True):
        with self.lock:
            if self.state in ("running", "paused"):
                self.state = "paused" if on else "running"
                if self.engine: self.engine.paused = on
            return self.status()

    def status(self):
        if self.state in ("running", "paused") and self.lock.acquire(blocking=False):      # self-heal without ever blocking the poll
            try:
                why = self._dead_reason()
                if why: self._fail(why)
            finally: self.lock.release()
        e = self.engine; s = self.source or {}
        d = {"state": self.state, "session_id": self.sid, "source": {k: s.get(k) for k in ("type", "name", "iface", "bpf", "path", "port") if s.get(k) is not None},
             "filter_mode": self.filter_mode, "capture_backend": self.capture_backend, "error": self.error, "note": self.finished_note, "geo": self.geo.status(), "blacklist": self.blacklist_status(),
             "pcap_export": bool(self.pcap_path and os.path.isfile(self.pcap_path)) and self.sid is not None, "started": e.started if e else None,
             "programs_error": self.programs.error if self.programs else ""}
        if e: d["totals"] = e.totals(); d["errors"] = e.errors[-5:]
        if self.collector: d["collector"] = {"port": self.collector.port, "stats": self.collector.decoder.stats, "exporters": list(self.collector.exporters), "allow": sorted(self.collector.allow), "rejected": self.collector.rejected}
        return d

    # ---------------- helpers for the API ----------------
    def latency(self, ip):
        from ..checkers import ping_check
        return ping_check.check(ip, timeout_ms=1000, count=3)

    def autostart(self):
        cfg = self.settings().get("autostart")
        if cfg and cfg.get("type") in ("device", "flows"):
            try: self.start(cfg)
            except Exception as e: self.error = f"autostart: {e}"


_mgr = None
_mlock = threading.Lock()


def get_manager():
    global _mgr
    with _mlock:
        if _mgr is None: _mgr = Manager()
        return _mgr
