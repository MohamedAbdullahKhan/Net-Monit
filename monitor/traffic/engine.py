"""Traffic accounting engine (port of Sniffnet's InfoTraffic / manage_packets logic).

Feed it parsed packets (feed_packet) or flow records (feed_flow); it keeps per-connection, per-host, per-service, per-program and
per-country totals, per-second series and calls the notifier once per closed second. Thread-safe (one RLock)."""
import collections
import ipaddress
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import netutil as N, services as S

Key = collections.namedtuple("Key", "src_ip src_port dst_ip dst_port proto")
IB, OB, IP_, OP = 0, 1, 2, 3                      # DataInfo slots: incoming bytes, outgoing bytes, incoming packets, outgoing packets


def add_data(di, direction, packets, nbytes):
    if direction == N.INCOMING: di[IB] += nbytes; di[IP_] += packets
    else: di[OB] += nbytes; di[OP] += packets


class Info:
    __slots__ = ("id", "key", "bytes", "packets", "first", "last", "direction", "service", "blacklisted", "msgs", "vlan", "src_mac",
                 "dst_mac", "program", "pid", "prev_b", "prev_p", "addr", "tmono")

    def as_dict(self):
        return {"id": self.id, "src_ip": self.key.src_ip, "src_port": self.key.src_port, "dst_ip": self.key.dst_ip, "dst_port": self.key.dst_port,
                "proto": self.key.proto, "bytes": self.bytes, "packets": self.packets, "first": self.first, "last": self.last,
                "direction": self.direction, "service": self.service, "blacklisted": self.blacklisted, "vlan": self.vlan,
                "src_mac": self.src_mac, "dst_mac": self.dst_mac, "program": self.program, "msgs": dict(self.msgs), "remote": self.addr}


class Resolver:
    """Remote address -> Host (country, ASN immediately from the local databases; reverse-DNS name a moment later in a worker thread)."""

    def __init__(self, geo, workers=4, max_cache=100000):
        self.geo, self.cache, self.pending, self.max_cache = geo, {}, set(), max_cache
        self.pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="traffic-rdns")
        self.lock = threading.Lock(); self.rdns = True

    def host(self, addr):
        return self.cache.get(addr)

    def request(self, addr, mine):
        with self.lock:
            if addr in self.cache: return self.cache[addr]
            a = N.ip(addr); cc, cn, asn, an = self.geo.lookup(addr) if self.geo else ("", "", 0, "")
            h = {"name": addr, "domain": "", "country": cc, "country_name": cn, "asn": asn, "asn_name": an,
                 "local": N.is_local_connection(a, mine), "loopback": a.is_loopback, "bogon": N.is_bogon(a)}
            if len(self.cache) >= self.max_cache: self.cache.clear()
            self.cache[addr] = h
            if self.rdns and not (a.is_multicast or a.is_unspecified or a.is_loopback) and addr not in self.pending:
                self.pending.add(addr); self.pool.submit(self._rdns, addr)
            return h

    def _rdns(self, addr):
        try:
            name = socket.gethostbyaddr(addr)[0]
            if name and name != addr: self.cache[addr]["domain"] = name; self.cache[addr]["name"] = name
        except Exception:
            pass
        finally:
            self.pending.discard(addr)

    def shutdown(self):
        self.pool.shutdown(wait=False, cancel_futures=True)


class ProgramLookup(threading.Thread):
    """local (port, proto) -> process name using psutil, refreshed every `period` seconds."""

    def __init__(self, period=2.0):
        super().__init__(daemon=True, name="traffic-programs")
        self.table, self.period, self._stop, self.error = {}, period, threading.Event(), ""

    def run(self):
        try: import psutil
        except Exception as e: self.error = f"psutil not available: {e}"; return
        names = {}
        while not self._stop.is_set():
            t = {}
            try:
                for c in psutil.net_connections(kind="inet"):
                    if not c.laddr or c.pid is None: continue
                    proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                    nm = names.get(c.pid)
                    if nm is None:
                        try: nm = names[c.pid] = psutil.Process(c.pid).name()
                        except Exception: nm = names[c.pid] = ""
                    if nm: t[(c.laddr.port, proto)] = (nm, c.pid)
                self.table = t; self.error = ""
            except Exception as e:
                self.error = str(e)
            self._stop.wait(self.period)

    def stop(self):
        self._stop.set()

    def find(self, port, proto):
        return self.table.get((port, proto))


class Engine:
    SERIES_LEN = 7200
    MAX_CONNS = 200000          # memory guard: a port scan or flood can create millions of tiny connections

    def __init__(self, session_id, source, mine=(), blacklist=None, resolver=None, programs=None, notifier=None, live=True):
        self.session_id, self.source, self.mine = session_id, source, list(mine)
        self.blacklist, self.resolver, self.programs, self.notifier, self.live = blacklist, resolver, programs, notifier, live
        self.lock = threading.RLock(); self.started = time.time(); self.paused = False
        self.conns, self._by_id, self._next_id = {}, {}, 1
        self.tot = [0, 0, 0, 0]; self.addrs, self.services, self.progs = {}, {}, {}
        self.series = collections.deque(maxlen=self.SERIES_LEN)       # (sec, in_b, out_b, in_p, out_p)
        self.iv = self._new_interval(); self.cur_sec = None; self.last_ts = None; self.dropped_unsupported = 0
        self.packets_seen = 0; self.errors = []; self.pruned = 0

    @staticmethod
    def _new_interval():
        return {"tot": [0, 0, 0, 0], "conns": {}, "addrs": {}, "services": {}, "programs": {}}

    # ------------------------------------------------------------------ input
    def feed_packet(self, p, ts):
        """p: parser.Packet"""
        if self.paused: return
        key = Key(p.src_ip, p.src_port, p.dst_ip, p.dst_port, p.proto)
        with self.lock:
            if not self.live: self.advance(ts)
            self._account(key, 1, p.length, ts, ts, ts, p.src_mac, p.dst_mac, p.msg, p.vlan, None)
            self.packets_seen += 1

    def feed_flow(self, f):
        if self.paused: return
        key = Key(f["src_ip"], f["src_port"], f["dst_ip"], f["dst_port"], f["proto"])
        ts = time.time()
        with self.lock:
            self._account(key, f["packets"], f["bytes"], ts, f["start"], f["end"], f["src_mac"], f["dst_mac"], f["msg"], f["vlan"], f["direction"])
            self.packets_seen += f["packets"]

    def _account(self, key, packets, nbytes, ts, t_first, t_last, smac, dmac, msg, vlan, hint):
        info = self.conns.get(key)
        if info is None:
            info = Info(); info.id = self._next_id; self._next_id += 1; info.key = key
            info.direction = hint or N.traffic_direction(key.src_ip, key.dst_ip, key.src_port, key.dst_port, self.mine)
            info.service = S.get_service(key, info.direction, self.mine)
            info.addr = N.address_to_lookup(key, info.direction)
            info.blacklisted = bool(self.blacklist and self.blacklist.contains(info.addr))
            info.bytes = info.packets = 0; info.first = t_first; info.last = t_last; info.msgs = {}; info.vlan = vlan
            info.src_mac = smac; info.dst_mac = dmac; info.program = None; info.pid = None; info.prev_b = info.prev_p = 0; info.tmono = ts
            self.conns[key] = info; self._by_id[info.id] = info
            if len(self.conns) > self.MAX_CONNS: self._prune()
        info.bytes += nbytes; info.packets += packets; info.tmono = ts
        if t_first < info.first: info.first = t_first
        if t_last > info.last: info.last = t_last
        if smac: info.src_mac = smac
        if dmac: info.dst_mac = dmac
        if vlan is not None: info.vlan = vlan
        if msg: info.msgs[msg] = info.msgs.get(msg, 0) + 1
        d = info.direction
        add_data(self.tot, d, packets, nbytes); add_data(self.iv["tot"], d, packets, nbytes)
        ci = self.iv["conns"].setdefault(key, [0, 0]); ci[0] += nbytes; ci[1] += packets
        a = info.addr; st = self.addrs.get(a)
        if st is None:
            st = self.addrs[a] = [0, 0, 0, 0]
            if self.resolver: self.resolver.request(a, self.mine)
        add_data(st, d, packets, nbytes); add_data(self.iv["addrs"].setdefault(a, [0, 0, 0, 0]), d, packets, nbytes)
        sv = info.service
        add_data(self.services.setdefault(sv, [0, 0, 0, 0]), d, packets, nbytes); add_data(self.iv["services"].setdefault(sv, [0, 0, 0, 0]), d, packets, nbytes)
        if info.program:
            add_data(self.progs.setdefault(info.program, [0, 0, 0, 0]), d, packets, nbytes)
            add_data(self.iv["programs"].setdefault(info.program, [0, 0, 0, 0]), d, packets, nbytes)

    def _prune(self):
        """Drop the 10% of connections that were idle the longest (totals, hosts and services keep their counts)."""
        n = max(1, len(self.conns) // 10)
        for info in sorted(self.conns.values(), key=lambda i: i.tmono)[:n]:
            self.conns.pop(info.key, None); self._by_id.pop(info.id, None); self.pruned += 1

    # ------------------------------------------------------------------ time
    def advance(self, now):
        """Close every whole second before `now` (live: called by a timer; offline: called with packet timestamps)."""
        with self.lock:
            cur = int(now); self.last_ts = now
            if self.cur_sec is None: self.cur_sec = cur; return
            if cur - self.cur_sec > 3600: self.cur_sec = cur - 3600          # long gap in a capture file: do not emit hours of blank ticks
            while self.cur_sec < cur:
                self._close(self.cur_sec); self.cur_sec += 1

    def _close(self, sec):
        iv = self.iv; self.iv = self._new_interval(); t = iv["tot"]
        self.series.append((sec, t[IB], t[OB], t[IP_], t[OP]))
        if self.notifier:
            try: self.notifier(self, sec, iv)
            except Exception as e: self.errors.append(f"notifier: {e}")

    def finish(self):
        """Flush the partial last second (end of an offline analysis or stop of a capture)."""
        with self.lock:
            if self.cur_sec is not None: self._close(self.cur_sec); self.cur_sec += 1

    def fill_programs(self, limit=3000):
        """Attach process names to connections that have none yet (credits their bytes so far to the program)."""
        if not self.programs: return 0
        n = 0
        with self.lock:
            for info in list(self.conns.values())[-limit:]:
                if info.program is not None or info.key.proto not in ("TCP", "UDP"): continue
                port = N.local_port(info.key, info.direction)
                f = self.programs.find(port, info.key.proto) if port else None
                if f:
                    info.program, info.pid = f; n += 1
                    di = self.progs.setdefault(f[0], [0, 0, 0, 0]); add_data(di, info.direction, info.packets, info.bytes)
        return n

    # ------------------------------------------------------------------ views
    def host_of(self, addr):
        return (self.resolver.host(addr) if self.resolver else None) or {"name": addr, "domain": "", "country": "", "country_name": "", "asn": 0,
                "asn_name": "", "local": False, "loopback": False, "bogon": None}

    def hosts(self):
        out = {}
        with self.lock:
            for a, st in self.addrs.items():
                h = self.host_of(a); k = (h["name"], h["asn"], h["country"])
                e = out.get(k)
                if e is None:
                    e = out[k] = {"name": h["name"], "domain": h["domain"], "asn": h["asn"], "asn_name": h["asn_name"], "country": h["country"],
                                  "country_name": h["country_name"], "local": h["local"], "loopback": h["loopback"], "bogon": h["bogon"],
                                  "traffic_type": N.traffic_type(a, self.mine, N.OUTGOING), "addresses": [], "d": [0, 0, 0, 0]}
                e["addresses"].append(a)
                for i in range(4): e["d"][i] += st[i]
        return list(out.values())

    def countries(self):
        c = {}
        for h in self.hosts():
            if not h["country"]: continue
            e = c.setdefault(h["country"], {"code": h["country"], "name": h["country_name"], "d": [0, 0, 0, 0], "hosts": 0})
            e["hosts"] += 1
            for i in range(4): e["d"][i] += h["d"][i]
        return list(c.values())

    def totals(self):
        with self.lock:
            return {"tot": list(self.tot), "connections": len(self.conns), "hosts": len(self.addrs), "packets_seen": self.packets_seen,
                    "blacklisted": sum(1 for i in self.conns.values() if i.blacklisted), "last_second": list(self.series[-1][1:]) if self.series else [0, 0, 0, 0],
                    "series_len": len(self.series), "pruned": self.pruned}

    def recent_series(self, n=120):
        with self.lock:
            s = list(self.series)[-n:]
        return s
