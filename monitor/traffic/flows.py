"""NetFlow v5 / v9 and IPFIX (RFC 7011) decoder + UDP collector. Port of Sniffnet's IPFIX collector (templates with TTL, delta-vs-total
counter handling, vendor-neutral information elements) extended with NetFlow v9 and v5, which most routers/switches export."""
import ipaddress
import socket
import struct
import threading
import time

TTL = 1800                                # template lifetime without refresh (seconds)
PROTOS = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6", 2: "IGMP"}
ICMP4 = None                              # lazily borrowed from parser for message names


def _ip(b):
    return str(ipaddress.ip_address(bytes(b)))


def _mac(b):
    return ":".join("%02x" % x for x in b)


def _u(b):
    return int.from_bytes(bytes(b), "big")


class Decoder:
    """Stateful per-collector decoder: template cache + total-counter baselines."""

    def __init__(self):
        self.templates = {}               # (exporter, domain, tid) -> (fields, expires, is_ipfix)
        self.baseline = {}                # (exporter, flow key) -> (bytes, packets, expires)
        self.stats = {"messages": 0, "records": 0, "templates": 0, "errors": 0, "no_template": 0}

    # ---- entry point ----
    def decode(self, data, exporter):
        """bytes -> list of flow dicts. Never raises."""
        try:
            if len(data) < 16: self.stats["errors"] += 1; return []
            v = struct.unpack("!H", data[:2])[0]
            self.stats["messages"] += 1
            if v == 5: return self._v5(data, exporter)
            if v == 9: return self._sets(data, exporter, 9)
            if v == 10: return self._sets(data, exporter, 10)
            self.stats["errors"] += 1
        except Exception:
            self.stats["errors"] += 1
        return []

    # ---- NetFlow v5 ----
    def _v5(self, d, exp):
        count, uptime, secs, nsecs = struct.unpack("!HIII", d[2:16]); out = []
        for i in range(min(count, (len(d) - 24) // 48)):
            r = d[24 + i * 48: 24 + (i + 1) * 48]
            src, dst, _, inif, outif, pk, by, first, last, sp, dp, _, flags, proto, tos = struct.unpack("!4s4s4sHHIIIIHHBBBB", r[:40])
            base = secs - uptime / 1000.0
            out.append(self._flow(_ip(src), _ip(dst), sp, dp, proto, by, pk, base + first / 1000.0, base + last / 1000.0, None, None, None, None, None))
        self.stats["records"] += len(out); return out

    # ---- NetFlow v9 / IPFIX ----
    def _sets(self, d, exp, ver):
        out = []; now = time.time()
        if ver == 10:
            length, export_time, seq, dom = struct.unpack("!HIII", d[2:16]); pos, end = 16, min(length, len(d)); t0 = export_time; uptime = None
        else:
            count, uptime, secs, seq, dom = struct.unpack("!HIIII", d[2:20]); pos, end = 20, len(d); t0 = secs
        while pos + 4 <= end:
            sid, slen = struct.unpack("!HH", d[pos:pos + 4])
            if slen < 4 or pos + slen > end: break
            body = d[pos + 4: pos + slen]; pos += slen
            if (ver == 10 and sid == 2) or (ver == 9 and sid == 0): self._templates(body, exp, dom, ver, now)
            elif (ver == 10 and sid == 3) or (ver == 9 and sid == 1): pass             # options templates: not needed for flow accounting
            elif sid >= 256: out.extend(self._data(body, sid, exp, dom, ver, t0, uptime, now))
        self.stats["records"] += len(out); return out

    def _templates(self, b, exp, dom, ver, now):
        p = 0
        while p + 4 <= len(b):
            tid, n = struct.unpack("!HH", b[p:p + 4]); p += 4; fields = []
            for _ in range(n):
                if p + 4 > len(b): return
                ie, ln = struct.unpack("!HH", b[p:p + 4]); p += 4
                if ver == 10 and ie & 0x8000:
                    ie &= 0x7FFF; p += 4; ie = (ie, True)                             # enterprise element: kept, ignored on decode
                else: ie = (ie, False)
                fields.append((ie, ln))
            if tid >= 256:
                self.templates[(exp, dom, tid)] = (fields, now + TTL, ver == 10); self.stats["templates"] += 1

    def _data(self, b, tid, exp, dom, ver, t0, uptime, now):
        t = self.templates.get((exp, dom, tid))
        if not t or t[1] < now:
            self.stats["no_template"] += 1; return []
        fields = t[0]; out = []; p = 0
        fixed = sum(l for _, l in fields if l != 0xFFFF)
        while p + fixed <= len(b) and fields:
            rec = {}; q = p; ok = True
            for (ie, ent), ln in fields:
                if ln == 0xFFFF:                                                      # variable length (IPFIX)
                    if q >= len(b): ok = False; break
                    ln = b[q]; q += 1
                    if ln == 255:
                        if q + 2 > len(b): ok = False; break
                        ln = struct.unpack("!H", b[q:q + 2])[0]; q += 2
                if q + ln > len(b): ok = False; break
                if not ent: rec.setdefault(ie, b[q:q + ln])
                q += ln
            if not ok or q == p: break
            p = q; f = self._record(rec, exp, ver, t0, uptime)
            if f: out.append(f)
        return out

    def _record(self, r, exp, ver, t0, uptime):
        g = lambda i: r.get(i)
        if 8 in r or 12 in r: src, dst = _ip(g(8)) if 8 in r else "0.0.0.0", _ip(g(12)) if 12 in r else "0.0.0.0"
        elif 27 in r or 28 in r: src, dst = _ip(g(27)) if 27 in r else "::", _ip(g(28)) if 28 in r else "::"
        else: return None
        proto = _u(g(4)) if 4 in r else 0
        sp = _u(g(7)) if 7 in r else None; dp = _u(g(11)) if 11 in r else None
        # counters: delta counters win (IE 1/2); else total counters (IE 85/86) turned into deltas against a baseline
        by, pk = (_u(g(1)) if 1 in r else None), (_u(g(2)) if 2 in r else None)
        key = (exp, src, dst, sp, dp, proto)
        if by is None and 85 in r: by = self._delta(key, 0, _u(g(85)))
        if pk is None and 86 in r: pk = self._delta(key, 1, _u(g(86)))
        if by is None and pk is None: return None
        # timestamps
        st = en = None
        if 152 in r: st = _u(g(152)) / 1000.0
        elif 150 in r: st = float(_u(g(150)))
        if 153 in r: en = _u(g(153)) / 1000.0
        elif 151 in r: en = float(_u(g(151)))
        if st is None and 22 in r and uptime is not None: st = t0 - uptime / 1000.0 + _u(g(22)) / 1000.0
        if en is None and 21 in r and uptime is not None: en = t0 - uptime / 1000.0 + _u(g(21)) / 1000.0
        st = st or en or t0; en = en or st
        hint = {0: "incoming", 1: "outgoing"}.get(_u(g(61))) if 61 in r else None             # flowDirection: 0 ingress, 1 egress
        vlan = _u(g(58)) if 58 in r else (_u(g(59)) if 59 in r else None)
        smac = _mac(g(56)) if 56 in r and len(g(56)) == 6 else None
        dmac = _mac(g(80)) if 80 in r and len(g(80)) == 6 else (_mac(g(57)) if 57 in r and len(g(57)) == 6 else None)
        msg = None
        if proto in (1, 58):
            ic = _u(g(32)) if 32 in r else (_u(g(139)) if 139 in r else None)
            if ic is not None:
                from .parser import ICMP4 as T4, ICMP6 as T6
                msg = (T4 if proto == 1 else T6).get(ic >> 8, "?")
        return self._flow(src, dst, sp, dp, proto, by or 0, pk or 0, st, en, hint, vlan, smac, dmac, msg)

    def _delta(self, key, idx, total):
        now = time.time(); b = self.baseline.get(key)
        if len(self.baseline) > 50000:
            self.baseline = {k: v for k, v in self.baseline.items() if v[2] > now}
        prev = [0, 0] if not b or b[2] < now else [b[0], b[1]]
        d = total - prev[idx] if total >= prev[idx] else total
        prev[idx] = total; self.baseline[key] = (prev[0], prev[1], now + TTL)
        return d

    @staticmethod
    def _flow(src, dst, sp, dp, proto, by, pk, st, en, hint, vlan, smac, dmac, msg):
        name = PROTOS.get(proto)
        if name is None: return None                                                      # protocols Sniffnet does not count
        if name not in ("TCP", "UDP"): sp = dp = None
        return {"src_ip": src, "dst_ip": dst, "src_port": sp, "dst_port": dp, "proto": name, "bytes": by, "packets": pk,
                "start": st, "end": en, "direction": hint, "vlan": vlan, "src_mac": smac, "dst_mac": dmac, "msg": msg}


class Collector(threading.Thread):
    """UDP listener feeding decoded flows to `on_flow(dict)`."""

    def __init__(self, port, on_flow, bind="0.0.0.0", allow=()):
        super().__init__(daemon=True, name="traffic-flow-collector")
        self.port, self.bind, self.on_flow = port, bind, on_flow
        self.allow = {a.strip() for a in allow if a and a.strip()}; self.rejected = 0      # empty = accept every exporter (UDP can be spoofed: use the allow-list)
        self.decoder = Decoder(); self._stop = threading.Event(); self.sock = None; self.exporters = {}

    def open(self):
        fam = socket.AF_INET6 if ":" in self.bind else socket.AF_INET
        self.sock = socket.socket(fam, socket.SOCK_DGRAM); self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.bind, self.port)); self.sock.settimeout(0.5)
        self.port = self.sock.getsockname()[1]

    def run(self):
        while not self._stop.is_set():
            try: data, addr = self.sock.recvfrom(65535)
            except socket.timeout: continue
            except OSError: break
            if self.allow and addr[0] not in self.allow:
                self.rejected += 1; continue
            self.exporters[addr[0]] = time.time()
            for f in self.decoder.decode(data, addr[0]):
                try: self.on_flow(f)
                except Exception: pass

    def stop(self):
        self._stop.set()
        try: self.sock.close()
        except Exception: pass
