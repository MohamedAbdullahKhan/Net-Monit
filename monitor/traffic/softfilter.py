"""Small software implementation of the common BPF filter syntax, used when libpcap/tcpdump cannot compile a filter
(and for pcap-file import). Supports: ip ip6 tcp udp icmp icmp6 arp igmp, [src|dst] host/net/port, portrange, broadcast, multicast,
vlan, less/greater N, and/or/not/&&/||/! and parentheses; qualifiers like 'tcp port 80' and 'ip host 1.2.3.4'."""
import ipaddress
import re


class FilterError(ValueError):
    pass


_TOK = re.compile(r"\s*(\(|\)|&&|\|\||!|[^\s()!&|]+)")


def _tokens(s):
    out, pos = [], 0
    s = s.strip()
    while pos < len(s):
        m = _TOK.match(s, pos)
        if not m: raise FilterError(f"cannot parse near '{s[pos:pos + 12]}'")
        out.append(m.group(1)); pos = m.end()
    return [{"&&": "and", "||": "or", "!": "not"}.get(t, t.lower() if t.isalpha() else t) for t in out]


class _P:
    def __init__(self, toks): self.t, self.i = toks, 0

    def peek(self): return self.t[self.i] if self.i < len(self.t) else None

    def take(self, what=None):
        if self.i >= len(self.t): raise FilterError("expression ended unexpectedly")
        v = self.t[self.i]; self.i += 1
        if what and v != what: raise FilterError(f"expected '{what}' but found '{v}'")
        return v

    def expr(self):
        left = self.term()
        while self.peek() == "or": self.take(); r = self.term(); left = (lambda a, b: lambda p: a(p) or b(p))(left, r)
        return left

    def term(self):
        left = self.factor()
        while self.peek() in ("and",) or (self.peek() not in (None, "or", ")")):
            if self.peek() == "and": self.take()
            r = self.factor(); left = (lambda a, b: lambda p: a(p) and b(p))(left, r)
        return left

    def factor(self):
        t = self.peek()
        if t is None: raise FilterError("expression ended unexpectedly")
        if t == "not": self.take(); f = self.factor(); return lambda p: not f(p)
        if t == "(":
            self.take(); e = self.expr(); self.take(")"); return e
        return self.prim()

    def prim(self):
        proto = None; d = None
        t = self.take()
        if t in ("ip", "ip6", "tcp", "udp", "icmp", "icmp6", "arp", "igmp") and self.peek() in ("src", "dst", "host", "net", "port", "portrange", "broadcast", "multicast"):
            proto = t; t = self.take()
        if t in ("src", "dst"): d = t; t = self.take()
        if t == "host":
            a = ipaddress.ip_address(self.take()); return self._host(proto, d, lambda x: ipaddress.ip_address(x) == a)
        if t == "net":
            spec = self.take()
            if self.peek() == "mask": self.take(); spec = f"{spec}/{ipaddress.ip_address(self.take())}"
            n = ipaddress.ip_network(spec, strict=False); return self._host(proto, d, lambda x: ipaddress.ip_address(x) in n)
        if t == "port":
            n = int(self.take()); return self._port(proto, d, lambda x: x == n)
        if t == "portrange":
            a, b = self.take().split("-"); a, b = int(a), int(b); return self._port(proto, d, lambda x: a <= x <= b)
        if t in ("tcp", "udp"): return lambda p: p.proto == t.upper()
        if t == "icmp": return lambda p: p.proto == "ICMP"
        if t == "icmp6": return lambda p: p.proto == "ICMPv6"
        if t == "arp": return lambda p: p.proto == "ARP"
        if t == "igmp": return lambda p: p.proto == "IGMP"
        if t == "ip": return lambda p: p.proto == "ARP" and False or ":" not in p.src_ip and p.proto != "ARP"
        if t == "ip6": return lambda p: ":" in p.src_ip
        if t == "vlan": return lambda p: p.vlan is not None
        if t == "multicast": return lambda p: ipaddress.ip_address(p.dst_ip).is_multicast
        if t == "broadcast": return lambda p: p.dst_ip == "255.255.255.255" or (p.dst_mac or "").lower() == "ff:ff:ff:ff:ff:ff"
        if t == "less": n = int(self.take()); return lambda p: p.length <= n
        if t == "greater": n = int(self.take()); return lambda p: p.length >= n
        raise FilterError(f"unsupported filter word '{t}'")

    @staticmethod
    def _proto_ok(proto, p):
        return proto is None or (proto == "tcp" and p.proto == "TCP") or (proto == "udp" and p.proto == "UDP") or (proto == "icmp" and p.proto == "ICMP") or \
            (proto == "icmp6" and p.proto == "ICMPv6") or (proto == "arp" and p.proto == "ARP") or (proto == "igmp" and p.proto == "IGMP") or \
            (proto == "ip" and ":" not in p.src_ip) or (proto == "ip6" and ":" in p.src_ip)

    def _host(self, proto, d, test):
        def f(p):
            if not self._proto_ok(proto, p): return False
            return (d != "dst" and test(p.src_ip)) or (d != "src" and test(p.dst_ip))
        return f

    def _port(self, proto, d, test):
        def f(p):
            if p.src_port is None or p.proto not in ("TCP", "UDP") or not self._proto_ok(proto, p): return False
            return (d != "dst" and test(p.src_port)) or (d != "src" and test(p.dst_port))
        return f


def compile_filter(text):
    """-> predicate(Packet) -> bool. Raises FilterError with a readable message."""
    if not text or not text.strip(): return lambda p: True
    try:
        p = _P(_tokens(text)); f = p.expr()
    except FilterError:
        raise
    except ValueError as e:                                   # e.g. an address or port that is not valid
        raise FilterError(str(e))
    if p.peek() is not None: raise FilterError(f"unexpected '{p.peek()}'")
    return f
