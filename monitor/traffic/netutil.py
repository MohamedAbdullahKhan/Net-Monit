"""Address helpers: bogon classification, traffic direction/type, local-network tests (port of Sniffnet manage_packets.rs/bogon.rs)."""
import ipaddress
from collections import namedtuple

Addr = namedtuple("Addr", "addr netmask broadcast")      # one interface address (ipaddress objects or None)

_B = [
    ('"this" network', ["0.0.0.0/8"]), ("private-use", ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]),
    ("carrier-grade NAT", ["100.64.0.0/10"]), ("loopback", ["127.0.0.0/8"]), ("link local", ["169.254.0.0/16"]),
    ("IETF protocol assignments", ["192.0.0.0/24"]), ("TEST-NET-1", ["192.0.2.0/24"]),
    ("network interconnect device benchmark testing", ["198.18.0.0/15"]), ("TEST-NET-2", ["198.51.100.0/24"]),
    ("TEST-NET-3", ["203.0.113.0/24"]), ("multicast", ["224.0.0.0/4"]), ("future use", ["240.0.0.0/4"]),
    ("node-scope unicast unspecified", ["::/128"]), ("node-scope unicast loopback", ["::1/128"]),
    ("IPv4-mapped", ["::ffff:0.0.0.0/96"]), ("IPv4-compatible", ["::/96"]), ("remotely triggered black hole", ["100::/64"]),
    ("ORCHID", ["2001:10::/28"]), ("documentation prefix", ["2001:db8::/32", "3fff::/20"]), ("ULA", ["fc00::/7"]),
    ("link-local unicast", ["fe80::/10"]), ("site-local unicast", ["fec0::/10"]), ("multicast v6", ["ff00::/8"]),
]
BOGONS = [(d, [ipaddress.ip_network(n) for n in nets]) for d, nets in _B]


def ip(x):
    return x if isinstance(x, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else ipaddress.ip_address(x)


def is_bogon(addr):
    """Description of the bogon range containing addr, or None (same order and ranges as Sniffnet)."""
    a = ip(addr)
    for desc, nets in BOGONS:
        for n in nets:
            if a.version == n.version and a in n:
                return desc
    return None


def is_broadcast(addr, mine):
    a = ip(addr)
    if a == ipaddress.IPv4Address("255.255.255.255"):
        return True
    return any((m.broadcast or ipaddress.IPv4Address("255.255.255.255")) == a for m in mine)


def is_my_address(addr, mine):
    a = ip(addr)
    return any(m.addr == a for m in mine) or a.is_loopback


def _same_net(local, mask, remote):
    if local.version != remote.version or mask is None:
        return False
    return all((m & l) == (m & r) for m, l, r in zip(mask.packed, local.packed, remote.packed))


def is_local_connection(addr, mine):
    """True when addr is on a network the capture interface belongs to (link-local counts as local)."""
    a, local = ip(addr), False
    for m in mine:
        if m.addr.version == 4 and a.version == 4:
            if a.is_link_local or _same_net(m.addr, m.netmask, a):
                local = True
        elif m.addr.version == 6 and a.version == 6:
            if a.is_link_local or _same_net(m.addr, m.netmask, a):
                local = True
    return local


INCOMING, OUTGOING = "incoming", "outgoing"


def traffic_direction(src, dst, sport, dport, mine):
    s, d = ip(src), ip(dst)
    if s.is_loopback and d.is_loopback and sport is not None and dport is not None:
        return OUTGOING if sport > dport else INCOMING

    def local(x):
        return (is_bogon(x) is not None) if not mine else any(m.addr == x for m in mine)
    if local(s):
        return OUTGOING
    if not s.is_unspecified:
        return INCOMING
    return OUTGOING if not local(d) else INCOMING


def traffic_type(dst, mine, direction):
    if direction == OUTGOING:
        d = ip(dst)
        if d.is_multicast:
            return "multicast"
        if is_broadcast(d, mine):
            return "broadcast"
    return "unicast"


def address_to_lookup(key, direction):
    return key.dst_ip if direction == OUTGOING else key.src_ip


def local_port(key, direction):
    p = key.src_port if direction == OUTGOING else key.dst_port
    return p if key.proto in ("TCP", "UDP") else None
