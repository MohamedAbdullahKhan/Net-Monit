"""Raw frame -> Packet. Link types as in Sniffnet's packet parser: NULL, ETHERNET, RAW(12/101), LOOP, IPV4, IPV6, LINUX_SLL, LINUX_SLL2.
Protocols counted: TCP, UDP, ICMP (v4), ICMPv6, IGMP, ARP. Everything else is ignored (returns None)."""
import socket
import struct
from collections import namedtuple

Packet = namedtuple("Packet", "length src_mac dst_mac vlan src_ip dst_ip src_port dst_port proto msg")

LINK_NULL, LINK_ETHERNET, LINK_RAW12, LINK_RAW, LINK_LOOP, LINK_SLL, LINK_SLL2, LINK_IPV4, LINK_IPV6 = 0, 1, 12, 101, 108, 113, 276, 228, 229
SUPPORTED_LINKS = {LINK_NULL, LINK_ETHERNET, LINK_RAW12, LINK_RAW, LINK_LOOP, LINK_SLL, LINK_SLL2, LINK_IPV4, LINK_IPV6}
LINK_NAMES = {0: "Null", 1: "Ethernet", 12: "Raw IP", 101: "Raw IP", 108: "Loop", 113: "Linux cooked (SLL)", 276: "Linux cooked v2 (SLL2)", 228: "IPv4", 229: "IPv6"}

ICMP4 = {0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench", 5: "Redirect", 6: "Alternate Host Address", 8: "Echo",
         9: "Router Advertisement", 10: "Router Solicitation", 11: "Time Exceeded", 12: "Parameter Problem", 13: "Timestamp",
         14: "Timestamp Reply", 15: "Information Request", 16: "Information Reply", 17: "Address Mask Request", 18: "Address Mask Reply",
         30: "Traceroute", 31: "Datagram Conversion Error", 32: "Mobile Host Redirect", 33: "IPv6 Where-Are-You", 34: "IPv6 I-Am-Here",
         35: "Mobile Registration Request", 36: "Mobile Registration Reply", 37: "Domain Name Request", 38: "Domain Name Reply", 39: "SKIP",
         40: "Photuris", 42: "Extended Echo Request", 43: "Extended Echo Reply"}
ICMP6 = {1: "Destination Unreachable", 2: "Packet Too Big", 3: "Time Exceeded", 4: "Parameter Problem", 128: "Echo Request", 129: "Echo Reply",
         130: "Multicast Listener Query", 131: "Multicast Listener Report", 132: "Multicast Listener Done", 133: "Router Solicitation",
         134: "Router Advertisement", 135: "Neighbor Solicitation", 136: "Neighbor Advertisement", 137: "Redirect Message",
         138: "Router Renumbering", 139: "ICMP Node Information Query", 140: "ICMP Node Information Response",
         146: "Mobile Prefix Solicitation", 147: "Mobile Prefix Advertisement", 151: "Multicast Router Advertisement",
         152: "Multicast Router Solicitation", 153: "Multicast Router Termination", 154: "FMIPv6 Messages", 155: "RPL Control Message",
         156: "ILNPv6 Locator Update Message", 157: "Duplicate Address Request", 158: "Duplicate Address Confirmation",
         159: "MPL Control Message", 160: "Extended Echo Request", 161: "Extended Echo Reply"}
IGMP = {0x11: "Membership Query", 0x12: "Membership Report v1", 0x16: "Membership Report v2", 0x22: "Membership Report v3", 0x17: "Leave Group",
        0x13: "DVMRP", 0x14: "PIM v1", 0x15: "Cisco Trace", 0x1e: "Multicast Traceroute Response", 0x1f: "Multicast Traceroute",
        0x30: "Multicast Router Advertisement", 0x31: "Multicast Router Solicitation", 0x32: "Multicast Router Termination"}
ARP = {1: "Request", 2: "Reply"}


def _mac(b):
    return ":".join("%02x" % x for x in b)


def _ip4(b):
    return socket.inet_ntop(socket.AF_INET, bytes(b))


def _ip6(b):
    return socket.inet_ntop(socket.AF_INET6, bytes(b))


def parse(data, link=LINK_ETHERNET, wire_len=None):
    """Parse one captured frame. Returns Packet or None (unsupported/truncated/uninteresting)."""
    n = len(data); length = wire_len or n
    src_mac = dst_mac = None; vlan = None
    try:
        if link == LINK_ETHERNET:
            if n < 14: return None
            dst_mac, src_mac, et = _mac(data[0:6]), _mac(data[6:12]), struct.unpack("!H", data[12:14])[0]
            off = 14
            while et in (0x8100, 0x88A8, 0x9100) and n >= off + 4:     # 802.1Q / QinQ: report the outermost tag
                tci, et = struct.unpack("!HH", data[off:off + 4]); vlan = vlan if vlan is not None else tci & 0x0FFF; off += 4
        elif link in (LINK_NULL, LINK_LOOP):
            if n < 4: return None
            af = struct.unpack("<I" if link == LINK_NULL else "!I", data[:4])[0]
            if link == LINK_NULL and af > 0xFFFF: af = struct.unpack("!I", data[:4])[0]
            et = 0x0800 if af == 2 else 0x86DD if af in (10, 23, 24, 28, 30) else None
            off = 4
        elif link in (LINK_RAW, LINK_RAW12, LINK_IPV4, LINK_IPV6):
            if n < 1: return None
            et = 0x0800 if link == LINK_IPV4 else 0x86DD if link == LINK_IPV6 else (0x0800 if data[0] >> 4 == 4 else 0x86DD if data[0] >> 4 == 6 else None)
            off = 0
        elif link == LINK_SLL:
            if n < 16: return None
            et = struct.unpack("!H", data[14:16])[0]; off = 16
            if data[10:16] != b"\x00" * 6: src_mac = _mac(data[6:6 + min(6, data[5])]) if data[5] >= 6 else None
        elif link == LINK_SLL2:
            if n < 20: return None
            et = struct.unpack("!H", data[0:2])[0]; off = 20
        else:
            return None
        if et == 0x0800: return _ipv4(data, off, n, length, src_mac, dst_mac, vlan)
        if et == 0x86DD: return _ipv6(data, off, n, length, src_mac, dst_mac, vlan)
        if et == 0x0806: return _arp(data, off, n, length, src_mac, dst_mac, vlan)
    except (struct.error, IndexError, ValueError):
        return None
    return None


def _transport(proto, data, off, n, v6):
    """-> (name, sport, dport, msg) or None."""
    if proto == 6:
        if n < off + 4: return ("TCP", None, None, None) if n >= off else None
        s, d = struct.unpack("!HH", data[off:off + 4]); return ("TCP", s, d, None)
    if proto == 17:
        if n < off + 4: return None
        s, d = struct.unpack("!HH", data[off:off + 4]); return ("UDP", s, d, None)
    if proto == 1 and not v6:
        return ("ICMP", None, None, ICMP4.get(data[off], "?") if n > off else "?")
    if proto == 58 and v6:
        return ("ICMPv6", None, None, ICMP6.get(data[off], "?") if n > off else "?")
    if proto == 2 and not v6:
        return ("IGMP", None, None, IGMP.get(data[off], "?") if n > off else "?")
    return None


def _ipv4(data, off, n, length, sm, dm, vlan):
    if n < off + 20: return None
    ihl = (data[off] & 0x0F) * 4
    if ihl < 20: return None
    proto = data[off + 9]; frag = struct.unpack("!H", data[off + 6:off + 8])[0] & 0x1FFF
    src, dst = _ip4(data[off + 12:off + 16]), _ip4(data[off + 16:off + 20])
    t = _transport(proto, data, off + ihl, n, False) if frag == 0 else None
    if t is None:
        if frag and proto in (6, 17): t = ("TCP" if proto == 6 else "UDP", None, None, None)   # later fragment: no ports
        else: return None
    return Packet(length, sm, dm, vlan, src, dst, t[1], t[2], t[0], t[3])


def _ipv6(data, off, n, length, sm, dm, vlan):
    if n < off + 40: return None
    nxt = data[off + 6]; src, dst = _ip6(data[off + 8:off + 24]), _ip6(data[off + 24:off + 40]); p = off + 40
    for _ in range(8):                                                  # walk extension headers
        if nxt in (0, 43, 60) and n >= p + 2:
            nxt, p = data[p], p + (data[p + 1] + 1) * 8
        elif nxt == 51 and n >= p + 2:
            nxt, p = data[p], p + (data[p + 1] + 2) * 4
        elif nxt == 44 and n >= p + 8:
            if struct.unpack("!H", data[p + 2:p + 4])[0] & 0xFFF8: return None   # later fragment
            nxt, p = data[p], p + 8
        else:
            break
    t = _transport(nxt, data, p, n, True)
    if t is None: return None
    return Packet(length, sm, dm, vlan, src, dst, t[1], t[2], t[0], t[3])


def _arp(data, off, n, length, sm, dm, vlan):
    if n < off + 28: return None
    htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", data[off:off + 8])
    if ptype != 0x0800 or plen != 4 or hlen != 6: return None
    sha, spa = data[off + 8:off + 14], data[off + 14:off + 18]; tpa = data[off + 24:off + 28]
    return Packet(length, sm or _mac(sha), dm, vlan, _ip4(spa), _ip4(tpa), None, None, "ARP", ARP.get(op, "?"))
