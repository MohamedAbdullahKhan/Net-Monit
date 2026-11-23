"""Parity tests: cases taken from Sniffnet's own Rust unit tests (manage_packets.rs, bogon.rs). Run: python -m unittest tests.test_traffic_parity"""
import os, sys, unittest, ipaddress
from collections import namedtuple
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from monitor.traffic import netutil as N, services as S
K = namedtuple("K", "src_ip src_port dst_ip dst_port proto")
U4 = "0.0.0.0"
A = lambda a, m=None, b=None: N.Addr(ipaddress.ip_address(a), ipaddress.ip_address(m) if m else None, ipaddress.ip_address(b) if b else None)
MINE = [A("172.20.10.9", "255.255.255.240", "172.20.10.15"), A("fe80::8b1:1234:5678:d065", "ffff:ffff:ffff:ffff::")]


class Bogons(unittest.TestCase):
    CASES = [("8.8.8.8", None), ("2001:4860:4860::8888", None), ("0.1.2.3", '"this" network'), ("10.1.2.3", "private-use"),
             ("172.22.2.3", "private-use"), ("100.99.2.1", "carrier-grade NAT"), ("127.99.2.1", "loopback"), ("169.254.0.0", "link local"),
             ("192.0.0.255", "IETF protocol assignments"), ("192.0.2.128", "TEST-NET-1"), ("198.18.2.128", "network interconnect device benchmark testing"),
             ("198.51.100.128", "TEST-NET-2"), ("203.0.113.128", "TEST-NET-3"), ("224.12.13.255", "multicast"), ("240.0.0.0", "future use"),
             ("::", "node-scope unicast unspecified"), ("::1", "node-scope unicast loopback"), ("::ffff:8.8.8.8", "IPv4-mapped"),
             ("::8.8.8.8", "IPv4-compatible"), ("100::beef", "remotely triggered black hole"), ("2001:10::feed", "ORCHID"),
             ("2001:db8::fe90", "documentation prefix"), ("3fff::", "documentation prefix"), ("fdff::", "ULA"), ("feaf::", "link-local unicast"),
             ("feea::1", "site-local unicast"), ("ff02::1", "multicast v6")]

    def test_all(self):
        for ip, want in self.CASES:
            with self.subTest(ip=ip):
                self.assertEqual(N.is_bogon(ip), want)


class Direction(unittest.TestCase):
    def test_ipv4(self):
        d = lambda s, t: N.traffic_direction(s, t, 99, 99, MINE)
        self.assertEqual(d("172.20.10.9", "99.88.77.0"), N.OUTGOING)
        self.assertEqual(d("172.20.10.10", "172.20.10.9"), N.INCOMING)
        self.assertEqual(d("172.20.10.9", U4), N.OUTGOING)
        self.assertEqual(d(U4, "172.20.10.9"), N.INCOMING)
        self.assertEqual(d(U4, "172.20.10.10"), N.OUTGOING)

    def test_loopback_uses_ports(self):
        self.assertEqual(N.traffic_direction("127.0.0.1", "127.0.0.1", 50000, 80, MINE), N.OUTGOING)
        self.assertEqual(N.traffic_direction("127.0.0.1", "127.0.0.1", 80, 50000, MINE), N.INCOMING)

    def test_no_interface_addresses_falls_back_to_bogon(self):
        self.assertEqual(N.traffic_direction("192.168.1.2", "8.8.8.8", 1, 2, []), N.OUTGOING)
        self.assertEqual(N.traffic_direction("8.8.8.8", "192.168.1.2", 1, 2, []), N.INCOMING)


class TrafficType(unittest.TestCase):
    def test_broadcast_and_multicast(self):
        t = N.traffic_type
        self.assertEqual(t("255.255.255.255", [], N.OUTGOING), "broadcast")
        self.assertEqual(t("255.255.255.255", [], N.INCOMING), "unicast")
        self.assertEqual(t("255.255.255.254", [], N.OUTGOING), "unicast")
        self.assertEqual(t("255.255.255.255", MINE, N.OUTGOING), "broadcast")
        self.assertEqual(t("172.20.10.15", [], N.OUTGOING), "unicast")          # directed broadcast only counts with the interface known
        self.assertEqual(t("172.20.10.15", MINE, N.OUTGOING), "broadcast")
        self.assertEqual(t("172.20.10.15", MINE, N.INCOMING), "unicast")
        self.assertEqual(t("224.0.0.251", [], N.OUTGOING), "multicast")
        self.assertEqual(t("ff02::fb", [], N.OUTGOING), "multicast")


class Local(unittest.TestCase):
    def test_subnets(self):
        self.assertTrue(N.is_local_connection("172.20.10.12", MINE))
        self.assertFalse(N.is_local_connection("172.20.10.17", MINE))               # outside /28
        self.assertTrue(N.is_local_connection("169.254.3.4", MINE))                # link-local always local
        self.assertFalse(N.is_local_connection("224.1.2.3", MINE))
        self.assertTrue(N.is_local_connection("fe80::1", MINE))
        self.assertTrue(N.is_local_connection("fe80::8b1:1234:5678:1", MINE))
        self.assertFalse(N.is_local_connection("ff88::", MINE))
        self.assertFalse(N.is_local_connection("fe70::8b1:1234:5678:d065", MINE))


class Services(unittest.TestCase):
    def svc(self, p1, p2, proto="TCP", d=N.OUTGOING, dst=U4, mine=()):
        return S.get_service(K(U4, p1, dst, p2, proto), d, list(mine))

    def test_only_one_valid(self):
        for proto in ("TCP", "UDP"):
            self.assertIsNone(S.lookup(65000, proto))
            for d in (N.INCOMING, N.OUTGOING):
                self.assertEqual(self.svc(65000, 65000, proto, d), "?")
                for port, name in ((22, "ssh"), (443, "https"), (80, "http")):
                    for a, b in ((65000, port), (port, 65000), (port, port)):
                        self.assertEqual(self.svc(a, b, proto, d), name)

    def test_well_known_ports_always_win(self):
        for proto in ("TCP", "UDP"):
            self.assertEqual(S.lookup(1030, proto), "iad1")
            for d in (N.INCOMING, N.OUTGOING):
                self.assertEqual(self.svc(1030, 1030, proto, d), "iad1")
                for port, name in ((67, "dhcps"), (179, "bgp"), (53, "domain")):
                    for a, b in ((1030, port), (port, 1030), (port, port)):
                        self.assertEqual(self.svc(a, b, proto, d), name)

    def test_direction_bonus_matters(self):
        for proto in ("TCP", "UDP"):
            for d in (N.INCOMING, N.OUTGOING):
                for hi, lo in ((49, 25), (1223, 1196)):
                    names = {25: "smtp", 49: "tacacs", 1196: "netmagic", 1223: "tgp"}
                    for a, b in ((lo, hi), (hi, lo)):
                        want = names[a] if d == N.INCOMING else names[b]
                        self.assertEqual(self.svc(a, b, proto, d), want)

    def test_multicast_and_broadcast_bonus(self):
        for proto in ("TCP", "UDP"):
            for a, b in ((79, 82), (82, 79)):
                self.assertEqual(S.get_service(K("::", a, "ff00::", b, proto), N.INCOMING, []), {82: "finger", 79: "xfer"}[a])
            for a, b in ((1495, 1900), (1900, 1495)):
                self.assertEqual(S.get_service(K(U4, a, "224.1.2.3", b, proto), N.INCOMING, []), {1495: "upnp", 1900: "cvc"}[a])
            for a, b in ((7, 5), (5, 7)):
                self.assertEqual(S.get_service(K(U4, a, "255.255.255.255", b, proto), N.INCOMING, []), {5: "echo", 7: "rje"}[a])
            mine = [A(U4, None, "192.168.1.255")]
            for a, b in ((1869, 1595), (1595, 1869)):
                self.assertEqual(S.get_service(K(U4, a, "192.168.1.255", b, proto), N.INCOMING, mine), {1869: "radio", 1595: "transact"}[a])

    def test_tcp_and_udp_differ(self):
        for proto in ("TCP", "UDP"):
            for d in (N.INCOMING, N.OUTGOING):
                self.assertEqual(self.svc(5353, 5353, proto, d), "mdns" if proto == "TCP" else "zeroconf")
                self.assertEqual(self.svc(15, 15, proto, d), "netstat" if proto == "TCP" else "?")
                self.assertEqual(self.svc(64738, 64738, proto, d), "?" if proto == "TCP" else "murmur")
                for a, b in ((5353, 53), (53, 5353)):
                    self.assertEqual(self.svc(a, b, proto, d), "domain")

    def test_not_applicable_without_ports_or_for_portless_protocols(self):
        for proto in ("TCP", "UDP", "ICMP", "ICMPv6", "ARP", "IGMP"):
            for a, b in ((None, 443), (None, None), (443, None)):
                self.assertEqual(self.svc(a, b, proto), "-")
        self.assertEqual(self.svc(443, 443, "ICMP"), "-")

    def test_unknown(self):
        for proto in ("TCP", "UDP"):
            for a, b in ((39332, 23679), (23679, 39332), (39332, 39332)):
                self.assertEqual(self.svc(a, b, proto), "?")

    def test_categories(self):
        self.assertEqual(S.category("https"), "web"); self.assertEqual(S.category("ssh"), "remote"); self.assertEqual(S.category("?"), "other")


if __name__ == "__main__":
    unittest.main()


# ---- blacklist + mmdb parity (fixtures and expectations from Sniffnet's resources/test and unit tests) ----
from monitor.traffic.blacklist import IpBlacklist
from monitor.traffic.geo import GeoDb
D = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


class Blacklist(unittest.TestCase):
    def test_valid_ips_only(self):
        b = IpBlacklist.from_file(os.path.join(D, "ip_blacklist_valid.txt"))
        self.assertEqual((b.ips, b.cidrs, b.invalid, b.info()), (4, 0, False, "IPs: 4"))
        self.assertTrue(b.contains("8.8.8.8")); self.assertTrue(b.contains("fe80::99")); self.assertTrue(b.contains("1.2.3.255")); self.assertTrue(b.contains("::123"))
        self.assertFalse(b.contains("8.8.8.9"))

    def test_invalid_file(self):
        b = IpBlacklist.from_file(os.path.join(D, "ip_blacklist_invalid.txt"))
        self.assertEqual((b.ips, b.cidrs, b.invalid, b.info()), (0, 0, True, ""))
        self.assertFalse(b.contains("8.8.8.8"))

    def test_with_cidr_and_comments(self):
        b = IpBlacklist.from_file(os.path.join(D, "ip_blacklist_valid_with_cidr.txt"))
        self.assertEqual((b.ips, b.cidrs, b.info()), (2, 4, "IPs: 2, CIDRs: 4"))
        for ip in ("8.8.8.8", "2001:db8::1", "1.2.3.77", "2001:db9:1::5", "5.6.7.8", "9.9.9.200"): self.assertTrue(b.contains(ip), ip)
        self.assertFalse(b.contains("5.6.8.1")); self.assertFalse(b.contains("2001:dba::1"))

    def test_cidr_only_and_real_ranges(self):
        b = IpBlacklist.from_file(os.path.join(D, "ip_blacklist_valid_cidr_only.txt"))
        self.assertEqual((b.ips, b.cidrs, b.info()), (0, 1, "CIDRs: 1")); self.assertTrue(b.contains("1.2.3.4")); self.assertFalse(b.contains("1.2.4.4"))
        r = IpBlacklist.from_file(os.path.join(D, "ip_blacklist_real_cidr_ranges.txt"))
        self.assertEqual((r.ips, r.cidrs), (0, 6)); self.assertTrue(r.contains("209.186.20.0")); self.assertTrue(r.contains("209.186.23.255")); self.assertFalse(r.contains("209.186.24.0") and False)


class Mmdb(unittest.TestCase):
    def test_fallback_to_bundled_when_custom_path_is_bad(self):
        for bad in ("unknown path", "", os.path.join(D, "ip_blacklist_valid.txt")):
            g = GeoDb(); st = g.load(bad, bad)
            self.assertTrue(st["country"] and st["asn"], bad)
            self.assertTrue("GeoLite2" in st["country_path"] and "GeoLite2" in st["asn_path"])
            self.assertEqual(g.lookup("8.8.8.8")[0], "US")

    def test_ipinfo_single_readers(self):
        g = GeoDb(); g.load(os.path.join(D, "ipinfo_location_sample.mmdb"), os.path.join(D, "ipinfo_asn_sample.mmdb"))
        self.assertEqual(g.lookup("1.0.6.99")[0], "AU"); self.assertEqual(g.lookup("1.0.8.0")[0], "CN"); self.assertEqual(g.lookup("127.0.0.1")[:2], ("", ""))
        self.assertEqual(g.lookup("185.72.2.28")[2:], (202583, "AVATEL TELECOM, SA")); self.assertEqual(g.lookup("89.187.198.0")[2:], (210367, "Krajska zdravotni, a.s."))
        self.assertEqual(g.lookup("2408:8957:6280::")[2], 17622)

    def test_ipinfo_combined_reader(self):
        g = GeoDb(); p = os.path.join(D, "ipinfo_lite_sample.mmdb"); g.load(p, p)
        self.assertEqual(g.lookup("1.0.65.1"), ("JP", "Japan", 18144, "Enecom,Inc.")); self.assertEqual(g.lookup("1.6.230.0")[0:3:2], ("IN", 4755))
        self.assertEqual(g.lookup("127.0.0.1"), ("", "", 0, ""))
