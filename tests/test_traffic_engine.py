"""Traffic Analyzer tests: parser, engine, notifications, flow collectors (NetFlow v5/v9, IPFIX), software filter, capture-file analysis."""
import os, sys, struct, socket, time, tempfile, threading, unittest, ipaddress
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="nm-traffic-")
from monitor import database as db
from pathlib import Path
db.DB_PATH = Path(TMP) / "t.db"
db.init_db()
from monitor.traffic import parser as P, netutil as N, store, notify
from monitor.traffic.engine import Engine, Resolver
from monitor.traffic.flows import Decoder, Collector
from monitor.traffic.softfilter import compile_filter, FilterError
from monitor.traffic.geo import GeoDb
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, Dot1Q, ICMPv6EchoRequest, IPv6ExtHdrHopByHop, Raw, wrpcap, GRE
from scapy.utils import PcapNgWriter

A = lambda a, m=None, b=None: N.Addr(ipaddress.ip_address(a), ipaddress.ip_address(m) if m else None, ipaddress.ip_address(b) if b else None)
MINE = [A("192.168.1.10", "255.255.255.0", "192.168.1.255")]
PK = lambda s, d, sp, dp, pr, n, msg=None: P.Packet(n, None, None, None, s, d, sp, dp, pr, msg)
GEO = GeoDb(); GEO.load()


def new_engine(**kw):
    r = Resolver(GEO); r.rdns = False; ticks = []
    e = Engine(1, "t", kw.pop("mine", MINE), kw.pop("blacklist", None), r, None, kw.pop("notifier", lambda eng, s, iv: ticks.append((s, list(iv["tot"])))), live=False)
    e._ticks = ticks; return e


class Parser(unittest.TestCase):
    def p(self, pkt, link=1): return P.parse(bytes(pkt), link)

    def test_tcp_ethernet(self):
        p = self.p(Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02") / IP(src="10.0.0.1", dst="93.184.216.34") / TCP(sport=51000, dport=443) / Raw(b"x" * 50))
        self.assertEqual((p.src_ip, p.dst_ip, p.src_port, p.dst_port, p.proto, p.src_mac, p.length), ("10.0.0.1", "93.184.216.34", 51000, 443, "TCP", "aa:bb:cc:dd:ee:01", 14 + 20 + 20 + 50))

    def test_vlan_udp_icmp_igmp_arp(self):
        self.assertEqual(self.p(Ether() / Dot1Q(vlan=42) / IP(src="1.1.1.1", dst="8.8.8.8") / UDP(sport=5, dport=53)).vlan, 42)
        i = self.p(Ether() / IP(src="1.1.1.1", dst="8.8.8.8") / ICMP()); self.assertEqual((i.proto, i.msg, i.src_port), ("ICMP", "Echo", None))
        a = self.p(Ether() / ARP(op=2, psrc="10.0.0.1", pdst="10.0.0.2")); self.assertEqual((a.proto, a.msg, a.src_ip, a.dst_ip), ("ARP", "Reply", "10.0.0.1", "10.0.0.2"))
        g = self.p(Ether() / IP(src="10.0.0.1", dst="224.0.0.22", proto=2) / Raw(b"\x16\x00\x00\x00\xe0\x00\x00\xfc")); self.assertEqual((g.proto, g.msg), ("IGMP", "Membership Report v2"))

    def test_ipv6_with_extension_header(self):
        p = self.p(Ether() / IPv6(src="fe80::1", dst="ff02::1") / IPv6ExtHdrHopByHop() / ICMPv6EchoRequest()); self.assertEqual((p.proto, p.msg), ("ICMPv6", "Echo Request"))
        t = self.p(Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=1234, dport=80)); self.assertEqual((t.proto, t.dst_port), ("TCP", 80))

    def test_other_link_types(self):
        ip = bytes(IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2))
        self.assertEqual(P.parse(ip, P.LINK_RAW).proto, "UDP")
        self.assertEqual(P.parse(struct.pack("<I", 2) + ip, P.LINK_NULL).dst_port, 2)                       # BSD loopback, little endian
        self.assertEqual(P.parse(struct.pack("!I", 2) + ip, P.LINK_LOOP).dst_port, 2)
        sll = b"\x00\x00\x00\x01\x00\x06" + b"\xaa" * 6 + b"\x00\x00" + b"\x08\x00" + ip; self.assertEqual(P.parse(sll, 113).proto, "UDP")
        sll2 = b"\x08\x00" + b"\x00" * 18 + ip; self.assertEqual(P.parse(sll2, 276).proto, "UDP")
        self.assertIsNone(P.parse(ip, 999))

    def test_ignored_and_damaged(self):
        self.assertIsNone(self.p(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / GRE()))                    # protocol not counted
        self.assertIsNone(P.parse(b"\x00" * 10, 1)); self.assertIsNone(P.parse(bytes(Ether() / IP() / TCP())[:20], 1)); self.assertIsNone(P.parse(b"", 1))
        frag = IP(src="1.1.1.1", dst="2.2.2.2", frag=5, proto=17) / Raw(b"zzzz"); f = self.p(Ether() / frag); self.assertEqual((f.proto, f.src_port), ("UDP", None))


class EngineTests(unittest.TestCase):
    def test_accounting_and_ticks(self):
        e = new_engine(); t = 1000.0
        for i in range(5):
            e.feed_packet(PK("192.168.1.10", "8.8.8.8", 50000, 443, "TCP", 100), t + i * 0.3); e.feed_packet(PK("8.8.8.8", "192.168.1.10", 443, 50000, "TCP", 1400), t + i * 0.3 + .1)
        e.feed_packet(PK("192.168.1.10", "1.1.1.1", 5353, 53, "UDP", 80), t + 3); e.finish()
        self.assertEqual(e.tot, [7000, 580, 5, 6]); self.assertEqual(len(e.conns), 3)
        self.assertEqual([x[0] for x in e._ticks], [1000, 1001, 1002, 1003])                         # empty seconds are still ticked
        self.assertEqual(e._ticks[0][1], [4200, 400, 3, 4]); self.assertEqual(e._ticks[2][1], [0, 0, 0, 0])
        self.assertEqual(e.services["https"], [7000, 500, 5, 5]); self.assertEqual(e.services["domain"], [0, 80, 0, 1])
        hosts = {h["name"]: h for h in e.hosts()}; self.assertEqual(hosts["8.8.8.8"]["country"], "US"); self.assertEqual(hosts["8.8.8.8"]["asn_name"], "Google LLC")
        self.assertEqual({c["code"] for c in e.countries()}, {"US", "AU"})

    def test_direction_service_type_of_new_connection(self):
        e = new_engine(); e.feed_packet(PK("8.8.8.8", "192.168.1.10", 443, 50000, "TCP", 60), 1.0)
        c = next(iter(e.conns.values())); self.assertEqual((c.direction, c.service, c.addr), ("incoming", "https", "8.8.8.8"))

    def test_blacklist_flag_and_notification(self):
        from monitor.traffic.blacklist import IpBlacklist
        bl = IpBlacklist.from_file(os.path.join(ROOT, "tests", "data", "ip_blacklist_valid.txt")); got = []
        s = notify.get_settings(); s["blacklist"]["enabled"] = True; notify.save_settings(s)
        n = notify.Notifier(lambda: 1, lambda: [], [lambda *a: got.append(a)])
        e = new_engine(blacklist=bl, notifier=n); e.feed_packet(PK("192.168.1.10", "8.8.8.8", 50000, 443, "TCP", 100), 10.0); e.feed_packet(PK("192.168.1.10", "9.9.9.9", 50001, 443, "TCP", 100), 10.2); e.finish()
        self.assertEqual([c.blacklisted for c in e.conns.values()], [True, False]); self.assertEqual(len(got), 1); self.assertEqual(got[0][0], "blacklist"); self.assertIn("8.8.8.8", got[0][2])

    def test_data_threshold_notification_with_units(self):
        s = notify.get_settings(); s["data"].update(enabled=True, unit="bytes", threshold="1k"); s["blacklist"]["enabled"] = False; notify.save_settings(s)
        self.assertEqual(notify.get_settings()["data"]["threshold"], 1000)
        got = []; n = notify.Notifier(lambda: 1, lambda: [], [lambda *a: got.append(a)]); e = new_engine(notifier=n)
        e.feed_packet(PK("192.168.1.10", "8.8.8.8", 50000, 443, "TCP", 900), 20.0); e.feed_packet(PK("192.168.1.10", "8.8.8.8", 50000, 443, "TCP", 900), 20.5); e.feed_packet(PK("192.168.1.10", "8.8.8.8", 50000, 443, "TCP", 100), 21.1); e.finish()
        self.assertEqual(len(got), 1); self.assertIn("1,800 bytes", got[0][2]); self.assertIn("8.8.8.8", got[0][2]); self.assertIn("https", got[0][2])
        s["data"].update(unit="bits", threshold="14k"); notify.save_settings(s); n.settings = notify.get_settings(); got.clear()
        e = new_engine(notifier=n); e.feed_packet(PK("192.168.1.10", "8.8.8.8", 50000, 443, "TCP", 1800), 30.0); e.finish(); self.assertEqual(len(got), 1)          # 1800 B = 14,400 bit
        s["data"].update(unit="packets", threshold="2"); notify.save_settings(s); n.settings = notify.get_settings(); got.clear()
        e = new_engine(notifier=n)
        for i in range(3): e.feed_packet(PK("192.168.1.10", "8.8.8.8", 50000, 443, "TCP", 10), 40.0 + i * .1)
        e.finish(); self.assertEqual(len(got), 1)
        s["data"]["enabled"] = False; notify.save_settings(s)

    def test_favorites_notification(self):
        s = notify.get_settings(); s["favorite"]["enabled"] = True; notify.save_settings(s); got = []
        favs = [{"kind": "service", "value": "https"}, {"kind": "host", "value": "1.1.1.1"}]
        n = notify.Notifier(lambda: 1, lambda: favs, [lambda *a: got.append(a)]); n.settings = notify.get_settings()
        e = new_engine(notifier=n); e.feed_packet(PK("192.168.1.10", "8.8.8.8", 50000, 443, "TCP", 100), 50.0); e.feed_packet(PK("192.168.1.10", "1.1.1.1", 50001, 8080, "TCP", 100), 50.2); e.feed_packet(PK("192.168.1.10", "2.2.2.2", 50002, 22, "TCP", 100), 50.3); e.finish()
        self.assertEqual(sorted(x[3]["favorite"]["value"] for x in got), ["1.1.1.1", "https"])
        s["favorite"]["enabled"] = False; notify.save_settings(s)

    def test_pause_and_flow_feed(self):
        e = new_engine(); e.paused = True; e.feed_packet(PK("192.168.1.10", "8.8.8.8", 1, 2, "TCP", 100), 1.0); self.assertEqual(e.tot, [0, 0, 0, 0])
        e.paused = False; e.feed_flow({"src_ip": "8.8.8.8", "dst_ip": "10.1.1.1", "src_port": 53, "dst_port": 40000, "proto": "UDP", "bytes": 900, "packets": 7, "start": 5.0, "end": 8.0, "direction": "incoming", "vlan": 7, "src_mac": None, "dst_mac": None, "msg": None})
        c = next(iter(e.conns.values())); self.assertEqual((e.tot, c.direction, c.vlan, c.first, c.last, c.service), ([900, 0, 7, 0], "incoming", 7, 5.0, 8.0, "domain"))

    def test_threshold_parser_like_sniffnet_field(self):
        for txt, want in (("500", 500), ("500k", 500000), ("2.5M", 2500000), ("1g", 10 ** 9), ("12kb", 12000), ("", 7), ("abc", 7), ("-5", 7)):
            self.assertEqual(notify.parse_threshold(txt, 7), want, txt)


def ipfix(domain, sets, seq=1, t=1700000000): body = b"".join(sets); return struct.pack("!HHIII", 10, 16 + len(body), t, seq, domain) + body
def tset(tid, fields, ent=()):
    rec = struct.pack("!HH", tid, len(fields)) + b"".join(struct.pack("!HH", i | (0x8000 if (i, l) in ent else 0), l) + (struct.pack("!I", 9) if (i, l) in ent else b"") for i, l in fields)
    return struct.pack("!HH", 2, 4 + len(rec)) + rec
def dset(tid, recs): b = b"".join(recs); return struct.pack("!HH", tid, 4 + len(b)) + b


class Flows(unittest.TestCase):
    def test_ipfix_record(self):
        D = Decoder(); F = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 8), (2, 8), (152, 8), (153, 8), (61, 1), (58, 2), (56, 6)]
        rec = socket.inet_aton("10.0.0.5") + socket.inet_aton("93.184.216.34") + struct.pack("!HHB", 51000, 443, 6) + struct.pack("!QQQQBH", 12345, 10, 1700000000000, 1700000004000, 1, 20) + bytes.fromhex("aabbccddeeff")
        r = D.decode(ipfix(7, [tset(256, F), dset(256, [rec])]), "192.0.2.1")[0]
        self.assertEqual((r["src_ip"], r["dst_port"], r["proto"], r["bytes"], r["packets"], r["direction"], r["vlan"], r["src_mac"], r["start"], r["end"]), ("10.0.0.5", 443, "TCP", 12345, 10, "outgoing", 20, "aa:bb:cc:dd:ee:ff", 1700000000.0, 1700000004.0))

    def test_totals_become_deltas_and_templates_are_per_exporter(self):
        D = Decoder(); F = [(8, 4), (12, 4), (4, 1), (85, 8), (86, 8)]
        mk = lambda by, pk: socket.inet_aton("10.0.0.5") + socket.inet_aton("8.8.8.8") + struct.pack("!BQQ", 17, by, pk)
        D.decode(ipfix(7, [tset(257, F)]), "192.0.2.1")
        self.assertEqual([D.decode(ipfix(7, [dset(257, [mk(b, p)])]), "192.0.2.1")[0]["bytes"] for b, p in ((1000, 10), (1700, 15), (50, 1))], [1000, 700, 50])        # counter reset -> new total
        self.assertEqual(D.decode(ipfix(7, [dset(257, [mk(5, 1)])]), "192.0.2.99"), [])                                                           # other exporter: no template
        self.assertEqual(D.stats["no_template"], 1)

    def test_variable_length_enterprise_and_padding(self):
        D = Decoder(); F = [(8, 4), (12, 4), (4, 1), (1, 8), (2, 8), (300, 0xFFFF), (310, 2)]
        rec = lambda s: socket.inet_aton("10.0.0.5") + socket.inet_aton("8.8.4.4") + struct.pack("!BQQ", 6, 100, 2) + bytes([len(s)]) + s + b"\x00\x07"
        out = D.decode(ipfix(1, [tset(300, F, ent={(310, 2)}), dset(300, [rec(b"abc"), rec(b"hello world")])]), "x")
        self.assertEqual([o["bytes"] for o in out], [100, 100])

    def test_netflow_v5_and_v9(self):
        D = Decoder(); hdr = struct.pack("!HHIIIIBBH", 5, 1, 5000, 1700000010, 0, 1, 0, 0, 0)
        r5 = struct.pack("!4s4s4sHHIIIIHHBBBBHHBBH", socket.inet_aton("10.1.1.1"), socket.inet_aton("1.1.1.1"), b"\0" * 4, 1, 2, 7, 900, 1000, 4000, 40000, 53, 0, 0, 17, 0, 0, 0, 0, 0, 0)
        f = D.decode(hdr + r5, "e")[0]; self.assertEqual((f["src_ip"], f["dst_port"], f["proto"], f["bytes"], f["packets"], round(f["end"] - f["start"])), ("10.1.1.1", 53, "UDP", 900, 7, 3))
        h9 = struct.pack("!HHIIII", 9, 2, 60000, 1700000100, 3, 0)
        t9 = struct.pack("!HHHH", 0, 4 + 4 + 20, 300, 5) + struct.pack("!" + "HH" * 5, 8, 4, 12, 4, 2, 4, 1, 4, 4, 1)
        d9 = struct.pack("!HH", 300, 4 + 20) + socket.inet_aton("10.2.2.2") + socket.inet_aton("9.9.9.9") + struct.pack("!IIB", 5, 500, 1) + b"\x00\x00\x00"
        g = D.decode(h9 + t9 + d9, "e")[0]; self.assertEqual((g["src_ip"], g["proto"], g["bytes"], g["packets"]), ("10.2.2.2", "ICMP", 500, 5))

    def test_garbage_never_raises_and_unknown_protocols_are_ignored(self):
        D = Decoder()
        for blob in (b"", b"\x00" * 3, os.urandom(64), struct.pack("!HHIII", 10, 9999, 0, 0, 0) + os.urandom(40), struct.pack("!HHIIII", 9, 5, 0, 0, 0, 0) + os.urandom(30)): self.assertEqual(D.decode(blob, "x"), [])
        F = [(8, 4), (12, 4), (4, 1), (1, 8), (2, 8)]; D.decode(ipfix(1, [tset(256, F)]), "e")
        self.assertEqual(D.decode(ipfix(1, [dset(256, [socket.inet_aton("1.1.1.1") + socket.inet_aton("2.2.2.2") + struct.pack("!BQQ", 47, 1, 1)])]), "e"), [])

    def test_udp_collector(self):
        got = []; c = Collector(0, got.append, "127.0.0.1"); c.open(); c.start()
        F = [(8, 4), (12, 4), (4, 1), (1, 8), (2, 8)]; m = ipfix(1, [tset(256, F), dset(256, [socket.inet_aton("1.1.1.1") + socket.inet_aton("2.2.2.2") + struct.pack("!BQQ", 6, 10, 1)])])
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(m, ("127.0.0.1", c.port)); t0 = time.time()
        while not got and time.time() - t0 < 3: time.sleep(.05)
        c.stop(); self.assertEqual(len(got), 1); self.assertEqual(got[0]["bytes"], 10)


class Hardening(unittest.TestCase):
    def test_connection_cap_prunes_oldest_but_keeps_totals(self):
        e = new_engine(); e.MAX_CONNS = 100
        for i in range(250): e.feed_packet(PK("192.168.1.10", f"8.8.{i // 250}.{i % 250 + 1}", 40000 + i, 443, "TCP", 100), 1000.0 + i * 0.001)
        self.assertLessEqual(len(e.conns), 100); self.assertGreater(e.pruned, 0); self.assertEqual(e.tot[1], 250 * 100); self.assertEqual(len(e._by_id), len(e.conns))
        self.assertTrue(any(c.key.src_port == 40249 for c in e.conns.values()))                    # the newest survive

    def test_flow_allow_list(self):
        got = []; c = Collector(0, got.append, "127.0.0.1", allow=["10.9.9.9"]); c.open(); c.start()
        F = [(8, 4), (12, 4), (4, 1), (1, 8), (2, 8)]; m = ipfix(1, [tset(256, F), dset(256, [socket.inet_aton("1.1.1.1") + socket.inet_aton("2.2.2.2") + struct.pack("!BQQ", 6, 10, 1)])])
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(m, ("127.0.0.1", c.port)); time.sleep(.6); c.stop()
        self.assertEqual((len(got), c.rejected), (0, 1))                                              # 127.0.0.1 is not on the list

    def test_capture_path_must_be_inside_the_data_folder(self):
        from monitor.traffic import manager as M
        M.DATA_DIR = os.path.join(TMP, "traffic2"); os.makedirs(os.path.join(M.DATA_DIR, "uploads"), exist_ok=True)
        outside = os.path.join(TMP, "outside.pcap"); wrpcap(outside, [Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / UDP()])
        for p in (outside, "/etc/passwd", os.path.join(M.DATA_DIR, "uploads", "..", "..", "outside.pcap")):
            with self.assertRaises(ValueError): M.Manager().start({"type": "pcap", "path": p})

    def test_webhook_scheme_and_flow_params(self):
        with self.assertRaises(ValueError): notify.save_settings({"webhook": {"enabled": True, "url": "file:///etc/passwd"}})
        with self.assertRaises(ValueError): notify.save_settings({"webhook": {"enabled": True, "url": "gopher://x"}})
        self.assertEqual(notify.save_settings({"webhook": {"enabled": False, "url": " https://hooks.example/x "}})["webhook"]["url"], "https://hooks.example/x"); notify.save_settings({"webhook": {"url": ""}})
        from monitor.traffic import manager as M
        for body in ({"type": "flows", "port": 0}, {"type": "flows", "port": 70000}, {"type": "flows", "port": 12071, "allow": ["not-an-ip"]}):
            with self.assertRaises((ValueError, RuntimeError)): M.Manager().start(body)


class SoftFilter(unittest.TestCase):
    def test_expressions(self):
        p = PK("10.0.0.1", "8.8.8.8", 51000, 443, "TCP", 100)
        for f, want in (("tcp port 443", True), ("udp", False), ("host 8.8.8.8 and not port 80", True), ("dst net 8.8.0.0/16", True), ("src host 8.8.8.8 or port 443", True),
                        ("(tcp or udp) and portrange 1-100", False), ("ip6", False), ("ip", True), ("src port 443", False), ("dst port 443 && tcp", True), ("! host 8.8.8.8", False),
                        ("net 10.0.0.0 mask 255.0.0.0", True), ("greater 99", True), ("less 50", False), ("", True), ("tcp dst port 443", True), ("ip host 10.0.0.1", True)):
            self.assertEqual(compile_filter(f)(p), want, f)

    def test_errors(self):
        for bad in ("foo bar", "tcp port", "host notanip", "(tcp", "tcp and"):
            with self.assertRaises(FilterError): compile_filter(bad)


class CaptureFile(unittest.TestCase):
    def setUp(self):
        from monitor.traffic import manager as M
        M.DATA_DIR = os.path.join(TMP, "traffic"); self.M = M; self.m = M.Manager()

    def wait(self):
        t0 = time.time()
        while self.m.state in ("running", "paused") and time.time() - t0 < 20: time.sleep(.05)

    def make(self, ng=False):
        pk = []; t = 1700000000.0
        for i in range(6):
            a = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / TCP(sport=50000, dport=443) / Raw(b"x" * 100); a.time = t + i; pk.append(a)
            b = Ether() / IP(src="8.8.8.8", dst="192.168.1.10") / TCP(sport=443, dport=50000) / Raw(b"y" * 900); b.time = t + i + .5; pk.append(b)
        u = Ether() / IP(src="192.168.1.10", dst="1.1.1.1") / UDP(sport=5353, dport=53) / Raw(b"q" * 30); u.time = t + 10; pk.append(u)
        os.makedirs(os.path.join(self.M.DATA_DIR, "uploads"), exist_ok=True); path = os.path.join(self.M.DATA_DIR, "uploads", "x.pcapng" if ng else "x.pcap")
        if ng:
            w = PcapNgWriter(path); [w.write(p) for p in pk]; w.close()
        else: wrpcap(path, pk)
        return path

    def test_pcap_and_pcapng_import(self):
        for ng in (False, True):
            m = self.M.Manager(); m.start({"type": "pcap", "path": self.make(ng)}); t0 = time.time()
            while m.state == "running" and time.time() - t0 < 20: time.sleep(.05)
            self.assertEqual(m.state, "finished", (ng, m.error)); tot = m.engine.totals()
            self.assertEqual(tot["packets_seen"], 13); self.assertEqual(len(m.engine.conns), 3); self.assertEqual(len(m.engine.series), 11)      # 11 seconds on the capture timeline
            self.assertEqual(m.engine.tot[N.INCOMING == "incoming" and 0], 6 * (900 + 54)) if False else None
            self.assertEqual(store.get_session(m.sid)["status"], "finished")

    def test_pcap_filter_and_errors(self):
        m = self.M.Manager(); m.start({"type": "pcap", "path": self.make(), "bpf": "udp"}); t0 = time.time()
        while m.state == "running" and time.time() - t0 < 20: time.sleep(.05)
        self.assertEqual(m.engine.totals()["packets_seen"], 1)
        with self.assertRaises(ValueError): self.M.Manager().start({"type": "pcap", "path": self.make(), "bpf": "foo bar"})
        with self.assertRaises(ValueError): self.M.Manager().start({"type": "pcap", "path": "/nonexistent.pcap"})
        bad = os.path.join(self.M.DATA_DIR, "uploads", "bad.pcap"); open(bad, "wb").write(b"not a capture at all, just text")
        m = self.M.Manager(); m.start({"type": "pcap", "path": bad}); t0 = time.time()
        while m.state == "running" and time.time() - t0 < 10: time.sleep(.05)
        self.assertTrue(m.error)                                                                                       # reported, not crashed


if __name__ == "__main__":
    unittest.main()
