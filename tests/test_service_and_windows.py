"""V12.0 patch 01: port fallback, Windows built-in capture (fake raw sockets), backend selection, interface list without scapy."""
import os, sys, time, socket, struct, tempfile, unittest, threading, shutil
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="nm-svc-")
from pathlib import Path
from monitor import database as db
db.DB_PATH = Path(TMP) / "t.db"; db.init_db()
from monitor import portcheck
from monitor.traffic import manager as M, capture_windows as CW, parser as P, store
from scapy.all import IP, TCP, UDP, Raw, RawPcapReader


def ip_packet(src, dst, sport, dport, size=100): return bytes(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport) / Raw(b"x" * size))


class PortFallback(unittest.TestCase):
    def test_free_port_is_kept(self):
        s = socket.socket(); s.bind(("0.0.0.0", 0)); free = s.getsockname()[1]; s.close()
        self.assertEqual(portcheck.pick_port(free), (free, ""))

    def test_taken_port_moves_to_the_next_free_one_and_says_why(self):
        a = socket.socket(); a.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0); a.bind(("0.0.0.0", 0)); a.listen(1); taken = a.getsockname()[1]
        try:
            port, why = portcheck.pick_port(taken); self.assertNotEqual(port, taken); self.assertGreater(port, taken); self.assertIn(str(taken), why); self.assertIn("not available", why)
        finally: a.close()

    def test_windows_reserved_port_error_is_skipped(self):
        real = portcheck.can_bind
        def fake(port, host="0.0.0.0"):
            return (False, "An attempt was made to access a socket in a manner forbidden by its access permissions (errno 10013)") if port < 50123 else real(port, host)
        portcheck.can_bind = fake
        try:
            port, why = portcheck.pick_port(50120); self.assertGreaterEqual(port, 50123); self.assertIn("10013", why)
        finally: portcheck.can_bind = real

    def test_gives_up_with_a_clear_error(self):
        real = portcheck.can_bind; portcheck.can_bind = lambda p, h="0.0.0.0": (False, "denied")
        try:
            with self.assertRaises(OSError) as c: portcheck.pick_port(50120, span=3)
            self.assertIn("No free port", str(c.exception))
        finally: portcheck.can_bind = real

    def test_remember_writes_the_active_port(self):
        portcheck.remember(TMP, 50133); self.assertEqual(open(os.path.join(TMP, "data", "active_port.txt")).read(), "50133")


class FakeSock:
    def __init__(self, frames, fail_ioctl=False): self.frames, self.closed, self.rcvall = list(frames), False, None; self.fail = fail_ioctl
    def settimeout(self, t): pass
    def recvfrom(self, n):
        if self.frames: return self.frames.pop(0), ("0.0.0.0", 0)
        time.sleep(0.05); raise socket.timeout()
    def ioctl(self, code, opt): self.rcvall = opt
    def close(self): self.closed = True


class WindowsCapture(unittest.TestCase):
    def test_frames_flow_through_as_raw_ip(self):
        got = []; socks = {}
        def factory(addr, v6): socks[addr] = FakeSock([ip_packet("10.0.0.5", "8.8.8.8", 50000, 443), ip_packet("8.8.8.8", "10.0.0.5", 443, 50000)]); return socks[addr]
        sn = CW.RawWindowsSniffer(["10.0.0.5", "127.0.0.1", "169.254.1.1", "fe80::1"], lambda raw, link, ts: got.append((raw, link)), factory); sn.start(); time.sleep(.4); sn.stop()
        self.assertEqual(sorted(socks), ["10.0.0.5"])                                                    # loopback / link-local are skipped
        self.assertEqual(len(got), 2); self.assertTrue(all(l == CW.LINK_RAW for _, l in got))
        p = P.parse(got[0][0], got[0][1]); self.assertEqual((p.src_ip, p.dst_port, p.proto, p.src_mac), ("10.0.0.5", 443, "TCP", None))
        self.assertTrue(socks["10.0.0.5"].closed); self.assertEqual(socks["10.0.0.5"].rcvall, CW.RCVALL_OFF)

    def test_errors_are_explained(self):
        def denied(a, v6): raise PermissionError("x")
        with self.assertRaises(PermissionError) as c: CW.RawWindowsSniffer(["10.0.0.5"], lambda *a: None, denied).start()
        self.assertIn("Administrator", str(c.exception))
        def broken(a, v6): raise OSError("WinError 10013")
        with self.assertRaises(OSError) as c: CW.RawWindowsSniffer(["10.0.0.5"], lambda *a: None, broken).start()
        self.assertIn("raw capture socket", str(c.exception)); self.assertIn("Npcap", str(c.exception))
        with self.assertRaises(OSError): CW.RawWindowsSniffer(["127.0.0.1"], lambda *a: None, lambda a, v: FakeSock([])).start()               # nothing capturable

    def test_one_failing_address_does_not_stop_the_others(self):
        socks = {}
        def f(addr, v6):
            if addr == "10.0.0.9": raise OSError("nope")
            socks[addr] = FakeSock([ip_packet("10.0.0.5", "8.8.8.8", 1, 2)]); return socks[addr]
        got = []; sn = CW.RawWindowsSniffer(["10.0.0.9", "10.0.0.5"], lambda r, l, t: got.append(1), f); sn.start(); time.sleep(.3); sn.stop(); self.assertEqual(len(got), 1)

    def test_manager_uses_it_on_windows_without_npcap_and_exports_raw_pcap(self):
        M.DATA_DIR = os.path.join(TMP, "traffic"); os.makedirs(M.DATA_DIR, exist_ok=True)
        saved = (sys.platform, M.npcap_installed, M.RawWindowsSniffer, M.interfaces)
        class Fake(CW.RawWindowsSniffer):
            def __init__(self, addrs, cb): super().__init__(addrs, cb, lambda a, v6: FakeSock([ip_packet("10.0.0.5", "8.8.8.8", 50000, 443, 200), ip_packet("8.8.8.8", "10.0.0.5", 443, 50000, 1000), ip_packet("10.0.0.5", "1.1.1.1", 50001, 80)]))
        try:
            sys.platform = "win32"; M.npcap_installed = lambda: False; M.RawWindowsSniffer = Fake
            M.interfaces = lambda: [{"name": "Ethernet", "description": "", "up": True, "addresses": [{"addr": "10.0.0.5", "netmask": "255.255.255.0", "broadcast": None}]}]
            m = M.Manager(); st = m.start({"type": "device", "iface": "Ethernet", "bpf": "tcp port 443", "export_pcap": True}); time.sleep(1.0)
            self.assertEqual(st["capture_backend"], "Windows built-in capture (no Npcap needed)"); self.assertEqual(m.filter_mode, "built-in")
            self.assertEqual(m.engine.totals()["packets_seen"], 2)                                         # the :80 packet was filtered out
            c = sorted(m.engine.conns.values(), key=lambda i: i.key.src_port); self.assertEqual((c[0].key.src_port, c[0].direction, c[0].service, c[1].direction), (443, "incoming", "https", "outgoing"))
            m.stop(); self.assertEqual(RawPcapReader(m.pcap_path).linktype, 101)                           # raw-IP pcap, readable everywhere
        finally:
            sys.platform, M.npcap_installed, M.RawWindowsSniffer, M.interfaces = saved

    def test_npcap_present_means_scapy_backend(self):
        import scapy.all as SA
        saved = (sys.platform, M.npcap_installed, SA.AsyncSniffer, M.interfaces); started = []
        class FakeSniffer:
            running = True; exception = None
            def __init__(self, **kw): started.append(kw)
            def start(self): pass
            def stop(self): pass
        try:
            sys.platform = "win32"; M.npcap_installed = lambda: True; SA.AsyncSniffer = FakeSniffer
            M.interfaces = lambda: [{"name": "Ethernet", "description": "", "up": True, "addresses": [{"addr": "10.0.0.5", "netmask": "255.255.255.0", "broadcast": None}]}]
            m = M.Manager(); st = m.start({"type": "device", "iface": "Ethernet", "bpf": ""}); self.assertEqual(st["capture_backend"], "Npcap / libpcap"); self.assertEqual(len(started), 1); m.stop()
        finally: sys.platform, M.npcap_installed, SA.AsyncSniffer, M.interfaces = saved


class Interfaces(unittest.TestCase):
    def test_list_works_when_scapy_is_missing_or_unusable(self):
        saved = sys.modules.get("scapy.all"); sys.modules["scapy.all"] = None                               # `from scapy.all import conf` now raises ImportError
        try:
            ifs = M.interfaces(); self.assertTrue(ifs); self.assertTrue(all("name" in i and "addresses" in i and "up" in i for i in ifs))
            self.assertTrue(ifs[0]["addresses"])                                                              # interfaces with addresses are listed first
        finally:
            if saved is not None: sys.modules["scapy.all"] = saved
            else: del sys.modules["scapy.all"]


if __name__ == "__main__":
    unittest.main()
