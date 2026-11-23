"""V12.4: a capture that died must not block Start, the page must be able to see it, Reset must clear everything."""
import os, sys, re, time, unittest, tempfile
TMP = tempfile.mkdtemp(); os.environ["NETMON_DATA_DIR"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from monitor.traffic import manager as M

class Dead:                       # a sniffer whose thread ended (Windows: raw socket closed by the OS, adapter disabled ...)
    running = False; exception = OSError("adapter went away")
    def stop(self): pass

class SelfHeal(unittest.TestCase):
    def mgr(self):
        m = M.Manager(); m.state = "running"; m.source = {"type": "device", "name": "x", "iface": "x"}; m.sniffer = Dead(); return m
    def test_dead_capture_detected(self): self.assertIn("adapter went away", self.mgr()._dead_reason())
    def test_alive_capture_still_blocks_start(self):
        m = M.Manager(); m.state = "running"; m.source = {"type": "device"}
        class Alive: running = True; threads = []
        m.sniffer = Alive(); self.assertEqual(m._dead_reason(), ""); 
        with self.assertRaises(RuntimeError): m.start({"type": "device", "iface": "x"})
    def test_status_turns_dead_capture_into_failed(self):
        m = self.mgr(); s = m.status()
        self.assertEqual(s["state"], "failed"); self.assertIn("stopped unexpectedly", s["error"])
    def test_start_after_dead_capture_is_not_refused_as_running(self):
        m = self.mgr()
        try: m.start({"type": "device", "iface": "no-such-card"})
        except Exception as e: self.assertNotIn("already running", str(e))
    def test_reset_clears_everything(self):
        m = M.Manager(); m.state = "paused"; m.source = {"type": "device"}; m.sniffer = Dead(); s = m.reset()
        self.assertEqual(s["state"], "idle"); self.assertEqual(s["error"], "")
    def test_flows_collector_dead(self):
        m = M.Manager(); m.state = "running"; m.source = {"type": "flows"}; m.collector = None
        self.assertTrue(m._dead_reason())
if __name__ == "__main__": unittest.main(verbosity=2)
