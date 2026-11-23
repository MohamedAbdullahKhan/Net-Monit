"""V12.4: engine selection and the Cloudflare-rate-limited fallback (no network needed)."""
import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from monitor.checkers import speedtest_check as S

CLI = (212.5, 48.2, 7.9, "ISP-local (Dubai)", "speedtest.isp.example:8080")
PARTIAL = {"reachable": True, "download_mbps": None, "upload_mbps": 89.3, "latency_ms": 49.1, "jitter_ms": 1.0, "server": "Cloudflare DXB", "host": "speed.cloudflare.com",
           "method_used": "builtin", "warning": "rate-limited (12 x HTTP 429/503)", "kind": "cloudflare"}
FULL = dict(PARTIAL, download_mbps=300.0)

class Engine(unittest.TestCase):
    def setUp(self):
        self.o = (S._try_speedtest_cli, S._test_target, S._public_ip_and_isp, S._speedtest_config)
        S._public_ip_and_isp = lambda: ("1.2.3.4", "TestISP"); S._speedtest_config = lambda: {}
        os.environ.pop("NETMON_SPEEDTEST_ENGINE", None); self.calls = []
        def cli(cb): self.calls.append("cli"); return self.cli_result
        def tgt(t, cb, icb): self.calls.append("builtin"); return dict(self.tgt_result) if self.tgt_result else None
        S._try_speedtest_cli, S._test_target = cli, tgt
    def tearDown(self): S._try_speedtest_cli, S._test_target, S._public_ip_and_isp, S._speedtest_config = self.o; os.environ.pop("NETMON_SPEEDTEST_ENGINE", None)
    def test_default_is_auto_and_uses_nearby_server(self):
        self.cli_result, self.tgt_result = CLI, FULL; r = S.check({})
        self.assertEqual(self.calls, ["cli"]); self.assertEqual(r["method_used"], "speedtest-cli"); self.assertEqual(r["download_mbps"], 212.5)
    def test_auto_falls_back_to_builtin_when_cli_missing(self):
        self.cli_result, self.tgt_result = None, FULL; r = S.check({})
        self.assertEqual(self.calls, ["cli", "builtin"]); self.assertEqual(r["download_mbps"], 300.0)
    def test_builtin_rate_limited_download_switches_to_cli(self):
        os.environ["NETMON_SPEEDTEST_ENGINE"] = "builtin"; self.cli_result, self.tgt_result = CLI, PARTIAL; r = S.check({})
        self.assertEqual(self.calls, ["builtin", "cli"]); self.assertEqual(r["download_mbps"], 212.5); self.assertIn("rate-limited", r["note"])
    def test_partial_result_kept_when_cli_also_fails(self):
        os.environ["NETMON_SPEEDTEST_ENGINE"] = "builtin"; self.cli_result, self.tgt_result = None, PARTIAL; r = S.check({})
        self.assertIsNone(r["download_mbps"]); self.assertEqual(r["upload_mbps"], 89.3)
    def test_auto_partial_does_not_call_cli_twice(self):
        self.cli_result, self.tgt_result = None, PARTIAL; S.check({}); self.assertEqual(self.calls.count("cli"), 1)

if __name__ == "__main__": unittest.main(verbosity=2)
