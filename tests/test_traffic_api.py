"""Traffic Analyzer API integration tests (Flask test client, real engine, real capture on loopback when permitted)."""
import os, sys, io, time, socket, struct, tempfile, unittest, shutil, threading
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, ROOT); os.chdir(ROOT)
TMP = tempfile.mkdtemp(prefix="nm-api-")
from pathlib import Path
from monitor import database as db
db.DB_PATH = Path(TMP) / "api.db"
CFG_BAK = os.path.join(TMP, "config.bak"); shutil.copy("config.yaml", CFG_BAK)
import app as A
from monitor import auth, config_manager as cm
from monitor.traffic import manager as M, store, api as TAPI
M.DATA_DIR = os.path.join(TMP, "traffic")
db.init_db(); auth.add_user("a@x.com", "admin", "Test@12345xy"); auth.add_user("v@x.com", "user", "Test@12345xy")
c = A.app.test_client()
login = lambda e: {"X-Session-Token": c.post("/api/auth/login", json={"email": e, "token": "Test@12345xy"}).get_json()["session"]}
H, HV = login("a@x.com"), login("v@x.com")
from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap


def pcap_bytes():
    pk = []; t = 1700000000.0
    def add(p, dt): p.time = t + dt; pk.append(p)
    for i in range(3):
        add(Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / TCP(sport=50000, dport=443) / Raw(b"x" * 100), i)
        add(Ether() / IP(src="8.8.8.8", dst="192.168.1.10") / TCP(sport=443, dport=50000) / Raw(b"y" * 900), i + .5)
    add(Ether() / IP(src="192.168.1.10", dst="1.1.1.1") / UDP(sport=5353, dport=53) / Raw(b"q" * 30), 4)
    add(Ether() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=50010, dport=80) / Raw(b"=cmd" * 10), 5)
    p = os.path.join(TMP, "s.pcap"); wrpcap(p, pk); return open(p, "rb").read()


def req(method, url, h=H, **kw): return getattr(c, method)(url, headers=h, **kw)
def wait_done(timeout=15):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if M.get_manager().state not in ("running", "paused"): return True
        time.sleep(.05)
    return False


class Api(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mgr = M.get_manager()
        r = req("post", "/api/traffic/pcap-upload", data={"file": (io.BytesIO(pcap_bytes()), "s.pcap")}, content_type="multipart/form-data")
        assert r.status_code == 200, r.data; cls.path = r.get_json()["path"]

    @classmethod
    def tearDownClass(cls):
        try: cls.mgr.stop()
        except Exception: pass
        shutil.copy(CFG_BAK, "config.yaml")

    def load_capture(self, bpf=""):
        if self.mgr.state in ("running", "paused"): self.mgr.stop()
        r = req("post", "/api/traffic/start", json={"type": "pcap", "path": self.path, "bpf": bpf}); self.assertTrue(r.get_json()["ok"], r.data); self.assertTrue(wait_done())

    # ---------------------------------------------------------------- security
    def test_everything_requires_admin(self):
        for m, u in (("get", "/api/traffic/status"), ("get", "/api/traffic/overview"), ("post", "/api/traffic/start"), ("get", "/api/traffic/connections"), ("get", "/api/traffic/export/report.csv"),
                     ("get", "/api/traffic/settings"), ("post", "/api/traffic/notifications/settings"), ("get", "/api/traffic/interfaces"), ("post", "/api/traffic/pcap-upload")):
            for h in ({}, HV):
                r = getattr(c, m)(u, headers=h, json={}); self.assertIn(r.status_code, (401, 403), (m, u, h))

    def test_page_is_admin_only(self):
        self.assertEqual(c.get("/traffic", headers=H).status_code, 200); self.assertIn(b"Traffic Analyzer", c.get("/traffic", headers=H).data)

    # ---------------------------------------------------------------- control
    def test_idle_status_and_interfaces(self):
        r = req("get", "/api/traffic/interfaces").get_json(); self.assertTrue(any(i["name"] for i in r["interfaces"]))
        s = req("get", "/api/traffic/status").get_json(); self.assertIn(s["state"], ("idle", "finished", "stopped")); self.assertTrue(s["geo"]["country"] and s["geo"]["asn"])

    def test_start_validation(self):
        for body in ({"type": "device", "iface": "no-such-card"}, {"type": "nonsense"}, {"type": "pcap", "path": "/does/not/exist.pcap"}, {"type": "pcap", "path": self.path, "bpf": "foo bar"}):
            r = req("post", "/api/traffic/start", json=body); self.assertEqual(r.status_code, 400, body); self.assertFalse(r.get_json()["ok"]); self.assertTrue(r.get_json()["error"])

    def test_upload_rejects_non_pcap(self):
        r = req("post", "/api/traffic/pcap-upload", data={"file": (io.BytesIO(b"hello, this is not a capture"), "x.pcap")}, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400); self.assertIn("not a pcap", r.get_json()["error"])

    # ---------------------------------------------------------------- views
    def test_overview(self):
        self.load_capture(); o = req("get", "/api/traffic/overview?top=5").get_json()
        self.assertTrue(o["active"]); self.assertEqual(o["connections"], 4)
        self.assertEqual((o["totals"]["in_bytes"], o["totals"]["out_bytes"]), (3 * 954, 3 * 154 + 72 + 94))
        names = {h["name"]: h for h in o["hosts"]}; self.assertEqual(names["8.8.8.8"]["country"], "US"); self.assertEqual(names["8.8.8.8"]["asn_name"], "Google LLC")
        self.assertEqual(o["hosts"][0]["name"], "8.8.8.8")                                                       # most data first
        self.assertEqual({s["name"] for s in o["services"]}, {"https", "domain", "http"}); self.assertEqual(next(s for s in o["services"] if s["name"] == "https")["category"], "web")
        self.assertTrue({"US", "AU"} <= {x["code"] for x in o["countries"]})
        self.assertEqual(len(o["series"]), 6); self.assertEqual(sum(s["in_bytes"] for s in o["series"]), 3 * 954)
        by_pk = req("get", "/api/traffic/overview?sort=packets").get_json(); self.assertEqual(by_pk["hosts"][0]["name"], "8.8.8.8")
        full = req("get", "/api/traffic/list/hosts").get_json(); self.assertEqual(full["total"], 3)
        self.assertEqual(req("get", "/api/traffic/list/bogus").status_code, 404)

    def test_connection_search_sort_paginate(self):
        self.load_capture(); g = lambda q: req("get", "/api/traffic/connections?" + q).get_json()
        self.assertEqual(g("")["total"], 4)                                                                  # https out, https in, domain, http
        self.assertEqual(g("q=8.8.8.8")["total"], 2); self.assertEqual(g("q=google")["total"], 2)
        self.assertEqual(g("service=https")["total"], 2); self.assertEqual(g("service==http")["total"], 1); self.assertEqual(g("service==htt")["total"], 0)       # '=' means exact
        self.assertEqual(g("proto=udp")["total"], 1); self.assertEqual(g("country=US")["total"], 3); self.assertEqual(g("country==us")["total"], 3); self.assertEqual(g("asn=google")["total"], 2)
        self.assertEqual(g("port=53")["total"], 1); self.assertEqual(g("ip=1.1.1.1")["total"], 1); self.assertEqual(g("direction=incoming")["total"], 1); self.assertEqual(g("q=nothing-matches-this")["total"], 0)
        a, d = g("sort=bytes_asc")["items"], g("sort=bytes_desc")["items"]; self.assertEqual([x["bytes"] for x in a], sorted(x["bytes"] for x in a)); self.assertEqual(d[0]["bytes"], max(x["bytes"] for x in d))
        p1 = g("page_size=3&page=1"); p2 = g("page_size=3&page=2"); self.assertEqual((p1["pages"], len(p1["items"]), len(p2["items"]), g("page_size=3&page=99")["page"]), (2, 3, 1, 2))

    def test_connection_detail_and_latency(self):
        self.load_capture(); it = req("get", "/api/traffic/connections?service==https&direction=outgoing").get_json()["items"][0]
        d = req("get", f"/api/traffic/connections/{it['id']}").get_json()
        self.assertEqual((d["src_port"], d["dst_port"], d["host"], d["category"], d["country"], d["duration"]), (50000, 443, "8.8.8.8", "web", "US", 2.0))
        self.assertEqual(req("get", "/api/traffic/connections/999999").status_code, 404)
        l = req("post", f"/api/traffic/connections/{it['id']}/latency").get_json(); self.assertIn("reachable", l); self.assertEqual(l["ip"], "8.8.8.8")

    def test_filter_on_import(self):
        self.load_capture("udp"); self.assertEqual(req("get", "/api/traffic/connections").get_json()["total"], 1)

    def test_device_link(self):
        cm.add_or_update_device({"id": "dns1", "name": "Google DNS probe", "host": "8.8.8.8", "type": "other", "method": "ping", "poll_interval_seconds": 30})
        self.load_capture(); o = req("get", "/api/traffic/overview").get_json(); self.assertEqual(next(h for h in o["hosts"] if h["name"] == "8.8.8.8")["device"], "Google DNS probe")
        self.assertEqual(req("get", "/api/traffic/connections?ip=8.8.8.8").get_json()["items"][0]["device"], "Google DNS probe"); cm.remove_device("dns1")

    # ---------------------------------------------------------------- favorites / notifications / settings
    def test_favorites(self):
        self.load_capture()
        self.assertEqual(req("post", "/api/traffic/favorites", json={"kind": "bogus", "value": "x"}).status_code, 400); self.assertEqual(req("post", "/api/traffic/favorites", json={"kind": "host", "value": ""}).status_code, 400)
        for kind, val in (("service", "https"), ("host", "1.1.1.1")): self.assertTrue(req("post", "/api/traffic/favorites", json={"kind": kind, "value": val}).get_json()["ok"])
        req("post", "/api/traffic/favorites", json={"kind": "service", "value": "https"})                                                          # duplicate is harmless
        self.assertEqual(len(req("get", "/api/traffic/favorites").get_json()["favorites"]), 2)
        self.assertEqual(req("get", "/api/traffic/connections?favorite=1").get_json()["total"], 3)                                                  # 2 https + 1.1.1.1
        o = req("get", "/api/traffic/overview").get_json(); self.assertTrue(next(s for s in o["services"] if s["name"] == "https")["favorite"]); self.assertFalse(next(s for s in o["services"] if s["name"] == "domain")["favorite"])
        for kind, val in (("service", "https"), ("host", "1.1.1.1")): req("delete", "/api/traffic/favorites", json={"kind": kind, "value": val})
        self.assertEqual(req("get", "/api/traffic/favorites").get_json()["favorites"], [])

    def test_notification_settings_roundtrip_and_validation(self):
        s = req("get", "/api/traffic/notifications/settings").get_json(); self.assertEqual(s["settings"]["data"]["enabled"], False); self.assertIn("pop", s["sounds"])
        r = req("post", "/api/traffic/notifications/settings", json={"volume": 250, "data": {"enabled": True, "threshold": "2.5M", "unit": "bits", "sound": "nonexistent"}, "sms": {"enabled": True, "numbers": [" +9715000 ", "", "+9716"]}, "bogus": 1}).get_json()["settings"]
        self.assertEqual((r["volume"], r["data"]["threshold"], r["data"]["unit"], r["data"]["sound"], r["sms"]["numbers"]), (100, 2500000, "bits", "none", ["+9715000", "+9716"]))
        r = req("post", "/api/traffic/notifications/settings", json={"data": {"unit": "parsecs", "threshold": "garbage"}}).get_json()["settings"]; self.assertEqual((r["data"]["unit"], r["data"]["threshold"]), ("bytes", 1000000))
        req("post", "/api/traffic/notifications/settings", json={"data": {"enabled": False}, "sms": {"enabled": False}})

    def test_notification_log_and_test_button(self):
        req("delete", "/api/traffic/notifications/log"); req("post", "/api/traffic/notifications/test"); time.sleep(.4)
        items = req("get", "/api/traffic/notifications/log").get_json()["items"]; self.assertEqual(len(items), 1); self.assertEqual((items[0]["kind"], items[0]["data"]["sound"]), ("test", "pop"))
        self.assertEqual(req("get", f"/api/traffic/notifications/log?since={items[0]['id']}").get_json()["items"], [])
        self.assertTrue(req("delete", "/api/traffic/notifications/log").get_json()["ok"]); self.assertEqual(req("get", "/api/traffic/notifications/log").get_json()["items"], [])

    def test_settings_validation_and_blacklist(self):
        self.assertEqual(req("post", "/api/traffic/settings", json={"blacklist": "/no/such/file.txt"}).status_code, 400)
        bl = os.path.join(ROOT, "tests", "data", "ip_blacklist_valid_with_cidr.txt")
        r = req("post", "/api/traffic/blacklist-upload", data={"file": (open(bl, "rb"), "bl.txt")}, content_type="multipart/form-data").get_json(); self.assertEqual(r["entries"], 6)
        st = req("get", "/api/traffic/settings").get_json(); self.assertEqual((st["blacklist"]["ips"], st["blacklist"]["cidrs"], st["blacklist"]["info"]), (2, 4, "IPs: 2, CIDRs: 4"))
        self.load_capture(); o = req("get", "/api/traffic/overview").get_json(); self.assertEqual(o["blacklisted"], 2)                       # 8.8.8.8 is listed: its in+out connections
        self.assertEqual(req("get", "/api/traffic/connections?blacklisted=1").get_json()["total"], 2)
        r = req("post", "/api/traffic/settings", json={"blacklist": "", "retention_days": 99999, "rdns": False}).get_json(); self.assertEqual((r["settings"]["retention_days"], r["blacklist"]["entries"]), (3650, 0))
        req("post", "/api/traffic/settings", json={"rdns": True, "retention_days": 30})

    # ---------------------------------------------------------------- history / export
    def test_history_and_exports(self):
        self.load_capture(); sid = self.mgr.sid
        s = req("get", "/api/traffic/sessions").get_json()["sessions"]; self.assertEqual(s[0]["id"], sid); self.assertEqual(s[0]["status"], "finished")
        d = req("get", f"/api/traffic/sessions/{sid}").get_json(); self.assertEqual(len(d["connections"]), 4); self.assertTrue(d["minutes"])
        csv_text = req("get", "/api/traffic/export/report.csv").data.decode(); lines = csv_text.strip().splitlines(); self.assertEqual(len(lines), 5); self.assertIn("src_ip,src_port", lines[0]); self.assertIn("8.8.8.8", csv_text)
        self.assertEqual(req("get", f"/api/traffic/export/report.csv?session={sid}").status_code, 200)
        self.assertEqual(req("get", "/api/traffic/export/capture.pcap").status_code, 404)                                                       # no pcap was saved for an import
        self.assertEqual(TAPI._csv_cell("=HYPERLINK(\"http://evil\")"), "'=HYPERLINK(\"http://evil\")"); self.assertEqual(TAPI._csv_cell("+1"), "'+1"); self.assertEqual(TAPI._csv_cell("plain"), "plain")
        self.assertTrue(req("delete", f"/api/traffic/sessions/{sid}").get_json()["ok"]); self.assertEqual(req("get", f"/api/traffic/sessions/{sid}").status_code, 404)

    def test_webhook_url_and_upload_hardening(self):
        r = req("post", "/api/traffic/notifications/settings", json={"webhook": {"enabled": True, "url": "file:///etc/passwd"}}); self.assertEqual(r.status_code, 400); self.assertIn("http", r.get_json()["error"])
        r = req("post", "/api/traffic/start", json={"type": "pcap", "path": "/etc/passwd"}); self.assertEqual(r.status_code, 400); self.assertIn("uploaded through Net-monit", r.get_json()["error"])
        big = req("post", "/api/traffic/pcap-upload", data={"file": (io.BytesIO(b"x"), "x.pcap")}, content_type="multipart/form-data", h=dict(H, **{"Content-Length": str(600 * 1024 * 1024)}))
        self.assertIn(big.status_code, (400, 413))

    def test_cannot_start_twice_or_delete_running(self):
        if self.mgr.state in ("running", "paused"): self.mgr.stop()
        r = req("post", "/api/traffic/start", json={"type": "flows", "port": 12056}); self.assertTrue(r.get_json()["ok"], r.data); sid = self.mgr.sid
        self.assertEqual(req("post", "/api/traffic/start", json={"type": "flows", "port": 12057}).status_code, 400)
        self.assertEqual(req("delete", f"/api/traffic/sessions/{sid}").status_code, 400)
        self.assertEqual(req("post", "/api/traffic/pause", json={"on": True}).get_json()["status"]["state"], "paused"); self.assertEqual(req("post", "/api/traffic/pause", json={"on": False}).get_json()["status"]["state"], "running")
        self.assertEqual(req("post", "/api/traffic/stop").get_json()["status"]["state"], "stopped")

    # ---------------------------------------------------------------- live sources
    def test_flow_collector_through_the_api(self):
        if self.mgr.state in ("running", "paused"): self.mgr.stop()
        port = 12058; self.assertTrue(req("post", "/api/traffic/start", json={"type": "flows", "port": port}).get_json()["ok"])
        F = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 8), (2, 8)]
        tpl = struct.pack("!HH", 256, len(F)) + b"".join(struct.pack("!HH", i, l) for i, l in F); ts = struct.pack("!HH", 2, 4 + len(tpl)) + tpl
        rec = socket.inet_aton("93.184.216.34") + socket.inet_aton("10.9.9.9") + struct.pack("!HHBQQ", 443, 52000, 6, 5000, 4); ds = struct.pack("!HH", 256, 4 + len(rec)) + rec
        body = ts + ds; msg = struct.pack("!HHIII", 10, 16 + len(body), int(time.time()), 1, 1) + body
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(msg, ("127.0.0.1", port)); t0 = time.time()
        while time.time() - t0 < 4 and not req("get", "/api/traffic/overview").get_json().get("connections"): time.sleep(.1)
        o = req("get", "/api/traffic/overview").get_json(); self.assertEqual(o["connections"], 1); self.assertEqual(o["totals"]["in_bytes"] + o["totals"]["out_bytes"], 5000)
        st = req("get", "/api/traffic/status").get_json(); self.assertEqual(st["collector"]["stats"]["records"], 1); req("post", "/api/traffic/stop")

    def test_live_capture_on_loopback_with_pcap_export(self):
        if not sys.platform.startswith("linux"): self.skipTest("native capture test is for Linux")
        if self.mgr.state in ("running", "paused"): self.mgr.stop()
        r = req("post", "/api/traffic/start", json={"type": "device", "iface": "lo", "bpf": "udp port 18081", "export_pcap": True})
        if r.status_code == 400 and "Permission" in r.get_json()["error"]: self.skipTest("no CAP_NET_RAW in this environment")
        self.assertTrue(r.get_json()["ok"], r.data); self.assertEqual(r.get_json()["status"]["filter_mode"], "built-in")
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for _ in range(5): u.sendto(b"x" * 200, ("127.0.0.1", 18081))
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"no", ("127.0.0.1", 19999)); time.sleep(1.6)
        o = req("get", "/api/traffic/overview").get_json(); self.assertEqual(o["connections"], 1); self.assertEqual(o["totals"]["in_packets"] + o["totals"]["out_packets"], 5)       # each packet counted once, filter honoured
        self.assertTrue(req("get", "/api/traffic/status").get_json()["pcap_export"]); req("post", "/api/traffic/stop")
        dl = req("get", "/api/traffic/export/capture.pcap"); self.assertEqual(dl.status_code, 200); self.assertTrue(dl.data[:4] in (b"\xd4\xc3\xb2\xa1",))


if __name__ == "__main__":
    unittest.main()
