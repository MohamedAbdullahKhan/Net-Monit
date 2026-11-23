"""Patch 07 backend tests (custom dashboard views + last-viewed tab). Run: python tests/test_patch07_backend.py"""
import os, sys, json
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); os.chdir(ROOT); sys.path.insert(0, ROOT)
import app as A
from monitor import auth, database as db, config_manager as cm
for f in ("data/monitor.db", "data/monitor.db-wal", "data/monitor.db-shm"):
    try: os.remove(f)
    except OSError: pass
db.init_db(); auth.add_user("a@x.com", "admin", "Test@12345xy"); auth.add_user("v@x.com", "user", "Test@12345xy")
for i in range(5): cm.add_or_update_device({"id": f"d{i}", "name": f"D{i}", "host": f"10.0.0.{i+1}", "type": "linux", "method": "ping", "poll_interval_seconds": 30})
c = A.app.test_client()
def login(e): return {"X-Session-Token": c.post("/api/auth/login", json={"email": e, "token": "Test@12345xy"}).get_json()["session"]}
HA, HV = login("a@x.com"), login("v@x.com")
ok = bad = 0
def check(n, cond, x=""):
    global ok, bad
    if cond: ok += 1; print("  PASS", n)
    else: bad += 1; print("  FAIL", n, x)
V = lambda h: c.get("/api/dashboard/custom-views", headers=h).get_json()["views"]
check("starts empty", V(HA) == [])
r = c.post("/api/dashboard/custom-views", json={"views": [{"name": "NOC priority", "device_ids": ["d1", "d3", "d1", "ghost"], "priority": True}]}, headers=HA).get_json()
check("saved, id generated, duplicates dropped", r["ok"] and len(r["views"][0]["id"]) >= 1 and r["views"][0]["device_ids"] == ["d1", "d3", "ghost"], r)
vid = r["views"][0]["id"]
check("deleted/unknown monitors disappear on read", V(HA)[0]["device_ids"] == ["d1", "d3"], V(HA))
check("other user does not see it (per user)", V(HV) == [])
check("viewer role can have own views", c.post("/api/dashboard/custom-views", json={"views": [{"name": "Mine", "device_ids": ["d2"]}]}, headers=HV).get_json()["ok"] and V(HA)[0]["name"] == "NOC priority")
check("needs login", c.get("/api/dashboard/custom-views").status_code in (401, 403))
check("empty name refused", c.post("/api/dashboard/custom-views", json={"views": [{"name": " ", "device_ids": ["d1"]}]}, headers=HA).status_code == 400)
check("duplicate names refused", c.post("/api/dashboard/custom-views", json={"views": [{"name": "A", "device_ids": []}, {"name": "a", "device_ids": []}]}, headers=HA).status_code == 400)
check("more than 12 refused", c.post("/api/dashboard/custom-views", json={"views": [{"name": f"v{i}", "device_ids": []} for i in range(13)]}, headers=HA).status_code == 400)
check("garbage body refused", c.post("/api/dashboard/custom-views", json={"views": "x"}, headers=HA).status_code == 400)
long = c.post("/api/dashboard/custom-views", json={"views": [{"name": "x" * 99, "id": "../../etc", "device_ids": [f"d{i}" for i in range(3)] * 400, "priority": False}]}, headers=HA).get_json()
check("name capped to 40, id sanitised, tiles capped & unique, priority flag kept", long["ok"] and len(long["views"][0]["name"]) == 40 and long["views"][0]["id"].isalnum() and len(long["views"][0]["device_ids"]) == 3 and long["views"][0]["priority"] is False, long)
check("last-view starts empty", c.get("/api/dashboard/last-view", headers=HA).get_json()["last_view"] is None)
check("last-view custom saved", c.post("/api/dashboard/last-view", json={"cat": "cv:abc123", "sev": "critical"}, headers=HA).get_json()["ok"] and c.get("/api/dashboard/last-view", headers=HA).get_json()["last_view"] == {"cat": "cv:abc123", "sev": "critical"})
check("last-view builtin tab saved", c.post("/api/dashboard/last-view", json={"cat": "windows", "sev": "all"}, headers=HA).get_json()["ok"])
check("last-view bad category refused", c.post("/api/dashboard/last-view", json={"cat": "<script>", "sev": "all"}, headers=HA).status_code == 400)
check("last-view bad severity refused", c.post("/api/dashboard/last-view", json={"cat": "all", "sev": "purple"}, headers=HA).status_code == 400)
check("last-view is per user", c.get("/api/dashboard/last-view", headers=HV).get_json()["last_view"] is None)
print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
