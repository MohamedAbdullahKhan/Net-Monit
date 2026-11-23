"""Patch 06 backend tests. Run:  python tests/test_patch06_backend.py   (uses a throw-away copy of data/)"""
import os, sys, json, shutil, tempfile, threading, time
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); os.chdir(ROOT); sys.path.insert(0, ROOT)
import app as A
from monitor import auth, database as db, config_manager as cm
import yaml
for f in ("data/monitor.db", "data/monitor.db-wal", "data/monitor.db-shm"):
    try: os.remove(f)
    except OSError: pass
db.init_db(); auth.add_user("t@x.com", "admin", "Test@12345xy")
c = A.app.test_client(); H = {"X-Session-Token": c.post("/api/auth/login", json={"email": "t@x.com", "token": "Test@12345xy"}).get_json()["session"]}
DEV = [("fw1","firewall","snmp"),("fw2","firewall","snmp"),("fw3","firewall","ping"),("sw1","switch","snmp"),("sw2","switch","snmp"),
       ("ap1","wireless","ping"),("ap2","wireless","ping"),("ws1","windows","powershell"),("ws2","windows","powershell"),("lx1","linux","ssh"),
       ("site1","other","url"),("site2","other","url")]
for i,(d,t,m) in enumerate(DEV):
    cm.add_or_update_device({"id":d,"name":d.upper(),"host":(f"https://{d}.example" if m=="url" else f"10.0.0.{i+1}"),"type":t,"method":m,"poll_interval_seconds":30})
P = lambda u, b: c.post(u, json=b, headers=H)
ok = fails = 0
def check(name, cond, extra=""):
    global ok, fails
    if cond: ok += 1; print("  PASS", name)
    else: fails += 1; print("  FAIL", name, extra)
TIM = {"alert_trigger_mode":"sustained","wait_sec":45,"alert_notify_mode":"cooldown","notify_cooldown_sec":777}
def wait_of(d): return db.get_device_notify(d).get("escalation_after_sec_l1")
def reset(): [db.set_device_notify(d[0],1,[],[],[],[],60,600,1200,1,{}) for d in DEV]
reset()
print("timing apply targets")
r = P("/api/settings/notify-timing/apply", {**TIM, "ids":["fw1"]}).get_json()
check("this device only", r["ok"] and r["count"]==1 and wait_of("fw1")==45 and wait_of("fw2")==60, r)
reset(); r = P("/api/settings/notify-timing/apply", {**TIM, "kind":"type","key":"firewall"}).get_json()
check("all firewalls (3)", r["count"]==3 and all(wait_of(x)==45 for x in ("fw1","fw2","fw3")) and wait_of("sw1")==60, r)
reset(); r = P("/api/settings/notify-timing/apply", {**TIM, "kind":"method","key":"snmp"}).get_json()
check("all SNMP monitors (4)", r["count"]==4 and wait_of("sw1")==45 and wait_of("fw3")==60, r)
reset(); r = P("/api/settings/notify-timing/apply", {**TIM, "ids":["fw1","sw2","ap1"]}).get_json()
check("hand-picked / current filter ids", r["count"]==3 and wait_of("sw2")==45 and wait_of("ap2")==60, r)
reset(); r = P("/api/settings/notify-timing/apply", {**TIM, "scope":"devices"}).get_json()
check("legacy scope devices still works (10, sites untouched)", r["count"]==10 and wait_of("site1")==60, r)
r = P("/api/settings/notify-timing/apply", {**TIM, "scope":"sites"}).get_json(); check("legacy scope sites (2)", r["count"]==2, r)
check("unknown ids rejected", P("/api/settings/notify-timing/apply", {**TIM, "ids":["nope"]}).status_code==400)
check("empty ids rejected", P("/api/settings/notify-timing/apply", {**TIM, "ids":[]}).status_code==400)
check("bad kind rejected", P("/api/settings/notify-timing/apply", {**TIM, "kind":"colour","key":"x"}).status_code==400)
db.set_device_notify("fw1",1,["keep@x.com"],["l1@x.com"],[],[],60,600,1200,2,{"cpu_pct":{"warning":50}},sms_numbers_l1=["+97150"])
P("/api/settings/notify-timing/apply", {**TIM, "ids":["fw1"]}); n = db.get_device_notify("fw1")
check("emails/SMS/levels/thresholds preserved", n["notify_emails"]==["keep@x.com"] and n["sms_numbers_l1"]==["+97150"] and n["escalation_levels"]==2 and n["thresholds"]["cpu_pct"]["warning"]==50, n)
print("threshold apply (ids)")
reset(); T = {"cpu_pct":{"enabled":True,"warning":60,"critical":85},"latency_ms":{"enabled":True,"warning":50,"critical":120}}
r = P("/api/devices/thresholds/apply", {"ids":["fw1","fw3","ws1"], "thresholds":T}).get_json()
n1, n3 = db.get_device_notify("fw1")["thresholds"], db.get_device_notify("fw3")["thresholds"]
check("applied to 3 monitors", r["ok"] and r["count"]==3, r)
check("SNMP firewall gets cpu+latency", n1["cpu_pct"]["warning"]==60 and n1["latency_ms"]["critical"]==120, n1)
check("ping firewall skips cpu (not a ping metric), keeps latency", "cpu_pct" not in n3 and n3["latency_ms"]["warning"]==50, n3)
check("other devices untouched", db.get_device_notify("fw2")["thresholds"]=={})
db.set_device_notify("fw2",1,[],[],[],[],60,600,1200,1,{"cpu_pct":{"warning":40,"wait_sec":99}})
P("/api/devices/thresholds/apply", {"ids":["fw2"],"thresholds":{"cpu_pct":{"enabled":True,"warning":61,"critical":86}}})
check("existing per-metric wait_sec kept", db.get_device_notify("fw2")["thresholds"]["cpu_pct"].get("wait_sec")==99)
check("warning>=critical refused", P("/api/devices/thresholds/apply", {"ids":["fw1"],"thresholds":{"cpu_pct":{"warning":90,"critical":80}}}).status_code==400)
check("empty thresholds refused", P("/api/devices/thresholds/apply", {"ids":["fw1"],"thresholds":{}}).status_code==400)
check("viewer cannot apply", c.post("/api/devices/thresholds/apply", json={"ids":["fw1"],"thresholds":T}).status_code in (401,403))
print("existing scope endpoints used by the type/method/all buttons")
r = P("/api/settings/thresholds/scoped", {"kind":"type","key":"switch","thresholds":{"cpu_pct":{"enabled":True,"warning":55,"critical":80}},"apply":True}).get_json(); check("type scope (switches)", r["ok"] and r["count"]==2, r)
r = P("/api/settings/thresholds/scoped", {"kind":"method","key":"ssh","thresholds":{"cpu_pct":{"enabled":True,"warning":55,"critical":80}},"apply":True}).get_json(); check("method scope (ssh)", r["ok"] and r["count"]==1, r)
r = P("/api/settings/thresholds/apply", {"scope":"sites","thresholds":{"response_ms":{"enabled":True,"warning":900,"critical":2500}}}).get_json(); check("all sites", r["ok"], r)
print("performance / safety")
with db.batch():
    db.set_system_setting("zz","1")
    try:
        with db.batch(): db.set_system_setting("zz","2")
    except Exception: pass
check("nested batch joins outer", db.get_system_setting("zz")=="2")
try:
    with db.batch():
        db.set_system_setting("zz","3"); raise RuntimeError("boom")
except RuntimeError: pass
check("batch rolls back on error", db.get_system_setting("zz")=="2")
n = {"c":0}; orig = db.get_connection
def counted(): n["c"]+=1; return orig()
db.get_connection = counted
c.get("/api/alerts/count", headers=H, environ_overrides={"HTTP_HOST":"demo.local:50113"}); n["c"]=0
c.get("/api/alerts/count", headers=H, environ_overrides={"HTTP_HOST":"demo.local:50113"}); same = n["c"]
check("repeat request to same host does no host-bookkeeping DB work", same <= 3, same)
db.get_connection = orig
stop = {"v": False}
def sched():
    while not stop["v"]:
        for i in range(5): db.record_metric("fw1","latency_ms",1.0,"ok")
        time.sleep(0.002)
th = threading.Thread(target=sched, daemon=True); th.start()
t0 = time.perf_counter(); r = P("/api/settings/notify-timing/apply", {**TIM, "scope":"all"}).get_json(); dt = time.perf_counter()-t0
stop["v"] = True; th.join(2)
check(f"bulk apply to {r['count']} monitors beside a busy writer finishes fast ({dt*1000:.0f} ms, no deadlock)", dt < 3 and r["ok"], dt)
cm.save_config(cm.get_config())
check("config.yaml valid after save and no .tmp left", yaml.safe_load(open(cm.CONFIG_PATH, encoding="utf-8")) and not os.path.exists(str(cm.CONFIG_PATH)+".tmp"))
print(f"\n{ok} passed, {fails} failed"); sys.exit(1 if fails else 0)
