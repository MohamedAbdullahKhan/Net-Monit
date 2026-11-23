"""Traffic notifications. Three Sniffnet rules (data threshold per second, favorite transmitted, blacklisted address transmitted)
plus Net-monit delivery: notification log (SQLite), audit log, e-mail to the SMTP admin group, SMS / voice call through the
configured gateways, webhook POST (Sniffnet 'remote notifications') and an optional browser sound."""
import json
import re
import smtplib
import ssl
import threading
import time
import urllib.request
from email.mime.text import MIMEText

from . import store

SOUNDS = ("none", "pop", "gulp", "swhoosh")
MULT = {"": 1, "k": 10 ** 3, "m": 10 ** 6, "g": 10 ** 9, "t": 10 ** 12}

DEFAULTS = {
    "volume": 50,
    "webhook": {"enabled": False, "url": ""},
    "email": {"enabled": False, "min_interval_sec": 300},
    "sms": {"enabled": False, "numbers": [], "min_interval_sec": 600},
    "call": {"enabled": False, "numbers": [], "min_interval_sec": 1800},
    "data": {"enabled": False, "unit": "bytes", "threshold": 1000000, "sound": "pop"},
    "favorite": {"enabled": False, "sound": "gulp"},
    "blacklist": {"enabled": False, "sound": "swhoosh"},
}


def parse_threshold(text, previous=None):
    """'500' / '500k' / '2.5M' / '1g' -> integer, like Sniffnet's field. Unparseable input keeps the previous value."""
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([kKmMgGtT]?)[bB]?\s*", str(text))
    if not m: return previous
    return int(float(m.group(1)) * MULT[m.group(2).lower()])


def get_settings():
    s = store.get_setting("notifications", {}) or {}
    out = json.loads(json.dumps(DEFAULTS))
    for k, v in s.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict): out[k].update(v)
        elif k in out: out[k] = v
    return out


def save_settings(new):
    cur = get_settings()
    for k, v in (new or {}).items():
        if k not in cur: continue
        if isinstance(v, dict) and isinstance(cur[k], dict):
            for kk, vv in v.items():
                if kk in cur[k]: cur[k][kk] = vv
        else: cur[k] = v
    url = str(cur["webhook"].get("url") or "").strip()
    if url and not url.lower().startswith(("http://", "https://")): raise ValueError("Webhook URL must start with http:// or https://")
    cur["webhook"]["url"] = url
    d = cur["data"]
    d["threshold"] = max(0, parse_threshold(d["threshold"], 1000000) or 0)
    if d["unit"] not in ("bytes", "bits", "packets"): d["unit"] = "bytes"
    for k in ("data", "favorite", "blacklist"):
        if cur[k].get("sound") not in SOUNDS: cur[k]["sound"] = "none"
    cur["volume"] = max(0, min(100, int(cur["volume"] or 0)))
    for k in ("sms", "call"):
        cur[k]["numbers"] = [str(n).strip() for n in cur[k].get("numbers", []) if str(n).strip()][:10]
    store.set_setting("notifications", cur)
    return cur


def fmt_bytes(n):
    for u in ("B", "kB", "MB", "GB", "TB"):
        if n < 1000 or u == "TB": return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1000.0


class Notifier:
    """Callable used by Engine: notifier(engine, second, interval)."""

    def __init__(self, session_id_fn, favorites_fn, sink=None):
        self.session_id_fn, self.favorites_fn = session_id_fn, favorites_fn
        self.sink = sink or []                                   # list of callables (kind, title, text, data) for the live UI (sound etc.)
        self.last_sent = {}; self.emitted = 0; self.settings = get_settings(); self._load = time.time()

    def _s(self):
        if time.time() - self._load > 5: self.settings = get_settings(); self._load = time.time()
        return self.settings

    def __call__(self, eng, sec, iv):
        s = self._s(); fired = []
        t = iv["tot"]
        d = s["data"]
        if d["enabled"] and d["threshold"]:
            val = (t[0] + t[1]) if d["unit"] == "bytes" else (t[0] + t[1]) * 8 if d["unit"] == "bits" else (t[2] + t[3])
            if val > d["threshold"]:
                top_h = sorted(((a, sum(v[:2])) for a, v in iv["addrs"].items()), key=lambda x: -x[1])[:5]
                top_s = sorted(((n, sum(v[:2])) for n, v in iv["services"].items()), key=lambda x: -x[1])[:5]
                fired.append(("data", "Data threshold exceeded",
                              f"{val:,} {d['unit']} in 1 s (threshold {d['threshold']:,}). In {fmt_bytes(t[0])} / out {fmt_bytes(t[1])}. "
                              f"Top hosts: {', '.join(eng.host_of(a)['name'] for a, _ in top_h) or '-'}. Top services: {', '.join(n for n, _ in top_s) or '-'}.",
                              {"in_bytes": t[0], "out_bytes": t[1], "in_packets": t[2], "out_packets": t[3]}, d["sound"]))
        if s["favorite"]["enabled"]:
            favs = self.favorites_fn()
            hit = []
            if favs:
                fh = {f["value"] for f in favs if f["kind"] == "host"}; fs = {f["value"] for f in favs if f["kind"] == "service"}
                fp = {f["value"] for f in favs if f["kind"] == "program"}
                for a, v in iv["addrs"].items():
                    h = eng.host_of(a)
                    if h["name"] in fh or a in fh or (h["domain"] and h["domain"] in fh): hit.append(("host", h["name"], v))
                for n, v in iv["services"].items():
                    if n in fs: hit.append(("service", n, v))
                for n, v in iv["programs"].items():
                    if n in fp: hit.append(("program", n, v))
            for kind, name, v in hit:
                fired.append(("favorite", "Favorite transmitted", f"{kind} '{name}' exchanged {fmt_bytes(v[0] + v[1])} ({v[2] + v[3]} packets) in the last second.",
                              {"favorite": {"kind": kind, "value": name}}, s["favorite"]["sound"]))
        if s["blacklist"]["enabled"]:
            seen = {}
            for k, (b, p) in iv["conns"].items():
                info = eng.conns.get(k)
                if info and info.blacklisted:
                    e = seen.setdefault(info.addr, [0, 0]); e[0] += b; e[1] += p
            for a, (b, p) in seen.items():
                fired.append(("blacklist", "Blacklisted address transmitted", f"{a} ({eng.host_of(a)['name']}) exchanged {fmt_bytes(b)} in the last second.",
                              {"ip": a}, s["blacklist"]["sound"]))
        for kind, title, text, data, sound in fired:
            self.emit(kind, title, text, data, sound, s)

    def emit(self, kind, title, text, data, sound, s):
        self.emitted += 1
        sid = self.session_id_fn()
        try: store.log_notification(kind, title, text, sid, dict(data or {}, sound=sound))
        except Exception: pass
        for f in self.sink:
            try: f(kind, title, text, data, sound, s["volume"])
            except Exception: pass
        threading.Thread(target=self._deliver, args=(kind, title, text, data, s), daemon=True).start()

    def _deliver(self, kind, title, text, data, s):
        try:
            from .. import database as db, config_manager as cm
            try: db.audit_log("traffic", "traffic_" + kind, title, text[:300])
            except Exception: pass
            now = time.time(); body = f"[Net-monit Traffic] {title}: {text}"
            if s["webhook"]["enabled"] and s["webhook"]["url"]:
                try:
                    req = urllib.request.Request(s["webhook"]["url"], data=json.dumps({"app": "net-monit", "kind": kind, "title": title, "text": text, "data": data, "time": now}).encode(),
                                                 headers={"Content-Type": "application/json", "User-Agent": "net-monit-traffic"})
                    urllib.request.urlopen(req, timeout=8).read()
                except Exception: pass
            for ch in ("email", "sms", "call"):
                cfg = s[ch]
                if not cfg.get("enabled"): continue
                if now - self.last_sent.get((ch, kind), 0) < cfg.get("min_interval_sec", 300): continue
                self.last_sent[(ch, kind)] = now
                if ch == "email": send_email(cm.get_config().get("smtp", {}), title, body)
                else:
                    from .. import messaging_gateway as mg
                    for n in cfg.get("numbers", []):
                        (mg.send_sms if ch == "sms" else mg.send_call)(n, body[:300])
        except Exception:
            pass


def send_email(smtp, subject, body):
    """Mail to the SMTP admin group (same recipients and server as device alerts)."""
    if not smtp.get("enabled"): return False, "SMTP disabled"
    to = smtp.get("admin_emails") or smtp.get("to_addresses") or []
    if not to: return False, "No admin e-mail addresses configured"
    msg = MIMEText(body, "plain"); msg["Subject"] = f"[Net-monit Traffic] {subject}"
    msg["From"] = smtp.get("from_address") or smtp.get("username", ""); msg["To"] = ", ".join(to)
    try:
        if smtp.get("use_tls", True):
            with smtplib.SMTP(smtp["host"], smtp["port"], timeout=15) as s:
                s.starttls(context=ssl.create_default_context()); s.login(smtp["username"], smtp["password"]); s.sendmail(msg["From"], to, msg.as_string())
        else:
            with smtplib.SMTP_SSL(smtp["host"], smtp["port"], timeout=15) as s:
                s.login(smtp["username"], smtp["password"]); s.sendmail(msg["From"], to, msg.as_string())
        return True, "Sent"
    except Exception as e:
        return False, str(e)
