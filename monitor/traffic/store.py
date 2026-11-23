"""SQLite persistence for the Traffic Analyzer (same monitor.db as the rest of Net-monit). Tables are created on first use."""
import json
import time

from .. import database as db

_ready = set()             # per database file


def init():
    if str(db.DB_PATH) in _ready:
        return
    with db._lock:
        c = db.get_connection()
        with c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS traffic_session (
                id INTEGER PRIMARY KEY AUTOINCREMENT, started_ts REAL, ended_ts REAL, source_type TEXT, source_name TEXT, bpf TEXT,
                status TEXT, in_bytes INTEGER DEFAULT 0, out_bytes INTEGER DEFAULT 0, in_packets INTEGER DEFAULT 0, out_packets INTEGER DEFAULT 0,
                connections INTEGER DEFAULT 0, pcap_path TEXT, note TEXT);
            CREATE TABLE IF NOT EXISTS traffic_minute (
                session_id INTEGER, minute_ts INTEGER, in_bytes INTEGER, out_bytes INTEGER, in_packets INTEGER, out_packets INTEGER,
                PRIMARY KEY (session_id, minute_ts));
            CREATE TABLE IF NOT EXISTS traffic_conn (
                session_id INTEGER, conn_id INTEGER, src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER, proto TEXT, direction TEXT,
                service TEXT, bytes INTEGER, packets INTEGER, first_ts REAL, last_ts REAL, remote TEXT, host TEXT, country TEXT, asn INTEGER,
                asn_name TEXT, program TEXT, blacklisted INTEGER, PRIMARY KEY (session_id, conn_id));
            CREATE TABLE IF NOT EXISTS traffic_favorite (
                id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, value TEXT, label TEXT, created_ts REAL, UNIQUE(kind, value));
            CREATE TABLE IF NOT EXISTS traffic_notification (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, title TEXT, text TEXT, session_id INTEGER, data_json TEXT);
            CREATE TABLE IF NOT EXISTS traffic_setting (key TEXT PRIMARY KEY, value TEXT);
            CREATE INDEX IF NOT EXISTS ix_traffic_notification_ts ON traffic_notification(ts);
            CREATE INDEX IF NOT EXISTS ix_traffic_conn_bytes ON traffic_conn(session_id, bytes);
            """)
        c.close()
    _ready.add(str(db.DB_PATH))


def _q(sql, args=(), one=False, write=False):
    init()
    with db._lock:
        c = db.get_connection()
        try:
            if write:
                with c:
                    cur = c.execute(sql, args); return cur.lastrowid
            rows = c.execute(sql, args).fetchall()
            return (dict(rows[0]) if rows else None) if one else [dict(r) for r in rows]
        finally:
            c.close()


# ---- settings (JSON values) ----
def get_setting(key, default=None):
    r = _q("SELECT value FROM traffic_setting WHERE key=?", (key,), one=True)
    if not r: return default
    try: return json.loads(r["value"])
    except Exception: return default


def set_setting(key, value):
    _q("INSERT INTO traffic_setting(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, json.dumps(value)), write=True)


# ---- sessions ----
def create_session(source_type, source_name, bpf="", pcap_path=""):
    return _q("INSERT INTO traffic_session(started_ts,source_type,source_name,bpf,status,pcap_path) VALUES(?,?,?,?,?,?)",
              (time.time(), source_type, source_name, bpf, "running", pcap_path), write=True)


def update_session(sid, **kw):
    if not kw: return
    cols = ", ".join(f"{k}=?" for k in kw)
    _q(f"UPDATE traffic_session SET {cols} WHERE id=?", (*kw.values(), sid), write=True)


def list_sessions(limit=50):
    return _q("SELECT * FROM traffic_session ORDER BY id DESC LIMIT ?", (limit,))


def get_session(sid):
    return _q("SELECT * FROM traffic_session WHERE id=?", (sid,), one=True)


def delete_session(sid):
    for t in ("traffic_minute", "traffic_conn"):
        _q(f"DELETE FROM {t} WHERE session_id=?", (sid,), write=True)
    _q("DELETE FROM traffic_session WHERE id=?", (sid,), write=True)


def mark_interrupted():
    """A capture that was 'running' when the server stopped can never be finished: mark it so History is honest."""
    _q("UPDATE traffic_session SET status='interrupted', ended_ts=COALESCE(ended_ts, started_ts) WHERE status='running'", write=True)


def purge_older_than(days):
    cut = time.time() - days * 86400
    ids = [r["id"] for r in _q("SELECT id FROM traffic_session WHERE started_ts<? AND status!='running'", (cut,))]
    for i in ids: delete_session(i)
    _q("DELETE FROM traffic_notification WHERE ts<?", (cut,), write=True)
    return len(ids)


# ---- history ----
def save_minutes(sid, rows):
    """rows: [(minute_ts, in_b, out_b, in_p, out_p)] (upsert: the current minute grows while the capture runs)"""
    init()
    with db.batch():
        c = db.get_connection()
        for r in rows:
            c.execute("INSERT INTO traffic_minute VALUES(?,?,?,?,?,?) ON CONFLICT(session_id,minute_ts) DO UPDATE SET in_bytes=excluded.in_bytes,"
                      "out_bytes=excluded.out_bytes,in_packets=excluded.in_packets,out_packets=excluded.out_packets", (sid, *r))


def get_minutes(sid):
    return _q("SELECT minute_ts,in_bytes,out_bytes,in_packets,out_packets FROM traffic_minute WHERE session_id=? ORDER BY minute_ts", (sid,))


def save_conns(sid, rows):
    """Replace the saved top connections of a session. rows: list of dicts."""
    init()
    with db.batch():
        c = db.get_connection()
        c.execute("DELETE FROM traffic_conn WHERE session_id=?", (sid,))
        c.executemany("INSERT INTO traffic_conn VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      [(sid, r["id"], r["src_ip"], r["src_port"], r["dst_ip"], r["dst_port"], r["proto"], r["direction"], r["service"], r["bytes"],
                        r["packets"], r["first"], r["last"], r["remote"], r.get("host", ""), r.get("country", ""), r.get("asn", 0), r.get("asn_name", ""),
                        r.get("program") or "", 1 if r["blacklisted"] else 0) for r in rows])


def get_conns(sid, limit=5000):
    return _q("SELECT * FROM traffic_conn WHERE session_id=? ORDER BY bytes DESC LIMIT ?", (sid, limit))


# ---- favorites ----
def list_favorites():
    return _q("SELECT id,kind,value,label,created_ts FROM traffic_favorite ORDER BY id")


def add_favorite(kind, value, label=""):
    _q("INSERT OR IGNORE INTO traffic_favorite(kind,value,label,created_ts) VALUES(?,?,?,?)", (kind, value, label or value, time.time()), write=True)


def delete_favorite(kind, value):
    _q("DELETE FROM traffic_favorite WHERE kind=? AND value=?", (kind, value), write=True)


# ---- notification log ----
def log_notification(kind, title, text, session_id=None, data=None):
    _q("INSERT INTO traffic_notification(ts,kind,title,text,session_id,data_json) VALUES(?,?,?,?,?,?)",
       (time.time(), kind, title, text, session_id, json.dumps(data or {})), write=True)
    _q("DELETE FROM traffic_notification WHERE id NOT IN (SELECT id FROM traffic_notification ORDER BY id DESC LIMIT 500)", write=True)


def list_notifications(limit=100):
    rows = _q("SELECT * FROM traffic_notification ORDER BY id DESC LIMIT ?", (limit,))
    for r in rows:
        try: r["data"] = json.loads(r.pop("data_json") or "{}")
        except Exception: r["data"] = {}
    return rows


def clear_notifications():
    _q("DELETE FROM traffic_notification", write=True)
