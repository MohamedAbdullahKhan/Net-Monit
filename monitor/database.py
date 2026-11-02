# =============================================================================
# Net-monit V11.3
# Copyright (c) 2024-2026 Abdullah. All rights reserved.
# Contact: abuabdullah.be@outlook.com
# Unauthorised copying, modification or distribution of this software
# is strictly prohibited without prior written permission from the author.
# =============================================================================
"""
database.py  —  Net-monit V11.3
SQLite storage — extended for multi-level escalation in device_notify.
"""
import json
import sqlite3
import time
import contextlib
import threading
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "monitor.db"
_lock = threading.RLock()   # V11.3 patch 06: re-entrant, so batch() can hold it around functions that also take it


_local = threading.local()
_wal_done = False


def _open_connection():
    """One SQLite connection. V11.3 patch 06: journal_mode=WAL is persistent in the DB file, so it is set once per
    process (it used to be re-issued, as a write, on EVERY connection); synchronous=NORMAL is the recommended
    setting for WAL (no fsync per commit; still crash-safe for the application); busy_timeout makes a save wait
    for the scheduler's write instead of failing."""
    global _wal_done
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    if not _wal_done:
        conn.execute("PRAGMA journal_mode=WAL;")
        _wal_done = True
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


class _SharedConn:
    """Stand-in handed out inside batch(): same connection for every call, commit/close deferred to the end."""
    def __init__(self, c): self._c = c
    def __getattr__(self, n): return getattr(self._c, n)
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def commit(self): pass
    def close(self): pass


@contextlib.contextmanager
def batch():
    """V11.3 patch 06: run many writes (e.g. 'apply to 300 devices') on ONE connection and ONE commit instead of
    one connection + commit per device."""
    if getattr(_local, "conn", None) is not None:      # nested: join the outer batch
        yield
        return
    # Take the process-wide write lock FIRST, then open the SQLite write transaction. The other order (SQLite lock
    # held while waiting for _lock) can deadlock against the scheduler thread, which does the opposite.
    with _lock:
        c = _open_connection()
        _local.conn = _SharedConn(c)
        try:
            c.execute("BEGIN")
            yield
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            _local.conn = None
            c.close()


def get_connection():
    shared = getattr(_local, "conn", None)
    return shared if shared is not None else _open_connection()


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection()
    with conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS device_status (
                device_id      TEXT PRIMARY KEY,
                name           TEXT,
                type           TEXT,
                method         TEXT,
                host           TEXT,
                status         TEXT DEFAULT 'unknown',
                last_checked   REAL,
                last_error     TEXT,
                metrics_json   TEXT
            );
            CREATE TABLE IF NOT EXISTS metric_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id   TEXT,
                metric      TEXT,
                value       REAL,
                state       TEXT,
                ts          REAL
            );
            CREATE TABLE IF NOT EXISTS alert_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id   TEXT,
                device_name TEXT,
                metric      TEXT,
                value       REAL,
                state       TEXT,
                message     TEXT,
                ts          REAL,
                emailed     INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS alert_state (
                device_id           TEXT,
                metric              TEXT,
                current_state       TEXT,
                last_email_ts       REAL,
                worst_state         TEXT DEFAULT 'ok',
                alert_started_ts    REAL,
                escalated           INTEGER DEFAULT 0,
                PRIMARY KEY (device_id, metric)
            );
            CREATE TABLE IF NOT EXISTS dashboard_tiles (
                device_id   TEXT PRIMARY KEY,
                position    INTEGER DEFAULT 0,
                hidden      INTEGER DEFAULT 0
            );
            -- Per-user dashboard prefs (view type, grid density, tile layout,
            -- theme, etc.) all live as key/value rows here, keyed by email.
            -- (V8.2: removed two earlier, never-wired-up dedicated tables
            -- that duplicated this -- see database.py history / changelog.)
            CREATE TABLE IF NOT EXISTS user_prefs_kv (
                email     TEXT NOT NULL,
                pref_key  TEXT NOT NULL,
                pref_value TEXT DEFAULT '',
                PRIMARY KEY (email, pref_key)
            );
            -- email_users: role = admin | user
            CREATE TABLE IF NOT EXISTS email_users (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                email       TEXT UNIQUE NOT NULL,
                email_hash  TEXT NOT NULL,
                role        TEXT NOT NULL DEFAULT 'user',
                token_hash  TEXT NOT NULL,
                active      INTEGER DEFAULT 1,
                created_ts  REAL
            );
            -- device_notify: extended for multi-level escalation (V3.4)
            CREATE TABLE IF NOT EXISTS device_notify (
                device_id                   TEXT PRIMARY KEY,
                notifications_enabled       INTEGER DEFAULT 1,
                notify_emails_json          TEXT DEFAULT '[]',
                -- L1 escalation (was escalation_emails in V3.3)
                escalation_emails_l1_json   TEXT DEFAULT '[]',
                -- L2 escalation
                escalation_emails_l2_json   TEXT DEFAULT '[]',
                -- L3 escalation
                escalation_emails_l3_json   TEXT DEFAULT '[]',
                -- time thresholds per level (seconds)
                escalation_after_sec_l1     INTEGER DEFAULT 60,   -- V8.2: default changed from 300 to 60 (sustained-mode confirm window)
                escalation_after_sec_l2     INTEGER DEFAULT 600,
                escalation_after_sec_l3     INTEGER DEFAULT 1200,
                -- how many levels are active (1, 2, or 3)
                escalation_levels           INTEGER DEFAULT 1,
                thresholds_json             TEXT DEFAULT '{}',
                -- V8.2: 'sustained' (default as of V8.2 -- wait for the L1
                -- timer to confirm before emailing at all, see alerts.py)
                -- or 'immediate' (email on first detection, no confirm
                -- delay -- this was the default before V8.2's alert-timing
                -- refinement; still available as an explicit opt-in).
                alert_trigger_mode          TEXT DEFAULT 'sustained'
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                actor       TEXT,
                action      TEXT,
                target      TEXT,
                detail      TEXT,
                ts          REAL
            );
            CREATE TABLE IF NOT EXISTS license_record (
                id              INTEGER PRIMARY KEY CHECK (id = 1),
                device_id       TEXT,
                activation_code TEXT,
                license_key     TEXT DEFAULT '',
                trial_start     REAL,
                activated       INTEGER DEFAULT 0
            );
            -- V8.2: moved here from a lazy create-on-first-use helper
            -- (_ensure_active_alerts_table, still called defensively
            -- elsewhere) -- it needs to exist before the very first alert
            -- ever fires, e.g. so purge_device() can reference it safely
            -- on a brand new install with zero alert history.
            CREATE TABLE IF NOT EXISTS active_alerts (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id       TEXT NOT NULL,
                device_name     TEXT,
                device_host     TEXT,
                metric          TEXT,
                severity        TEXT,      -- warning | critical
                message         TEXT,
                status          TEXT DEFAULT 'active',  -- active | acknowledged | resolved
                triggered_ts    REAL,
                acknowledged_ts REAL,
                acknowledged_by TEXT,
                ack_until_ts    REAL,      -- suppress re-escalation until this time
                resolved_ts     REAL,
                resolved_by     TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_active_alerts_lookup
            ON active_alerts (device_id, metric, status);
            -- New feature: admin-editable notification email templates,
            -- one row per alert state (warning/critical/offline/recovered).
            -- A state with NO row here uses the app's built-in default
            -- template (see monitor/notification_templates.py) -- this
            -- table only stores the admin's *overrides*, so an empty table
            -- is a perfectly normal, fully-working state (nothing has been
            -- customized yet).
            CREATE TABLE IF NOT EXISTS notification_templates (
                state             TEXT PRIMARY KEY,   -- warning | critical | offline | recovered
                subject_template  TEXT,
                text_template     TEXT,
                html_template     TEXT,
                enabled           INTEGER DEFAULT 1,
                updated_ts        REAL,
                updated_by        TEXT
            );
            -- V8.4: admin-defined static text placeholders (e.g. {{company_name}}),
            -- distinct from the built-in system placeholders in
            -- notification_templates.py which are populated from live alert data.
            CREATE TABLE IF NOT EXISTS custom_placeholders (
                key               TEXT PRIMARY KEY,
                value             TEXT DEFAULT '',
                description       TEXT DEFAULT '',
                created_ts        REAL,
                updated_ts        REAL,
                updated_by        TEXT
            );
            -- V8.5: self-service "forgot your token" resets. reset_token_hash
            -- follows the exact same "never store the raw secret" rule as
            -- email_users.token_hash -- only a SHA-256 hash sits in this
            -- table; the raw reset token exists only in the emailed link and
            -- in memory for the few seconds it takes to hash it.
            CREATE TABLE IF NOT EXISTS token_reset_requests (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                email             TEXT NOT NULL,
                reset_token_hash  TEXT NOT NULL,
                created_ts        REAL,
                expires_ts        REAL,
                used              INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_token_reset_hash ON token_reset_requests (reset_token_hash);
        """)

        def _cols(table):
            return [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]

        # Schema migrations for existing databases (V3.3 → V3.4)
        migrations = [
            ("worst_state",             "alert_state",  "TEXT DEFAULT 'ok'"),
            ("alert_started_ts",        "alert_state",  "REAL"),
            ("escalated",               "alert_state",  "INTEGER DEFAULT 0"),
            # V7.2 fix: dashboard_tiles was only ever created with
            # (device_id, position, hidden) but get_dashboard_layout()'s
            # fallback path selects size/col/row too -- this was crashing
            # every single logged-in /api/status call with
            # "sqlite3.OperationalError: no such column: size".
            ("size", "dashboard_tiles", "TEXT DEFAULT 'normal'"),
            ("col",  "dashboard_tiles", "INTEGER DEFAULT 0"),
            ("row",  "dashboard_tiles", "INTEGER DEFAULT 0"),
            ("escalation_emails_l1_json","device_notify","TEXT DEFAULT '[]'"),
            ("escalation_emails_l2_json","device_notify","TEXT DEFAULT '[]'"),
            ("escalation_emails_l3_json","device_notify","TEXT DEFAULT '[]'"),
            ("escalation_after_sec_l1", "device_notify","INTEGER DEFAULT 60"),
            ("escalation_after_sec_l2", "device_notify","INTEGER DEFAULT 600"),
            ("escalation_after_sec_l3", "device_notify","INTEGER DEFAULT 1200"),
            ("escalation_levels",       "device_notify","INTEGER DEFAULT 1"),
            # V8.2: alert trigger mode (immediate vs sustained-confirm)
            ("alert_trigger_mode",      "device_notify","TEXT DEFAULT 'sustained'"),
            # V8.4: repeat-alert cooldown. Distinct from alert_trigger_mode
            # above -- that controls the delay before the FIRST alert of a
            # new episode; these two control the minimum gap between
            # REPEAT alerts once an episode is already open (the anti-flap
            # / anti-spam control). See alerts.py::process_alerts().
            ("alert_notify_mode",       "device_notify","TEXT DEFAULT 'immediate'"),
            ("notify_cooldown_sec",     "device_notify","INTEGER DEFAULT 300"),
            # V8.5: SMS / voice-call escalation numbers, per level -- same
            # JSON-array-of-strings shape as the escalation_emails_lN
            # columns above, just phone numbers instead of email addresses.
            # An empty array means that channel is off at that level,
            # exactly the same "empty = disabled" convention the email
            # columns already use -- no separate enable/disable flag
            # needed. SMS can be used at L1 (primary/first alert) same as
            # any level -- there's nothing escalation-only about it; a
            # device with sms_numbers_l1 populated gets an SMS on the
            # very first alert, same as email would.
            ("sms_numbers_l1_json",     "device_notify","TEXT DEFAULT '[]'"),
            ("sms_numbers_l2_json",     "device_notify","TEXT DEFAULT '[]'"),
            ("sms_numbers_l3_json",     "device_notify","TEXT DEFAULT '[]'"),
            ("call_numbers_l1_json",    "device_notify","TEXT DEFAULT '[]'"),
            ("call_numbers_l2_json",    "device_notify","TEXT DEFAULT '[]'"),
            ("call_numbers_l3_json",    "device_notify","TEXT DEFAULT '[]'"),
        ]
        for col, tbl, defn in migrations:
            if col not in _cols(tbl):
                conn.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} {defn}")

        # Migrate old escalation_emails_json → escalation_emails_l1_json
        old_cols = _cols("device_notify")
        if "escalation_emails_json" in old_cols:
            conn.execute("""
                UPDATE device_notify
                SET escalation_emails_l1_json = escalation_emails_json
                WHERE escalation_emails_l1_json = '[]' AND escalation_emails_json != '[]'
            """)
        if "escalation_after_sec" in old_cols:
            conn.execute("""
                UPDATE device_notify
                SET escalation_after_sec_l1 = escalation_after_sec
                WHERE escalation_after_sec_l1 = 300 AND escalation_after_sec != 300
            """)

    conn.close()


# ============================================================
# Device status
# ============================================================
def purge_device(device_id):
    with _lock:
        conn = get_connection()
        with conn:
            for tbl in ("device_status", "metric_history", "alert_state",
                        "dashboard_tiles", "device_notify", "active_alerts"):
                conn.execute(f"DELETE FROM {tbl} WHERE device_id=?", (device_id,))
        conn.close()


def upsert_device_status(device_id, name, dtype, method, host, status, metrics, error=None):
    with _lock:
        conn = get_connection()
        with conn:
            conn.execute("""
                INSERT INTO device_status
                    (device_id, name, type, method, host, status, last_checked, last_error, metrics_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    name=excluded.name, type=excluded.type, method=excluded.method,
                    host=excluded.host, status=excluded.status,
                    last_checked=excluded.last_checked,
                    last_error=excluded.last_error, metrics_json=excluded.metrics_json
            """, (device_id, name, dtype, method, host, status,
                  time.time(), error, json.dumps(metrics or {})))
        conn.close()


def get_all_device_status():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM device_status ORDER BY name").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ============================================================
# Metric history
# ============================================================
def record_metric(device_id, metric, value, state):
    with _lock:
        conn = get_connection()
        with conn:
            conn.execute(
                "INSERT INTO metric_history (device_id,metric,value,state,ts) VALUES (?,?,?,?,?)",
                (device_id, metric, value, state, time.time()))
            conn.execute("DELETE FROM metric_history WHERE ts<?", (time.time() - 14 * 86400,))
        conn.close()


def get_metric_history(device_id, metric, since_seconds=3600):
    conn = get_connection()
    rows = conn.execute(
        "SELECT value,state,ts FROM metric_history WHERE device_id=? AND metric=? AND ts>? ORDER BY ts ASC",
        (device_id, metric, time.time() - since_seconds)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ============================================================
# Alert state + log
# ============================================================
def get_alert_state(device_id, metric):
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM alert_state WHERE device_id=? AND metric=?",
        (device_id, metric)).fetchone()
    conn.close()
    return dict(row) if row else None


def set_alert_state(device_id, metric, state, last_email_ts,
                    worst_state=None, alert_started_ts=None, escalated=None):
    with _lock:
        conn = get_connection()
        prev = conn.execute(
            "SELECT * FROM alert_state WHERE device_id=? AND metric=?",
            (device_id, metric)).fetchone()
        prev = dict(prev) if prev else {}
        ws  = worst_state      if worst_state      is not None else prev.get("worst_state", "ok")
        ast = alert_started_ts if alert_started_ts is not None else prev.get("alert_started_ts")
        esc = escalated        if escalated         is not None else prev.get("escalated", 0)
        with conn:
            conn.execute("""
                INSERT INTO alert_state
                    (device_id, metric, current_state, last_email_ts, worst_state,
                     alert_started_ts, escalated)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id, metric) DO UPDATE SET
                    current_state=excluded.current_state,
                    last_email_ts=excluded.last_email_ts,
                    worst_state=excluded.worst_state,
                    alert_started_ts=excluded.alert_started_ts,
                    escalated=excluded.escalated
            """, (device_id, metric, state, last_email_ts, ws, ast, esc))
        conn.close()


def log_alert(device_id, device_name, metric, value, state, message, emailed):
    with _lock:
        conn = get_connection()
        with conn:
            conn.execute("""
                INSERT INTO alert_log
                    (device_id, device_name, metric, value, state, message, ts, emailed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (device_id, device_name, metric, value, state, message, time.time(), int(emailed)))
        conn.close()


def get_recent_alerts(limit=100):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM alert_log ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ============================================================
# Dashboard tile layout
# ============================================================
def get_tile_layout():
    conn = get_connection()
    # Ensure size column exists (V3.5)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(dashboard_tiles)").fetchall()]
    if "size" not in cols:
        conn.execute("ALTER TABLE dashboard_tiles ADD COLUMN size TEXT DEFAULT 'normal'")
        conn.commit()
    rows = conn.execute("SELECT * FROM dashboard_tiles").fetchall()
    conn.close()
    result = {}
    for r in rows:
        rd = dict(r)
        result[rd["device_id"]] = {
            "position": rd["position"],
            "hidden":   bool(rd["hidden"]),
            "size":     rd.get("size", "normal"),
        }
    return result


def set_tile_size(device_id, size="normal"):
    """Store tile size preference: normal | wide | tall"""
    with _lock:
        conn = get_connection()
        cols = [r[1] for r in conn.execute("PRAGMA table_info(dashboard_tiles)").fetchall()]
        if "size" not in cols:
            with conn:
                conn.execute("ALTER TABLE dashboard_tiles ADD COLUMN size TEXT DEFAULT 'normal'")
        with conn:
            conn.execute("""
                INSERT INTO dashboard_tiles (device_id, position, hidden, size)
                VALUES (?, COALESCE((SELECT position FROM dashboard_tiles WHERE device_id=?), 0),
                        COALESCE((SELECT hidden FROM dashboard_tiles WHERE device_id=?), 0), ?)
                ON CONFLICT(device_id) DO UPDATE SET size=excluded.size
            """, (device_id, device_id, device_id, size))
        conn.close()


def set_tile_hidden(device_id, hidden):
    with _lock:
        conn = get_connection()
        with conn:
            conn.execute("""
                INSERT INTO dashboard_tiles (device_id, position, hidden)
                VALUES (?, COALESCE((SELECT position FROM dashboard_tiles WHERE device_id=?), 0), ?)
                ON CONFLICT(device_id) DO UPDATE SET hidden=excluded.hidden
            """, (device_id, device_id, int(hidden)))
        conn.close()


def set_tile_order(device_ids):
    with _lock:
        conn = get_connection()
        with conn:
            for pos, did in enumerate(device_ids):
                conn.execute("""
                    INSERT INTO dashboard_tiles (device_id, position, hidden)
                    VALUES (?, ?, COALESCE((SELECT hidden FROM dashboard_tiles WHERE device_id=?), 0))
                    ON CONFLICT(device_id) DO UPDATE SET position=excluded.position
                """, (did, pos, did))
        conn.close()


# ============================================================
# V5.0: Per-user dashboard tile layout
# NOTE (V8.2): an earlier, never-fully-wired-up attempt at per-user layout
# and view-mode storage (user_tile_layout / user_dashboard_prefs tables)
# lived here and was removed -- nothing in app.py or the frontend ever
# called it. The live implementation is get_dashboard_layout() /
# save_dashboard_layout() and get_user_pref()/set_user_pref() below, both
# backed by user_prefs_kv.


# ============================================================
# Per-device notification config (V3.4 multi-level escalation)
# ============================================================
def get_device_notify(device_id):
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM device_notify WHERE device_id=?", (device_id,)).fetchone()
    conn.close()
    if row:
        r = dict(row)
        r["notify_emails"]         = json.loads(r.get("notify_emails_json") or "[]")
        r["escalation_emails_l1"]  = json.loads(r.get("escalation_emails_l1_json") or "[]")
        r["escalation_emails_l2"]  = json.loads(r.get("escalation_emails_l2_json") or "[]")
        r["escalation_emails_l3"]  = json.loads(r.get("escalation_emails_l3_json") or "[]")
        r["thresholds"]            = json.loads(r.get("thresholds_json") or "{}")
        # Back-compat: escalation_emails = L1 list
        r["escalation_emails"]     = r["escalation_emails_l1"]
        r["escalation_after_sec"]  = r.get("escalation_after_sec_l1", 60)
        r["alert_trigger_mode"]    = r.get("alert_trigger_mode") or "sustained"
        r["alert_notify_mode"]     = r.get("alert_notify_mode") or "immediate"
        r["notify_cooldown_sec"]   = r.get("notify_cooldown_sec") or 300
        r["sms_numbers_l1"]        = json.loads(r.get("sms_numbers_l1_json") or "[]")
        r["sms_numbers_l2"]        = json.loads(r.get("sms_numbers_l2_json") or "[]")
        r["sms_numbers_l3"]        = json.loads(r.get("sms_numbers_l3_json") or "[]")
        r["call_numbers_l1"]       = json.loads(r.get("call_numbers_l1_json") or "[]")
        r["call_numbers_l2"]       = json.loads(r.get("call_numbers_l2_json") or "[]")
        r["call_numbers_l3"]       = json.loads(r.get("call_numbers_l3_json") or "[]")
        return r
    return {
        "device_id": device_id,
        "notifications_enabled": 1,
        "notify_emails": [],
        "escalation_emails_l1": [],
        "escalation_emails_l2": [],
        "escalation_emails_l3": [],
        "escalation_after_sec_l1": 60,
        "escalation_after_sec_l2": 600,
        "escalation_after_sec_l3": 1200,
        "escalation_levels": 1,
        "thresholds": {},
        "escalation_emails": [],
        "escalation_after_sec": 300,
        "alert_trigger_mode": "sustained",
        "alert_notify_mode": "immediate",
        "notify_cooldown_sec": 300,
        "sms_numbers_l1": [], "sms_numbers_l2": [], "sms_numbers_l3": [],
        "call_numbers_l1": [], "call_numbers_l2": [], "call_numbers_l3": [],
    }


def set_device_notify(device_id, notifications_enabled, notify_emails,
                      escalation_emails_l1, escalation_emails_l2, escalation_emails_l3,
                      escalation_after_sec_l1, escalation_after_sec_l2, escalation_after_sec_l3,
                      escalation_levels, thresholds, alert_trigger_mode="sustained",
                      alert_notify_mode="immediate", notify_cooldown_sec=300,
                      sms_numbers_l1=None, sms_numbers_l2=None, sms_numbers_l3=None,
                      call_numbers_l1=None, call_numbers_l2=None, call_numbers_l3=None):
    if alert_trigger_mode not in ("immediate", "sustained"):
        alert_trigger_mode = "sustained"
    if alert_notify_mode not in ("immediate", "cooldown"):
        alert_notify_mode = "immediate"
    try:
        notify_cooldown_sec = max(1, int(notify_cooldown_sec))
    except (TypeError, ValueError):
        notify_cooldown_sec = 300
    with _lock:
        conn = get_connection()
        with conn:
            conn.execute("""
                INSERT INTO device_notify
                    (device_id, notifications_enabled, notify_emails_json,
                     escalation_emails_l1_json, escalation_emails_l2_json, escalation_emails_l3_json,
                     escalation_after_sec_l1, escalation_after_sec_l2, escalation_after_sec_l3,
                     escalation_levels, thresholds_json, alert_trigger_mode,
                     alert_notify_mode, notify_cooldown_sec,
                     sms_numbers_l1_json, sms_numbers_l2_json, sms_numbers_l3_json,
                     call_numbers_l1_json, call_numbers_l2_json, call_numbers_l3_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    notifications_enabled=excluded.notifications_enabled,
                    notify_emails_json=excluded.notify_emails_json,
                    escalation_emails_l1_json=excluded.escalation_emails_l1_json,
                    escalation_emails_l2_json=excluded.escalation_emails_l2_json,
                    escalation_emails_l3_json=excluded.escalation_emails_l3_json,
                    escalation_after_sec_l1=excluded.escalation_after_sec_l1,
                    escalation_after_sec_l2=excluded.escalation_after_sec_l2,
                    escalation_after_sec_l3=excluded.escalation_after_sec_l3,
                    escalation_levels=excluded.escalation_levels,
                    thresholds_json=excluded.thresholds_json,
                    alert_trigger_mode=excluded.alert_trigger_mode,
                    alert_notify_mode=excluded.alert_notify_mode,
                    notify_cooldown_sec=excluded.notify_cooldown_sec,
                    sms_numbers_l1_json=excluded.sms_numbers_l1_json,
                    sms_numbers_l2_json=excluded.sms_numbers_l2_json,
                    sms_numbers_l3_json=excluded.sms_numbers_l3_json,
                    call_numbers_l1_json=excluded.call_numbers_l1_json,
                    call_numbers_l2_json=excluded.call_numbers_l2_json,
                    call_numbers_l3_json=excluded.call_numbers_l3_json
            """, (device_id, int(notifications_enabled),
                  json.dumps(notify_emails),
                  json.dumps(escalation_emails_l1),
                  json.dumps(escalation_emails_l2),
                  json.dumps(escalation_emails_l3),
                  int(escalation_after_sec_l1),
                  int(escalation_after_sec_l2),
                  int(escalation_after_sec_l3),
                  int(escalation_levels),
                  json.dumps(thresholds),
                  alert_trigger_mode,
                  alert_notify_mode,
                  notify_cooldown_sec,
                  json.dumps(sms_numbers_l1 or []),
                  json.dumps(sms_numbers_l2 or []),
                  json.dumps(sms_numbers_l3 or []),
                  json.dumps(call_numbers_l1 or []),
                  json.dumps(call_numbers_l2 or []),
                  json.dumps(call_numbers_l3 or [])))
        conn.close()


def get_all_device_notify():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM device_notify").fetchall()
    conn.close()
    out = {}
    for r in rows:
        d = dict(r)
        d["notify_emails"]        = json.loads(d.get("notify_emails_json") or "[]")
        d["escalation_emails_l1"] = json.loads(d.get("escalation_emails_l1_json") or "[]")
        d["escalation_emails_l2"] = json.loads(d.get("escalation_emails_l2_json") or "[]")
        d["escalation_emails_l3"] = json.loads(d.get("escalation_emails_l3_json") or "[]")
        d["thresholds"]           = json.loads(d.get("thresholds_json") or "{}")
        out[d["device_id"]] = d
    return out


# ============================================================
# Email user registry
# ============================================================
def get_all_users():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM email_users ORDER BY role, email").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_user_by_email(email):
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM email_users WHERE email=? AND active=1", (email.lower(),)).fetchone()
    conn.close()
    return dict(row) if row else None


def add_user(email, role, token_hash):
    import hashlib
    email_hash = hashlib.sha256(email.lower().encode()).hexdigest()
    with _lock:
        conn = get_connection()
        with conn:
            conn.execute("""
                INSERT INTO email_users (email, email_hash, role, token_hash, active, created_ts)
                VALUES (?, ?, ?, ?, 1, ?)
                ON CONFLICT(email) DO UPDATE SET
                    role=excluded.role, token_hash=excluded.token_hash,
                    email_hash=excluded.email_hash, active=1
            """, (email.lower(), email_hash, role, token_hash, time.time()))
        conn.close()


def update_user_email(user_id, new_email):
    """
    V10.0: lets an admin fix a typo'd email without deleting and re-adding
    the account (which would also mean generating/distributing a new
    token). Keyed by the stable `id` column, not by the email itself,
    since the email is exactly what's being changed here.
    Returns True on success, False if new_email is already taken by a
    different account (UNIQUE constraint on email) or user_id doesn't exist.
    """
    import hashlib
    email_hash = hashlib.sha256(new_email.lower().encode()).hexdigest()
    with _lock:
        conn = get_connection()
        try:
            with conn:
                cur = conn.execute(
                    "UPDATE email_users SET email=?, email_hash=? WHERE id=?",
                    (new_email.lower(), email_hash, user_id))
                changed = cur.rowcount > 0
        except sqlite3.IntegrityError:
            changed = False
        conn.close()
    return changed


def delete_user(email):
    with _lock:
        conn = get_connection()
        with conn:
            conn.execute("DELETE FROM email_users WHERE email=?", (email.lower(),))
        conn.close()


def validate_user(email_hash, token_hash):
    """V10.0: no longer called by the login path (see auth.attempt_login) --
    a per-user salted PBKDF2 hash can't be matched with a single SQL
    "WHERE token_hash=?", only verified in application code after
    looking the row up by email. Left in place, unused, rather than
    removed; nothing currently calls it."""
    conn = get_connection()
    row = conn.execute(
        "SELECT role FROM email_users WHERE email_hash=? AND token_hash=? AND active=1",
        (email_hash, token_hash)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


# ============================================================
# Audit log
# ============================================================
def audit_log(actor, action, target, detail=""):
    with _lock:
        conn = get_connection()
        with conn:
            conn.execute(
                "INSERT INTO audit_log (actor,action,target,detail,ts) VALUES (?,?,?,?,?)",
                (actor, action, target, detail, time.time()))
        conn.close()


def get_audit_log(limit=200):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ============================================================
# License record
# ============================================================
def get_license_record():
    conn = get_connection()
    row = conn.execute("SELECT * FROM license_record WHERE id=1").fetchone()
    conn.close()
    return dict(row) if row else None

def set_license_record(device_id, activation_code, license_key, trial_start, activated):
    with _lock:
        conn = get_connection()
        with conn:
            conn.execute("""
                INSERT OR REPLACE INTO license_record
                    (id, device_id, activation_code, license_key, trial_start, activated)
                VALUES (1, ?, ?, ?, ?, ?)
            """, (device_id, activation_code, license_key, trial_start, activated))
        conn.close()

def set_license_activated(license_key):
    with _lock:
        conn = get_connection()
        with conn:
            conn.execute(
                "UPDATE license_record SET license_key=?, activated=1 WHERE id=1",
                (license_key,))
        conn.close()


# =============================================================================
# V7.2 ADDITIONS: per-user dashboard layout + user preferences
# =============================================================================

def get_user_pref(email: str, key: str):
    """Get a user preference value. Returns None if not set."""
    if not email:
        return None
    conn = get_connection()
    with conn:
        row = conn.execute(
            "SELECT pref_value FROM user_prefs_kv WHERE email=? AND pref_key=?",
            (email.lower(), key)
        ).fetchone()
    return row["pref_value"] if row else None


def set_user_pref(email: str, key: str, value: str):
    """Upsert a user preference."""
    if not email:
        return
    conn = get_connection()
    with conn:
        conn.execute(
            """INSERT INTO user_prefs_kv (email, pref_key, pref_value)
               VALUES (?, ?, ?)
               ON CONFLICT(email, pref_key) DO UPDATE SET pref_value=excluded.pref_value""",
            (email.lower(), key, str(value))
        )
        conn.commit()


def get_dashboard_layout(email: str) -> list:
    """
    Return per-user tile layout as list of dicts:
      [{device_id, position, hidden, size, col, row}, ...]
    Falls back to global dashboard_tiles table if no per-user layout saved.
    """
    if not email:
        return _get_global_layout()
    conn = get_connection()
    with conn:
        rows = conn.execute(
            """SELECT pref_value
               FROM user_prefs_kv
               WHERE email=? AND pref_key='tile_layout_v2'""",
            (email.lower(),)
        ).fetchone()
    if rows and rows["pref_value"]:
        try:
            import json
            return json.loads(rows["pref_value"])
        except Exception:
            pass
    return _get_global_layout()


def _get_global_layout() -> list:
    """Read from legacy dashboard_tiles table."""
    conn = get_connection()
    with conn:
        rows = conn.execute(
            "SELECT device_id, position, hidden, size, col, row FROM dashboard_tiles"
        ).fetchall()
    return [{"device_id": r["device_id"], "position": r["position"],
             "hidden": bool(r["hidden"]), "size": r["size"] or "normal",
             "col": r["col"] or 0, "row": r["row"] if r["row"] is not None else r["position"]} for r in rows]


def save_dashboard_layout(email: str, layout: list):
    """
    Save per-user tile layout. layout is list of dicts:
      [{device_id, position, hidden, size, col, row}, ...]
    """
    import json
    if not email:
        return
    layout_json = json.dumps(layout)
    conn = get_connection()
    with conn:
        conn.execute(
            """INSERT INTO user_prefs_kv (email, pref_key, pref_value)
               VALUES (?, 'tile_layout_v2', ?)
               ON CONFLICT(email, pref_key) DO UPDATE SET pref_value=excluded.pref_value""",
            (email.lower(), layout_json)
        )
        conn.commit()


# =============================================================================
# V7.2 NEW FEATURE TABLES: Speed Test | Network Scan
# =============================================================================

def _ensure_new_tables():
    """Create V7.2+ feature tables if they don't exist, and migrate new columns."""
    conn = get_connection()
    with conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS speedtest_history (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                ts            REAL,
                download_mbps REAL,
                upload_mbps   REAL,
                latency_ms    REAL,
                server        TEXT,
                method_used   TEXT,
                elapsed_sec   REAL
            );
            CREATE TABLE IF NOT EXISTS network_scan_jobs (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                subnet     TEXT,
                status     TEXT DEFAULT 'pending',
                result_json TEXT,
                created_ts REAL,
                updated_ts REAL
            );
            -- V10.1: mirrors network_scan_jobs' pending/running/done/error
            -- polling shape, plus progress_json for live in-flight samples --
            -- network_scan has no equivalent column because it only ever
            -- reports once, at the end; a speed test has real intermediate
            -- values worth showing (see speedtest_check.py's progress_cb).
            CREATE TABLE IF NOT EXISTS speedtest_jobs (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                status        TEXT DEFAULT 'pending',
                phase         TEXT,
                progress_json TEXT,
                result_json   TEXT,
                created_ts    REAL,
                updated_ts    REAL
            );
        """)
        # V7.2: WAN telemetry columns (jitter, ISP, public IP) — added via
        # migration so upgrades from V6.x databases don't lose history.
        existing_cols = {row["name"] for row in
                          conn.execute("PRAGMA table_info(speedtest_history)").fetchall()}
        for col, coltype in (("jitter_ms", "REAL"),
                              ("isp", "TEXT"),
                              ("public_ip", "TEXT"),
                              # V8.6: client-side ("test my connection") mode --
                              # local_ip/hostname identify WHICH end-user
                              # machine the row is about, distinct from
                              # public_ip/isp/download/upload which describe
                              # WHICHEVER machine (server, for test_source=
                              # 'server'; that same requesting browser, for
                              # test_source='client') actually ran the
                              # bandwidth measurement. See app.py's
                              # /api/speedtest/submit-client-result.
                              ("local_ip", "TEXT"),
                              ("hostname", "TEXT"),
                              ("test_source", "TEXT DEFAULT 'server'")):
            if col not in existing_cols:
                conn.execute(f"ALTER TABLE speedtest_history ADD COLUMN {col} {coltype}")
    conn.close()


def record_speedtest(result: dict):
    _ensure_new_tables()
    conn = get_connection()
    with conn:
        conn.execute(
            """INSERT INTO speedtest_history
               (ts, download_mbps, upload_mbps, latency_ms, jitter_ms, isp, public_ip,
                server, method_used, elapsed_sec, local_ip, hostname, test_source)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (time.time(),
             result.get("download_mbps"),
             result.get("upload_mbps"),
             result.get("latency_ms"),
             result.get("jitter_ms"),
             result.get("isp", ""),
             result.get("public_ip", ""),
             result.get("server",""),
             result.get("method_used",""),
             result.get("elapsed_sec"),
             result.get("local_ip", ""),
             result.get("hostname", ""),
             result.get("test_source", "server"))
        )
    conn.close()


def get_speedtest_history(limit: int = 50) -> list:
    _ensure_new_tables()
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM speedtest_history ORDER BY ts DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def clear_speedtest_history():
    """Delete all speed test history rows (used by the 'Purge Logs' button)."""
    _ensure_new_tables()
    conn = get_connection()
    with conn:
        conn.execute("DELETE FROM speedtest_history")
    conn.close()


def create_scan_job(subnet: str) -> int:
    _ensure_new_tables()
    conn = get_connection()
    with conn:
        cur = conn.execute(
            "INSERT INTO network_scan_jobs (subnet, status, created_ts, updated_ts) VALUES (?,?,?,?)",
            (subnet, "pending", time.time(), time.time())
        )
        job_id = cur.lastrowid
    conn.close()
    return job_id


def update_scan_job(job_id: int, status: str, result: dict | None):
    _ensure_new_tables()
    conn = get_connection()
    with conn:
        conn.execute(
            "UPDATE network_scan_jobs SET status=?, result_json=?, updated_ts=? WHERE id=?",
            (status, json.dumps(result) if result else None, time.time(), job_id)
        )
    conn.close()


def get_scan_job(job_id: int) -> dict | None:
    _ensure_new_tables()
    conn = get_connection()
    row  = conn.execute(
        "SELECT * FROM network_scan_jobs WHERE id=?", (job_id,)
    ).fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    if d.get("result_json"):
        d["result"] = json.loads(d["result_json"])
    d.pop("result_json", None)
    return d


def create_speedtest_job() -> int:
    _ensure_new_tables()
    conn = get_connection()
    with conn:
        cur = conn.execute(
            "INSERT INTO speedtest_jobs (status, created_ts, updated_ts) VALUES (?,?,?)",
            ("pending", time.time(), time.time())
        )
        job_id = cur.lastrowid
    conn.close()
    return job_id


def update_speedtest_job(job_id: int, status: str | None = None, phase: str | None = None,
                          progress: dict | None = None, result: dict | None = None):
    """Partial update -- a live progress tick only touches phase/progress
    (called many times per test); the final call also sets status/result."""
    _ensure_new_tables()
    conn = get_connection()
    with conn:
        row = conn.execute("SELECT status, phase FROM speedtest_jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            conn.close()
            return
        conn.execute(
            "UPDATE speedtest_jobs SET status=?, phase=?, progress_json=?, result_json=?, updated_ts=? WHERE id=?",
            (
                status if status is not None else row["status"],
                phase if phase is not None else row["phase"],
                json.dumps(progress) if progress is not None else None,
                json.dumps(result) if result else None,
                time.time(), job_id
            )
        )
    conn.close()


def get_speedtest_job(job_id: int) -> dict | None:
    _ensure_new_tables()
    conn = get_connection()
    row  = conn.execute("SELECT * FROM speedtest_jobs WHERE id=?", (job_id,)).fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    d["progress"] = json.loads(d["progress_json"]) if d.get("progress_json") else None
    d["result"]   = json.loads(d["result_json"]) if d.get("result_json") else None
    d.pop("progress_json", None)
    d.pop("result_json", None)
    return d


def get_scan_history(limit: int = 20) -> list:
    _ensure_new_tables()
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, subnet, status, created_ts, updated_ts FROM network_scan_jobs ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# =============================================================================
# V7.2: System-wide settings (admin-configured defaults, e.g. default theme)
# =============================================================================

_sys_table_ok = False


def _ensure_system_settings_table():
    global _sys_table_ok
    if _sys_table_ok:
        return
    conn = get_connection()
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS system_settings (
                setting_key   TEXT PRIMARY KEY,
                setting_value TEXT
            )
        """)
    conn.close()
    _sys_table_ok = True


def get_system_setting(key: str, default=None):
    _ensure_system_settings_table()
    conn = get_connection()
    row = conn.execute(
        "SELECT setting_value FROM system_settings WHERE setting_key=?", (key,)
    ).fetchone()
    conn.close()
    return row["setting_value"] if row else default


def set_system_setting(key: str, value: str):
    _ensure_system_settings_table()
    conn = get_connection()
    with conn:
        conn.execute(
            """INSERT INTO system_settings (setting_key, setting_value) VALUES (?, ?)
               ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value""",
            (key, str(value))
        )
    conn.close()


# =============================================================================
# V7.2: Active Alerts (Acknowledge / Resolve lifecycle)
# =============================================================================

def _ensure_active_alerts_table():
    conn = get_connection()
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS active_alerts (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id       TEXT NOT NULL,
                device_name     TEXT,
                device_host     TEXT,
                metric          TEXT,
                severity        TEXT,      -- warning | critical
                message         TEXT,
                status          TEXT DEFAULT 'active',  -- active | acknowledged | resolved
                triggered_ts    REAL,
                acknowledged_ts REAL,
                acknowledged_by TEXT,
                ack_until_ts    REAL,      -- suppress re-escalation until this time
                resolved_ts     REAL,
                resolved_by     TEXT
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_active_alerts_lookup
            ON active_alerts (device_id, metric, status)
        """)
    conn.close()


def get_ack_suppression(device_id, metric):
    """
    V8.4. Returns the ack_until_ts (unix timestamp) if this device+metric
    is currently suppressed by an admin acknowledgment -- either because
    its active_alerts row is presently 'acknowledged', or because it WAS
    acknowledged and has since auto-resolved (the metric flapped back to
    'ok' for a poll cycle or two) but is still inside that acknowledgment's
    suppression window. Returns None if not suppressed.

    This is intentionally read-only and does not touch upsert_active_alert
    or auto_resolve_active_alerts' row lifecycle at all -- it's a separate
    check alerts.py::process_alerts() consults before emailing, so a
    flapping metric can't silently defeat an admin's acknowledgment by
    auto-resolving the row (which correctly still happens, for the Alert
    Event Log's sake) and having the very next bad reading look like a
    brand new, never-acknowledged incident.
    """
    _ensure_active_alerts_table()
    conn = get_connection()
    row = conn.execute(
        """SELECT ack_until_ts FROM active_alerts
           WHERE device_id=? AND metric=? AND acknowledged_ts IS NOT NULL
             AND status IN ('acknowledged','resolved')
           ORDER BY id DESC LIMIT 1""",
        (device_id, metric)
    ).fetchone()
    conn.close()
    if row and row["ack_until_ts"] and time.time() < row["ack_until_ts"]:
        return row["ack_until_ts"]
    return None


def upsert_active_alert(device_id, device_name, device_host, metric, severity, message):
    """
    Create a new active alert row for this device+metric if one isn't
    already open (active or acknowledged). Returns the alert id.
    If an acknowledged alert's suppression window (ack_until_ts) has
    passed, it is reopened as a fresh 'active' alert (new escalation cycle).

    V8.4: if the most recent row for this device+metric was resolved (the
    metric flapped back to 'ok') but is still inside its acknowledgment's
    suppression window (see get_ack_suppression), this reopens that same
    row as 'acknowledged' rather than creating a new-looking, apparently
    unacknowledged row -- keeping the Active Alerts panel visually
    consistent with the fact that process_alerts() is, for the same
    reason, not sending an email for this reading either.
    """
    _ensure_active_alerts_table()
    conn = get_connection()
    now = time.time()
    row = conn.execute(
        """SELECT * FROM active_alerts
           WHERE device_id=? AND metric=? AND status IN ('active','acknowledged')
           ORDER BY id DESC LIMIT 1""",
        (device_id, metric)
    ).fetchone()

    if row:
        r = dict(row)
        if r["status"] == "acknowledged" and r.get("ack_until_ts") and now > r["ack_until_ts"]:
            # Suppression window expired -- start a fresh escalation cycle
            with conn:
                conn.execute(
                    "UPDATE active_alerts SET status='active', severity=?, message=?, triggered_ts=? WHERE id=?",
                    (severity, message, now, r["id"])
                )
            conn.close()
            return r["id"]
        # Still open (active, or acknowledged and within suppression window) -- leave as-is
        conn.close()
        return r["id"]

    # V8.4: no open row -- but if the most recent row was resolved while
    # still inside its own acknowledgment suppression window (a flap),
    # reopen it as acknowledged instead of starting a fresh-looking one.
    recent = conn.execute(
        """SELECT * FROM active_alerts
           WHERE device_id=? AND metric=? AND status='resolved' AND acknowledged_ts IS NOT NULL
           ORDER BY id DESC LIMIT 1""",
        (device_id, metric)
    ).fetchone()
    if recent:
        rr = dict(recent)
        if rr.get("ack_until_ts") and now < rr["ack_until_ts"]:
            with conn:
                conn.execute(
                    """UPDATE active_alerts SET status='acknowledged', severity=?, message=?,
                       triggered_ts=?, resolved_ts=NULL, resolved_by=NULL WHERE id=?""",
                    (severity, message, now, rr["id"])
                )
            conn.close()
            return rr["id"]

    with conn:
        cur = conn.execute(
            """INSERT INTO active_alerts
               (device_id, device_name, device_host, metric, severity, message,
                status, triggered_ts)
               VALUES (?,?,?,?,?,?,'active',?)""",
            (device_id, device_name, device_host, metric, severity, message, now)
        )
        alert_id = cur.lastrowid
    conn.close()
    return alert_id


def auto_resolve_active_alerts(device_id, metric):
    """Called when a metric returns to 'ok' -- silently closes any open alert."""
    _ensure_active_alerts_table()
    conn = get_connection()
    now = time.time()
    with conn:
        conn.execute(
            """UPDATE active_alerts SET status='resolved', resolved_ts=?, resolved_by='system (auto-recovered)'
               WHERE device_id=? AND metric=? AND status IN ('active','acknowledged')""",
            (now, device_id, metric)
        )
    conn.close()


def acknowledge_alert(alert_id, by_email):
    """Acknowledge -- suppresses further escalation until 23:59:59 today."""
    _ensure_active_alerts_table()
    import datetime
    conn = get_connection()
    now = time.time()
    end_of_day = datetime.datetime.now().replace(hour=23, minute=59, second=59, microsecond=0).timestamp()
    with conn:
        conn.execute(
            """UPDATE active_alerts SET status='acknowledged', acknowledged_ts=?,
               acknowledged_by=?, ack_until_ts=? WHERE id=?""",
            (now, by_email, end_of_day, alert_id)
        )
    conn.close()


def resolve_alert(alert_id, by_email):
    _ensure_active_alerts_table()
    conn = get_connection()
    with conn:
        conn.execute(
            "UPDATE active_alerts SET status='resolved', resolved_ts=?, resolved_by=? WHERE id=?",
            (time.time(), by_email, alert_id)
        )
    conn.close()


def get_active_alerts(status_filter=None, limit=200):
    """status_filter: None (all), 'active', 'acknowledged', 'resolved'."""
    _ensure_active_alerts_table()
    conn = get_connection()
    if status_filter:
        rows = conn.execute(
            "SELECT * FROM active_alerts WHERE status=? ORDER BY triggered_ts DESC LIMIT ?",
            (status_filter, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM active_alerts ORDER BY triggered_ts DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def count_open_alerts():
    """Count of active + acknowledged (i.e. not yet resolved) alerts."""
    _ensure_active_alerts_table()
    conn = get_connection()
    row = conn.execute(
        "SELECT COUNT(*) as c FROM active_alerts WHERE status IN ('active','acknowledged')"
    ).fetchone()
    conn.close()
    return row["c"] if row else 0


# ============================================================
# Notification templates (admin-editable, per alert state)
# ============================================================
# One row per state = one admin OVERRIDE of that state's built-in default
# template. No row for a state = that state still uses the built-in
# default (see monitor/notification_templates.py DEFAULT_TEMPLATES) --
# this is the normal, fully-working condition for any state that hasn't
# been customized, not a missing/broken state.

def get_notification_template(state: str):
    """Returns the saved override dict for this state, or None if the
    admin has never customized it (caller should fall back to the
    built-in default in that case)."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM notification_templates WHERE state=?", (state,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_notification_templates() -> dict:
    """Returns {state: override_dict} for every state that has a saved
    override. States not present in this dict are still using their
    built-in default."""
    conn = get_connection()
    rows = conn.execute("SELECT * FROM notification_templates").fetchall()
    conn.close()
    return {r["state"]: dict(r) for r in rows}


def set_notification_template(state: str, subject_template: str,
                               text_template: str, html_template: str,
                               enabled: bool = True, updated_by: str = ""):
    with _lock:
        conn = get_connection()
        with conn:
            conn.execute("""
                INSERT INTO notification_templates
                    (state, subject_template, text_template, html_template,
                     enabled, updated_ts, updated_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(state) DO UPDATE SET
                    subject_template=excluded.subject_template,
                    text_template=excluded.text_template,
                    html_template=excluded.html_template,
                    enabled=excluded.enabled,
                    updated_ts=excluded.updated_ts,
                    updated_by=excluded.updated_by
            """, (state, subject_template, text_template, html_template,
                  int(bool(enabled)), time.time(), updated_by))
        conn.close()


def delete_notification_template(state: str):
    """Removes the admin's override for this state, reverting it to the
    built-in default template. Safe to call even if no override exists."""
    with _lock:
        conn = get_connection()
        with conn:
            conn.execute("DELETE FROM notification_templates WHERE state=?", (state,))
        conn.close()


# ============================================================
# V8.4: custom notification placeholders (Settings > Templates)
# Admin-defined static text substitutions, e.g. {{company_name}} ->
# "Acme Corp" -- distinct from the built-in placeholders in
# notification_templates.py, which are populated from live alert data
# at render time. See notification_templates.py::all_placeholders() for
# where these get merged with the built-ins for the editor's reference
# list / autocomplete, and ::render() for where their values actually
# get substituted into a sent email.
# ============================================================
def get_custom_placeholders() -> list:
    """Returns all custom placeholders as a list of dicts, key ascending."""
    conn = get_connection()
    rows = conn.execute("SELECT * FROM custom_placeholders ORDER BY key ASC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_custom_placeholder_values() -> dict:
    """Returns {key: value} only -- the shape render() actually needs to
    substitute values into a template, without the description/metadata."""
    conn = get_connection()
    rows = conn.execute("SELECT key, value FROM custom_placeholders").fetchall()
    conn.close()
    return {r["key"]: r["value"] for r in rows}


def set_custom_placeholder(key: str, value: str, description: str = "", updated_by: str = ""):
    """Create or update a custom placeholder. Caller (app.py route) is
    responsible for duplicate-checking against the built-in placeholder
    registry before calling this -- this function only enforces
    uniqueness among custom placeholders themselves (via the key being
    the table's PRIMARY KEY, so re-using an existing custom key updates
    it in place rather than erroring, which is correct for an "edit"
    action but means the route must explicitly reject an add of a key
    that's meant to be new but collides)."""
    now = time.time()
    with _lock:
        conn = get_connection()
        with conn:
            conn.execute("""
                INSERT INTO custom_placeholders (key, value, description, created_ts, updated_ts, updated_by)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value=excluded.value,
                    description=excluded.description,
                    updated_ts=excluded.updated_ts,
                    updated_by=excluded.updated_by
            """, (key, value, description, now, now, updated_by))
        conn.close()


def delete_custom_placeholder(key: str):
    with _lock:
        conn = get_connection()
        with conn:
            conn.execute("DELETE FROM custom_placeholders WHERE key=?", (key,))
        conn.close()


# ============================================================
# V8.4: configuration export / import (Admin Panel > Backup & Restore)
# Deliberately excludes anything that is history/data rather than
# configuration (metric_history, alert_log, active_alerts, audit_log,
# speedtest_history, network_scan_jobs) -- a configuration restore
# should never touch those. Generic/column-introspecting by design so
# it stays correct as the schema grows in future releases without
# needing to be revisited here every time.
# ============================================================
_CONFIG_TABLES = ["device_notify", "notification_templates", "system_settings", "custom_placeholders"]


def export_config_tables(include_users: bool = True) -> dict:
    """Returns the non-history configuration tables as plain dicts/lists,
    suitable for JSON serialization."""
    conn = get_connection()
    out = {}
    for table in _CONFIG_TABLES:
        try:
            out[table] = [dict(r) for r in conn.execute(f"SELECT * FROM {table}").fetchall()]
        except Exception:
            out[table] = []  # table doesn't exist in this DB version -- tolerate
    if include_users:
        try:
            out["users"] = [dict(r) for r in conn.execute(
                "SELECT email, email_hash, role, token_hash, active, created_ts FROM email_users"
            ).fetchall()]
        except Exception:
            out["users"] = []
    conn.close()
    return out


def _import_table_rows(conn, table: str, rows: list):
    """Generic REPLACE-semantics import for one table: clears it, then
    re-inserts each row using only the columns that actually exist in
    THIS database's current schema -- so an export taken on an older or
    newer app version still imports safely (extra keys in the import
    file are dropped, missing ones fall back to the column's own
    DEFAULT). Skips silently if the table doesn't exist in this DB yet."""
    try:
        real_cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    except Exception:
        return
    if not real_cols:
        return
    conn.execute(f"DELETE FROM {table}")
    for row in rows:
        cols = [c for c in real_cols if c in row]
        if not cols:
            continue
        placeholders = ",".join("?" for _ in cols)
        conn.execute(
            f"INSERT INTO {table} ({','.join(cols)}) VALUES ({placeholders})",
            [row[c] for c in cols]
        )


def import_config_tables(data: dict, include_users: bool = True):
    """Replaces the configuration tables' contents from a previously
    exported dict (see export_config_tables). REPLACE semantics per
    table -- EXCEPT email_users, which is deliberately upserted rather
    than replaced (see below), so restoring a backup can never delete
    the admin account you're currently logged in as just because it
    wasn't present in the file being restored."""
    with _lock:
        conn = get_connection()
        with conn:
            for table in _CONFIG_TABLES:
                if table in data:
                    _import_table_rows(conn, table, data[table])
            if include_users and "users" in data:
                for u in data["users"]:
                    if not u.get("email") or not u.get("token_hash"):
                        continue
                    role = u.get("role") if u.get("role") in ("admin", "supervisor", "user") else "user"
                    conn.execute("""
                        INSERT INTO email_users (email, email_hash, role, token_hash, active, created_ts)
                        VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT(email) DO UPDATE SET
                            role=excluded.role,
                            token_hash=excluded.token_hash,
                            active=excluded.active
                    """, (u["email"], u.get("email_hash", ""), role,
                          u["token_hash"], int(u.get("active", 1)), u.get("created_ts", time.time())))
        conn.close()


# ============================================================
# V8.5: self-service "forgot your token" reset requests
# ============================================================
TOKEN_RESET_TTL_SEC = 30 * 60   # reset links expire 30 minutes after being requested

def create_token_reset(email: str, reset_token_hash: str, ttl_sec: int = None) -> int:
    now = time.time()
    ttl = ttl_sec if ttl_sec is not None else TOKEN_RESET_TTL_SEC
    with _lock:
        conn = get_connection()
        with conn:
            cur = conn.execute(
                "INSERT INTO token_reset_requests (email, reset_token_hash, created_ts, expires_ts, used) "
                "VALUES (?, ?, ?, ?, 0)",
                (email.lower(), reset_token_hash, now, now + ttl)
            )
            reset_id = cur.lastrowid
        conn.close()
    return reset_id


def get_valid_token_reset(reset_token_hash: str):
    """Returns the request row if it exists, is unused, and hasn't
    expired -- else None. Deliberately does NOT distinguish "doesn't
    exist" from "expired" from "already used" in its return value (just
    None either way) -- the caller (auth.py) surfaces one generic
    "this link is invalid or has expired" message regardless, so an
    attacker probing reset links can't learn which failure mode occurred."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM token_reset_requests WHERE reset_token_hash=? AND used=0 AND expires_ts > ?",
        (reset_token_hash, time.time())
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def mark_token_reset_used(reset_id: int):
    with _lock:
        conn = get_connection()
        with conn:
            conn.execute("UPDATE token_reset_requests SET used=1 WHERE id=?", (reset_id,))
        conn.close()


def purge_expired_token_resets():
    """Housekeeping -- called opportunistically (see auth.py) rather than
    on a schedule, since this table stays tiny and there's no harm in an
    expired-but-not-yet-purged row sitting around (get_valid_token_reset
    already excludes it from ever validating)."""
    with _lock:
        conn = get_connection()
        with conn:
            conn.execute("DELETE FROM token_reset_requests WHERE expires_ts < ?", (time.time() - 86400,))
        conn.close()
