# =============================================================================
# Net-monit V11.3
# Copyright (c) 2024-2026 Abdullah | Abdullah-InfoXtek.com
# Contact: abuabdullah.be@outlook.com
# Unauthorised copying, modification or distribution is strictly prohibited.
# =============================================================================
"""
app.py -- Net-monit V11.3
Port   : 50113
Supports HTTP and HTTPS (set NETMON_SSL_CERT / NETMON_SSL_KEY env vars for HTTPS)
"""
import json, logging, os, platform, re, time, warnings
import base64

warnings.filterwarnings("ignore", message=".*TripleDES.*")
try:
    from cryptography.utils import CryptographyDeprecationWarning as _CW
    warnings.filterwarnings("ignore", category=_CW)
except ImportError:
    pass

from flask import Flask, jsonify, render_template, request, redirect, Response, has_request_context

from monitor import database as db
from monitor import config_manager
from monitor import scheduler as sched
from monitor import email_notifier
from monitor import messaging_gateway
from monitor import notification_templates
from monitor import threshold_meta
from monitor import alerts as alerts_engine
from monitor import auth
from monitor.license import license_manager

# V10.0: write logs to a file as well as stderr. Running as an installed
# Windows Service means pythonw.exe with no console attached (see
# install_service.py) -- stderr-only logging was going nowhere in that
# deployment mode, which is the normal day-to-day way this app runs, not
# an edge case. Same logs/service.log path install_service.py already
# uses, so both ways of running the app end up in one place. Falls back
# to stderr-only if the directory somehow isn't writable rather than
# blocking startup over a logging problem.
_LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
_log_handlers = [logging.StreamHandler()]
try:
    os.makedirs(_LOG_DIR, exist_ok=True)
    _log_handlers.append(logging.FileHandler(
        os.path.join(_LOG_DIR, "service.log"), encoding="utf-8"))
except OSError:
    pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=_log_handlers,
)
log = logging.getLogger("netmonit.app")

APP_VERSION = "11.3"
APP_PORT    = int(os.environ.get("NETMON_PORT", 50113))
SSL_CERT    = os.environ.get("NETMON_SSL_CERT", "")
SSL_KEY     = os.environ.get("NETMON_SSL_KEY",  "")

app = Flask(__name__)
app.secret_key = os.environ.get("NETMON_SECRET", os.urandom(32).hex())


def _batched(fn):
    """V11.3 patch 06: run a bulk endpoint's DB writes on ONE connection and ONE commit."""
    import functools
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        with db.batch():
            return fn(*a, **kw)
    return wrapper


_LAST_HOST = None


@app.before_request
def _remember_access_host():
    # Same value the welcome-email flow already uses (request.host --
    # whatever hostname/IP + port the browser actually used to reach this
    # server). Persisted so alerts.py/email_notifier.py, which run from a
    # background scheduler thread with no HTTP request in progress, can
    # still build a correct "Open Dashboard" link automatically -- reusing
    # whichever address the admin most recently accessed the app with,
    # instead of a hardcoded value that goes stale the moment the server's
    # address changes.
    # V11.3 patch 06: this ran two DB connections plus a CREATE TABLE write on EVERY request (the dashboard polls
    # every few seconds), fighting the scheduler for the write lock and slowing every Save. Now the DB is only
    # touched when the host the browser used actually changes.
    global _LAST_HOST
    if request.endpoint == "static":
        return
    host = request.host
    if host and host != _LAST_HOST:
        try:
            if host != db.get_system_setting("last_known_host"):
                db.set_system_setting("last_known_host", host)
            _LAST_HOST = host
        except Exception:
            pass  # never let this best-effort bookkeeping break a real request


# ── session helpers ────────────────────────────────────────────────────────
def _tok():
    # V10.4: flask.request only exists on the thread that is actually serving
    # the HTTP request. Every helper built on this one (_session, _email,
    # _is_admin, _require_login, ...) used to raise RuntimeError("Working
    # outside of request context") if it was ever reached from a background
    # thread -- the exact failure "Test WAN Speed" showed as "Request
    # failed: Working outside of request context...". With this guard they
    # degrade to "not logged in" / "system" instead of raising.
    if not has_request_context():
        return ""
    return (request.headers.get("X-Session-Token") or
            request.cookies.get("netmon_session", ""))

def _session():
    return auth.validate_session(_tok())

def _is_admin():
    s = _session()
    return s is not None and s.get("role") == "admin"

def _is_logged_in():
    return _session() is not None

def _is_view_only():
    """V10.0: the 'View' role (stored internally as 'user', see auth.py) --
    dashboard and speed test only, everything else redirects to '/'."""
    s = _session()
    return s is not None and s.get("role") == "user"

def _require_admin():
    if not _is_admin():
        return jsonify({"error": "Admin access required"}), 401
    return None

def _require_login():
    if not _is_logged_in():
        return jsonify({"error": "Login required"}), 401
    return None

# V8.6: identifies WHICH machine's browser actually made this request --
# used by the speed test routes so a result can show the real end-user PC
# (e.g. 192.168.6.7) even when Net-monit itself is hosted elsewhere
# (e.g. 192.168.1.100). request.remote_addr is the standard, reliable way
# to get this -- it's the actual TCP source address the request arrived
# from, not something the browser self-reports (which could be spoofed or,
# for hostname, isn't exposed to web pages by any browser API at all).
def _client_local_ip():
    # V10.4: same guard as _tok() -- returns "" (unknown) off the request
    # thread instead of raising. See _finish_speedtest_result's docstring.
    if not has_request_context():
        return ""
    # X-Forwarded-For first, for the reverse-proxy case (nginx/IIS in
    # front of Net-monit) -- the proxy's own address would otherwise be
    # all every request shows. Only the first (left-most, original
    # client) hop is trusted; a single-hop deployment without a proxy
    # just falls through to remote_addr directly.
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or ""

def _client_hostname(ip: str) -> str:
    """
    Best-effort reverse DNS lookup of the client's LAN IP. Returns "" if
    it fails -- this is expected and common: reverse DNS for internal
    IPs only resolves if the network's DNS server is configured for it
    (typical in a Windows AD/domain environment, which is plausible given
    this app already targets Windows LANs for its ssh/powershell checkers
    -- but far from guaranteed on a home network or a LAN without proper
    PTR records). Callers must treat an empty result as "unknown", not
    an error.
    """
    if not ip:
        return ""
    try:
        import socket as _socket
        hostname, _, _ = _socket.gethostbyaddr(ip)
        return hostname.split(".")[0]  # short name, not the full FQDN
    except Exception:
        return ""

def _email():
    s = _session()
    return s.get("email", "system") if s else "system"


# ── appearance defaults: read once per request, exposed to every template ──
# V10.1: before this, nothing except the admin GET/POST routes themselves
# ever read default_theme/default_accent_color -- admin.html's own text
# claims "Sets the theme and accent colour shown to anonymous visitors and
# any user who hasn't personalised their own preference yet", but no
# render_template() call anywhere passed those values into a template, and
# theme.js's early-init only ever looked at localStorage with a hardcoded
# fallback. So the setting saved but never once actually reached an
# anonymous visitor or a fresh account. A context processor (vs. repeating
# this in all ten render_template() calls, and inevitably missing one on
# a future page) guarantees every page gets it, this one included.
def _appearance_defaults() -> dict:
    return {
        "default_theme":        db.get_system_setting("default_theme") or "dark",
        "default_accent_color": db.get_system_setting("default_accent_color") or "#0078d4",
        "default_bg_color":     db.get_system_setting("default_bg_color") or "",
    }

@app.context_processor
def _inject_appearance_defaults():
    return {"appearance": _appearance_defaults()}


# ── page routes ────────────────────────────────────────────────────────────
@app.route("/")
def dashboard_page():
    return render_template("index.html", active="dashboard", version=APP_VERSION)

@app.route("/devices")
def devices_page():
    if _is_view_only():
        return redirect("/")
    return render_template("devices.html", active="devices", version=APP_VERSION)

@app.route("/settings")
def settings_page():
    if _is_view_only():
        return redirect("/")
    return render_template("settings.html", active="settings", version=APP_VERSION)

@app.route("/activation")
def activation_page():
    """Standalone full-page license activation view (also embedded in Settings -> License)."""
    if _is_view_only():
        return redirect("/")
    return render_template("activation.html", active="activation", version=APP_VERSION)

@app.route("/alerts")
def alerts_page():
    if _is_view_only():
        return redirect("/")
    return render_template("alerts.html", active="alerts", version=APP_VERSION)

def _patches_applied():
    """Patch numbers recorded by apply_patch.py in PATCHES-APPLIED.txt (install root), e.g. ["01", "02"].
    Lines look like '01 | V11.3-patch-01 | 2026-10-16 | summary'. Missing/unreadable file = no patches."""
    try:
        out = []
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "PATCHES-APPLIED.txt"), encoding="utf-8") as fh:
            for line in fh:
                n = line.split("|", 1)[0].strip()
                if n.isdigit(): out.append(n)
        return out
    except OSError:
        return []

@app.route("/about")
def about_page():
    return render_template("about.html", active="about", version=APP_VERSION, patches=_patches_applied())

@app.route("/admin")
def admin_page():
    if _is_view_only():
        return redirect("/")
    return render_template("admin.html", active="admin", version=APP_VERSION)


# =============================================================================
# V7.2: Alert Event Logs -- Acknowledge / Resolve lifecycle API
# =============================================================================
@app.route("/api/alerts/active")
def api_alerts_active():
    """List active/acknowledged/resolved alerts. ?status=active|acknowledged|resolved (omit for all)."""
    status = request.args.get("status")
    limit  = int(request.args.get("limit", 200))
    return jsonify(db.get_active_alerts(status_filter=status, limit=limit))

@app.route("/api/alerts/count")
def api_alerts_count():
    """Public lightweight count for the sidebar badge."""
    return jsonify({"open": db.count_open_alerts()})

@app.route("/api/alerts/<int:alert_id>/acknowledge", methods=["POST"])
def api_alert_acknowledge(alert_id):
    """Acknowledge -- suppresses further escalation for this metric until 23:59:59 today."""
    err = _require_login()
    if err: return err
    db.acknowledge_alert(alert_id, _email())
    db.audit_log(_email(), "alert_acknowledge", str(alert_id), "")
    return jsonify({"ok": True})

@app.route("/api/alerts/<int:alert_id>/resolve", methods=["POST"])
def api_alert_resolve(alert_id):
    """
    Resolve -- immediately closes the alert (no re-verification required)
    and sends the device's normal recovery/status notification to its
    configured recipients (or admins by default), per device notify config.
    """
    err = _require_login()
    if err: return err
    open_rows = db.get_active_alerts(limit=500)
    row = next((a for a in open_rows if a["id"] == alert_id), None)
    db.resolve_alert(alert_id, _email())
    db.audit_log(_email(), "alert_resolve", str(alert_id), "")

    if row:
        try:
            cfg = config_manager.get_config()
            dn  = db.get_device_notify(row["device_id"]) or {}
            email_notifier.send_alert_email(
                cfg.get("smtp", {}), row.get("device_name",""), row.get("device_host",""),
                row.get("metric","status"), None, "resolved",
                threshold=None, device_notify=dn,
            )
        except Exception:
            pass  # Never fail the resolve action just because email sending had an issue
    return jsonify({"ok": True})


# ── auth API ───────────────────────────────────────────────────────────────
@app.route("/api/auth/login", methods=["POST"])
def api_login():
    body  = request.get_json(force=True) or {}
    email = body.get("email", "").strip().lower()
    token = body.get("token", "").strip()
    if not email or not token:
        return jsonify({"ok": False, "error": "Email and token required"}), 400
    sess, role = auth.attempt_login(email, token)
    if sess:
        return jsonify({"ok": True, "session": sess, "role": role})
    return jsonify({"ok": False, "error": "Invalid email or token"}), 401

@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    auth.logout(_tok())
    return jsonify({"ok": True})

@app.route("/api/auth/check")
def api_auth_check():
    s = _session()
    if s:
        return jsonify({"logged_in": True, "role": s["role"], "email": s["email"]})
    return jsonify({"logged_in": False, "role": None, "email": None})


# ── V8.5: self-service token reset ("Forgot your token?") ──────────────────
# Both routes are deliberately public (no _require_login/_require_admin) --
# this IS the pre-auth recovery path for someone who's locked out.
@app.route("/api/auth/forgot-token", methods=["POST"])
def api_forgot_token():
    body  = request.get_json(force=True) or {}
    email = body.get("email", "").strip().lower()
    # Same generic response regardless of whether the email is registered --
    # see auth.request_token_reset()'s docstring for why this matters.
    generic_msg = "If that email is registered, we've sent a verification code to it."
    if not email:
        return jsonify({"ok": False, "error": "Email is required"}), 400
    otp = auth.request_token_reset(email)
    if otp:
        cfg = config_manager.get_config()
        ok, err = email_notifier.send_token_reset_otp_email(cfg.get("smtp", {}), email, otp)
        if not ok:
            log.warning(f"Token reset OTP email failed for {email}: {err}")
            db.audit_log("system", "token_reset_email_failed", email, err or "")
        else:
            db.audit_log("system", "token_reset_requested", email, "")
    return jsonify({"ok": True, "message": generic_msg})

@app.route("/api/auth/verify-reset-otp", methods=["POST"])
def api_verify_reset_otp():
    body  = request.get_json(force=True) or {}
    email = body.get("email", "").strip().lower()
    otp   = body.get("otp", "").strip()
    if not email or not otp:
        return jsonify({"ok": False, "error": "Email and code are required"}), 400
    verified_token = auth.verify_reset_otp(email, otp)
    if not verified_token:
        return jsonify({"ok": False, "error": "That code is incorrect, expired, or has already been used."}), 400
    db.audit_log(email, "token_reset_otp_verified", email, "")
    return jsonify({"ok": True, "verified_token": verified_token})

@app.route("/api/auth/reset-token", methods=["POST"])
def api_complete_token_reset():
    body           = request.get_json(force=True) or {}
    email          = body.get("email", "").strip().lower()
    verified_token = body.get("verified_token", "").strip()
    new_token      = body.get("new_token", "").strip()
    if not email or not verified_token:
        return jsonify({"ok": False, "error": "Verification is missing -- start over from 'Forgot your token?'"}), 400
    if len(new_token) < 8:
        return jsonify({"ok": False, "error": "Token must be at least 8 characters"}), 400
    ok = auth.complete_token_reset(email, verified_token, new_token)
    if not ok:
        return jsonify({"ok": False, "error": "Verification expired or already used. Request a new code from the login screen."}), 400
    db.audit_log(email, "token_reset_completed", email, "")
    return jsonify({"ok": True, "email": email})


# ── user preferences: theme ────────────────────────────────────────────────
@app.route("/api/prefs/theme", methods=["GET"])
def api_get_theme():
    err = _require_login()
    if err: return err
    theme = db.get_user_pref(_email(), "theme") or "dark"
    return jsonify({"theme": theme})

@app.route("/api/prefs/theme", methods=["POST"])
def api_set_theme():
    err = _require_login()
    if err: return err
    body  = request.get_json(force=True) or {}
    theme = body.get("theme", "dark")
    if theme not in ("dark", "light", "system"):
        return jsonify({"error": "Invalid theme"}), 400
    db.set_user_pref(_email(), "theme", theme)
    return jsonify({"ok": True})


# ── user preferences: accent colour (V7.2) ─────────────────────────────────
import re as _re_color
_HEX_COLOR_RE = _re_color.compile(r"^#[0-9A-Fa-f]{6}$")

# V10.1: shared by /api/prefs/bg-image (per-user) and /api/admin/appearance
# (system default) so the two don't grow two slightly-different copies of
# the same validation rules over time.
def _validate_bg_image_data_url(data_url: str):
    """Returns (data_url, None) if valid, else (None, error_message)."""
    if not data_url.startswith("data:image/"):
        return None, "That doesn't look like an image file"
    try:
        header, b64data = data_url.split(",", 1)
        mime = header.split(":")[1].split(";")[0]
        ext  = mime.split("/")[1]
        if ext not in ("png", "jpeg", "jpg", "webp", "gif"):
            return None, f"Unsupported image type: {mime}. Use PNG, JPG, WEBP, or GIF."
        raw_len = len(b64data) * 3 // 4  # approx decoded size without actually decoding
        if raw_len > 4 * 1024 * 1024:
            return None, "Background image is too large (max 4MB)"
    except Exception as e:
        return None, f"Could not process that image: {e}"
    return data_url, None

@app.route("/api/prefs/accent-color", methods=["GET"])
def api_get_accent():
    err = _require_login()
    if err: return err
    color = db.get_user_pref(_email(), "accent_color") or db.get_system_setting("default_accent_color") or "#0078d4"
    return jsonify({"color": color})

@app.route("/api/prefs/accent-color", methods=["POST"])
def api_set_accent():
    err = _require_login()
    if err: return err
    body  = request.get_json(force=True) or {}
    color = body.get("color", "").strip()
    if not _HEX_COLOR_RE.match(color):
        return jsonify({"error": "Color must be a hex value like #0078d4"}), 400
    db.set_user_pref(_email(), "accent_color", color)
    return jsonify({"ok": True})


# ── user preferences: background colour + image (V10.0) ───────────────────
@app.route("/api/prefs/bg-color", methods=["GET"])
def api_get_bg_color():
    err = _require_login()
    if err: return err
    color = db.get_user_pref(_email(), "bg_color") or ""
    return jsonify({"color": color})

@app.route("/api/prefs/bg-color", methods=["POST"])
def api_set_bg_color():
    err = _require_login()
    if err: return err
    body  = request.get_json(force=True) or {}
    color = body.get("color", "").strip()
    if color and not _HEX_COLOR_RE.match(color):
        return jsonify({"error": "Color must be a hex value like #0078d4"}), 400
    db.set_user_pref(_email(), "bg_color", color)   # empty string = "use theme default"
    return jsonify({"ok": True})

@app.route("/api/prefs/bg-image", methods=["GET"])
def api_get_bg_image():
    err = _require_login()
    if err: return err
    image = db.get_user_pref(_email(), "bg_image") or ""
    return jsonify({"image": image})

@app.route("/api/prefs/bg-image", methods=["POST"])
def api_set_bg_image():
    err = _require_login()
    if err: return err
    body = request.get_json(force=True) or {}
    data_url, error = _validate_bg_image_data_url(body.get("image_data", ""))
    if error:
        return jsonify({"error": error}), 400
    db.set_user_pref(_email(), "bg_image", data_url)
    return jsonify({"ok": True})

@app.route("/api/prefs/bg-image", methods=["DELETE"])
def api_clear_bg_image():
    err = _require_login()
    if err: return err
    db.set_user_pref(_email(), "bg_image", "")
    return jsonify({"ok": True})


# ── admin: system-wide default appearance (V7.2, bg-color/image V10.1) ────
@app.route("/api/admin/appearance", methods=["GET"])
def api_get_admin_appearance():
    err = _require_admin()
    if err: return err
    d = _appearance_defaults()
    d["default_bg_image"] = db.get_system_setting("default_bg_image") or ""
    return jsonify(d)

@app.route("/api/admin/appearance", methods=["POST"])
def api_set_admin_appearance():
    err = _require_admin()
    if err: return err
    body     = request.get_json(force=True) or {}
    theme    = body.get("default_theme", "dark")
    color    = body.get("default_accent_color", "#0078d4")
    bg_color = body.get("default_bg_color", "")
    if theme not in ("dark", "light", "system"):
        return jsonify({"error": "Invalid theme"}), 400
    if not _HEX_COLOR_RE.match(color):
        return jsonify({"error": "Color must be a hex value like #0078d4"}), 400
    if bg_color and not _HEX_COLOR_RE.match(bg_color):
        return jsonify({"error": "Background color must be a hex value like #0f1520"}), 400
    db.set_system_setting("default_theme", theme)
    db.set_system_setting("default_accent_color", color)
    db.set_system_setting("default_bg_color", bg_color)
    db.audit_log(_email(), "set_default_appearance", "",
                 f"theme={theme} color={color} bg_color={bg_color or '(none)'}")
    return jsonify({"ok": True})

@app.route("/api/admin/appearance/bg-image", methods=["POST"])
def api_set_admin_bg_image():
    err = _require_admin()
    if err: return err
    body = request.get_json(force=True) or {}
    data_url, error = _validate_bg_image_data_url(body.get("image_data", ""))
    if error:
        return jsonify({"error": error}), 400
    db.set_system_setting("default_bg_image", data_url)
    db.audit_log(_email(), "set_default_appearance", "", "bg_image=updated")
    return jsonify({"ok": True})

@app.route("/api/admin/appearance/bg-image", methods=["DELETE"])
def api_clear_admin_bg_image():
    err = _require_admin()
    if err: return err
    db.set_system_setting("default_bg_image", "")
    db.audit_log(_email(), "set_default_appearance", "", "bg_image=removed")
    return jsonify({"ok": True})


# ── public: effective appearance defaults, no login required (V10.1) ──────
# Anonymous visitors need this before any session exists -- that's exactly
# why it can't live behind /api/admin/appearance (admin-only, and it's an
# edit surface, not a read of the effective values). The hex/theme values
# here are never secret; they're the same thing every visitor already sees
# rendered on the page.
@app.route("/api/appearance/defaults", methods=["GET"])
def api_get_appearance_defaults():
    d = _appearance_defaults()
    return jsonify({
        "theme":        d["default_theme"],
        "accent_color": d["default_accent_color"],
        "bg_color":     d["default_bg_color"],
        "bg_image":     db.get_system_setting("default_bg_image") or "",
    })


# ── dashboard layout (tile positions, sizes, visibility) ──────────────────
@app.route("/api/dashboard/layout", methods=["GET"])
def api_get_layout():
    err = _require_login()
    if err: return err
    layout = db.get_dashboard_layout(_email())
    return jsonify(layout)

@app.route("/api/dashboard/layout", methods=["POST"])
def api_save_layout():
    err = _require_login()
    if err: return err
    body = request.get_json(force=True) or {}
    # V8.2 fix: dashboard.js has always sent the tile array under the key
    # "tiles" (see saveLayout() in dashboard.js). This handler was reading
    # body.get("layout", []) -- a key the frontend never sends -- so every
    # single "Save Layout" click silently persisted an EMPTY list, which is
    # why the layout always reverted to default order after a refresh or
    # page change. Accept "tiles" (current) and "layout" (back-compat, in
    # case any older/external caller still uses it).
    tiles = body.get("tiles", body.get("layout", []))
    db.save_dashboard_layout(_email(), tiles)
    # Edit Mode bundles a staged view_type/grid_cols change into this same
    # POST (see saveLayout() in dashboard.js) -- persist those too instead
    # of silently dropping them.
    if body.get("view_type") in ("grid", "list"):
        db.set_user_pref(_email(), "view_mode", body["view_type"])
    if "grid_cols" in body:
        try:
            db.set_user_pref(_email(), "grid_cols", str(int(body["grid_cols"])))
        except (TypeError, ValueError):
            pass
    return jsonify({"ok": True})

@app.route("/api/dashboard/view-mode", methods=["POST"])
def api_set_view_mode():
    err = _require_login()
    if err: return err
    body = request.get_json(force=True) or {}
    # V8.2 fix: dashboard.js sends {view_type, grid_cols}, not {mode}. Reading
    # the wrong key meant this always fell back to the "grid" default no
    # matter what the person picked, which is why List view snapped back to
    # Grid on the very next 5-second poll. Accept "view_type" (current) and
    # "mode" (back-compat).
    mode = body.get("view_type", body.get("mode", "grid"))
    if mode not in ("grid", "list"):
        return jsonify({"error": "Invalid mode"}), 400
    db.set_user_pref(_email(), "view_mode", mode)
    # grid_cols was accepted by the frontend payload but never actually
    # saved anywhere -- density (2/3/4/5/Auto) was lost on every reload.
    if "grid_cols" in body:
        try:
            db.set_user_pref(_email(), "grid_cols", str(int(body["grid_cols"])))
        except (TypeError, ValueError):
            pass
    return jsonify({"ok": True})

@app.route("/api/dashboard/view-mode", methods=["GET"])
def api_get_view_mode():
    err = _require_login()
    if err: return err
    mode = db.get_user_pref(_email(), "view_mode") or "grid"
    cols = db.get_user_pref(_email(), "grid_cols")
    try:
        cols = int(cols) if cols is not None else 0
    except (TypeError, ValueError):
        cols = 0
    return jsonify({"mode": mode, "view_type": mode, "grid_cols": cols})


# ── live status ────────────────────────────────────────────────────────────
@app.route("/api/status")
def api_status():
    rows    = db.get_all_device_status()
    session = _session()
    role    = session["role"] if session else None
    email   = session["email"] if session else None

    # Per-user layout
    layout_list = db.get_dashboard_layout(email) if email else []
    layout_map  = {item["device_id"]: item for item in layout_list}

    cfg = config_manager.get_config()
    polled_ids = {r["device_id"] for r in rows}
    for d in cfg.get("devices", []):
        if d["id"] not in polled_ids:
            rows.append({
                "device_id": d["id"], "name": d["name"],
                "type": d.get("type","network"), "method": d.get("method","ping"),
                "host": d.get("host",""), "status": "unknown",
                "last_checked": None, "last_error": None, "metrics_json": "{}",
            })

    for r in rows:
        r["metrics"] = json.loads(r.pop("metrics_json") or "{}")
        lay = layout_map.get(r["device_id"], {})
        r["tile_position"]  = lay.get("position", 0)
        r["tile_hidden"]    = lay.get("hidden", False)
        r["tile_size"]      = lay.get("size", "normal")
        r["tile_col"]       = lay.get("col", 0)
        r["tile_row"]       = lay.get("row", 0)
        if role != "admin":
            r["host"] = "*** (admin only)"
            r.pop("last_error", None)

    rows.sort(key=lambda x: x["tile_position"])
    visible = [r for r in rows if not r["tile_hidden"]]
    summary = {s: sum(1 for r in visible if r["status"] == s)
               for s in ("ok","warning","critical","offline")}
    summary["total"] = len(visible)

    view_mode = db.get_user_pref(email, "view_mode") if email else "grid"
    theme     = db.get_user_pref(email, "theme") if email else "dark"
    grid_cols_raw = db.get_user_pref(email, "grid_cols") if email else None
    try:
        grid_cols = int(grid_cols_raw) if grid_cols_raw is not None else 0
    except (TypeError, ValueError):
        grid_cols = 0

    return jsonify({
        "devices":    rows,
        "summary":    summary,
        "server_time": time.time(),
        "role":       role,
        "version":    APP_VERSION,
        "port":       APP_PORT,
        "platform":   platform.system(),
        "license":    license_manager.get_status_dict(),
        # V8.2 fix: dashboard.js reads data.view_type / data.grid_cols (see
        # refresh() in dashboard.js). This endpoint only ever sent
        # "view_mode" and never sent grid_cols at all, so both silently
        # defaulted every single poll -- the visible symptom was "list view
        # keeps reverting to grid" and "grid density resets on refresh".
        # view_mode is kept alongside for back-compat with any other caller.
        "view_type":  view_mode or "grid",
        "view_mode":  view_mode or "grid",
        "grid_cols":  grid_cols,
        "theme":      theme or "dark",
    })


@app.route("/api/history/<device_id>/<metric>")
def api_history(device_id, metric):
    since = int(request.args.get("since_seconds", 3600))
    return jsonify(db.get_metric_history(device_id, metric, since))

@app.route("/api/alerts")
def api_alerts():
    return jsonify(db.get_recent_alerts(int(request.args.get("limit", 100))))

@app.route("/api/system/info")
def api_system_info():
    return jsonify({
        "version":  APP_VERSION,
        "port":     APP_PORT,
        "platform": platform.system(),
        "python":   platform.python_version(),
        "hostname": platform.node(),
        "license":  license_manager.get_status_dict(),
    })


# ── devices ────────────────────────────────────────────────────────────────
@app.route("/api/devices", methods=["GET"])
def api_get_devices():
    cfg  = config_manager.get_config()
    devs = cfg.get("devices", [])
    if not _is_admin():
        devs = [{"id":d["id"],"name":d["name"],
                 "type":d.get("type",""),"method":d.get("method","")} for d in devs]
    return jsonify(devs)

@app.route("/api/devices", methods=["POST"])
def api_add_device():
    err = _require_admin()
    if err: return err
    device  = request.get_json(force=True)
    missing = {"id","name","type","method","host"} - set(device)
    if missing:
        return jsonify({"error": f"Missing fields: {missing}"}), 400
    cfg = config_manager.add_or_update_device(device)
    sched.reload_scheduler(cfg)
    db.audit_log(_email(), "add_device", device.get("id",""), "")
    return jsonify({"ok": True})

@app.route("/api/devices/<device_id>", methods=["PUT"])
def api_update_device(device_id):
    err = _require_admin()
    if err: return err
    device = request.get_json(force=True)
    device["id"] = device_id
    cfg = config_manager.add_or_update_device(device)
    sched.reload_scheduler(cfg)
    db.audit_log(_email(), "edit_device", device_id, "")
    return jsonify({"ok": True})

@app.route("/api/devices/<device_id>", methods=["DELETE"])
def api_delete_device(device_id):
    err = _require_admin()
    if err: return err
    cfg = config_manager.remove_device(device_id)
    sched.reload_scheduler(cfg)
    db.audit_log(_email(), "delete_device", device_id, "")
    return jsonify({"ok": True})


@app.route("/api/devices/<device_id>/test", methods=["POST"])
def api_test_device(device_id):
    err = _require_admin()
    if err: return err
    cfg    = config_manager.get_config()
    device = next((d for d in cfg.get("devices",[]) if d["id"]==device_id), None)
    if not device:
        return jsonify({"ok":False,"status":"error","detail":"Device not found"}), 404
    method = device.get("method","ping")
    host   = device.get("host","")
    try:
        if method == "ping":
            from monitor.checkers.ping_check import check
            r  = check(host, timeout_ms=device.get("ping_timeout_ms",1500))
            ok = r.get("reachable",False)
            detail = f"Latency: {r.get('latency_ms','?')} ms, Loss: {r.get('packet_loss_pct','?')}%" if ok else r.get("error","No response")
        elif method == "powershell":
            from monitor.checkers.powershell_check import check
            from monitor import crypto
            pc = device.get("powershell",{})
            r  = check(host, remote=pc.get("remote",False), use_winrm=pc.get("use_winrm",True),
                       username=pc.get("username"), password=crypto.decrypt(pc.get("password","") or ""), timeout=20)
            ok = r.get("reachable",False)
            detail = f"CPU: {r.get('cpu_pct','?')}%, Mem: {r.get('memory_pct','?')}%, Disk: {r.get('disk_pct','?')}%" if ok else r.get("error","PS check failed")
        elif method == "ssh":
            from monitor.checkers.ssh_check import check
            from monitor import crypto
            sc = device.get("ssh",{})
            r  = check(host, port=sc.get("port",22), username=sc.get("username","monitor"),
                       password=crypto.decrypt(sc.get("password","") or ""), key_path=sc.get("key_path"))
            ok = r.get("reachable",False)
            detail = f"CPU: {r.get('cpu_pct','?')}%, Mem: {r.get('memory_pct','?')}%" if ok else r.get("error","SSH failed")
        elif method == "snmp":
            from monitor.checkers.snmp_check import check
            sc = device.get("snmp",{})
            r  = check(device_id, host, community=sc.get("community","public"), version=sc.get("version",2))
            ok = r.get("reachable",False)
            detail = f"SNMP OK  uptime: {r.get('uptime_ticks','?')}" if ok else r.get("error","SNMP failed")
        elif method == "disk_usage":
            from monitor.checkers.disk_usage_check import check
            r  = check(device)
            ok = r.get("reachable",False)
            detail = f"Disk: {r.get('disk_pct','?')}%, Free: {r.get('free_gb','?')} GB" if ok else r.get("error","Disk failed")
        elif method == "url":
            from monitor.checkers.url_check import check
            r  = check(device)
            ok = r.get("reachable",False)
            detail = (f"HTTP {r.get('status_code','?')}, {r.get('response_ms','?')} ms"
                      + (f", SSL exp. in {r['ssl_days_left']}d" if r.get("ssl_days_left") is not None else ""))\
                     if ok else r.get("error", "URL check failed")
        elif method == "service":
            from monitor.checkers.service_check import check
            r  = check(device)
            ok = r.get("reachable", False)
            up = sum(1 for s in r.get("services", []) if s.get("running"))
            detail = f"{up}/{len(r.get('services', []))} service(s) running" if ok else r.get("error", "Service check failed")
        elif method == "task":
            from monitor.checkers.task_check import check
            r  = check(device)
            ok = r.get("reachable", False)
            good = sum(1 for t in r.get("tasks", []) if t.get("ok"))
            detail = f"{good}/{len(r.get('tasks', []))} task(s) OK" if ok else r.get("error", "Task check failed")
        else:
            ok, detail = False, f"Unknown method: {method}"
        db.audit_log(_email(), "test_device", device_id, "PASS" if ok else "FAIL")
        return jsonify({"ok":ok, "status":"pass" if ok else "fail", "detail":detail})
    except Exception as e:
        log.exception("Device test error %s", device_id)
        return jsonify({"ok":False,"status":"error","detail":str(e)}), 500


# ── per-device notifications ───────────────────────────────────────────────
@app.route("/api/devices/<device_id>/notify", methods=["GET"])
def api_get_notify(device_id):
    err = _require_admin()
    if err: return err
    return jsonify(db.get_device_notify(device_id))

@app.route("/api/devices/<device_id>/notify", methods=["POST"])
def api_set_notify(device_id):
    err = _require_admin()
    if err: return err
    b = request.get_json(force=True) or {}
    # V11.1: reject impossible thresholds (warning above critical, out of range, not a number) with a clear
    # message instead of silently saving values that would never alert or always alert.
    clean_thr, thr_errors = threshold_meta.validate_thresholds(b.get("thresholds", {}))
    if thr_errors:
        return jsonify({"ok": False, "error": thr_errors[0], "errors": thr_errors}), 400
    b["thresholds"] = clean_thr
    db.set_device_notify(
        device_id,
        notifications_enabled   = b.get("notifications_enabled", 1),
        notify_emails           = b.get("notify_emails", []),
        escalation_emails_l1    = b.get("escalation_emails_l1", []),
        escalation_emails_l2    = b.get("escalation_emails_l2", []),
        escalation_emails_l3    = b.get("escalation_emails_l3", []),
        escalation_after_sec_l1 = int(b.get("escalation_after_sec_l1", 60)),
        escalation_after_sec_l2 = int(b.get("escalation_after_sec_l2", 600)),
        escalation_after_sec_l3 = int(b.get("escalation_after_sec_l3", 1200)),
        escalation_levels       = int(b.get("escalation_levels", 1)),
        thresholds              = b.get("thresholds", {}),
        alert_trigger_mode      = b.get("alert_trigger_mode", "sustained"),
        alert_notify_mode       = b.get("alert_notify_mode", "immediate"),
        notify_cooldown_sec     = int(b.get("notify_cooldown_sec", 300)),
        sms_numbers_l1          = b.get("sms_numbers_l1", []),
        sms_numbers_l2          = b.get("sms_numbers_l2", []),
        sms_numbers_l3          = b.get("sms_numbers_l3", []),
        call_numbers_l1         = b.get("call_numbers_l1", []),
        call_numbers_l2         = b.get("call_numbers_l2", []),
        call_numbers_l3         = b.get("call_numbers_l3", []),
    )
    return jsonify({"ok": True})


# ── tile layout (legacy per-tile ops) ─────────────────────────────────────
@app.route("/api/tiles/<device_id>/hide",  methods=["POST"])
def api_hide_tile(device_id):
    err = _require_login()
    if err: return err
    db.set_tile_hidden(device_id, True)
    return jsonify({"ok": True})

@app.route("/api/tiles/<device_id>/show",  methods=["POST"])
def api_show_tile(device_id):
    err = _require_login()
    if err: return err
    db.set_tile_hidden(device_id, False)
    return jsonify({"ok": True})

@app.route("/api/tiles/order", methods=["POST"])
def api_tile_order():
    err = _require_login()
    if err: return err
    db.set_tile_order(request.get_json(force=True).get("device_ids",[]))
    return jsonify({"ok": True})

@app.route("/api/tiles/<device_id>/size", methods=["POST"])
def api_tile_size(device_id):
    err = _require_login()
    if err: return err
    db.set_tile_size(device_id, (request.get_json(force=True) or {}).get("size","normal"))
    return jsonify({"ok": True})


# ── SMTP settings ──────────────────────────────────────────────────────────
@app.route("/api/settings/smtp", methods=["GET"])
def api_get_smtp():
    err = _require_admin()
    if err: return err
    cfg  = config_manager.get_config()
    smtp = dict(cfg.get("smtp", {}))
    smtp["password"] = ""
    return jsonify(smtp)

@app.route("/api/settings/smtp", methods=["POST"])
def api_update_smtp():
    err = _require_admin()
    if err: return err
    config_manager.update_smtp(request.get_json(force=True))
    return jsonify({"ok": True})

@app.route("/api/settings/test-email", methods=["POST"])
def api_test_email():
    err = _require_admin()
    if err: return err
    cfg  = config_manager.get_config()
    body = request.get_json(silent=True) or {}
    ok, msg = email_notifier.send_alert_email(
        cfg["smtp"], "Test Device", "127.0.0.1",
        "test_metric", 99.9, body.get("state","warning"), threshold=75
    )
    return jsonify({"ok": ok, "message": msg})


# ── V8.5: SMS / voice-call escalation gateways ─────────────────────────────
@app.route("/api/settings/sms-gateway", methods=["GET"])
def api_get_sms_gateway():
    err = _require_admin()
    if err: return err
    gw = dict(config_manager.get_sms_gateway())
    gw["auth_pass"] = ""   # never echo the credential back, same pattern as SMTP
    gw["presets"] = {k: {kk: vv for kk, vv in v.items() if kk != "note"} for k, v in messaging_gateway.PRESETS.items()}
    gw["preset_notes"] = {k: v.get("note", "") for k, v in messaging_gateway.PRESETS.items()}
    gw["preset_labels"] = {k: v.get("label", k) for k, v in messaging_gateway.PRESETS.items()}
    return jsonify(gw)

@app.route("/api/settings/sms-gateway", methods=["POST"])
def api_update_sms_gateway():
    err = _require_admin()
    if err: return err
    config_manager.update_sms_gateway(request.get_json(force=True))
    return jsonify({"ok": True})

@app.route("/api/settings/sms-gateway/test", methods=["POST"])
def api_test_sms_gateway():
    err = _require_admin()
    if err: return err
    body  = request.get_json(force=True) or {}
    phone = (body.get("phone") or "").strip()
    if not phone:
        return jsonify({"ok": False, "error": "Enter a phone number to send the test to"}), 400
    ok, error = messaging_gateway.test_gateway("sms", phone)
    db.audit_log(_email(), "test_sms_gateway", phone, error or "sent")
    return jsonify({"ok": ok, "error": error})

@app.route("/api/settings/call-gateway", methods=["GET"])
def api_get_call_gateway():
    err = _require_admin()
    if err: return err
    gw = dict(config_manager.get_call_gateway())
    gw["auth_pass"] = ""
    gw["presets"] = {k: {kk: vv for kk, vv in v.items() if kk != "note"} for k, v in messaging_gateway.PRESETS.items()}
    gw["preset_notes"] = {k: v.get("note", "") for k, v in messaging_gateway.PRESETS.items()}
    gw["preset_labels"] = {k: v.get("label", k) for k, v in messaging_gateway.PRESETS.items()}
    return jsonify(gw)

@app.route("/api/settings/call-gateway", methods=["POST"])
def api_update_call_gateway():
    err = _require_admin()
    if err: return err
    config_manager.update_call_gateway(request.get_json(force=True))
    return jsonify({"ok": True})

@app.route("/api/settings/call-gateway/test", methods=["POST"])
def api_test_call_gateway():
    err = _require_admin()
    if err: return err
    body  = request.get_json(force=True) or {}
    phone = (body.get("phone") or "").strip()
    if not phone:
        return jsonify({"ok": False, "error": "Enter a phone number to call for the test"}), 400
    ok, error = messaging_gateway.test_gateway("call", phone)
    db.audit_log(_email(), "test_call_gateway", phone, error or "sent")
    return jsonify({"ok": ok, "error": error})


# ── V8.5: organisation branding ─────────────────────────────────────────────
@app.route("/api/settings/organisation", methods=["GET"])
def api_get_organisation():
    # Deliberately public (no _require_login) -- base.html's sidebar/header
    # render this on EVERY page, including the pre-login state (the login
    # form is an overlay on top of the normal page shell, not a separate
    # route), same precedent as /api/license/status being fetched
    # unauthenticated from base.html's inline script.
    return jsonify(config_manager.get_organisation())

@app.route("/api/settings/organisation", methods=["POST"])
def api_update_organisation():
    err = _require_admin()
    if err: return err
    body = request.get_json(force=True) or {}
    color = body.get("color")
    if color is not None and not re.fullmatch(r"#[0-9a-fA-F]{6}", color or ""):
        return jsonify({"error": "Colour must be a hex value like #8b95a5"}), 400
    config_manager.update_organisation(name=body.get("name"), color=color)
    db.audit_log(_email(), "update_organisation", "-", body.get("name","")[:80])
    return jsonify({"ok": True})

@app.route("/api/settings/organisation/logo", methods=["POST"])
def api_upload_org_logo():
    err = _require_admin()
    if err: return err
    body     = request.get_json(force=True) or {}
    data_url = body.get("logo_data", "")
    if not data_url.startswith("data:image/"):
        return jsonify({"error": "That doesn't look like an image file"}), 400
    try:
        header, b64data = data_url.split(",", 1)
        mime = header.split(":")[1].split(";")[0]
        ext  = mime.split("/")[1]
        ext  = {"jpeg": "jpg", "svg+xml": "svg"}.get(ext, ext)
        if ext not in ("png", "jpg", "gif", "webp", "svg"):
            return jsonify({"error": f"Unsupported image type: {mime}. Use PNG, JPG, GIF, WEBP, or SVG."}), 400
        raw = base64.b64decode(b64data)
        if len(raw) > 2 * 1024 * 1024:
            return jsonify({"error": "Logo file is too large (max 2MB)"}), 400
    except Exception as e:
        return jsonify({"error": f"Could not process that image: {e}"}), 400

    upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    # Remove any previously-uploaded logo of a different extension so
    # switching from e.g. a .png to a .svg logo doesn't leave the old
    # file behind as dead weight.
    for old_ext in ("png", "jpg", "gif", "webp", "svg"):
        old_path = os.path.join(upload_dir, f"org_logo.{old_ext}")
        if os.path.exists(old_path):
            os.remove(old_path)
    filename = f"org_logo.{ext}"
    with open(os.path.join(upload_dir, filename), "wb") as f:
        f.write(raw)
    logo_path = f"/static/uploads/{filename}"
    config_manager.update_organisation(logo_path=logo_path)
    db.audit_log(_email(), "update_org_logo", "-", filename)
    return jsonify({"ok": True, "logo_path": logo_path})

@app.route("/api/settings/organisation/logo", methods=["DELETE"])
def api_remove_org_logo():
    err = _require_admin()
    if err: return err
    upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "uploads")
    for ext in ("png", "jpg", "gif", "webp", "svg"):
        p = os.path.join(upload_dir, f"org_logo.{ext}")
        if os.path.exists(p):
            os.remove(p)
    config_manager.update_organisation(logo_path="")
    db.audit_log(_email(), "remove_org_logo", "-", "")
    return jsonify({"ok": True})


# ── notification + threshold settings ─────────────────────────────────────
@app.route("/api/settings/notifications", methods=["GET"])
def api_get_notifications():
    err = _require_admin()
    if err: return err
    cfg = config_manager.get_config()
    return jsonify(cfg.get("notifications") or {
        "send_on_warning": True,"send_on_critical": True,
        "send_on_recovery": True,"send_on_offline": True,
        "resend_warn_minutes": 60,"resend_crit_minutes": 30,
        "include_detail": True,"include_host": True,
    })

@app.route("/api/settings/notifications", methods=["POST"])
def api_update_notifications():
    err = _require_admin()
    if err: return err
    config_manager.update_notifications(request.get_json(force=True))
    return jsonify({"ok": True})

@app.route("/api/settings/thresholds", methods=["GET"])
def api_get_thresholds():
    err = _require_admin()
    if err: return err
    return jsonify(config_manager.get_config().get("global_thresholds") or {})

@app.route("/api/settings/thresholds", methods=["POST"])
def api_update_thresholds():
    err = _require_admin()
    if err: return err
    clean_thr, thr_errors = threshold_meta.validate_thresholds(request.get_json(force=True))
    if thr_errors:
        return jsonify({"ok": False, "error": thr_errors[0], "errors": thr_errors}), 400
    config_manager.update_global_thresholds(clean_thr)
    return jsonify({"ok": True})


@app.route("/api/threshold-meta", methods=["GET"])
def api_threshold_meta():
    """V11.1: the metric catalogue the Settings and Devices screens render their threshold tables from:
    label, unit, direction, allowed range, recommended warning/critical, and which metrics each monitoring
    method (ping, snmp, ..., url = websites) offers. Any logged-in user may read it (it is static)."""
    err = _require_login()
    if err: return err
    return jsonify(threshold_meta.public_catalogue())

@app.route("/api/settings/escalation-defaults", methods=["GET"])
def api_get_esc():
    err = _require_admin()
    if err: return err
    return jsonify(config_manager.get_config().get("escalation_defaults") or {})

@app.route("/api/settings/escalation-defaults", methods=["POST"])
def api_update_esc():
    err = _require_admin()
    if err: return err
    config_manager.update_escalation_defaults(request.get_json(force=True))
    return jsonify({"ok": True})

@app.route("/api/settings/escalation-defaults/apply-all", methods=["POST"])
@_batched
def api_apply_esc_all():
    err = _require_admin()
    if err: return err
    body = request.get_json(force=True) or {}
    cfg  = config_manager.get_config()
    for d in cfg.get("devices",[]):
        ex = db.get_device_notify(d["id"])
        db.set_device_notify(
            d["id"],
            notifications_enabled   = ex.get("notifications_enabled",1),
            notify_emails           = ex.get("notify_emails",[]),
            escalation_emails_l1    = body.get("escalation_emails_l1",[]),
            escalation_emails_l2    = body.get("escalation_emails_l2",[]),
            escalation_emails_l3    = body.get("escalation_emails_l3",[]),
            escalation_after_sec_l1 = int(body.get("escalation_after_sec_l1",60)),
            escalation_after_sec_l2 = int(body.get("escalation_after_sec_l2",600)),
            escalation_after_sec_l3 = int(body.get("escalation_after_sec_l3",1200)),
            escalation_levels       = ex.get("escalation_levels",1),
            thresholds              = ex.get("thresholds",{}),
            alert_trigger_mode      = body.get("alert_trigger_mode", ex.get("alert_trigger_mode","sustained")),
            alert_notify_mode       = body.get("alert_notify_mode", ex.get("alert_notify_mode","immediate")),
            notify_cooldown_sec     = int(body.get("notify_cooldown_sec", ex.get("notify_cooldown_sec",300))),
            # V8.5: deliberately preserved from the existing per-device
            # config, NOT taken from `body` -- phone numbers are
            # device/team-specific, unlike the timing/email defaults this
            # bulk action exists to push out. Applying defaults must never
            # silently wipe a device's SMS/call escalation contacts.
            sms_numbers_l1          = ex.get("sms_numbers_l1", []),
            sms_numbers_l2          = ex.get("sms_numbers_l2", []),
            sms_numbers_l3          = ex.get("sms_numbers_l3", []),
            call_numbers_l1         = ex.get("call_numbers_l1", []),
            call_numbers_l2         = ex.get("call_numbers_l2", []),
            call_numbers_l3         = ex.get("call_numbers_l3", []),
        )
    db.audit_log(_email(),"apply_esc_all","all","")
    return jsonify({"ok":True,"count":len(cfg.get("devices",[]))})


# ── V11.3 patch 04: type / method scopes, facets, and single-device thresholds ────────────────────
def _drop_noop_rows(clean):
    """A row that only says enabled=true changes nothing; keeping it would make a metric look 'set here' (hiding where
    its value really comes from). Rows with a value, a disabled flag or a wait time stay."""
    return {k: v for k, v in clean.items() if (set(v) - {"enabled"}) or v.get("enabled") is False}

def _device_by_id(did):
    return next((d for d in config_manager.get_config().get("devices", []) if d.get("id") == did), None)

def _in_scope(device, kind, key):
    return (device.get(kind) or "") == key

@app.route("/api/monitor-facets", methods=["GET"])
def api_monitor_facets():
    """Counts for the Type / Method filters: only types and methods that exist, plus their labels."""
    err = _require_admin()
    if err: return err
    devs = config_manager.get_config().get("devices", [])
    def tally(field):
        out = {}
        for d in devs:
            k = d.get(field) or ""
            if k: out[k] = out.get(k, 0) + 1
        return out
    types, methods = tally("type"), tally("method")
    order = [k for k, _ in threshold_meta.DEVICE_TYPES]
    def methods_of(t):
        return sorted({d.get("method") for d in devs if (d.get("type") or "") == t and d.get("method") and d.get("method") != "url"})
    type_rows = [{"id": k, "label": threshold_meta.TYPE_LABELS.get(k, k.replace("_", " ").title()), "count": n,
                  "methods": methods_of(k), "metrics": threshold_meta.type_metrics(k, methods_of(k))}
                 for k, n in sorted(types.items(), key=lambda kv: (order.index(kv[0]) if kv[0] in order else 99, kv[0]))]
    method_rows = [{"id": k, "label": threshold_meta.METHOD_LABELS.get(k, k), "count": n,
                    "metrics": threshold_meta.scope_metrics("method", k)} for k, n in sorted(methods.items())]
    return jsonify({"types": type_rows, "methods": method_rows,
                    "all_types": [{"id": k, "label": v, "metrics": threshold_meta.type_metrics(k, [])} for k, v in threshold_meta.DEVICE_TYPES]})

@app.route("/api/settings/thresholds/scoped", methods=["GET"])
def api_get_scoped_thresholds():
    err = _require_admin()
    if err: return err
    return jsonify(config_manager.effective_scoped_thresholds())

@app.route("/api/settings/thresholds/scoped", methods=["POST"])
@_batched
def api_set_scoped_thresholds():
    """Body {kind: 'type'|'method', key: 'firewall'|'ssh'|..., thresholds: {metric: {enabled, warning, critical}},
    apply: bool}. Saves the thresholds for every device of that type/method. An empty `thresholds` removes the scope
    (its devices inherit the global values again). With apply=true the per-device warning/critical/enabled overrides of
    the SENT metrics are removed from every device in that scope, so they all follow the scope (wait_sec is kept)."""
    err = _require_admin()
    if err: return err
    b = request.get_json(force=True) or {}
    kind, key = b.get("kind"), str(b.get("key") or "").strip()
    if kind not in threshold_meta.SCOPE_KINDS or not key:
        return jsonify({"ok": False, "error": "kind must be 'type' or 'method' and key must be given."}), 400
    devs_in = [d for d in config_manager.get_config().get("devices", []) if _in_scope(d, kind, key)]
    known = threshold_meta.TYPE_LABELS if kind == "type" else threshold_meta.METHOD_LABELS
    if key not in known and not devs_in:
        return jsonify({"ok": False, "error": f"Unknown {kind} '{key}'."}), 400
    if kind == "method" and key == "url":
        return jsonify({"ok": False, "error": "Website thresholds are set on the Sites side of this tab."}), 400
    allowed = threshold_meta.scope_metrics(kind, key)
    incoming = b.get("thresholds") or {}
    if not isinstance(incoming, dict):
        return jsonify({"ok": False, "error": "Thresholds must be an object of metric settings."}), 400
    incoming = {k: v for k, v in incoming.items() if k in allowed}
    clean, errs = threshold_meta.validate_thresholds(incoming)
    if errs:
        return jsonify({"ok": False, "error": errs[0], "errors": errs}), 400
    clean = _drop_noop_rows({k: {kk: vv for kk, vv in v.items() if kk != "wait_sec"} for k, v in clean.items()})
    config_manager.update_scoped_thresholds(kind, key, clean)
    cleared = changed = 0
    if b.get("apply") and clean:
        for d in devs_in:
            ex = db.get_device_notify(d["id"]); thr = dict(ex.get("thresholds") or {}); hit = False
            for m in clean:
                row = thr.get(m)
                if not isinstance(row, dict) or not any(f in row for f in ("warning", "critical", "enabled")):
                    continue
                keep = {kk: vv for kk, vv in row.items() if kk == "wait_sec" and vv not in (None, "")}
                if keep: thr[m] = keep
                else:    thr.pop(m, None)
                hit = True; cleared += 1
            if hit:
                _save_notify_merged(d["id"], ex, thresholds=thr); changed += 1
    db.audit_log(_email(), "set_scoped_thresholds", f"{kind}:{key}",
                 f"{len(clean)} metric(s); {len(devs_in)} device(s); apply={bool(b.get('apply'))}; {cleared} override(s) removed")
    return jsonify({"ok": True, "count": len(devs_in), "overrides_removed": cleared, "devices_changed": changed,
                    "cleared_scope": not clean})

_SOURCE_ORDER = ("global", "method", "type", "device config", "device override")

def _threshold_sources(device, notify, scoped, global_thr):
    """Which layer decides each metric: the highest layer that sets warning/critical/enabled for it."""
    layers = (("global", global_thr or {}),
              ("method " + (device.get("method") or ""), (scoped.get("method") or {}).get(device.get("method") or "") or {}),
              ("type " + (device.get("type") or ""), (scoped.get("type") or {}).get(device.get("type") or "") or {}),
              ("device config", device.get("thresholds") or {}),
              ("this device", (notify or {}).get("thresholds") or {}))
    out = {}
    for label, layer in layers:
        for m, row in (layer or {}).items():
            if isinstance(row, dict) and any(f in row for f in ("warning", "critical", "enabled")):
                out[m] = label
    return out

@app.route("/api/devices/<device_id>/thresholds", methods=["GET"])
def api_get_device_thresholds(device_id):
    """Everything the dashboard's device window needs: basics, live status, and for every metric of this device's
    method the EFFECTIVE warning/critical, which layer decides it, and this device's own override."""
    err = _require_admin()
    if err: return err
    d = _device_by_id(device_id)
    if not d: return jsonify({"error": "Unknown device."}), 404
    notify = db.get_device_notify(device_id)
    gl, sc = config_manager.effective_global_thresholds(), config_manager.effective_scoped_thresholds()
    eff = alerts_engine.effective_thresholds(d, gl, notify, sc)
    src = _threshold_sources(d, notify, sc, gl)
    own = notify.get("thresholds") or {}
    meta = threshold_meta.public_catalogue()["metrics"]
    keys = threshold_meta.METHOD_METRICS.get(d.get("method") or "ping", threshold_meta.DEVICE_METRICS)
    st = next((r for r in db.get_all_device_status() if r["device_id"] == device_id), {}) or {}
    rows = []
    for k in keys:
        e = eff.get(k, {})
        rows.append({"key": k, "label": meta[k]["label"], "unit": meta[k]["unit"], "lower_is_worse": bool(meta[k].get("lower_is_worse")),
                     "effective": {"warning": e.get("warning"), "critical": e.get("critical"), "enabled": e.get("enabled", True) is not False},
                     "source": src.get(k, "built-in"), "override": {f: own.get(k, {}).get(f) for f in ("enabled", "warning", "critical", "wait_sec") if f in (own.get(k) or {})}})
    return jsonify({
        "device": {"id": device_id, "name": d.get("name"), "host": d.get("host"), "type": d.get("type") or "",
                   "type_label": threshold_meta.TYPE_LABELS.get(d.get("type") or "", d.get("type") or ""),
                   "method": d.get("method") or "", "method_label": threshold_meta.METHOD_LABELS.get(d.get("method") or "", d.get("method") or ""),
                   "poll_interval_seconds": d.get("poll_interval_seconds"), "status": st.get("status", "unknown"),
                   "last_checked": st.get("last_checked"), "last_error": st.get("last_error")},
        "metrics": rows,
        "notify": {"alert_trigger_mode": notify.get("alert_trigger_mode"), "escalation_after_sec_l1": notify.get("escalation_after_sec_l1"),
                   "alert_notify_mode": notify.get("alert_notify_mode"), "notify_cooldown_sec": notify.get("notify_cooldown_sec"),
                   "notifications_enabled": notify.get("notifications_enabled", 1)}})

@app.route("/api/devices/<device_id>/thresholds", methods=["POST"])
def api_set_device_thresholds(device_id):
    """Body {thresholds: {metric: {enabled, warning, critical, wait_sec}}}. Saves THIS device's own overrides for the
    metrics of its method; a metric missing from the body (or blank) goes back to inheriting. Everything else about
    the device's notification settings is left exactly as it is."""
    err = _require_admin()
    if err: return err
    d = _device_by_id(device_id)
    if not d: return jsonify({"ok": False, "error": "Unknown device."}), 404
    b = request.get_json(force=True) or {}
    keys = threshold_meta.METHOD_METRICS.get(d.get("method") or "ping", threshold_meta.DEVICE_METRICS)
    incoming = {k: v for k, v in (b.get("thresholds") or {}).items() if k in keys}
    clean, errs = threshold_meta.validate_thresholds(incoming)
    if errs:
        return jsonify({"ok": False, "error": errs[0], "errors": errs}), 400
    ex = db.get_device_notify(device_id)
    thr = {k: v for k, v in (ex.get("thresholds") or {}).items() if k not in keys}
    thr.update(_drop_noop_rows(clean))
    _save_notify_merged(device_id, ex, thresholds=thr)
    db.audit_log(_email(), "set_device_thresholds", device_id, f"{len(clean)} override(s)")
    return jsonify({"ok": True, "overrides": len(_drop_noop_rows(clean))})


# ── V11.3 patch 03: offline-detection settings (fewer false "offline" alerts) ──────────────────────
@app.route("/api/settings/offline-detection", methods=["GET"])
def api_get_offline_detection():
    err = _require_admin()
    if err: return err
    r, d, c = sched.offline_settings({})
    return jsonify({"offline_retries": r, "offline_retry_delay_sec": d, "offline_confirm_polls": c,
                    "limits": {k: list(v) for k, v in sched._OFFLINE_LIMITS.items()}})

@app.route("/api/settings/offline-detection", methods=["POST"])
def api_set_offline_detection():
    """Body {offline_retries 0-5, offline_retry_delay_sec 1-30, offline_confirm_polls 1-10}. A device is called
    OFFLINE only after every re-check failed AND that happened on `offline_confirm_polls` polls in a row."""
    err = _require_admin()
    if err: return err
    b = request.get_json(force=True) or {}
    clean = {}
    for key, (lo, hi) in sched._OFFLINE_LIMITS.items():
        try:
            n = int(b.get(key))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": f"{key} must be a whole number."}), 400
        if n < lo or n > hi:
            return jsonify({"ok": False, "error": f"{key} must be between {lo} and {hi}."}), 400
        clean[key] = n
    cfg = config_manager.get_config()
    cfg.setdefault("defaults", {}).update(clean)
    config_manager.save_config(cfg)
    db.audit_log(_email(), "set_offline_detection", "defaults", ", ".join(f"{k}={v}" for k, v in clean.items()))
    return jsonify({"ok": True, **clean})


# ── V11.2: apply-to-all helpers + endpoints ───────────────────────────────
def _is_site(device):
    return (device.get("method") or "") == "url"

def _resolve_targets(b):
    """V11.3 patch 06: which monitors a bulk 'apply' touches. Body is ONE of
       {ids: [...]}                      a hand-picked list: this device, or the current Devices-page search/filter
       {kind: 'type'|'method', key: ..}  every monitor of that device type / check method
       {scope: 'all'|'devices'|'sites'}  everything / everything except websites / websites only (V11.2 behaviour)
    Returns (devices, label) or raises ValueError with a message safe to show."""
    devs = config_manager.get_config().get("devices", [])
    ids = b.get("ids")
    if ids is not None:
        if not isinstance(ids, list) or not ids:
            raise ValueError("No monitors were selected.")
        want = {str(i) for i in ids}
        out = [d for d in devs if d["id"] in want]
        if not out:
            raise ValueError("None of the selected monitors exist any more.")
        return out, f"{len(out)} selected"
    kind = b.get("kind")
    if kind:
        key = str(b.get("key") or "").strip()
        if kind not in threshold_meta.SCOPE_KINDS or not key:
            raise ValueError("kind must be 'type' or 'method' and key must be given.")
        out = [d for d in devs if _in_scope(d, kind, key)]
        if not out:
            raise ValueError(f"No monitors have {kind} '{key}'.")
        return out, f"{kind}:{key}"
    scope = b.get("scope", "all")
    if scope not in ("all", "devices", "sites"):
        raise ValueError("scope must be 'all', 'devices' or 'sites'.")
    return _scope_devices(scope), scope


def _scope_devices(scope):
    """Devices matching scope: 'devices' (everything except websites), 'sites' (method url) or 'all'."""
    out = []
    for d in config_manager.get_config().get("devices", []):
        if scope == "all" or (scope == "sites") == _is_site(d):
            out.append(d)
    return out

def _save_notify_merged(device_id, ex, **changes):
    """Write a device's notify row back with `changes` applied and EVERYTHING else (emails, SMS/call numbers,
    escalation levels, other thresholds) preserved exactly as it was."""
    cur = dict(ex); cur.update(changes)
    db.set_device_notify(
        device_id,
        notifications_enabled   = cur.get("notifications_enabled", 1),
        notify_emails           = cur.get("notify_emails", []),
        escalation_emails_l1    = cur.get("escalation_emails_l1", []),
        escalation_emails_l2    = cur.get("escalation_emails_l2", []),
        escalation_emails_l3    = cur.get("escalation_emails_l3", []),
        escalation_after_sec_l1 = int(cur.get("escalation_after_sec_l1", 60)),
        escalation_after_sec_l2 = int(cur.get("escalation_after_sec_l2", 600)),
        escalation_after_sec_l3 = int(cur.get("escalation_after_sec_l3", 1200)),
        escalation_levels       = int(cur.get("escalation_levels", 1)),
        thresholds              = cur.get("thresholds", {}),
        alert_trigger_mode      = cur.get("alert_trigger_mode", "sustained"),
        alert_notify_mode       = cur.get("alert_notify_mode", "immediate"),
        notify_cooldown_sec     = int(cur.get("notify_cooldown_sec", 300)),
        sms_numbers_l1          = cur.get("sms_numbers_l1", []),
        sms_numbers_l2          = cur.get("sms_numbers_l2", []),
        sms_numbers_l3          = cur.get("sms_numbers_l3", []),
        call_numbers_l1         = cur.get("call_numbers_l1", []),
        call_numbers_l2         = cur.get("call_numbers_l2", []),
        call_numbers_l3         = cur.get("call_numbers_l3", []),
    )

@app.route("/api/settings/thresholds/apply", methods=["POST"])
@_batched
def api_apply_thresholds():
    """V11.2: Settings > Thresholds > 'Apply to all devices' / 'Apply to all sites'.
    Body {scope: 'devices'|'sites', thresholds: {metric: {enabled, warning, critical}}}.
    1) validates the values (same rules as every other save), 2) stores them as the GLOBAL values for that
    category's metrics, 3) removes the per-device warning/critical/enabled override of the metrics SENT from
    every device of that category, so they all use the new values. A per-metric 'wait_sec' is kept (it is a
    timing setting, not a threshold). Other categories' thresholds are not touched."""
    err = _require_admin()
    if err: return err
    b = request.get_json(force=True) or {}
    scope = b.get("scope")
    if scope not in ("devices", "sites"):
        return jsonify({"ok": False, "error": "scope must be 'devices' or 'sites'."}), 400
    metrics = list(threshold_meta.SITE_METRICS if scope == "sites" else threshold_meta.DEVICE_METRICS)
    incoming = b.get("thresholds") or {}
    if not isinstance(incoming, dict):
        return jsonify({"ok": False, "error": "Thresholds must be an object of metric settings."}), 400
    incoming = {k: v for k, v in incoming.items() if k in metrics}      # other category / unknown keys ignored
    clean, errs = threshold_meta.validate_thresholds(incoming)
    if errs:
        return jsonify({"ok": False, "error": errs[0], "errors": errs}), 400
    glob = dict(config_manager.get_config().get("global_thresholds") or {})
    for k in metrics:
        if k in clean:
            glob[k] = {kk: vv for kk, vv in clean[k].items() if kk != "wait_sec"}
    config_manager.update_global_thresholds(glob)
    touched = cleared = 0
    for d in _scope_devices(scope):
        ex  = db.get_device_notify(d["id"])
        thr = dict(ex.get("thresholds") or {})
        changed = False
        for k in clean:                      # only the metrics that were actually sent
            row = thr.get(k)
            if not isinstance(row, dict) or not any(f in row for f in ("warning", "critical", "enabled")):
                continue
            keep = {kk: vv for kk, vv in row.items() if kk == "wait_sec" and vv not in (None, "")}
            if keep: thr[k] = keep
            else:    thr.pop(k, None)
            changed = True; cleared += 1
        if changed:
            _save_notify_merged(d["id"], ex, thresholds=thr)
            touched += 1
    n = len(_scope_devices(scope))
    db.audit_log(_email(), "apply_thresholds_all", scope, f"{n} {scope}; {cleared} override(s) removed on {touched}")
    return jsonify({"ok": True, "count": n, "overrides_removed": cleared, "devices_changed": touched})

@app.route("/api/settings/notify-timing/apply", methods=["POST"])
@_batched
def api_apply_notify_timing():
    """V11.2: 'Apply wait & cooldown to all devices / only devices / only sites'.
    Body {scope: 'all'|'devices'|'sites', alert_trigger_mode, wait_sec, alert_notify_mode, notify_cooldown_sec}.
    Only these timing fields change; emails, SMS/call numbers, escalation levels and thresholds stay as they
    are. 'wait_sec' is the Level-1 delay used by 'Wait to confirm' mode; it is applied only in that mode, and
    it also removes per-metric 'wait_sec' overrides (otherwise they would silently win over the new value)."""
    err = _require_admin()
    if err: return err
    b = request.get_json(force=True) or {}
    try:
        devs, scope = _resolve_targets(b)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    trig = b.get("alert_trigger_mode", "sustained")
    mode = b.get("alert_notify_mode", "immediate")
    if trig not in ("immediate", "sustained"):
        return jsonify({"ok": False, "error": "Trigger mode must be 'immediate' or 'sustained'."}), 400
    if mode not in ("immediate", "cooldown"):
        return jsonify({"ok": False, "error": "Repeat-alert mode must be 'immediate' or 'cooldown'."}), 400
    def _int(name, lo, hi, default):
        raw = b.get(name, default)
        try:
            n = int(raw)
        except (TypeError, ValueError):
            raise ValueError(f"{name} must be a whole number.")
        if n < lo or n > hi:
            raise ValueError(f"{name} must be between {lo} and {hi}.")
        return n
    try:
        cooldown = _int("notify_cooldown_sec", 1, 604800, 300)
        wait     = _int("wait_sec", 1, 86400, 60) if trig == "sustained" else None
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    wait_overrides_cleared = 0
    for d in devs:
        ex = db.get_device_notify(d["id"])
        changes = {"alert_trigger_mode": trig, "alert_notify_mode": mode, "notify_cooldown_sec": cooldown}
        if wait is not None:
            changes["escalation_after_sec_l1"] = wait
            thr = {}
            for k, row in (ex.get("thresholds") or {}).items():
                if isinstance(row, dict) and "wait_sec" in row:
                    row = {kk: vv for kk, vv in row.items() if kk != "wait_sec"}
                    wait_overrides_cleared += 1
                    if not row: continue
                thr[k] = row
            changes["thresholds"] = thr
        _save_notify_merged(d["id"], ex, **changes)
    db.audit_log(_email(), "apply_notify_timing", scope,
                 f"{len(devs)} monitor(s): trigger={trig}, wait={wait}, repeat={mode}, cooldown={cooldown}")
    return jsonify({"ok": True, "count": len(devs), "scope": scope,
                    "wait_overrides_removed": wait_overrides_cleared})


@app.route("/api/devices/thresholds/apply", methods=["POST"])
@_batched
def api_apply_device_thresholds():
    """V11.3 patch 06: write threshold values as each chosen monitor's OWN override.
    Body {ids:[...] | kind+key | scope, thresholds: {metric: {enabled, warning, critical, wait_sec}}}.
    Used for 'this device' and 'the monitors in my current search/filter'. Only the metrics SENT are changed;
    a metric that does not apply to a monitor's check method is skipped for that monitor; every other threshold,
    email, SMS/call number and escalation setting stays as it is."""
    err = _require_admin()
    if err: return err
    b = request.get_json(force=True) or {}
    try:
        devs, label = _resolve_targets(b)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    incoming = b.get("thresholds") or {}
    if not isinstance(incoming, dict) or not incoming:
        return jsonify({"ok": False, "error": "Fill in at least one threshold row first."}), 400
    clean, errs = threshold_meta.validate_thresholds(incoming)
    if errs:
        return jsonify({"ok": False, "error": errs[0], "errors": errs}), 400
    changed = skipped = 0
    for d in devs:
        allowed = set(threshold_meta.metrics_for_method(d.get("method") or "ping"))
        mine = {k: v for k, v in clean.items() if k in allowed}
        if not mine:
            skipped += 1
            continue
        ex = db.get_device_notify(d["id"]); thr = dict(ex.get("thresholds") or {})
        for k, row in mine.items():
            new = dict(row)
            old = thr.get(k) if isinstance(thr.get(k), dict) else {}
            if "wait_sec" not in new and old.get("wait_sec") not in (None, ""):
                new["wait_sec"] = old["wait_sec"]
            thr[k] = new
        _save_notify_merged(d["id"], ex, thresholds=thr); changed += 1
    db.audit_log(_email(), "apply_device_thresholds", label,
                 f"{changed} monitor(s) changed, {skipped} skipped; metrics: {', '.join(sorted(clean))}")
    return jsonify({"ok": True, "count": changed, "skipped": skipped, "scope": label})


# ── notification templates (admin-editable, per alert state) ──────────────
@app.route("/api/settings/notification-templates", methods=["GET"])
def api_get_notification_templates():
    err = _require_admin()
    if err: return err
    result = {}
    for state in notification_templates.ALERT_STATES:
        eff = notification_templates.get_effective_template(state)
        result[state] = eff
    return jsonify({
        "templates":    result,
        "placeholders": notification_templates.all_placeholders(db.get_custom_placeholders()),
    })

@app.route("/api/settings/notification-templates/<state>", methods=["POST"])
def api_save_notification_template(state):
    err = _require_admin()
    if err: return err
    if state not in notification_templates.ALERT_STATES:
        return jsonify({"error": f"Unknown state '{state}'"}), 400
    b = request.get_json(force=True) or {}
    subject = b.get("subject_template", "")
    text    = b.get("text_template", "")
    html    = b.get("html_template", "")
    db.set_notification_template(
        state, subject, text, html,
        enabled=b.get("enabled", True),
        updated_by=_email(),
    )
    db.audit_log(_email(), "save_notification_template", state, "")
    custom_keys = [c["key"] for c in db.get_custom_placeholders()]
    return jsonify({
        "ok": True,
        "unknown_placeholders": {
            "subject": notification_templates.find_unknown_placeholders(subject, custom_keys),
            "text":    notification_templates.find_unknown_placeholders(text, custom_keys),
            "html":    notification_templates.find_unknown_placeholders(html, custom_keys),
        },
        "missing_required": {
            "subject": notification_templates.missing_required_placeholders(subject),
            "text":    notification_templates.missing_required_placeholders(text),
            "html":    notification_templates.missing_required_placeholders(html),
        },
    })

@app.route("/api/settings/notification-templates/<state>/reset", methods=["POST"])
def api_reset_notification_template(state):
    err = _require_admin()
    if err: return err
    if state not in notification_templates.ALERT_STATES:
        return jsonify({"error": f"Unknown state '{state}'"}), 400
    db.delete_notification_template(state)
    db.audit_log(_email(), "reset_notification_template", state, "")
    return jsonify({"ok": True, "template": notification_templates.get_effective_template(state)})

@app.route("/api/settings/notification-templates/<state>/preview", methods=["POST"])
def api_preview_notification_template(state):
    """Renders subject/text/html using sample data WITHOUT saving or
    sending anything -- lets an admin see the result of edits before
    committing to them."""
    err = _require_admin()
    if err: return err
    if state not in notification_templates.ALERT_STATES:
        return jsonify({"error": f"Unknown state '{state}'"}), 400
    b = request.get_json(force=True) or {}
    sample_context = {p["key"]: p["example"] for p in notification_templates.PLACEHOLDERS}
    sample_context["state"] = state
    sample_context["label"] = state.upper()
    # V8.4: custom placeholders resolve to their real configured value in
    # preview too (not left as a literal {{token}}) -- preview should
    # show exactly what an actual email would contain.
    sample_context.update(db.get_custom_placeholder_values())
    return jsonify({
        "subject": notification_templates.render(b.get("subject_template",""), sample_context),
        "text":    notification_templates.render(b.get("text_template",""),    sample_context),
        "html":    notification_templates.render(b.get("html_template",""),    sample_context),
    })


# ── custom notification placeholders (V8.4) ────────────────────────────────
@app.route("/api/settings/custom-placeholders", methods=["GET"])
def api_get_custom_placeholders():
    err = _require_admin()
    if err: return err
    return jsonify(db.get_custom_placeholders())

@app.route("/api/settings/custom-placeholders", methods=["POST"])
def api_add_custom_placeholder():
    """Creates a NEW custom placeholder. Rejects a key that already
    exists -- either as a built-in system placeholder or as an existing
    custom one -- so an admin can't silently shadow a built-in value or
    accidentally overwrite a different custom placeholder while thinking
    they're adding a new one. Use PUT on the same route to edit an
    existing custom placeholder's value/description instead."""
    err = _require_admin()
    if err: return err
    b = request.get_json(force=True) or {}
    key = (b.get("key") or "").strip()
    if not key:
        return jsonify({"error": "Placeholder key is required."}), 400
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9_]*$", key):
        return jsonify({"error": "Placeholder key must start with a letter and contain only letters, numbers, and underscores."}), 400
    if key in notification_templates.PLACEHOLDER_KEYS:
        return jsonify({"error": f'"{key}" is already a built-in placeholder — choose a different name.', "duplicate": True}), 409
    existing_keys = {c["key"] for c in db.get_custom_placeholders()}
    if key in existing_keys:
        return jsonify({"error": f'A custom placeholder named "{key}" already exists.', "duplicate": True}), 409
    db.set_custom_placeholder(key, b.get("value", ""), b.get("description", ""), updated_by=_email())
    db.audit_log(_email(), "add_custom_placeholder", key, "")
    return jsonify({"ok": True})

@app.route("/api/settings/custom-placeholders/<key>", methods=["PUT"])
def api_update_custom_placeholder(key):
    err = _require_admin()
    if err: return err
    existing_keys = {c["key"] for c in db.get_custom_placeholders()}
    if key not in existing_keys:
        return jsonify({"error": f'No custom placeholder named "{key}" exists.'}), 404
    b = request.get_json(force=True) or {}
    db.set_custom_placeholder(key, b.get("value", ""), b.get("description", ""), updated_by=_email())
    db.audit_log(_email(), "update_custom_placeholder", key, "")
    return jsonify({"ok": True})

@app.route("/api/settings/custom-placeholders/<key>", methods=["DELETE"])
def api_delete_custom_placeholder(key):
    err = _require_admin()
    if err: return err
    db.delete_custom_placeholder(key)
    db.audit_log(_email(), "delete_custom_placeholder", key, "")
    return jsonify({"ok": True})


# ── users ──────────────────────────────────────────────────────────────────
@app.route("/api/admin/users", methods=["GET"])
def api_get_users():
    err = _require_admin()
    if err: return err
    users = db.get_all_users()
    return jsonify([{"id":u["id"],"email":u["email"],"role":u["role"],"active":u["active"]} for u in users])

@app.route("/api/admin/users", methods=["POST"])
def api_add_user():
    err = _require_admin()
    if err: return err
    body  = request.get_json(force=True) or {}
    email = body.get("email","").strip().lower()
    role  = body.get("role","user")
    token = body.get("token","").strip()
    if not email or not token:
        return jsonify({"error": "email and token required"}), 400
    if len(token) < 8:
        return jsonify({"error": "Token must be 8+ characters"}), 400
    if role not in ("admin","supervisor","user"):
        return jsonify({"error": "Role must be admin, supervisor, or user"}), 400
    auth.add_user(email, role, token)
    db.audit_log(_email(),"add_user",email,f"role={role}")
    cfg      = config_manager.get_config()
    app_host = request.host or f"localhost:{APP_PORT}"
    sent, msg = config_manager.send_welcome_email(cfg["smtp"],email,role,token,app_host)
    return jsonify({"ok":True,"welcome_email_sent":sent,"welcome_email_msg":msg})

@app.route("/api/admin/users/<int:user_id>/email", methods=["PUT"])
def api_edit_user_email(user_id):
    err = _require_admin()
    if err: return err
    body = request.get_json(force=True) or {}
    new_email = body.get("email", "").strip().lower()
    if not new_email or "@" not in new_email:
        return jsonify({"error": "A valid email is required"}), 400
    users = db.get_all_users()
    target = next((u for u in users if u["id"] == user_id), None)
    if not target:
        return jsonify({"error": "User not found"}), 404
    old_email = target["email"]
    ok = db.update_user_email(user_id, new_email)
    if not ok:
        return jsonify({"error": "That email is already in use by another account"}), 409
    db.audit_log(_email(), "edit_user_email", old_email, f"-> {new_email}")
    return jsonify({"ok": True, "email": new_email})

@app.route("/api/admin/users/<path:email>/token", methods=["PUT"])
def api_reset_token(email):
    err = _require_admin()
    if err: return err
    body  = request.get_json(force=True) or {}
    token = body.get("token","").strip()
    if not token or len(token) < 8:
        return jsonify({"error": "Token must be 8+ characters"}), 400
    users = db.get_all_users()
    role  = next((u["role"] for u in users if u["email"]==email.lower()),"user")
    auth.add_user(email.lower(), role, token)
    db.audit_log(_email(),"reset_token",email,"")
    cfg = config_manager.get_config()
    sent, msg = config_manager.send_welcome_email(
        cfg["smtp"], email, role, token, request.host or f"localhost:{APP_PORT}"
    )
    return jsonify({"ok":True,"welcome_email_sent":sent,"welcome_email_msg":msg})

@app.route("/api/admin/users/<path:email>", methods=["DELETE"])
def api_delete_user(email):
    err = _require_admin()
    if err: return err
    db.delete_user(email.lower())
    db.audit_log(_email(),"delete_user",email,"")
    return jsonify({"ok": True})

@app.route("/api/admin/generate-token")
def api_gen_token():
    err = _require_admin()
    if err: return err
    return jsonify({"token": auth.generate_token()})

@app.route("/api/admin/email-groups")
def api_email_groups():
    err = _require_admin()
    if err: return err
    users  = db.get_all_users()
    emails = [u["email"] for u in users if u.get("active",1)]
    cfg    = config_manager.get_config()
    smtp   = cfg.get("smtp",{})
    all_e  = list(dict.fromkeys(emails + smtp.get("admin_emails",[]) +
                                smtp.get("support_emails",[]) + smtp.get("manager_emails",[])))
    return jsonify({"all_emails":all_e,"admin_emails":smtp.get("admin_emails",[]),
                    "support_emails":smtp.get("support_emails",[]),"manager_emails":smtp.get("manager_emails",[])})


# ── configuration backup / restore (V8.4) ──────────────────────────────────
@app.route("/api/admin/config/export", methods=["GET"])
def api_config_export():
    """Downloads the full portable configuration -- devices, SMTP,
    notification templates, custom placeholders, escalation defaults,
    system settings, and (unless ?users=0) user accounts -- as a single
    JSON file. Deliberately excludes history/data (metric history, alert
    log, audit log, speed test/network scan history) and the server
    port/host, which are installation-specific, not configuration."""
    err = _require_admin()
    if err: return err
    include_users = request.args.get("users", "1") != "0"
    payload = {
        "export_format_version": 1,
        "app_version":           APP_VERSION,
        "exported_at":           time.time(),
        "exported_by":           _email(),
        "includes_users":        include_users,
        "config_yaml":           config_manager.export_yaml_config(),
        **db.export_config_tables(include_users=include_users),
    }
    db.audit_log(_email(), "export_config", "-", f"users={include_users}")
    fname = f"netmonit-config-backup-{time.strftime('%Y%m%d-%H%M%S')}.json"
    return Response(
        json.dumps(payload, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'}
    )

@app.route("/api/admin/config/import", methods=["POST"])
def api_config_import():
    """Restores configuration from a file previously produced by
    /api/admin/config/export. REPLACE semantics for devices/SMTP/
    templates/thresholds/etc; user accounts are UPSERTED rather than
    replaced (an imported user is added/updated, but an existing user
    not present in the file is never deleted) specifically so a restore
    can never lock out the admin currently performing it. The server's
    own port/host are never touched by a restore -- see
    config_manager.import_yaml_config()'s docstring."""
    err = _require_admin()
    if err: return err
    body = request.get_json(force=True) or {}
    data = body.get("data")
    if not isinstance(data, dict) or "export_format_version" not in data:
        return jsonify({"error": "This doesn't look like a Net-monit configuration export file."}), 400
    include_users = bool(body.get("include_users", True))
    try:
        if "config_yaml" in data:
            config_manager.import_yaml_config(data["config_yaml"])
        db.import_config_tables(data, include_users=include_users)
    except Exception as e:
        log.exception("Config import failed")
        return jsonify({"error": f"Import failed: {e}"}), 500
    sched.reload_scheduler(config_manager.get_config())
    db.audit_log(_email(), "import_config", "-",
                 f"from {data.get('exported_by','?')} @ {data.get('app_version','?')}, users={include_users}")
    device_count = len(data.get("config_yaml", {}).get("devices", []))
    return jsonify({"ok": True, "device_count": device_count})

@app.route("/api/audit")
def api_audit():
    err = _require_admin()
    if err: return err
    return jsonify(db.get_audit_log(int(request.args.get("limit",200))))


# ── license API ────────────────────────────────────────────────────────────
@app.route("/api/license/status")
def api_license_status():
    license_manager.refresh()
    return jsonify(license_manager.get_status_dict())

@app.route("/api/license/activate", methods=["POST"])
def api_license_activate():
    err = _require_admin()
    if err: return err
    body = request.get_json(force=True) or {}
    key  = body.get("license_key","").strip()
    if not key:
        return jsonify({"ok": False, "message": "License key is required"}), 400
    result = license_manager.activate(key)
    if result["ok"]:
        db.audit_log(_email(),"license_activate","","success")
    return jsonify(result), (200 if result["ok"] else 400)




# =============================================================================
# V7.2 NEW FEATURES: Speed Test | URL Monitor | Network Scan
# =============================================================================

# ── Page routes for new features ──────────────────────────────────────────
@app.route("/speedtest")
def speedtest_page():
    return render_template("speedtest.html", active="speedtest", version=APP_VERSION)

@app.route("/urlmonitor")
def sitesmonitor_page():
    if _is_view_only():
        return redirect("/")
    return render_template("urlmonitor.html", active="urlmonitor", version=APP_VERSION)

@app.route("/networkscan")
def networkscan_page():
    if _is_view_only():
        return redirect("/")
    return render_template("networkscan.html", active="networkscan", version=APP_VERSION)


# ── Speed Test API ────────────────────────────────────────────────────────
@app.route("/api/speedtest/run", methods=["POST"])
def api_speedtest_run():
    """Run an on-demand internet speed test FROM THIS SERVER (can take
    20-30s). Measures the server's own WAN connection -- every browser
    that triggers this sees the same download/upload numbers regardless
    of that browser's own connection, since the bandwidth test itself
    executes here, not in the browser. For a given end user's own
    connection, see /api/speedtest/submit-client-result below, which the
    "Test my connection" button in the UI uses instead."""
    from monitor.checkers.speedtest_check import check as speedtest_check
    import threading
    err = _require_login()
    if err: return err

    result = {}
    done   = threading.Event()
    def _run():
        # V10.4: an exception here used to vanish -- `result` stayed empty,
        # done was never set, and the caller waited the full 60s only to get
        # a misleading "Timeout" 504. Now the real reason is logged and
        # returned immediately.
        try:
            result.update(speedtest_check({}))
        except Exception as e:
            log.exception("Speed test (sync) failed")
            result.update({"reachable": False, "error": f"Speed test failed: {e}"})
        finally:
            done.set()
    threading.Thread(target=_run, daemon=True).start()
    done.wait(timeout=60)

    if not result:
        return jsonify({"reachable": False, "error": "Timeout waiting for speed test"}), 504

    result = _finish_speedtest_result(result)
    return jsonify(result)


def _finish_speedtest_result(result: dict, local_ip: str | None = None, email: str | None = None) -> dict:
    """Shared by the sync and async speed test routes: attach who/where,
    persist to history, audit-log. V10.1 -- pulled out so run-async below
    doesn't grow its own slightly-different copy of the same five lines.

    V10.3: local_ip/email are now optional pass-through params instead of
    always being re-derived here via _client_local_ip()/_email(). Both of
    those read flask.request (X-Forwarded-For/remote_addr) and
    flask.session respectively, which only exist on the thread that's
    actually handling the HTTP request. That's fine for /api/speedtest/run
    (sync), which calls this function from that real request thread. It is
    NOT fine for /api/speedtest/run-async below, which calls this from
    inside a plain threading.Thread -- Flask's request context is
    thread-local and does not follow a request into a manually spawned
    thread. Calling _client_local_ip()/_email() from there raised exactly
    "Working outside of request context", caught by run-async's own
    except-Exception and surfaced to the user as a failed test ("Request
    failed: Working outside of request context..."). Fix: read
    request/session ONCE on the real request thread, before the background
    thread starts, and hand the two plain strings in -- see
    api_speedtest_run_async.

    V10.4: defence in depth on top of that fix. _client_local_ip() and
    _email() now check has_request_context() and return "" / "system"
    off the request thread instead of raising, so even a future caller that
    forgets to pass local_ip/email from a background thread gets a blank
    IP / "system" actor rather than a failed test. This function itself
    still never needs Flask if both params are supplied.
    """
    # V8.6: who clicked the button, and from where -- distinct from the
    # download/upload/public_ip numbers above, which describe the SERVER's
    # connection regardless of who triggered the test.
    if local_ip is None:
        local_ip = _client_local_ip()
    result["local_ip"]    = local_ip
    result["hostname"]    = _client_hostname(local_ip)
    result["test_source"] = "server"
    db.record_speedtest(result)
    if result.get("reachable"):
        if email is None:
            email = _email()
        def _mbps(v):
            return "n/a" if v is None else v
        db.audit_log(email, "speedtest", "internet",
                     f"DL={_mbps(result.get('download_mbps'))} UL={_mbps(result.get('upload_mbps'))} "
                     f"via {result.get('server') or result.get('method_used') or '?'}")
    return result


@app.route("/api/speedtest/run-async", methods=["POST"])
def api_speedtest_run_async():
    """V10.1: job + polling version of /api/speedtest/run above, for a
    speedometer that actually moves with real samples during the ~15s test
    instead of a hardcoded elapsed-time sweep. Mirrors /api/networkscan/scan's
    threading.Thread + job-row pattern; the one thing network scan doesn't
    need that this does is progress -- see speedtest_check.check()'s
    progress_cb, which this is what finally calls it with a real callback."""
    from monitor.checkers.speedtest_check import check as speedtest_check
    import threading
    err = _require_login()
    if err: return err

    # V10.3: read everything flask.request/session-bound HERE, on the real
    # request thread -- see _finish_speedtest_result's docstring. Neither
    # is safe to read from inside _run() below.
    local_ip = _client_local_ip()
    email    = _email()

    job_id = db.create_speedtest_job()

    job_info = {}          # engine / target / rtt_ms, as the checker learns them -- shown by the page

    def _on_progress(phase, mbps, elapsed):
        # V10.4: progress reporting is best-effort. This runs on the
        # checker's sampler thread -- an exception here (e.g. a transient
        # "database is locked") would kill that thread and silently truncate
        # the sample series the final Mbps figure is computed from.
        # V10.7: mbps is None while an engine has no live speed to report
        # (the ping phase; speedtest-cli) -- the page then shows "measuring"
        # instead of a made-up number.
        try:
            db.update_speedtest_job(job_id, phase=phase,
                                    progress={"mbps": None if mbps is None else round(mbps, 2),
                                              "elapsed_sec": elapsed, **job_info})
        except Exception:
            log.debug("Speed test job %s: progress update skipped", job_id, exc_info=True)

    def _on_info(info):
        try:
            job_info.update({k: info[k] for k in ("engine", "target", "rtt_ms") if k in info})
            db.update_speedtest_job(job_id, progress={"mbps": None, "elapsed_sec": 0, **job_info})
        except Exception:
            log.debug("Speed test job %s: info update skipped", job_id, exc_info=True)

    def _store_final(status, result):
        # V10.4: the final status write is what the browser is waiting for --
        # retry once so a single transient DB hiccup can't leave the job
        # "running" forever (the UI also has its own overall time limit).
        for attempt in (1, 2):
            try:
                db.update_speedtest_job(job_id, status=status, result=result)
                return
            except Exception:
                log.exception("Speed test job %s: could not store final status %r (attempt %d)",
                              job_id, status, attempt)
                time.sleep(0.5)

    def _run():
        # Step 1 -- the measurement. Only a failure HERE is a failed test.
        try:
            db.update_speedtest_job(job_id, status="running")
            result = speedtest_check({}, progress_cb=_on_progress, info_cb=_on_info)
        except Exception as e:
            log.exception("Speed test job %s failed", job_id)
            _store_final("error", {"error": str(e)})
            return
        # Step 2 -- attach who/where, save to history, audit-log. The Mbps
        # figures already exist by now; a hiccup in this bookkeeping (history
        # write, audit write, reverse DNS) must not turn a good measurement
        # into "Request failed" -- it is logged and flagged, not fatal.
        try:
            result = _finish_speedtest_result(result, local_ip=local_ip, email=email)
        except Exception:
            log.exception("Speed test job %s: measured OK but saving/annotating the result failed", job_id)
            result.setdefault("local_ip", local_ip)
            result.setdefault("test_source", "server")
            result["warning"] = "Measured OK, but the result could not be saved to history."
        _store_final("done", result)
    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"job_id": job_id, "status": "started"})


@app.route("/api/speedtest/status/<int:job_id>")
def api_speedtest_status(job_id):
    """Poll speed test job status -- same shape as /api/networkscan/status."""
    err = _require_login()
    if err: return err
    job = db.get_speedtest_job(job_id)
    if not job:
        return jsonify({"error": "Speed test job not found"}), 404
    return jsonify(job)


def _lookup_isp_for_ip(ip, timeout=3.0):
    """
    Best-effort ISP / organisation name for a PUBLIC IP -- fills the ISP column for PC (browser)
    tests, which used to show "--" because only the server-side test looked it up. The IP comes
    from the browser, so it is validated as a real, globally routable address before it goes
    anywhere near a URL.
    """
    try:
        import ipaddress, urllib.request
        addr = ipaddress.ip_address(str(ip).strip())
        if not addr.is_global:
            return ""
        req = urllib.request.Request(f"https://ipapi.co/{addr}/json/",
                                     headers={"User-Agent": f"netmonit/{APP_VERSION}"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            info = json.loads(r.read().decode("utf-8", "replace"))
        return str(info.get("org") or info.get("asn") or "")[:120]
    except Exception:
        return ""


@app.route("/api/speedtest/submit-client-result", methods=["POST"])
def api_speedtest_submit_client_result():
    """
    V8.6. Receives a speed test result the BROWSER already measured
    itself (download/upload/latency against Cloudflare's public speed
    test endpoints, run client-side -- see speedtest.html) and records
    it, attaching the actual requesting machine's local IP (as seen by
    this server -- e.g. 192.168.6.7, even though Net-monit itself might
    be hosted at 192.168.1.100) and a best-effort hostname.

    This is the route that makes "the speed we're getting differs per
    PC" actually mean something: the numbers in the request body were
    measured IN that PC's own browser, against the public internet, not
    computed here -- this route's job is only to attach who/where and
    persist the result, not to re-measure anything.
    """
    err = _require_login()
    if err: return err
    body = request.get_json(force=True) or {}

    # V10.7: every number is checked, not just the two speeds. Python's JSON parser accepts NaN and
    # Infinity, and latency/jitter/elapsed used to be stored exactly as sent, so one hand-made request
    # could put junk in the history. 0..100000 also rejects NaN (every comparison with NaN is False).
    for k in ("download_mbps", "upload_mbps", "latency_ms", "jitter_ms", "elapsed_sec"):
        if k in body and body[k] is not None:
            try:
                v = float(body[k])
            except (TypeError, ValueError):
                return jsonify({"error": f"Invalid value for {k}"}), 400
            if not (0 <= v <= 100000):
                return jsonify({"error": f"Invalid value for {k}"}), 400
            body[k] = v

    local_ip = _client_local_ip()
    result = {
        "reachable":     bool(body.get("reachable", True)),
        "download_mbps": body.get("download_mbps"),
        "upload_mbps":   body.get("upload_mbps"),
        "latency_ms":    body.get("latency_ms"),
        "jitter_ms":     body.get("jitter_ms"),
        "isp":           str(body.get("isp") or "")[:120],
        # The end user's OWN public IP, fetched by their OWN browser
        # directly from a public IP-echo service -- not this server's
        # public IP, and not proxied through this server either (that
        # would just show the server's public IP again).
        "public_ip":     str(body.get("public_ip") or "")[:64],
        "server":        str(body.get("server") or "Cloudflare (browser)")[:120],
        "method_used":   "browser",
        "elapsed_sec":   body.get("elapsed_sec"),
        "local_ip":      local_ip,
        "hostname":      _client_hostname(local_ip),
        "test_source":   "client",
    }
    if not result["isp"] and result["public_ip"]:
        result["isp"] = _lookup_isp_for_ip(result["public_ip"])      # V10.7: PC tests used to show "--"
    db.record_speedtest(result)
    db.audit_log(_email(), "speedtest_client", local_ip or "unknown",
                 f"DL={result['download_mbps']} UL={result['upload_mbps']} host={result['hostname'] or '?'}")
    return jsonify({"ok": True, **result})


@app.route("/api/speedtest/history")
def api_speedtest_history():
    # Public history - login only needed to run new tests
    limit = int(request.args.get("limit", 50))
    return jsonify(db.get_speedtest_history(limit))


@app.route("/api/speedtest/history", methods=["DELETE"])
def api_speedtest_clear_history():
    """Purge all speed test history (Admin only)."""
    err = _require_admin()
    if err: return err
    db.clear_speedtest_history()
    db.audit_log(_email(), "speedtest_purge", "internet", "history cleared")
    return jsonify({"ok": True})


# ── URL Monitor API ───────────────────────────────────────────────────────
@app.route("/api/urlmonitor/check", methods=["POST"])
def api_urlmonitor_check():
    """On-demand URL check. Public endpoint - no login required for quick checks."""
    from monitor.checkers.url_check import check as url_check
    # Public endpoint - anyone can check a URL
    body   = request.get_json(force=True) or {}
    device = {"host": body.get("url",""), "url_config": body.get("config",{})}
    if not device["host"]:
        return jsonify({"error": "url is required"}), 400
    result = url_check(device)
    if not result.get("reachable"):
        import time as _time
        _time.sleep(2)
        result = url_check(device)
    return jsonify(result)


@app.route("/api/urlmonitor/results")
def api_urlmonitor_results():
    """Get latest status + saved configuration for all URL-monitored devices."""
    err = _require_login()
    if err: return err
    rows = db.get_all_device_status()
    cfg  = config_manager.get_config()
    cfg_by_id = {d["id"]: d for d in cfg.get("devices", [])}

    url_rows = [
        dict(r) for r in rows
        if (r.get("method") or "") == "url"
    ]
    for r in url_rows:
        r["metrics"] = __import__("json").loads(r.pop("metrics_json") or "{}")
        saved = cfg_by_id.get(r["device_id"], {})
        r["url_config"] = saved.get("url_config", {})
        r["poll_interval_seconds"] = saved.get("poll_interval_seconds", 60)
        # V11.3 patch 02: colour the Sites table with the SAME thresholds the alert engine uses
        try:
            eff = alerts_engine.effective_thresholds({**saved, "id": r["device_id"]}, config_manager.effective_global_thresholds(),
                                              db.get_device_notify(r["device_id"]), config_manager.effective_scoped_thresholds())
            for mk, rk in (("ssl_days_left", "ssl_state"), ("response_ms", "response_state")):
                if r["metrics"].get(mk) is not None:
                    r[rk] = alerts_engine.evaluate_metric_state(r["metrics"][mk], eff.get(mk))
        except Exception as exc:                      # the page still works with its fallback colours
            app.logger.warning("Sites row state for %s failed: %s", r.get("device_id"), exc)

    # Also include configured URL devices that haven't reported status yet
    polled_ids = {r["device_id"] for r in url_rows}
    for d in cfg.get("devices", []):
        if d.get("method") == "url" and d["id"] not in polled_ids:
            url_rows.append({
                "device_id": d["id"], "name": d["name"], "host": d.get("host",""),
                "status": "unknown", "last_checked": None, "metrics": {},
                "url_config": d.get("url_config", {}),
                "poll_interval_seconds": d.get("poll_interval_seconds", 60),
            })

    return jsonify(url_rows)


# ── Network Scan API ──────────────────────────────────────────────────────
@app.route("/api/networkscan/detect-subnets")
def api_networkscan_detect():
    """Detect local subnets from network interfaces."""
    from monitor.checkers.network_scan import get_local_subnets
    err = _require_login()
    if err: return err
    return jsonify({"subnets": get_local_subnets()})


@app.route("/api/networkscan/scan", methods=["POST"])
def api_networkscan_scan():
    """
    Scan a subnet. Body: {subnet, port_scan, udp_scan, max_workers}
    This can take 10-60s for a /24 subnet.
    Runs in background; poll /api/networkscan/status for progress.
    """
    from monitor.checkers.network_scan import scan_subnet
    err = _require_admin()
    if err: return err
    body       = request.get_json(force=True) or {}
    subnet     = body.get("subnet","").strip()
    port_scan  = bool(body.get("port_scan", True))
    udp_scan   = body.get("udp_scan")                   # V10.7: None = follow port_scan
    udp_scan   = None if udp_scan is None else bool(udp_scan)
    max_workers= int(body.get("max_workers", 64))

    if not subnet:
        return jsonify({"error": "subnet is required (e.g. 192.168.1.0/24)"}), 400

    # Safely pull user context string BEFORE leaving the HTTP request lifecycle
    user_email = _email()

    scan_id = db.create_scan_job(subnet)
    import threading
    def _run():
        try:
            db.update_scan_job(scan_id, "running", None)
            result = scan_subnet(subnet, port_scan=port_scan,
                                 max_workers=max_workers, udp_scan=udp_scan)
            db.update_scan_job(scan_id, "done", result)
            db.audit_log(user_email, "network_scan", subnet,
                         f"found={result.get('hosts_alive',0)}")
        except Exception as e:
            db.update_scan_job(scan_id, "error", {"error": str(e)})
    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"scan_id": scan_id, "status": "started",
                    "subnet": subnet})


@app.route("/api/networkscan/status/<int:scan_id>")
def api_networkscan_status(scan_id):
    """Poll scan job status."""
    err = _require_login()
    if err: return err
    job = db.get_scan_job(scan_id)
    if not job:
        return jsonify({"error": "Scan job not found"}), 404
    return jsonify(job)


@app.route("/api/networkscan/history")
def api_networkscan_history():
    """List recent scan jobs."""
    err = _require_login()
    if err: return err
    return jsonify(db.get_scan_history(int(request.args.get("limit",20))))


@app.route("/api/networkscan/add-devices", methods=["POST"])
def api_networkscan_add_devices():
    """Add discovered hosts as ping-monitored devices."""
    err = _require_admin()
    if err: return err
    body    = request.get_json(force=True) or {}
    hosts   = body.get("hosts", [])
    added   = 0
    cfg     = config_manager.get_config()
    existing_ids   = {d["id"] for d in cfg.get("devices",[])}
    existing_hosts = {d["host"] for d in cfg.get("devices",[])}
    for h in hosts:
        ip   = h.get("ip","").strip()
        name = h.get("name") or h.get("hostname") or ip
        if not ip or ip in existing_hosts:
            continue
        dev_id = f"scan_{ip.replace('.','_')}"
        if dev_id in existing_ids:
            continue
        device = {
            "id":     dev_id,
            "name":   name,
            "type":   "network",
            "method": h.get("method","ping"),
            "host":   ip,
            "poll_interval_seconds": 60,
        }
        config_manager.add_or_update_device(device)
        added += 1
    if added:
        sched.reload_scheduler(config_manager.get_config())
        db.audit_log(_email(), "scan_add_devices", f"{added} devices", "")
    return jsonify({"ok": True, "added": added})


# ── startup ────────────────────────────────────────────────────────────────
def initialize():
    db.init_db()
    auth.seed_default_admin_if_empty()
    license_manager.refresh()
    cfg = config_manager.load_config()
    sched.start_scheduler(cfg)
    state = license_manager.state
    log.info("Net-monit V%s  port=%s  platform=%s  license=%s  devices=%d",
             APP_VERSION, APP_PORT, platform.system(), state,
             len(cfg.get("devices",[])))
    log.info("Dashboard: http://0.0.0.0:%s", APP_PORT)
    if state == "trial":
        log.info("TRIAL: %d days remaining. Get free key: abuabdullah.be@outlook.com",
                 license_manager.trial_days_remaining)

if __name__ == "__main__":
    initialize()
    ssl_ctx = None
    if SSL_CERT and SSL_KEY and os.path.isfile(SSL_CERT) and os.path.isfile(SSL_KEY):
        import ssl
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(SSL_CERT, SSL_KEY)
        log.info("HTTPS enabled: cert=%s", SSL_CERT)
    app.run(host="0.0.0.0", port=APP_PORT, debug=False,
            use_reloader=False, ssl_context=ssl_ctx)