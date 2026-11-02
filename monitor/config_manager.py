# =============================================================================
# Net-monit V11.3
# Copyright (c) 2024-2026 Abdullah. All rights reserved.
# Contact: abuabdullah.be@outlook.com
# Unauthorised copying, modification or distribution of this software
# is strictly prohibited without prior written permission from the author.
# =============================================================================
"""
config_manager.py — Net-monit V11.3
Loads config.yaml into memory; writes back on UI changes.
Fix (V4.0 from V3.5): _save_config was missing (caused 500 on save notifications/thresholds/escalation).
"""
import os, threading, time, yaml
from pathlib import Path
from . import database as db
from . import crypto

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"
_lock   = threading.Lock()
_config = None


def load_config():
    global _config
    with _lock:
        _config = _load()
    return _config


def get_config():
    global _config
    if _config is None:
        return load_config()
    return _config


def _load():
    try:
        # utf-8-sig instead of utf-8: automatically strips a UTF-8 BOM
        # (Byte Order Mark) if the file has one, with zero effect if it
        # doesn't. A BOM is invisible in most editors but sits before the
        # very first real character in the file -- YAML parsers choke on
        # it, and it's a very common side effect of copy-pasting a YAML
        # file through Windows Notepad, some terminals, or certain
        # clipboard tools (e.g. moving config.yaml from a test server to
        # a production one by copy/paste rather than a raw file copy).
        with open(CONFIG_PATH, encoding="utf-8-sig") as f:
            raw = f.read()
    except FileNotFoundError:
        raw = ""

    try:
        cfg = yaml.safe_load(raw) or {}
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        loc  = f" (line {mark.line+1}, column {mark.column+1})" if mark else ""
        err_msg = "config.yaml YAML error" + loc + ": " + str(getattr(exc,"problem",exc))
        raise SystemExit(err_msg) from None

    if not isinstance(cfg, dict):
        raise SystemExit(
            "config.yaml is not structured correctly (parsed to a "
            f"{type(cfg).__name__}, expected a set of key: value settings "
            "at the top level). This usually means the file was only "
            "partially copied/pasted, or something else was pasted into "
            "it by mistake -- check the whole file starts with keys like "
            "'devices:' and 'smtp:' at the very left margin, with nothing "
            "else above them."
        )

    cfg.setdefault("defaults", {})
    cfg["defaults"].setdefault("poll_interval_seconds", 30)
    cfg["defaults"].setdefault("ping_timeout_ms", 1000)
    cfg["defaults"].setdefault("offline_retries", 2)               # V11.3 patch 03: re-check this many times before
    cfg["defaults"].setdefault("offline_retry_delay_sec", 3)       #   calling a device unreachable, this many seconds apart,
    cfg["defaults"].setdefault("offline_confirm_polls", 2)         #   and require this many polls in a row before OFFLINE
    cfg["defaults"].setdefault("thresholds", {})
    cfg.setdefault("devices", [])
    cfg.setdefault("smtp", {})

    # Sanitise from_address (must be single email)
    fa = str(cfg["smtp"].get("from_address") or "")
    if "," in fa:
        parts = [p.strip() for p in fa.split(",") if p.strip()]
        cfg["smtp"]["from_address"] = parts[0]
        extras = parts[1:]
        adm = cfg["smtp"].get("admin_emails") or cfg["smtp"].get("to_addresses", [])
        for e in extras:
            if e not in adm:
                adm.append(e)

    cfg["smtp"].setdefault("admin_emails",   cfg["smtp"].get("to_addresses", []))
    cfg["smtp"].setdefault("manager_emails", [])
    cfg["smtp"].setdefault("support_emails", [])

    # V8.5: smtp.password, sms_gateway.auth_pass, and call_gateway.auth_pass
    # are all encrypted at rest (see save_config()) -- decrypted once here,
    # centrally, so every consumer of get_config() just receives working
    # plaintext without each call site needing its own decrypt call.
    # is_encrypted() correctly leaves an already-plaintext value (e.g. the
    # env var override below, or a field that's simply empty) untouched.
    if cfg["smtp"].get("password") and crypto.is_encrypted(cfg["smtp"]["password"]):
        cfg["smtp"]["password"] = crypto.decrypt(cfg["smtp"]["password"])
    for gw_key in ("sms_gateway", "call_gateway"):
        gw = cfg.get(gw_key, {})
        if gw.get("auth_pass") and crypto.is_encrypted(gw["auth_pass"]):
            gw["auth_pass"] = crypto.decrypt(gw["auth_pass"])

    # Env-var password override
    env_pw = os.environ.get("NETMON_SMTP_PASSWORD")
    if env_pw:
        cfg["smtp"]["password"] = env_pw

    return cfg


def save_config(cfg):
    # V8.5: encrypt sensitive credential fields in the copy written to
    # disk, while the in-memory cache (_config, set below) stays
    # plaintext for actual use (SMTP login, gateway HTTP auth headers).
    # Centralized here rather than in each update_X() function so this
    # can't be forgotten by a future settings-update function -- ANY code
    # path that ends up calling save_config() with a plaintext
    # smtp.password / sms_gateway.auth_pass / call_gateway.auth_pass gets
    # it encrypted on the way to disk, no plaintext password touches disk
    # under any code path, current or future.
    #
    # Device credentials (cfg['devices'][*]) are NOT touched here -- they
    # arrive already encrypted, via crypto.encrypt_device_creds() called
    # from add_or_update_device() before save_config() is ever invoked
    # for a device change. Re-encrypting an already-encrypted value here
    # would be a silent no-op anyway (is_encrypted() guards it below),
    # but device creds are excluded from this loop entirely since their
    # structure (nested under ssh/powershell/snmp method blocks) doesn't
    # match the flat smtp/*_gateway shape this loop assumes.
    import copy
    disk_cfg = copy.deepcopy(cfg)
    smtp_pw = disk_cfg.get("smtp", {}).get("password")
    if smtp_pw and not crypto.is_encrypted(smtp_pw):
        disk_cfg["smtp"]["password"] = crypto.encrypt(smtp_pw)
    for gw_key in ("sms_gateway", "call_gateway"):
        gw_pw = disk_cfg.get(gw_key, {}).get("auth_pass")
        if gw_pw and not crypto.is_encrypted(gw_pw):
            disk_cfg[gw_key]["auth_pass"] = crypto.encrypt(gw_pw)

    # V11.3 patch 06: C-based dumper when available (same output, much faster with many devices) and an atomic
    # write (temp file + replace) so a crash or antivirus lock can never leave a half-written config.yaml.
    dumper = getattr(yaml, "CDumper", None) or yaml.Dumper
    tmp = str(CONFIG_PATH) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        yaml.dump(disk_cfg, f, Dumper=dumper, default_flow_style=False, allow_unicode=True, sort_keys=False)
    for attempt in range(5):
        try:
            os.replace(tmp, CONFIG_PATH)
            break
        except PermissionError:           # Windows: antivirus/indexer briefly holding the file
            if attempt == 4: raise
            time.sleep(0.05 * (attempt + 1))
    global _config
    with _lock:
        _config = cfg  # in-memory cache stays plaintext/decrypted

# Alias so internal calls using _save_config() work correctly
_save_config = save_config


def update_smtp(settings):
    cfg = get_config()
    smtp = cfg["smtp"]
    for k in ("enabled","host","port","use_tls","username","from_address",
              "admin_emails","manager_emails","support_emails",
              "resend_interval_minutes","to_addresses"):
        if k in settings:
            smtp[k] = settings[k]
    # V8.5: was plaintext, unconditionally. Now: a newly-submitted
    # password is stored plaintext IN MEMORY (matching every other field
    # here) -- save_config() above encrypts it transparently on the way
    # to disk. Blank/omitted means keep whatever's already there
    # (unchanged behavior), which save_config() will also encrypt
    # correctly regardless of why it's currently plaintext.
    if settings.get("password"):
        smtp["password"] = settings["password"]
    if "admin_emails" in settings:
        smtp["to_addresses"] = settings["admin_emails"]
    save_config(cfg)
    return cfg


# ============================================================
# V8.5: SMS / voice-call escalation gateways
# Config lives in config.yaml (not SQLite) alongside 'smtp' -- same
# consistency reasoning: this is a global outbound-notification-channel
# credential set, the same category of sensitivity/scope as SMTP.
# Unlike smtp.password (previously stored plaintext -- also fixed this
# session, see _load() below), auth_pass here was encrypted at rest from
# the start, via the crypto module already imported at the top of this
# file -- the same Fernet mechanism protecting device credentials.
# ============================================================
_GATEWAY_KEYS = ("enabled", "preset", "method", "url", "headers",
                  "body_template", "auth", "auth_user", "auth_pass")

def _default_gateway():
    return {"enabled": False, "preset": "custom", "method": "POST", "url": "",
            "headers": {}, "body_template": "", "auth": "none",
            "auth_user": "", "auth_pass": ""}

def get_sms_gateway() -> dict:
    cfg = get_config()
    return {**_default_gateway(), **cfg.get("sms_gateway", {})}

def get_call_gateway() -> dict:
    cfg = get_config()
    return {**_default_gateway(), **cfg.get("call_gateway", {})}

def update_sms_gateway(settings: dict):
    cfg = get_config()
    gw = {**_default_gateway(), **cfg.get("sms_gateway", {})}
    for k in _GATEWAY_KEYS:
        if k in settings:
            gw[k] = settings[k]
    # "blank means keep existing" -- same pattern as SMTP's password
    # field. Stored plaintext in memory here; save_config() encrypts it
    # transparently on the way to disk (see that function's docstring).
    if not settings.get("auth_pass"):
        gw["auth_pass"] = cfg.get("sms_gateway", {}).get("auth_pass", "")
    cfg["sms_gateway"] = gw
    save_config(cfg)
    return cfg

def update_call_gateway(settings: dict):
    cfg = get_config()
    gw = {**_default_gateway(), **cfg.get("call_gateway", {})}
    for k in _GATEWAY_KEYS:
        if k in settings:
            gw[k] = settings[k]
    if not settings.get("auth_pass"):
        gw["auth_pass"] = cfg.get("call_gateway", {}).get("auth_pass", "")
    cfg["call_gateway"] = gw
    save_config(cfg)
    return cfg


# ============================================================
# V8.5: organisation branding (Settings > Organisation)
# Small enough (two strings) to live in config.yaml directly rather than
# system_settings (SQLite) -- consistent with treating config.yaml as
# the place for "how this installation is set up" rather than data.
# ============================================================
def get_organisation() -> dict:
    cfg = get_config()
    return {"name": cfg.get("organisation", {}).get("name", ""),
            "logo_path": cfg.get("organisation", {}).get("logo_path", ""),
            "color": cfg.get("organisation", {}).get("color", "#8b95a5")}

def update_organisation(name: str = None, logo_path: str = None, color: str = None):
    cfg = get_config()
    org = cfg.get("organisation", {})
    if name is not None:
        org["name"] = name
    if logo_path is not None:
        org["logo_path"] = logo_path
    if color is not None:
        org["color"] = color
    cfg["organisation"] = org
    save_config(cfg)
    return cfg


def add_or_update_device(device):
    cfg = get_config()
    # Encrypt credentials before persisting to config.yaml
    device_to_save = crypto.encrypt_device_creds(device)
    devices = cfg.get("devices", [])
    idx = next((i for i, d in enumerate(devices) if d["id"] == device["id"]), None)
    if idx is not None:
        devices[idx] = device_to_save
    else:
        devices.append(device_to_save)
    cfg["devices"] = devices
    save_config(cfg)
    return cfg


def remove_device(device_id):
    cfg = get_config()
    cfg["devices"] = [d for d in cfg["devices"] if d["id"] != device_id]
    save_config(cfg)
    db.purge_device(device_id)
    return cfg


def send_welcome_email(smtp_cfg, to_email, role, token, app_host="localhost:5000"):
    """Send welcome email with login credentials to a newly created or updated user."""
    import smtplib, ssl
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    if not smtp_cfg.get("enabled"):
        return False, "SMTP not enabled"

    subject = "Your Net-monit Access Credentials"
    html = f"""<html><body style="font-family:Arial,sans-serif;background:#0B0E14;padding:24px;">
<div style="max-width:480px;margin:auto;background:#12161F;border:1px solid #232A36;border-radius:8px;overflow:hidden;">
  <div style="background:#4FD1C5;padding:14px 20px;color:#07221F;font-weight:700;font-size:15px;">
    Net-monit — Account Created
  </div>
  <div style="padding:22px;color:#E6E9EF;">
    <p style="margin:0 0 16px;">Your Net-monit account is ready. Sign in using the credentials below.</p>
    <table style="width:100%;font-size:14px;">
      <tr><td style="color:#8B93A3;padding:5px 0;width:80px;">Email</td>
          <td style="color:#E6E9EF;font-family:monospace;">{to_email}</td></tr>
      <tr><td style="color:#8B93A3;padding:5px 0;">Token</td>
          <td style="color:#4FD1C5;font-family:monospace;font-weight:700;">{token}</td></tr>
      <tr><td style="color:#8B93A3;padding:5px 0;">Role</td>
          <td style="color:#E6E9EF;">{role}</td></tr>
    </table>
    <div style="margin:16px 0;padding:12px;background:#0B0E14;border-radius:6px;">
      <p style="margin:0 0 6px;font-size:12px;color:#8B93A3;">Dashboard URL:</p>
      <a href="http://{app_host}" style="color:#4FD1C5;font-family:monospace;font-size:13px;">http://{app_host}</a>
    </div>
    <p style="color:#5B6472;font-size:12px;margin:0;">Keep your token secure — it is stored as a one-way hash and cannot be recovered.</p>
  </div>
</div></body></html>"""
    plain = "Net-monit Account\nEmail: " + to_email + "\nToken: " + token + "\nRole: " + role + "\nDashboard: http://" + app_host

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = smtp_cfg.get("from_address") or smtp_cfg.get("username","")
    msg["To"]      = to_email
    msg.attach(MIMEText(plain,"plain"))
    msg.attach(MIMEText(html,"html"))

    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP(smtp_cfg["host"], smtp_cfg.get("port",587), timeout=15) as s:
            if smtp_cfg.get("use_tls",True): s.starttls(context=ctx)
            if smtp_cfg.get("username"):     s.login(smtp_cfg["username"], smtp_cfg["password"])
            s.sendmail(msg["From"], [to_email], msg.as_string())
        return True, "Sent"
    except Exception as e:
        return False, str(e)


# ── V4.0 save helpers ────────────────────────────────────────────────
def update_notifications(settings: dict):
    cfg = get_config()
    cfg.setdefault("notifications", {}).update(settings)
    save_config(cfg)   # FIX: was _save_config(cfg) which was undefined


def update_global_thresholds(thresholds: dict):
    cfg = get_config()
    cfg["global_thresholds"] = thresholds
    save_config(cfg)   # FIX: was _save_config(cfg) which was undefined


def effective_scoped_thresholds(cfg=None):
    """{"type": {"firewall": {metric: {...}}}, "method": {"ssh": {...}}} -- thresholds that apply to every device of
    that TYPE / METHOD (Settings > Thresholds). Read from the live config on every call."""
    cfg = cfg if cfg is not None else get_config()
    raw = cfg.get("scoped_thresholds") or {}
    return {"type": dict(raw.get("type") or {}), "method": dict(raw.get("method") or {})}


def update_scoped_thresholds(kind, key, thresholds):
    """Replace ONE scope's thresholds; an empty dict removes the scope (its devices inherit again)."""
    cfg = get_config()
    sc = cfg.setdefault("scoped_thresholds", {})
    group = sc.setdefault(kind, {})
    if thresholds:
        group[key] = thresholds
    else:
        group.pop(key, None)
    save_config(cfg)


def effective_global_thresholds(cfg=None):
    """The global thresholds the ALERT ENGINE must use: Settings > Thresholds saves to cfg["global_thresholds"]
    (update_global_thresholds above); the legacy cfg["defaults"]["thresholds"] is kept as a base layer so old
    config files still work. Read it fresh from the live config on every call -- never from a stale copy.
    (Until V11.3 patch 02 the scheduler read ONLY the legacy key, so values saved in Settings never reached
    the live alert engine.)"""
    cfg = cfg if cfg is not None else get_config()
    merged = {}
    for src in ((cfg.get("defaults") or {}).get("thresholds"), cfg.get("global_thresholds")):
        for metric, row in (src or {}).items():
            merged[metric] = {**merged.get(metric, {}), **(row or {})}
    return merged


def update_escalation_defaults(defaults: dict):
    cfg = get_config()
    cfg["escalation_defaults"] = defaults
    save_config(cfg)   # FIX: was _save_config(cfg) which was undefined


# ============================================================
# V8.4: configuration export / import (Admin Panel > Backup & Restore)
# ============================================================
def export_yaml_config() -> dict:
    """Returns the portable subset of config.yaml for a configuration
    backup: devices (credentials still Fernet-encrypted, exactly as
    stored on disk -- see monitor/crypto.py), SMTP settings, and the
    various default/notification sections.

    Deliberately EXCLUDES the 'server' section (port/host) -- those are
    tied to *this specific installation*, not to the customer's
    configuration, and must never be silently overwritten by a restore
    (imagine restoring a V8.2 backup onto a V8.4 install and having your
    port revert to 5082 -- see CLAUDE.md's version/port convention for
    why that would break more than just the port)."""
    cfg = get_config()
    return {
        "devices":              cfg.get("devices", []),
        "smtp":                 cfg.get("smtp", {}),
        "defaults":             cfg.get("defaults", {}),
        "notifications":        cfg.get("notifications", {}),
        "global_thresholds":    cfg.get("global_thresholds", {}),
        "escalation_defaults":  cfg.get("escalation_defaults", {}),
    }


def import_yaml_config(data: dict):
    """Restores devices/SMTP/defaults/notifications/thresholds/escalation
    from a backup produced by export_yaml_config(). Devices are written
    back exactly as exported -- their credential fields are already
    Fernet-encrypted (that's what's actually stored in config.yaml), so
    this does NOT route through crypto.encrypt_device_creds() again,
    which would double-encrypt them and make them permanently
    undecryptable. The current installation's 'server' section
    (port/host) is always preserved, never overwritten -- see
    export_yaml_config()'s docstring for why."""
    cfg = get_config()
    for key in ("devices", "smtp", "defaults", "notifications",
                "global_thresholds", "escalation_defaults"):
        if key in data:
            cfg[key] = data[key]
    save_config(cfg)
    return cfg
