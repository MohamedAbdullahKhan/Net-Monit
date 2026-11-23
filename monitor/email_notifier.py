# =============================================================================
# Net-monit V12.4
# Copyright (c) 2024-2026 Abdullah. All rights reserved.
# Contact: abuabdullah.be@outlook.com
# Unauthorised copying, modification or distribution of this software
# is strictly prohibited without prior written permission from the author.
# =============================================================================
"""
email_notifier.py  —  Net-monit V12.4
Multi-level escalation + default admin/support CC on all alerts.

Routing rules:
  To  : per-device notify_emails  (falls back to global admin_emails)
  Cc  : support_emails always on warning+
        manager_emails on critical
        admin_emails CC'd on EVERY alert (default always-in-loop)
        + escalation emails added when their level fires
"""
import smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from monitor import database as db
from monitor import notification_templates
from monitor import threshold_meta

# Keep this in sync with APP_VERSION in app.py on every release -- this is
# a separate, standalone module (no import of app.py, to avoid a circular
# import: app.py imports this module, not the other way around), so it
# has to be updated here too, or it silently goes stale in every email
# even after the rest of the app has moved on to a newer version.
APP_VERSION = "12.4"

# Fallback only -- used if no one has ever loaded a page in this app yet
# (so app.py's before_request hook hasn't had a chance to record anything).
# In every normal situation, _portal_url() below returns the address the
# admin/user most recently actually accessed the app with instead.
_FALLBACK_PORTAL_URL = "http://localhost:5050"


def _portal_url() -> str:
    """
    Dashboard link used in alert/recovered emails. Automatically matches
    however people are actually reaching this server -- PC name or IP --
    the exact same way the "Account Created" welcome email already does
    (both ultimately come from request.host, Flask's own record of what
    the browser put in its request). The difference is *when* that value
    is available: the welcome email sends from inside an active HTTP
    request, so it can read request.host directly; alert emails send from
    a background scheduler thread with no HTTP request happening at all,
    so app.py's before_request hook persists the most recent request.host
    it saw (key "last_known_host") for this function to read back here.
    """
    try:
        host = db.get_system_setting("last_known_host")
    except Exception:
        host = None
    return f"http://{host}" if host else _FALLBACK_PORTAL_URL

STATE_COLORS = {"warning":"#F2B84B","critical":"#FF5C5C","recovered":"#3DD68C","offline":"#888888"}
STATE_LABELS = {"warning":"WARNING","critical":"CRITICAL","recovered":"RECOVERED","offline":"OFFLINE"}
STATE_BG     = {"warning":"#2A2000","critical":"#280000","recovered":"#002010","offline":"#1A1A1A"}
ESC_COLORS   = {1:"#F2B84B", 2:"#FF8C00", 3:"#FF5C5C"}
ESC_LABELS   = {1:"ESCALATION L1", 2:"ESCALATION L2", 3:"ESCALATION L3"}


def _dedup(lst):
    seen = set()
    return [x for x in lst if x and not (x in seen or seen.add(x))]


def _pick_recipients(smtp_cfg, device_notify, state, recovered_from=None):
    """
    Returns (to_list, cc_list).
    Admin emails are ALWAYS CC'd (default always-in-loop behaviour).
    Support is CC on warning+.
    Managers CC on critical.
    Escalation emails added per active level.
    """
    admins   = smtp_cfg.get("admin_emails") or smtp_cfg.get("to_addresses", [])
    managers = smtp_cfg.get("manager_emails", [])
    support  = smtp_cfg.get("support_emails", [])

    dn = device_notify or {}
    dev_to       = dn.get("notify_emails", []) or admins
    esc_l1_emails= dn.get("escalation_emails_l1", dn.get("escalation_emails", []))
    esc_l2_emails= dn.get("escalation_emails_l2", [])
    esc_l3_emails= dn.get("escalation_emails_l3", [])
    fired_level  = int(dn.get("escalation_level_fired", 0))

    eff = recovered_from if state == "recovered" else state

    to_list = _dedup(dev_to)

    # Build CC: always include admins (default always-in-loop)
    cc_list = _dedup(support + admins)
    if eff == "critical":
        cc_list = _dedup(cc_list + managers)

    # Add escalation emails for fired level (and all lower levels already CC'd)
    if fired_level >= 1:
        cc_list = _dedup(cc_list + esc_l1_emails)
    if fired_level >= 2:
        cc_list = _dedup(cc_list + esc_l2_emails)
    if fired_level >= 3:
        cc_list = _dedup(cc_list + esc_l3_emails)

    # Remove anyone already in To from Cc
    cc_list = [e for e in cc_list if e not in to_list]
    return to_list, cc_list


def send_alert_email(smtp_cfg, device_name, device_host, metric, value,
                     state, threshold=None, recovered_from=None,
                     device_notify=None):
    if not smtp_cfg.get("enabled", False):
        return False, "Email alerts disabled"

    to_list, cc_list = _pick_recipients(smtp_cfg, device_notify, state, recovered_from)
    if not to_list:
        return False, "No recipients configured"

    dn           = device_notify or {}
    fired_level  = int(dn.get("escalation_level_fired", 0))
    is_esc       = fired_level > 0

    label  = ESC_LABELS.get(fired_level, STATE_LABELS.get(state, state.upper())) if is_esc else STATE_LABELS.get(state, state.upper())
    color  = ESC_COLORS.get(fired_level, STATE_COLORS.get(state, "#888888")) if is_esc else STATE_COLORS.get(state, "#888888")
    bg     = STATE_BG.get(state, "#12161F")
    ts     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    val_str= f"{value:.1f}" if isinstance(value, (int, float)) else str(value)
    thr_str= threshold_meta.format_threshold(metric, threshold) if threshold is not None else "\u2014"
    portal_url = _portal_url()

    esc_banner_html = ""
    if is_esc:
        esc_banner_html = f"""<div style="background:#3A1500;border:1px solid {color};border-radius:6px;padding:10px 14px;margin-bottom:14px;">
  <span style="color:{color};font-weight:700;font-size:12px;">\u26a1 ESCALATION LEVEL {fired_level}</span>
  <span style="color:#aaa;font-size:12px;margin-left:10px;">Alert has been active and unresolved \u2014 escalated to level {fired_level} recipients.</span>
</div>"""

    # Every value a template placeholder can reference. See
    # monitor/notification_templates.py::PLACEHOLDERS for the full,
    # documented list shown in the Settings UI.
    context = {
        "device_name":            device_name,
        "device_host":            device_host,
        "metric":                 metric,
        "metric_label":           threshold_meta.label_with_unit(metric),
        "value":                  val_str,
        "threshold":              thr_str,
        "state":                  state,
        "label":                  label,
        "color":                  color,
        "bg":                     bg,
        "timestamp":              ts,
        "portal_url":             portal_url,
        "app_version":            APP_VERSION,
        "escalation_level":       str(fired_level),
        "escalation_banner_html": esc_banner_html,
    }
    # V8.4: admin-defined custom placeholders (e.g. {{company_name}}).
    # Merged in after the built-ins above so a custom placeholder can
    # never accidentally override a system one -- app.py's add-route
    # already rejects creating a custom placeholder with a name that
    # collides with a built-in, but this ordering is a second, cheap
    # guarantee of the same invariant at render time.
    context = {**db.get_custom_placeholder_values(), **context}

    tmpl = notification_templates.get_effective_template(state)
    subject = notification_templates.render(tmpl["subject_template"], context)
    text    = notification_templates.render(tmpl["text_template"],    context)
    html    = notification_templates.render(tmpl["html_template"],    context)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = smtp_cfg.get("from_address") or smtp_cfg.get("username", "")
    msg["To"]      = ", ".join(to_list)
    if cc_list:
        msg["Cc"]  = ", ".join(cc_list)
    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))

    all_rcpt = _dedup(to_list + cc_list)
    try:
        if smtp_cfg.get("use_tls", True):
            ctx = ssl.create_default_context()
            with smtplib.SMTP(smtp_cfg["host"], smtp_cfg["port"], timeout=15) as s:
                s.starttls(context=ctx)
                s.login(smtp_cfg["username"], smtp_cfg["password"])
                s.sendmail(msg["From"], all_rcpt, msg.as_string())
        else:
            with smtplib.SMTP_SSL(smtp_cfg["host"], smtp_cfg["port"], timeout=15) as s:
                s.login(smtp_cfg["username"], smtp_cfg["password"])
                s.sendmail(msg["From"], all_rcpt, msg.as_string())
        return True, "Sent"
    except Exception as exc:
        return False, str(exc)


def send_token_reset_otp_email(smtp_cfg: dict, to_email: str, otp: str):
    """
    V10.0: sends a 6-digit one-time code, entered back into the app,
    rather than a clickable link -- see auth.py's stage 1-3 docstrings
    for the full flow this is step 1 of. Same SMTP connection pattern
    (TLS/SSL branch, timeout, error handling) as send_alert_email() for
    consistency. Returns (ok: bool, error: str).
    """
    if not smtp_cfg or not smtp_cfg.get("enabled"):
        return False, "SMTP is not configured"
    subject = "Your Net-monit verification code"
    text = (
        f"A token reset was requested for this email address.\n\n"
        f"Your verification code is: {otp}\n\n"
        f"Enter this code in Net-monit within 10 minutes to continue.\n\n"
        f"If you didn't request this, you can safely ignore this email -- "
        f"your existing token stays valid and this code will simply expire unused."
    )
    html = f"""<html><body style="font-family:sans-serif;color:#1a1a1a;">
      <p>A token reset was requested for this email address.</p>
      <p style="font-size:13px;color:#444;">Your verification code:</p>
      <p style="font-size:32px;font-weight:700;letter-spacing:6px;font-family:monospace;
         background:#f4f4f5;padding:14px 20px;border-radius:8px;display:inline-block;">{otp}</p>
      <p style="font-size:12px;color:#666;">This code expires in 10 minutes and can only be used once.
      If you didn't request this, you can safely ignore this email -- your existing token stays valid.</p>
      </body></html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = smtp_cfg.get("from_address") or smtp_cfg.get("username", "")
    msg["To"]      = to_email
    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))

    try:
        if smtp_cfg.get("use_tls", True):
            ctx = ssl.create_default_context()
            with smtplib.SMTP(smtp_cfg["host"], smtp_cfg["port"], timeout=15) as s:
                s.starttls(context=ctx)
                s.login(smtp_cfg["username"], smtp_cfg["password"])
                s.sendmail(msg["From"], [to_email], msg.as_string())
        else:
            with smtplib.SMTP_SSL(smtp_cfg["host"], smtp_cfg["port"], timeout=15) as s:
                s.login(smtp_cfg["username"], smtp_cfg["password"])
                s.sendmail(msg["From"], [to_email], msg.as_string())
        return True, "Sent"
    except Exception as exc:
        return False, str(exc)
