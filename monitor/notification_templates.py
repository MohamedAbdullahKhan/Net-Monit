# =============================================================================
# Net-monit V11.3
# Copyright (c) 2024-2026 Abdullah. All rights reserved.
# Contact: abuabdullah.be@outlook.com
# Unauthorised copying, modification or distribution of this software
# is strictly prohibited without prior written permission from the author.
# =============================================================================
"""
notification_templates.py -- Net-monit V8.2 (new)

Admin-editable notification email templates, one per alert state
(warning / critical / offline / recovered). An admin can customize the
subject, plain-text body, and HTML body for any state from
Settings -> Notification Templates. Any state left uncustomized keeps
using the built-in default below, so this whole feature is purely
additive: a fresh install, or any state nobody has touched, behaves
100% identically to how email_notifier.py worked before this file
existed.

PLACEHOLDER SYNTAX: {{placeholder_name}}  (double curly braces)

Double braces were chosen deliberately over single braces (Python's
usual str.format() style) because single braces collide with CSS: an
admin's custom HTML template writing a <style> block like
".foo { color: red; }" would otherwise be misread as a template
field and crash rendering. Double braces never collide with normal
HTML/CSS, and are a widely recognizable convention (Mustache/Handlebars/
many email tools use the same syntax), so it doubles as being easy to
explain to a non-programmer admin.

See PLACEHOLDERS below for the full list of what's available.
"""
import re

# ============================================================
# Available placeholders
# ============================================================
# required=True  -> always present and meaningful for every single alert;
#                    a template that omits it is still valid, but is
#                    probably missing important context.
# required=False -> only sometimes meaningful (e.g. escalation_level is
#                    "0" for a plain, non-escalated alert) -- safe to
#                    leave out of a template freely.
PLACEHOLDERS = [
    {"key": "device_name", "required": True, "example": "Production Web Server",
     "description": "The device/site's display name."},
    {"key": "device_host", "required": True, "example": "192.168.1.50",
     "description": "The device/site's host, IP address, or URL."},
    {"key": "metric", "required": True, "example": "cpu_pct",
     "description": "Raw metric key that triggered this alert."},
    {"key": "metric_label", "required": True, "example": "Response time (ms)",
     "description": "Human-readable metric name with its unit, e.g. Response time (ms), SSL certificate expires in (days)."},
    {"key": "value", "required": True, "example": "94.2",
     "description": "The value that triggered this alert."},
    {"key": "threshold", "required": False, "example": "90",
     "description": "The threshold that was crossed, with its unit (e.g. 1000 ms, or below 30 days for SSL expiry). Shows an em-dash if not applicable to this alert."},
    {"key": "state", "required": True, "example": "critical",
     "description": "Raw state: warning, critical, offline, or recovered."},
    {"key": "label", "required": True, "example": "CRITICAL",
     "description": "Display label shown in the subject/banner (automatically becomes e.g. 'ESCALATION L2' once an escalation level fires)."},
    {"key": "color", "required": False, "example": "#FF5C5C",
     "description": "Hex color associated with this state/level -- for use in custom HTML styling."},
    {"key": "bg", "required": False, "example": "#280000",
     "description": "Per-state dark background color for the email card (a subtly different tint for warning/critical/offline/recovered)."},
    {"key": "timestamp", "required": True, "example": "2026-08-20 14:32:10",
     "description": "When this alert was generated."},
    {"key": "portal_url", "required": True, "example": "http://192.168.3.7:5050",
     "description": "THE DASHBOARD LINK. Automatically matches however your team actually accesses the server (PC name or IP) -- see app.py's _remember_access_host()."},
    {"key": "app_version", "required": False, "example": "8.4",
     "description": "Current Net-monit version, normally shown in the footer."},
    {"key": "escalation_level", "required": False, "example": "2",
     "description": "0 for a normal (non-escalated) alert; 1, 2, or 3 once that escalation level has fired."},
    {"key": "escalation_banner_html", "required": False, "example": "<div>...</div>",
     "description": "Pre-built HTML escalation banner snippet, ready to drop straight into an HTML template. Empty string when escalation_level is 0. Not meaningful in a plain-text template."},
]
PLACEHOLDER_KEYS = {p["key"] for p in PLACEHOLDERS}

ALERT_STATES = ("warning", "critical", "offline", "recovered")

_TOKEN_RE = re.compile(r"\{\{\s*(\w+)\s*\}\}")


def render(template_str: str, context: dict) -> str:
    """
    Replace every {{placeholder}} in template_str with context[placeholder].

    Unknown/mistyped placeholders (e.g. "{{devcie_name}}") are left as
    literal text in the output rather than raising an exception -- a
    typo in an admin-edited template must never be able to crash the
    alert pipeline and silently stop every notification from sending.
    The mistake will just be visibly wrong in the email instead, which
    is easy to spot and fix.
    """
    def _sub(match):
        key = match.group(1)
        return str(context[key]) if key in context else match.group(0)
    return _TOKEN_RE.sub(_sub, template_str or "")


def find_unknown_placeholders(template_str: str, extra_keys=None) -> list:
    """Returns any {{...}} tokens in template_str that aren't in
    PLACEHOLDER_KEYS -- used by the Settings UI to warn about likely
    typos before saving, without blocking the save (the admin might
    have a good reason; this is a hint, not a hard rule).

    extra_keys (V8.4): admin-defined custom placeholder keys, which are
    valid but aren't part of the static PLACEHOLDERS registry -- pass
    the current set from db.get_custom_placeholders() so they aren't
    flagged as unknown/typos."""
    found = set(m.group(1) for m in _TOKEN_RE.finditer(template_str or ""))
    known = PLACEHOLDER_KEYS | set(extra_keys or [])
    return sorted(found - known)


def missing_required_placeholders(template_str: str) -> list:
    """Returns required placeholder keys that do NOT appear anywhere in
    template_str -- another non-blocking hint for the Settings UI."""
    found = set(m.group(1) for m in _TOKEN_RE.finditer(template_str or ""))
    required = {p["key"] for p in PLACEHOLDERS if p["required"]}
    return sorted(required - found)


def all_placeholders(custom: list = None) -> list:
    """V8.4. Returns the built-in PLACEHOLDERS list plus any admin-
    defined custom placeholders (from db.get_custom_placeholders()),
    merged into one list shaped consistently for the Settings UI's
    reference table, insert-chip list, and "{{"-autocomplete dropdown.
    Custom entries carry "custom": True so the UI can render them
    distinctly (and route their remove action differently -- a custom
    placeholder can be deleted from the registry entirely; a built-in
    one can only be removed from a specific template's text)."""
    out = [dict(p, custom=False) for p in PLACEHOLDERS]
    for c in (custom or []):
        out.append({
            "key": c["key"],
            "required": False,
            "description": c.get("description") or "Custom placeholder",
            "example": c.get("value", ""),
            "custom": True,
        })
    return out


# ============================================================
# Built-in default templates
# ============================================================
# These reproduce EXACTLY what email_notifier.py generated before this
# feature existed -- so a fresh install, or any state with no admin
# override, behaves identically to before, byte for byte once rendered.

DEFAULT_SUBJECT = "[{{label}}] {{device_name}} \u2014 {{metric_label}}"

DEFAULT_TEXT = (
    "Network Monitor Alert [{{label}}]\n"
    "======================\n"
    "Device:    {{device_name}} ({{device_host}})\n"
    "Metric:    {{metric}}\n"
    "Value:     {{value}}\n"
    "Threshold: {{threshold}}\n"
    "State:     {{label}}\n"
    "Time:      {{timestamp}}\n"
    "\n"
    "Open Net-monit dashboard: {{portal_url}}\n"
)

DEFAULT_HTML = """<html><body style="margin:0;padding:24px;background:#0B0E14;font-family:Arial,sans-serif;">
<div style="max-width:520px;margin:auto;background:{{bg}};border:1px solid {{color}}33;border-radius:10px;overflow:hidden;">
  <div style="background:{{color}};padding:16px 22px;">
    <span style="font-weight:800;font-size:13px;letter-spacing:1px;color:#0B0E14;">{{label}}</span>
    <span style="float:right;font-size:12px;color:#0B0E14;opacity:.7;">{{timestamp}}</span>
  </div>
  <div style="padding:22px;color:#E6E9EF;">
    {{escalation_banner_html}}
    <h2 style="margin:0 0 14px;font-size:20px;color:#fff;">{{device_name}}</h2>
    <table style="width:100%;font-size:14px;border-collapse:collapse;">
      <tr><td style="padding:6px 0;color:#888;width:110px;">Host</td>
          <td style="color:#E6E9EF;">{{device_host}}</td></tr>
      <tr><td style="padding:6px 0;color:#888;">Metric</td>
          <td style="color:#E6E9EF;">{{metric_label}}</td></tr>
      <tr><td style="padding:6px 0;color:#888;">Value</td>
          <td style="color:{{color}};font-weight:700;font-size:16px;">{{value}}</td></tr>
      <tr><td style="padding:6px 0;color:#888;">Threshold</td>
          <td style="color:#aaa;">{{threshold}}</td></tr>
    </table>
    <div style="margin-top:20px;text-align:center;">
      <a href="{{portal_url}}" target="_blank"
         style="display:inline-block;background:{{color}};color:#0B0E14;font-weight:700;
                font-size:13px;text-decoration:none;padding:11px 26px;border-radius:6px;">
        Open Net-monit Dashboard \u2192
      </a>
    </div>
  </div>
  <div style="padding:10px 22px 16px;color:#555;font-size:12px;border-top:1px solid #232A36;">
    Sent by Net-monit V{{app_version}} &nbsp;\u00b7&nbsp; {{timestamp}}
  </div>
</div></body></html>"""

DEFAULT_TEMPLATES = {
    state: {
        "subject_template": DEFAULT_SUBJECT,
        "text_template":    DEFAULT_TEXT,
        "html_template":    DEFAULT_HTML,
        "enabled":           True,
    }
    for state in ALERT_STATES
}


def get_effective_template(state: str) -> dict:
    """
    Returns the template Net-monit should actually use to send an alert
    for this state right now:
        {"subject_template", "text_template", "html_template",
         "is_customized", "override_disabled"}

    - No saved override for this state at all -> built-in default.
    - A saved override exists but its "enabled" flag is off -> built-in
      default too (the admin can keep a draft customization saved and
      temporarily switch back to the default without losing their draft).
    - A saved, enabled override exists -> the override's own text, with
      any individual field the admin left BLANK falling back to that
      one field's default (so an admin who only wants to tweak the
      subject line doesn't have to also redefine the whole HTML body).
    """
    from . import database as db
    override = db.get_notification_template(state)
    default  = DEFAULT_TEMPLATES.get(state, DEFAULT_TEMPLATES["warning"])

    if not override or not override.get("enabled", 1):
        return {
            **default,
            "is_customized":    bool(override),
            "override_disabled": bool(override) and not override.get("enabled", 1),
        }

    return {
        "subject_template": override.get("subject_template") or default["subject_template"],
        "text_template":    override.get("text_template")    or default["text_template"],
        "html_template":    override.get("html_template")    or default["html_template"],
        "is_customized":     True,
        "override_disabled": False,
    }
