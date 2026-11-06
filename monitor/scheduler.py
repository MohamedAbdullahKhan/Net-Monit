# =============================================================================
# Net-monit V11.3
# Copyright (c) 2024-2026 Abdullah. All rights reserved.
# Contact: abuabdullah.be@outlook.com
# Unauthorised copying, modification or distribution of this software
# is strictly prohibited without prior written permission from the author.
# =============================================================================
"""
scheduler.py  —  Net-monit V11.3
APScheduler background polling. Each device runs in its own interval job.
"""
import logging
import threading
import time
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.executors.pool import ThreadPoolExecutor
from . import database as db
from . import alerts
from . import crypto
from .checkers import ping_check, snmp_check, powershell_check, ssh_check, disk_usage_check, url_check, speedtest_check, service_check, task_check

log = logging.getLogger("monitor.scheduler")
_scheduler = None


_OFFLINE_DEFAULTS = {"offline_retries": 2, "offline_retry_delay_sec": 3, "offline_confirm_polls": 2}
_OFFLINE_LIMITS   = {"offline_retries": (0, 5), "offline_retry_delay_sec": (1, 30), "offline_confirm_polls": (1, 10)}
_fail_streak = {}                 # device id -> consecutive polls (each already retried) that found it unreachable
_streak_lock = threading.Lock()
_POLL_ERROR_HOLD = 5              # consecutive MONITORING errors (checker crashed) before one is shown as a problem


class _UnknownMethod(Exception):
    pass


def offline_settings(device, app_cfg=None):
    """(retries, retry_delay_sec, confirm_polls) for one device: device override > live config defaults > built-in,
    always clamped to a sane range so a typo in config.yaml can never disable polling."""
    try:
        from . import config_manager
        defaults = config_manager.get_config().get("defaults", {}) or {}
    except Exception:
        defaults = (app_cfg or {}).get("defaults", {}) or {}
    out = []
    for key in ("offline_retries", "offline_retry_delay_sec", "offline_confirm_polls"):
        raw = device.get(key, defaults.get(key, _OFFLINE_DEFAULTS[key]))
        lo, hi = _OFFLINE_LIMITS[key]
        try:
            val = int(raw)
        except (TypeError, ValueError):
            val = _OFFLINE_DEFAULTS[key]
        out.append(max(lo, min(hi, val)))
    return tuple(out)


def _primary_check(device, app_cfg, method, host, did):
    """ONE attempt of the device's primary check. Returns the metrics dict; raises on a monitoring error."""
    if method == "ping":
        timeout_ms = device.get("ping_timeout_ms",
                     app_cfg.get("defaults", {}).get("ping_timeout_ms", 1000))
        return ping_check.check(host, timeout_ms=timeout_ms)
    if method == "snmp":
        sc = device.get("snmp", {})
        return snmp_check.check(
            host,
            community=sc.get("community", "public"),
            version=sc.get("version", 2),
            interfaces=sc.get("interfaces"),
        )
    if method == "powershell":
        pc = device.get("powershell", {})
        return powershell_check.check(
            host,
            remote=pc.get("remote", False),
            use_winrm=pc.get("use_winrm", False),
            username=pc.get("username"),
            password=pc.get("password"),
        )
    if method == "ssh":
        sc = device.get("ssh", {})
        return ssh_check.check(
            host,
            port=sc.get("port", 22),
            username=sc.get("username", "monitor"),
            password=sc.get("password"),
            key_path=sc.get("key_path"),
        )
    if method == "disk_usage":
        return disk_usage_check.check(device)
    if method == "url":
        return url_check.check(device)
    if method == "speedtest":
        return speedtest_check.check(device)
    raise _UnknownMethod(method)


def _poll_device(device, app_cfg):
    # Decrypt credentials before passing to checkers
    device = crypto.decrypt_device_creds(device)
    did    = device["id"]
    dname  = device["name"]
    host   = device["host"]
    method = device.get("method", "ping")

    # V11.3 patch 03 -- no false OFFLINE alerts. A device is only reported offline when
    #   1) the check failed on every one of (retries + 1) attempts, a few seconds apart, AND
    #   2) that happened on `confirm_polls` polls in a row.
    # A checker that CRASHED (our own error, not "no reply") is never reported as a device being offline unless it
    # keeps happening (_POLL_ERROR_HOLD polls in a row). While a failure is unconfirmed the previous status is kept.
    retries, retry_delay, confirm_polls = offline_settings(device, app_cfg)
    attempts = 1 if method == "speedtest" else retries + 1
    metrics = None
    for attempt in range(attempts):
        try:
            metrics = _primary_check(device, app_cfg, method, host, did)
        except _UnknownMethod:
            log.warning("Unknown method '%s' for device %s", method, did)
            return
        except Exception as exc:
            log.error("Poll error %s (attempt %d/%d): %s", did, attempt + 1, attempts, exc)
            metrics = {"reachable": False, "error": str(exc), "poll_error": True}
        if metrics.get("reachable") or method == "speedtest":
            break
        if attempt < attempts - 1:
            time.sleep(retry_delay)
    if attempt:
        metrics["attempts"] = attempt + 1          # only recorded when a re-check was needed

    if method != "speedtest":
        with _streak_lock:
            if metrics.get("reachable"):
                _fail_streak.pop(did, None); streak = 0
            else:
                streak = _fail_streak.get(did, 0) + 1; _fail_streak[did] = streak
        if not metrics.get("reachable"):
            reason = metrics.get("error") or "no reply"
            if metrics.get("poll_error") and streak < _POLL_ERROR_HOLD:
                log.error("%s (%s): the %s check itself failed (%s). Not treated as offline; holding the current status "
                          "(%d of %d).", dname, host, method, reason, streak, _POLL_ERROR_HOLD)
                return
            if streak < confirm_polls:
                log.warning("%s (%s): unreachable after %d attempt(s) [%s]. Poll %d of %d to confirm; holding the current status.",
                            dname, host, attempt + 1, reason, streak, confirm_polls)
                return
            log.warning("%s (%s): OFFLINE confirmed after %d attempt(s) on %d poll(s) in a row [%s].",
                        dname, host, attempt + 1, streak, reason)

    # V8.2: services/tasks watching is an optional EXTRA layered on top of
    # whatever primary check just ran above (ping/powershell/ssh/url/etc),
    # not a separate device method -- see service_check.py / task_check.py.
    # Merged into the same metrics dict so evaluate_device(), the Alert
    # Event Log, and the dashboard tile all pick them up through the exact
    # same pipeline as every other metric, with no special-casing needed.
    try:
        if (device.get("services_watch") or {}).get("enabled"):
            sres = service_check.check(device)
            if sres.get("services"):
                metrics["services"] = sres["services"]
            if sres.get("error") and not sres.get("reachable", True):
                metrics.setdefault("warnings", []).append(f"Service check: {sres['error']}")
        if (device.get("tasks_watch") or {}).get("enabled"):
            tres = task_check.check(device)
            if tres.get("tasks"):
                metrics["tasks"] = tres["tasks"]
            if tres.get("error") and not tres.get("reachable", True):
                metrics.setdefault("warnings", []).append(f"Task check: {tres['error']}")
    except Exception as exc:
        log.error("Service/task watch error %s: %s", did, exc)
        metrics.setdefault("warnings", []).append(f"Service/task watch error: {exc}")

    # V11.3 patch 02: read the LIVE global thresholds (what Settings > Thresholds saves), fresh on every poll.
    try:
        from . import config_manager
        global_thr = config_manager.effective_global_thresholds()
    except Exception as exc:                      # never let a config hiccup stop a poll
        log.error("Could not read global thresholds, falling back to the job's config copy: %s", exc)
        global_thr = (app_cfg.get("defaults", {}) or {}).get("thresholds", {}) or {}
    device_notify = db.get_device_notify(did)

    try:
        from . import config_manager as _cm
        scoped_thr = _cm.effective_scoped_thresholds()
    except Exception as exc:
        log.error("Could not read type/method thresholds: %s", exc)
        scoped_thr = {}
    overall, metric_states = alerts.evaluate_device(
        device, metrics, global_thr, device_notify=device_notify, scoped_thresholds=scoped_thr)

    error_msg = metrics.get("error") or metrics.get("last_error")
    db.upsert_device_status(did, dname, device.get("type","network"),
                            method, host, overall, metrics, error=error_msg)

    # V11.3 patch 08: all the database writes of ONE poll (every metric row + the alert bookkeeping) in a single
    # transaction instead of one connection + commit each. The e-mail/SMS part below stays outside it, so a slow
    # SMTP server never holds the database write lock.
    with db.batch():
        for metric, (state, value, _) in metric_states.items():
            if isinstance(value, (int, float)):
                db.record_metric(did, metric, value, state)

            # V7.2: Active-alert lifecycle (Alert Event Logs page).
            # A metric in warning/critical opens (or refreshes) an active alert;
            # a metric back to ok silently auto-resolves any open alert for it.
            if state in ("warning", "critical"):
                db.upsert_active_alert(
                    did, dname, host, metric, state,
                    f"{dname} ({host}) — {metric.replace('_',' ')} is {state}"
                    f"{': ' + str(round(value,1)) if isinstance(value,(int,float)) else ''}"
                )
            elif state == "ok":
                db.auto_resolve_active_alerts(did, metric)

    smtp_cfg  = app_cfg.get("smtp", {})
    resend    = smtp_cfg.get("resend_interval_minutes", 30)
    alerts.process_alerts(device, metric_states, smtp_cfg, resend,
                          device_notify=device_notify)


def start_scheduler(app_cfg):
    global _scheduler
    # 30 workers (APScheduler's default is 10): a few offline devices, each retrying, must not starve everyone else's polls
    _scheduler = BackgroundScheduler(daemon=True, executors={"default": ThreadPoolExecutor(30)})
    _add_jobs(app_cfg)
    _scheduler.start()
    log.info("Scheduler started with %d device(s)", len(app_cfg.get("devices", [])))


def reload_scheduler(app_cfg, poll_now=()):
    """V11.3 patch 08: bring the jobs in line with the config WITHOUT restarting every poll. It used to remove all jobs and
    re-add them with next_run_time=now, so saving ONE device made EVERY device (SSH, PowerShell, SNMP, URL...) poll at
    once. Now: existing jobs keep their schedule (they just get the fresh device settings), deleted devices lose their
    job, new devices poll at once, and only the devices listed in `poll_now` are re-polled immediately."""
    global _scheduler
    if not _scheduler:
        return
    import datetime
    default_interval = app_cfg.get("defaults", {}).get("poll_interval_seconds", 30)
    wanted = set()
    for device in app_cfg.get("devices", []):
        did = device["id"]; wanted.add(did)
        interval = device.get("poll_interval_seconds", default_interval)
        job = _scheduler.get_job(did)
        if job is None:
            _scheduler.add_job(_poll_device, "interval", seconds=interval, args=[device, app_cfg], id=did,
                               next_run_time=datetime.datetime.now(), misfire_grace_time=60, coalesce=True)
            continue
        job.modify(args=[device, app_cfg])
        cur = getattr(job.trigger, "interval", None)
        if cur is None or int(cur.total_seconds()) != int(interval):
            _scheduler.reschedule_job(did, trigger="interval", seconds=interval)
        if did in poll_now:
            job.modify(next_run_time=datetime.datetime.now())
    for job in _scheduler.get_jobs():
        if job.id not in wanted:
            _scheduler.remove_job(job.id)
    log.info("Scheduler synced: %d device(s), %d polled now", len(wanted), len(set(poll_now) & wanted))


def _add_jobs(app_cfg):
    default_interval = app_cfg.get("defaults", {}).get("poll_interval_seconds", 30)
    for device in app_cfg.get("devices", []):
        interval = device.get("poll_interval_seconds", default_interval)
        _scheduler.add_job(
            _poll_device,
            "interval",
            seconds=interval,
            args=[device, app_cfg],
            id=device["id"],
            next_run_time=__import__("datetime").datetime.now(),
            misfire_grace_time=60,
            coalesce=True,
        )
