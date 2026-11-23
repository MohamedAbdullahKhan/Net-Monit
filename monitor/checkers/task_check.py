# =============================================================================
# Net-monit V12.4
# Copyright (c) 2024-2026 Abdullah. All rights reserved.
# Contact: abuabdullah.be@outlook.com
# Unauthorised copying, modification or distribution of this software
# is strictly prohibited without prior written permission from the author.
# =============================================================================
"""
task_check.py — V8.2 (new)

Watches one or more scheduled tasks on a host:
  - Windows: Task Scheduler tasks, given by their full path as shown in
             Task Scheduler (e.g. "\\Backup\\NightlyBackup", or just
             "NightlyBackup" for a task at the root).
  - Linux:   systemd timers (e.g. "backup" for backup.timer / backup.service).
             Plain cron doesn't record success/failure anywhere standard,
             so cron-only setups won't show a pass/fail state here -- this
             checks the *systemd timer* + the service it triggers, which is
             the modern equivalent on most current distros.

Same design as service_check.py: an optional extra check attached to an
existing device, reusing that device's ssh/powershell credentials rather
than asking for a second set.

device["tasks_watch"] shape:
    {
        "enabled": true,
        "platform": "windows" | "linux",
        "items": ["\\Backup\\NightlyBackup"],
    }

Returns:
    {
        "reachable": bool,
        "tasks": [
            {"name": "...", "ok": true, "last_result": 0,
             "last_run": "2026-07-20T02:00:00", "state": "Ready"},
        ],
        "error": str | None,
    }
"""
import logging

log = logging.getLogger("monitor.task_check")

_EMPTY = {"reachable": True, "tasks": [], "error": None}


def check(device: dict) -> dict:
    tw = device.get("tasks_watch") or {}
    if not tw.get("enabled"):
        return dict(_EMPTY)

    items = [t.strip() for t in (tw.get("items") or []) if isinstance(t, str) and t.strip()]
    if not items:
        return dict(_EMPTY)

    platform = tw.get("platform")
    if not platform:
        if device.get("powershell"):
            platform = "windows"
        elif device.get("ssh"):
            platform = "linux"

    if platform == "windows":
        return _check_windows(device, items)
    elif platform == "linux":
        return _check_linux(device, items)

    return {
        "reachable": False,
        "tasks": [],
        "error": ("Task monitoring needs SSH (Linux) or PowerShell (Windows) "
                  "credentials configured on this device first."),
    }


def _check_windows(device: dict, items: list) -> dict:
    from . import powershell_check
    pc = device.get("powershell", {}) or {}

    names_ps = ",".join("'" + n.replace("'", "''") + "'" for n in items)
    script = f"""
$names = @({names_ps})
$results = foreach ($full in $names) {{
    $leaf = Split-Path $full -Leaf
    $path = Split-Path $full
    if (-not $path) {{ $path = '\\' }}
    if (-not $path.EndsWith('\\')) {{ $path = $path + '\\' }}
    $task = Get-ScheduledTask -TaskName $leaf -TaskPath $path -ErrorAction SilentlyContinue
    if (-not $task) {{
        [PSCustomObject]@{{ name=$full; ok=$false; state='NotFound'; last_result=$null; last_run=$null; next_run=$null }}
    }} else {{
        $info = $task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
        $lr = if ($info) {{ $info.LastTaskResult }} else {{ $null }}
        [PSCustomObject]@{{
            name = $full
            ok = ($lr -eq 0)
            state = $task.State.ToString()
            last_result = $lr
            last_run = if ($info -and $info.LastRunTime) {{ $info.LastRunTime.ToString('o') }} else {{ $null }}
            next_run = if ($info -and $info.NextRunTime) {{ $info.NextRunTime.ToString('o') }} else {{ $null }}
        }}
    }}
}}
@($results) | ConvertTo-Json -Compress
"""
    data = powershell_check.run_ps_script(
        device["host"], script,
        remote=pc.get("remote", False),
        username=pc.get("username"),
        password=pc.get("password"),
    )
    if isinstance(data, dict) and "error" in data:
        return {"reachable": False, "tasks": [], "error": data["error"]}

    tasks = data if isinstance(data, list) else [data]
    return {"reachable": True, "tasks": tasks, "error": None}


def _check_linux(device: dict, items: list) -> dict:
    import paramiko
    sc = device.get("ssh", {}) or {}

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        connect_kwargs = dict(hostname=device["host"], port=sc.get("port", 22),
                               username=sc.get("username", "monitor"), timeout=8)
        if sc.get("key_path"):
            connect_kwargs["pkey"] = paramiko.RSAKey.from_private_key_file(sc["key_path"])
        elif sc.get("password"):
            connect_kwargs["password"] = sc["password"]
        else:
            return {"reachable": False, "tasks": [], "error": "No SSH credentials configured on this device"}

        client.connect(**connect_kwargs)

        parts = []
        for n in items:
            unit = n[:-len(".timer")] if n.endswith(".timer") else n
            safe = unit.replace("'", "'\\''")
            parts.append(
                f"echo '@@{safe}@@'; "
                f"systemctl show '{safe}.service' -p Result,ActiveState,ExecMainStartTimestamp 2>&1; "
                f"echo '--'; "
                f"systemctl show '{safe}.timer' -p LoadState 2>&1"
            )
        command = " ; ".join(parts)

        stdin, stdout, stderr = client.exec_command(command, timeout=10)
        output = stdout.read().decode(errors="ignore")

        results = []
        blocks = output.split("@@")
        i = 1
        while i < len(blocks) - 1:
            name = blocks[i].strip("@\n ")
            body = blocks[i + 1]
            svc_part = body.split("--", 1)[0]
            timer_part = body.split("--", 1)[1] if "--" in body else ""

            props = {}
            for line in svc_part.splitlines():
                if "=" in line:
                    k, _, val = line.partition("=")
                    props[k.strip()] = val.strip()

            timer_loaded = "LoadState=loaded" in timer_part
            if not timer_loaded and not props.get("Result"):
                results.append({"name": name, "ok": False, "state": "NotFound",
                                 "last_result": None, "last_run": None})
            else:
                result = props.get("Result", "")
                ok = result == "success"
                results.append({
                    "name": name,
                    "ok": ok,
                    "state": props.get("ActiveState", "unknown"),
                    "last_result": result or None,
                    "last_run": props.get("ExecMainStartTimestamp") or None,
                })
            i += 2

        return {"reachable": True, "tasks": results, "error": None}

    except paramiko.AuthenticationException:
        return {"reachable": False, "tasks": [], "error": "SSH authentication failed"}
    except Exception as exc:  # noqa: BLE001
        return {"reachable": False, "tasks": [], "error": str(exc)}
    finally:
        client.close()
