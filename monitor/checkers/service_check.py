# =============================================================================
# Net-monit V12.4
# Copyright (c) 2024-2026 Abdullah. All rights reserved.
# Contact: abuabdullah.be@outlook.com
# Unauthorised copying, modification or distribution of this software
# is strictly prohibited without prior written permission from the author.
# =============================================================================
"""
service_check.py — V8.2 (new)

Watches one or more named services on a host:
  - Windows: service names as shown in services.msc / `Get-Service -Name`
             (e.g. "Spooler", "wuauserv", "W3SVC")
  - Linux:   systemd unit names (e.g. "sshd", "nginx", "docker")

Design: this is NOT a standalone device method. It's an optional extra
check attached to a device that's already being monitored some other way
(ping/powershell/ssh/etc — see device["services_watch"]). It deliberately
reuses whatever ssh/powershell credentials that device already has
configured for its primary check, rather than asking for a second set of
credentials, since it's almost always the same host.

device["services_watch"] shape:
    {
        "enabled": true,
        "platform": "windows" | "linux",   # which credential set to use
        "items": ["Spooler", "wuauserv"],   # names to watch
    }

Returns:
    {
        "reachable": bool,      # False only if we couldn't even connect
        "services": [
            {"name": "Spooler", "running": true,  "state": "Running"},
            {"name": "wuauserv", "running": false, "state": "Stopped"},
        ],
        "error": str | None,
    }
An item that doesn't exist on the host is reported with running=False,
state="NotFound" rather than silently dropped, so a typo'd service name
still surfaces as a visible problem instead of disappearing.
"""
import logging

log = logging.getLogger("monitor.service_check")

_EMPTY = {"reachable": True, "services": [], "error": None}


def check(device: dict) -> dict:
    sw = device.get("services_watch") or {}
    if not sw.get("enabled"):
        return dict(_EMPTY)

    items = [s.strip() for s in (sw.get("items") or []) if isinstance(s, str) and s.strip()]
    if not items:
        return dict(_EMPTY)

    platform = sw.get("platform")
    if not platform:
        # Infer from whichever credential block the device already has.
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
        "services": [],
        "error": ("Service monitoring needs SSH (Linux) or PowerShell (Windows) "
                  "credentials configured on this device first -- set those up, "
                  "then pick a platform for service monitoring."),
    }


def _check_windows(device: dict, items: list) -> dict:
    from . import powershell_check
    pc = device.get("powershell", {}) or {}

    names_ps = ",".join("'" + n.replace("'", "''") + "'" for n in items)
    script = f"""
$names = @({names_ps})
$results = foreach ($n in $names) {{
    $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
    if ($svc) {{
        [PSCustomObject]@{{ name=$n; running=($svc.Status -eq 'Running'); state=$svc.Status.ToString() }}
    }} else {{
        [PSCustomObject]@{{ name=$n; running=$false; state='NotFound' }}
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
    if "error" in data and not isinstance(data, list):
        return {"reachable": False, "services": [], "error": data["error"]}

    services = data if isinstance(data, list) else [data]
    return {"reachable": True, "services": services, "error": None}


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
            return {"reachable": False, "services": [], "error": "No SSH credentials configured on this device"}

        client.connect(**connect_kwargs)

        # One systemctl call per unit, each wrapped with a delimiter so we
        # can reliably split the output even if a unit name is unusual.
        parts = []
        for n in items:
            safe = n.replace("'", "'\\''")
            parts.append(f"echo '@@{safe}@@'; systemctl is-active '{safe}' 2>&1")
        command = " ; ".join(parts)

        stdin, stdout, stderr = client.exec_command(command, timeout=10)
        output = stdout.read().decode(errors="ignore")

        results = []
        blocks = output.split("@@")
        # blocks looks like: ['', 'name1', '\nactive\n', 'name2', '\ninactive\n', ...]
        i = 1
        while i < len(blocks) - 1:
            name = blocks[i].strip("@\n ")
            status_text = blocks[i + 1].strip().splitlines()[0].strip() if blocks[i + 1].strip() else ""
            if status_text == "active":
                running, state = True, "active"
            elif status_text in ("inactive", "failed", "unknown"):
                running, state = False, status_text
            elif "not-found" in status_text or "not be found" in status_text.lower() or not status_text:
                running, state = False, "NotFound"
            else:
                running, state = False, status_text or "unknown"
            results.append({"name": name, "running": running, "state": state})
            i += 2

        return {"reachable": True, "services": results, "error": None}

    except paramiko.AuthenticationException:
        return {"reachable": False, "services": [], "error": "SSH authentication failed"}
    except Exception as exc:  # noqa: BLE001
        return {"reachable": False, "services": [], "error": str(exc)}
    finally:
        client.close()
