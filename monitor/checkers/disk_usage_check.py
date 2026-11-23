# =============================================================================
# Net-monit V12.4
# Copyright (c) 2024-2026 Abdullah. All rights reserved.
# Contact: abuabdullah.be@outlook.com
# Unauthorised copying, modification or distribution of this software
# is strictly prohibited without prior written permission from the author.
# =============================================================================
"""
disk_usage_check.py
Polls free/used disk space on a "shared drive" target - a local/UNC
Windows share or a Linux/NFS mount path - and reports it as disk_pct so
it slots straight into the existing warning/critical threshold engine
(defaults.thresholds.disk_pct) and email alerting, exactly like the
disk_pct already produced by the SSH and PowerShell host checkers.

Two backends, chosen by device.disk.os:
  "windows" - runs PowerShell locally or via WinRM (Invoke-Command),
              reusing the same pwsh/powershell.exe discovery as
              powershell_check.py. Accepts a drive letter ("Z:") or a
              UNC path ("\\fileserver\\share").
  "linux"   - runs `df -P <path>` over SSH, reusing the same paramiko
              connection pattern as ssh_check.py. <path> is wherever the
              share is mounted on that Linux host (e.g. /mnt/shared).

Returns: {"reachable": bool, "disk_pct": float, "free_gb": float,
          "total_gb": float, "error": str (on failure)}
"""
import re
import shutil
import subprocess

import paramiko


def check(device):
    disk_cfg = device.get("disk", {})
    os_type = disk_cfg.get("os", "windows")
    path = disk_cfg.get("path")

    if not path:
        return {"reachable": False, "error": "No 'disk.path' configured for this shared drive"}

    if os_type == "linux":
        return _check_linux(
            host=device["host"],
            path=path,
            port=disk_cfg.get("port", 22),
            username=disk_cfg.get("username", "monitor"),
            password=disk_cfg.get("password"),
            key_path=disk_cfg.get("key_path"),
        )
    return _check_windows(
        host=device["host"],
        path=path,
        remote=disk_cfg.get("remote", True),
        username=disk_cfg.get("username"),
        password=disk_cfg.get("password"),
    )


# --------------------------------------------------------------------------
# Windows: drive letter or UNC path, via local/remote PowerShell
# --------------------------------------------------------------------------
def _powershell_binary():
    for candidate in ("pwsh", "powershell.exe", "powershell"):
        if shutil.which(candidate):
            return candidate
    return None


def _windows_ps_snippet(path):
    # Works for both a UNC path ("\server\share") and a local/mapped
    # drive letter ("Z:" or "Z:\"). New-PSDrive lets us query a UNC path
    # the same way we'd query a local drive, without needing it mapped
    # ahead of time.
    escaped = path.replace("'", "''")
    return (
        "$ErrorActionPreference = 'Stop'; "
        "try { "
        f"  $p = '{escaped}'; "
        "  if ($p -match '^[a-zA-Z]:\\?$') { "
        "    $d = Get-PSDrive -Name $p.Substring(0,1); "
        "    $used = $d.Used; $free = $d.Free; "
        "  } else { "
        "    $tmp = New-PSDrive -Name NETMONTMP -PSProvider FileSystem -Root $p -ErrorAction Stop; "
        "    $item = Get-Item ('NETMONTMP:\'); "
        "    $share = Get-WmiObject -Class Win32_Share -ErrorAction SilentlyContinue; "
        "    $total = (Get-PSDrive NETMONTMP).Used + (Get-PSDrive NETMONTMP).Free; "
        "    $used = (Get-PSDrive NETMONTMP).Used; $free = (Get-PSDrive NETMONTMP).Free; "
        "    Remove-PSDrive -Name NETMONTMP -ErrorAction SilentlyContinue; "
        "  } "
        "  $total = $used + $free; "
        "  $pct = if ($total -gt 0) { [math]::Round(($used / $total) * 100, 1) } else { 0 }; "
        "  $result = @{ disk_pct = $pct; "
        "                free_gb = [math]::Round($free / 1GB, 2); "
        "                total_gb = [math]::Round($total / 1GB, 2) }; "
        "  $result | ConvertTo-Json -Compress "
        "} catch { "
        "  $err = @{ error = $_.Exception.Message }; $err | ConvertTo-Json -Compress; exit 1 "
        "}"
    )


def _check_windows(host, path, remote=True, username=None, password=None, timeout=20):
    binary = _powershell_binary()
    if not binary:
        return {
            "reachable": False,
            "error": "No PowerShell interpreter found on PATH (install pwsh, "
                     "or run this app on/near a Windows host with PowerShell 5.1+).",
        }

    snippet = _windows_ps_snippet(path)

    if remote:
        escaped_script = snippet.replace("'", "''")
        if username and password:
            cred_block = (
                f"$pw = ConvertTo-SecureString '{password}' -AsPlainText -Force; "
                f"$cred = New-Object System.Management.Automation.PSCredential('{username}', $pw); "
            )
            cred_arg = "-Credential $cred "
        else:
            cred_block, cred_arg = "", ""
        ps_command = (
            f"{cred_block}"
            f"$sb = [ScriptBlock]::Create('{escaped_script}'); "
            f"Invoke-Command -ComputerName {host} {cred_arg}-ScriptBlock $sb"
        )
    else:
        ps_command = snippet

    try:
        result = subprocess.run(
            [binary, "-NoProfile", "-NonInteractive", "-Command", ps_command],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"reachable": False, "error": "PowerShell disk check timed out"}

    if result.returncode != 0:
        return {"reachable": False, "error": (result.stderr or "PowerShell script failed").strip()[:500]}

    try:
        import json
        data = json.loads(result.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"reachable": False, "error": "Could not parse PowerShell output as JSON"}

    if "error" in data:
        return {"reachable": False, "error": str(data["error"])[:500]}

    data["reachable"] = True
    return data


# --------------------------------------------------------------------------
# Linux/NFS: mount path, via SSH (same approach as ssh_check.py)
# --------------------------------------------------------------------------
def _check_linux(host, path, port=22, username="monitor", password=None, key_path=None, timeout=8):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        connect_kwargs = dict(hostname=host, port=port, username=username, timeout=timeout)
        if key_path:
            connect_kwargs["pkey"] = paramiko.RSAKey.from_private_key_file(key_path)
        elif password:
            connect_kwargs["password"] = password
        else:
            return {"reachable": False, "error": "No SSH credentials configured (key_path or password)"}

        client.connect(**connect_kwargs)

        safe_path = path.replace("'", "'\''")
        command = f"df -Pk '{safe_path}' | tail -1"
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode(errors="ignore")
        err = stderr.read().decode(errors="ignore")

        # df -Pk: Filesystem 1K-blocks Used Available Capacity Mounted-on
        match = re.search(r"\S+\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)%", output)
        if not match:
            return {"reachable": False, "error": (err or f"Path not found or not mounted: {path}").strip()[:300]}

        total_kb, used_kb, avail_kb, pct = match.groups()
        return {
            "reachable": True,
            "disk_pct": float(pct),
            "free_gb": round(int(avail_kb) / (1024 * 1024), 2),
            "total_gb": round(int(total_kb) / (1024 * 1024), 2),
        }

    except paramiko.AuthenticationException:
        return {"reachable": False, "error": "SSH authentication failed"}
    except Exception as exc:  # noqa: BLE001
        return {"reachable": False, "error": str(exc)}
    finally:
        client.close()
