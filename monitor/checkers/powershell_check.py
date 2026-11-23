# =============================================================================
# Net-monit V12.4
# Copyright (c) 2024-2026 Abdullah. All rights reserved.
# Contact: abuabdullah.be@outlook.com
# Unauthorised copying, modification or distribution of this software
# is strictly prohibited without prior written permission from the author.
# =============================================================================
"""
powershell_check.py  —  V5.0
Polls Windows hosts for CPU / memory / disk utilization.

KEY FIXES in V4.0:
  - Always passes -ExecutionPolicy Bypass so windows_metrics.ps1 runs
    regardless of the system execution policy (fixes "running scripts is
    disabled on this system" error).
  - For REMOTE hosts: the script is embedded inline as a ScriptBlock string
    so no .ps1 file needs to exist or be trusted on the remote machine.
  - For LOCAL checks: uses -ExecutionPolicy Bypass on the local call.
  - Automatically sets WinRM TrustedHosts to * for IP-address targets so
    WinRM can authenticate without HTTPS or a domain.
  - Passes -Authentication Negotiate (Kerberos/NTLM) so domain credentials
    work correctly from IP-address targets.
"""
import json
import subprocess
import shutil
import logging
from pathlib import Path

log = logging.getLogger("monitor.ps_check")

SCRIPT_PATH = Path(__file__).resolve().parent.parent.parent / "scripts" / "windows_metrics.ps1"


def _powershell_binary():
    """Find whichever PowerShell is available on this machine."""
    for candidate in ("pwsh", "powershell.exe", "powershell"):
        if shutil.which(candidate):
            return candidate
    return None


def _read_script() -> str:
    """Read windows_metrics.ps1 content; return fallback if missing."""
    try:
        return SCRIPT_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        log.warning("windows_metrics.ps1 not found at %s — using inline fallback", SCRIPT_PATH)
        return _inline_fallback_script()


def _inline_fallback_script() -> str:
    """
    Minimal inline metrics script used when windows_metrics.ps1 is missing.
    Returns the same JSON shape as the full script.
    """
    return r"""
try {
    $cpu   = [math]::Round((Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average, 1)
    $os    = Get-WmiObject Win32_OperatingSystem
    $memPct= [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize * 100, 1)
    $disk  = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" |
             Where-Object { $_.Size -gt 0 } |
             ForEach-Object { [math]::Round((1 - $_.FreeSpace / $_.Size) * 100, 1) } |
             Measure-Object -Maximum | Select-Object -ExpandProperty Maximum
    $uptime= [math]::Round(((Get-Date) - $os.ConvertToDateTime($os.LastBootUpTime)).TotalHours, 1)
    @{ cpu_pct=$cpu; memory_pct=$memPct; disk_pct=$disk; uptime_hours=$uptime;
       hostname=$env:COMPUTERNAME } | ConvertTo-Json -Compress
} catch {
    @{ error=$_.Exception.Message } | ConvertTo-Json -Compress
    exit 1
}
"""


def _build_remote_command(host: str, username: str | None, password: str | None) -> str:
    """Back-compat wrapper: builds the remote invoke command for the metrics script."""
    return build_remote_invoke_command(host, username, password, _read_script())


def build_remote_invoke_command(host: str, username: str | None, password: str | None,
                                 script_body: str) -> str:
    """
    Build an Invoke-Command that:
      1. Auto-adds the target to WinRM TrustedHosts (required for IP addresses
         without HTTPS / domain Kerberos).
      2. Uses -Authentication Negotiate so domain creds work from IP targets.
      3. Embeds the given script INLINE as a ScriptBlock — no .ps1 file
         needs to exist or be signed on the remote host.
      4. Passes -ExecutionPolicy Bypass inside the remote ScriptBlock.

    V8.2: this was originally private to the CPU/mem/disk metrics check
    (_build_remote_command, still kept below as a thin wrapper for
    back-compat) but the exact same WinRM trust/auth machinery is what
    service_check.py and task_check.py need too -- pulled out here once
    rather than copy-pasted three times.

    This fixes:
      "WinRM client cannot process the request. Default authentication may be
       used with an IP address under the following conditions: the transport is
       HTTPS or the destination is in the TrustedHosts list."
    """
    # Escape single-quotes for PowerShell single-quoted string embedding
    escaped_body = script_body.replace("'", "''").replace("\r\n", "\n")

    # Build credential block
    if username and password:
        # Escape single-quotes in password too
        safe_pw   = password.replace("'", "''")
        safe_user = username.replace("'", "''")
        cred_block = (
            f"$pw   = ConvertTo-SecureString '{safe_pw}' -AsPlainText -Force; "
            f"$cred = New-Object System.Management.Automation.PSCredential('{safe_user}', $pw); "
        )
        cred_arg = "-Credential $cred "
        auth_arg  = "-Authentication Negotiate "
    else:
        cred_block = ""
        cred_arg   = ""
        auth_arg   = ""

    # Auto-trust the host in WinRM TrustedHosts so IP-address auth works.
    # This is idempotent — safe to run on every poll.
    trust_block = (
        f"$cur = (Get-Item WSMan:\\localhost\\Client\\TrustedHosts -ErrorAction SilentlyContinue).Value; "
        f"if ($cur -notlike '*{host}*' -and $cur -ne '*') {{ "
        f"  Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value (if ($cur) {{\"$cur,{host}\"}} else {{\"{host}\"}}) -Force "
        f"}}; "
    )

    # The remote ScriptBlock runs with Bypass policy
    sb_command = (
        f"[ScriptBlock]::Create("
        f"'Set-ExecutionPolicy Bypass -Scope Process -Force; "
        f"{escaped_body}'"
        f")"
    )

    return (
        f"{trust_block}"
        f"{cred_block}"
        f"$sb = {sb_command}; "
        f"Invoke-Command -ComputerName {host} "
        f"{auth_arg}"
        f"{cred_arg}"
        f"-ScriptBlock $sb "
        f"-ErrorAction Stop"
    )


def run_ps_script(host, script_body, remote=False, username=None, password=None, timeout=20):
    """
    V8.2: general-purpose "run this PowerShell, get JSON back" helper shared
    by service_check.py and task_check.py, built on the same binary-lookup
    and remote/local dispatch as check() above, but for an arbitrary script
    body instead of the fixed CPU/mem/disk metrics script.
    Returns parsed JSON dict, or {"error": "..."} on failure -- never raises.
    """
    binary = _powershell_binary()
    if not binary:
        return {"error": "No PowerShell interpreter found on PATH (install PowerShell 7 / pwsh)."}

    ps_command = (build_remote_invoke_command(host, username, password, script_body)
                  if remote else f"& {{ {script_body} }}")
    try:
        result = subprocess.run(
            [binary, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_command],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"PowerShell check timed out after {timeout}s"}
    except Exception as exc:
        return {"error": f"Subprocess error: {exc}"}

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()
    if result.returncode != 0 and not stdout:
        return {"error": (stderr or "PowerShell script failed with no output")[:600]}

    lines = [l for l in stdout.splitlines() if l.strip().startswith("{") or l.strip().startswith("[")]
    if not lines:
        return {"error": (stderr or stdout or "No JSON output")[:600]}
    try:
        return json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        return {"error": f"JSON parse error: {exc} — raw: {lines[-1][:200]}"}


def check(host, remote=False, use_winrm=True, username=None, password=None, timeout=30):
    """
    Run a PowerShell metrics check against host.

    Parameters
    ----------
    host      : str   — IP or hostname
    remote    : bool  — True = WinRM remote, False = run locally
    use_winrm : bool  — reserved (always True for remote)
    username  : str   — DOMAIN\\user or user@domain
    password  : str   — plaintext (AES-encrypted at rest in config.yaml)
    timeout   : int   — seconds before giving up
    """
    binary = _powershell_binary()
    if not binary:
        return {
            "reachable": False,
            "error": (
                "No PowerShell interpreter found on PATH. "
                "Install PowerShell 7 (pwsh) or run the app on/near a Windows host."
            ),
        }

    if remote:
        ps_command = _build_remote_command(host, username, password)
    else:
        # LOCAL: just run the .ps1 with ExecutionPolicy Bypass
        ps_command = f"& '{SCRIPT_PATH}'"

    try:
        result = subprocess.run(
            [
                binary,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy", "Bypass",   # ← FIX: always bypass policy
                "-Command", ps_command,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"reachable": False, "error": f"PowerShell check timed out after {timeout}s"}
    except Exception as exc:
        return {"reachable": False, "error": f"Subprocess error: {exc}"}

    # Non-zero exit usually means the script itself failed
    stdout = result.stdout.strip()
    stderr = result.stderr.strip()

    if result.returncode != 0 and not stdout:
        err = stderr or "PowerShell script failed with no output"
        return {"reachable": False, "error": err[:600]}

    # Parse the last JSON line (script may print progress lines before it)
    lines = [l for l in stdout.splitlines() if l.strip().startswith("{")]
    if not lines:
        err_detail = (stderr or stdout or "No JSON output")[:600]
        return {"reachable": False, "error": err_detail}

    try:
        data = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        return {"reachable": False, "error": f"JSON parse error: {exc} — raw: {lines[-1][:200]}"}

    if "error" in data:
        return {"reachable": False, "error": data["error"][:500]}

    data["reachable"] = True
    return data
