"""Choose a TCP port the web server can really bind.

Windows reserves blocks of ports (Hyper-V, WSL2, Docker, 'excluded port ranges') and a normal bind() on them fails with
WinError 10013 even though no program uses the port. A service that cannot bind its port used to stop at once. Now it logs the
reason and takes the next free port."""
import os
import re
import socket
import subprocess
import sys


def can_bind(port, host="0.0.0.0"):
    """-> (True, '') or (False, reason)"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if os.name != "nt":
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)         # Linux/macOS: ignore TIME_WAIT leftovers
        s.bind((host, port))
        return True, ""
    except OSError as e:
        return False, f"{e.strerror or e} (errno {getattr(e, 'winerror', None) or e.errno})"
    finally:
        s.close()


def _netsh(args):
    try:
        r = subprocess.run(["netsh"] + args, capture_output=True, text=True, timeout=8,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return r.stdout or ""
    except Exception:
        return ""


def windows_port_problem(port):
    """V12.4: -> (hard, message). hard=True when Windows has the port in an excluded (reserved) range: bind() will fail.
    hard=False with a message when the port lies in the Windows dynamic (ephemeral) range 49152-65535 by default:
    it works, but Windows may hand it to an outgoing connection or reserve it after a reboot (Hyper-V/WSL/Docker),
    which is why 5050 is the default since V12.4. ('', False) = no problem or not Windows."""
    if os.name != "nt":
        return False, ""
    for m in re.finditer(r"^\s*(\d+)\s+(\d+)", _netsh(["int", "ipv4", "show", "excludedportrange", "protocol=tcp"]), re.M):
        lo, hi = int(m.group(1)), int(m.group(2))
        if lo <= port <= hi:
            return True, f"port {port} is inside the Windows excluded port range {lo}-{hi} (reserved by Hyper-V/WSL/Docker)"
    out = _netsh(["int", "ipv4", "show", "dynamicport", "tcp"])
    a, b = re.search(r"Start Port\s*:\s*(\d+)", out), re.search(r"Number of Ports\s*:\s*(\d+)", out)
    if a and b and int(a.group(1)) <= port < int(a.group(1)) + int(b.group(1)):
        return False, f"port {port} is inside the Windows dynamic port range; Windows may take it for outgoing connections. Prefer a port below 49152 (default 5050)"
    return False, ""


def pick_port(preferred, host="0.0.0.0", span=60):
    """-> (port, note). note is '' when the preferred port works, otherwise the reason it was skipped."""
    hard, warn = windows_port_problem(preferred)
    if hard:
        ok, why = False, warn
    else:
        ok, why = can_bind(preferred, host)
    if ok:
        return preferred, warn
    for p in range(preferred + 1, preferred + 1 + span):
        if not windows_port_problem(p)[0] and can_bind(p, host)[0]:
            return p, f"port {preferred} is not available ({why}); using {p}"
    raise OSError(f"No free port found between {preferred} and {preferred + span}. Last error on {preferred}: {why}")


def remember(base_dir, port):
    """data/active_port.txt = the port the dashboard really listens on (read by the installer and shown in the logs)."""
    try:
        d = os.path.join(base_dir, "data"); os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "active_port.txt"), "w", encoding="utf-8") as f:
            f.write(str(port))
    except OSError:
        pass
