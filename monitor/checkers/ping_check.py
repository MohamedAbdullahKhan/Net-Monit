# =============================================================================
# Net-monit V12.4
# Copyright (c) 2024-2026 Abdullah. All rights reserved.
# Contact: abuabdullah.be@outlook.com
# Unauthorised copying, modification or distribution of this software
# is strictly prohibited without prior written permission from the author.
# =============================================================================
"""
ping_check.py
Cross-platform ICMP ping using the OS's own `ping` binary via subprocess.
This avoids needing raw-socket / root privileges that libraries like
ping3 require on Linux.

Returns: {"reachable": bool, "latency_ms": float|None, "packet_loss_pct": float}
"""
import platform
import re
import subprocess


# A reply line carries "TTL=64" (IPv4, any language) or "time=1ms" / "time<1ms" (IPv6 on Windows has no TTL).
# "Destination host unreachable" / "TTL expired in transit" lines contain neither, so they are NOT counted as replies.
_REPLY_RE = re.compile(r"ttl\s*=\s*\d+|:\s[^\n]*[=<]\s*[\d.]+\s*ms", re.IGNORECASE)
_MS_RE = re.compile(r"[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)


def check(host, timeout_ms=1000, count=4):
    system = platform.system().lower()

    if system == "windows":
        cmd = ["ping", "-n", str(count), "-w", str(timeout_ms), host]
    else:
        # -W is seconds on Linux ping; round up
        timeout_s = max(1, int(round(timeout_ms / 1000)))
        cmd = ["ping", "-c", str(count), "-W", str(timeout_s), host]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=(count * timeout_ms / 1000) + 5
        )
        output = result.stdout or ""
        rc = result.returncode
    except subprocess.TimeoutExpired:
        return {"reachable": False, "latency_ms": None, "packet_loss_pct": 100.0, "error": "ping timed out"}
    except FileNotFoundError:
        return {"reachable": False, "latency_ms": None, "packet_loss_pct": 100.0, "error": "ping binary not found"}
    except OSError as exc:
        return {"reachable": False, "latency_ms": None, "packet_loss_pct": 100.0, "error": f"ping could not run: {exc}"}

    # V11.3 patch 03: count the replies we can SEE instead of trusting one translated "% loss" sentence. On a Windows
    # in another language (or a ping that words its summary differently) the old parser found no "% loss", reported
    # 100 % loss and the device went OFFLINE although every reply was on screen. Windows also counts a gateway's
    # "Destination host unreachable" as a received packet, which made a dead host look alive.
    reply_lines = [ln for ln in output.splitlines() if _REPLY_RE.search(ln)]
    replies = len(reply_lines)
    if replies:
        replies = min(replies, count)
        loss_pct = round((count - replies) * 100.0 / count, 1)
        reachable = True
    else:
        parsed = _parse_packet_loss(output, system)
        # No visible reply. Linux ping exits 0 only if something answered; Windows exits 0 even for "unreachable".
        reachable = (system != "windows" and rc == 0 and parsed is not None and parsed < 100.0)
        loss_pct = 0.0 if reachable else 100.0
    avg_latency = _parse_avg_latency(output, system)
    if reachable and avg_latency is None:
        times = [float(m.group(1)) for m in (_MS_RE.search(ln) for ln in reply_lines) if m]
        if times:
            avg_latency = round(sum(times) / len(times), 2)
    out = {"reachable": reachable, "latency_ms": avg_latency, "packet_loss_pct": loss_pct}
    if not reachable:
        out["error"] = "no reply to %d ping(s)" % count
    return out


def _parse_packet_loss(output, system):
    match = re.search(r"(\d+(?:\.\d+)?)\s*%\s*(?:packet )?loss", output, re.IGNORECASE)
    if match:
        return float(match.group(1))
    return None


def _parse_avg_latency(output, system):
    if system == "windows":
        match = re.search(r"Average\s*=\s*(\d+)\s*ms", output, re.IGNORECASE)
        if match:
            return float(match.group(1))
    else:
        # Linux/Mac: rtt min/avg/max/mdev = 0.123/0.456/0.789/0.012 ms
        match = re.search(r"=\s*[\d.]+/([\d.]+)/[\d.]+", output)
        if match:
            return float(match.group(1))
    return None
