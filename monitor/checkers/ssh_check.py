# =============================================================================
# Net-monit V12.4
# Copyright (c) 2024-2026 Abdullah. All rights reserved.
# Contact: abuabdullah.be@outlook.com
# Unauthorised copying, modification or distribution of this software
# is strictly prohibited without prior written permission from the author.
# =============================================================================
"""
ssh_check.py
Polls Linux/Unix hosts over SSH for CPU / memory / disk utilization, for
boxes that don't run an SNMP agent. Uses plain POSIX tools (top, free, df)
that exist on virtually every distro, so no agent install is required on
the target - just SSH access for a (read-only) monitoring user.

Auth: prefer an SSH key (key_path) over a password. Either way, create a
dedicated low-privilege "monitor" user on each target rather than using root.
"""
import paramiko
import re


def check(host, port=22, username="monitor", password=None, key_path=None, timeout=8):
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

        # %Cpu(s) line from top, the Mem line from free, and root disk usage from df
        command = (
            "top -bn1 | grep -i '%Cpu' ; "
            "free | grep -i '^Mem' ; "
            "df -P / | tail -1"
        )
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode(errors="ignore")
        err = stderr.read().decode(errors="ignore")

        metrics = {"reachable": True}

        idle_match = re.search(r"([\d.]+)\s*id", output)
        if idle_match:
            metrics["cpu_pct"] = round(100 - float(idle_match.group(1)), 1)

        mem_match = re.search(r"^Mem:\s+(\d+)\s+(\d+)", output, re.MULTILINE)
        if mem_match:
            total, used = int(mem_match.group(1)), int(mem_match.group(2))
            if total > 0:
                metrics["memory_pct"] = round(used / total * 100, 1)

        disk_match = re.search(r"(\d+)%\s+/\s*$", output, re.MULTILINE)
        if disk_match:
            metrics["disk_pct"] = float(disk_match.group(1))

        if len(metrics) == 1 and err:
            return {"reachable": False, "error": err.strip()[:300]}

        return metrics

    except paramiko.AuthenticationException:
        return {"reachable": False, "error": "SSH authentication failed"}
    except Exception as exc:  # noqa: BLE001
        return {"reachable": False, "error": str(exc)}
    finally:
        client.close()
