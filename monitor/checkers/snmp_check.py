# =============================================================================
# Net-monit V12.4
# Copyright (c) 2024-2026 Abdullah. All rights reserved.
# Contact: abuabdullah.be@outlook.com
# Unauthorised copying, modification or distribution of this software
# is strictly prohibited without prior written permission from the author.
# =============================================================================
"""
snmp_check.py
Polls SNMP-capable devices (routers, switches, or servers running an SNMP
agent like net-snmp) for uptime, interface bandwidth utilization, and -
where the agent supports HOST-RESOURCES-MIB - CPU/memory load.

Works with SNMP v1/v2c out of the box (community string). For v3, extend
_get_engine() below with pysnmp's UsmUserData.

Notes on OIDs (these are deliberately the *standard* MIB-II / Host
Resources OIDs so this works across vendors without extra config):
  sysUpTime           1.3.6.1.2.1.1.3.0
  ifDescr             1.3.6.1.2.1.2.2.1.2.<ifIndex>
  ifSpeed             1.3.6.1.2.1.2.2.1.5.<ifIndex>   (bits/sec)
  ifInOctets          1.3.6.1.2.1.2.2.1.10.<ifIndex>
  ifOutOctets         1.3.6.1.2.1.2.2.1.16.<ifIndex>
  hrProcessorLoad     1.3.6.1.2.1.25.3.3.1.2.<cpuIndex>   (Host Resources MIB)

Vendor-specific CPU OIDs (e.g. Cisco's CPMCPUTotal5minRev) can be supplied
per-device in config.yaml under snmp.custom_oids and will be read the same
way, in case hrProcessorLoad isn't supported on a given box.
"""
from pysnmp.hlapi import (
    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, getCmd, nextCmd,
)

OID_SYSUPTIME = "1.3.6.1.2.1.1.3.0"
OID_IFDESCR = "1.3.6.1.2.1.2.2.1.2"
OID_IFSPEED = "1.3.6.1.2.1.2.2.1.5"
OID_IFIN = "1.3.6.1.2.1.2.2.1.10"
OID_IFOUT = "1.3.6.1.2.1.2.2.1.16"
OID_CPU_LOAD = "1.3.6.1.2.1.25.3.3.1.2"

# in-memory store of previous octet counters for bandwidth delta calc
# keyed by f"{device_id}:{ifIndex}" -> (timestamp, in_octets, out_octets)
_prev_counters = {}


def _snmp_get(host, community, version, oid, port=161, timeout=2, retries=1):
    mp_model = 1 if version == 2 else 0
    iterator = getCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=mp_model),
        UdpTransportTarget((host, port), timeout=timeout, retries=retries),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
    )
    error_indication, error_status, error_index, var_binds = next(iterator)
    if error_indication or error_status:
        return None
    for name, value in var_binds:
        return value
    return None


def _snmp_walk(host, community, version, oid, port=161, timeout=2, retries=1, max_rows=64):
    mp_model = 1 if version == 2 else 0
    results = []
    for (error_indication, error_status, error_index, var_binds) in nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=mp_model),
        UdpTransportTarget((host, port), timeout=timeout, retries=retries),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
        lexicographicMode=False,
    ):
        if error_indication or error_status:
            break
        for name, value in var_binds:
            results.append((str(name), value))
        if len(results) >= max_rows:
            break
    return results


def check(device_id, host, community="public", version=2, interfaces=None,
          custom_oids=None, port=161):
    """
    Returns a metrics dict, e.g.:
    {
      "reachable": True,
      "uptime_ticks": 123456,
      "cpu_pct": 12.0,                 # if available
      "bandwidth_pct": 4.3,            # max utilization across watched interfaces
      "interfaces": {"Gi0/1": {"in_mbps": 1.2, "out_mbps": 0.4, "util_pct": 3.1}}
    }
    """
    metrics = {"reachable": False}
    try:
        uptime = _snmp_get(host, community, version, OID_SYSUPTIME, port=port)
        if uptime is None:
            return {"reachable": False, "error": "SNMP agent did not respond"}
        metrics["reachable"] = True
        metrics["uptime_ticks"] = int(uptime)

        # CPU (Host Resources MIB) - best effort, many devices won't support this
        cpu_rows = _snmp_walk(host, community, version, OID_CPU_LOAD, port=port, max_rows=4)
        if cpu_rows:
            values = [int(v) for _, v in cpu_rows if str(v).isdigit()]
            if values:
                metrics["cpu_pct"] = sum(values) / len(values)

        if custom_oids and "cpu_pct" in custom_oids:
            val = _snmp_get(host, community, version, custom_oids["cpu_pct"], port=port)
            if val is not None:
                try:
                    metrics["cpu_pct"] = float(val)
                except (TypeError, ValueError):
                    pass

        # Interface bandwidth utilization
        if_descr_rows = _snmp_walk(host, community, version, OID_IFDESCR, port=port, max_rows=64)
        watched = {}
        for oid_str, descr in if_descr_rows:
            if_index = oid_str.split(".")[-1]
            descr_str = str(descr)
            if interfaces and descr_str not in interfaces:
                continue
            watched[if_index] = descr_str

        interface_metrics = {}
        max_util = 0.0
        now = __import__("time").time()
        for if_index, descr_str in watched.items():
            speed = _snmp_get(host, community, version, f"{OID_IFSPEED}.{if_index}", port=port)
            in_oct = _snmp_get(host, community, version, f"{OID_IFIN}.{if_index}", port=port)
            out_oct = _snmp_get(host, community, version, f"{OID_IFOUT}.{if_index}", port=port)
            if speed is None or in_oct is None or out_oct is None:
                continue
            speed_bps = int(speed) or 1
            in_oct, out_oct = int(in_oct), int(out_oct)

            key = f"{device_id}:{if_index}"
            prev = _prev_counters.get(key)
            _prev_counters[key] = (now, in_oct, out_oct)

            if prev:
                prev_ts, prev_in, prev_out = prev
                dt = max(now - prev_ts, 1)
                # handle counter wrap (32-bit) crudely by ignoring negative deltas
                in_bps = max(0, (in_oct - prev_in) * 8 / dt)
                out_bps = max(0, (out_oct - prev_out) * 8 / dt)
                util_pct = max(in_bps, out_bps) / speed_bps * 100
                interface_metrics[descr_str] = {
                    "in_mbps": round(in_bps / 1_000_000, 2),
                    "out_mbps": round(out_bps / 1_000_000, 2),
                    "util_pct": round(util_pct, 1),
                }
                max_util = max(max_util, util_pct)

        if interface_metrics:
            metrics["interfaces"] = interface_metrics
            metrics["bandwidth_pct"] = round(max_util, 1)

        return metrics

    except Exception as exc:  # noqa: BLE001 - surface as device error, don't crash poller
        return {"reachable": False, "error": str(exc)}
