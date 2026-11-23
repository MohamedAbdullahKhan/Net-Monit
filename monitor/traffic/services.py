"""Port -> service detection (Sniffnet's nmap-services table and scoring rule) and service categories."""
import os
from .netutil import OUTGOING, ip, is_broadcast

_DATA = os.path.join(os.path.dirname(__file__), "data")
_SERVICES, _CATEGORIES = {}, {}


def _load():
    if _SERVICES:
        return
    with open(os.path.join(_DATA, "services.txt"), encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or "\t" not in line:
                continue
            name, pp = line.rstrip("\n").split("\t", 1)
            try:
                port, proto = pp.split("/")
                _SERVICES[(int(port), proto.upper())] = name
            except ValueError:
                pass
    with open(os.path.join(_DATA, "categories.txt"), encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or "\t" not in line:
                continue
            name, cat = line.rstrip("\n").split("\t", 1)
            _CATEGORIES[name] = cat.strip()


def lookup(port, proto):
    _load()
    return _SERVICES.get((port, proto))


def category(service):
    _load()
    return _CATEGORIES.get(service, "other") if service not in (None, "?", "-") else "other"


def get_service(key, direction, mine):
    """Name of the service of a connection, '-' (not applicable: no ports) or '?' (unknown).
    Each port gets a score (known service x (3 if well-known <1024 else 1, +1 for the direction bonus)); best score wins,
    ties go to the destination port, exactly like Sniffnet."""
    if key.proto not in ("TCP", "UDP") or key.src_port is None or key.dst_port is None:
        return "-"
    s1, s2 = lookup(key.src_port, key.proto), lookup(key.dst_port, key.proto)
    d = ip(key.dst_ip)
    bonus_dest = direction == OUTGOING or d.is_multicast or is_broadcast(d, mine)

    def score(svc, port, bonus):
        return (3 if port < 1024 else 1) + (1 if bonus else 0) if svc else 0
    a, b = score(s1, key.src_port, not bonus_dest), score(s2, key.dst_port, bonus_dest)
    return (s1 or "?") if a > b else (s2 or "?")
