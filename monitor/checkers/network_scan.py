# =============================================================================
# Net-monit V12.4 -- Network Scanner (Context-Safe Edition)
# Copyright (c) 2024-2026 Abdullah | Abdullah-InfoXtek.com
# =============================================================================
"""
network_scan.py
Scans a subnet for live hosts using:
  - ICMP ping (subprocess)
  - ARP table lookup (fast, no root needed on local subnet)
  - TCP port scan on common ports to identify device type
  - Reverse DNS lookup for hostname resolution
  - MAC vendor lookup (OUI prefix)
"""
import logging, socket, subprocess, platform, ipaddress
import concurrent.futures, time, re, os

# Standard localized fallback logger to prevent web-context leakage
log = logging.getLogger("monitor.checkers.network_scan")

# Common ports to probe for device-type identification
PORT_PROBES = {
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    # (161/SNMP is UDP-only -- it is probed over UDP now, see UDP_PROBES)
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5000: "Flask/Dev",
    5086: "Net-monit",  # V8.6 -- keep recognizing existing installs on the network
    5087: "Net-monit",  # V8.7
    5088: "Net-monit",  # V8.8
    50100: "Net-monit", # V10.0
    50101: "Net-monit", # V10.1
    50102: "Net-monit", # V10.2
    50103: "Net-monit", # V10.3
    50104: "Net-monit", # V10.4
    50105: "Net-monit", # V10.5
    50106: "Net-monit", # V10.6
    50107: "Net-monit", # V10.7
    50108: "Net-monit", # V10.8
    50109: "Net-monit", # V10.9
    50110: "Net-monit", # V11.0
    50111: "Net-monit", # V11.1
    50112: "Net-monit", # V11.2
    50113: "Net-monit", # V11.3-V11.8 (keep recognizing)
    50120: "Net-monit", # V12.0 / V12.1
    5050: "Net-monit", # V12.4 -- current
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9100: "Printer",
}

# OUI database (first 3 bytes of MAC -> vendor). V8.2: expanded from ~30 to
# ~140 entries -- the old table was missing most Cisco/HP/Dell ranges (the
# most commonly reported gap) plus most consumer router/IoT brands. This is
# still a hand-picked "common vendors" table, not the full IEEE registry
# (50,000+ entries) -- see build_local_subnet_report()/docs for that
# tradeoff. Unmatched MACs still show the MAC itself with vendor "unknown",
# same as before.
# ─────────────────────────────────────────────────────────────────────────────
#  UDP  (V10.7)
#  UDP has no handshake, so "open" cannot be learned by connecting. A UDP port is reported ONLY when
#  the device ANSWERED a real protocol request on it. Silence proves nothing (a firewall, or a service
#  that never replies to a stranger), so silent ports are NOT listed -- the page says so. All probes
#  are small, standard, read-only requests.
# ─────────────────────────────────────────────────────────────────────────────
UDP_PROBES = {
    53:   "DNS",
    69:   "TFTP",
    123:  "NTP",
    137:  "NetBIOS-NS",
    161:  "SNMP",
    1900: "SSDP/UPnP",
    5353: "mDNS",
}


def _tlv(tag, body):
    n = len(body)
    if n < 128:
        length = bytes([n])
    else:
        lb = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(lb)]) + lb
    return bytes([tag]) + length + body


def _snmp_get_request():
    """SNMPv2c GetRequest for sysDescr.0 with community 'public' (read-only)."""
    oid = bytes([0x2B, 6, 1, 2, 1, 1, 1, 0])                                   # 1.3.6.1.2.1.1.1.0
    varbinds = _tlv(0x30, _tlv(0x30, _tlv(0x06, oid) + _tlv(0x05, b"")))
    pdu = _tlv(0xA0, _tlv(0x02, b"\x01") + _tlv(0x02, b"\x00") + _tlv(0x02, b"\x00") + varbinds)
    return _tlv(0x30, _tlv(0x02, b"\x01") + _tlv(0x04, b"public") + pdu)


def _udp_payloads():
    import struct
    return {
        # root NS query: every DNS server answers it (an answer or REFUSED -- either proves DNS is listening)
        53:   (struct.pack(">HHHHHH", 0x4E4D, 0x0100, 1, 0, 0, 0) + b"\x00" + struct.pack(">HH", 2, 1),
               lambda d: len(d) >= 12 and d[:2] == b"NM" and bool(d[2] & 0x80)),
        # read request for a file that does not exist -> ERROR packet (comes from a NEW source port; recvfrom copes)
        69:   (b"\x00\x01netmonit-probe.nonexistent\x00octet\x00",
               lambda d: len(d) >= 4 and d[:2] in (b"\x00\x05", b"\x00\x03")),
        123:  (b"\x1b" + b"\x00" * 47,
               lambda d: len(d) >= 48 and (d[0] & 0x07) in (4, 5)),
        # NetBIOS node-status query for "*"
        137:  (struct.pack(">HHHHHH", 0x4D4E, 0, 1, 0, 0, 0) + b"\x20" + b"CK" + b"A" * 30 + b"\x00" + struct.pack(">HH", 0x21, 1),
               lambda d: len(d) >= 12 and d[:2] == b"MN" and bool(d[2] & 0x80)),
        161:  (_snmp_get_request(),
               lambda d: len(d) > 10 and d[0] == 0x30 and b"\xa2" in d[:48]),
        1900: (b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n',
               lambda d: d[:5] == b"HTTP/" or d[:7] == b"NOTIFY "),
        5353: (struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0) + b"\x09_services\x07_dns-sd\x04_udp\x05local\x00" + struct.pack(">HH", 12, 0x8001),
               lambda d: len(d) >= 12 and bool(d[2] & 0x80)),
    }


_UDP_PAYLOADS = _udp_payloads()


def _udp_probe(ip: str, port: int, timeout: float = 1.0, proto: int | None = None) -> bool:
    """
    True only if `ip` sent back a VALID answer to the `proto` request (default: the well-known
    port itself; `proto` lets tests aim a probe at a different port). Unconnected socket + recvfrom:
    some services (TFTP, SSDP) answer from a different source port, so replies are matched by the
    sender's IP and by content, not by port. An ICMP "port unreachable" (an OSError on some
    platforms) simply means closed -> False.
    """
    entry = _UDP_PAYLOADS.get(proto if proto is not None else port)
    if entry is None:
        return False
    payload, valid = entry
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(payload, (ip, port))
        end = time.monotonic() + timeout
        while True:
            left = end - time.monotonic()
            if left <= 0:
                return False
            sock.settimeout(left)
            try:
                data, addr = sock.recvfrom(4096)
            except OSError:                                # timeout, or ICMP unreachable surfaced as an error
                return False
            if addr[0] == ip and valid(data):
                return True
    except OSError:
        return False
    finally:
        sock.close()


OUI_PREFIXES = {
    # VMware / virtualization
    "00:50:56": "VMware", "00:0c:29": "VMware", "00:05:69": "VMware",
    "00:1c:14": "VMware", "00:16:3e": "Xen/Citrix", "08:00:27": "VirtualBox",
    "02:42:":   "Docker", "00:15:5d": "Microsoft (Hyper-V)",
    # Raspberry Pi
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi", "28:cd:c1": "Raspberry Pi",
    "d8:3a:dd": "Raspberry Pi",
    # Apple
    "3c:97:0e": "Apple", "a4:c3:f0": "Apple", "f0:18:98": "Apple",
    "ac:de:48": "Apple", "00:1e:c2": "Apple", "28:e0:2c": "Apple",
    "3c:15:c2": "Apple", "40:6c:8f": "Apple", "68:96:7b": "Apple",
    "7c:6d:62": "Apple", "88:66:5a": "Apple", "a8:5c:2c": "Apple",
    "b8:53:ac": "Apple", "d0:03:4b": "Apple", "f4:5c:89": "Apple",
    # Dell
    "00:1e:c9": "Dell", "14:18:77": "Dell", "00:21:9b": "Dell",
    "b8:2a:72": "Dell", "18:03:73": "Dell", "24:6e:96": "Dell",
    "34:17:eb": "Dell", "5c:f9:dd": "Dell", "84:2b:2b": "Dell",
    "a4:1f:72": "Dell", "b0:83:fe": "Dell", "d4:be:d9": "Dell",
    "f8:b1:56": "Dell", "00:14:22": "Dell", "00:26:b9": "Dell",
    # HP / HPE
    "00:1f:29": "HP", "00:25:b3": "HP", "3c:d9:2b": "HP",
    "94:57:a5": "HP", "a0:1d:48": "HP", "d8:9d:67": "HP",
    "9c:8e:99": "HP", "00:0e:7f": "HP", "00:23:7d": "HP",
    "00:17:a4": "HP", "b4:99:ba": "HPE", "e8:39:35": "HPE",
    "94:18:82": "HPE (Aruba)", "24:de:c6": "Aruba Networks",
    "6c:f3:7f": "Aruba Networks", "d8:c7:c8": "Aruba Networks",
    # Cisco (many ranges -- this vendor alone has hundreds of OUIs; these
    # are the ones most commonly seen on office/SMB networks)
    "00:1d:60": "Cisco", "00:1e:13": "Cisco", "00:1f:27": "Cisco",
    "00:0c:85": "Cisco", "00:14:69": "Cisco", "00:17:59": "Cisco",
    "00:18:19": "Cisco", "00:1a:2f": "Cisco", "00:1b:54": "Cisco",
    "00:1c:0e": "Cisco", "00:21:55": "Cisco", "00:22:90": "Cisco",
    "00:23:04": "Cisco", "00:24:97": "Cisco", "00:25:45": "Cisco",
    "58:97:1e": "Cisco", "68:bc:0c": "Cisco", "70:81:05": "Cisco",
    "84:78:ac": "Cisco", "88:5a:92": "Cisco", "b0:aa:77": "Cisco",
    "c8:00:84": "Cisco", "e0:2f:6d": "Cisco", "f8:66:f2": "Cisco",
    "00:07:7d": "Cisco (Linksys)", "00:0f:66": "Cisco (Linksys)",
    "58:6d:8f": "Cisco (Linksys)", "c0:56:27": "Cisco (Linksys)",
    "00:1a:70": "Cisco Meraki", "88:15:44": "Cisco Meraki",
    "0c:8d:db": "Cisco Meraki", "e0:cb:bc": "Cisco Meraki",
    # Networking / routers
    "fc:72:96": "TP-Link", "50:d4:f7": "TP-Link", "c4:6e:1f": "TP-Link",
    "14:cc:20": "TP-Link", "18:d6:c7": "TP-Link", "a0:f3:c1": "TP-Link",
    "74:da:38": "Edimax", "00:90:a9": "Western Digital",
    "00:26:18": "Netgear", "20:e5:2a": "Netgear", "a0:21:b7": "Netgear",
    "00:14:6c": "Netgear", "2c:30:33": "Netgear", "84:1b:5e": "Netgear",
    "9c:3d:cf": "Netgear", "c0:3f:0e": "Netgear",
    "c8:3a:35": "Tenda", "00:1a:2b": "Ubiquiti", "04:18:d6": "Ubiquiti",
    "f0:9f:c2": "Ubiquiti", "24:a4:3c": "Ubiquiti", "44:d9:e7": "Ubiquiti",
    "68:d7:9a": "Ubiquiti", "78:8a:20": "Ubiquiti", "b4:fb:e4": "ASUSTek",
    "10:bf:48": "ASUSTek", "f8:32:e4": "ASUSTek", "1c:87:2c": "ASUSTek",
    "2c:56:dc": "ASUSTek", "38:2c:4a": "ASUSTek", "04:d9:f5": "ASUSTek",
    "00:1d:d9": "MikroTik", "4c:5e:0c": "MikroTik", "6c:3b:6b": "MikroTik",
    "b8:69:f4": "MikroTik", "cc:2d:e0": "MikroTik", "e4:8d:8c": "MikroTik",
    "00:04:96": "Extreme Networks", "00:e0:2b": "Extreme Networks",
    "00:01:30": "Juniper", "00:05:85": "Juniper", "3c:8a:b0": "Juniper",
    "5c:5e:ab": "Juniper", "78:19:f7": "Juniper", "f4:cc:55": "Juniper",
    "d4:9d:c0": "D-Link", "1c:7e:e5": "D-Link", "84:c9:b2": "D-Link",
    "00:1c:f0": "D-Link", "00:22:b0": "D-Link", "00:26:5a": "D-Link",
    "e0:69:95": "Belkin", "94:44:52": "Belkin", "b4:75:0e": "Belkin",
    # Storage / NAS
    "00:11:32": "Synology", "00:24:1a": "wistron/Synology", "00:11:d9": "QNAP",
    "24:5e:be": "QNAP", "00:08:9b": "QNAP",
    # Printers
    "00:1b:a9": "HP (Printer)", "3c:d9:2b:00": "HP (Printer)",
    "00:00:74": "Ricoh", "00:26:73": "Ricoh", "00:01:e6": "HP LaserJet",
    "00:20:6b": "Epson", "64:eb:8c": "Epson", "00:26:ab": "Brother",
    "00:80:77": "Brother", "30:05:5c": "Brother",
    # IoT / smart home
    "18:fe:34": "Espressif (ESP8266/32 IoT)", "24:0a:c4": "Espressif (ESP8266/32 IoT)",
    "3c:71:bf": "Espressif (ESP8266/32 IoT)", "a4:cf:12": "Espressif (ESP8266/32 IoT)",
    "cc:50:e3": "Espressif (ESP8266/32 IoT)", "68:c6:3a": "Amazon (Echo/Alexa)",
    "44:65:0d": "Amazon", "84:d6:d0": "Amazon", "fc:65:de": "Sonos",
    "5c:aa:fd": "Sonos", "94:9f:3e": "Sonos", "b8:e9:37": "Google (Nest/Chromecast)",
    "f4:f5:d8": "Google (Nest/Chromecast)", "d0:73:d5": "Nest Labs",
    "18:b4:30": "Nest Labs", "64:16:66": "Nest Labs",
    # Phones / mobile
    "00:1a:11": "Google", "3c:5a:b4": "Google", "f8:8f:ca": "Google",
    "8c:85:80": "Samsung", "e8:50:8b": "Samsung", "5c:0a:5b": "Samsung",
    "d0:22:be": "Samsung", "f0:5a:09": "Samsung", "cc:07:ab": "Huawei",
    "00:e0:fc": "Huawei", "10:47:80": "Huawei", "4c:54:99": "Huawei",
    "88:36:6c": "Xiaomi", "50:8f:4c": "Xiaomi", "64:09:80": "Xiaomi",
    "34:ce:00": "LG Electronics", "10:68:3f": "LG Electronics",
    # Servers / other enterprise
    "00:0d:3a": "Microsoft", "00:17:fa": "Microsoft", "00:03:ff": "Microsoft",
    "b0:35:9f": "Microsoft (Surface)", "1c:1b:0d": "Microsoft (Surface)",
    "00:1b:21": "Intel", "00:1f:c6": "Intel", "3c:a9:f4": "Intel",
    "a4:34:d9": "Intel", "00:e0:4c": "Realtek", "52:54:00": "QEMU/KVM",
    "00:10:18": "Broadcom", "00:0a:f7": "Broadcom",
    "ac:1f:6b": "Super Micro Computer", "0c:c4:7a": "Super Micro Computer",
    "00:25:90": "Super Micro Computer",
}

IS_WIN = platform.system() == "Windows"


def _ping_one(ip: str, timeout_ms: int = 1000) -> bool:
    """Return True if host responds to ping."""
    try:
        if IS_WIN:
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), str(ip)]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), str(ip)]
        
        # List-form subprocess call (not shell=True) -- ip always comes from
        # ipaddress.ip_network().hosts(), never raw user input, but the
        # list form means there's no shell-interpolation risk either way.
        r = subprocess.run(cmd, capture_output=True, timeout=5, env=os.environ.copy())
        return r.returncode == 0
    except Exception:
        return False


def _tcp_port_open(ip: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((str(ip), port), timeout=timeout):
            return True
    except Exception:
        return False


def _get_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except Exception:
        return ""


def _read_arp_table() -> dict:
    """
    V8.2: bulk-read the OS's *entire* ARP/neighbor table in one shot,
    instead of shelling out per-host. Two real bugs this fixes:

    1. Timing: the old code ran `arp -a <ip>` for a single host
       immediately after pinging *that* host -- if the host answered via
       the TCP-port fallback instead of ICMP (some devices/firewalls
       block ping), or the OS just hadn't committed the ARP entry yet,
       the lookup could run before the cache was populated and silently
       come back empty. Reading the table once, after every host in the
       subnet has already been contacted, gives the OS's ARP cache the
       maximum possible time to settle.
    2. Missing binary: many current Linux distributions (server images
       especially) no longer ship the legacy `arp` command (net-tools)
       by default -- only the modern `ip` command (iproute2) is
       guaranteed present. A missing binary made every single MAC on
       Linux come back blank. `ip neighbor` is tried first on Linux, with
       `arp -n` only as a fallback for older systems that still have it.

    Returns: {ip: "aa:bb:cc:dd:ee:ff"} for every entry currently in the
    table, resolved or not-yet-resolved entries excluded.
    """
    table = {}
    clean_env = os.environ.copy()
    try:
        if IS_WIN:
            # `arp -a` (no IP filter) dumps every interface's full table in
            # one call -- built into every Windows install, no extra tools.
            out = subprocess.check_output(
                ["arp", "-a"], timeout=6, stderr=subprocess.DEVNULL, env=clean_env
            ).decode(errors="ignore")
            for line in out.splitlines():
                m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})", line)
                if m:
                    table[m.group(1)] = m.group(2).replace("-", ":").lower()
        else:
            try:
                out = subprocess.check_output(
                    ["ip", "neighbor", "show"], timeout=6,
                    stderr=subprocess.DEVNULL, env=clean_env
                ).decode(errors="ignore")
                for line in out.splitlines():
                    m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+.*?lladdr\s+([0-9a-fA-F:]{17})", line)
                    if m and "FAILED" not in line and "INCOMPLETE" not in line:
                        table[m.group(1)] = m.group(2).lower()
            except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass
            if not table:
                # Fallback for older distros that still ship net-tools
                # but not iproute2 (rare, but cheap to cover).
                try:
                    out = subprocess.check_output(
                        ["arp", "-n"], timeout=6, stderr=subprocess.DEVNULL, env=clean_env
                    ).decode(errors="ignore")
                    for line in out.splitlines():
                        m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-fA-F:]{17})", line)
                        if m:
                            table[m.group(1)] = m.group(2).lower()
                except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    pass
    except Exception as exc:
        log.debug("ARP/neighbor table read failed: %s", exc)
    return table


def _vendor_from_mac(mac: str) -> str:
    if not mac:
        return ""
    prefix6 = mac[:8]  # xx:xx:xx
    prefix4 = mac[:5]  # xx:xx
    for prefix, vendor in OUI_PREFIXES.items():
        if prefix6.startswith(prefix) or prefix.startswith(prefix4):
            return vendor
    return ""


def _identify_device_type(open_ports: list[int], udp_ports: list[int] | None = None) -> str:
    ports = set(open_ports)
    udp = set(udp_ports or [])
    if 3389 in ports:      return "Windows Server/Desktop"
    if 22 in ports and 80 in ports: return "Linux Server"
    if 22 in ports:        return "Linux/Unix Host"
    if 445 in ports:       return "Windows Host"
    if 161 in udp:         return "Network Device (SNMP)"      # V10.7: it answered an SNMP request over UDP, where SNMP really lives
    if 80 in ports or 443 in ports:  return "Web Server"
    if 161 in ports:       return "Network Device (SNMP)"
    if 23 in ports:        return "Network Device (Telnet)"
    if 9100 in ports:      return "Network Printer"
    if 3306 in ports:      return "Database Server"
    if 5086 in ports or 5087 in ports or 5088 in ports or 50100 in ports or 50101 in ports or 50102 in ports or 50103 in ports or 50104 in ports or 50105 in ports or 50106 in ports or 50107 in ports or 50108 in ports or 50109 in ports or 50110 in ports or 50111 in ports or 50112 in ports or 50113 in ports or 50120 in ports or 5050 in ports: return "Net-monit Server"
    if ports or udp:       return "Network Device"
    return "Host"


def scan_subnet(
    subnet: str,
    port_scan: bool = True,
    max_workers: int = 64,
    ports: list | None = None,
    udp_scan: bool | None = None,
) -> dict:
    """
    Scan entire subnet for live hosts, then enrich each one with
    hostname/MAC/vendor/open-port data.

    V10.0: rewritten from nested per-host thread pools (an outer pool of
    up to `max_workers` -- user-selectable up to 256 in the UI -- each
    ALSO spinning up its own inner 4-worker pool, so up to 4x that many
    real OS threads, each ping additionally spawning its own subprocess)
    to three flat phases below, each with exactly one appropriately-sized
    pool. The nested version was the confirmed root cause of two reported
    bugs that turned out to share one cause: (1) wildly inconsistent host
    counts on repeat scans of the same subnet (e.g. 34 real hosts reading
    back as 3, then 24, then 31) -- spawning up to 256 simultaneous ping
    subprocesses plus 4x that many threads created enough OS-level
    contention that genuinely-alive hosts would spuriously miss their
    tight response-time windows, differently on every run; and (2)
    MAC/vendor/hostname coming back empty more often than they should --
    under that same contention the whole scan could take long enough that
    early hosts' ARP cache entries had gone stale by the time the bulk
    ARP-table read happened at the end. Fixing the concurrency model fixes
    both: hosts are checked more reliably, and the scan finishes in a
    tighter, more predictable window.

    Ping-phase concurrency is capped independently of whatever `max_workers`
    the caller requests, since it's the only subprocess-spawning phase;
    the two lighter phases (raw TCP connects, no subprocess) can safely
    use the full requested value.
    """
    if ports is None:
        ports = list(PORT_PROBES.keys())
    if udp_scan is None:
        udp_scan = port_scan          # V10.7: UDP is checked whenever the port scan is, unless told otherwise

    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError as e:
        return {"error": str(e), "hosts_found": [], "total_scanned": 0}

    if net.num_addresses > 65536:
        return {"error": "Subnet too large. Maximum /16 (65536 hosts).",
                "hosts_found": [], "total_scanned": 0}

    all_hosts = [str(h) for h in net.hosts()]
    total     = len(all_hosts)
    t0        = time.perf_counter()

    ping_workers  = min(max_workers, 40)   # subprocess-spawning -- kept modest regardless of request
    tcp_workers   = max_workers            # plain socket connects -- cheap, safe to scale with the request
    probe_workers = max(8, max_workers // 2)

    try:
        log.info(f"Scanning {subnet} ({total} hosts, port_scan={port_scan}, "
                 f"ping_workers={ping_workers}, tcp_workers={tcp_workers})")
    except Exception:
        pass

    # ---- Phase 1: ping sweep, every host, one flat pool -----------------
    ping_alive = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=ping_workers) as ex:
        futures = {ex.submit(_ping_one, ip): ip for ip in all_hosts}
        done, not_done = concurrent.futures.wait(futures, timeout=90)
        for f in done:
            try:
                if f.result():
                    ping_alive.add(futures[f])
            except Exception:
                pass
        for f in not_done:
            f.cancel()

    # ---- Phase 2: TCP fallback, only for hosts ping didn't confirm ------
    # Some devices/firewalls block ICMP but still have a port open. Each
    # host's three candidate ports are now checked CONCURRENTLY rather
    # than one after another -- same accuracy, a fraction of the time.
    remaining = [ip for ip in all_hosts if ip not in ping_alive]
    tcp_alive = set()
    if remaining:
        with concurrent.futures.ThreadPoolExecutor(max_workers=tcp_workers) as ex:
            futures = {}
            for ip in remaining:
                for p in (80, 443, 22):
                    futures[ex.submit(_tcp_port_open, ip, p, 0.6)] = ip
            done, not_done = concurrent.futures.wait(futures, timeout=30)
            for f in done:
                try:
                    if f.result():
                        tcp_alive.add(futures[f])
                except Exception:
                    pass
            for f in not_done:
                f.cancel()

    alive_ips = ping_alive | tcp_alive
    results = {
        ip: {"ip": ip, "hostname": "", "mac": "", "vendor": "",
             "open_ports": [], "udp_ports": [], "port_details": [], "device_type": "Host", "reachable": True,
             "latency_ms": None}
        for ip in alive_ips
    }

    # ---- Phase 3: hostname + port probing, alive hosts only -------------
    # The expensive per-host work now only runs against the (usually much
    # smaller) confirmed-alive set, instead of spinning up a 4-worker pool
    # for every dead IP in the subnet too.
    if alive_ips:
        with concurrent.futures.ThreadPoolExecutor(max_workers=probe_workers) as ex:
            host_futures = {ex.submit(_get_hostname, ip): ip for ip in alive_ips}
            port_futures = {}
            if port_scan:
                for ip in alive_ips:
                    for p in ports:
                        port_futures[ex.submit(_tcp_port_open, ip, p, 0.4)] = (ip, p)

            udp_futures = {}
            if udp_scan:
                for ip in alive_ips:
                    for p in UDP_PROBES:
                        udp_futures[ex.submit(_udp_probe, ip, p, 1.0)] = (ip, p)

            all_futures = list(host_futures) + list(port_futures) + list(udp_futures)
            done, _ = concurrent.futures.wait(all_futures, timeout=60)
            for f in done:
                if f in host_futures:
                    ip = host_futures[f]
                    try:
                        results[ip]["hostname"] = f.result() or ""
                    except Exception:
                        pass
                elif f in port_futures:
                    ip, p = port_futures[f]
                    try:
                        if f.result():
                            results[ip]["open_ports"].append(p)
                    except Exception:
                        pass
                elif f in udp_futures:
                    ip, p = udp_futures[f]
                    try:
                        if f.result():
                            results[ip]["udp_ports"].append(p)
                    except Exception:
                        pass

    for r in results.values():
        r["open_ports"]  = sorted(r["open_ports"])          # TCP, unchanged meaning
        r["udp_ports"]   = sorted(r["udp_ports"])           # UDP ports that ANSWERED a probe
        r["port_details"] = (
            [{"port": p, "proto": "tcp", "service": PORT_PROBES.get(p, "")} for p in r["open_ports"]] +
            [{"port": p, "proto": "udp", "service": UDP_PROBES.get(p, "")} for p in r["udp_ports"]])
        r["device_type"] = _identify_device_type(r["open_ports"], r["udp_ports"])

    found = list(results.values())

    # ---- MAC/vendor backfill from the OS ARP/neighbor table -------------
    # A short settle delay + one retry pass covers the common case where a
    # handful of hosts resolve into the ARP cache a moment after everything
    # else already has. With the flat phases above, the whole scan now
    # finishes in a tighter window, so entries are far less likely to have
    # gone stale by the time this runs than under the old nested design.
    if found:
        time.sleep(0.4)
        arp_table = _read_arp_table()
        missing = [h for h in found if h["ip"] not in arp_table]
        if missing:
            time.sleep(0.6)
            arp_table.update(_read_arp_table())
        for h in found:
            mac = arp_table.get(h["ip"], "")
            h["mac"]    = mac
            h["vendor"] = _vendor_from_mac(mac)

    found.sort(key=lambda h: ipaddress.ip_address(h["ip"]))
    duration = round(time.perf_counter() - t0, 1)

    try:
        log.info(f"Scan complete: {len(found)}/{total} hosts alive in {duration}s")
    except Exception:
        pass

    return {
        "subnet":        str(subnet),
        "hosts_found":   found,
        "total_scanned": total,
        "hosts_alive":   len(found),
        "duration_sec":  duration,
        "port_scan":     port_scan,
        "udp_scan":      udp_scan,
        "tcp_probed":    sorted(ports) if port_scan else [],
        "udp_probed":    sorted(UDP_PROBES) if udp_scan else [],
    }


def get_local_subnets() -> list[str]:
    """Auto-detect local network subnets safely."""
    subnets = []
    clean_env = os.environ.copy()
    try:
        hostname = socket.gethostname()
        addrs    = socket.getaddrinfo(hostname, None, socket.AF_INET)
        for addr in addrs:
            ip = addr[4][0]
            if not ip.startswith("127."):
                parts = ip.split(".")
                subnets.append(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")
    except Exception:
        pass

    try:
        if IS_WIN:
            out = subprocess.check_output(
                ["ipconfig"], stderr=subprocess.DEVNULL, timeout=5, env=clean_env
            ).decode(errors="ignore")
            ips = re.findall(r"IPv4.*?:\s*([\d.]+)", out)
        else:
            out = subprocess.check_output(
                ["ip", "-o", "-4", "addr", "show"], stderr=subprocess.DEVNULL, timeout=5, env=clean_env
            ).decode(errors="ignore")
            ips = re.findall(r"inet\s+([\d.]+)/(\d+)", out)
            subnets = []
            for ip, prefix in ips:
                if not ip.startswith("127."):
                    try:
                        net = ipaddress.ip_interface(f"{ip}/{prefix}").network
                        subnets.append(str(net))
                    except Exception:
                        pass
            return list(dict.fromkeys(subnets))
            
        for ip in ips:
            if not ip.startswith("127.") and not ip.startswith("169."):
                parts = ip.split(".")
                subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                if subnet not in subnets:
                    subnets.append(subnet)
    except Exception:
        pass
    return list(dict.fromkeys(subnets)) or ["192.168.1.0/24"]