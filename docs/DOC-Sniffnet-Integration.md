# Sniffnet integration notes (reverse engineering and parity)

Source analysed: Sniffnet 1.5.1 (Rust, iced GUI, libpcap), full source repository. Because it is a complete source tree the analysis was done by reading the code, not by binary tooling. Net-monit V12 re-implements its analysis engine in Python.

## How Sniffnet works (what was reverse engineered)
| Sniffnet part | What it does | Net-monit V12 module |
|---|---|---|
| `networking/capture.rs`, `parse_packets.rs` | capture thread per adapter, 1-second tick, reverse-DNS worker pool, pcap file and IPFIX socket sources | `manager.py`, `capture_linux.py` (native AF_PACKET), `engine.py` |
| `lib/sniffnet-packet-parser` | link types NULL / Ethernet / RAW / LOOP / IPV4 / IPV6 / SLL / SLL2; TCP UDP ICMP ICMPv6 IGMP ARP; VLAN; MAC | `parser.py` |
| `manage_packets.rs` | per-connection accounting, direction rule, traffic type (unicast/multicast/broadcast), local-network test, service scoring, address to look up | `engine.py`, `netutil.py`, `services.py` |
| `types/bogon.rs` | 23 special-purpose address ranges | `netutil.py` |
| `resources/services` | 6,000+ port/service pairs and categories | `services.py`, `data/` |
| `mmdb/*` | country and AS lookup, GeoLite2 + IPinfo readers, fallback to bundled | `geo.py` |
| `types/ip_blacklist.rs` | IP/CIDR list, comments, invalid-list detection | `blacklist.py` |
| `notifications/*` | threshold (bytes/bits/packets per second), favorite, blacklist, sound, remote HTTP, log | `notify.py` |
| `report/*` | search parameters (substring, `=` exact), sort types, 30 per page, CSV report | `api.py` |
| `networking/ipfix/*` | RFC 7011 collector: templates with TTL, delta vs total counters, MACs, VLAN, timestamps | `flows.py` |
| `types/latency.rs` | three pings averaged | uses Net-monit's `ping_check` |
| GUI pages | overview, inspect, connection details, notifications, settings, thumbnail | `templates/traffic.html`, `static/js/traffic.js` |

Key rules copied exactly: traffic direction (loopback decided by ports, own addresses mean outgoing, bogon fallback when the card's addresses are unknown); a broadcast only counts as such for outgoing packets; a service is chosen by scoring each port (known = 1, well-known below 1024 = 3, +1 for the side the direction favours, ties go to the destination port); link-local addresses are always "local"; a country filter matches the ISO code.

## Parity matrix
| Sniffnet feature | Status in V12 |
|---|---|
| Choose adapter, promiscuous capture | **Ported** (Linux native; Windows built-in raw-socket capture, Npcap used if present; macOS via scapy/BPF) |
| Capture filters | **Adapted**: built-in filter for common syntax everywhere, native BPF only for exotic syntax where libpcap exists |
| Overview statistics, live chart, bytes/bits/packets | **Ported** |
| Hosts, services, programs, countries ranking | **Ported** (+ favorites, device links) |
| Connections inspect, search, `=` exact, sort, paging | **Ported** |
| Connection details, ICMP/ARP/IGMP message types, MAC, VLAN | **Ported** |
| Service detection and categories | **Ported** (same table) |
| Country (with flags) and AS of remote hosts, custom .mmdb | **Ported** (GeoLite2 and IPinfo formats, fallback to bundled) |
| Reverse DNS, local network detection, bogon | **Ported** |
| Program (process) names | **Ported** via psutil (needs rights) |
| Favorites | **Ported** |
| Notifications: data threshold, favorite, blacklist, sounds, log | **Ported** |
| Remote notification (webhook) | **Ported** (http/https only) |
| IP blacklist | **Ported** (IP + CIDR, `#`/`;` comments) |
| Latency measurement | **Ported** |
| PCAP save, CSV report | **Ported** |
| Open a pcap file | **Ported** (+ pcapng) |
| IPFIX collector | **Ported**, plus NetFlow v5 and v9 and an exporter allow-list |
| Thumbnail mode | **Ported** as the Mini monitor window |
| IPFIX exporter (forward captured traffic as IPFIX) | Not ported |
| Dropped-packet counter | Not ported |
| 25+ interface languages, theme gallery, window scale | Not ported (Net-monit has its own English UI and theme) |
| Automatic update check | Deliberately not ported (Net-monit makes no outbound calls of its own) |
| **New in Net-monit** | History in SQLite, e-mail/SMS/call/audit alerts, links to monitored devices, auto-start with the service, retention, Linux capture without libpcap, NetFlow v5/v9 |

## Parity tests
Sniffnet's own unit-test cases were ported to `tests/test_traffic_parity.py`: all 27 bogon cases, direction (IPv4, loopback, no-address fallback), traffic type (broadcast/multicast), local-network tests, the service-scoring tests (only-one-valid, well-known wins, direction bonus, multicast/broadcast bonus, TCP vs UDP, not-applicable, unknown), the blacklist fixtures (4 IPs; invalid; 2 IPs + 4 CIDRs; CIDR only; real ranges) and the mmdb tests (IPinfo ASN, location and combined readers, fallback to the bundled database). They use Sniffnet's own fixture files in `tests/data/`.

## Differences you should know
- Python is slower than Rust: about 100,000 packets per second per capture (see the user guide). Use NetFlow/IPFIX for very busy links.
- Directly delivered loopback packets are counted once on Linux (the native capture ignores the duplicate outgoing copy).
- A capture is limited to 200,000 live connections in memory (oldest idle dropped, totals unaffected).
- GeoLite2 data is subject to MaxMind's EULA; see `NOTICE.md`.
