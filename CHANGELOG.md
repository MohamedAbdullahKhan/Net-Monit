# Net-monit changelog

## V12.4 (2026-11-23) — complete project, port 5050 (upgrades of V11.x keep their old port, e.g. 50113)

Everything in V12.2 and V12.2-patch-01, plus:

- **Fix:** every visible "V11.3" label (sidebar "About" link, page title, footers) now says V12.4.
- **Fix: Traffic Analyzer stuck on "A capture is already running. Stop it first." with no Stop button.** A capture that died by itself (adapter disabled, raw socket closed by Windows, collector crash) stayed marked "running" on the server. Now: a dead capture is detected, shown as "Stopped (error)" with the reason, and never blocks the next Start. The status call can no longer fail silently (the page used to show "Idle" when it did), and a new **Reset capture** button / `POST /api/traffic/reset` clears any stuck state.
- **Fix: WAN speed test with "--" download ("Cloudflare rate-limited this network, 12 x HTTP 429/503").** Default engine is now `auto`: a nearby Speedtest.net server inside your ISP first (ping is no longer measured to Cloudflare), Cloudflare second. If Cloudflare answers but refuses the download, the test switches to the Speedtest.net engine instead of showing "--". `speedtest.engine: builtin` in config.yaml restores the old behaviour. The relaxed TLS-strictness setting from patch 01 stays (certificates are still verified).
- **New:** `Diagnose-SpeedTest.bat` shows step by step where a speed test fails.
- **Upgrader:** can be re-run on an install that already says V12.x (it refreshes files instead of "STOPPED: already ..."), finds the Windows service by scanning for Net-monit services, and verifies that the process answering on the port really is the new version.

## V12.2 patch 01 (2026-11-23)

- **Fix:** sidebar link, page title and footers still said "Net-monit V11.3" (inherited from V12.0). Now V12.2 everywhere; About shows the live version, port and patches.
- **Fix (probable):** WAN speed test with no download. The speed-test code is identical to V11.3, so the cause is the environment. Python 3.13+ enables strict certificate checking, which fails behind firewalls/proxies that inspect HTTPS; the test now relaxes only that strictness (certificates are still verified).
- **New:** `Diagnose-SpeedTest.bat` shows step by step where a speed test fails (DNS, TCP, TLS strict/relaxed, 1 MB download, the real test).
- Upgrader: after the restart it checks that the answering process is really V12.2 (an old process holding the port is restarted or reported) instead of only checking that something answers.

## V12.2 (includes V12.0 + patch 01)

- **Default port is now 5050** everywhere (app, service, installers, firewall rule, docs). The old 50113/50120 sit in the Windows dynamic port range (49152-65535) that Windows hands to outgoing connections and that Hyper-V/WSL/Docker reserve; on affected machines the service started and stopped at once. Port 5050 fixed it on the reporting machine; the root cause was inferred from that result, not from a captured error.
- **Port pre-flight** (`monitor/portcheck.py`): ports inside a Windows *excluded* range are skipped automatically; ports inside the *dynamic* range are logged as a warning. Existing installs keep whatever port they use (the upgrader pins it).
- **Npcap step in setup** (`setup/Install-Npcap.ps1`, called by Setup.bat and both wizards): already installed -> skip; OEM installer in `setup\deps` -> fully silent; otherwise downloads the newest free installer from npcap.com, verifies its signature and opens Npcap's own wizard. Npcap's free edition has no silent mode and may not be redistributed, so a 100% silent install is only possible with the paid OEM edition. Npcap stays optional: built-in capture works without it.
- About page shows the port actually in use.
- Folder `C:\NetMonit-V12.2`, service `Net_Monit_V122` / `netmonit-v122`.
- New: `V11.8-to-V12.2` upgrade package (keeps data, config, license, service name and port).

## V12.0 patch 01

- **Fix: the Windows service stopped right after starting.** The service now checks that its port can really be bound. Windows reserves port blocks (Hyper-V, WSL, Docker) and a bind there fails with error 10013; Net-monit now logs the reason, takes the next free port and records it in `data\active_port.txt` (the installer reads it, opens the right URL and adds the firewall rule for it).
- **Fix: the Traffic Analyzer's automatic start and old-data cleanup never ran under the Windows service** (the service does not call `initialize()`). They run now.
- **Windows capture without Npcap**: built-in capture with raw sockets (needs Administrator / Local System only). Npcap, when installed, is used automatically for MAC addresses, VLAN tags and advanced filters. Npcap's free edition cannot be redistributed or installed silently, so it is not bundled.
- The interface list no longer depends on scapy (works on a bare Windows install).
- Installer: verifies that every required Python package imports after `pip install` and says clearly if one is missing or the service did not stay running.

## V12.0 (new major release, port 50120)

**New: Traffic Analyzer** (sidebar > Traffic). Everything Sniffnet's engine does, built into Net-monit on the same Flask + SQLite + Python platform.

- Capture from a network card (native on Linux, built-in on Windows with no extra software, scapy on macOS), from a .pcap/.pcapng file, or collect NetFlow v5 / v9 / IPFIX from routers and switches.
- Live chart (incoming above the line, outgoing below), totals, ranked hosts, services, programs and countries; bytes / bits / packets.
- Connections: search, exact match with `=`, filters (program, host, country, AS, protocol, service, IP, port, direction, favorites, blacklisted), sorting, paging, detail panel with latency.
- Service detection (6,000+ ports) with categories, country and AS of every remote host (GeoLite2 or IPinfo databases), reverse DNS, program names, bogon and local-network detection.
- Favorites, an IP blacklist, notifications (traffic above a limit, a favorite active, a blacklisted address contacted) with sounds, e-mail, SMS, voice call, webhook, audit log and a notification log.
- Save packets to .pcap, CSV report, capture history in SQLite, mini-monitor window, automatic start with the service, retention setting.
- Traffic hosts are linked to your monitored Net-monit devices.

**Included from V11.3 patches 06-08**: context-aware "apply to" buttons that really apply, much faster saving (bulk notify loading, no full re-poll after a device save, batched database writes), custom dashboard views and a dashboard that remembers its tab, Save / Save & close / Cancel in every editing window.

**Fixes**: missing favicon (404 on every page); README login instructions (the first-run token is random, in `data/FIRST-RUN-ADMIN-TOKEN.txt`).

**Upgrade notes**: V12 installs side by side (`C:\NetMonit-V12.0`, service `Net_Monit_V120`, Linux `/opt/netmonit-v120`, port 50120). Like earlier major releases a new install folder has a new Device ID, so request a new free license key. To keep your devices and history, copy `config.yaml` and the `data` folder of V11.3 into the V12 folder before the first start (the database is extended automatically). Windows live capture needs no extra software and a service running as Local System (Npcap is optional); Linux needs `CAP_NET_RAW` (the supplied systemd unit grants it).
