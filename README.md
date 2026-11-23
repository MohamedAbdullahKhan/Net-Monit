# Net-monit V12.4

**Self-hosted network and infrastructure monitoring platform**: devices, servers, websites and now **network traffic**.

Copyright (c) 2024-2026 Abdullah · abuabdullah.be@outlook.com · https://infoxtek.com

## What is new in V12.4: Traffic Analyzer
See which connections, hosts, services, programs and countries use your network, live. It is a Python port of the engine of [Sniffnet](https://github.com/GyulyVGC/sniffnet) built into Net-monit (same Flask + SQLite platform).
- Capture from a network card, read a .pcap/.pcapng file, or collect NetFlow v5/v9/IPFIX from routers and switches.
- Live chart, ranked hosts / services (6,000+) / programs / countries, connection search and details, country and AS lookup, reverse DNS, blacklist, favorites.
- Notifications (traffic above a limit, favorite active, blacklisted address) by sound, e-mail, SMS, voice call, webhook, audit log.
- PCAP export, CSV report, history in SQLite, mini-monitor window, links to your monitored devices.
Guide: `docs/DOC-Traffic-Analyzer-Guide.md`. Technical notes and parity with Sniffnet: `docs/DOC-Sniffnet-Integration.md`.

Everything else from V11.3 and patches 01-08 is included (see `CHANGELOG.md`).

## Core features
- **Monitoring**: Ping, SNMP, SSH, PowerShell, disk/shared folder, HTTP/HTTPS with SSL expiry; 13 device types; custom dashboard views.
- **Alerting**: warning/critical thresholds per device, type, method or globally; L1/L2/L3 escalation; e-mail, SMS, voice call; audit log.
- **Speed test**: built-in WAN test and browser test with live gauge.
- **Network scan**: TCP/UDP port scan and device discovery.
- **Administration**: users (Admin/Viewer), AES-encrypted credentials, backup/restore.
- **Licensing**: 30-day trial, then a free offline Ed25519 key tied to the installation's Device ID and Activation Code.

## Install
**Windows**: right-click `Setup.bat`, Run as administrator. Installs to `C:\NetMonit-V12.4`, service `Net_Monit_V124`, opens http://localhost:5050. Traffic capture needs **no extra software** on Windows (built-in capture); installing Npcap is optional and only adds MAC addresses, VLAN tags and advanced filters.
**Linux**: `chmod +x setup.sh && sudo bash setup.sh`. Installs to `/opt/netmonit-v124`, service `netmonit-v124`, port 5050. The service may capture packets (`CAP_NET_RAW`).
**Manual**: `pip install -r requirements.txt` then `python app.py` (or `NETMON_PORT=5050 python app.py`). Packet capture needs Administrator/root.

## First login
The admin account is `admin@email.com`. Its **random first-run token** is written to `data/FIRST-RUN-ADMIN-TOKEN.txt` on the first start (the file is deleted after you log in). Log in with it and change it in the Admin Panel at once.

## If the Windows service stops right after it starts
1. Open `C:\NetMonit-V12.4\logs\service.log` and read the last lines: the reason is written there.
2. `Address already in use` / `10013` / `forbidden by its access permissions`: Windows reserves some ports (Hyper-V, WSL, Docker). Since V12.0 patch 01 Net-monit then takes the next free port automatically; the port in use is in `data\active_port.txt` and the log. List the reserved ranges with `netsh int ipv4 show excludedportrange protocol=tcp`.
3. `No module named ...`: a Python package did not install. Open Command Prompt as Administrator and run `C:\NetMonit-V12.4\venv\Scripts\python.exe -m pip install -r C:\NetMonit-V12.4\requirements.txt`, read the error, then start the service again.
4. Still stuck: run `C:\NetMonit-V12.4\venv\Scripts\python.exe C:\NetMonit-V12.4\app.py` in an Administrator Command Prompt; the error is printed on screen.

## Upgrading from V11.3
V12 installs side by side. A new install folder has a new Device ID, so request a new free license key (Settings > License). To keep your devices and history copy `config.yaml` and the `data` folder from V11.3 into the V12 folder before the first start.

## Configuration
`config.yaml`: port (`server: port: 5050`), SMTP, polling intervals, speed-test engine. Traffic settings (databases, blacklist, retention, notifications) are set in the Traffic page.

## Project structure (new in V12)
```
monitor/traffic/    capture, parser, engine, flows (NetFlow/IPFIX), geo, blacklist, notify, store, manager, api
templates/traffic.html   static/js/traffic.js   static/css/traffic.css
static/flags  static/img/svc  static/sounds     (from Sniffnet resources, see NOTICE.md)
tests/              traffic tests incl. ports of Sniffnet's own unit tests
licenses/  NOTICE.md  CHANGELOG.md
```

## Support and licensing
abuabdullah.be@outlook.com · https://infoxtek.com. Third-party notices: `NOTICE.md`.
