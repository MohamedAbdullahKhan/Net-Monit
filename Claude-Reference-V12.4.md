# Claude Future Reference — Net-monit V12.4 (complete)

> Upload this file at the start of every new session. Claude has no memory between chats (memory is off), so this file IS the memory. Say "ready for bug fixes" after reading it.

## 0. Owner rules (apply to every output)
1. Straight answers, no politeness padding; correct the user's mistakes bluntly.
2. App work: every output has an incremental **version name and port**; skip ports that are restricted/in use. Current: **complete project V12.4 = port 5050 ALWAYS**; the **upgrade/patch packages keep the installed port (V11.x = 50113)**; demo preview port **5051**.
3. Every response ships this reference file updated (requirements, design, UI, code, flow, payloads, functions, features, fixes, updates).
4. "Setup guide / user guide / manual" = click-by-click guide a non-technical person can follow.
5. Do not re-walk the whole chat history; work from the last output.
6. Be honest about what was NOT tested (no Windows machine in the sandbox).

## 1. Product
Net-monit: self-hosted monitoring (Flask + SQLite + APScheduler). Windows service (pywin32, pythonw) / Linux systemd. Ping, SNMP, SSH, PowerShell, URL, disk checks; alert engine with escalation; email/SMS/call; offline Ed25519 licensing (Device ID tied to **install folder**); speed test; network scan; **V12: Traffic Analyzer** (device capture, pcap, NetFlow v5/v9/IPFIX, hosts/services/programs/countries, favorites, blacklist, notifications, history, mini monitor, offline GeoLite).

## 2. Version lineage
V11.3 → patches 01–08 (= "V11.8", port 50113) → V12.0 (port 50120, Traffic Analyzer) → V12.1 = V12.0-patch-01 (service port fallback; user said it did NOT fix the service) → **V12.2 (port 5050)**.

## 2b. V12.4 (2026-11-23) — CURRENT. User said: next version must be V12.4 (not another 12.2 patch); complete project port 5050 always; patch/upgrade keeps 50113.
Folder `C:\NetMonit-V12.4`, service `Net_Monit_V124` / `netmonit-v124`, `APP_VERSION="12.4"`. Packages: `Net-monit-V12.4.zip` (full), `Net-monit-V11.8-to-V12.4-Upgrade.zip` (upgrader `upgrade_to_v124.py`, accepts V11.x, V12.0–12.4), `Net-monit-Demo-V12.4.zip`, this file.
What the user reported after testing the first V12.2 upgrade (screenshots) and what was found:
1. **About sidebar said "V11.3"** (title said V12.2). CONFIRMED BUG: `base.html` (title, sidebar, footers), `admin.html`, `settings.html` hard-coded "V11.3" since V12.0; my rename missed it. Fixed everywhere. Lesson: after any rename grep templates for the OLD string.
2. **Upgrader said "STOPPED: already V12.2"** when re-run on `C:\NetMonit-V11.3`, so fixes could never be re-applied. FIXED: same-version = repair mode (refreshes files that differ). Also: service discovery scans `sc query` for *monit* services (asks/uses `--service` if several); after restart it checks `/about` contains `V<version>` (an old process keeping the port is restarted, else warned).
3. **WAN speed test: "Download: Cloudflare rate-limited this network (12 x HTTP 429/503)", upload 89.3 Mbps, ping to Cloudflare DXB.** `speedtest_check.py` is byte-identical to V11.3 patched-08 and the default `config.yaml` has no speedtest section in either, so this is NOT a V12 code regression; the TLS-strictness theory from V12.2 patch-01 was WRONG for this report (server answered 429). V12.4: default engine **auto** (Speedtest.net server inside the ISP first → ping not to Cloudflare; Cloudflare second); if Cloudflare gives no download, switch to speedtest-cli instead of showing "--". `speedtest.engine: builtin` restores old behaviour. Original User-Agent `netmonit/11.3` restored (removes a variable). Relaxed `VERIFY_X509_STRICT` kept (certs still verified). Tests: `tests/test_speedtest_fallback.py` (5). NOT verified against real Speedtest.net/Cloudflare (sandbox has no route); requires `speedtest-cli` importable in the install's Python (it is in requirements.txt; upgrader runs pip).
4. **Traffic page: red "A capture is already running. Stop it first." while chip says Idle and no Stop button.** Mechanism found: the page only renders status when `/status` returns OK; if it fails the HTML default "Idle/no Stop" stays; and the server kept `state=running` after a capture died (nothing reset it). Exact trigger on the user's Windows PC (Hyper-V adapter) NOT observed (no logs). V12.4: `Manager._dead_reason()/_fail()/reset()`, `status()` self-heals without blocking, `start()` auto-clears a dead capture, `/status` never 500s (degraded JSON), new `POST /api/traffic/reset` + **Reset capture** button (`#tr-btn-reset`), failed state shown as "Stopped (error)" with reason, status-read failures shown in the red banner. Tests: `tests/test_traffic_selfheal.py` (6) + live API test on a real Linux capture.
Test status V12.4: 88 unit tests OK (+ patch06 26/26, patch07 17/17), demo 26 traffic checks, explanation coverage 210 items, real V11.3-p8 tree upgraded: port stays 50113, About shows V12.4, repair mode OK.
STILL UNVERIFIED: real Windows (service, Npcap, Hyper-V capture, registry/service scan, pip), real speedtest-cli path. If Traffic or speed test still misbehaves ask for: `logs\service.log` tail, Diagnose-SpeedTest window, browser F12 console/network for `/api/traffic/status`.

## 3. V12.2 changes (earlier this session)
| # | Change | Where |
|---|---|---|
| 1 | Default port 5050 (3 defaults: `app.py APP_PORT`, `install_service.py APP_PORT`, `setup_wizard.py`) + all docs/installers/firewall text | whole tree |
| 2 | Folder `C:\NetMonit-V12.2`, service `Net_Monit_V122`, linux `netmonit-v122` (+ `scripts/linux/netmonit-v122.service`) | installers |
| 3 | `portcheck.windows_port_problem(port)`: `netsh excludedportrange` ⇒ hard skip; `netsh dynamicport` ⇒ warning only (so upgraded 50113 installs keep working) | `monitor/portcheck.py` |
| 4 | `setup/Install-Npcap.ps1`: installed→skip; `setup\deps\npcap*oem*.exe`→`/S` silent; else scrape npcap.com for newest, Authenticode check (Nmap/Insecure subject), visible wizard; never blocks setup. Called from `Setup.bat` (before wizard) and both wizards (step 5b) | setup |
| 5 | About page shows live port (`port=APP_PORT` into template) | app.py, about.html |
| 6 | Scanner still labels 50113/50120 as Net-monit | `network_scan.py` |
| 7 | Upgrader V11.8/V12.0/V12.1 → V12.2 keeping port | `upgrade_to_v124.py` |
| 8 | Demo V12.2 incl. Traffic Analyzer simulation | `Net-monit-Demo-V12.4` |
| 9 | New docs: Complete Setup Guide, Demo Guide; Admin/Patching/Windows-Ready updated; docx regenerated | `docs/` |

### Why the V12.0 service failed (UNPROVEN)
No `service.log` was ever captured. Port 50120 (and 50113) lie in the Windows dynamic range 49152–65535; moving to 5050 fixed it for the user. Leading explanation only. If it recurs on 5050: get `logs\service.log`, `netstat -ano | findstr :5050`, `netsh int ipv4 show excludedportrange protocol=tcp`.

### Npcap facts (do not re-promise silent install)
`/S` is OEM-only (paid). Free edition: no silent mode, no redistribution, 5-system licence. Npcap is optional; built-in raw-socket capture works (no MAC/VLAN/loopback). Do not automate clicks.

## 3b. V12.2-patch-01 (2026-11-23) — user report after testing the upgrade
User reported: (1) V11.3 patched-08 WAN speed test works, V12.2 shows no download; (2) About/sidebar still says V11.3.
- (2) CONFIRMED BUG, my fault/inherited: `templates/base.html` (title, sidebar "About Net-monit V11.3", footers), `admin.html`, `settings.html` had hard-coded "V11.3" which V12.0 shipped and my rename missed. Fixed in all templates/CSS/py headers. Upgrader additionally verifies the process answering is really the new version (`/about` contains V12.2), restarts once more, else warns (old process keeping the port).
- (1) `speedtest_check.py`, speed routes in app.py, speedtest.html/js are BYTE-IDENTICAL to V11.3p8, so not a code regression. Cause unproven (no service.log/UI warning received). Leading hypothesis: Python 3.13+ sets `VERIFY_X509_STRICT` by default → TLS-inspecting firewall certs rejected → every stream dies → no download. Patch clears that flag in `_new_connection` (certs still verified). Added `scripts/diagnose_speedtest.py` + `Diagnose-SpeedTest.bat` (DNS/TCP/TLS strict vs relaxed/1 MB download/real test; also prints Python version, proxy). Sandbox had no route to Cloudflare, so the fix itself could not be exercised end-to-end.
- Still needed from user if it persists: Diagnose-SpeedTest output + `logs\service.log` tail + the yellow warning text under the speed result.
- Packaging: patch package `Net-monit-V12.2-patch-01` (apply_patch.py, sha256 manifest, 20 files); full zip, upgrade zip and demo rebuilt with the fix. PATCHES-APPLIED for upgraded installs is rewritten to a single `01 | V12.2-patch-01` line (old V11 lines kept in backup `safety/`).
- Lesson: after any rename, grep templates for the OLD version string; run a visual check of base.html.

## 4. Upgrader design (`upgrade_to_v124.py`)
Args: `--target --service --port --dry-run --force --no-restart --skip-pip --no-npcap --no-auto-rollback --rollback`.
Flow: read APP_VERSION (accept 11.*, 12.0, 12.1) → require patch 08 in PATCHES-APPLIED.txt unless `--force` → find service (registry `HKLM\SOFTWARE\NetMonit-V*` InstallPath match → ServiceName; else guess) → **detect port** in order: `--port`, config.yaml `server.port`, service registry env `NETMON_PORT`, systemd unit, registry `Port`, `data/active_port.txt`, old `app.py` default → verify manifest sha256 of `files/` → backup replaced files + safety copies (config.yaml, monitor.db, PATCHES-APPLIED) to `patch_backups/V12.2-upgrade-<ts>` with ROLLBACK.json → stop service → copy files atomically (never `data/ logs/ venv/ config.yaml secret.key .env *.db`) → **pin port**: regex `NETMON_PORT", \d+` in `app.py` and `install_service.py` → old port → append PATCHES-APPLIED line → pip install -r requirements.txt + import check → Npcap helper → start service → poll `http://127.0.0.1:<port>/` 60 s → fail ⇒ auto rollback (restores files, removes added files and empty dirs, restores config/applied). Excluded from payload: tests, Setup.bat, Uninstall.bat, setup/ (except Install-Npcap.ps1), scripts/linux, scripts/windows, data, logs.
Verified on Linux with a mock V11.3 tree: port stays 50113 (nothing on 5050), rollback restores. NOT verified on Windows (registry, sc.exe, pip, real V11 tree).

## 5. Demo design (`Net-monit-Demo-V12.4`)
Static site `docs/` (landing `index.html`, `demo/*.html` = real V12.2 templates rendered by `seed_capture.py` with the Flask test client; `demo/data/api.json` captured API; `demo/data/traffic.json` = real engine output on synthetic pcap). `demo-shim.js` mocks `/api/*`; `traffic-sim.js` wraps `fetch` for `/api/traffic/*` (status, interfaces, overview, list, connections, detail, latency, favorites, notifications settings/log/test, settings, sessions, start/stop/pause, pcap-upload, blacklist-upload, CSV). State in `sessionStorage["nmdemo_traffic_v1"]`; Reset demo clears it. Guide data `guide-data.js` (traffic page + 6 scenarios), tools in `tools/` (seed_traffic.py, build_traffic_data.py, seed_capture.py, build_demo.py). Tests: `traffic_test.js` 26/26, `coverage_test.js` 209 items (traffic 39/39), plus ui/backend tests.
Synthetic data: 8 local hosts 10.0.1.x, 22 public IPs, 185.220.101.1 blacklisted, backup burst 60–75 s.

## 6. Test status at hand-off
V12.2 app: 77 unittests OK (tests/test_traffic_*, test_service_and_windows) + patch06 26/26 + patch07 17/17; smoke boot port 5050 → 200; `/api/traffic/status` 401 unauthenticated. Upgrader mock test OK. Demo 26/26 + coverage OK.

## 7. Open items / unverified
- Real Windows run of: service start, Npcap script, wizard step 5b, upgrader registry/service code, pip step.
- V11.x source never seen: upgrader assumes `NETMON_PORT", <n>` pattern in app.py/install_service.py and PATCHES-APPLIED.txt lines `NN | ...`.
- Windows dynamic-range warning is log-only.
- Demo: pcap "upload" validates by file name (real app validates content/magic).
- Demo preview port 5051 chosen by Claude (next after 5050).

## 8. Bug-fix workflow for next session
1. Read this file. 2. Ask for the failing log/screenshot only if not provided. 3. Reproduce with the unit tests/Flask test client. 4. Fix, add a test, bump version (V12.3, port: keep 5050 unless owner says otherwise; demo 5052), update this file, rebuild packages (full app, upgrade-from-V11.8 package, demo).

---
# APPENDIX — V12.0 reference (original, port/version renamed to V12.2 where it describes current behaviour)

# Net-monit V12.0 -- Claude Reference (complete memory)

Release: **V12.0**, default port **5050**, service `Net_Monit_V122` / `netmonit-v120`, folder `C:\NetMonit-V12.0` / `/opt/netmonit-v120`. Same platform: Python 3 + Flask, SQLite (`data/monitor.db`), config in `config.yaml`, vanilla JS UI. Baseline = V11.3 + patches 01-08 (all included, no patches on top yet). New folder = new Device ID = new free license key; to keep data copy `config.yaml` + `data/` from V11.3.

## 1. Request of this session
Reverse engineer Sniffnet (sniffnet-main.zip, Rust, v1.5.1) completely and integrate every feature into Net-monit as release 12 on the same platform (SQLite, Python). Slash commands given (REA / impeccable): the source is a complete repository, so it was analysed by reading code (REA's binary tooling is for shipped artifacts); the rea-changelog/ci-tests/analysis/tool-design skills belong to REA's own repo and did not apply; impeccable's craft floor was applied to the new page (Operate mode, incumbent style).

## 2. What Sniffnet does (reverse engineered)
capture thread per adapter with 1 s tick; reverse-DNS pool; parse Ethernet/VLAN/IPv4/IPv6/TCP/UDP/ICMP/ICMPv6/IGMP/ARP (link types NULL, ETHERNET, RAW, LOOP, IPV4, IPV6, SLL, SLL2); per-connection accounting; direction rule; traffic type; local test; service scoring (nmap table, 6k ports, categories); 23 bogon ranges; country/AS via .mmdb (GeoLite2, IPinfo); IP blacklist; favorites (host/service/program); notifications (data threshold bytes|bits|packets per second, favorite, blacklist; sound; remote HTTP; log); search (substring, `=` exact; fields program, domain, country code, AS, protocol, service, ip...) with sort and 30/page; reports CSV/PCAP; latency (3 pings); program lookup by local port; IPFIX collector (RFC 7011 templates with TTL, delta vs total counters, MAC/VLAN/timestamps); thumbnail mode; languages/themes/update check.

## 3. Architecture added in V12 (`monitor/traffic/`)
| File | Role |
|---|---|
| netutil.py | bogon table, direction, traffic type, local/broadcast tests (`Addr` = addr, netmask, broadcast) |
| services.py + data/services.txt, categories.txt | port->service, scoring, category |
| parser.py | `parse(bytes, linktype, wirelen) -> Packet(length, src_mac, dst_mac, vlan, src_ip, dst_ip, src_port, dst_port, proto, msg)` |
| engine.py | `Engine.feed_packet/feed_flow/advance/finish/fill_programs`; `Resolver` (geo now, rDNS in thread), `ProgramLookup` (psutil); conn cap 200k; DataInfo = [in_b, out_b, in_p, out_p] |
| flows.py | `Decoder` NetFlow v5, v9, IPFIX; `Collector` UDP thread with exporter allow-list |
| geo.py | `GeoDb.load(country, asn)` fallback to bundled; `lookup(ip)->(cc, name, asn, as_name)` for GeoLite2 + IPinfo |
| blacklist.py | `IpBlacklist.from_file` (# and ; comments, ips/cidrs/invalid) |
| softfilter.py | BPF-subset compiler (host/net/port/portrange/src/dst/proto/and/or/not/mask/less/greater) |
| capture_linux.py | native AF_PACKET sniffer (loopback once, promisc), `PcapWriter` |
| notify.py | rules, `parse_threshold` (k/M/G), settings, `Notifier` callable, delivery: log, audit, e-mail, SMS, call, webhook |
| store.py | SQLite tables traffic_session, traffic_minute, traffic_conn, traffic_favorite, traffic_notification, traffic_setting |
| manager.py | sources device/pcap/flows, lifecycle, ticker, persistence every 30 s, autostart, filter engine choice |
| api.py | routes below |
UI: `templates/traffic.html`, `static/js/traffic.js`, `static/css/traffic.css`, sidebar link in base.html. Assets from Sniffnet: `static/flags`, `static/img/svc`, `static/sounds`; bundled `data/geo/*.mmdb` (built 2026-07).
app.py: `/traffic` page (admin only), `_traffic_api.register(...)`, `initialize()` marks interrupted sessions, purges by retention, runs autostart.

## 4. API (`/api/traffic/*`, all admin-only; 401/403 otherwise)
GET status | interfaces | overview?top&sort(bytes|packets)&series | list/<hosts|services|programs|countries> | connections?q&app&domain&country(ISO)&asn&proto&service&ip&port&direction&favorite=1&blacklisted=1&sort(bytes|packets|last|first _asc|_desc)&page&page_size | connections/<id> | favorites | notifications/settings | notifications/log?since&limit | settings | sessions | sessions/<id> | export/report.csv?session | export/capture.pcap?session
POST start {type: device|pcap|flows, iface, bpf, export_pcap | path | port, bind, allow[]} | stop | pause {on} | pcap-upload (multipart, <=500 MB, magic checked) | connections/<id>/latency | favorites {kind: host|service|program, value} (DELETE same body) | notifications/settings {volume, webhook, email, sms, call, data{enabled,unit,threshold,sound}, favorite, blacklist} | notifications/test | settings {country_db, asn_db, blacklist, rdns, retention_days, autostart} | blacklist-upload
DELETE notifications/log | sessions/<id>.
Overview payload: active, state, totals{in/out bytes/packets}, last_second, series[{t,in_bytes,out_bytes,in_packets,out_packets}], hosts[], services[], programs[], countries[] (each with in/out/bytes/packets, favorite, host: country, asn, device link).

## 5. Flow of a capture
start -> `Manager.start` (confines pcap path to data/traffic; chooses filter engine) -> source thread -> `parser.parse` -> `Engine.feed_*` -> per-second `_close` -> `Notifier` -> log/sound/channels; ticker + persistence threads; `stop` -> `finish` -> save minutes + top 3000 connections -> session `finished`.

## 6. Decisions, security, fixes found while building
- scapy native BPF silently drops everything without tcpdump -> built-in filter first; native BPF only if libpcap/tcpdump present and never on Linux.
- Linux loopback duplicates -> native sniffer ignores PACKET_OUTGOING on `lo`.
- Session marked `finished` only after final DB save (race found by tests).
- Country filter = ISO code (substring of name matched "US" in "Australia").
- Port 0 silently became 2055 (fixed: explicit validation).
- Hardening: pcap paths confined to data/traffic; upload cap; webhook http/https only; flow exporter allow-list; connection cap; CSV formula-injection guard; all DNS/packet-derived text HTML-escaped; toasts use textContent; Linux unit gets only CAP_NET_RAW.
- Favicon 404 fixed; README first-login text fixed (token is random in data/FIRST-RUN-ADMIN-TOKEN.txt).
- Version bump changed only functional tokens (port 5050, V122 names, "V12.0"); history comments "V11.3 patch NN" untouched. `.docx` guides are still V11.3 (only .md guides were bumped; new guide is .md).

## 7. Tests (all in the package, `tests/`)
66 Python tests (`python -m unittest tests.test_traffic_parity tests.test_traffic_engine tests.test_traffic_api`): ports of Sniffnet's own unit tests and fixtures (bogons, direction, traffic type, services, blacklist, mmdb), parser (all link types), engine, notifications, NetFlow v5/v9/IPFIX incl. garbage, filters, pcap/pcapng import, API (admin-only, search/sort/paging, favorites, notifications, settings, history, CSV, flows, live loopback capture + pcap export), hardening. `tests/ui_traffic.js`: 37 checks on the real page in jsdom. Regression: patch 06/07/08 backend tests 26/17/24 pass on V12. Clean-extraction smoke test: first login, /traffic, assets, live capture via API, 401 without login.
NOT verified: a real browser, Windows (Npcap, service as Local System, Windows capture path through scapy), macOS, real router NetFlow exports, real internet traffic on a physical NIC (loopback was used), programs lookup on Windows.

## 8. Limits
~109k packets/s parse+account per capture (about 570 Mbit/s of 654-byte frames) -> NetFlow for busy links; exotic BPF needs libpcap on Windows/macOS; program names need root/LocalSystem; no dropped-packet counter; no IPFIX exporter; no languages/themes (Net-monit own); no update check (by design). GeoLite2 EULA: check before redistributing outside the organisation (see NOTICE.md).

## 9. Open items
Dashboard card for live traffic; per-device traffic view on the Devices page; sampling for very busy links; Windows validation; refresh the .docx guides; logo SVG sanitising (from the earlier audit); GitHub Pages demo does not include V12.
