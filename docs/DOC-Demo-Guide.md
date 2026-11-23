# Net-monit V12.4 — Live Demo: how to use it, present it and publish it

The demo is a static website (no server, no database). It runs the **real V12.4 pages** with simulated data inside your browser. Nothing is sent anywhere. Pressing **Reset demo** (bottom bar) clears everything you changed.

## 1. Try it
- **Online:** `https://<your-github-user>.github.io/<repo>/` → landing page → **Open the live demo**.
- **On your PC:** extract the package, open Command Prompt in the `docs` folder and run `python -m http.server 5051`, then open `http://localhost:5051/`. (Port 5051 is the demo's preview port; V12.4 itself is 5050.) Opening the files by double-click does **not** work: browsers block the data files.

## 2. The bottom bar (every demo page)
| Control | What it does |
|---|---|
| **Scenario** | Opens the right page and shows a yellow hint with the steps. 15 scenarios. |
| **Explain mode** | Turn on, then click any button, field or card: a panel explains it. |
| **Page guide** | A drawer listing every option on the current page with its explanation. Searchable. |
| **Reset demo** | Restores the original data. |

## 3. Scenarios
Dashboard tour · Make an alert fire · Add a device · Refused threshold values · Check a website · Run a speed test · Scan the network · Activate a license · See the Viewer role · **Traffic Analyzer tour** · **Start a live capture** · **Analyse a capture file** · **Favorites and alerts** · **Blacklist demo** · **Filter connections**.

## 4. Traffic Analyzer in the demo (what is real, what is simulated)
| Part | In the demo |
|---|---|
| Page, buttons, tabs, lists, graph, detail panel, notification log, sounds | **Real V12.4 code** |
| The opening analysis (hosts, services, programs, countries, 400 connections, history) | **Real V12.4 engine output** from a synthetic 30,465-packet office capture (generated, no real company data) |
| Live capture after you press Start | **Simulated** traffic (rates vary, bursts every ~47 s) spread over the same hosts |
| Capture file | The name is checked, then the same analysis opens; the real app reads your file's content |
| NetFlow | Simulated collector; no router needed |
| Notifications | Real rules and sounds against the simulated traffic; email/SMS/call are not sent |
| Blacklist | Host 185.220.101.1 is blacklisted in the demo; uploading any file just counts its lines |

### Walk-through (5 minutes, good for presenting)
1. Scenario **Traffic Analyzer tour**. Explain mode on. Hover the graph, read **Hosts** (flags, AS owners, device names), **Services**, **Programs**, **Countries**.
2. **Connections** → search `chrome` → click a row → **Measure latency**. Try `=https`, then **More** → country `US`, direction `outgoing`. Press **CSV**.
3. **Start** a live capture (choose Ethernet0). Watch totals grow. Click a star on a host.
4. **Notifications** → data limit `300k` → Save → hear the sound when it trips; read the log.
5. **Pause**, **Stop**, open **History**, click the new session.
6. Open **Settings**: country/AS databases, blacklist upload, reverse DNS, start automatically.
7. Sign out (account menu) and try `traffic.html` as Viewer → access refused, as in the real app.

## 5. Publish on GitHub (free)
1. Create a public repository, for example `net-monit-demo`.
2. Upload the **contents** of this package (`docs/`, `tests/`, `README.md`, etc.) — on github.com use **Add file → Upload files**, drag everything, **Commit**.
3. Repository **Settings → Pages → Build and deployment → Source: Deploy from a branch → Branch: main, folder: /docs → Save**.
4. After about a minute the site is at `https://<user>.github.io/<repo>/`. `docs/.nojekyll` is included so the folders are served as they are.
5. Update later: replace files in `docs/` and commit.

## 6. Run the tests (optional)
```
cd docs && python -m http.server 5051          (terminal 1)
npm i jsdom                                    (terminal 2, in the package folder)
node tests/traffic_test.js     26 checks: Traffic API behaviour, validation, role block
node tests/coverage_test.js    every explanation matches a real element on every page (209 items)
node tests/ui_test.js          explain mode, guide drawer, scenarios
node tests/backend_test.js     devices, thresholds, alerts, speed test, scan, license
```
jsdom has no canvas or audio, so a gauge/graph/`play()` message there is expected.

## 7. Honest limits
No real ping/SNMP/SSH/PowerShell/scan/email/SMS/voice. No real packet capture in a browser. Speed-test "PC speed" is the only real measurement. Data is invented, except the Traffic analysis which is real engine output on synthetic packets.
