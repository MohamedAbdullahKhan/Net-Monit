# Net-monit V12.4 — Setup Guide

This guide walks through installing Net-monit V12.4 on a Windows or Linux machine. It's written for whoever is doing the install — usually an IT admin — and assumes no prior familiarity with the product.

## Before you start

- **One machine on your network** to host Net-monit (Windows 10/11/Server, or a modern Linux distribution). This machine will do the monitoring — it needs network access to whatever you want to monitor, outbound SMTP access for email alerts, outbound HTTPS for SMS/voice gateway alerts, and outbound HTTPS to speed.cloudflare.com if end users will use the browser-based "Test Your PC Speed" speed test.
- **Port 5050** must be free on that machine (this is Net-monit V12.4's port — note the port number *is* the version, so this differs from your previous version if you're upgrading, e.g. V8.8, which used 5088).
- **Python 3.9 or newer** (3.11 recommended; the installer checks this on Windows and downloads Python 3.11 if it is missing; most Linux distributions already have it).
- **A license key** — see "Activation" below. You can also start a trial without one.

## Windows installation

> **Prefer a click-by-click version?** See `DOC-Setup-Windows-Ready.md` (installer, written for non-technical users) or `DOC-Setup-Python-Manual.md` (run it yourself with Python). `DOC-App-Workflow.md` explains how the whole app works.

1. **Copy the Net-monit V12.4 folder** to the machine (any location — the installer will offer to move it to `C:\NetMonit-V12.4` by default).
2. **Run `Setup.bat`** as Administrator. This launches the graphical setup wizard.
3. The wizard checks for Python, installs any missing pip dependencies, and asks where to install (default `C:\NetMonit-V12.4`).
4. If a previous Net-monit service is already running on this machine (e.g. you're upgrading from V8.8), the wizard **stops it first**, before making any changes — this ordering matters and is deliberate, so don't run the old and new versions' installers in parallel.
5. The wizard registers a Windows Service named `Net_Monit_V124` (via `sc.exe`), pointed at `pythonw.exe` so no console window stays open.
6. Once registration completes, the service starts automatically and the wizard opens your browser to `http://localhost:5050`.
7. **First-run:** you'll land on the Activation screen if no license/trial is active yet (see Activation below), otherwise straight to a login screen with a seeded default admin account — check the wizard's final screen, it displays the generated default admin password once, so **note it down before closing the wizard**.

### Alternate Windows path: PowerShell installer

If you prefer scripting the install (e.g. for imaging multiple machines), `setup/Setup-Windows.ps1` performs the same steps non-interactively. Run it from an elevated PowerShell prompt; it accepts the same install-directory parameter as the GUI wizard.

## Linux installation

1. Copy the Net-monit V12.4 folder to the target machine, e.g. `/opt/netmonit-v124-src` (temporary — the installer relocates it).
2. From that folder, run:
   ```bash
   sudo ./setup.sh
   ```
3. This installs Python dependencies (via `pip`), copies the application to `/opt/netmonit-v124`, and installs a **systemd service** named `netmonit-v124` (`scripts/linux/netmonit-v124.service`).
4. The installer enables and starts the service:
   ```bash
   sudo systemctl enable netmonit-v124
   sudo systemctl start netmonit-v124
   ```
5. Check it's running:
   ```bash
   sudo systemctl status netmonit-v124
   ```
6. Open `http://<this-machine's-IP>:5050` from any browser on the network.

## Activation

On first launch you'll see the Activation screen if there's no valid license yet. You have two options:

- **Start a trial** -- no key needed, time-limited (30 days), gets you into the full product immediately to evaluate it.
- **Enter a license key** -- step by step:
  1. On the Activation screen, find **Device ID** and **Activation Code** (each is 16 letters and digits). They are made from this specific machine, which is *why* a key only works on one installation. Click **Copy Both Values**.
  2. Send both values to your vendor (email is fine -- they are not secret).
  3. Your vendor sends back a **license key**. It is long: it starts with **NM1-** and is about **127 characters** including dashes. It looks like `NM1-1ZEPS-DV3QJ-PM5QC-...` (shortened here).
  4. **Copy the whole key and paste it** into the box on the Activation screen (sign in as an Admin first -- the box is hidden for other users). Do not type it. Spaces, line breaks and lower case are ignored.
  5. Click **Activate License**. The badge turns green and says *Licensed*.
  - If it says the key is incomplete or invalid: you pasted only part of it, or the key was made for a different Device ID / Activation Code. Ask the vendor to re-check the two values you sent. If it says it is an **old-format key**, it was issued before V11.0 and you need a new one.
  - (The Product Owner Guide that explains *how* to generate keys is a separate, vendor-only document -- it isn't part of this package.)

## Optional: make the WAN speed test measure against a nearby server

**Why you might want this.** "Test WAN Speed" measures the route from the Net-monit machine to a test server, and by default that server is Cloudflare's. The result is therefore "how fast is my connection *to Cloudflare*". On some internet providers that route is slower than the provider's own network, which is why a site like speedtest.net — it tests against a server inside your provider — can show a higher number for the same line. Net-monit always tells you what it measured against: the Speed Test page shows the server name and the round-trip time in the status line, and in the **Target** column of the log. If you want the number to reflect a closer server, point Net-monit at one.

**What you need.** The web address of a *LibreSpeed-compatible* test server close to you: one your own IT team runs (LibreSpeed is free, open-source software that installs on any small server), or one your provider offers. The address is the folder that contains the two files `garbage.php` and `empty.php` — for example `https://speedtest.example.ae/`.

**Steps on Windows**

1. Open **File Explorer** and go to the Net-monit install folder (by default `C:\NetMonit-V12.4`).
2. Right-click the file `config.yaml`, choose **Open with**, then **Notepad**.
3. Near the top, find the block that starts with `# speedtest:` (it sits just above the line `server:`).
4. Delete the `#` and the single space after it at the start of these lines — keep every other space exactly as it is, because the indentation matters:
   ```
   speedtest:
     targets:
       - name: "HQ Dubai"
         url: "https://speedtest.example.ae/"
   ```
   Replace `HQ Dubai` with any name you like, and the `url` with your server's address.
5. Choose **File → Save**. Do not rename the file.
6. Restart the service: press the **Windows key**, type `services.msc`, press **Enter**, find **Net_Monit_V124** in the list, right-click it and choose **Restart**.
7. Open the **Speed Test** page and click **Test WAN Speed**. The status line should now show your server's name and its round-trip time, and the **Target** column in the log shows it too.

**Steps on Linux**

1. Open the file: `sudo nano <install folder>/config.yaml` (the install folder is where you ran `setup.sh`).
2. Remove the `#` and one space from the start of the `speedtest:` lines shown above, change the name and address, save (Ctrl+O, Enter) and exit (Ctrl+X).
3. Restart: `sudo systemctl restart netmonit-v124`.

**Good to know**

- You can list several servers; Net-monit tries them in the order listed, and uses Cloudflare if none of them answers. A result always says which one it used.
- The file uses **spaces, never tabs**. If the service will not start after an edit, a tab or a missing space is the usual cause — the log file in the install folder's `logs/` folder names the line.
- `engine: builtin` (under `speedtest:`) tells Net-monit to skip the optional speedtest-cli library and always use its own test. The default, `auto`, tries speedtest-cli first and falls back to the built-in test.

## Upgrading to V12.4

If you're upgrading an existing V8.8 install, or any install from V10.0 to V11.2, rather than doing a fresh install, the steps are the same either way -- only which old service/port/directory you're moving from changes.

1. **License key.** A key is tied to the **Activation Code** of one installation, and that code includes the install folder. V12.4 installs into its own new folder, so the new installation shows a new Device ID / Activation Code and needs its own key. Copy both values from the new installation's Activation screen and request the key (free; see "Activation" above). Keys from **V10.9 and earlier** never work in V11.x (see item 10). The 30-day trial is available while you wait.
2. **Your existing data is safe.** No database columns were removed or renamed this release. Devices, alert history, and settings all carry over. Saved thresholds keep working unchanged.
3. Because the port and service name change with every release (5088 -> 50100 -> 50101 -> 50102 -> 50103 -> 50104 -> 50105 -> 50106 -> 50107 -> 50108 -> 50109 -> 50110 -> 50111 -> 50112 -> 5050 and `Net_Monit_V88` -> `Net_Monit_V100` -> `Net_Monit_V101` -> `Net_Monit_V102` -> `Net_Monit_V103` -> `Net_Monit_V104` -> `Net_Monit_V105` -> `Net_Monit_V106` -> `Net_Monit_V107` -> `Net_Monit_V108` -> `Net_Monit_V109` -> `Net_Monit_V110` -> `Net_Monit_V111` -> `Net_Monit_V112` -> `Net_Monit_V124`), V12.4 installs **side-by-side** with whatever you had before rather than replacing it in place -- the Windows/Linux installers will stop and remove the *old* service as part of installing the new one (see step 4 of the Windows section above), but the install directories are different (`C:\\NetMonit-V8.8`, `C:\\NetMonit-V10.0`, `C:\\NetMonit-V10.1`, `C:\\NetMonit-V10.2`, `C:\\NetMonit-V10.3`, `C:\\NetMonit-V10.4`, `C:\\NetMonit-V10.5`, `C:\\NetMonit-V10.6`, `C:\\NetMonit-V10.7`, `C:\\NetMonit-V10.8`, `C:\\NetMonit-V10.9`, `C:\\NetMonit-V11.0` vs. `C:\\NetMonit-V11.1`), so keep your old install directory around until you've confirmed V11.1 is working, then remove it manually.
4. **Copy your `data/monitor.db` file** from the old install directory into the new one before first starting the V12.4 service, if you want to carry over devices, alert history, and settings. Alternatively, use the **Admin Panel -> Backup & Restore** export/import feature from your old install before upgrading, and restore it once V11.1 is up -- this is the recommended path. If you added a `speedtest:` section to `config.yaml`, copy those lines across too.
5. Update any firewall rules that reference your old port (5088, 50100, 50101, 50102, 50103, 50104, 50105, 50106, 50107, 50108, 50109, 50110, 50111, 50112) to also allow 5050.
6. If you're coming from V8.8 specifically: your admin account's access token upgrades automatically to a stronger storage format (PBKDF2, not the older plain SHA-256) the next time that account successfully logs in -- nothing you need to do, it happens transparently on sign-in. If you're already on V10.0 or later, this already happened.
7. **Check you are really on the new version.** After installing, the browser tab title and the About page must say **V12.4**, and the address must end in **:5050**. Every version keeps its own port, so an old bookmark (for example one ending in `:50112`) opens the *old* service, not the one you just installed. Also, Python does not pick up changed files while a service is running -- if you ever copy new files over an existing install by hand, restart the service afterwards.
8. **What V12.4 changes**
   - **No change to how monitoring works.** V12.4 is the "ready to publish" release: new step-by-step guides, `DOC-Setup-Windows-Ready.md`, `DOC-Setup-Python-Manual.md` and `DOC-App-Workflow.md`, and a live demo web page for the GitHub repository.
   - **`config.yaml` no longer contains the two sample monitors** ("Test Router" and a Google check). A fresh install starts with an empty monitor list.
   - Version, port and service name move to V12.4 / 5050 / `Net_Monit_V124`.
9. **What V11.2 changed (still applies)**
   - **Threshold tables are short and clean.** Each metric now shows only its name, unit, *Enabled*, *Warning* and *Critical* boxes. The explanation (what it means, which direction raises an alert, the allowed minimum and maximum, the recommended values, what a healthy value looks like) is behind a small **!** button beside the metric name. **Point at the ! and read it for as long as the pointer stays there; click it to keep the box open, and close it with the X** (or press Esc).
   - **"Per-device / per-site threshold overrides" is grouped into two collapsible categories, Devices and Sites**, and each monitor's active thresholds are shown as compact chips instead of one long line. Bold = overridden for that monitor.
   - **Apply to all devices / Apply to all sites (Settings > Thresholds).** Each category has its own button. It saves the values shown as the new default **and removes every per-device (or per-site) override of those metrics**, so every monitor of that category uses them. Wait times set per metric are kept. It asks for confirmation first.
   - **Apply wait & cooldown to all (Settings > Escalation, and inside every Notify window).** Three buttons: *All devices & sites*, *Devices only*, *Sites only*. They copy the **Alert trigger mode / wait seconds** and the **Repeat-alert cooldown** shown on screen to the chosen monitors. Emails, SMS/call numbers, escalation levels and thresholds are **not** changed. In "Wait to confirm" mode, a per-metric wait override on a monitor is removed so the new wait really applies.
   - **Settings > Monitors shows "Healthy"** instead of the raw word "ok" in the Status column.
   - Everything below still applies.
10. **What V11.1 changed (still applies)**
   - **Website (site) thresholds are now correct.** Settings > Thresholds and the per-device **Notify** window used to show the device metrics (CPU, memory, disk ...) for a website. A website now shows **its own five metrics**: *Response time (ms)*, *SSL certificate expires in (days)*, *SSL handshake time (ms)*, *DNS lookup time (ms)* and *TCP connect time (ms)*. Every row shows its unit, which direction raises an alert, the **allowed minimum and maximum**, the **recommended warning and critical values** and what a healthy value looks like. A **Fill recommended values** button sets them all in one click.
   - **SSL days left works in the opposite direction:** it alerts when the number of days *falls below* the threshold (default: warning at 30 days, critical at 7).
   - **Impossible values are refused with a clear message** (for example a warning that is higher than the critical, or a number outside the allowed range), on every screen and on the server.
   - **Alert messages are readable:** "Response time (ms)" with the value and the threshold including their units, instead of "response ms".
   - **A site's own "Warn if slower than (ms)" and SSL warn-days now set that site's warning threshold** (they used to produce a note only). A value set in Settings > Thresholds still wins. If you filled in "Warn if slower than" on any site, that site can now raise a warning alert when it is slower than that.
   - **SMS and voice-call alerts now work.** Since V8.5, any alert for a device that had SMS or call numbers raised an internal error, so those alerts never went out. Fixed.
   - **Setup wizard:** if the optional "Install Python" step fails, the wizard now shows the error instead of spinning forever.
11. **What V11.0 changed (still applies)**
   - **License keys are now cryptographically signed and cannot be forged.** Before V11.0 every copy of Net-monit contained the secret needed to *make* keys, so anyone able to read the program files could issue themselves a key. V11.0 contains only a *public* verification key: it can check a key but can never create one. The private key exists only in the vendor's License Key Generator.
   - **Old keys (the short `XXXXX-XXXXX` ones) are no longer accepted.** Your vendor must issue a new key for each installation. The new key is long -- it starts with `NM1-` and is about 127 characters including dashes -- so **copy and paste it, do not type it**. The Activation page accepts it with spaces, line breaks or lower case.
   - **A key is still tied to one installation:** it only works with the exact Device ID and Activation Code shown on that installation's Activation screen. The Activation Code includes the install folder, so a new install folder (a new version) needs a new key.
   - If an upgraded installation still holds an old key, the Activation page says so plainly ("the key saved on this installation was issued before V11.0") instead of just "Invalid".
   - Nothing else about how you use the product changes.

12. **What V10.9 changed (still applies)**
   - **WAN test uses the built-in test again (fixes "only a text line, no gauge").** V10.8 let the optional `speedtest-cli` library run, which has no live gauge and chose a server in Frankfurt. The built-in test is now the default: live needle (green download, purple upload), nearest Cloudflare data centre, works as a service. To go back to the old library, put `speedtest:` / `engine: auto` in `config.yaml` (not recommended).
   - **HTTP 429 handled.** When the test server rate-limits you, the test waits, uses fewer connections and says so; it no longer reports "21 connection errors" or a bare "HTTP 429". Wait 5-10 minutes between tests. Applies to both "Test WAN Speed" and "Test Your PC Speed".
   - Everything from V10.8 (service start-up fix) still applies.

13. **What V10.8 changed (still applies)**
   - **Fixes "service installs but the dashboard does not open until I run `app.py` by hand".** The Windows service has no console window, and some code assumed one. V10.8 gives the service proper "null" streams once, at the very start (`install_service.py`), logs every startup failure to `logs\service.log`, and stops (so Windows restarts it) if the web server thread dies instead of sitting there doing nothing.
   - **`speedtest-cli` no longer breaks the service.** The optional third-party library needs a console (`'NoneType' object has no attribute 'fileno'`). V10.8 checks for that and goes straight to the built-in test when running as a service. **If you edited `speedtest_check.py` yourself to fix that error, do not copy your edit into V10.8** -- use the shipped file as it is.
   - **(V10.8 note, resolved in V10.9)** the built-in WAN test could show "HTTP 429" or many connection errors when run repeatedly; see "What V10.9 changes".
   - If you only use V10.7 features, V10.8 changes nothing else.

14. **What V10.7 changed (still applies)**
   - **WAN speed test accuracy (fixes a V10.6 problem).** V10.6 could report a much lower speed than the connection really had — the slower the line, the bigger the shortfall — and a short test could run far longer than it should. Fixed: each step now ends on time and measures only while data is flowing. Upload is now counted at the receiving end (the old way over-read on slow lines). A step that cannot be measured now shows "--" instead of a made-up 0.
   - **The test tells you what it measured against.** The status line and a new **Target** column show the server and the round-trip time (for Cloudflare, which data centre answered). "Test WAN Speed" measures the route to that server, so on some providers it reads lower than speedtest.net, which tests against a server inside the provider. To measure against a nearer server, see *Optional: make the WAN speed test measure against a nearby server*, above.
   - **A new gauge.** The needle now follows the live speed through download (**green**), drops back, and follows upload (**purple**), with a coloured arc behind it. The scale is non-linear (0–1000) like speedtest.net's, so slow lines are readable too. The panel says **Showing: WAN** (or **Your PC**), and the log's Source badges read **WAN** and **PC**.
   - **PC speed test.** Upload is counted the same accurate way, latency is the typical (median) round trip, the ISP name is now filled in, and a direction that failed is stored as unknown rather than 0.
   - **Network Scan now shows TCP *and* UDP.** Every open port is labelled with its type (`22/tcp` in blue, `161/udp` in orange). A new **Check UDP ports too** option sends small standard requests (DNS, TFTP, NTP, NetBIOS, SNMP "public", UPnP, mDNS) and lists a UDP port only when the device *answers*. You can filter the results by port number, service name, `tcp` or `udp`.
   - **Safer display.** Host names, MAC/vendor names and other text discovered on your network are now shown as plain text, so a hostile device name cannot inject code into the page.

   If you don't use the Speed Test or Network Scan pages, V10.7 changed nothing else about how you use the product.

## Updating with a patch

Small updates (bug fixes, small features) come as a patch zip that replaces only the changed files and keeps your port, service name, data and license. See `DOC-Patching-Guide.md`.

## Uninstalling

- **Windows:** run `Uninstall.bat` as Administrator (stops and removes the `Net_Monit_V124` service, offers to delete the install directory and data).
- **Linux:** run `scripts/linux/uninstall.sh` as root (stops, disables, and removes the systemd unit; offers to delete `/opt/netmonit-v124`).

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Browser can't reach `http://localhost:5050` | Service isn't running — check `sc query Net_Monit_V124` (Windows) or `systemctl status netmonit-v124` (Linux). Also confirm nothing else is using port 5050. |
| Activation says "Invalid license key" | Paste the **whole** key (starts with `NM1-`, about 127 characters with dashes). It must have been made for the exact Device ID and Activation Code shown on this screen -- a different install folder, a different PC or a reinstall gives a different Activation Code, so the vendor must issue a key for the new values. |
| Activation says "old-format key" / "New license key required" | The key was issued before V11.0. Those keys are no longer accepted. Send the Device ID and Activation Code from this screen to your vendor and enter the new key. |
| I set a threshold and it says "must be lower than critical" or "outside the allowed range" | The warning must be on the *milder* side of the critical: lower for time/percent metrics, **higher** for *SSL certificate expires in (days)*. Use **Fill recommended values** to start from sensible numbers. |
| A website alert says "SSL certificate expires in ... below 30 days" | The certificate is close to expiry. Renew it. To be told earlier or later, change the warning in Settings > Thresholds > Website metrics. |
| Service is installed but the dashboard will not open; it only works when I run `python app.py` | See **"Service installed but dashboard not opening"** below. The shipped V12.4 files fix the known cause (an edited `speedtest_check.py`, or a service with no console). Use the V12.4 files unmodified. |
| WAN test shows only "Complete ... via speedtest-cli" and the gauge does not move | You are on a build that lets the `speedtest-cli` library run (V10.8) or `config.yaml` has `engine: auto`. Use V12.4 (default `builtin`) and remove `engine: auto`. |
| Speed test shows "HTTP 429" or "connection errors" | The test server (Cloudflare) is rate-limiting repeated tests from your public IP. Wait 5-10 minutes and run one test. V12.4 slows down and says "rate-limited"; a figure shown with that message can read low. |
| Installer says Python not found (Windows) | Install Python 3.10+ from python.org and re-run `Setup.bat`. |
| Service starts then immediately stops | Check the log file in the install directory's `logs/` folder for the actual startup error — usually a missing pip dependency or a `config.yaml` syntax error. |
| Alert emails never arrive | Check Settings → SMTP is configured and saved, and that the host machine can reach your SMTP server on its configured port (some networks block outbound 25/587 by default). |
| SMS/call alerts never arrive | Check Settings → SMS & Call Alerts — use the "Send test" button there first; it surfaces the gateway's raw HTTP error, which is almost always more specific than "it didn't work." |
| "Test Your PC Speed" speed test fails but "Test WAN Speed" works fine | The end user's own network (not the server's) is blocking outbound HTTPS to `speed.cloudflare.com` — check their firewall/proxy/ad-blocker. This is expected behavior, not a bug: the two buttons test two different network paths. |
| Speed test "Hostname" column is blank | Expected on networks without reverse DNS configured for internal IPs (common on home/small-office networks, less common on a Windows AD domain) — the local IP is still shown even when the hostname can't be resolved. |
| Network Scan finds devices but MAC/vendor is blank for some | This is expected for devices Net-monit hasn't yet exchanged any traffic with (their entry isn't in this machine's ARP table yet) — re-running the scan after those devices have been contacted once usually fills it in. See the Admin Guide for more detail. |
| WAN speed is much lower than speedtest.net shows | "Test WAN Speed" measures to the server named in the status line (Cloudflare by default), not to a server inside your internet provider, and some providers route to Cloudflare more slowly than to their own network. Check the **Target** and round-trip time in the log; to measure against a nearer server, see *Optional: make the WAN speed test measure against a nearby server*. |
| Network Scan shows no UDP ports for a device | A UDP port is listed only when the device answers a request for that service (DNS, TFTP, NTP, NetBIOS, SNMP with community `public`, UPnP, mDNS). A silent device can still run UDP services — firewalls often drop these probes. The expanded row lists exactly which UDP ports were checked. |

For anything else, see the Admin Guide (day-to-day operation) or the User Guide (end-user features), both in this same `docs/` folder.

## Service installed but dashboard not opening (step by step, no technical knowledge needed)

Do these in order. Stop as soon as the dashboard opens.

1. **Use clean V12.4 files.** Delete the folder you installed from, extract the V12.4 zip again, and do **not** edit any `.py` file. Edited files are the most common reason for this problem.
2. **Remove the old service.** Right-click `Uninstall.bat` and choose **Run as administrator**. Follow the prompts. (Old versions keep their own service and port, so an old service can stay behind.)
3. **Install again.** Right-click `Setup.bat` and choose **Run as administrator**. Finish every screen of the wizard.
4. **Check the service is running.** Press the Windows key, type `services.msc`, press Enter. Find **Net-monit V12.4 Network Monitor**. The Status column must say **Running**. If it does not, right-click it and choose **Start**.
5. **Open the dashboard.** In a browser go to `http://localhost:5050` (use your own port if you changed it in the wizard).
6. **Still not opening? Read the log.** Open the install folder (default `C:\NetMonit-V12.4`), then the `logs` folder, then open `service.log` in Notepad and scroll to the bottom. Look for a line containing `ERROR`, `Traceback` or `crashed`. Copy the last 30 lines.
7. **Run it in the foreground to see the real error.** Press the Windows key, type `cmd`, right-click **Command Prompt**, choose **Run as administrator**, then type these two lines, pressing Enter after each:

   ```
   cd C:\NetMonit-V12.4
   venv\Scripts\python.exe install_service.py debug
   ```
   Read the message printed on screen. Press `Ctrl+C` to stop it when done. Send the output together with the 30 log lines from step 6 to support.
8. **Port already in use?** In the same Command Prompt type `netstat -ano | findstr :5050`. If a line appears, another program uses that port: re-run `Setup.bat` and choose a different port.
