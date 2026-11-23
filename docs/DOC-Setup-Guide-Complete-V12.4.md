# Net-monit V12.4 — Complete Setup Guide (step by step, no IT knowledge needed)

Two parts: **Part A** installs Net-monit. **Part B** configures the Traffic Analyzer ("the sniffer") so it sees the traffic you want. Read the box at the top of each step before you click anything.

> **Port:** V12.4 uses **5050**. The address you type in the browser is `http://localhost:5050` (or `http://SERVER-IP:5050` from another PC). If you upgraded an older version with the upgrade package, your **old port is kept** (for example 50113) — use that one.


---

# PART A — Install

## A1. What you need
| Need | Detail |
|---|---|
| A PC or server that stays on | Windows 10/11/Server, or Linux. 4 GB RAM is plenty. |
| Administrator rights | You will click **Yes** on a Windows security prompt. |
| Internet (first install only) | Only to download **Python** and **Npcap** if they are missing. Offline? See A6. |
| Free port 5050 | Nothing else may use it. Setup checks this for you. |

## A2. Install on Windows
1. Copy the whole **Net-monit-V12.4** folder to the PC (Desktop is fine). Do not run it from inside the zip: right-click the zip → **Extract All** first.
2. Double-click **Setup.bat**. Click **Yes** when Windows asks for permission.
3. A black window appears and checks things in this order. **Do not close it.**
   1. **Python** — if missing it is downloaded and installed silently (about 1–3 minutes).
   2. **Npcap** (packet-capture driver) — see A3.
   3. The Net-monit **setup wizard** opens.
4. In the wizard click **Next**. Keep the suggested folder `C:\NetMonit-V12.4`. Keep port **5050** unless your IT team told you otherwise.
5. Wait for the green bars. The wizard installs the Python packages, registers the Windows service **Net_Monit_V124**, adds the firewall rule for the port and starts the service.
6. The last screen shows the **first-run admin token**. **Write it down now** — it is also saved in `C:\NetMonit-V12.4\data\FIRST-RUN-ADMIN-TOKEN.txt`.
7. Your browser opens `http://localhost:5050`. Sign in as **admin@email.com** with the token, then change the password.

## A3. Npcap (the packet-capture driver) — read this, it is not like Python
Npcap is a free driver from npcap.com. Net-monit works **without** it (it then captures with Windows raw sockets). With it you also get MAC addresses, VLAN tags and every filter.

**Why the install is not completely silent:** Npcap's silent mode (`/S`) exists only in the paid **Npcap OEM** edition. The free edition cannot be silent and may not be bundled in other software — that is Npcap's licence, not a Net-monit limit. The free edition is licensed for up to 5 computers.

What Setup does:
1. Npcap already installed → skips it.
2. You put a licensed OEM installer named like `npcap-1.xx-oem.exe` into `Net-monit-V12.4\setup\deps` → installs **fully silent**.
3. Otherwise → downloads the newest installer from npcap.com, checks its digital signature, and opens **Npcap's own window**. Click **I Agree → Install → Next → Finish**. Setup waits and continues.
4. Anything fails or you cancel → setup continues anyway. Install Npcap later from https://npcap.com (keep "Install Npcap in WinPcap API-compatible mode" **un-ticked**, tick "Support loopback traffic").

## A4. Check that it works
1. Open `http://localhost:5050` → login page.
2. Open **About**: it must say **V12.4** and show the port.
3. Press the Windows key, type `services.msc`, find **Net-monit V12.4** → Status **Running**, Startup **Automatic**.

## A5. If the service starts and then stops by itself
This was the V12.0/V12.1 problem. Do these in order, stop at the first that explains it:
1. **Read the log.** Open `C:\NetMonit-V12.4\logs\service.log` in Notepad and go to the bottom. The last error line says why.
2. **Port problem (most common).** Open **Command Prompt as administrator** and run:
   - `netstat -ano | findstr :5050` — if a line appears, another program owns 5050. Pick another port (step 5).
   - `netsh int ipv4 show excludedportrange protocol=tcp` — if 5050 lies inside any listed range, Windows (Hyper-V/WSL/Docker) reserved it. Pick another port.
   - `netsh int ipv4 show dynamicport tcp` — ports from 49152 up are handed to outgoing connections. **Never use a port above 49151.** (Old default 50113/50120 were in this range.)
3. **Antivirus** blocking `pythonw.exe` → add `C:\NetMonit-V12.4` as an exception.
4. **Python missing** → re-run `Setup.bat`.
5. **Change the port:** stop the service, edit `C:\NetMonit-V12.4\config.yaml`, add (or edit):
   ```yaml
   server:
     port: 5051
   ```
   then start the service and allow the new port: `netsh advfirewall firewall add rule name="Net-monit" dir=in action=allow protocol=TCP localport=5051`.
6. Still stuck → send `logs\service.log` (last 50 lines) and the output of the three `netsh`/`netstat` commands.


## A5b. WAN speed test shows no download ("Cloudflare rate-limited this network, HTTP 429/503")
This message means Cloudflare **answered** your test but refused the download (upload and ping worked). It is a limit on your public IP address, not a Net-monit fault: many tests in a row, or many people behind the same ISP address, trigger it.
- **V12.4 handles it for you:** the default engine is `auto`: a Speedtest.net server inside your ISP is tried first (so the ping is no longer measured to Cloudflare), Cloudflare second, and if Cloudflare refuses the download the test switches engine instead of showing "--".
- To force the old behaviour add to `config.yaml`: `speedtest:` / `  engine: builtin`. To pin your own server list see `speedtest.targets` in the Setup Guide.
- Run **one** test and wait 5–10 minutes before the next.
- Still wrong? Double-click **Diagnose-SpeedTest.bat** in the install folder. It shows step by step where the test fails (DNS, port 443, TLS, a 1 MB download, then Net-monit's own test). Send the whole window plus the last 40 lines of `logs\service.log`.

## A5c. Traffic page says "A capture is already running" but there is no Stop button
V12.4 fixes the cause (a capture that died by itself stayed marked as running). If you ever see it: the page now shows **Reset capture** next to Start; press it, confirm, then Start again. A capture that stopped unexpectedly is shown as **Stopped (error)** with the reason.

## A6. Offline install
Copy these into `Net-monit-V12.4\setup\deps` on a PC with internet first: the Python installer (python.org, 3.11+) and the Npcap installer (npcap.com). Setup uses local files first.

## A7. Install on Linux
```bash
sudo ./setup.sh
sudo systemctl status netmonit-v124
```
Dashboard: `http://SERVER-IP:5050`. The service already has the permission to capture packets.

## A8. License
Free trial starts automatically (30 days). For a key: **Settings → License** shows your Device ID and Activation Code; send both to the vendor and paste the key you get back. The key is tied to the Device ID, which is tied to the **install folder** — upgrading in place keeps it; installing into a new folder needs a new key.


---

# PART B — Configure the Traffic Analyzer (the "sniffer")

Open **Traffic** in the left menu (admin only). Pick **one** of four ways to feed it. First decide what you want to see:

| I want to see… | Use | Section |
|---|---|---|
| Everything this server itself sends/receives | **Network card** on this server | B1 |
| All traffic of other PCs/servers on a switch | Network card + **mirror (SPAN) port** | B2 |
| Traffic of a whole site/link, light on the server | **NetFlow / IPFIX** from the router/firewall | B3 |
| A recording someone gave me / from Wireshark | **Capture file** | B4 |

## B1. This server's own traffic (simplest)
1. **Traffic → Start a capture → Network card.**
2. Choose the card that has the server's real IP (it is pre-selected). Ignore "vEthernet (WSL)" and "Loopback" unless you test those.
3. Leave **Filter** empty (see B5 for examples). Tick **Save the packets** only if you want a .pcap for Wireshark.
4. Press **Start capture**. The graph moves within a second.
5. Want it to start every time the service starts? Open **Settings** tab → tick **Start automatically** → Save.

## B2. Other machines' traffic through a mirror port
A normal switch sends each computer only its own traffic, so a card on the Net-monit server cannot see the others. Make the switch **copy** traffic to the server's port:
1. Plug the Net-monit server into a free switch port (say port 48). Use a dedicated card if you can.
2. On the switch create a **port mirror / SPAN** session: source = the ports or VLAN you want to watch, destination = port 48. Example (Cisco IOS):
   ```
   monitor session 1 source interface Gi1/0/1 - 10 both
   monitor session 1 destination interface Gi1/0/48
   ```
   Other brands call it "Port Mirroring" or "Monitor Session" in the web menu.
3. In Net-monit choose that card and press Start. You now see all mirrored traffic.
4. **Virtual machines:** on VMware set the port group security option **Promiscuous mode = Accept**; on Hyper-V use a port mirror on the VM network adapter (Advanced features → Port mirroring: *Destination* on the Net-monit VM, *Source* on the VMs to watch).
5. The mirror card should have no IP address of its own if you can avoid it, otherwise the dashboard traffic is also counted.

## B3. NetFlow / IPFIX from a router or firewall
Best for big or remote networks: the device summarises traffic and sends small records; the server needs no mirror port.
1. **Traffic → Start a capture → NetFlow / IPFIX.** Keep UDP port **2055**. In **Only accept from** type the router's IP (very important — UDP can be faked). Press **Start**.
2. **Allow the port in the firewall of the Net-monit server:**
   `netsh advfirewall firewall add rule name="Net-monit NetFlow" dir=in action=allow protocol=UDP localport=2055`
3. **Tell the router/firewall to export to the server** (use NetFlow **v5, v9 or IPFIX**):

| Device | Commands (replace 10.0.1.100 with the Net-monit server IP) |
|---|---|
| Cisco IOS (classic) | `ip flow-export version 9` / `ip flow-export destination 10.0.1.100 2055` then on each interface `ip flow ingress` and `ip flow egress` |
| MikroTik | `/ip traffic-flow set enabled=yes interfaces=all` then `/ip traffic-flow target add dst-address=10.0.1.100 port=2055 version=9` |
| FortiGate | `config system netflow` / `set collector-ip 10.0.1.100` / `set collector-port 2055` / `end`, then on each interface `config system interface` / `edit port1` / `set netflow-sampler both` / `end` |
| Linux server or pfSense (softflowd) | `softflowd -i eth0 -n 10.0.1.100:2055 -v 9` |

4. Wait 1–2 minutes (routers send templates first). Records appear under **Overview**. If nothing arrives after 5 minutes: wrong IP/port, firewall, or the "Only accept from" list does not contain the router's source IP.
5. NetFlow has no program names and no MAC addresses — that is normal.

## B4. Analyse a capture file
1. **Capture file → Choose file** (pcap or pcapng format, up to 500 MB; the file content is checked, not its name) → **Start**.
2. It is read as fast as possible and the result opens in Overview and Connections. It is saved in **History**.

## B5. Filters (optional, "BPF")
| Goal | Type |
|---|---|
| Web only | `tcp port 443 or tcp port 80` |
| One server | `host 10.0.1.50` |
| Hide DNS noise | `not port 53` |
| One subnet | `net 192.168.10.0/24` |
| Only UDP | `udp` |
A wrong filter is refused with a message. Advanced filters (`tcp[13] & 2 != 0`) need Npcap.

## B6. Alerts, favorites, blacklist, geo data
- **Favorites:** click the star next to a host, service or program.
- **Notifications tab:** tick *Traffic above a limit* (write `500k`, `5M`, `1G`), *Favorite sends data*, *Blacklisted address contacted*. Choose sounds. Email/SMS/call/webhook reuse the existing Net-monit messaging settings.
- **Blacklist:** Settings tab → upload a text file, one IP or range (CIDR) per line, `#` for comments.
- **Country / AS names** work offline from the bundled GeoLite database (built July 2026). To update: replace the two `.mmdb` files or point the Settings paths to newer ones.
- **Reverse DNS** (host names): on by default; untick if you do not want Net-monit to query your DNS.

## B7. Capacity and honesty
- About 100,000 packets/second per capture (≈ 570 Mbit/s typical traffic). Faster links: use NetFlow.
- Windows built-in capture cannot see MAC addresses, VLAN tags or loopback traffic; Npcap can.
- Program names appear only when capturing on the same Windows machine and the service runs as Local System.
- A capture keeps up to 200,000 connections in memory; History keeps the busiest 3,000 per capture; old captures are removed after 30 days (Settings).

## B8. Quick test that everything works
1. Start a capture on the server's card (B1). Open a website in another browser tab.
2. **Overview → Hosts** must show the website's IP with a country flag; **Programs** shows `chrome.exe` (Windows).
3. **Connections** → search `443` → click a row → **Measure latency**.
4. **Stop** → **History** shows the capture.
