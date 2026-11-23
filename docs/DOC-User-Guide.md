# Net-monit V11.3 — User Guide

A plain-language walkthrough of using Net-monit day to day. If you need to configure alerts, add devices, or manage users, see the Admin Guide instead — this guide covers viewing and using the dashboard.

## Signing in

Go to the address your IT admin gave you (something like `http://<server-name>:5050`) and log in with your account.

## The Dashboard

This is the home screen — a grid of tiles, one per monitored device, server, or website, refreshing automatically every few seconds.

### Reading a tile

- **Colored dot + label:** green "Healthy" (with a gentle heartbeat pulse), yellow "Warning", red "Critical", or gray "Offline".
- **Name and address** of whatever's being monitored.
- **"Checked Ns ago"** — how recently this tile's data was refreshed.
- **The numbers in the middle** depend on what kind of thing is being monitored — a server shows CPU/Memory/Disk/latency, a website shows response time/HTTP status/SSL certificate days remaining, a host with watched services or scheduled tasks shows a quick "3/3 up" style summary.

### Tabs

Across the top: **General** (everything), **Network**, **Firewall**, **Windows**, **Linux**, **URL** — click any to filter the dashboard down to just that category. The number next to each tab is how many tiles are in it.

### Switching views

- **Grid / List** toggle, top-left area — List shows a more compact row-based layout, useful when you have a lot of tiles and want to scan quickly.
- **Column count** (2/3/4/5/Auto) controls how many tiles fit per row in Grid view.
- Both of these remember your choice — next time you log in, it's exactly how you left it.

### Rearranging your dashboard

Click **Editing...** to enter Edit Mode:
- **Drag** any tile to reorder it.
- **Resize** using the corner handle.
- **Hide** a tile you don't want to see right now without deleting the underlying device (hidden tiles show at 50% opacity while you're still in Edit Mode, so you can find and re-show them, and disappear entirely once you exit Edit Mode).
- Click **Save Layout** when you're happy with it, or **Cancel** to discard changes, or **Reset** to go back to the default order.

Your layout is personal to your account — it won't change what anyone else sees when they log in.

### Adding something to the dashboard quickly

Click **+ Add Tile** for a quick way to add a network device, server, shared drive, or website without leaving the dashboard. Pick the kind of thing you're adding, fill in its address, and save — it'll show up as a new tile immediately and start being monitored on the next check cycle.

## Sites Monitor

A dedicated page (separate from the main Dashboard's device list) for tracking websites and web applications specifically — response time, whether it's up, HTTP status code, and how many days remain before its SSL/HTTPS certificate expires.

## Network Scan

Sweeps your local network to find devices that aren't yet being monitored — useful for discovering what's actually on the network. Each result shows what it could determine: hostname, MAC address, likely manufacturer, device type guess (e.g. "Linux/Unix Host", "Windows Host", "Network Printer"), and any open ports it found. Click **Add** next to anything you want to start monitoring properly.

## Speed Test

Runs an internet speed test on demand and keeps a history, so you can see your connection's download/upload speed over time rather than just a single snapshot.

- **Test WAN Speed** measures the internet connection of the Net-monit server itself (the "WAN" — the line to your internet provider). The panel says **Showing: WAN**.
- **Test Your PC Speed** measures the internet connection of the PC you are using right now, from your browser. The panel says **Showing: Your PC**, with your PC's name.

**Reading the dial.** The test runs in steps: latency first, then **download** (the needle and arc are **green** and follow the live speed), then the needle drops back and **upload** runs (**purple**). When it finishes, the dial rests on the download result and the small line under it shows download ↓, upload ↑ and ping.

**What the number means.** Every result says what it was measured against — the line under the buttons while testing, the note afterwards, and the **Target** column in the log (for example *Cloudflare (DXB · Dubai)*) — together with the round-trip time to it. A speed test measures the route to *a particular server*. A site such as speedtest.net uses a server inside your internet provider, so on some providers it shows a higher figure than a test against Cloudflare. That is a difference in what is being measured, not a faulty line. Your administrator can point the WAN test at a nearer server. A step that could not be measured shows **--**, never a made-up 0.

**The log.** The **Source** badge reads **WAN** or **PC**. **Export CSV** saves the history (the Target and Method columns are at the end of each row).

## Alert Event Log

Every time something changes state (goes down, comes back up, crosses a warning/critical line), it's recorded here — whether or not it actually triggered an email to anyone. If your admin has turned on "wait to confirm" alerting for something, you may see brief blips logged here that never generated an email, which is expected: short problems that resolve on their own are recorded for visibility but don't need to interrupt anyone.

## Getting help

For anything about configuring alerts, adding devices, or managing accounts, that's covered in the Admin Guide — ask whoever administers your Net-monit installation.

## Opening a device from the dashboard (V11.3 patch 04)

**Double-click a tile** to open that device's window: its type and method, live status, last error and the thresholds that apply to it. Administrators can change the device's own thresholds there and jump to the full device or notification settings. In *Settings*, the Monitors, Escalation, Notifications and Thresholds lists have **Type** and **Method** filters.

The **Devices** page also has the Type and Method filters and a **Group by** list, so you can see, for example, only the firewalls or all devices grouped by how they are checked.
