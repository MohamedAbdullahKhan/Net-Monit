# Traffic Analyzer: user guide (Net-monit V12.4)

The Traffic Analyzer answers one question: **what is using my network right now?** It watches the traffic of a network card (or reads a capture file, or listens to your routers) and shows every connection, who it goes to, which service and program it belongs to, and which country it ends in.

## Before you start (once)

| System | What you need |
|---|---|
| **Windows** | Nothing to install. Net-monit captures with Windows raw sockets, using the rights of the Net-monit service (Local System). Optional: install **Npcap** (https://npcap.com) to also see MAC addresses and VLAN tags and to use advanced filters; Net-monit detects it and uses it automatically. |
| **Linux** | The supplied systemd service already has the right to capture (`CAP_NET_RAW`). Running by hand: `sudo python app.py`. Program names need root. |
| **Capture files / NetFlow** | Nothing extra. |

Open **Traffic** in the left menu. You must be signed in as an admin (viewers cannot see it, because it shows addresses and host names).

## 1. Watch your network card (live)
1. Under **Start a capture** choose **Network card**.
2. Pick the card that has your real IP address (Net-monit pre-selects it).
3. Optional: type a **filter**, for example `tcp port 443`, `host 10.0.0.5`, `udp and not port 53`, `net 192.168.0.0/16`. Words you can use: `host`, `net`, `port`, `portrange`, `src`, `dst`, `tcp`, `udp`, `icmp`, `arp`, `ip`, `ip6`, `and`, `or`, `not`, brackets.
4. Optional: tick **Save the packets to a .pcap file** to download them later from History (limit 500 MB per capture).
5. Press **Start capture**. Within a second the chart moves.

Use **Pause** to freeze counting and **Stop** to end. The state chip at the top shows *Capturing*, *Paused*, *Finished* or *Stopped*.

## 2. Read a capture file
Choose **Capture file**, select a .pcap or .pcapng file (up to 500 MB) and press Start. The file is analysed as fast as it can be read; the chart follows the time inside the file.

## 3. Collect NetFlow / IPFIX from routers and switches
1. Choose **NetFlow / IPFIX**, keep port 2055 (or another UDP port) and press Start.
2. On the router/switch set the flow export (NetFlow v5, v9 or IPFIX) to this server's IP and that port.
3. Allow the UDP port in the Windows/Linux firewall.
4. Recommended: in **Only accept from** list the exporter IPs. UDP can be faked, so without a list anyone who can reach the port could inject numbers.

## 4. The Overview tab
- **Chart**: incoming above the middle line, outgoing below it. Switch **Bytes / Bits / Packets** and the window (1 minute to 1 hour). Move the mouse over the chart to read exact values.
- **Totals**: current and total traffic, number of connections and remote hosts, blacklisted connections, how long the capture runs.
- **Hosts / Services / Programs / Countries**: ranked by **Data** or **Packets**. The coloured bar shows the incoming (green) / outgoing (blue) share. Click a name to see its connections. Click the star to make it a **favorite**.
- A green tag with a name means the address is one of your monitored Net-monit devices.

## 5. The Connections tab
Type in the search box to find an address, port, host, service, program, country or AS. **More filters** lets you search one field at a time. Start a value with `=` for an exact match (`=https` finds only https, not https-alt). The **country** filter uses the 2-letter code (`US`). Sort by data, packets or time. Click a row for details: both addresses, protocol, service and its category, direction, size, first/last seen, program, MAC and VLAN, ICMP/ARP message types, and **Measure latency** (three pings). **Download CSV report** exports what the capture has seen.

## 6. Notifications
Three rules (all off until you tick them):
1. **Traffic above a limit**: per second, incoming plus outgoing, in bytes, bits or packets. Write `500k`, `2.5M`, `1G`. The message names the busiest hosts and services of that second.
2. **A favorite sends or receives data**.
3. **A blacklisted address is contacted** (add a blacklist in Settings).

Each notification is shown on screen, can play a **sound**, is written to the **notification log** and the **audit log**, and can also be sent by **e-mail** (to the admin group of your SMTP settings), **SMS**, **voice call** (through your configured gateways) and **webhook** (a JSON POST). E-mail, SMS and call have a minimum interval so one traffic spike cannot flood you. **Send a test** checks the setup.

## 7. History
Every capture is saved: totals, traffic per minute and the busiest 3,000 connections. Click a row to see details and download the CSV or the .pcap. Old captures are removed after the retention time set in Settings (default 30 days). A capture that was running when the server stopped is shown as *interrupted*.

## 8. Settings
- **Country and AS databases**: Net-monit ships GeoLite2 files (built July 2026). Point to newer or other .mmdb files (GeoLite2, IPinfo). A wrong path falls back to the bundled file and says so.
- **Reverse DNS**: turn off if you do not want Net-monit to ask your DNS server about remote addresses.
- **IP blacklist**: upload a text file with one IP or CIDR range per line (`#` or `;` starts a comment).
- **Start automatically**: after you started a network-card or NetFlow capture, tick this and save; the capture then starts whenever Net-monit starts.

## Mini monitor
The **Mini monitor** button opens a small window with just the live numbers and chart, to keep an eye on the network while you work elsewhere.

## What the built-in Windows capture can and cannot do
It sees every IPv4 packet (and IPv6 where Windows allows it) of the chosen card, incoming and outgoing, but starts at the IP header: no MAC addresses and no VLAN tags, and loopback traffic (127.0.0.1) is not visible. Some security programs block raw sockets; if capture fails with a message about raw sockets, add Net-monit as an exception or install Npcap.

## Limits (read this)
- A Python capture handles roughly **100,000 packets per second** per capture (about 570 Mbit/s of typical 654-byte frames, around 1 Gbit/s of full-size frames). Above that, packets are missed. For very busy links use NetFlow/IPFIX from the router instead.
- The built-in filter understands the common syntax above. Exotic filters (for example `tcp[13] & 2 != 0`) need Npcap on Windows or libpcap on macOS and are not available on Linux.
- Program names need enough rights to read other users' sockets (root / Local System).
- A capture keeps up to 200,000 connections in memory; the least recently active are dropped first (totals stay correct).
- Dropped-packet counters and exporting traffic as IPFIX (Sniffnet features) are not included.
