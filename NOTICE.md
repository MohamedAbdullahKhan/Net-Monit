# Third-party notices (Net-monit V12.4)

**Sniffnet** (https://github.com/GyulyVGC/sniffnet), version 1.5.1, Copyright (c) 2022 Giuliano Bellini, dual-licensed MIT / Apache-2.0
(texts in `licenses/`). The Traffic Analyzer is a Python re-implementation of Sniffnet's analysis logic (connection accounting, direction
and traffic-type rules, service scoring, bogon ranges, notification rules, IPFIX collector, blacklist and search semantics). The following
data files are taken unchanged from Sniffnet's `resources/`: `monitor/traffic/data/services.txt`, `categories.txt`, the country flags in
`static/flags/`, the service-category icons in `static/img/svc/` and the notification sounds in `static/sounds/`.

**MaxMind GeoLite2** Country and ASN databases (`monitor/traffic/data/geo/*.mmdb`, built July 2026). This product includes GeoLite2 data
created by MaxMind, available from https://www.maxmind.com. GeoLite2 data is governed by MaxMind's GeoLite2 End User License Agreement;
check that EULA (attribution, update and redistribution terms) before you redistribute Net-monit outside your organisation. You can
replace the files with your own in Traffic > Settings.

**Service names** (`services.txt`) derive from the nmap services list (Nmap Public Source License).

**Python libraries**: scapy (GPL-2.0, used to read capture files, for capture on macOS and on Windows when Npcap is installed). Npcap is not bundled (its free edition may not be redistributed), maxminddb (Apache-2.0), psutil (BSD-3), Flask (BSD-3),
and the others listed in `requirements.txt`.
