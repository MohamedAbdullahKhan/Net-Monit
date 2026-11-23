# Net-monit V12.4 — How the app works, start to finish

GitHub draws the diagrams below automatically. Words in **bold** are the names you see on screen.

## 1. The big picture
```mermaid
flowchart LR
  A[You add a device or site] --> B[Scheduler runs a check every interval]
  B --> C[Checker: ping / SNMP / SSH / PowerShell / disk / website / service / task]
  C --> D[Evaluate against thresholds]
  D --> E{State}
  E -->|Healthy| F[Dashboard shows Healthy]
  E -->|Warning / Critical / Offline| G[Alert logic]
  G --> H[Email / SMS / Voice]
  G --> I[Escalation L1 to L2 to L3]
  F --> J[(SQLite history)]
  G --> J
```
1. **Add:** Devices page (network, server, PowerShell host) or Sites page (website). Network Scan can add many at once.
2. **Check:** the scheduler (APScheduler) runs each monitor at its own interval (30 s by default). Each method has its own checker in `monitor/checkers/`.
3. **Evaluate:** each measured value is compared with a Warning and a Critical threshold.
4. **Record:** every result is saved in SQLite (`data/monitor.db`); old data is purged on a schedule.
5. **Alert:** only when the state is bad *and* the timing rules below say it is time.

## 2. Which threshold wins
```mermaid
flowchart TD
  V[Measured value] --> P{Per-device or per-site override for this metric?}
  P -->|yes| U[Use the override]
  P -->|no| G{Global default saved in Settings > Thresholds?}
  G -->|yes| W[Use the global value]
  G -->|no| R[Use the built-in recommended value]
```
- Higher is worse for everything except **SSL certificate expires in (days)**, where lower is worse (warning 30, critical 7).
- **Apply to all devices / Apply to all sites** (Settings > Thresholds) saves the table as the default and removes the overrides of those metrics.
- The **!** next to a metric shows its meaning, allowed range and recommended values.

## 3. From a bad reading to an email
```mermaid
stateDiagram-v2
  [*] --> Healthy
  Healthy --> Warning: value passes warning
  Healthy --> Critical: value passes critical
  Healthy --> Offline: no answer
  Warning --> Critical
  Critical --> Warning
  Warning --> Healthy: recovered
  Critical --> Healthy: recovered
  Offline --> Healthy: recovered
```
Two timers decide when you are told:

| Setting | Where | What it does |
|---|---|---|
| **Alert trigger mode** | Settings > Escalation, or a monitor's **Notify** window | *Immediate*: alert at the first bad reading. *Wait to confirm*: alert only if the problem lasts the number of **wait seconds**. |
| **Repeat-alert cooldown** | same place | *Immediate*: no extra gap. *Cooldown*: at least N seconds between repeat alerts for the same problem. |

A per-metric **Wait** (in the Notify window) beats the monitor's Level 1 time. **Apply wait & cooldown to: All devices & sites / Devices only / Sites only** copies the on-screen values to those monitors; it changes only these timing fields.

```mermaid
sequenceDiagram
  participant M as Monitor
  participant A as Alert logic
  participant L1 as Level 1 contacts
  participant L2 as Level 2 contacts
  M->>A: bad reading (t=0)
  A->>A: wait to confirm (e.g. 60 s)
  A->>L1: email / SMS / call
  A->>A: cooldown between repeats
  A->>L2: escalate if still bad after the L2 time
  M->>A: reading is good again
  A->>L1: recovery message
```

## 4. Install workflow
```mermaid
flowchart TD
  S[Run Setup.bat as administrator] --> P{Python 3.9+ found?}
  P -->|no| D[Download and install Python 3.11] --> W
  P -->|yes| W[Setup Wizard]
  W --> I[Copy files, create venv, pip install]
  I --> R[Register Windows Service Net_Monit_V124]
  R --> B[Browser opens http://localhost:5050]
  B --> T[Log in with the first-run token]
  T --> K[Activation: 30-day trial or license key]
```
Linux: `sudo bash setup.sh` does the same with a systemd service `netmonit-v124`. Manual run: `python app.py` (see `DOC-Setup-Python-Manual.md`).

## 5. License workflow
```mermaid
flowchart LR
  A[Activation screen shows Device ID + Activation Code] --> B[You send both to the vendor]
  B --> C[Vendor generates an NM1- key with the private key]
  C --> D[You paste the key and click Activate License]
  D --> E[App checks the signature with the public key]
```
The app only **verifies** keys. Signing needs a private key that never leaves the vendor.

## 6. Upgrade workflow
Each version has its own folder, port and service name. Install the new one next to the old one, check it, then remove the old service. Steps: `DOC-Setup-Guide.md`, section "Upgrading".

## 7. Pages and what they are for
| Page | Use it to |
|---|---|
| Dashboard | See every monitor's state now |
| Devices | Add and edit devices; open **Notify** for contacts, thresholds, timing |
| Sites | Websites: response time, SSL days left, DNS/connect/handshake timing |
| Network Scan | Find devices on a subnet (ping, TCP, UDP) |
| Speed Test | WAN and browser speed tests |
| Alerts | History of alerts and recoveries |
| Settings | SMTP, thresholds, escalation, templates, monitors |
| Admin | Users, license, audit log, about |
