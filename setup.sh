#!/usr/bin/env bash
# =============================================================================
# Net-monit V12.4 -- Linux Setup Script
# Copyright (c) 2024-2026 Abdullah | Abdullah-InfoXtek.com
# Contact: abuabdullah.be@outlook.com
# Usage: sudo bash setup.sh [--port 5050] [--path /opt/netmonit-v124] [--svc netmonit-v124]
# =============================================================================
set -euo pipefail

APP_VER="V12.4"
DEFAULT_PORT=5050
DEFAULT_PATH="/opt/netmonit-v124"
DEFAULT_SVC="netmonit-v124"
SVC_USER="netmonit"

GREEN="\033[0;32m"; YELLOW="\033[0;33m"; RED="\033[0;31m"
CYAN="\033[0;36m"; BOLD="\033[1m"; RESET="\033[0m"

log()  { echo -e "${GREEN}[OK]${RESET}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET} $*"; }
err()  { echo -e "${RED}[ERR]${RESET}  $*"; exit 1; }
info() { echo -e "${CYAN}[-->]${RESET}  $*"; }

PORT="$DEFAULT_PORT"; INSTALL_PATH="$DEFAULT_PATH"; SVC_NAME="$DEFAULT_SVC"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --port) PORT="$2"; shift 2 ;;
        --path) INSTALL_PATH="$2"; shift 2 ;;
        --svc)  SVC_NAME="$2"; shift 2 ;;
        --help) echo "Usage: sudo bash setup.sh [--port 5050] [--path /opt/netmonit-v124] [--svc netmonit-v124]"; exit 0 ;;
        *) shift ;;
    esac
done

echo ""
echo -e "${BOLD}${CYAN}============================================================${RESET}"
echo -e "${BOLD}  Net-monit $APP_VER  --  Linux Setup${RESET}"
echo -e "${BOLD}  Copyright (c) 2024-2026 Abdullah | Abdullah-InfoXtek.com${RESET}"
echo -e "${BOLD}  Port: $PORT  |  Path: $INSTALL_PATH  |  Service: $SVC_NAME${RESET}"
echo -e "${BOLD}${CYAN}============================================================${RESET}"
echo ""

[[ $EUID -ne 0 ]] && err "Run as root: sudo bash setup.sh"

# ── Package manager ────────────────────────────────────────────────────────
if   command -v apt-get &>/dev/null; then PKG="apt-get install -y -q"
elif command -v dnf     &>/dev/null; then PKG="dnf install -y -q"
elif command -v yum     &>/dev/null; then PKG="yum install -y -q"
else PKG=""; fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Step 1: System packages
info "Step 1/8  System Packages"
if [[ -n "$PKG" ]]; then
    $PKG python3 python3-pip python3-venv python3-dev \
         curl wget net-tools iputils-ping gcc libssl-dev 2>/dev/null || \
         warn "Some system packages may have failed (continuing)"
    log "System packages installed"
fi

# Step 2: Python check
info "Step 2/8  Python"
PY=""
for cmd in python3.12 python3.11 python3.10 python3.9 python3; do
    if command -v "$cmd" &>/dev/null; then
        VER=$("$cmd" --version 2>&1 | grep -oP '\d+\.\d+' | head -1)
        MAJ=${VER%%.*}; MIN=${VER##*.}
        if (( MAJ >= 3 && MIN >= 9 )); then
            PY=$(command -v "$cmd")
            log "Python: $PY  ($("$PY" --version))"
            break
        fi
    fi
done
[[ -z "$PY" ]] && err "Python 3.9+ not found. Install: $PKG python3.11"

# Step 3: Directories
info "Step 3/8  Directories"
mkdir -p "$INSTALL_PATH"/{data,logs,monitor/checkers,static/{css,js,img},templates,setup,tools,scripts/{windows,linux}}
log "Directories: $INSTALL_PATH"

# Step 4: Copy files
info "Step 4/8  Copying Files"
rsync -a --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
      --exclude='*.zip' --exclude='venv' --exclude='monitor.db' \
      --exclude='secret.key' --exclude='*.log' \
      "$SCRIPT_DIR/" "$INSTALL_PATH/" 2>/dev/null || \
      cp -r "$SCRIPT_DIR"/. "$INSTALL_PATH/"
log "Files copied"

# Step 5: Config
info "Step 5/8  Configuration"
CFG="$INSTALL_PATH/config.yaml"
cat > "$CFG" << CFGEOF
# Net-monit $APP_VER config.yaml
smtp:
  enabled: false
  host: smtp-mail.outlook.com
  port: 587
  use_tls: true
  username: ''
  password: ''
  from_address: ''
  admin_emails: []
  support_emails: []
  manager_emails: []
server:
  port: $PORT
  host: 0.0.0.0
devices: []
CFGEOF
log "config.yaml written (port=$PORT)"

# Step 6: Virtual env + pip
info "Step 6/8  Python Dependencies"
VENV="$INSTALL_PATH/venv"
if [[ ! -d "$VENV" ]]; then
    "$PY" -m venv "$VENV"
    log "Virtual environment: $VENV"
fi
PY_VENV="$VENV/bin/python"
"$PY_VENV" -m pip install --quiet --upgrade pip
REQ="$INSTALL_PATH/requirements.txt"
if [[ -f "$REQ" ]]; then
    "$PY_VENV" -m pip install --quiet -r "$REQ"
    log "pip install completed from requirements.txt"
else
    "$PY_VENV" -m pip install --quiet Flask PyYAML APScheduler cryptography paramiko pysnmp
    log "pip install completed (base packages)"
fi

# Step 7: Service user + systemd
info "Step 7/8  System Service"
if ! id "$SVC_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
    log "Service user created: $SVC_USER"
fi
chown -R "$SVC_USER:$SVC_USER" "$INSTALL_PATH"
chmod -R 755 "$INSTALL_PATH"
chmod 700 "$INSTALL_PATH/data"

SVC_FILE="/etc/systemd/system/${SVC_NAME}.service"
cat > "$SVC_FILE" << UNITEOF
[Unit]
Description=Net-monit $APP_VER Network Monitor
Documentation=https://Abdullah-InfoXtek.com
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SVC_USER
Group=$SVC_USER
# V12 Traffic Analyzer: lets the service capture packets without running as root
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
WorkingDirectory=$INSTALL_PATH
ExecStart=$PY_VENV $INSTALL_PATH/app.py
Restart=on-failure
RestartSec=5s
StartLimitIntervalSec=120
StartLimitBurst=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SVC_NAME
Environment=PYTHONUNBUFFERED=1
Environment=NETMON_PORT=$PORT
Environment=NETMON_SVC_NAME=$SVC_NAME

[Install]
WantedBy=multi-user.target
UNITEOF

systemctl daemon-reload
systemctl enable "$SVC_NAME"
systemctl start  "$SVC_NAME" && log "Service started" || warn "Service start failed"

# Firewall
command -v ufw          &>/dev/null && ufw allow "$PORT/tcp" &>/dev/null && log "ufw rule added"
command -v firewall-cmd &>/dev/null && { firewall-cmd --permanent --add-port="$PORT/tcp" &>/dev/null; firewall-cmd --reload &>/dev/null; log "firewalld rule added"; }

# Step 8: Summary
info "Step 8/8  Complete"
sleep 2
STATUS=$(systemctl is-active "$SVC_NAME" 2>/dev/null || echo "unknown")
MY_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")
echo ""
echo -e "${BOLD}${GREEN}Net-monit $APP_VER installed successfully!${RESET}"
echo ""
echo -e "  Install path : $INSTALL_PATH"
echo -e "  Dashboard    : ${CYAN}http://$MY_IP:$PORT${RESET}"
echo -e "  Service      : $SVC_NAME (${STATUS})"
echo ""
echo -e "  ${BOLD}First-run admin token${RESET} (one-time, unique to this install):"
echo -e "    Email : admin@email.com"
echo -e "    Token : see $INSTALL_PATH/data/FIRST-RUN-ADMIN-TOKEN.txt"
echo -e "            or: sudo journalctl -u $SVC_NAME | grep -A6 'FIRST-RUN'"
echo -e "  ${BOLD}Change it immediately via Admin Panel once logged in!${RESET}"
echo ""
echo -e "  Service commands:"
echo -e "    sudo systemctl start   $SVC_NAME"
echo -e "    sudo systemctl stop    $SVC_NAME"
echo -e "    sudo systemctl restart $SVC_NAME"
echo -e "    sudo journalctl -u $SVC_NAME -f"
echo ""
echo -e "  For a FREE license key: abuabdullah.be@outlook.com"
echo ""
