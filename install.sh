#!/usr/bin/env bash
# Hermes Sentinel — One-Line Installer
# curl -sSL https://raw.githubusercontent.com/pratomobowo/hermes-sentinel/main/install.sh | sudo bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
BOLD='\033[1m'

echo -e "${BLUE}${BOLD}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║     Hermes Sentinel — Installer         ║"
echo "  ║     Satellite malware detection agent    ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${NC}"

# ─── 1. Detect Python 3 ───────────────────────────────────────
echo -e "\n${BOLD}[1/5] Checking Python 3...${NC}"

PYTHON=""
for candidate in python3.12 python3.11 python3.10 python3.9 python3.8 python3; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" -c "import sys; print(str(sys.version_info.major)+'.'+str(sys.version_info.minor))" 2>/dev/null || true)
        if [[ "$ver" =~ ^3\.[0-9]+$ ]]; then
            minor=$(echo "$ver" | cut -d. -f2)
            if [ "$minor" -ge 8 ]; then
                PYTHON="$candidate"
                echo -e "  ${GREEN}✓ Found: $PYTHON ($ver)${NC}"
                break
            fi
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    echo -e "  ${YELLOW}Python 3.8+ not found. Installing...${NC}"
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq python3
    elif command -v dnf &>/dev/null; then
        dnf install -y python3
    elif command -v yum &>/dev/null; then
        yum install -y python3
    elif command -v apk &>/dev/null; then
        apk add python3
    else
        echo -e "  ${RED}✗ Cannot install Python. Install manually: python3${NC}"
        exit 1
    fi
    PYTHON="python3"
    echo -e "  ${GREEN}✓ Python 3 installed${NC}"
fi

# ─── 2. Get Configuration ─────────────────────────────────────
echo -e "\n${BOLD}[2/5] Configuration...${NC}"

read -rp "  Hermes webhook URL [http://your-hermes:8644/webhooks/sentinel]: " MASTER_URL
MASTER_URL=${MASTER_URL:-"http://your-hermes:8644/webhooks/sentinel"}

read -rp "  Shared secret [sentinel-secret]: " SHARED_SECRET
SHARED_SECRET=${SHARED_SECRET:-"sentinel-secret"}

read -rp "  Server name [$(hostname)]: " SERVER_NAME
SERVER_NAME=${SERVER_NAME:-"$(hostname)"}

read -rp "  Directories to scan (space-separated) [/var/www]: " WATCH_DIRS
WATCH_DIRS=${WATCH_DIRS:-"/var/www"}

read -rp "  Enable auto-quarantine? (y/n) [y]: " QUARANTINE
QUARANTINE=${QUARANTINE:-"y"}

# ─── 3. Download Sentinel ─────────────────────────────────────
echo -e "\n${BOLD}[3/5] Downloading Sentinel...${NC}"

INSTALL_DIR="/opt/hermes-sentinel"
CONFIG_DIR="/etc/hermes-sentinel"
REPO_BASE="https://raw.githubusercontent.com/pratomobowo/hermes-sentinel/main"

mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"

echo "  Downloading agent..."
curl -sSL "$REPO_BASE/hermes-sentinel.py" -o "$INSTALL_DIR/hermes-sentinel.py"
chmod 755 "$INSTALL_DIR/hermes-sentinel.py"

echo "  Downloading rules..."
mkdir -p "$INSTALL_DIR/rules"
for rule in judol backdoor webshell cryptominer seo-spam vuln-scan; do
    curl -sSL "$REPO_BASE/rules/${rule}.yaml" -o "$INSTALL_DIR/rules/${rule}.yaml" 2>/dev/null || true
done

echo -e "  ${GREEN}✓ Agent: $INSTALL_DIR/hermes-sentinel.py${NC}"
echo -e "  ${GREEN}✓ Rules: $INSTALL_DIR/rules/${NC}"

# ─── 4. Write Config ──────────────────────────────────────────
echo -e "\n${BOLD}[4/5] Writing config...${NC}"

QUARANTINE_BOOL="false"
[ "$QUARANTINE" = "y" ] && QUARANTINE_BOOL="true"

# Build watch_dirs YAML list
WATCH_DIRS_YAML=""
for d in $WATCH_DIRS; do
    WATCH_DIRS_YAML="${WATCH_DIRS_YAML}  - $d"$'\n'
done

cat > "$CONFIG_DIR/config.yaml" << EOF
server_name: "$SERVER_NAME"
master_url: "$MASTER_URL"
secret: "$SHARED_SECRET"
watch_dirs:
${WATCH_DIRS_YAML}
interval: 300
baseline_on_start: true
quarantine: $QUARANTINE_BOOL
EOF

chmod 600 "$CONFIG_DIR/config.yaml"
echo -e "  ${GREEN}✓ Config: $CONFIG_DIR/config.yaml${NC}"

# ─── 5. Install Systemd Service ───────────────────────────────
echo -e "\n${BOLD}[5/5] Installing systemd service...${NC}"

cat > /etc/systemd/system/sentinel.service << EOF
[Unit]
Description=Hermes Sentinel — Malware Detection Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PYTHON $INSTALL_DIR/hermes-sentinel.py --config $CONFIG_DIR/config.yaml
Restart=always
RestartSec=30
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sentinel
systemctl start sentinel

sleep 2
if systemctl is-active --quiet sentinel; then
    echo -e "  ${GREEN}✓ Service running${NC}"
else
    echo -e "  ${RED}✗ Service failed to start. Check: journalctl -u sentinel -n 20${NC}"
    systemctl status sentinel --no-pager || true
    exit 1
fi

# ─── Done ─────────────────────────────────────────────────────
echo -e "\n${GREEN}${BOLD}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║   Sentinel installed successfully!       ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Server:     ${BOLD}$SERVER_NAME${NC}"
echo -e "  Scanning:   ${BOLD}$WATCH_DIRS${NC}"
echo -e "  Webhook:    ${BOLD}$MASTER_URL${NC}"
echo -e "  Quarantine: ${BOLD}$QUARANTINE_BOOL${NC}"
echo ""
echo -e "  ${BOLD}Commands:${NC}"
echo "    systemctl status sentinel   # check status"
echo "    journalctl -u sentinel -f   # watch logs"
echo "    sentinel --scan-once        # manual scan"
echo ""
echo -e "  ${BOLD}Config:${NC} $CONFIG_DIR/config.yaml"
echo -e "  ${BOLD}DB:${NC}     $CONFIG_DIR/baseline.db"
echo ""
