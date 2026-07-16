#!/bin/bash
set -e

echo ""
echo "=============================================="
echo "  Hermes Sentinel — Satellite Installer"
echo "  Lightweight malware detection agent"
echo "=============================================="
echo ""

# Check Python3
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 is required but not installed."
    exit 1
fi
echo "✅ Python3: $(python3 --version)"

# Create directories
echo ""
echo "📁 Creating directories..."
mkdir -p /opt/hermes-sentinel
mkdir -p /etc/hermes-sentinel

# Download agent
echo "📥 Downloading agent..."
curl -sSL -o /opt/hermes-sentinel/hermes-sentinel.py \
    https://raw.githubusercontent.com/pratomobowo/hermes-sentinel/main/hermes-sentinel.py
chmod +x /opt/hermes-sentinel/hermes-sentinel.py

# Create config
echo ""
echo "📝 Configuring..."
echo ""
echo "   This satellite needs to know where your Hermes Agent lives."
echo "   It sends scan results there for AI reasoning + Telegram alerts."
echo ""

read -p "   Hermes webhook URL (e.g. http://192.168.1.10:8644/webhooks/sentinel): " MASTER_URL
read -p "   Webhook shared secret: " SHARED_SECRET
read -p "   Server name (for alerts, e.g. web-prod-1): " SERVER_NAME
read -p "   Directories to scan [default: /var/www]: " WATCH_DIRS
SERVER_NAME=${SERVER_NAME:-$(hostname)}
WATCH_DIRS=${WATCH_DIRS:-/var/www}

# Write config
cat > /etc/hermes-sentinel/config.yaml << YAML
server_name: "${SERVER_NAME}"
master_url: "${MASTER_URL}"
secret: "${SHARED_SECRET}"
watch_dirs:
  - ${WATCH_DIRS}
interval: 300
baseline_on_start: true
YAML

echo "   ✅ Config saved: /etc/hermes-sentinel/config.yaml"

# Install systemd service
echo ""
echo "🔧 Installing systemd service..."
cat > /etc/systemd/system/sentinel.service << 'UNIT'
[Unit]
Description=Hermes Sentinel - Malware detection agent
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/hermes-sentinel/hermes-sentinel.py --config /etc/hermes-sentinel/config.yaml
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload

# Test scan
echo ""
echo "🔍 Running test scan..."
python3 /opt/hermes-sentinel/hermes-sentinel.py --scan-once 2>&1

# Final
echo ""
echo "=============================================="
echo "  ✅ Satellite installed on ${SERVER_NAME}"
echo "=============================================="
echo ""
echo "   ┌───────────────────────────────────────────┐"
echo "   │  Agent:  /opt/hermes-sentinel/hermes-sentinel.py"
echo "   │  Config: /etc/hermes-sentinel/config.yaml"
echo "   │  Reports to: ${MASTER_URL}"
echo "   │  Watching: ${WATCH_DIRS}"
echo "   └───────────────────────────────────────────┘"
echo ""
echo "   Start watching:  systemctl start sentinel"
echo "   Check status:    systemctl status sentinel"
echo "   View logs:       journalctl -u sentinel -f"
echo "   Manual scan:     python3 /opt/hermes-sentinel/hermes-sentinel.py --scan-once"
echo ""
echo "   GitHub: https://github.com/pratomobowo/hermes-sentinel"
echo ""
