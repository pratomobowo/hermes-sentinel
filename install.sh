#!/bin/bash
set -e

echo "=== Hermes Sentinel Installer ==="
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

# Create default config if not exists
if [ ! -f /etc/hermes-sentinel/config.yaml ]; then
    echo "📝 Creating default config..."
    cat > /etc/hermes-sentinel/config.yaml << 'EOF'
# Hermes Sentinel Configuration
server_name: "CHANGE-ME"
master_url: "https://YOUR-HERMES/webhook/sentinel"
secret: "your-shared-secret"
watch_dirs:
  - /var/www
interval: 300
baseline_on_start: true
EOF
    echo "   ⚠️  Edit /etc/hermes-sentinel/config.yaml with your settings!"
fi

# Install systemd service
echo "🔧 Installing systemd service..."
cat > /etc/systemd/system/sentinel.service << 'EOF'
[Unit]
Description=Hermes Sentinel — Malware detection agent
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
EOF

systemctl daemon-reload

echo ""
echo "=== ✅ Hermes Sentinel installed! ==="
echo ""
echo "   Next steps:"
echo "   1. Edit /etc/hermes-sentinel/config.yaml"
echo "   2. systemctl enable --now sentinel"
echo "   3. Check: journalctl -u sentinel -f"
echo ""
echo "   To test: python3 /opt/hermes-sentinel/hermes-sentinel.py --scan-once"
echo ""
