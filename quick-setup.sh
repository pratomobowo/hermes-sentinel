#!/bin/bash
set -e
# Hermes Sentinel Quick Setup
# curl -sSL https://raw.githubusercontent.com/pratomobowo/hermes-sentinel/main/quick-setup.sh | bash
RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m' BLUE='\033[0;34m' NC='\033[0m'

banner() { echo -e "${BLUE}============================================\n  Hermes Sentinel Setup\n  Malware Detection + AI Reasoning\n============================================${NC}"; }

check_deps() {
    for dep in python3 curl systemctl; do
        command -v $dep &>/dev/null || { echo -e "${RED}Missing: $dep${NC}"; exit 1; }
    done
    echo -e "${GREEN}Dependencies OK${NC}"
}

# Generate secret at runtime via Python (avoids shell heredoc redaction)
gen_secret() { python3 -c "import secrets; print(secrets.token_hex(16))"; }

setup_satellite() {
    echo -e "\n${YELLOW}--- Installing Satellite ---${NC}"
    mkdir -p /opt/hermes-sentinel /etc/hermes-sentinel
    curl -sSL -o /opt/hermes-sentinel/hermes-sentinel.py \
        https://raw.githubusercontent.com/pratomobowo/hermes-sentinel/main/hermes-sentinel.py
    chmod +x /opt/hermes-sentinel/hermes-sentinel.py

    S=$(gen_secret)
    M_URL="${MASTER_URL:-http://localhost:8644/webhooks/sentinel}"
    S_NAME="${SERVER_NAME:-$(hostname)}"

    printf 'server_name: "%s"\nmaster_url: "%s"\nsecret: "%s"\nwatch_dirs:\n  - /var/www\ninterval: 300\nbaseline_on_start: true\nquarantine: false\n' \
        "$S_NAME" "$M_URL" "$S" > /etc/hermes-sentinel/config.yaml

    echo "   Secret: $S"
    echo "   Config: /etc/hermes-sentinel/config.yaml"

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
[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable sentinel
    echo -e "${GREEN}Satellite installed. Start: systemctl start sentinel${NC}"
}

setup_hermes_master() {
    echo -e "\n${YELLOW}--- Setting up Hermes Master ---${NC}"
    command -v hermes &>/dev/null || { echo -e "${RED}hermes CLI not found${NC}"; exit 1; }

    PORT="${WEBHOOK_PORT:-8644}"
    S=$(gen_secret)
    TARGET="${TELEGRAM_CHAT:-}"

    hermes config set platforms.webhook.enabled true
    hermes config set platforms.webhook.extra.host 0.0.0.0
    hermes config set platforms.webhook.extra.port "$PORT"
    hermes config set platforms.webhook.extra.secret "$S"

    DLV="local"
    CHAT="origin"
    if [ -n "$TARGET" ]; then
        DLV="telegram"
        CHAT="$TARGET"
    fi

    hermes webhook subscribe sentinel \
        --prompt "Sentinel Alert from {server}\nSummary: {summary}\nFindings: {findings}\n\nAnalyze and report." \
        --deliver "$DLV" --deliver-chat-id "$CHAT" \
        --description "Sentinel malware reports" 2>/dev/null || true

    echo -e "${GREEN}Master setup done. Restart: hermes gateway restart${NC}"
    echo "  Webhook: http://IP:${PORT}/webhooks/sentinel"
    echo "  Secret:  $S"
}

# Main
banner; check_deps
case "${1:-}" in
    --master)    setup_hermes_master ;;
    --satellite) setup_satellite ;;
    *)
        setup_satellite
        command -v hermes &>/dev/null && setup_hermes_master
        ;;
esac
echo -e "\n${GREEN}Done. github.com/pratomobowo/hermes-sentinel${NC}"
