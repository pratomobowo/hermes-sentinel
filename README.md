# 🛡️ Hermes Sentinel

**Lightweight satellite agents that watch your web servers for malware, gambling redirects, and backdoors.**

Reports to [Hermes Agent](https://github.com/NousResearch/hermes-agent) for AI-powered reasoning. When it finds something, you get a Telegram alert. When everything's clean — silence.

---

## Quick Start (3 Steps)

### Step 1: Install on each server you want to protect

```bash
curl -sSL https://raw.githubusercontent.com/pratomobowo/hermes-sentinel/main/install.sh | bash
```

Edit one config file:
```bash
nano /etc/hermes-sentinel/config.yaml
```

```yaml
server_name: "web-server-prod-1"
master_url: "http://YOUR-HERMES-IP:8644/webhooks/sentinel"
secret: "your-shared-secret"
watch_dirs:
  - /var/www
interval: 300
```

Start it:
```bash
systemctl enable --now sentinel
```

That's it. The satellite is now watching your server every 5 minutes.

### Step 2: Enable webhook on Hermes Agent

```bash
# Enable webhook platform
hermes config set platforms.webhook.enabled true
hermes config set platforms.webhook.extra.host 0.0.0.0
hermes config set platforms.webhook.extra.port 8644
hermes config set platforms.webhook.extra.secret "your-shared-secret"

# Restart gateway
hermes gateway restart
```

### Step 3: Create the subscription

```bash
hermes webhook subscribe sentinel \
  --prompt "🚨 Sentinel Alert from {server}\\n\\nFindings: {findings}\\n\\nAnalyze. Is this real? What should I do?" \
  --deliver telegram \
  --deliver-chat-id "YOUR-TELEGRAM-CHAT-ID"
```

Done. When satellite finds malware, Hermes AI analyzes it and sends you a Telegram alert.

---

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌───────────────┐
│  Server A    │     │  Server B    │     │  Server C      │
│  (satellite) │     │  (satellite) │     │  (satellite)   │
└──────┬───────┘     └──────┬───────┘     └──────┬────────┘
       │  POST /webhooks/sentinel              │
       │  {"findings": [...], "summary": {...}}│
       ▼                    ▼                    ▼
┌──────────────────────────────────────────────────────────┐
│                 Hermes Agent (Master)                     │
│  ┌────────────────────────────────────────────────────┐  │
│  │ 1. Receives JSON findings from satellites          │  │
│  │ 2. AI analyzes: real threat or false positive?     │  │
│  │ 3. If real → Telegram alert to you                │  │
│  │ 4. If clean → silent (no spam)                    │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
       │
       ▼
  ┌──────────┐
  │ Telegram  │  🚨 "Server-A: CRITICAL
  │ (to you)  │   Backdoor in /vendor/.../logicsecure.php"
  └──────────┘
```

**Silent when clean. Loud when compromised.**

---

## Commands

```bash
# One-time scan (cron-friendly)
hermes-sentinel.py --scan-once

# JSON output for piping
hermes-sentinel.py --scan-once --json | jq '.[].severity'

# Continuous daemon mode
systemctl start sentinel

# Check status
systemctl status sentinel

# View logs
journalctl -u sentinel -f
```

---

## What It Detects

| Threat | How |
|--------|-----|
| **Remote C2 Loader** | `base64_decode(C2_URL)` chain → `eval()` from external server |
| **Obfuscated Webshells** | 5.8MB PHP camouflaged as vendor library with fake `@package` header |
| **CGI Webshell Directories** | ALFA/Eren/jancx family + `.alfa`/`.Eren` reverse shell handlers |
| **PHP Backdoors** | `shell_exec()`, `passthru()`, `popen()`, `eval(base64_decode())` |
| **Crypto Miners** | XMRig binary disguised as `[kswapd0]`, cron re-launch every hour |
| **SEO Cloaking** | `is_google_bot()` in `index.php` → serves gambling spam to Google |
| **Gambling Injection** | `<script src="http://slot88...">`, hidden iframes, meta refresh |
| **.phtml Upload Bypass** | Extension filter bypass via `.phtml`, `.phar` in article uploads |
| **Password Uploaders** | SHA256-gated backdoors hidden in `/.logs/`, `/.cache/` |
| **Identical Clone Spread** | Same file hash across 4+ directories — attacker persistence |
| **Cron Anomalies** | `www-data` cron with foreign URLs or miner launch commands |
| **Kernel Masquerade** | Miner disguised as `[kswapd0]` via `exec -a` |
| **.htaccess Redirects** | `RewriteRule` to external gambling/malware domains |
| **Core File Tampering** | SHA256 hash mismatch vs baseline |

---

## Rule Packs

Detection rules are modular YAML files in `rules/`. Extend them without touching code:

```
rules/
├── judol.yaml        # Gambling injection patterns (16 keywords)
├── backdoor.yaml     # Remote C2, password uploaders, CGI webshells
├── webshell.yaml     # 5.8MB obfuscated, .php in wrong dirs, name disguise
├── cryptominer.yaml  # XMRig binary, kernel masquerade, cron persistence
├── seo-spam.yaml     # Cloaked index.php, spam HTML, gambling blogs
└── vuln-scan.yaml    # mysql exposed, allow_url_fopen, root SSH, writable plugins
```

Add your own:
```yaml
# rules/my-custom.yaml
patterns:
  - name: "my_company_backdoor"
    search_terms: ["suspicious_string_only_we_know"]
    severity: critical
```

---

## Configuration Reference

```yaml
# /etc/hermes-sentinel/config.yaml
server_name: "web-01"              # Server identifier in alerts
master_url: "http://IP:8644/webhooks/sentinel"  # Hermes webhook URL
secret: "shared-hmac-secret"       # Same as webhook HMAC secret
watch_dirs:                        # Directories to monitor
  - /var/www
  - /var/www/other-site
interval: 300                      # Seconds between scans (default 300)
baseline_on_start: true            # Build SHA256 baseline on first run
```

---

## How It Works

Each satellite is a single Python file (`hermes-sentinel.py`) running as a systemd service. Every 5 minutes it:

1. **Walks** all files in `watch_dirs`
2. **Scans** content for malware patterns (regex + keyword matching)
3. **Checks** crontabs for web users (`www-data`, `nginx`, `apache`)
4. **Verifies** file hashes against baseline (detects tampering)
5. **Detects** identical clones across directories (attacker persistence)
6. **Scans** running processes for kernel-masquerading miners
7. **Posts** findings as JSON to the Hermes webhook

When findings arrive at Hermes, the AI agent:
- **Reasons** about each finding: real threat or false positive?
- **Correlates** multiple findings into attack chains
- **Sends** a Telegram alert with severity, location, and remediation steps

When there are zero findings → nothing happens. No noise.

---

## Real-World Battle Test

Hermes Sentinel's v0.2.0 rules were built from forensic analysis of a real server compromise:

- **~120 malware/backdoor files** discovered across 3 months of attacks
- **Attacker:** 3 IPs from Cambodia / Southeast Asia
- **C2 Server:** `megaranger.store`
- **Signature:** `VATHAN VS EVERYBODY`, `Coded By Sole Sad & Invisible`
- **Attack chain:** SLiMS plugin upload → webshell → lateral traverse to OJS journal → crypto miner cron → SEO gambling spam

Every detection rule in the `rules/` directory maps to a real attack pattern from this case.

---

## Why Not Wazuh / OSSEC?

Wazuh is great, but it's heavy. Elasticsearch + Manager + Agent stack wants 4+ GB RAM. For a fleet of small web servers running WordPress or Laravel on a 2GB VPS, that's non-starter.

| | Wazuh | Hermes Sentinel |
|---|---|---|
| **Install** | Elasticsearch + Manager + Agent | 1 Python file |
| **RAM** | 4+ GB minimum | ~20 MB |
| **CPU** | 5-15% steady | 0.5% spike every 5 min |
| **Storage** | 10+ GB (Elasticsearch indices) | ~0 (no database) |
| **Dependencies** | Java, Elasticsearch, Filebeat | Python 3 only |
| **AI reasoning** | Manual rule tuning | LLM-powered via Hermes |
| **Telegram alerts** | DIY webhook setup | Built-in |

---

## License

MIT — built by [Next IT](https://next-it.co.id) as open source.

---

## Roadmap

- [ ] HTML signature baseline (detect injected content vs legitimate changes)
- [ ] Auto-quarantine (rename suspicious files to `.quarantine`)
- [ ] Multi-server dashboard in Hermes
- [ ] YARA rule integration
- [ ] Discord/Slack alert support
- [ ] RPM/DEB packages
- [ ] One-command Hermes master setup script
