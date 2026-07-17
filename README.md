# Hermes Sentinel

**Lightweight malware detection agents.** Install on any web server. Detects gambling injections, backdoors, cryptominers, SEO spam. Silent when clean — reports to your Hermes Agent for AI-powered alerts. Optionally auto-quarantines threats.

---

## The Architecture (Two Separate Servers)

```
┌─────────────────────────────────┐     ┌──────────────────────────────────┐
│  Your Client's Server            │     │  Your Server (Hermes Master)     │
│  (Satellite Agent)               │     │                                  │
│                                  │     │  hermes config set ...           │
│  curl | bash  ← install          │     │  hermes webhook subscribe ...   │
│  systemctl start sentinel        │     │  hermes gateway restart         │
│                                  │     │                                  │
│  Runs: hermes-sentinel.py        │────▶│  Receives: POST /webhooks/      │
│  Scans: /var/www every 5min      │     │            sentinel             │
│  Sends: JSON to webhook          │     │  AI analyzes findings           │
│                                  │     │  Sends Telegram alert to you    │
│  Needs: ONLY Python 3            │     │  Needs: Hermes Agent installed  │
│  Does NOT need Hermes            │     │  Needs: Telegram connected      │
└─────────────────────────────────┘     └──────────────────────────────────┘
```

**The satellite does NOT need Hermes.** It's a single Python file. It just sends scan results to your Hermes server via HTTP.

---

## Quick Start

### Part A: Install Satellite on Client Server (2 min)

On each web server you want to protect:

```bash
curl -sSL https://raw.githubusercontent.com/pratomobowo/hermes-sentinel/main/install.sh | bash
```

The installer will ask:
- **Hermes webhook URL** — where to send reports (your Hermes server IP)
- **Shared Secret** — matches what you set on Hermes master
- **Server name** — for identification in alerts
- **Directories to scan** — defaults to `/var/www`
- **Enable quarantine?** — auto-isolate CRITICAL/HIGH threats (optional)

That's it on the client side. Start watching:
```bash
systemctl start sentinel
```

**Requirements on client server:** Python 3. Nothing else. No database, no framework, no Hermes.

### Part B: Setup Hermes Master (on your server)

Your server (where Hermes Agent + Telegram live):

```bash
# Enable webhooks
hermes config set platforms.webhook.enabled true
hermes config set platforms.webhook.extra.host 0.0.0.0
hermes config set platforms.webhook.extra.port 8644
hermes config set platforms.webhook.extra.secret "your-shared-secret"

# Restart gateway
hermes gateway restart

# Create sentinel subscription
hermes webhook subscribe sentinel \
  --prompt "Sentinel Alert from {server}. Summary: {summary}. Findings: {findings}. Analyze and report." \
  --deliver telegram \
  --deliver-chat-id "YOUR-TELEGRAM-CHAT-ID"
```

Done. When satellite finds malware, Hermes AI analyzes it and sends you a Telegram alert.

### Part C: Verify Everything Works

From the satellite server, trigger a test report:
```bash
python3 -c "
import urllib.request, json, time
payload = json.dumps({
    'server': 'test-server',
    'timestamp': time.time(),
    'findings': [{'type': 'test_scan', 'severity': 'low', 'detail': 'Manual test report'}],
    'summary': {'total': 1, 'critical': 0, 'high': 0, 'medium': 0, 'low': 1}
}).encode()
r = urllib.request.Request('http://YOUR-HERMES-IP:8644/webhooks/sentinel',
    data=payload, headers={'Content-Type': 'application/json'})
print(urllib.request.urlopen(r, timeout=10).read().decode())
"
```

You should get a Telegram alert from Hermes analyzing the test report.

---

## Detection Engine

### 18 Detection Categories (v0.2.0)

| # | Category | Rule Pack | Severity |
|---|----------|-----------|----------|
| 1 | Gambling domain injection | `judol.yaml` | High |
| 2 | Remote C2 code loader (base64 → eval) | `backdoor.yaml` | Critical |
| 3 | Password-gated file uploaders (.logs/.cache/.storage/) | `backdoor.yaml` | Critical |
| 4 | gzuncompress → eval chain (VATHAN signature) | `backdoor.yaml` | Critical |
| 5 | Known attacker C2 domains (megaranger.store, etc.) | `backdoor.yaml` | Critical |
| 6 | CGI webshell directories (ALFA/Eren/jancx) | `backdoor.yaml` | Critical |
| 7 | Obfuscated 5.8MB webshell (fake @package header) | `webshell.yaml` | Critical |
| 8 | PHP files in JS/CSS/Images/Locale directories | `webshell.yaml` | High |
| 9 | File manager webshell (35KB-160KB base64 chain) | `webshell.yaml` | Critical |
| 10 | Generic tech name disguises (45 patterns) | `webshell.yaml` | Medium |
| 11 | Identical file cloned across 3+ directories | `webshell.yaml` | Critical |
| 12 | Crypto miner binary + config | `cryptominer.yaml` | Critical |
| 13 | Kernel process masquerade (exec -a [kswapd0]) | `cryptominer.yaml` | Critical |
| 14 | Cron miner persistence (every hour re-launch) | `cryptominer.yaml` | Critical |
| 15 | SEO spam home.php (100KB+ gambling keywords) | `seo-spam.yaml` | High |
| 16 | Index.php GoogleBot cloaking | `seo-spam.yaml` | Critical |
| 17 | REP/MAR auto-generated spam HTML | `seo-spam.yaml` | Medium |
| 18 | .phtml/.phar upload filter bypass | Agent core | Critical |

### File Integrity Monitoring

Persistent SHA256 baseline via SQLite. Survives daemon restarts and reboots.

| Detection | Severity | Description |
|-----------|----------|-------------|
| `file_modified` | Medium | Hash changed from baseline |
| `new_file` | Medium | New file appeared (not in baseline) |
| `file_deleted` | Low | Baseline file disappeared from disk |

### Optional: Auto-Quarantine

When `quarantine: true` is set, CRITICAL and HIGH severity files are automatically moved to `/etc/hermes-sentinel/quarantine/<timestamp>/`. Each file gets a `.meta.json` with original path, severity, and detection type — so you can always restore. Audit trail logged to SQLite.

---

## Commands (on Satellite)

```bash
# One-time scan
python3 /opt/hermes-sentinel/hermes-sentinel.py --scan-once

# JSON output (for cron piping)
python3 /opt/hermes-sentinel/hermes-sentinel.py --scan-once --json

# Service control
systemctl start sentinel
systemctl stop sentinel
systemctl status sentinel

# Logs
journalctl -u sentinel -f

# View quarantine log
sqlite3 /etc/hermes-sentinel/baseline.db "SELECT * FROM quarantine_log ORDER BY id DESC LIMIT 10"
```

---

## Configuration

```yaml
# /etc/hermes-sentinel/config.yaml
server_name: "web-01"                                          # Identifier in alerts
master_url: "http://YOUR-HERMES-IP:8644/webhooks/sentinel"    # Hermes webhook
secret: "shared-secret"                                        # Same as webhook HMAC
watch_dirs:                                                    # Directories to monitor
  - /var/www
  - /var/www/other-site
interval: 300                                                  # Seconds between scans
baseline_on_start: true                                        # Build SHA256 baseline
quarantine: false                                              # Auto-isolate CRITICAL+HIGH threats
```

**Persistent baseline** is stored at `/etc/hermes-sentinel/baseline.db` (SQLite). Survives restarts and reboots — no rebuild needed unless `baseline_on_start: true`.

---

## Rule Packs

Detection rules are modular YAML in `rules/`. Extend without touching code:

```
rules/
├── judol.yaml        # Gambling injection (16 keywords)
├── backdoor.yaml     # Remote C2, password uploaders, CGI webshells, C2 domains
├── webshell.yaml     # 5.8MB obfuscated, .php in wrong dirs, name disguise, clone detection
├── cryptominer.yaml  # XMRig binary, kernel masquerade, cron persistence
├── seo-spam.yaml     # Cloaked index.php, spam HTML, gambling blogs
└── vuln-scan.yaml    # mysql exposed, allow_url_fopen, root SSH
```

Rule packs support: `search_terms`, `regex`, `combined_regex`, `domains`, `file_pattern`, `path_pattern`, `naming_pattern`, `size_kb_min/max`, `must_also_contain`, and nested `triggers`.

---

## Real-World Battle Test

v0.2.0 rules were built from forensic analysis of a real server compromise:

- **~120 malware files** across 3 months of attacks
- **Attacker IPs:** 116.212.128.214 (Cambodia), 103.87.68.151, 103.132.8.4
- **C2 Server:** `megaranger.store`
- **Signatures:** `VATHAN VS EVERYBODY`, `Coded By Sole Sad & Invisible`
- **Attack chain:** SLiMS plugin upload → webshell → OJS lateral → cryptominer → SEO spam

---

## Why Not Wazuh?

| | Wazuh | Hermes Sentinel |
|---|---|---|
| **Install** | Elasticsearch + Manager + Agent | 1 Python file |
| **RAM** | 4+ GB | ~20 MB |
| **Dependencies** | Java, ES, Filebeat | Python 3 only |
| **AI reasoning** | Manual rule tuning | LLM via Hermes |
| **Telegram alerts** | DIY webhook setup | Built-in |

---

## License

MIT — built by [Next IT](https://next-it.co.id).
