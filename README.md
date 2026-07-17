# Hermes Sentinel

**Lightweight malware detection agent.** Install on any web server. Detects gambling injections, backdoors, cryptominers, SEO spam, reverse shells, brute force attacks. **Satellite decides, Hermes oversees.**

> Single Python file. Stdlib only. Zero dependencies. Zero inbound ports.

## Architecture: Satellite Decides, Hermes Oversees

```
┌──────────────────────────────────────────────────────────────────┐
│  SERVER CLIENT (remote)                    ZERO INBOUND PORTS    │
│                                                                   │
│  Sentinel scan loop:                                              │
│    1. detect → findings (pattern + behavioral)                    │
│    2. auto-respond → quarantine/kill (configurable)               │
│    3. POST /report ──────────────→ Hermes                         │
│    4. GET  /commands?server=X ───→ Hermes (poll safe commands)    │
│                                                                   │
│  Sentinel has FULL CONTEXT: file content, process tree, network.  │
│  It decides what's dangerous. Hermes can't send destructive       │
│  commands — only administrative (rescan, status, whitelist, undo).│
└──────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────┐
│  HERMES MASTER (your server)                                      │
│                                                                   │
│  Receives reports → AI reasoning → Telegram alert                 │
│  Admin via Telegram: "quarantine X" → Hermes puts in command queue│
│  Sentinel polls queue → executes safe commands → reports back     │
└──────────────────────────────────────────────────────────────────┘
```

### Why This Architecture

| | Sentinel (on server) | Hermes (central) |
|---|---|---|
| **Detection** | ✅ Full context: files, processes, network | ❌ Only sees JSON summary |
| **Action** | ✅ Auto-quarantine, auto-kill, auto-block | ❌ No context |
| **Reports** | ✅ Sends findings to Hermes | ✅ Receives + forwards to Telegram |
| **Safe commands** | ✅ Rescan, status, whitelist, rebuild, undo | ✅ Admin request via Telegram |

---

## Roadmap

| Version | Focus | Status |
|---------|-------|:------:|
| v0.3.0 | Pattern matcher + quarantine | ✅ Baseline |
| **v0.4.0** | Smart integrity: git-aware, whitelist, dedup, severity, diff | ✅ Shipped |
| **v0.5.0** | Behavioral: process scanner, network monitor, user session, cron/timer | ✅ Shipped |
| **v0.7.0** | Incremental scan: inotify real-time, mtime fallback, large file optimization | ✅ Shipped |
| **v0.7.1** | Behavioral dedup with SQLite persistence across scan-once restarts | ✅ Shipped |
| **v0.9.0** | Command & Control: two-way Sentinel ↔ Hermes, safe command queue | 🚧 Next |
| **v0.8.0** | Correlation engine: incident grouping, kill chain detection | 📋 Planned |
| **v1.0.0** | Production: dashboard, heartbeat, auto-update, plugin system | 📋 Planned |

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

### 21+ Detection Categories

| # | Category | Severity | Detection Method |
|---|----------|:--------:|------------------|
| 1 | Gambling domain injection | High | Content pattern |
| 2 | Remote C2 code loader (base64 → eval) | Critical | Content pattern |
| 3 | Password-gated file uploaders | Critical | Content pattern |
| 4 | gzuncompress → eval chain (VATHAN) | Critical | Content pattern |
| 5 | CGI webshell directories (ALFA/Eren/jancx) | Critical | Path pattern |
| 6 | Obfuscated webshell (fake @package) | Critical | Content + size |
| 7 | PHP in JS/CSS/Images dirs | High | Path pattern |
| 8 | File manager webshell (base64 chain) | Critical | Content pattern |
| 9 | Tech name disguises (45 patterns) | Medium | Content pattern |
| 10 | Cloned malware (3+ identical files) | Critical | File hash |
| 11 | Crypto miner binary + config | Critical | Filename + process |
| 12 | Kernel masquerade (exec -a [kswapd0]) | Critical | Process scanner |
| 13 | Cron miner persistence | Critical | Cron scanner |
| 14 | SEO spam home.php (100KB+) | High | Size + content |
| 15 | GoogleBot cloaking | Critical | Content pattern |
| 16 | REP/MAR spam HTML | Medium | Filename pattern |
| 17 | Upload filter bypass (.phtml/.phar) | Critical | Extension check |
| 18 | Reverse shell (/dev/tcp/) | Critical | Process scanner |
| 19 | Botnet port outbound (IRC 6667, etc.) | High | Network scanner |
| 20 | SSH brute force (10+ failures) | High | User session scanner |
| 21 | New listening port (backdoor) | High | Network delta |

### Smart Integrity (v0.4.0 — v0.7.1)

| Feature | Detail |
|---------|--------|
| **Git-aware** | `git pull`/checkout = silent. Only alert uncommitted changes |
| **Whitelist** | `integrity_whitelist` glob patterns (vendor/*, *.lock) |
| **Alert dedup** | SQLite-persisted. Same event = 1 alert in window. Survives restarts |
| **Path severity** | `/images/` → HIGH, `/vendor/` → LOW, everything else → MEDIUM |
| **Diff output** | `"Hash changed — 142 lines, 4821 bytes"` |
| **Volatile exclude** | cache/, tmp/, logs/, sessions/ — skip integrity, keep malware scan |

### Behavioral Monitoring (v0.5.0)
- **Process scanner:** `/proc/*/cmdline` — reverse shells, Python exec, shell spawned by nginx
- **Network monitor:** `/proc/net/tcp` — botnet ports, high-port outbound, new listeners
- **User session:** new users, root SSH, odd-hour login, brute force
- **Systemd timer:** new `.timer` files via SQLite delta
- **Extended cron:** `/etc/crontab` + `/etc/cron.d/` delta

### Incremental Scanning (v0.7.0)
- **inotify:** Linux kernel events for real-time file monitoring
- **mtime fallback:** when inotify unavailable or max watches exceeded
- **Large file optimization:** >10MB → scan head+tail only
- **Full scan safety net:** every 15 minutes ensures no missed changes

---

## Configuration

```yaml
# /etc/hermes-sentinel/config.yaml
server_name: "web-01"                                          # Identifier in alerts
master_url: "http://YOUR-HERMES-IP:8644/webhooks/sentinel"    # Hermes webhook
secret: "shared-secret"                                        # Same as webhook HMAC
watch_dirs:                                                    # Directories to monitor
  - /var/www
interval: 300                                                  # Seconds between scans (daemon poll interval)
baseline_on_start: true                                        # Build SHA256 baseline
quarantine: false                                              # Auto-isolate CRITICAL+HIGH threats
integrity_excludes:                                            # Skip integrity for volatile dirs
  - /var/www/app/cache/
  - "*.log"
integrity_whitelist:                                           # Skip integrity for known-safe files
  - composer.lock
  - "vendor/*"
```

---

## Commands

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

## Why Not Wazuh?

| | Wazuh | Hermes Sentinel |
|---|---|---|
| **Install** | Elasticsearch + Manager + Agent | 1 Python file |
| **RAM** | 4+ GB | ~20 MB |
| **Dependencies** | Java, ES, Filebeat | Python 3 only |
| **AI reasoning** | Manual rule tuning | LLM via Hermes |
| **Telegram alerts** | DIY webhook setup | Built-in |
| **Attack surface** | Agent opens ports | Zero inbound ports |

---

## License

MIT — built by [Next IT](https://next-it.co.id).
