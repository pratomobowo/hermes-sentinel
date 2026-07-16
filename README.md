# 🛡️ Hermes Sentinel

**Lightweight satellite agents that watch your web servers for malware, gambling redirects, and backdoors.**

Reports to a central [Hermes Agent](https://github.com/NousResearch/hermes-agent) for AI-powered reasoning and Telegram alerts.

---

## The Problem

You manage multiple web servers. Every few weeks, one gets hit with a judol (online gambling) injection — backdoors in `/uploads/`, injected `<script>` tags, malicious cron jobs. You don't find out until a client reports it or Google blacklists the domain.

Manual audits across 5, 10, 20 servers? **Exhausting.**

---

## How Hermes Sentinel Works

```
┌─────────────┐     ┌─────────────┐     ┌───────────────┐
│  Server A    │     │  Server B    │     │  Server C      │
│  (satellite) │     │  (satellite) │     │  (satellite)   │
└──────┬───────┘     └──────┬───────┘     └──────┬────────┘
       │                    │                    │
       │  "Backdoor found   │  "Cron anomaly"    │  "All clear"
       │   in uploads/"     │                    │
       ▼                    ▼                    ▼
┌─────────────────────────────────────────────────────┐
│               Hermes Agent (Master)                  │
│  ┌───────────────────────────────────────────────┐  │
│  │  Reasoning: "Server A has a PHP backdoor       │  │
│  │  matching pattern JUDOL-X. Server B's cron     │  │
│  │  is false-positive (expected maintenance)."    │  │
│  │                                                │  │
│  │  Alert → Telegram: "🚨 Server A compromised"  │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

**Silent when clean. Loud when compromised.**

---

## Quick Start

### 1. Deploy satellite on each server

```bash
# One-liner install
curl -sSL https://raw.githubusercontent.com/pratomobowo/hermes-sentinel/main/install.sh | bash
```

The installer:
- Downloads `hermes-sentinel.py`
- Creates a systemd service
- Starts watching `/var/www/`

### 2. Configure your Hermes Agent

```yaml
# ~/.hermes/config.yaml
webhook:
  sentinel:
    enabled: true
    port: 9191
    secret: "your-shared-secret"
```

### 3. Get alerts on Telegram

When a satellite detects:
- Injected `<script>` to gambling domains
- PHP backdoors (`eval`, `base64_decode`, `shell_exec`)
- Malicious cron jobs
- New files in `/uploads/`
- Modified `.htaccess` redirects

→ Hermes reasons about it and sends you a Telegram alert.

---

## What It Detects

| Threat | Pattern | Example |
|--------|---------|---------|
| **Remote Code Execution** | `eval(base64_decode(C2_URL))` chain | `megaranger.store` payload fetch |
| **Massive Obfuscated Webshell** | 5.8MB PHP with fake `@package` header | `logicsecure.php`, `brainpanel.php` |
| **CGI Webshell Directories** | ALFA/Eren/jancx family + `.alfa` handlers | Perl/Bash/Python reverse shells |
| **PHP Backdoors** | `shell_exec()`, `eval()`, `gzuncompress()`, `passthru()` | Command injection gateways |
| **Crypto Miners** | XMRig disguised as `[kswapd0]`, `[kcached]` | Cron re-launch every hour |
| **SEO Cloaking** | `is_google_bot()` → gambling spam / real site | Gambling links indexed by Google |
| **.phtml Upload Bypass** | Extension filter bypass via `.phtml`, `.phar` | Article submission backdoor |
| **Password-Gated Uploaders** | SHA256 hash gate in `.logs/`, `.cache/`, `.storage/` | Hidden file upload backdoors |
| **Identical Clone Spread** | Same file hash across 4+ directories | Attacker persistence cloning |
| **Gambling Injection** | `<script src="http://slot*">` | situstogel, slot88, poker |
| **Index.php Cloaking** | GoogleBot detection → spam include / real redirect | SEO poisoning |
| **Cron Anomalies** | `www-data` cron with foreign URLs or miner launch | Judol cron spam |
| **.htaccess Redirects** | `RewriteRule` to external domains | SEO spam redirect |
| **Core File Tampering** | Hash mismatch vs baseline | Modified WordPress/Laravel core |

---

## Why Not Wazuh / OSSEC?

Wazuh is great — but it's heavy. Elasticsearch + Manager + Agent stack wants 4+ GB RAM. For a fleet of small web servers running WordPress or Laravel on a 2GB VPS, that's non-starter.

**Hermes Sentinel:** 20MB RAM, 0.5% CPU, zero dependencies beyond Python 3.

---

## Architecture

```
hermes-sentinel/
├── hermes-sentinel.py    # Core satellite agent
├── install.sh            # One-liner installer
├── sentinel.service      # systemd unit template
├── hermes/               # Hermes Agent integration
│   └── sentinel-skill.md # AI reasoning skill
├── rules/                # Detection rule packs
│   ├── judol.yaml        # Gambling injection patterns
│   ├── backdoor.yaml     # PHP backdoor patterns
│   └── custom.yaml       # Your custom rules
└── tests/
```

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
