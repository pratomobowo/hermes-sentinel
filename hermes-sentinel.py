#!/usr/bin/env python3
"""Hermes Sentinel — Lightweight web server malware detection agent.

Watches your web server for malware, gambling redirects, and backdoors.
Reports findings to a central Hermes Agent for AI-powered reasoning.

Usage:
    hermes-sentinel.py --config config.yaml
    hermes-sentinel.py --scan-once --config config.yaml

Config (YAML):
    master_url: "https://hermes.example.com/webhook/sentinel"
    secret: "shared-secret"
    server_name: "web-server-1"
    watch_dirs:
      - /var/www
    interval: 300  # seconds between scans (default 300)
    baseline_on_start: true  # hash core files on first run (default true)
"""

import subprocess
import hashlib
import json
import os
import re
import sys
import time
import urllib.request
import argparse
from pathlib import Path

# ─── Pattern Rules ────────────────────────────────────────────

# Known gambling domains (extend this list)
JUDOL_DOMAINS = [
    "slot", "togel", "poker", "casino", "judi", "bola",
    "maxwin", "pragmatic", "pgsoft", "zeus", "mahjong",
    "starlight", "sweet-bonanza", "gacor", "bocoran",
    "hoki", "jackpot", "bandar", "dewa", "raja",
]

# Suspicious PHP patterns
PHP_BACKDOOR_PATTERNS = [
    (r"\beval\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)", "Backdoor: eval() with encoding function"),
    (r"\bshell_exec\s*\(", "Backdoor: shell_exec()"),
    (r"\bsystem\s*\(", "Backdoor: system()"),
    (r"\bpassthru\s*\(", "Backdoor: passthru()"),
    (r"\bpopen\s*\(", "Backdoor: popen()"),
    (r"\bexec\s*\(", "Backdoor: exec()"),
    (r"\$\w+\s*=\s*file_get_contents\s*\(\s*['\"]php://input['\"]", "Backdoor: php://input capture"),
    (r"function\s+\w+\s*\([^)]*\)\s*\{\s*.*\$_(GET|POST|REQUEST|COOKIE)", "Backdoor: web-command gateway"),
    (r'\$_POST\s*\[[\'"]\w+[\'"]\]\s*\(\s*\$_POST', "Backdoor: callback via POST"),
]

# ─── New: Rule Pack Loader ─────────────────────────────────────

RULE_PACKS = {}
def _load_rule_packs(rule_dir=None):
    """Load YAML rule packs from rules/ directory."""
    if rule_dir is None:
        rule_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")

    packs = {}
    if not os.path.isdir(rule_dir):
        return packs

    for fname in sorted(os.listdir(rule_dir)):
        if not fname.endswith((".yaml", ".yml")):
            continue
        try:
            with open(os.path.join(rule_dir, fname)) as f:
                import yaml
                data = yaml.safe_load(f)
                if data and "patterns" in data:
                    packs[fname] = data["patterns"]
        except Exception:
            pass
    return packs

# ─── New: Cryptominer Detection ────────────────────────────────

MINER_FILENAMES = {"defunct", "gs-dbus", "xmrig", "MINER_defunct_xmrig"}
MINER_PROCESS_NAMES = ["[kswapd0]", "[kcached]", "[kworker]", "[kthreadd]"]

def scan_cryptominers(dirs):
    """Scan for crypto miner binaries, configs, and cron persistence."""
    findings = []
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            for f in files:
                if f in MINER_FILENAMES or any(f.startswith(p) for p in ["defunct", "gs-dbus", "xmrig"]):
                    fp = os.path.join(root, f)
                    findings.append({
                        "type": "cryptominer_binary",
                        "file": fp,
                        "detail": f"Cryptominer binary detected: {f}",
                        "severity": "critical",
                    })
                if f.endswith(".dat") and any(n in root for n in ["template", "css", "js", "plugins"]):
                    fp = os.path.join(root, f)
                    findings.append({
                        "type": "miner_config_in_webroot",
                        "file": fp,
                        "detail": "Miner config file in web-accessible directory",
                        "severity": "high",
                    })
    # Check process list
    try:
        ps_out = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=5)
        for line in ps_out.stdout.splitlines():
            for name in MINER_PROCESS_NAMES:
                if name in line and "grep" not in line and "kernel" not in line.lower():
                    findings.append({
                        "type": "kernel_masquerade_process",
                        "detail": f"Process masquerading as kernel daemon: {name}",
                        "ps_line": line.strip(),
                        "severity": "critical",
                    })
    except Exception:
        pass
    return findings

# ─── New: SEO Spam & Cloaking Detection ────────────────────────

def scan_seo_spam(dirs):
    """Detect gambling SEO spam, cloaked index.php, and spam HTML files."""
    findings = []
    SPAM_HTML_GLOBS = ["*-REP.html", "*-MAR.html"]
    CLOAKING_TERMS = ["is_google_bot", "googlebot", "index_old.php", "strpos.*googlebot"]

    for d in dirs:
        if not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            for f in files:
                fp = os.path.join(root, f)

                # home.php with gambling keywords
                if f == "home.php":
                    try:
                        sz = os.path.getsize(fp)
                        if sz > 100000:  # >100KB
                            findings.append({
                                "type": "seo_spam_homepage",
                                "file": fp,
                                "detail": f"Large home.php ({sz} bytes) — likely SEO spam landing page",
                                "severity": "high",
                            })
                    except OSError:
                        pass

                # Cloaked index.php
                if f == "index.php":
                    try:
                        with open(fp, "r", errors="replace") as fh:
                            content = fh.read()
                        if "is_google_bot" in content or "googlebot" in content.lower():
                            findings.append({
                                "type": "cloaked_index_php",
                                "file": fp,
                                "detail": "index.php contains GoogleBot cloaking logic",
                                "severity": "critical",
                            })
                    except Exception:
                        pass

                # REP/MAR spam HTML
                import fnmatch
                for pat in SPAM_HTML_GLOBS:
                    if fnmatch.fnmatch(f, pat):
                        findings.append({
                            "type": "seo_spam_html",
                            "file": fp,
                            "detail": "Auto-generated SEO spam HTML file",
                            "severity": "medium",
                        })

    return findings

# ─── New: PHTML/PHAR Backdoor Detection ────────────────────────

SHELL_EXTENSIONS = {".phtml", ".phar", ".pht", ".php5", ".php7", ".shtml"}

def scan_shell_extensions(dirs):
    """Detect .phtml/.phar files that bypass file upload filters."""
    findings = []
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in SHELL_EXTENSIONS:
                    fp = os.path.join(root, f)
                    findings.append({
                        "type": "bypass_extension_backdoor",
                        "file": fp,
                        "detail": f"{ext} file bypasses PHP-extension-only upload filter",
                        "severity": "critical",
                    })
    return findings

# ─── New: CGI Webshell Directory Detection ─────────────────────

CGI_WEBSHELL_DIRS = ["ALFA_DATA", "ERENUSE", "jancox", "osdcgiapi", "alfacgiapi", "Erencgiapi", "RIMURU"]
CGI_WEBSHELL_EXTS = {".alfa", ".Eren", ".rimuru"}

def scan_cgi_webshell_dirs(dirs):
    """Detect CGI webshell directories and .alfa handlers."""
    findings = []
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for root, dirs_list, files in os.walk(d):
            for dirname in dirs_list:
                if dirname in CGI_WEBSHELL_DIRS:
                    findings.append({
                        "type": "cgi_webshell_directory",
                        "file": os.path.join(root, dirname),
                        "detail": f"CGI webshell directory: {dirname} (ALFA/Eren/jancx family)",
                        "severity": "critical",
                    })
            for f in files:
                ext = os.path.splitext(f)[1]
                if ext in CGI_WEBSHELL_EXTS:
                    fp = os.path.join(root, f)
                    findings.append({
                        "type": "cgi_webshell_handler",
                        "file": fp,
                        "detail": f"CGI webshell handler: {ext}",
                        "severity": "critical",
                    })
    return findings

# ─── New: Clone Detection ──────────────────────────────────────

def scan_cloned_malware(dirs):
    """Detect identical malware files cloned across multiple directories."""
    findings = []
    hash_map = {}
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            for f in files:
                if not f.endswith(".php"):
                    continue
                fp = os.path.join(root, f)
                try:
                    sz = os.path.getsize(fp)
                    if sz < 1000 or sz > 10000000:
                        continue
                except OSError:
                    continue
                h = hash_file(fp)
                if h:
                    hash_map.setdefault(h, []).append(fp)

    for h, paths in hash_map.items():
        if len(paths) >= 3:
            findings.append({
                "type": "cloned_malware",
                "detail": f"Identical file found in {len(paths)} locations — persistence cloning",
                "files": paths[:5],
                "severity": "critical",
            })
    return findings

# ─── Original: Suspicious cron patterns ────────────────────────

SUSPICIOUS_CRON_PATTERNS = [
    (r"(wget|curl)\s+.*(\.xyz|\.top|\.tk|\.ml|\.ga|\.cf)", "Cron: foreign-TLD download"),
    (r"@(reboot|daily|hourly).*wget", "Cron: suspicious download on schedule"),
]

# File types to scan content of
SCAN_EXTENSIONS = {".php", ".html", ".htm", ".js", ".htaccess", ".phtml", ".php5", ".php7", ".pht", ".shtml"}

# File types that should NEVER exist in uploads (always flag)
DANGEROUS_IN_UPLOADS = {".php", ".phtml", ".php5", ".php7", ".pht", ".sh", ".exe", ".py", ".pl"}


def hash_file(path):
    """Return SHA256 of a file."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def build_baseline(dirs):
    """Build initial hash baseline for all scannable files."""
    baseline = {}
    for d in dirs:
        for root, _, files in os.walk(d):
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in SCAN_EXTENSIONS:
                    fp = os.path.join(root, f)
                    file_hash = hash_file(fp)
                    if file_hash:
                        baseline[fp] = file_hash
    return baseline


def scan_files(dirs, baseline=None):
    """Scan watched directories for threats. Returns list of findings."""
    findings = []

    for d in dirs:
        if not os.path.isdir(d):
            continue

        for root, _, files in os.walk(d):
            for f in files:
                fp = os.path.join(root, f)
                ext = os.path.splitext(f)[1].lower()

                # Check for dangerous files in uploads
                uploads_match = re.search(r"/uploads/", root)
                if uploads_match and ext in DANGEROUS_IN_UPLOADS:
                    findings.append({
                        "type": "dangerous_file_in_uploads",
                        "file": fp,
                        "detail": f"{ext} file found in uploads directory",
                        "severity": "critical",
                    })
                    continue

                # Only scan content-relevant file types
                if ext not in SCAN_EXTENSIONS:
                    continue

                # Check baseline (file tampering)
                if baseline and fp in baseline:
                    current_hash = hash_file(fp)
                    if current_hash and current_hash != baseline[fp]:
                        findings.append({
                            "type": "file_modified",
                            "file": fp,
                            "detail": "File hash changed from baseline",
                            "severity": "medium",
                        })

                # Read and scan file content
                try:
                    with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                except (OSError, PermissionError):
                    continue

                # Scan for domain-level attacks
                for domain in JUDOL_DOMAINS:
                    if domain.lower() in content.lower():
                        findings.append({
                            "type": "suspicious_domain",
                            "file": fp,
                            "detail": f"Reference to gambling-related domain: {domain}",
                            "severity": "high",
                        })
                        break

                # Scan for PHP backdoors
                for pattern, desc in PHP_BACKDOOR_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        findings.append({
                            "type": "php_backdoor",
                            "file": fp,
                            "detail": desc,
                            "pattern": pattern,
                            "severity": "critical",
                        })
                        break

                # Scan .htaccess for suspicious redirects
                if f == ".htaccess":
                    redirects = re.findall(r"RewriteRule\s+.*https?://([^\s\]]+)", content, re.IGNORECASE)
                    for target in redirects:
                        findings.append({
                            "type": "htaccess_redirect",
                            "file": fp,
                            "detail": f".htaccess redirect to external domain: {target}",
                            "severity": "high",
                        })

    return findings


def scan_crontabs():
    """Scan crontabs for web user for suspicious entries."""
    findings = []
    users_to_check = ["www-data", "nginx", "apache", "nobody"]

    for user in users_to_check:
        try:
            output = subprocess.run(
                ["crontab", "-l", "-u", user],
                capture_output=True, text=True, timeout=5
            )
            if output.returncode != 0:
                continue

            for line in output.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                for pattern, desc in SUSPICIOUS_CRON_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            "type": "suspicious_cron",
                            "user": user,
                            "detail": desc,
                            "line": line,
                            "severity": "high",
                        })
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue

    return findings


def scan_recent_files(dirs, minutes=60):
    """Find recently created/modified files in watched directories."""
    findings = []
    cutoff = time.time() - (minutes * 60)

    for d in dirs:
        if not os.path.isdir(d):
            continue

        for root, _, files in os.walk(d):
            for f in files:
                fp = os.path.join(root, f)
                try:
                    mtime = os.path.getmtime(fp)
                except OSError:
                    continue

                if mtime > cutoff:
                    findings.append({
                        "type": "recent_file",
                        "file": fp,
                        "detail": f"File modified in last {minutes} minutes",
                        "mtime": mtime,
                        "severity": "low",
                    })

    return findings


def report_findings(findings, config):
    """Send findings to Hermes Agent master."""
    if not findings or not config.get("master_url"):
        return

    payload = json.dumps({
        "server": config.get("server_name", os.uname().nodename),
        "timestamp": time.time(),
        "findings": findings,
        "summary": {
            "total": len(findings),
            "critical": sum(1 for f in findings if f.get("severity") == "critical"),
            "high": sum(1 for f in findings if f.get("severity") == "high"),
            "medium": sum(1 for f in findings if f.get("severity") == "medium"),
            "low": sum(1 for f in findings if f.get("severity") == "low"),
        }
    }).encode("utf-8")

    secret = config.get("secret", "")
    req = urllib.request.Request(
        config["master_url"],
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-Sentinel-Secret": secret,
            "User-Agent": "Hermes-Sentinel/1.0",
        },
    )

    try:
        urllib.request.urlopen(req, timeout=10)
        return True
    except Exception as e:
        print(f"Failed to report: {e}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(description="Hermes Sentinel Agent")
    parser.add_argument("--config", default="/etc/hermes-sentinel/config.yaml", help="Config file path")
    parser.add_argument("--scan-once", action="store_true", help="Scan once and exit (skip daemon loop)")
    parser.add_argument("--json", action="store_true", help="Output findings as JSON (for cron/pipe usage)")
    args = parser.parse_args()

    # Load config — simple YAML-like format
    config = _load_config(args.config)

    watch_dirs = config.get("watch_dirs", ["/var/www"])
    interval = int(config.get("interval", 300))
    baseline = {}

    if config.get("baseline_on_start", True):
        print(f"[sentinel] Building baseline for {len(watch_dirs)} directories...")
        baseline = build_baseline(watch_dirs)
        print(f"[sentinel] Baseline: {len(baseline)} files")

    # Single scan mode (for cron usage)
    if args.scan_once or args.json:
        findings = scan_files(watch_dirs, baseline)
        findings.extend(scan_crontabs())
        findings.extend(scan_recent_files(watch_dirs, minutes=60))
        findings.extend(scan_cryptominers(watch_dirs))
        findings.extend(scan_seo_spam(watch_dirs))
        findings.extend(scan_shell_extensions(watch_dirs))
        findings.extend(scan_cgi_webshell_dirs(watch_dirs))
        findings.extend(scan_cloned_malware(watch_dirs))

        if args.json:
            print(json.dumps(findings, indent=2, ensure_ascii=False))
        elif findings:
            print(f"[sentinel] {len(findings)} findings:")
            for f in findings:
                print(f"  [{f['severity'].upper()}] {f['type']}: {f.get('file', f.get('line', ''))} — {f['detail']}")
        else:
            print("[sentinel] All clear — no threats detected.")
        return 0

    # Daemon mode — continuous watching
    print(f"[sentinel] Watching {len(watch_dirs)} directories every {interval}s...")
    print(f"[sentinel] Master: {config.get('master_url', 'none')}")

    while True:
        try:
            print(f"[sentinel] Scanning... ({time.strftime('%H:%M:%S')})")
            findings = scan_files(watch_dirs, baseline)
            findings.extend(scan_crontabs())
            findings.extend(scan_recent_files(watch_dirs, minutes=interval // 60))
            findings.extend(scan_cryptominers(watch_dirs))
            findings.extend(scan_seo_spam(watch_dirs))
            findings.extend(scan_shell_extensions(watch_dirs))
            findings.extend(scan_cgi_webshell_dirs(watch_dirs))
            findings.extend(scan_cloned_malware(watch_dirs))

            if findings:
                print(f"[sentinel] {len(findings)} findings detected")
                for f in findings:
                    if f.get("severity") in ("critical", "high"):
                        print(f"  🚨 [{f['severity'].upper()}] {f['type']}: {f.get('file', '')} — {f['detail']}")

                report_findings(findings, config)
            else:
                print("[sentinel] Clean")

            time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[sentinel] Shutting down.")
            return 0
        except Exception as e:
            print(f"[sentinel] Error: {e}", file=sys.stderr)
            time.sleep(interval)


def _load_config(path):
    """Load simple YAML-like config. Falls back to defaults if file missing."""
    config = {
        "server_name": os.uname().nodename,
        "watch_dirs": ["/var/www"],
        "interval": 300,
        "baseline_on_start": True,
    }

    if not os.path.exists(path):
        return config

    # Use a simple line parser (no PyYAML dependency)
    current_key = None
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if ":" in line and not line.startswith(" "):
                key, val = line.split(":", 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")

                if key == "watch_dirs":
                    current_key = key
                    config[key] = []
                elif val == "true":
                    config[key] = True
                elif val == "false":
                    config[key] = False
                elif val.isdigit():
                    config[key] = int(val)
                else:
                    config[key] = val
            elif line.startswith("- ") and current_key == "watch_dirs":
                config["watch_dirs"].append(line[2:].strip())

    return config


if __name__ == "__main__":
    sys.exit(main())
