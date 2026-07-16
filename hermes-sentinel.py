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

# Suspicious cron patterns
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
