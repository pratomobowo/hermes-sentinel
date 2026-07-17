#!/usr/bin/env python3
"""Hermes Sentinel v0.7.0 — Lightweight web server malware detection agent.

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
import sqlite3
import shutil
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

    yaml_loaded = False
    for fname in sorted(os.listdir(rule_dir)):
        if not fname.endswith((".yaml", ".yml")):
            continue
        try:
            with open(os.path.join(rule_dir, fname)) as f:
                import yaml
                yaml_loaded = True
                data = yaml.safe_load(f)
                if data and "patterns" in data:
                    packs[fname] = data["patterns"]
        except ImportError:
            print("[sentinel] PyYAML not installed — skipping rule packs. Install: pip install PyYAML", file=sys.stderr)
            return {}
        except Exception:
            pass
    return packs


# ─── Scan with loaded rule packs ─────────────────────────────────

def scan_rule_packs(dirs, rule_packs):
    """Scan watch dirs using YAML rule pack patterns."""
    findings = []

    # Keys that indicate a pattern is meant for file-level scanning
    FILE_FILTER_KEYS = {
        "search_terms", "regex", "combined_regex", "domains",
        "must_also_contain", "file_pattern", "file_names", "file_name",
        "naming_pattern", "path_pattern", "path_indicators", "path_context",
        "size_kb_min", "size_kb_max", "size_mb_gt", "size_trigger_mb",
        "triggers",
    }

    for d in dirs:
        if not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            for f in files:
                fp = os.path.join(root, f)
                ext = os.path.splitext(f)[1].lower()

                try:
                    sz = os.path.getsize(fp)
                except OSError:
                    continue

                for pack_name, patterns in rule_packs.items():
                    for pattern in patterns:
                        name = pattern.get("name", "unknown")
                        severity = pattern.get("severity", "medium")
                        desc = pattern.get("description", "")

                        # Skip patterns not meant for file-content scanning
                        # (server health checks, cron-only, URL-only patterns, etc.)
                        pattern_keys = set(pattern.keys()) - {"name", "severity", "description"}
                        if not (pattern_keys & FILE_FILTER_KEYS):
                            continue

                        # --- Pre-content filters ---

                        # file_pattern (glob match on filename)
                        fpm = pattern.get("file_pattern")
                        if fpm:
                            import fnmatch
                            if not fnmatch.fnmatch(f, fpm):
                                continue

                        # file_names (exact match)
                        fn_list = pattern.get("file_names", [])
                        if fn_list and f not in fn_list:
                            continue

                        # file_name (single exact match)
                        file_name = pattern.get("file_name")
                        if file_name and f != file_name:
                            continue

                        # naming_pattern (regex on filename)
                        np_list = pattern.get("naming_pattern", [])
                        if np_list and not any(re.search(p, f) for p in np_list):
                            continue

                        # path_pattern (regex on directory path)
                        pp_raw = pattern.get("path_pattern")
                        if pp_raw and not re.search(pp_raw, root):
                            continue

                        # path_indicators (regex on full path)
                        pi_list = pattern.get("path_indicators", [])
                        if pi_list and not any(re.search(p, fp) for p in pi_list):
                            continue

                        # path_context (substring in root)
                        pc = pattern.get("path_context")
                        if pc and pc not in root:
                            continue

                        # --- Size triggers ---

                        if pattern.get("size_kb_min") and sz < pattern["size_kb_min"] * 1024:
                            continue
                        if pattern.get("size_kb_max") and sz > pattern["size_kb_max"] * 1024:
                            continue
                        if pattern.get("size_mb_gt") and sz < pattern["size_mb_gt"] * 1024 * 1024:
                            continue
                        if pattern.get("size_trigger_mb") and sz < pattern["size_trigger_mb"] * 1024 * 1024:
                            continue

                        # --- Nested triggers (webshell.yaml style) ---

                        triggers = pattern.get("triggers")
                        if triggers and isinstance(triggers, dict):
                            t_size = triggers.get("size_mb_gt")
                            if t_size and sz < t_size * 1024 * 1024:
                                continue
                            t_ext = triggers.get("extension")
                            if t_ext:
                                t_ext_norm = t_ext if t_ext.startswith(".") else f".{t_ext}"
                                if ext != t_ext_norm and ext != t_ext:
                                    continue
                            t_dirs = triggers.get("likely_in_dirs", [])
                            if t_dirs and not any(d in root.split(os.sep) for d in t_dirs):
                                continue

                        # --- Content checks ---

                        need_content = any([
                            pattern.get("search_terms"),
                            pattern.get("regex"),
                            pattern.get("combined_regex"),
                            pattern.get("domains"),
                            pattern.get("must_also_contain"),
                            triggers and isinstance(triggers, dict) and triggers.get("must_contain"),
                        ])

                        content = None
                        if need_content:
                            if ext not in SCAN_EXTENSIONS:
                                continue
                            try:
                                with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                                    content = fh.read()
                            except (OSError, PermissionError):
                                continue

                        # search_terms (ANY match)
                        st = pattern.get("search_terms", [])
                        if st:
                            if content is None:
                                continue
                            if not any(t.lower() in content.lower() for t in st):
                                continue

                        # regex
                        rx = pattern.get("regex")
                        if rx:
                            if content is None:
                                continue
                            if not re.search(rx, content, re.IGNORECASE | re.DOTALL):
                                continue

                        # combined_regex
                        crx = pattern.get("combined_regex")
                        if crx:
                            if content is None:
                                continue
                            if not re.search(crx, content, re.IGNORECASE | re.DOTALL):
                                continue

                        # domains
                        dms = pattern.get("domains", [])
                        if dms:
                            if content is None:
                                continue
                            if not any(d.lower() in content.lower() for d in dms):
                                continue

                        # must_also_contain (ALL must match)
                        mac = pattern.get("must_also_contain", [])
                        if mac:
                            if content is None:
                                continue
                            if not all(t.lower() in content.lower() for t in mac):
                                continue

                        # trigger-level must_contain
                        if triggers and isinstance(triggers, dict):
                            tmc = triggers.get("must_contain", [])
                            if tmc:
                                if content is None:
                                    continue
                                if not all(t.lower() in content.lower() for t in tmc):
                                    continue

                        # --- All checks passed ---
                        findings.append({
                            "type": name,
                            "file": fp,
                            "detail": desc,
                            "severity": severity,
                            "rule_pack": pack_name,
                        })

    return findings

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
                if f.endswith(".dat") and any(
                    os.sep + d == root or root.startswith(os.sep + d + os.sep) or root.startswith(d + os.sep)
                    for d in ("template", "css", "js", "plugins")
                ):
                    fp = os.path.join(root, f)
                    findings.append({
                        "type": "miner_config_in_webroot",
                        "file": fp,
                        "detail": "Miner config file in web-accessible directory",
                        "severity": "high",
                    })
    # Check process list — only flag if /proc/<pid>/cmdline is NON-empty
    # (real kernel threads have empty cmdline; miners disguised via exec -a have real cmdlines)
    try:
        ps_out = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=5)
        for line in ps_out.stdout.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            pid = parts[1]
            proc_name = " ".join(parts[10:]) if len(parts) > 10 else ""
            for name in MINER_PROCESS_NAMES:
                if name in proc_name and "grep" not in line:
                    # Verify: real kernel threads have empty /proc/<pid>/cmdline
                    try:
                        with open(f"/proc/{pid}/cmdline", "rb") as f:
                            cmdline = f.read()
                        if cmdline.strip(b"\x00").strip():
                            # Non-empty cmdline → this is exec -a disguised process
                            findings.append({
                                "type": "kernel_masquerade_process",
                                "detail": f"Process masquerading as kernel daemon: {name} (PID {pid})",
                                "ps_line": line.strip(),
                                "severity": "critical",
                            })
                    except (FileNotFoundError, PermissionError):
                        pass  # Process already exited, skip
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


# ─── v0.9.0: Image-Embedded PHP — bypass upload filter ──────────

IMAGE_MAGIC_BYTES = {
    b"\xff\xd8\xff": "JPEG",
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"GIF89a": "GIF89a",
    b"GIF87a": "GIF87a",
}


def scan_image_embedded_php(dirs):
    """Detect PHP code embedded in image files (upload filter bypass)."""
    findings = []
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            for f in files:
                fp = os.path.join(root, f)
                try:
                    sz = os.path.getsize(fp)
                    if sz < 64 or sz > 10 * 1024 * 1024:
                        continue
                    with open(fp, "rb") as fh:
                        header = fh.read(12)
                except (OSError, PermissionError):
                    continue

                is_image = any(header.startswith(m) for m in IMAGE_MAGIC_BYTES)
                if not is_image:
                    continue

                try:
                    with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                except (OSError, PermissionError):
                    continue

                if "<?php" in content or "<?=" in content:
                    ext = os.path.splitext(f)[1].lower()
                    findings.append({
                        "type": "image_embedded_php",
                        "file": fp,
                        "detail": f"PHP code in image file ({ext}) — upload filter bypass",
                        "severity": "critical",
                    })
    return findings


# ─── v0.9.0: Symlink Attack — file read jailbreak ──────────────

SYMLINK_SENSITIVE_TARGETS = [
    "wp-config.php", "config.php", ".env", ".htaccess",
    "passwd", "shadow", "id_rsa", "id_ed25519",
    "/dev", "authorized_keys",
]


def scan_symlink_attack(dirs):
    """Detect symlinks pointing to sensitive files from web-accessible dirs."""
    findings = []
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            for f in files:
                fp = os.path.join(root, f)
                try:
                    if not os.path.islink(fp):
                        continue
                    target = os.readlink(fp)
                except OSError:
                    continue
                target_lower = target.lower()
                if any(s in target_lower for s in SYMLINK_SENSITIVE_TARGETS):
                    findings.append({
                        "type": "symlink_attack",
                        "file": fp,
                        "detail": f"Symlink to sensitive file: {fp} → {target}",
                        "severity": "critical",
                    })
    return findings


# ─── v0.9.0: .user.ini Backdoor — PHP auto_prepend injection ───

def scan_user_ini_injection(dirs):
    """Detect .user.ini files with auto_prepend_file/auto_append_file backdoor."""
    findings = []
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            for f in files:
                if f.lower() != ".user.ini":
                    continue
                fp = os.path.join(root, f)
                if os.path.islink(fp):
                    continue
                try:
                    with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                except (OSError, PermissionError):
                    continue
                if "auto_prepend_file" in content or "auto_append_file" in content:
                    findings.append({
                        "type": "user_ini_backdoor",
                        "file": fp,
                        "detail": ".user.ini auto_prepend/auto_append backdoor in web root",
                        "severity": "critical",
                    })
    return findings


# ─── v0.9.0: Polyglot Webshell — valid file that runs as PHP ───

POLYGLOT_EXTENSIONS = {".svg", ".xml", ".ico", ".wav", ".pdf"}


def scan_polyglot_webshell(dirs):
    """Detect files with non-PHP extensions containing executable PHP."""
    findings = []
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            for f in files:
                fp = os.path.join(root, f)
                ext = os.path.splitext(f)[1].lower()
                if ext not in POLYGLOT_EXTENSIONS:
                    continue
                try:
                    sz = os.path.getsize(fp)
                    if sz < 64 or sz > 2 * 1024 * 1024:
                        continue
                    with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                except (OSError, PermissionError):
                    continue

                php_patterns = [
                    r"<\?php\s",
                    r"<\?=\s",
                    r"\beval\s*\(.*\$_(GET|POST|REQUEST)",
                    r"\bsystem\s*\(\s*\$",
                    r"\bshell_exec\s*\(\s*\$",
                ]
                if any(re.search(p, content, re.IGNORECASE) for p in php_patterns):
                    findings.append({
                        "type": "polyglot_webshell",
                        "file": fp,
                        "detail": f"Polyglot webshell: {ext} file contains executable PHP code",
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

# Path patterns to skip for integrity monitoring (volatile files)
# Content scanning still runs — only new_file/file_modified/file_deleted are suppressed
DEFAULT_INTEGRITY_EXCLUDES = [
    "cache/", "tmp/", "temp/", "logs/", "sessions/",
    "compiled/", "templates_c/", "var/cache/", "storage/framework/",
    ".git/", "node_modules/", "vendor/",
]
DEFAULT_INTEGRITY_EXCLUDE_GLOBS = [
    "*.log", "*.cache", "*.lock", "*.pid", "*.tmp",
]


def is_volatile_path(filepath, config=None):
    """Check if a file should be excluded from integrity monitoring.
    Still scanned for malware content — only new_file/file_modified/file_deleted are suppressed."""
    import fnmatch

    fname = os.path.basename(filepath)

    # Check config-provided excludes first
    if config:
        for pat in config.get("integrity_excludes", []):
            if pat.startswith("*."):
                if fnmatch.fnmatch(fname, pat):
                    return True
            elif pat in filepath:
                return True

    # Check built-in defaults
    for pat in DEFAULT_INTEGRITY_EXCLUDES:
        # Match as directory component (not substring)
        # e.g. "cache/" matches /var/www/cache/ but not /tmp/sentinel-cache/
        if f"/{pat}" in filepath or filepath.startswith(f"/{pat}"):
            return True
    for gpat in DEFAULT_INTEGRITY_EXCLUDE_GLOBS:
        if fnmatch.fnmatch(fname, gpat):
            return True

    return False


# ─── v0.4.0: Diff Output ───────────────────────────────────────

def _count_lines(fp):
    try:
        with open(fp, 'rb') as f:
            return sum(1 for _ in f)
    except Exception:
        return 0


def _file_size(fp):
    try:
        return os.path.getsize(fp)
    except OSError:
        return 0


def _diff_detail(fp, old_hash=None):
    lines = _count_lines(fp)
    sz = _file_size(fp)
    return f'{lines} lines, {sz} bytes'


# ─── v0.4.0: Alert Dedup (SQLite-persistent) ─────────────────────


def _alert_dedup_db():
    """Ensure dedup table exists in baseline db."""
    try:
        db = sqlite3.connect(_get_baseline_db())
        db.execute("""
            CREATE TABLE IF NOT EXISTS alert_dedup (
                key TEXT PRIMARY KEY,
                last_alert REAL NOT NULL
            )
        """)
        db.commit()
        db.close()
    except Exception:
        pass


def _is_duplicate_alert(key, window_minutes=10):
    now = time.time()
    _alert_dedup_db()
    try:
        db = sqlite3.connect(_get_baseline_db())
        row = db.execute("SELECT last_alert FROM alert_dedup WHERE key = ?", (key,)).fetchone()
        if row and now - row[0] < window_minutes * 60:
            db.close()
            return True
        db.execute("INSERT OR REPLACE INTO alert_dedup (key, last_alert) VALUES (?, ?)", (key, now))
        db.commit()
        db.close()
    except Exception:
        pass
    return False


# ─── v0.4.0: Severity Tuning ────────────────────────────────────

def integrity_severity(fp):
    high_risk = ['/images/', '/uploads/', '/assets/', '/media/',
                 '/js/', '/css/', '/fonts/', '/static/']
    for d in high_risk:
        if d in fp:
            return 'high'
    low_risk = ['/vendor/', '/node_modules/', '/bower_components/',
                '/cache/', '/tmp/', '/logs/']
    for d in low_risk:
        if d in fp:
            return 'low'
    return 'medium'


# ─── v0.4.0: Git-Aware Integrity ─────────────────────────────────

def _set_state(key, value):
    db_path = _get_baseline_db()
    try:
        db = sqlite3.connect(db_path)
        db.execute('CREATE TABLE IF NOT EXISTS sentinel_state (key TEXT PRIMARY KEY, value TEXT)')
        db.execute('INSERT OR REPLACE INTO sentinel_state (key, value) VALUES (?, ?)', (key, value))
        db.commit()
        db.close()
    except Exception:
        pass


def _get_state(key):
    db_path = _get_baseline_db()
    try:
        db = sqlite3.connect(db_path)
        row = db.execute('SELECT value FROM sentinel_state WHERE key = ?', (key,)).fetchone()
        db.close()
        return row[0] if row else None
    except Exception:
        return None


def git_tracked_changes(watch_dir):
    git_dir = os.path.join(watch_dir, '.git')
    if not os.path.isdir(git_dir):
        return set()
    try:
        result = subprocess.run(
            ['git', '-C', watch_dir, 'rev-parse', 'HEAD'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return set()
        current_head = result.stdout.strip()
    except Exception:
        return set()
    state_key = f'git_head:{watch_dir}'
    stored_head = _get_state(state_key)
    if not stored_head:
        _set_state(state_key, current_head)
        return set()
    if stored_head == current_head:
        return set()
    try:
        result = subprocess.run(
            ['git', '-C', watch_dir, 'diff', '--name-only', stored_head, current_head],
            capture_output=True, text=True, timeout=10
        )
        changed = set()
        for f in result.stdout.strip().split(chr(10)):
            if not f:
                continue
            full = os.path.normpath(os.path.join(watch_dir, f))
            changed.add(full)
    except Exception:
        changed = set()
    _set_state(state_key, current_head)
    return changed


# ─── v0.4.0: Unified Integrity Skip ─────────────────────────────

def is_integrity_skipped(fp, config=None, git_changed=None):
    import fnmatch
    if is_volatile_path(fp, config):
        return True
    if config:
        fname = os.path.basename(fp)
        for pat in config.get('integrity_whitelist', []):
            if '*' in pat or '?' in pat:
                if fnmatch.fnmatch(fname, pat) or fnmatch.fnmatch(fp, pat):
                    return True
            else:
                if pat in fp or pat == fname:
                    return True
    if git_changed and fp in git_changed:
        return True
    return False


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


# ─── SQLite Persistent Baseline ─────────────────────────────────

def _baseline_db_path(config=None):
    """Return path to the SQLite baseline database. Uses config dir if provided."""
    if config and config.get("_config_dir"):
        return os.path.join(config["_config_dir"], "baseline.db")
    # Fallback: next to the script
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "baseline.db")


# Module-level: set by main() from config path
_BASELINE_DB_FILE = None


def _get_baseline_db():
    """Return the current baseline db path."""
    global _BASELINE_DB_FILE
    if _BASELINE_DB_FILE:
        return _BASELINE_DB_FILE
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "baseline.db")


def baseline_db_init():
    """Create baseline table if not exists."""
    db = sqlite3.connect(_get_baseline_db())
    db.execute("""
        CREATE TABLE IF NOT EXISTS baseline (
            filepath TEXT PRIMARY KEY,
            sha256 TEXT NOT NULL,
            size INTEGER NOT NULL,
            mtime REAL NOT NULL,
            added_at TEXT DEFAULT (datetime('now'))
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS sentinel_state (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    # v0.8.0: Persistent incident log for SOC reporting
    db.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            server_name TEXT NOT NULL DEFAULT 'unknown',
            timestamp TEXT NOT NULL DEFAULT (datetime('now')),
            severity TEXT NOT NULL,
            type TEXT NOT NULL,
            file TEXT,
            detail TEXT,
            rule_pack TEXT,
            sha256 TEXT,
            quarantined INTEGER DEFAULT 0,
            scan_mode TEXT DEFAULT 'daemon'
        )
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_incidents_scan ON incidents(scan_id)
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp)
    """)
    db.execute("""
        CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity)
    """)
    db.commit()
    db.close()


def baseline_db_load():
    """Load all baseline entries into a dict {filepath: sha256}."""
    baseline = {}
    db_path = _get_baseline_db()
    if not os.path.exists(db_path):
        return baseline
    try:
        db = sqlite3.connect(db_path)
        rows = db.execute("SELECT filepath, sha256 FROM baseline").fetchall()
        for fp, sha in rows:
            baseline[fp] = sha
        db.close()
    except Exception:
        pass
    return baseline


def baseline_db_save(baseline_dict):
    """Persist current file hashes to SQLite (UPSERT)."""
    db = sqlite3.connect(_get_baseline_db())
    baseline_db_init()
    now = time.time()
    for fp, sha in baseline_dict.items():
        try:
            st = os.stat(fp)
            sz = st.st_size
            mt = st.st_mtime
        except OSError:
            sz = 0
            mt = now
        db.execute(
            """INSERT OR REPLACE INTO baseline (filepath, sha256, size, mtime, added_at)
               VALUES (?, ?, ?, ?, datetime('now'))""",
            (fp, sha, sz, mt)
        )
    db.commit()
    db.close()


def baseline_db_update(filepath, sha256):
    """Update single file entry after change (re-baseline after alert)."""
    db = sqlite3.connect(_get_baseline_db())
    baseline_db_init()
    try:
        st = os.stat(filepath)
        sz = st.st_size
        mt = st.st_mtime
    except OSError:
        sz = 0
        mt = time.time()
    db.execute(
        """INSERT OR REPLACE INTO baseline (filepath, sha256, size, mtime, added_at)
           VALUES (?, ?, ?, ?, datetime('now'))""",
        (filepath, sha256, sz, mt)
    )
    db.commit()
    db.close()


def baseline_db_remove(filepath):
    """Remove a deleted file from baseline."""
    db = sqlite3.connect(_get_baseline_db())
    db.execute("DELETE FROM baseline WHERE filepath = ?", (filepath,))
    db.commit()
    db.close()


# ─── v0.8.0: Persistent Incident Logger ───────────────────────────

def _generate_scan_id():
    """Generate unique scan ID: SCAN-YYYYMMDD-HHMMSS-XXXX."""
    import random, string
    suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    return f"SCAN-{time.strftime('%Y%m%d-%H%M%S')}-{suffix}"


def log_incidents(findings, scan_id, config, scan_mode='daemon'):
    """Persist all findings from a scan to the incidents table for SOC reporting."""
    server_name = config.get('server_name', os.uname().nodename)
    try:
        db = sqlite3.connect(_get_baseline_db())
        for f in findings:
            db.execute("""
                INSERT INTO incidents (scan_id, server_name, timestamp, severity, type, file, detail, rule_pack, sha256, quarantined, scan_mode)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                server_name,
                f.get('timestamp', time.strftime('%Y-%m-%dT%H:%M:%S')),
                f.get('severity', 'low'),
                f.get('type', 'unknown'),
                f.get('file', ''),
                f.get('detail', ''),
                f.get('rule_pack', ''),
                f.get('sha256', ''),
                1 if f.get('quarantined') else 0,
                scan_mode,
            ))
        db.commit()
        db.close()
        return len(findings)
    except Exception as e:
        print(f"[sentinel] Failed to log incidents: {e}")
        return 0


def query_incidents(start=None, end=None, severity=None, limit=1000):
    """Query incident log for SOC reporting. Returns list of dicts."""
    try:
        db = sqlite3.connect(_get_baseline_db())
        query = "SELECT * FROM incidents WHERE 1=1"
        params = []
        if start:
            query += " AND timestamp >= ?"
            params.append(start)
        if end:
            query += " AND timestamp <= ?"
            params.append(end)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        rows = db.execute(query, params).fetchall()
        cols = [desc[0] for desc in db.description]
        db.close()
        return [dict(zip(cols, row)) for row in rows]
    except Exception as e:
        print(f"[sentinel] Failed to query incidents: {e}")
        return []


# ─── Quarantine System ───────────────────────────────────────────


def _quarantine_dir():
    """Return quarantine base directory (next to baseline db)."""
    return os.path.join(os.path.dirname(_get_baseline_db()), "quarantine")


def quarantine_file(filepath, finding, config):
    """Move a file to quarantine with metadata. Returns (success, qpath)."""

    # Guard: file might already be quarantined by a previous detection
    if not os.path.exists(filepath):
        return False, None

    qbase = _quarantine_dir()
    ts = time.strftime("%Y%m%d-%H%M%S")
    filename = os.path.basename(filepath)
    qdir = os.path.join(qbase, ts)
    os.makedirs(qdir, exist_ok=True)

    if os.path.isdir(filepath):
        print(f"[quarantine] Skipping directory: {filepath}", file=sys.stderr)
        return False, None

    try:
        # Use hash prefix for uniqueness
        h = hashlib.sha256(filepath.encode()).hexdigest()[:8]
        qname = f"{h}_{filename}"
        qpath = os.path.join(qdir, qname)

        shutil.move(filepath, qpath)

        meta = {
            "original_path": filepath,
            "quarantine_path": qpath,
            "severity": finding.get("severity", "unknown"),
            "finding_type": finding.get("type", "unknown"),
            "detail": finding.get("detail", ""),
            "quarantined_at": ts,
            "server": config.get("server_name", os.uname().nodename),
        }
        with open(qpath + ".meta.json", "w") as f:
            json.dump(meta, f, indent=2)

        _quarantine_log(meta)
        return True, qpath
    except Exception as e:
        print(f"[quarantine] Failed to quarantine {filepath}: {e}", file=sys.stderr)
        return False, None


def _quarantine_log(meta):
    """Append quarantine event to SQLite log."""
    db_path = _get_baseline_db()
    try:
        db = sqlite3.connect(db_path)
        db.execute("""
            CREATE TABLE IF NOT EXISTS quarantine_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filepath TEXT,
                quarantine_path TEXT,
                severity TEXT,
                finding_type TEXT,
                detail TEXT,
                quarantined_at TEXT DEFAULT (datetime('now')),
                restored INTEGER DEFAULT 0
            )
        """)
        db.execute(
            """INSERT INTO quarantine_log (filepath, quarantine_path, severity, finding_type, detail)
               VALUES (?, ?, ?, ?, ?)""",
            (meta["original_path"], meta["quarantine_path"],
             meta["severity"], meta["finding_type"], meta["detail"])
        )
        db.commit()
        db.close()
    except Exception as e:
        print(f"[quarantine] Failed to log: {e}", file=sys.stderr)


def should_quarantine(finding, config):
    """Decide if a finding triggers quarantine.
    Quarantines CRITICAL + HIGH severity findings with file paths."""
    if not config.get("quarantine", False):
        return False
    if finding.get("severity", "").lower() not in ("critical", "high"):
        return False
    if not finding.get("file"):
        return False
    return True


# ─── Integrity-Based Vendor Content Skip ───────────────────────

DEFAULT_CONTENT_SKIP_DIRS = ["vendor", "node_modules"]


def _should_skip_content_scan(fp, baseline, config=None):
    """Skip content scan for package dir files whose hash is unchanged
    from baseline. Configurable via config.yaml 'content_skip_dirs'.

    File must be:
    1. Inside a content_skip_dirs directory (default: vendor, node_modules)
    2. Present in the baseline hash database
    3. Current hash matches baseline hash

    Files with changed hash or new files still get full content scan.
    """
    if not baseline or fp not in baseline:
        return False
    dirs = DEFAULT_CONTENT_SKIP_DIRS
    if config:
        dirs = config.get("content_skip_dirs", DEFAULT_CONTENT_SKIP_DIRS)
    if not dirs:
        return False
    markers = [f"{os.sep}{d}{os.sep}" for d in dirs]
    if not any(m in fp for m in markers):
        return False
    current = hash_file(fp)
    if current and current == baseline[fp]:
        return True
    return False


def _scan_file_patterns(fp, content, findings):
    """Run built-in malware patterns against file content. Mutates findings list."""
    for domain in JUDOL_DOMAINS:
        if domain.lower() in content.lower():
            findings.append({
                "type": "suspicious_domain",
                "file": fp,
                "detail": f"Reference to gambling-related domain: {domain}",
                "severity": "high",
            })
            break

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

    if os.path.basename(fp) == ".htaccess":
        redirects = re.findall(r"RewriteRule\s+.*https?://([^\s\]]+)", content, re.IGNORECASE)
        for target in redirects:
            findings.append({
                "type": "htaccess_redirect",
                "file": fp,
                "detail": f".htaccess redirect to external domain: {target}",
                "severity": "high",
            })


def build_baseline(dirs):
    """Build initial hash baseline for all scannable files. Persists to SQLite."""
    baseline = {}
    baseline_db_init()
    for d in dirs:
        for root, _, files in os.walk(d):
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in SCAN_EXTENSIONS:
                    fp = os.path.join(root, f)
                    file_hash = hash_file(fp)
                    if file_hash:
                        baseline[fp] = file_hash
    baseline_db_save(baseline)
    return baseline


def scan_files(dirs, baseline=None, config=None, git_changed=None):
    """Scan watched directories for threats. Returns list of findings.
    config is needed for integrity exclude checking.
    git_changed is set of files changed by git (skip integrity alerts)."""
    findings = []
    scanned_paths = set()

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

                scanned_paths.add(fp)

                # Check baseline: new file
                if baseline and fp not in baseline and not is_integrity_skipped(fp, config, git_changed):
                    if not _is_duplicate_alert(fp):
                        current_hash = hash_file(fp)
                        if current_hash:
                            findings.append({
                                "type": "new_file",
                                "file": fp,
                                "detail": f"New file — {_diff_detail(fp)}",
                                "severity": integrity_severity(fp),
                            })
                            baseline_db_update(fp, current_hash)
                            baseline[fp] = current_hash

                # Check baseline: file modified
                if baseline and fp in baseline:
                    current_hash = hash_file(fp)
                    if current_hash and current_hash != baseline[fp]:
                        if not is_integrity_skipped(fp, config, git_changed) and not _is_duplicate_alert(fp):
                            findings.append({
                                "type": "file_modified",
                                "file": fp,
                                "detail": f"Hash changed — {_diff_detail(fp)}",
                                "severity": integrity_severity(fp),
                            })
                        baseline_db_update(fp, current_hash)
                        baseline[fp] = current_hash

                # Read and scan file content
                if _should_skip_content_scan(fp, baseline, config):
                    continue

                try:
                    with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                except (OSError, PermissionError):
                    continue

                # Scan built-in malware patterns
                _scan_file_patterns(fp, content, findings)

    return findings, scanned_paths

# ─── Scan: detect files deleted from baseline ────────────────────

def scan_deleted_files(scanned_paths, config=None, git_changed=None):
    """Detect files in baseline that no longer exist on disk.
    Skips volatile, whitelisted, and git-changed paths."""
    findings = []
    db_path = _get_baseline_db()
    if not os.path.exists(db_path):
        return findings
    try:
        db = sqlite3.connect(db_path)
        rows = db.execute("SELECT filepath FROM baseline").fetchall()
        db.close()
        for (fp,) in rows:
            if fp not in scanned_paths and not os.path.exists(fp):
                if not is_integrity_skipped(fp, config):
                    findings.append({
                        "type": "file_deleted",
                        "file": fp,
                        "detail": "Baseline file no longer exists on disk",
                        "severity": "low",
                    })
                baseline_db_remove(fp)
    except Exception:
        pass
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

# ─── v0.5.0: Behavioral Process Scanner ──────────────────────────

# Suspicious process patterns
PROCESS_SIGNATURES = [
    # Reverse shells
    (r"/dev/tcp/", "Reverse shell: /dev/tcp/ connection attempt"),
    (r"bash -i >&", "Reverse shell: interactive bash redirect"),
    (r"nc -e.*(/bin/\w+|/bin/bash|/bin/sh)", "Reverse shell: netcat -e backdoor"),
    (r"bash -c.*\$\(.*\)", "Process command injection via bash -c"),
    # Python execution wrappers
    (r"python\d* -c.*(eval|exec|pty\.spawn|os\.system|subprocess)", "Python execution wrapper"),
    (r"python\d* -c.*base64", "Python base64 execution chain"),
    # Suspicious command patterns
    (r"chmod\s+[0-7]*7[0-7]*7\s+/", "Suspicious chmod: world-writable binary"),
    (r"iptables.*DROP.*OUTPUT", "Suspicious iptables: blocking outbound traffic"),
    # Data exfiltration
    (r"tar.*\|.*(nc|curl|wget)", "Data exfiltration: tar piped to network"),
    (r"curl.*-F.*@/", "Data upload via curl -F"),
]

def scan_processes():
    """Scan running processes for reverse shells, suspicious execution, and anomalies.
    Reads /proc/*/cmdline — no 'ps' dependency."""
    findings = []

    # Helper: read cmdline from pid
    def read_cmdline(pid):
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                raw = f.read()
            return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        except Exception:
            return ""

    try:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = entry
            cmdline = read_cmdline(pid)
            if not cmdline:
                continue

            # Check process signatures
            for pat, desc in PROCESS_SIGNATURES:
                if re.search(pat, cmdline, re.IGNORECASE) and not _is_duplicate_alert("proc:" + pid + ":" + desc[:20], window_minutes=30):
                    findings.append({
                        "type": "suspicious_process",
                        "detail": desc,
                        "pid": int(pid),
                        "cmdline": cmdline[:256],
                        "severity": "critical",
                    })
                    break

            # Suspicious parent-child: web server spawning shell
            if cmdline.startswith(("sh", "bash", "/bin/sh", "/bin/bash")):
                try:
                    ppid_stat = f"/proc/{pid}/stat"
                    with open(ppid_stat) as f:
                        stat = f.read()
                    ppid = stat.split()[3]
                    parent_cmd = read_cmdline(ppid)
                    if parent_cmd and any(s in parent_cmd.lower() for s in
                        ("nginx", "apache", "httpd", "php", "www-data", "postgres")):
                        findings.append({
                            "type": "suspicious_parent_process",
                            "detail": f"Shell spawned by web/service process ({parent_cmd[:80]})",
                            "pid": int(pid),
                            "ppid": int(ppid),
                            "cmdline": cmdline[:128],
                            "parent_cmdline": parent_cmd[:128],
                            "severity": "critical",
                        })
                except Exception:
                    pass

    except PermissionError:
        pass  # Can't read /proc — no findings

    return findings


# ─── v0.5.0: Network Connection Monitor ─────────────────────────

# Suspicious outbound ports
BOTNET_PORTS = {6667, 6697, 9999, 31337, 4444, 4445, 8080, 8081, 9001}

# Suspicious IP patterns (RFC 1918 + localhost excluded from alert)
def _parse_proc_net_tcp():
    """Parse /proc/net/tcp into list of (local_ip, local_port, remote_ip, remote_port, state)."""
    entries = []
    try:
        with open("/proc/net/tcp") as f:
            lines = f.readlines()[1:]  # Skip header
        for line in lines:
            parts = line.strip().split()
            if len(parts) < 10:
                continue
            # local_address (hex), rem_address (hex), st (state)
            local_hex = parts[1]
            remote_hex = parts[2]
            st = parts[3]

            # Parse hex address:port (reverse byte order)
            lip_int = int(local_hex.split(":")[0], 16)
            lport_int = int(local_hex.split(":")[1], 16)
            rip_int = int(remote_hex.split(":")[0], 16)
            rport_int = int(remote_hex.split(":")[1], 16)

            local_ip = f"{(lip_int >> 24) & 0xff}.{(lip_int >> 16) & 0xff}.{(lip_int >> 8) & 0xff}.{lip_int & 0xff}"
            remote_ip = f"{(rip_int >> 24) & 0xff}.{(rip_int >> 16) & 0xff}.{(rip_int >> 8) & 0xff}.{rip_int & 0xff}"

            entries.append((local_ip, lport_int, remote_ip, rport_int, st))
        return entries
    except Exception:
        return []


def scan_network_connections():
    """Detect suspicious network connections: botnet ports, foreign IPs, listener changes."""
    findings = []
    entries = _parse_proc_net_tcp()

    # Track listening ports (baseline for comparison)
    current_listeners = set()
    for lip, lp, rip, rp, st in entries:
        # TCP_LISTEN = 0A, TCP_ESTABLISHED = 01
        if st == "0A":
            current_listeners.add(lp)

    # Check for suspicious outbound connections
    for lip, lp, rip, rp, st in entries:
        if st != "01":  # Only established connections
            continue

        # Botnet/IRC ports
        if rp in BOTNET_PORTS and not _is_duplicate_alert("net:botnet:" + rip + ":" + str(rp), window_minutes=30):
            findings.append({
                "type": "suspicious_network_connection",
                "detail": f"Outbound connection to botnet/IRC port {rp} -> {rip}",
                "local_ip": lip,
                "local_port": lp,
                "remote_ip": rip,
                "remote_port": rp,
                "severity": "high",
            })

        # High outbound ports (potential reverse shell callbacks)
        if rp > 50000 and rp not in (80, 443, 8080, 8443) and not _is_duplicate_alert("net:highport:" + rip + ":" + str(rp), window_minutes=30):
            findings.append({
                "type": "high_port_outbound",
                "detail": f"Outbound connection to high port {rp} -> {rip}",
                "local_ip": lip,
                "local_port": lp,
                "remote_ip": rip,
                "remote_port": rp,
                "severity": "medium",
            })

    # Check for new listening ports (vs baseline)
    stored_listeners = _get_state("network_listeners")
    if stored_listeners:
        try:
            prev = set(json.loads(stored_listeners))
            new_ports = current_listeners - prev
            closed_ports = prev - current_listeners

            for port in new_ports:
                findings.append({
                    "type": "new_listening_port",
                    "detail": f"New port listening: {port} — potential backdoor or unauthorized service",
                    "port": port,
                    "severity": "high",
                })
            for port in closed_ports:
                findings.append({
                    "type": "closed_listening_port",
                    "detail": f"Port stopped listening: {port} — service may have been stopped",
                    "port": port,
                    "severity": "low",
                })
        except json.JSONDecodeError:
            pass

    # Save current listener snapshot
    _set_state("network_listeners", json.dumps(sorted(current_listeners)))

    return findings


# ─── v0.5.0: User Session Monitor ────────────────────────────────

def scan_user_sessions():
    """Detect suspicious SSH logins, new users, and anomalous session times."""
    findings = []

    # Track known users via sentinel_state
    known_users_raw = _get_state("known_users")
    known_users = set(json.loads(known_users_raw)) if known_users_raw else set()

    current_users = set()
    try:
        # Check /etc/passwd for new users (UID >= 1000 = human user)
        with open("/etc/passwd") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) < 4:
                    continue
                uid = int(parts[2])
                username = parts[0]
                if uid >= 1000 and uid < 65534:
                    current_users.add(username)
                    if known_users and username not in known_users:
                        findings.append({
                            "type": "new_system_user",
                            "detail": f"New user account created: {username} (UID {uid})",
                            "username": username,
                            "uid": uid,
                            "severity": "high",
                        })
    except Exception:
        pass

    _set_state("known_users", json.dumps(sorted(current_users)))

    # Check active sessions via 'who' command
    try:
        result = subprocess.run(["who", "-u"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            username = parts[0]
            tty = parts[1]

            # Root SSH login (not from console)
            if username == "root" and tty != "tty1" and tty != "console" and not _is_duplicate_alert("root_remote_login", window_minutes=30):
                findings.append({
                    "type": "root_remote_login",
                    "detail": f"Root login via {tty} — use sudo instead",
                    "username": username,
                    "session_line": line.strip(),
                    "severity": "high",
                })

            # Login at odd hours (midnight - 5am)
            try:
                login_time = parts[2] if len(parts) > 2 else ""
                if login_time and ":" in login_time:
                    parts_time = login_time.split(":")
                    if len(parts_time) >= 2:
                        hour = int(parts_time[0].split()[-1] if " " in parts_time[0] else parts_time[0])
                        if 0 <= hour <= 5:
                            findings.append({
                                "type": "odd_hour_login",
                                "detail": f"User {username} logged in at odd hour ({login_time}) via {tty}",
                                "username": username,
                                "session_line": line.strip(),
                                "severity": "medium",
                            })
            except (ValueError, IndexError):
                pass
    except Exception:
        pass

    # Check 'last' for recent login failures (brute force)
    try:
        result = subprocess.run(["lastb", "-n", "20"], capture_output=True, text=True, timeout=5)
        fail_count = sum(1 for l in result.stdout.splitlines() if l.strip() and "ssh:" in l.lower())
        if fail_count >= 10 and not _is_duplicate_alert("ssh_brute_force", window_minutes=30):
            findings.append({
                "type": "ssh_brute_force",
                "detail": f"{fail_count} recent SSH login failures — possible brute force attack",
                "fail_count": fail_count,
                "severity": "high",
            })
    except Exception:
        pass

    return findings


# ─── v0.5.0: Systemd Timer & Extended Cron Monitor ───────────────

def scan_systemd_timers():
    """Detect new or suspicious systemd timers."""
    findings = []

    known_timers_raw = _get_state("known_timers")
    known_timers = set(json.loads(known_timers_raw)) if known_timers_raw else set()

    current_timers = set()
    timer_paths = ["/etc/systemd/system/", "/lib/systemd/system/"]

    for tpath in timer_paths:
        try:
            for fname in os.listdir(tpath):
                if fname.endswith(".timer"):
                    current_timers.add(f"{tpath}{fname}")
        except Exception:
            pass

    if known_timers:
        new_timers = current_timers - known_timers
        for t in new_timers:
            if not _is_duplicate_alert("timer:" + t, window_minutes=60):
                timer_detail = ""
                try:
                    with open(t) as f:
                        timer_detail = f.read()[:256]
                except Exception:
                    pass
                findings.append({
                    "type": "new_systemd_timer",
                    "detail": f"New systemd timer: {os.path.basename(t)}",
                    "timer_path": t,
                    "timer_content": timer_detail[:256],
                    "severity": "medium",
                })

    _set_state("known_timers", json.dumps(sorted(current_timers)))
    return findings


def scan_extended_crontabs():
    """Extended cron scan: system-wide crontab, /etc/cron.*/, and suspicious patterns."""
    findings = []

    # Standard user crontab scan (existing)
    findings.extend(scan_crontabs())

    # System-wide crontab
    try:
        with open("/etc/crontab") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Check for suspicious patterns
                for pat, desc in SUSPICIOUS_CRON_PATTERNS:
                    if re.search(pat, line, re.IGNORECASE):
                        findings.append({
                            "type": "suspicious_system_cron",
                            "detail": f"System crontab: {desc}",
                            "line": line,
                            "severity": "high",
                        })
    except Exception:
        pass

    # /etc/cron.d/ entries
    cron_d_dir = "/etc/cron.d/"
    known_cron_d_raw = _get_state("known_cron_d")
    known_cron_d = set(json.loads(known_cron_d_raw)) if known_cron_d_raw else set()

    current_cron_d = set()
    try:
        for fname in os.listdir(cron_d_dir):
            fp = os.path.join(cron_d_dir, fname)
            if os.path.isfile(fp):
                current_cron_d.add(fname)
    except Exception:
        pass

    if known_cron_d:
        new_cron = current_cron_d - known_cron_d
        for name in new_cron:
            cron_content = ""
            try:
                with open(os.path.join(cron_d_dir, name)) as f:
                    cron_content = f.read()[:256]
            except Exception:
                pass
            findings.append({
                "type": "new_cron_entry",
                "detail": f"New /etc/cron.d/ entry: {name}",
                "cron_file": f"/etc/cron.d/{name}",
                "content": cron_content,
                "severity": "medium",
            })

    _set_state("known_cron_d", json.dumps(sorted(current_cron_d)))
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

# ─── v0.7.0: inotify Watcher ─────────────────────────────────────

# inotify constants
IN_ACCESS = 0x00000001
IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_CLOSE_NOWRITE = 0x00000010
IN_OPEN = 0x00000020
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_CLOEXEC = 0o2000000
IN_NONBLOCK = 0o4000
IN_ONLYDIR = 0x01000000
IN_DONT_FOLLOW = 0x02000000
IN_EXCL_UNLINK = 0x04000000
IN_ISDIR = 0x40000000
IN_IGNORED = 0x80000000

# Events we care about: new file, modified, deleted
WATCH_MASK = (IN_CREATE | IN_MODIFY | IN_CLOSE_WRITE |
              IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE_SELF)

# Max watches before fallback
WATCH_LIMIT_SOFT = 50000  # warn at 50K
_LAST_SCAN_TIME = 0.0  # mtime fallback reference


def _inotify_init():
    """Initialize inotify, return fd or None on failure."""
    import ctypes
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        fd = libc.inotify_init1(IN_CLOEXEC | IN_NONBLOCK)
        if fd < 0:
            return None
        return fd
    except Exception:
        return None


def _inotify_add_watch(fd, path, mask):
    """Add an inotify watch. Returns wd or -1 on failure."""
    import ctypes
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        encoded = path.encode("utf-8") + b"\x00"
        wd = libc.inotify_add_watch(fd, encoded, mask)
        return wd
    except Exception:
        return -1


def _inotify_read_events(fd, timeout=2.0):
    """Read inotify events with timeout. Returns list of (wd, mask, name)."""
    import ctypes, select, struct
    events = []
    try:
        ready, _, _ = select.select([fd], [], [], timeout)
        if not ready:
            return events
        buf = os.read(fd, 4096)
        i = 0
        while i < len(buf):
            wd, mask, cookie, name_len = struct.unpack_from("iIII", buf, i)
            name = buf[i + 16:i + 16 + name_len].rstrip(b"\x00").decode("utf-8", errors="replace")
            events.append((wd, mask, name))
            i += 16 + name_len
    except Exception:
        pass
    return events


def _watch_tree_recursive(fd, root, wd_map):
    """Recursively add inotify watches to a directory tree.
    Returns (watch_count, failed_paths)."""
    import ctypes
    count = 0
    failed = []
    try:
        wd = _inotify_add_watch(fd, root, WATCH_MASK)
        if wd < 0:
            errno_val = ctypes.get_errno()
            if errno_val == 28:  # ENOSPC
                failed.append(root)
            return 0, failed
        wd_map[wd] = root
        count += 1
    except Exception:
        return 0, failed

    # Only recurse if under soft limit
    if count >= WATCH_LIMIT_SOFT:
        return count, failed

    try:
        for entry in os.listdir(root):
            full = os.path.join(root, entry)
            if os.path.isdir(full) and entry != ".git":
                sub_count, sub_failed = _watch_tree_recursive(fd, full, wd_map)
                count += sub_count
                failed.extend(sub_failed)
    except PermissionError:
        pass

    return count, failed


def _resolve_inotify_path(wd_map, wd, name):
    """Resolve full file path from watch descriptor and filename."""
    base = wd_map.get(wd, "")
    if base and name:
        return os.path.join(base, name)
    return ""


# ─── v0.7.0: Incremental File Scanner ────────────────────────────

LARGE_FILE_THRESHOLD = 10 * 1024 * 1024  # 10 MB
LARGE_FILE_HEAD_BYTES = 65536   # 64 KB
LARGE_FILE_TAIL_BYTES = 65536   # 64 KB


def scan_files_incremental(file_list, baseline=None, config=None, git_changed=None):
    """Scan only specific files (from inotify or mtime). Returns (findings, scanned_paths)."""
    findings = []
    scanned_paths = set()

    for fp in file_list:
        if not os.path.isfile(fp):
            continue
        ext = os.path.splitext(fp)[1].lower()
        if ext not in SCAN_EXTENSIONS:
            continue
        scanned_paths.add(fp)

        # Large file optimization: only scan head + tail
        try:
            sz = os.path.getsize(fp)
        except OSError:
            continue
        is_large = sz > LARGE_FILE_THRESHOLD

        # Baseline checks (same logic as scan_files)
        if baseline and fp not in baseline and not is_integrity_skipped(fp, config, git_changed):
            if not _is_duplicate_alert(fp):
                current_hash = hash_file(fp) if not is_large else None
                if current_hash:
                    findings.append({
                        "type": "new_file",
                        "file": fp,
                        "detail": f"New file — {_diff_detail(fp)}",
                        "severity": integrity_severity(fp),
                    })
                    baseline_db_update(fp, current_hash)
                    baseline[fp] = current_hash

        if baseline and fp in baseline:
            current_hash = hash_file(fp) if not is_large else None
            if current_hash and current_hash != baseline[fp]:
                if not is_integrity_skipped(fp, config, git_changed) and not _is_duplicate_alert(fp):
                    findings.append({
                        "type": "file_modified",
                        "file": fp,
                        "detail": f"Hash changed — {_diff_detail(fp)}",
                        "severity": integrity_severity(fp),
                    })
                baseline_db_update(fp, current_hash)
                baseline[fp] = current_hash

        # Content scan
        if _should_skip_content_scan(fp, baseline, config):
            continue
        try:
            if is_large:
                # Scan only head + tail
                with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                    head = fh.read(LARGE_FILE_HEAD_BYTES)
                with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(max(0, sz - LARGE_FILE_TAIL_BYTES))
                    tail = fh.read(LARGE_FILE_TAIL_BYTES)
                content = head + "\n...[TRUNCATED]...\n" + tail
            else:
                with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
        except (OSError, PermissionError):
            continue

        # Run built-in malware patterns
        _scan_file_patterns(fp, content, findings)

    return findings, scanned_paths


# ─── v0.7.0: Mtime Fallback Scan ─────────────────────────────────

def scan_mtime_incremental(dirs):
    """Return files modified since last scan. Fallback when inotify unavailable."""
    global _LAST_SCAN_TIME
    now = time.time()
    cutoff = _LAST_SCAN_TIME if _LAST_SCAN_TIME > 0 else now - 3600
    _LAST_SCAN_TIME = now

    changed = []
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            for f in files:
                fp = os.path.join(root, f)
                ext = os.path.splitext(f)[1].lower()
                if ext not in SCAN_EXTENSIONS:
                    continue
                try:
                    mtime = os.path.getmtime(fp)
                    if mtime > cutoff:
                        changed.append(fp)
                except OSError:
                    continue
    return changed


# ─── v0.7.0: Resource Throttle ───────────────────────────────────

_SCAN_BATCH_SIZE = 50  # files per batch
_SCAN_BATCH_PAUSE = 0.1  # seconds between batches


def _throttle_resources(batch_num):
    """Brief pause between scan batches to avoid CPU/IO spikes."""
    if batch_num > 0 and batch_num % _SCAN_BATCH_SIZE == 0:
        time.sleep(_SCAN_BATCH_PAUSE)


# ─── v0.7.0: Inotify Daemon Loop ─────────────────────────────────

def daemon_loop_inotify(watch_dirs, baseline, config, rule_packs, interval):
    """Main daemon loop using inotify for real-time file monitoring.
    Falls back to mtime scan if inotify unavailable."""
    import ctypes

    # Try inotify first
    fd = _inotify_init()
    use_inotify = fd is not None
    wd_map = {}

    if use_inotify:
        total_watches = 0
        for d in watch_dirs:
            if os.path.isdir(d):
                count, failed = _watch_tree_recursive(fd, d, wd_map)
                total_watches += count
                if failed:
                    print(f"[sentinel] Inotify ENOSPC on {len(failed)} dirs — some dirs use mtime fallback")
        if total_watches > 0:
            print(f"[sentinel] Inotify active: {total_watches} watches on {len(wd_map)} directories")
        else:
            print(f"[sentinel] Inotify failed to add ANY watches — using mtime fallback")
            use_inotify = False
    else:
        print(f"[sentinel] Inotify unavailable — using mtime-based incremental scan")

    last_full_scan = 0  # force immediate first scan
    FULL_SCAN_INTERVAL = 900  # full scan every 15 minutes as safety net

    print(f"[sentinel] Watching {len(watch_dirs)} directories (inotify: {use_inotify})...")
    print(f"[sentinel] Master: {config.get('master_url', 'none')}")

    while True:
        try:
            event_files = set()
            full_scan = False

            if use_inotify:
                # Collect events in 2-second window
                events = _inotify_read_events(fd, timeout=2.0)
                for wd, mask, name in events:
                    fp = _resolve_inotify_path(wd_map, wd, name)
                    if fp and os.path.isfile(fp):
                        event_files.add(fp)

                # Check if full scan needed
                now = time.time()
                if now - last_full_scan >= FULL_SCAN_INTERVAL:
                    full_scan = True
                    last_full_scan = now
            else:
                # Mtime fallback
                event_files = set(scan_mtime_incremental(watch_dirs))
                full_scan = True  # mtime scan already filters

            # Compute git-changed files
            git_changed = set()
            for d in watch_dirs:
                git_changed |= git_tracked_changes(d)

            # Scan: incremental or full
            if full_scan or len(event_files) > 100:
                # Full scan every 15 min OR when event flood (>100 files changed)
                sys.stdout.flush()
                print(f"[sentinel] Full scan triggered ({len(event_files)} events)")
                findings, scanned_paths = scan_files(watch_dirs, baseline, config, git_changed)
            else:
                findings, scanned_paths = scan_files_incremental(list(event_files), baseline, config, git_changed)

            # v0.5.0 behavioral (every cycle — lightweight)
            findings.extend(scan_processes())
            findings.extend(scan_network_connections())
            findings.extend(scan_user_sessions())
            findings.extend(scan_systemd_timers())
            if full_scan:
                findings.extend(scan_extended_crontabs())
            else:
                findings.extend(scan_crontabs())

            # Full-walk scans only on full scan (every 15 min)
            if full_scan:
                findings.extend(scan_image_embedded_php(watch_dirs))
                findings.extend(scan_symlink_attack(watch_dirs))
                findings.extend(scan_user_ini_injection(watch_dirs))
                findings.extend(scan_polyglot_webshell(watch_dirs))
                findings.extend(scan_cryptominers(watch_dirs))
                findings.extend(scan_seo_spam(watch_dirs))
                findings.extend(scan_shell_extensions(watch_dirs))
                findings.extend(scan_cgi_webshell_dirs(watch_dirs))
                findings.extend(scan_cloned_malware(watch_dirs))
                if rule_packs:
                    findings.extend(scan_rule_packs(watch_dirs, rule_packs))
                findings.extend(scan_deleted_files(scanned_paths, config, git_changed))
                findings.extend(scan_recent_files(watch_dirs, minutes=15))

            if findings:
                qcount = 0
                for f in findings:
                    if should_quarantine(f, config):
                        ok, qpath = quarantine_file(f["file"], f, config)
                        if ok:
                            f["quarantined"] = qpath
                            qcount += 1
                if qcount:
                    print(f"[sentinel] Quarantined {qcount} files")

                # v0.8.0: Log all findings to persistent incident DB for SOC reporting
                scan_id = _generate_scan_id()
                logged = log_incidents(findings, scan_id, config, scan_mode='inotify')
                if logged:
                    print(f"[sentinel] Logged {logged} incidents ({scan_id})")

                print(f"[sentinel] {len(findings)} findings detected")
                for f in findings:
                    if f.get("severity") in ("critical", "high"):
                        print(f"  [{f['severity'].upper()}] {f['type']}: {f.get('file', '')} — {f['detail']}")

                report_findings(findings, config)
            elif full_scan:
                sys.stdout.flush()
                print(f"[sentinel] Full scan clean ({time.strftime('%H:%M:%S')})")

        except KeyboardInterrupt:
            print("\n[sentinel] Shutting down.")
            if use_inotify:
                os.close(fd)
            return 0
        except Exception as e:
            print(f"[sentinel] Error: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            time.sleep(interval)




def main():
    parser = argparse.ArgumentParser(description="Hermes Sentinel Agent")
    parser.add_argument("--config", default="/etc/hermes-sentinel/config.yaml", help="Config file path")
    parser.add_argument("--scan-once", action="store_true", help="Scan once and exit (skip daemon loop)")
    parser.add_argument("--json", action="store_true", help="Output findings as JSON (for cron/pipe usage)")
    args = parser.parse_args()

    # Load config — simple YAML-like format
    config = _load_config(args.config)

    # Set baseline DB location next to config file (writable, survives restarts)
    config_dir = os.path.dirname(os.path.abspath(args.config))
    global _BASELINE_DB_FILE
    _BASELINE_DB_FILE = os.path.join(config_dir, "baseline.db")

    watch_dirs = config.get("watch_dirs", ["/var/www"])
    interval = int(config.get("interval", 300))
    baseline = {}

    # Load YAML rule packs
    rule_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")
    rule_packs = _load_rule_packs(rule_dir)

    # Load persistent baseline from SQLite
    baseline_db_init()
    baseline = baseline_db_load()
    if baseline:
        print(f"[sentinel] Loaded persistent baseline: {len(baseline)} files from baseline.db")

    if config.get("baseline_on_start", True):
        print(f"[sentinel] Building baseline for {len(watch_dirs)} directories...")
        baseline = build_baseline(watch_dirs)
        print(f"[sentinel] Baseline: {len(baseline)} files saved to baseline.db")

    # Single scan mode (for cron usage)
    if args.scan_once or args.json:
        # Pre-compute git-changed files for integrity skip
        git_changed = set()
        for d in watch_dirs:
            git_changed |= git_tracked_changes(d)
        if git_changed:
            print(f'[sentinel] Git changes detected in {len(git_changed)} files — skipping integrity alerts')

        findings, scanned_paths = scan_files(watch_dirs, baseline, config, git_changed)
        findings.extend(scan_crontabs())
        findings.extend(scan_recent_files(watch_dirs, minutes=60))
        findings.extend(scan_image_embedded_php(watch_dirs))
        findings.extend(scan_symlink_attack(watch_dirs))
        findings.extend(scan_user_ini_injection(watch_dirs))
        findings.extend(scan_polyglot_webshell(watch_dirs))
        findings.extend(scan_cryptominers(watch_dirs))
        findings.extend(scan_seo_spam(watch_dirs))
        findings.extend(scan_shell_extensions(watch_dirs))
        findings.extend(scan_cgi_webshell_dirs(watch_dirs))
        findings.extend(scan_cloned_malware(watch_dirs))
        if rule_packs:
            findings.extend(scan_rule_packs(watch_dirs, rule_packs))
        findings.extend(scan_deleted_files(scanned_paths, config, git_changed))

        # v0.5.0: Behavioral monitoring
        findings.extend(scan_processes())
        findings.extend(scan_network_connections())
        findings.extend(scan_user_sessions())
        findings.extend(scan_systemd_timers())
        findings.extend(scan_extended_crontabs())

        # Quarantine CRITICAL/HIGH findings
        quarantine_count = 0
        for f in findings:
            if should_quarantine(f, config):
                ok, qpath = quarantine_file(f["file"], f, config)
                if ok:
                    f["quarantined"] = qpath
                    quarantine_count += 1
        if quarantine_count:
            print(f"[sentinel] Quarantined {quarantine_count} files")

        # v0.8.0: Log all findings to persistent incident DB
        scan_id = _generate_scan_id()
        logged = log_incidents(findings, scan_id, config, scan_mode='scan-once')
        if logged:
            print(f"[sentinel] Logged {logged} incidents ({scan_id})")

        if args.json:
            print(json.dumps(findings, indent=2, ensure_ascii=False))
        elif findings:
            print(f"[sentinel] {len(findings)} findings:")
            for f in findings:
                print(f"  [{f['severity'].upper()}] {f['type']}: {f.get('file', f.get('line', ''))} — {f['detail']}")
        else:
            print("[sentinel] All clear — no threats detected.")
        return 0

    # Daemon mode — inotify incremental watching
    # Full scan every 15 min, behavioral every 5 min
    daemon_loop_inotify(watch_dirs, baseline, config, rule_packs, interval)
    return 0

def _load_config(path):
    """Load simple YAML-like config. Falls back to defaults if file missing."""
    config = {
        "server_name": os.uname().nodename,
        "watch_dirs": ["/var/www"],
        "interval": 300,
        "baseline_on_start": True,
        "content_skip_dirs": ["vendor", "node_modules"],
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

                if not val:
                    # Empty value after colon — could be a list
                    current_key = key
                    config[key] = []
                elif val == "true":
                    config[key] = True
                    current_key = None
                elif val == "false":
                    config[key] = False
                    current_key = None
                elif val.isdigit():
                    config[key] = int(val)
                    current_key = None
                else:
                    config[key] = val
                    current_key = None
            elif line.startswith("- ") and current_key and isinstance(config.get(current_key), list):
                config[current_key].append(line[2:].strip())

    return config


if __name__ == "__main__":
    sys.exit(main())
