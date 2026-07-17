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
                if f.endswith(".dat") and any(n in root for n in ["template", "css", "js", "plugins"]):
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


def baseline_db_new_files(dirs):
    """Return files that exist on disk but NOT in baseline."""
    new_files = []
    db_path = _get_baseline_db()
    known = set()
    if os.path.exists(db_path):
        try:
            db = sqlite3.connect(db_path)
            rows = db.execute("SELECT filepath FROM baseline").fetchall()
            known = {r[0] for r in rows}
            db.close()
        except Exception:
            pass

    for d in dirs:
        if not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            for f in files:
                fp = os.path.join(root, f)
                ext = os.path.splitext(f)[1].lower()
                if ext in SCAN_EXTENSIONS and fp not in known:
                    new_files.append(fp)
    return new_files


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


def scan_files(dirs, baseline=None, config=None):
    """Scan watched directories for threats. Returns list of findings.
    config is needed for integrity exclude checking."""
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

                # Check baseline: new file (exists on disk, not in baseline)
                # Skip integrity check for volatile paths (cache, logs, sessions, etc.)
                if baseline and fp not in baseline and not is_volatile_path(fp, config):
                    current_hash = hash_file(fp)
                    if current_hash:
                        findings.append({
                            "type": "new_file",
                            "file": fp,
                            "detail": "New file detected — not in baseline snapshot",
                            "severity": "medium",
                        })
                        # Auto-add to baseline so it only alerts once
                        baseline_db_update(fp, current_hash)
                        baseline[fp] = current_hash

                # Check baseline: file modified
                # Skip integrity alert for volatile paths, but silently re-baseline
                if baseline and fp in baseline:
                    current_hash = hash_file(fp)
                    if current_hash and current_hash != baseline[fp]:
                        if not is_volatile_path(fp, config):
                            findings.append({
                                "type": "file_modified",
                                "file": fp,
                                "detail": "File hash changed from baseline",
                                "severity": "medium",
                            })
                        # Re-baseline so same change doesn't alert again
                        baseline_db_update(fp, current_hash)
                        baseline[fp] = current_hash

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

    return findings, scanned_paths

# ─── Scan: detect files deleted from baseline ────────────────────

def scan_deleted_files(scanned_paths, config=None):
    """Detect files in baseline that no longer exist on disk.
    Skips volatile paths to avoid noise."""
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
                if not is_volatile_path(fp, config):
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
        findings, scanned_paths = scan_files(watch_dirs, baseline, config)
        findings.extend(scan_crontabs())
        findings.extend(scan_recent_files(watch_dirs, minutes=60))
        findings.extend(scan_cryptominers(watch_dirs))
        findings.extend(scan_seo_spam(watch_dirs))
        findings.extend(scan_shell_extensions(watch_dirs))
        findings.extend(scan_cgi_webshell_dirs(watch_dirs))
        findings.extend(scan_cloned_malware(watch_dirs))
        if rule_packs:
            findings.extend(scan_rule_packs(watch_dirs, rule_packs))
        findings.extend(scan_deleted_files(scanned_paths, config))

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
            findings, scanned_paths = scan_files(watch_dirs, baseline, config)
            findings.extend(scan_crontabs())
            findings.extend(scan_recent_files(watch_dirs, minutes=interval // 60))
            findings.extend(scan_cryptominers(watch_dirs))
            findings.extend(scan_seo_spam(watch_dirs))
            findings.extend(scan_shell_extensions(watch_dirs))
            findings.extend(scan_cgi_webshell_dirs(watch_dirs))
            findings.extend(scan_cloned_malware(watch_dirs))
            if rule_packs:
                findings.extend(scan_rule_packs(watch_dirs, rule_packs))
            findings.extend(scan_deleted_files(scanned_paths, config))

            if findings:
                # Quarantine CRITICAL/HIGH before reporting
                qcount = 0
                for f in findings:
                    if should_quarantine(f, config):
                        ok, qpath = quarantine_file(f["file"], f, config)
                        if ok:
                            f["quarantined"] = qpath
                            qcount += 1
                if qcount:
                    print(f"[sentinel] Quarantined {qcount} files")

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
