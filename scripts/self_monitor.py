#!/opt/splunk-watchdog/venv/bin/python3
"""
Splunk Watchdog - Self Monitoring Script
Checks the health of Watchdog itself every 30 minutes.
"""

import configparser
import subprocess
import requests
import sqlite3
import logging
import os
import sys
import json
import re
import urllib.parse
from datetime import datetime, timedelta
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# ------------------------------------------------------------
# Load configuration
# ------------------------------------------------------------
CONFIG_PATH = "/opt/splunk-watchdog/config/watchdog.ini"
config = configparser.ConfigParser(interpolation=None)
if not config.read(CONFIG_PATH):
    print(f"ERROR: Config file not found at {CONFIG_PATH}")
    sys.exit(1)

log_path = config.get('general', 'log_path')
db_path = config.get('general', 'db_path')

# ------------------------------------------------------------
# Self-monitoring thresholds
# ------------------------------------------------------------
HEARTBEAT_STATE_FILE = config.get(
    'heartbeat', 'state_file',
    fallback="/opt/splunk-watchdog/db/.last_heartbeat"
)
HEARTBEAT_MAX_AGE_SECONDS = 5400   # 90 minutes
LAST_RUN_MAX_AGE_SECONDS = 1200 # 20 minutes (15-min cycle + 5-min slack)
DB_LAST_RECORD_MAX_AGE_SECONDS = 1200 # 20 minutes
DISK_WARN_PERCENT = 80
DISK_CRIT_PERCENT = 90

# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------
os.makedirs(os.path.dirname(log_path), exist_ok=True)
logging.basicConfig(
    filename=log_path,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [selfmon] %(message)s'
)


# ============================================================
# Webhook
# ============================================================

def send_webhook_raw(full_text):
    webhook_url = config.get('webhook', 'url')
    if not webhook_url or "YOUR" in webhook_url or "XXXX" in webhook_url:
        logging.warning("Webhook URL not configured. Skipping.")
        return False

    encoded_text = urllib.parse.quote(full_text, safe='')

    if "text=" in webhook_url:
        final_url = re.sub(r'text=[^&]*', f'text={encoded_text}', webhook_url)
    else:
        separator = "&" if "?" in webhook_url else "?"
        final_url = f"{webhook_url}{separator}text={encoded_text}"

    try:
        response = requests.post(final_url, timeout=5)
        if response.status_code not in (200, 204):
            logging.error(f"Webhook failed: HTTP {response.status_code}")
            return False
        return True
    except Exception as e:
        logging.error(f"Webhook error: {str(e)[:150]}")
        return False


def send_selfmon_alert(message, severity="critical"):
    prefix = {
        "info": "[INFO]",
        "warning": "[WARNING]",
        "critical": "[CRITICAL]"
    }.get(severity, "[CRITICAL]")

    title = f"*{prefix} [SELF-MONITOR] Watchdog Problem*"
    full_text = f"{title}\n\n{message}"
    return send_webhook_raw(full_text)


# ============================================================
# Self-Checks
# ============================================================

def check_timer_active():
    """Check if splunk-watchdog.timer is active."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "splunk-watchdog.timer"],
            capture_output=True, text=True, timeout=5
        )
        status = result.stdout.strip()
        if status == "active":
            return (True, "Timer is active")
        return (False, f"Timer status: {status}")
    except Exception as e:
        return (False, f"Cannot check timer: {str(e)[:100]}")


def check_last_service_run():
    """Check when the last health_check service ran."""
    try:
        result = subprocess.run(
            ["systemctl", "show", "splunk-watchdog.service",
             "--property=ExecMainStartTimestampMonotonic"],
            capture_output=True, text=True, timeout=5
        )
        # Fallback: check the log file for last "Starting health check cycle"
        if not os.path.exists(log_path):
            return (False, "Log file missing")

        with open(log_path, 'r') as f:
            lines = f.readlines()

        last_start = None
        for line in reversed(lines):
            if "Starting health check cycle" in line:
                # Format: "2026-10-13 09:40:26,062 - INFO - Starting..."
                try:
                    ts_str = line.split(" - ")[0].strip()
                    last_start = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S,%f")
                    break
                except Exception:
                    continue

        if last_start is None:
            return (False, "No health check runs found in log")

        age = (datetime.now() - last_start).total_seconds()
        if age > LAST_RUN_MAX_AGE_SECONDS:
            return (False, f"Last run was {age/60:.1f} minutes ago (threshold: "
                           f"{LAST_RUN_MAX_AGE_SECONDS/60:.0f} min)")
        return (True, f"Last run was {age/60:.1f} minutes ago")
    except Exception as e:
        return (False, f"Cannot determine last run: {str(e)[:100]}")


def check_heartbeat_file():
    """Check that the heartbeat state file is recent."""
    try:
        if not os.path.exists(HEARTBEAT_STATE_FILE):
            return (False, f"Heartbeat file missing: {HEARTBEAT_STATE_FILE}")

        with open(HEARTBEAT_STATE_FILE, 'r') as f:
            content = f.read().strip()

        last_hb = datetime.fromisoformat(content)
        age = (datetime.now() - last_hb).total_seconds()

        if age > HEARTBEAT_MAX_AGE_SECONDS:
            return (False, f"Last heartbeat was {age/60:.1f} minutes ago "
                           f"(threshold: {HEARTBEAT_MAX_AGE_SECONDS/60:.0f} min)")
        return (True, f"Last heartbeat was {age/60:.1f} minutes ago")
    except Exception as e:
        return (False, f"Cannot read heartbeat file: {str(e)[:100]}")


def check_db_recent_records():
    """Check that the DB has recent records."""
    try:
        if not os.path.exists(db_path):
            return (False, f"Database missing: {db_path}")

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT MAX(timestamp) FROM health_checks")
        row = cursor.fetchone()
        conn.close()

        if not row or not row[0]:
            return (False, "No records in health_checks table")

        last_ts = datetime.fromisoformat(row[0])
        age = (datetime.now() - last_ts).total_seconds()

        if age > DB_LAST_RECORD_MAX_AGE_SECONDS:
            return (False, f"Last DB record was {age/60:.1f} minutes ago "
                           f"(threshold: {DB_LAST_RECORD_MAX_AGE_SECONDS/60:.0f} min)")
        return (True, f"Last DB record was {age/60:.1f} minutes ago")
    except Exception as e:
        return (False, f"Cannot query DB: {str(e)[:100]}")


def check_script_exists():
    """Check that the main health_check.py exists and is executable."""
    script = "/opt/splunk-watchdog/scripts/health_check.py"
    try:
        if not os.path.exists(script):
            return (False, f"Script missing: {script}")
        if not os.access(script, os.X_OK):
            return (False, f"Script not executable: {script}")
        return (True, "Main script is present and executable")
    except Exception as e:
        return (False, f"Cannot check script: {str(e)[:100]}")


def check_disk_usage():
    """Check Watchdog's own disk usage."""
    try:
        result = subprocess.run(
            ["df", "-h", "/opt/splunk-watchdog"],
            capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.strip().split("\n")
        if len(lines) < 2:
            return (False, "Cannot parse df output")
        parts = lines[1].split()
        usage = int(parts[4].replace('%', ''))
        if usage >= DISK_CRIT_PERCENT:
            return (False, f"Disk usage CRITICAL: {usage}%")
        if usage >= DISK_WARN_PERCENT:
            return (False, f"Disk usage high: {usage}%")
        return (True, f"Disk usage {usage}%")
    except Exception as e:
        return (False, f"Cannot check disk: {str(e)[:100]}")


def check_failed_systemd_units():
    """Check if any watchdog-related systemd units are in failed state."""
    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--state=failed",
             "--no-legend", "--no-pager"],
            capture_output=True, text=True, timeout=5
        )
        failed = []
        for line in result.stdout.strip().split("\n"):
            if "watchdog" in line.lower():
                failed.append(line.strip().split()[0])

        if failed:
            return (False, f"Failed units: {', '.join(failed)}")
        return (True, "No failed watchdog units")
    except Exception as e:
        return (False, f"Cannot check failed units: {str(e)[:100]}")


# ============================================================
# Main
# ============================================================

def main():
    logging.info("=" * 60)
    logging.info("Starting self-monitoring cycle")

    checks = [
        ("Systemd timer active",         check_timer_active),
        ("Last health check run",        check_last_service_run),
        ("Heartbeat file freshness",     check_heartbeat_file),
        ("Recent DB records",            check_db_recent_records),
        ("Main script exists",           check_script_exists),
        ("Watchdog disk usage",          check_disk_usage),
        ("Failed systemd units",         check_failed_systemd_units),
    ]

    problems = []
    for name, func in checks:
        try:
            ok, detail = func()
            if ok:
                logging.info(f"[OK] {name}: {detail}")
            else:
                logging.warning(f"[FAIL] {name}: {detail}")
                problems.append(f"[CRITICAL] {name}: {detail}")
        except Exception as e:
            logging.exception(f"Error in check '{name}': {e}")
            problems.append(f"[CRITICAL] {name}: Internal error - {str(e)[:100]}")

    if problems:
        message = "Watchdog self-monitoring detected problems:\n\n" + "\n".join(problems)
        logging.warning(f"Sending self-monitoring alert with {len(problems)} problems")
        send_selfmon_alert(message, severity="critical")
    else:
        logging.info("Self-monitoring: all checks passed")

    logging.info("Self-monitoring cycle completed")
    logging.info("=" * 60)


if __name__ == "__main__":
    main()
