#!/opt/splunk-watchdog/venv/bin/python3
"""
Splunk Watchdog - Health Check Script
Checks health of Splunk stack components, sends alerts, and heartbeat.
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
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from urllib3.exceptions import InsecureRequestWarning

try:
    import paramiko
except ImportError:
    print("ERROR: paramiko not installed. Run: pip install paramiko")
    sys.exit(1)

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# ------------------------------------------------------------
# Load configuration
# ------------------------------------------------------------
CONFIG_PATH = "/opt/splunk-watchdog/config/watchdog.ini"
config = configparser.ConfigParser(interpolation=None)
if not config.read(CONFIG_PATH):
    print(f"ERROR: Config file not found at {CONFIG_PATH}")
    sys.exit(1)

# ------------------------------------------------------------
# Logging setup
# ------------------------------------------------------------
log_path = config.get('general', 'log_path')
os.makedirs(os.path.dirname(log_path), exist_ok=True)
logging.basicConfig(
    filename=log_path,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ------------------------------------------------------------
# Constants from config
# ------------------------------------------------------------
THROTTLE_FILE = "/opt/splunk-watchdog/db/.last_alert"
THROTTLE_SECONDS = 900  # 15 minutes

HEARTBEAT_ENABLED = config.getboolean('heartbeat', 'enabled', fallback=True)
HEARTBEAT_INTERVAL = config.getint('heartbeat', 'interval_seconds', fallback=3600)
HEARTBEAT_STATE_FILE = config.get('heartbeat', 'state_file',
                                   fallback="/opt/splunk-watchdog/db/.last_heartbeat")

DISK_WARN = config.getint('thresholds', 'disk_warn', fallback=80)
DISK_CRIT = config.getint('thresholds', 'disk_crit', fallback=90)
QUEUE_WARN = config.getint('thresholds', 'queue_warn', fallback=70)
QUEUE_CRIT = config.getint('thresholds', 'queue_crit', fallback=90)
LOADAVG_WARN = config.getfloat('thresholds', 'loadavg_warn', fallback=8.0)
WD_DISK_WARN = config.getint('thresholds', 'watchdog_disk_warn', fallback=80)
WD_DISK_CRIT = config.getint('thresholds', 'watchdog_disk_crit', fallback=90)


# ============================================================
# Helper functions
# ============================================================

def ping_host(ip):
    try:
        subprocess.run(["ping", "-c", "1", "-W", "2", ip],
                       check=True, capture_output=True, timeout=5)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def check_tcp_port(host, port, timeout=3):
    try:
        result = subprocess.run(
            ["nc", "-zv", "-w", str(timeout), host, str(port)],
            capture_output=True, text=True, timeout=timeout + 1)
        return result.returncode == 0
    except Exception:
        return False


def check_udp_port(host, port, timeout=3):
    try:
        result = subprocess.run(
            ["nc", "-zu", "-w", str(timeout), host, str(port)],
            capture_output=True, text=True, timeout=timeout + 1)
        return result.returncode == 0
    except Exception:
        return False


def send_udp_syslog(host, port, message):
    """Send a syslog message via UDP."""
    try:
        proc = subprocess.run(
            ["nc", "-u", "-w", "2", host, str(port)],
            input=message.encode('utf-8'),
            capture_output=True, timeout=5)
        return proc.returncode == 0
    except Exception:
        return False


def ssh_exec(host, port, user, password, command, timeout=15):
    """Execute a command over SSH. Uses key if available, otherwise password."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh_key_path = config.get('ssh', 'key_path', fallback=None)
    use_key = ssh_key_path and os.path.exists(ssh_key_path)

    try:
        if use_key:
            client.connect(
                hostname=host, port=port, username=user,
                key_filename=ssh_key_path, timeout=timeout,
                allow_agent=False, look_for_keys=False)
        else:
            client.connect(
                hostname=host, port=port, username=user,
                password=password, timeout=timeout,
                allow_agent=False, look_for_keys=False)
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode('utf-8', errors='ignore').strip()
        err = stderr.read().decode('utf-8', errors='ignore').strip()
        exit_code = stdout.channel.recv_exit_status()
        client.close()
        return (exit_code == 0, out, err)
    except paramiko.AuthenticationException as e:
        try: client.close()
        except Exception: pass
        return (False, "", f"SSH authentication failed: {str(e)[:100]}")
    except paramiko.SSHException as e:
        try: client.close()
        except Exception: pass
        return (False, "", f"SSH protocol error: {str(e)[:100]}")
    except Exception as e:
        try: client.close()
        except Exception: pass
        return (False, "", f"SSH connection error: {str(e)[:100]}")


def splunk_get(host, port, user, password, endpoint, timeout=10):
    """Perform GET against Splunk REST API. Uses token if available."""
    url = f"https://{host}:{port}{endpoint}"

    # Determine which token to use based on host
    token = None
    try:
        sh_host = config.get('splunk', 'sh_host', fallback=None)
        idx_host = config.get('splunk', 'idx_host', fallback=None)

        if host == sh_host:
            token = config.get('splunk', 'sh_token', fallback=None)
        elif host == idx_host:
            token = config.get('splunk', 'idx_token', fallback=None)
    except (configparser.NoOptionError, configparser.NoSectionError):
        token = None

    try:
        if token:
            headers = {"Authorization": f"Bearer {token}"}
            response = requests.get(
                url, headers=headers, verify=False,
                timeout=timeout, params={"output_mode": "json"})
        else:
            response = requests.get(
                url, auth=(user, password), verify=False,
                timeout=timeout, params={"output_mode": "json"})

        if response.status_code == 200:
            try:
                return (True, response.json(), "")
            except ValueError:
                return (True, None, "Invalid JSON")
        return (False, None, f"HTTP {response.status_code}")

    except requests.exceptions.Timeout:
        return (False, None, "Timeout")
    except requests.exceptions.ConnectionError:
        return (False, None, "Connection refused")
    except Exception as e:
        return (False, None, str(e)[:100])


def splunk_search_oneshot(host, port, user, password, token, search_query, timeout=30):
    """
    Execute a one-shot Splunk search and return results as a list of dicts.
    """
    url = f"https://{host}:{port}/services/search/jobs/export"
    data = {
        "search": search_query,
        "output_mode": "json",
        "exec_mode": "oneshot",
    }
    try:
        if token:
            headers = {"Authorization": f"Bearer {token}"}
            response = requests.post(
                url, headers=headers, verify=False,
                data=data, timeout=timeout)
        else:
            response = requests.post(
                url, auth=(user, password), verify=False,
                data=data, timeout=timeout)

        if response.status_code != 200:
            return (False, None, f"HTTP {response.status_code}")

        results = []
        for line in response.text.strip().split("\n"):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                if "result" in obj:
                    results.append(obj["result"])
            except json.JSONDecodeError:
                continue

        return (True, results, "")
    except requests.exceptions.Timeout:
        return (False, None, "Timeout")
    except requests.exceptions.ConnectionError:
        return (False, None, "Connection refused")
    except Exception as e:
        return (False, None, str(e)[:100])


def check_splunk_health(host, port, user, password):
    ok, data, err = splunk_get(host, port, user, password,
                                "/services/server/health/splunkd")
    if ok:
        return True, "OK"
    return False, err


# ============================================================
# Database
# ============================================================

def init_db():
    db_path = config.get('general', 'db_path')
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS health_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            component TEXT NOT NULL,
            check_type TEXT NOT NULL,
            status TEXT NOT NULL,
            details TEXT
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON health_checks(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_component ON health_checks(component)')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS heartbeat (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            status TEXT NOT NULL,
            details TEXT
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_hb_timestamp ON heartbeat(timestamp)')
    conn.commit()
    return conn


def save_result(conn, component, check_type, status, details=""):
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO health_checks (timestamp, component, check_type, status, details)
        VALUES (?, ?, ?, ?, ?)
    ''', (datetime.now().isoformat(), component, check_type, status, details))
    conn.commit()


def save_heartbeat(conn, status, details=""):
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO heartbeat (timestamp, status, details)
        VALUES (?, ?, ?)
    ''', (datetime.now().isoformat(), status, details))
    conn.commit()


# ============================================================
# Webhook
# ============================================================

def should_send_alert(severity):
    try:
        if os.path.exists(THROTTLE_FILE):
            with open(THROTTLE_FILE, 'r') as f:
                data = json.load(f)
            last_time = data.get(severity)
            if last_time:
                last_dt = datetime.fromisoformat(last_time)
                if datetime.now() - last_dt < timedelta(seconds=THROTTLE_SECONDS):
                    return False
        return True
    except Exception:
        return True


def mark_alert_sent(severity):
    try:
        data = {}
        if os.path.exists(THROTTLE_FILE):
            with open(THROTTLE_FILE, 'r') as f:
                data = json.load(f)
        data[severity] = datetime.now().isoformat()
        with open(THROTTLE_FILE, 'w') as f:
            json.dump(data, f)
    except Exception as e:
        logging.warning(f"Could not update throttle file: {e}")


def send_webhook_raw(full_text):
    """Send raw text to Bale webhook (no throttling)."""
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
            logging.error(f"Webhook failed: HTTP {response.status_code} - {response.text[:200]}")
            return False
        return True
    except Exception as e:
        logging.error(f"Webhook error: {str(e)[:150]}")
        return False


def send_webhook(message, severity="info", force=False):
    """Send alert to Bale webhook with throttling."""
    if not force and not should_send_alert(severity):
        logging.info(f"Alert throttled (severity={severity}). Skipping.")
        return False

    prefix = {
        "info": "[INFO]",
        "warning": "[WARNING]",
        "critical": "[CRITICAL]"
    }.get(severity, "[INFO]")

    title = f"*{prefix} Splunk Watchdog Alert*"
    full_text = f"{title}\n\n{message}"

    success = send_webhook_raw(full_text)
    if success:
        mark_alert_sent(severity)
        logging.info(f"Webhook sent successfully (severity={severity})")
    return success


# ============================================================
# Heartbeat
# ============================================================

def should_send_heartbeat():
    if not HEARTBEAT_ENABLED:
        return False
    try:
        if not os.path.exists(HEARTBEAT_STATE_FILE):
            return True
        with open(HEARTBEAT_STATE_FILE, 'r') as f:
            last = datetime.fromisoformat(f.read().strip())
        return (datetime.now() - last).total_seconds() >= HEARTBEAT_INTERVAL
    except Exception:
        return True


def mark_heartbeat_sent():
    try:
        with open(HEARTBEAT_STATE_FILE, 'w') as f:
            f.write(datetime.now().isoformat())
    except Exception as e:
        logging.warning(f"Could not update heartbeat file: {e}")


def send_heartbeat(conn, all_issues):
    if all_issues:
        status = "ISSUES"
        summary = f"Heartbeat: Watchdog is alive but {len(all_issues)} issue(s) detected"
    else:
        status = "OK"
        summary = "Heartbeat: All systems OK"

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    title = "*[HEARTBEAT] Splunk Watchdog Alive*"
    body = (
        f"{summary}\n"
        f"Time: {now}\n"
        f"Components checked: 4\n"
        f"Checks per cycle: 68+"
    )
    full_text = f"{title}\n\n{body}"

    success = send_webhook_raw(full_text)
    if success:
        mark_heartbeat_sent()
        save_heartbeat(conn, status, summary)
        logging.info(f"Heartbeat sent (status={status})")
    else:
        logging.error("Heartbeat failed to send")
    return success


# ============================================================
# Component checks
# ============================================================


def check_search_head(conn, ip):
    issues = []

    if not ping_host(ip):
        save_result(conn, "search_head", "ping", "fail", f"Ping to {ip} failed")
        return [f"[CRITICAL] Search Head ({ip}): Ping failed"]
    save_result(conn, "search_head", "ping", "ok", f"Ping to {ip} OK")

    for port, label in [
        (config.getint('network', 'splunk_mgmt_port'), "Management"),
        (config.getint('network', 'splunk_web_port'), "Splunk Web"),
    ]:
        if check_tcp_port(ip, port):
            save_result(conn, "search_head", f"port_{port}", "ok", f"TCP {port} open")
        else:
            save_result(conn, "search_head", f"port_{port}", "fail", f"TCP {port} closed")
            issues.append(f"[WARNING] Search Head: {label} port {port} closed")

    # splunkd health
    ok, msg = check_splunk_health(
        config.get('splunk', 'sh_host'),
        config.getint('splunk', 'sh_port'),
        config.get('splunk', 'sh_user'),
        config.get('splunk', 'sh_pass', fallback=''))
    if ok:
        save_result(conn, "search_head", "splunkd_health", "ok", msg)
    else:
        save_result(conn, "search_head", "splunkd_health", "fail", msg)
        issues.append(f"[CRITICAL] Search Head: splunkd health failed - {msg}")

    # KV Store
    ok, data, err = splunk_get(
        config.get('splunk', 'sh_host'),
        config.getint('splunk', 'sh_port'),
        config.get('splunk', 'sh_user'),
        config.get('splunk', 'sh_pass', fallback=''),
        "/services/kvstore/status")
    if ok and data:
        try:
            entries = data.get("entry", [])
            if not entries:
                save_result(conn, "search_head", "kvstore", "unknown",
                            "No entries in KV Store status")
            else:
                current = entries[0].get("content", {}).get("current", {})
                disabled = current.get("disabled", False)
                backup_status = current.get("backupRestoreStatus", "unknown")
                migration_status = current.get("migrationStatus", "unknown")

                if disabled:
                    save_result(conn, "search_head", "kvstore", "fail",
                                "KV Store is DISABLED")
                    issues.append("[CRITICAL] Search Head: KV Store is disabled")
                elif backup_status != "Ready":
                    save_result(conn, "search_head", "kvstore", "warn",
                                f"backupRestoreStatus={backup_status}")
                    issues.append(
                        f"[WARNING] Search Head: KV Store backup status is '{backup_status}'")
                elif migration_status == "InProgress":
                    save_result(conn, "search_head", "kvstore", "warn",
                                f"migrationStatus={migration_status}")
                    issues.append("[WARNING] Search Head: KV Store migration in progress")
                else:
                    save_result(conn, "search_head", "kvstore", "ok",
                                f"Ready (backup={backup_status}, migration={migration_status})")
        except (KeyError, IndexError, TypeError) as e:
            save_result(conn, "search_head", "kvstore", "unknown",
                        f"Parse error: {str(e)[:100]}")
    else:
        save_result(conn, "search_head", "kvstore", "fail", err)
        issues.append(f"[WARNING] Search Head: Cannot check KV Store - {err}")

    # ────────────────────────────────────────────────────────
    # 1. Search Peers
    # ────────────────────────────────────────────────────────
    ok, data, err = splunk_get(
        config.get('splunk', 'sh_host'),
        config.getint('splunk', 'sh_port'),
        config.get('splunk', 'sh_user'),
        config.get('splunk', 'sh_pass', fallback=''),
        "/services/search/distributed/peers")
    if ok and data:
        try:
            entries = data.get("entry", [])
            if not entries:
                save_result(conn, "search_head", "search_peers", "warn",
                            "No search peers configured")
                issues.append("[WARNING] Search Head: No search peers configured")
            else:
                down_peers = [e.get("name") for e in entries 
                             if e.get("content", {}).get("status") != "Up"]
                if down_peers:
                    save_result(conn, "search_head", "search_peers", "fail",
                                f"{len(down_peers)} down: {', '.join(down_peers[:3])}")
                    issues.append(
                        f"[CRITICAL] Search Head: {len(down_peers)} search peer(s) down: "
                        f"{', '.join(down_peers[:3])}"
                    )
                else:
                    save_result(conn, "search_head", "search_peers", "ok",
                                f"{len(entries)} peer(s) up")
        except (KeyError, IndexError) as e:
            save_result(conn, "search_head", "search_peers", "unknown", str(e)[:100])
    else:
        save_result(conn, "search_head", "search_peers", "fail", err)

    # ────────────────────────────────────────────────────────
    # 2. Search Scheduler
    # ────────────────────────────────────────────────────────
    ok, data, err = splunk_get(
        config.get('splunk', 'sh_host'),
        config.getint('splunk', 'sh_port'),
        config.get('splunk', 'sh_user'),
        config.get('splunk', 'sh_pass', fallback=''),
        "/services/search/scheduler")
    if ok and data:
        try:
            entries = data.get("entry", [])
            if not entries:
                save_result(conn, "search_head", "scheduler", "unknown", "No entries")
            else:
                content = entries[0].get("content", {})
                disabled = content.get("saved_searches_disabled", False)
                if disabled:
                    save_result(conn, "search_head", "scheduler", "fail",
                                "saved_searches_disabled=True")
                    issues.append("[CRITICAL] Search Head: Scheduler disabled")
                else:
                    save_result(conn, "search_head", "scheduler", "ok",
                                "Scheduler active")
        except (KeyError, IndexError) as e:
            save_result(conn, "search_head", "scheduler", "unknown", str(e)[:100])
    else:
        save_result(conn, "search_head", "scheduler", "fail", err)

    # ────────────────────────────────────────────────────────
    # 3. Disk usage
    # ────────────────────────────────────────────────────────
    ok, data, err = splunk_get(
        config.get('splunk', 'sh_host'),
        config.getint('splunk', 'sh_port'),
        config.get('splunk', 'sh_user'),
        config.get('splunk', 'sh_pass', fallback=''),
        "/services/server/status/partitions-space")
    if ok and data:
        try:
            entries = data.get("entry", [])
            for e in entries:
                content = e.get("content", {})
                mount = content.get("mount_point", "?")
                try:
                    capacity = float(content.get("capacity", 0))
                    free = float(content.get("free", 0))
                    if capacity > 0:
                        usage = ((capacity - free) / capacity) * 100
                        if usage >= DISK_CRIT:
                            save_result(conn, "search_head", f"disk_{mount}", "fail",
                                        f"{usage:.1f}%")
                            issues.append(
                                f"[CRITICAL] Search Head: Disk {mount} usage "
                                f"critical ({usage:.1f}%)"
                            )
                        elif usage >= DISK_WARN:
                            save_result(conn, "search_head", f"disk_{mount}", "warn",
                                        f"{usage:.1f}%")
                            issues.append(
                                f"[WARNING] Search Head: Disk {mount} usage "
                                f"high ({usage:.1f}%)"
                            )
                        else:
                            save_result(conn, "search_head", f"disk_{mount}", "ok",
                                        f"{usage:.1f}%")
                except (ValueError, TypeError):
                    pass
        except (KeyError, IndexError):
            save_result(conn, "search_head", "disk", "unknown", "Parse error")
    else:
        save_result(conn, "search_head", "disk", "fail", err)

    # ────────────────────────────────────────────────────────
    # 4. Active search jobs
    # ────────────────────────────────────────────────────────
    ok, data, err = splunk_get(
        config.get('splunk', 'sh_host'),
        config.getint('splunk', 'sh_port'),
        config.get('splunk', 'sh_user'),
        config.get('splunk', 'sh_pass', fallback=''),
        "/services/search/jobs?count=0")
    if ok and data:
        try:
            entries = data.get("entry", [])
            # Count running jobs
            running = 0
            for e in entries:
                content = e.get("content", {})
                dispatch_state = content.get("dispatchState", "")
                if dispatch_state in ("Running", "Queued", "Parsing"):
                    running += 1

            total = len(entries)
            if running > 50:
                save_result(conn, "search_head", "search_jobs", "warn",
                            f"{running} running / {total} total")
                issues.append(
                    f"[WARNING] Search Head: {running} search jobs running "
                    f"(threshold: 50)"
                )
            else:
                save_result(conn, "search_head", "search_jobs", "ok",
                            f"{running} running / {total} total")
        except (KeyError, IndexError) as e:
            save_result(conn, "search_head", "search_jobs", "unknown", str(e)[:100])
    else:
        save_result(conn, "search_head", "search_jobs", "unknown", err)

    return issues


def check_es(conn):
    """Check ES (Enterprise Security) specific health."""
    issues = []

    # ────────────────────────────────────────────────────────
    # 1. ES Apps status (ignore SA-UEBA)
    # ────────────────────────────────────────────────────────
    IGNORED_APPS = ["UEBA", "SA-UEBA", "DA-ESS-UEBA"]  # apps that are intentionally disabled

    ok, data, err = splunk_get(
        config.get('splunk', 'sh_host'),
        config.getint('splunk', 'sh_port'),
        config.get('splunk', 'sh_user'),
        config.get('splunk', 'sh_pass', fallback=''),
        "/services/apps/local?count=0")
    if ok and data:
        try:
            entries = data.get("entry", [])
            es_apps = [e for e in entries if any(x in e.get("name", "")
                       for x in ["ESS", "SA-", "DA-", "Enterprise", "Threat", "TIM", "UEBA"])]
            disabled_apps = [
                e.get("name") for e in es_apps
                if e.get("content", {}).get("disabled", False)
                and not any(ignored in e.get("name", "") for ignored in IGNORED_APPS)
            ]
            if disabled_apps:
                save_result(conn, "es", "es_apps", "warn",
                            f"{len(disabled_apps)} disabled: {', '.join(disabled_apps[:3])}")
                issues.append(
                    f"[WARNING] ES: {len(disabled_apps)} ES app(s) disabled: "
                    f"{', '.join(disabled_apps[:3])}"
                )
            else:
                save_result(conn, "es", "es_apps", "ok",
                            f"{len(es_apps)} ES apps enabled (ignored: {', '.join(IGNORED_APPS)})")
        except (KeyError, IndexError) as e:
            save_result(conn, "es", "es_apps", "unknown", str(e)[:100])
    else:
        save_result(conn, "es", "es_apps", "fail", err)
        issues.append(f"[WARNING] ES: Cannot check apps - {err}")

    # ────────────────────────────────────────────────────────
    # 2. Correlation Searches (only local Search Head)
    # ────────────────────────────────────────────────────────
    search = (
        '| rest /services/saved/searches splunk_server=local '
        '| search title="* - Rule" OR title="* - Correlation*" '
        '| stats count as total, '
        'sum(eval(if(disabled=1,1,0))) as disabled_count, '
        'sum(eval(if(disabled=0,1,0))) as enabled_count'
    )
    ok, data, err = splunk_search_oneshot(
        config.get('splunk', 'sh_host'),
        config.getint('splunk', 'sh_port'),
        config.get('splunk', 'sh_user'),
        config.get('splunk', 'sh_pass', fallback=''),
        config.get('splunk', 'sh_token', fallback=None),
        search)
    if ok and data:
        try:
            total = 0
            disabled = 0
            enabled = 0
            for result in data:
                total += int(result.get("total", 0) or 0)
                disabled += int(result.get("disabled_count", 0) or 0)
                enabled += int(result.get("enabled_count", 0) or 0)

            if total == 0:
                save_result(conn, "es", "correlation_searches", "warn",
                            "No correlation searches found")
                issues.append("[WARNING] ES: No correlation searches found")
            else:
                save_result(conn, "es", "correlation_searches", "ok",
                            f"{total} total, {enabled} enabled, {disabled} disabled")
        except (ValueError, TypeError, IndexError) as e:
            save_result(conn, "es", "correlation_searches", "unknown", str(e)[:100])
    else:
        save_result(conn, "es", "correlation_searches", "unknown", err)

    # ────────────────────────────────────────────────────────
    # 3. Threat Intel Downloads (last 24h)
    # ────────────────────────────────────────────────────────
    search = (
        'search index=_internal source=*threatlist.log earliest=-24h '
        '| stats count by status '
        '| head 10'
    )
    ok, data, err = splunk_search_oneshot(
        config.get('splunk', 'sh_host'),
        config.getint('splunk', 'sh_port'),
        config.get('splunk', 'sh_user'),
        config.get('splunk', 'sh_pass', fallback=''),
        config.get('splunk', 'sh_token', fallback=None),
        search)
    if ok and data:
        try:
            errors = 0
            total = 0
            for result in data:
                status = result.get("status", "")
                count = int(result.get("count", 0))
                total += count
                if "error" in status.lower() or "fail" in status.lower():
                    errors += count

            if errors > 0:
                save_result(conn, "es", "threatintel_downloads", "warn",
                            f"{total} total, {errors} errors")
                issues.append(
                    f"[WARNING] ES: {errors} error(s) in Threat Intel downloads (24h)"
                )
            else:
                save_result(conn, "es", "threatintel_downloads", "ok",
                            f"{total} downloads in 24h")
        except (ValueError, TypeError):
            save_result(conn, "es", "threatintel_downloads", "unknown", "Parse error")
    else:
        save_result(conn, "es", "threatintel_downloads", "unknown", err)

    # ────────────────────────────────────────────────────────
    # 4. Age of last Threat Intel download (thresholds: 10h warn, 14h crit)
    # ────────────────────────────────────────────────────────
    search = (
        'search index=_internal source=*threatlist.log earliest=-7d '
        '| stats latest(_time) as last_time '
        '| eval age_hours = round((now() - last_time) / 3600, 1)'
    )
    ok, data, err = splunk_search_oneshot(
        config.get('splunk', 'sh_host'),
        config.getint('splunk', 'sh_port'),
        config.get('splunk', 'sh_user'),
        config.get('splunk', 'sh_pass', fallback=''),
        config.get('splunk', 'sh_token', fallback=None),
        search)
    if ok and data:
        try:
            for result in data:
                age_h = float(result.get("age_hours", 999))
                if age_h > 16:
                    save_result(conn, "es", "threatintel_age", "fail",
                                f"Last download {age_h:.1f}h ago")
                    issues.append(
                        f"[CRITICAL] ES: Last Threat Intel download was "
                        f"{age_h:.1f}h ago"
                    )
                elif age_h > 12:
                    save_result(conn, "es", "threatintel_age", "warn",
                                f"Last download {age_h:.1f}h ago")
                    issues.append(
                        f"[WARNING] ES: Last Threat Intel download was "
                        f"{age_h:.1f}h ago"
                    )
                else:
                    save_result(conn, "es", "threatintel_age", "ok",
                                f"Last download {age_h:.1f}h ago")
        except (ValueError, TypeError):
            save_result(conn, "es", "threatintel_age", "unknown", "Parse error")
    else:
        save_result(conn, "es", "threatintel_age", "unknown", err)

    # ────────────────────────────────────────────────────────
    # 5. Notable Events (last 24h) - use index=notable directly
    # ────────────────────────────────────────────────────────
    search = (
        '| tstats count where index=notable earliest=-24h '
        '| head 1'
    )
    ok, data, err = splunk_search_oneshot(
        config.get('splunk', 'sh_host'),
        config.getint('splunk', 'sh_port'),
        config.get('splunk', 'sh_user'),
        config.get('splunk', 'sh_pass', fallback=''),
        config.get('splunk', 'sh_token', fallback=None),
        search)
    if ok and data:
        try:
            count = 0
            for result in data:
                count = int(result.get("count", 0))
            save_result(conn, "es", "notable_events_24h", "ok",
                        f"{count} notable events in 24h")
        except (ValueError, TypeError):
            save_result(conn, "es", "notable_events_24h", "unknown", "Parse error")
    else:
        save_result(conn, "es", "notable_events_24h", "unknown", err)

    return issues

def check_indexer(conn, ip):
    issues = []

    if not ping_host(ip):
        save_result(conn, "indexer", "ping", "fail", f"Ping to {ip} failed")
        return [f"[CRITICAL] Indexer ({ip}): Ping failed"]
    save_result(conn, "indexer", "ping", "ok", f"Ping to {ip} OK")

    for port, label in [
        (config.getint('network', 'splunk_mgmt_port'), "Management"),
        (config.getint('network', 'splunk_s2s_port'), "S2S Receiving"),
    ]:
        if check_tcp_port(ip, port):
            save_result(conn, "indexer", f"port_{port}", "ok", f"TCP {port} open")
        else:
            save_result(conn, "indexer", f"port_{port}", "fail", f"TCP {port} closed")
            issues.append(f"[WARNING] Indexer: {label} port {port} closed")

    ok, msg = check_splunk_health(
        config.get('splunk', 'idx_host'),
        config.getint('splunk', 'idx_port'),
        config.get('splunk', 'idx_user'),
        config.get('splunk', 'idx_pass', fallback=''))
    if ok:
        save_result(conn, "indexer", "splunkd_health", "ok", msg)
    else:
        save_result(conn, "indexer", "splunkd_health", "fail", msg)
        issues.append(f"[CRITICAL] Indexer: splunkd health failed - {msg}")

    # ────────────────────────────────────────────────────────
    # 1. Introspection: status + average_KBps
    # ────────────────────────────────────────────────────────
    ok, data, err = splunk_get(
        config.get('splunk', 'idx_host'),
        config.getint('splunk', 'idx_port'),
        config.get('splunk', 'idx_user'),
        config.get('splunk', 'idx_pass', fallback=''),
        "/services/server/introspection/indexer")
    if ok and data:
        try:
            entries = data.get("entry", [])
            if not entries:
                save_result(conn, "indexer", "indexer_introspection", "unknown",
                            "No entries")
            else:
                content = entries[0].get("content", {})
                status = content.get("status", "unknown")
                rate = content.get("average_KBps", 0)
                reason = content.get("reason", "")

                if status == "normal":
                    save_result(conn, "indexer", "indexer_introspection", "ok",
                                f"status={status}, rate={rate:.1f} KB/s")
                else:
                    save_result(conn, "indexer", "indexer_introspection", "warn",
                                f"status={status}, reason={reason}")
                    issues.append(
                        f"[WARNING] Indexer: Introspection status is '{status}' - {reason}"
                    )

                # Check ingestion rate
                try:
                    rate_val = float(rate)
                    if rate_val < 1.0:
                        save_result(conn, "indexer", "indexer_rate", "warn",
                                    f"Rate {rate_val:.2f} KB/s")
                        issues.append(
                            f"[WARNING] Indexer: Ingestion rate is very low "
                            f"({rate_val:.2f} KB/s)"
                        )
                    else:
                        save_result(conn, "indexer", "indexer_rate", "ok",
                                    f"Rate {rate_val:.1f} KB/s")
                except (ValueError, TypeError):
                    pass
        except (KeyError, IndexError) as e:
            save_result(conn, "indexer", "indexer_introspection", "unknown",
                        f"Parse error: {str(e)[:100]}")
    else:
        save_result(conn, "indexer", "indexer_introspection", "fail", err)
        issues.append(f"[WARNING] Indexer: Cannot fetch introspection - {err}")

    # ────────────────────────────────────────────────────────
    # 2. Disk usage (partitions-space)
    # ────────────────────────────────────────────────────────
    ok, data, err = splunk_get(
        config.get('splunk', 'idx_host'),
        config.getint('splunk', 'idx_port'),
        config.get('splunk', 'idx_user'),
        config.get('splunk', 'idx_pass', fallback=''),
        "/services/server/status/partitions-space")
    if ok and data:
        try:
            entries = data.get("entry", [])
            for e in entries:
                content = e.get("content", {})
                mount = content.get("mount_point", "?")
                # Only check /opt (Splunk installation)
                if mount != "/opt":
                    continue
                try:
                    capacity = float(content.get("capacity", 0))
                    free = float(content.get("free", 0))
                    if capacity > 0:
                        usage = ((capacity - free) / capacity) * 100
                        if usage >= DISK_CRIT:
                            save_result(conn, "indexer", "disk", "fail",
                                        f"{mount}: {usage:.1f}%")
                            issues.append(
                                f"[CRITICAL] Indexer: Disk {mount} usage "
                                f"critical ({usage:.1f}%)"
                            )
                        elif usage >= DISK_WARN:
                            save_result(conn, "indexer", "disk", "warn",
                                        f"{mount}: {usage:.1f}%")
                            issues.append(
                                f"[WARNING] Indexer: Disk {mount} usage "
                                f"high ({usage:.1f}%)"
                            )
                        else:
                            save_result(conn, "indexer", "disk", "ok",
                                        f"{mount}: {usage:.1f}%")
                except (ValueError, TypeError):
                    pass
        except (KeyError, IndexError):
            save_result(conn, "indexer", "disk", "unknown", "Parse error")
    else:
        save_result(conn, "indexer", "disk", "fail", err)
        issues.append(f"[WARNING] Indexer: Cannot fetch partitions - {err}")

    # ────────────────────────────────────────────────────────
    # 3. License usage (via SPL)
    # ────────────────────────────────────────────────────────
    license_query = (
        'search index=_internal source=*license_usage.log type="Usage" earliest=-24h '
        '| stats sum(b) as total_bytes '
        '| eval total_gb = round(total_bytes/1024/1024/1024, 2)'
    )
    ok, data, err = splunk_search_oneshot(
        config.get('splunk', 'idx_host'),
        config.getint('splunk', 'idx_port'),
        config.get('splunk', 'idx_user'),
        config.get('splunk', 'idx_pass', fallback=''),
        config.get('splunk', 'idx_token', fallback=None),
        license_query)
    if ok and data:
        try:
            # data is a list of result dicts
            for result in data:
                total_gb = result.get("total_gb", "0")
                save_result(conn, "indexer", "license_daily", "ok",
                            f"24h usage: {total_gb} GB")
        except Exception as e:
            save_result(conn, "indexer", "license_daily", "unknown",
                        str(e)[:100])
    else:
        save_result(conn, "indexer", "license_daily", "unknown",
                    f"Cannot query license: {err}")

    # ────────────────────────────────────────────────────────
    # 4. Number of indexes
    # ────────────────────────────────────────────────────────
    ok, data, err = splunk_get(
        config.get('splunk', 'idx_host'),
        config.getint('splunk', 'idx_port'),
        config.get('splunk', 'idx_user'),
        config.get('splunk', 'idx_pass', fallback=''),
        "/services/data/indexes")
    if ok and data:
        try:
            entries = data.get("entry", [])
            count = len(entries)
            if count < 10:
                save_result(conn, "indexer", "index_count", "warn",
                            f"Only {count} indexes")
                issues.append(
                    f"[WARNING] Indexer: Only {count} indexes (expected ≥10)"
                )
            else:
                save_result(conn, "indexer", "index_count", "ok",
                            f"{count} indexes")
        except (KeyError, IndexError):
            save_result(conn, "indexer", "index_count", "unknown", "Parse error")
    else:
        save_result(conn, "indexer", "index_count", "fail", err)

    # ────────────────────────────────────────────────────────
    # 5. Indexer queues (via SPL)
    # ────────────────────────────────────────────────────────
    queue_query = (
        'search index=_internal source=*metrics.log group=queue earliest=-5m '
        '| stats latest(current_size) as current_size latest(max_size) as max_size by name '
        '| eval fill_pct = if(max_size > 0, round(current_size / max_size * 100, 1), 0)'
    )
    ok, data, err = splunk_search_oneshot(
        config.get('splunk', 'idx_host'),
        config.getint('splunk', 'idx_port'),
        config.get('splunk', 'idx_user'),
        config.get('splunk', 'idx_pass', fallback=''),
        config.get('splunk', 'idx_token', fallback=None),
        queue_query)
    if ok and data:
        try:
            for result in data:
                name = result.get("name", "?")
                fill = float(result.get("fill_pct", 0))
                if fill >= QUEUE_CRIT:
                    save_result(conn, "indexer", f"queue_{name}", "fail",
                                f"{fill}% full")
                    issues.append(
                        f"[CRITICAL] Indexer: Queue {name} at {fill}%"
                    )
                elif fill >= QUEUE_WARN:
                    save_result(conn, "indexer", f"queue_{name}", "warn",
                                f"{fill}% full")
                    issues.append(
                        f"[WARNING] Indexer: Queue {name} at {fill}%"
                    )
                else:
                    save_result(conn, "indexer", f"queue_{name}", "ok",
                                f"{fill}% full")
        except Exception as e:
            save_result(conn, "indexer", "indexer_queue", "unknown",
                        f"Parse error: {str(e)[:100]}")
    else:
        save_result(conn, "indexer", "indexer_queue", "unknown",
                    f"Cannot query queues: {err}")

    return issues


def check_syslog_relay(conn, ip):
    issues = []

    if not ping_host(ip):
        save_result(conn, "syslog_relay", "ping", "fail", f"Ping to {ip} failed")
        return [f"[CRITICAL] Syslog Relay ({ip}): Ping failed"]
    save_result(conn, "syslog_relay", "ping", "ok", f"Ping to {ip} OK")

    ssh_port = config.getint('network', 'ssh_port')
    if not check_tcp_port(ip, ssh_port):
        save_result(conn, "syslog_relay", "port_ssh", "fail", f"TCP {ssh_port} closed")
        issues.append(f"[CRITICAL] Syslog Relay: SSH port {ssh_port} closed")
        return issues
    save_result(conn, "syslog_relay", "port_ssh", "ok", f"TCP {ssh_port} open")

    udp_port = config.getint('network', 'syslog_udp_port')
    if check_udp_port(ip, udp_port):
        save_result(conn, "syslog_relay", "port_udp", "ok", f"UDP {udp_port} reachable")
    else:
        save_result(conn, "syslog_relay", "port_udp", "warn", f"UDP {udp_port} not reachable")
        issues.append(f"[WARNING] Syslog Relay: UDP port {udp_port} not reachable")

    host = config.get('splunk', 'relay_host')
    user = config.get('splunk', 'relay_user')
    password = config.get('splunk', 'relay_pass', fallback='')

    # rsyslog service
    ok, out, err = ssh_exec(host, ssh_port, user, password, "systemctl is-active rsyslog")
    if not ok:
        save_result(conn, "syslog_relay", "rsyslog_service", "fail", f"SSH failed: {err}")
        issues.append(f"[CRITICAL] Syslog Relay: Cannot check rsyslog - {err[:100]}")
    elif out.strip() == "active":
        save_result(conn, "syslog_relay", "rsyslog_service", "ok", "rsyslog active")
    else:
        save_result(conn, "syslog_relay", "rsyslog_service", "fail", f"not active: {out}")
        issues.append("[CRITICAL] Syslog Relay: rsyslog service is not active")

    # Port 514 listener
    ok, out, err = ssh_exec(host, ssh_port, user, password, "ss -tulnp | grep ':514 '")
    if not ok:
        save_result(conn, "syslog_relay", "syslog_listener", "fail", f"SSH failed: {err}")
        issues.append(f"[WARNING] Syslog Relay: Cannot check listener - {err[:100]}")
    elif "514" in out:
        save_result(conn, "syslog_relay", "syslog_listener", "ok", "Port 514 listening")
    else:
        save_result(conn, "syslog_relay", "syslog_listener", "fail", "Port 514 not listening")
        issues.append("[WARNING] Syslog Relay: No listener on port 514")

    # Disk
    ok, out, err = ssh_exec(host, ssh_port, user, password,
                            "df -h / | tail -1 | awk '{print $5}'")
    if not ok:
        save_result(conn, "syslog_relay", "disk", "fail", f"SSH failed: {err}")
        issues.append(f"[CRITICAL] Syslog Relay: Cannot check disk - {err[:100]}")
    elif out.strip():
        usage_str = out.strip().replace('%', '')
        try:
            usage = int(usage_str)
            if usage >= DISK_CRIT:
                save_result(conn, "syslog_relay", "disk", "fail", f"Disk usage {usage}%")
                issues.append(f"[CRITICAL] Syslog Relay: Disk usage critical ({usage}%)")
            elif usage >= DISK_WARN:
                save_result(conn, "syslog_relay", "disk", "warn", f"Disk usage {usage}%")
                issues.append(f"[WARNING] Syslog Relay: Disk usage high ({usage}%)")
            else:
                save_result(conn, "syslog_relay", "disk", "ok", f"Disk usage {usage}%")
        except ValueError:
            save_result(conn, "syslog_relay", "disk", "unknown", out)

    # Logrotate
    ok, out, err = ssh_exec(host, ssh_port, user, password,
                            "find /var/log -name '*.gz' -mtime -2 2>/dev/null | wc -l")
    if not ok:
        save_result(conn, "syslog_relay", "logrotate", "fail", f"SSH failed: {err}")
        issues.append(f"[WARNING] Syslog Relay: Cannot check logrotate - {err[:100]}")
    else:
        try:
            count = int(out.strip())
            if count > 0:
                save_result(conn, "syslog_relay", "logrotate", "ok",
                            f"{count} rotated files in 2 days")
            else:
                save_result(conn, "syslog_relay", "logrotate", "warn",
                            "No rotated files in 2 days")
                issues.append("[WARNING] Syslog Relay: Log rotation may not be working")
        except ValueError:
            pass

    # UF service
    ok, out, err = ssh_exec(host, ssh_port, user, password,
                            "systemctl is-active SplunkForwarder")
    if not ok:
        save_result(conn, "syslog_relay", "uf_service", "fail", f"SSH failed: {err}")
        issues.append(f"[CRITICAL] Syslog Relay: Cannot check UF - {err[:100]}")
    elif out.strip() == "active":
        save_result(conn, "syslog_relay", "uf_service", "ok", "UF active")
    else:
        save_result(conn, "syslog_relay", "uf_service", "fail", f"not active: {out}")
        issues.append("[CRITICAL] Syslog Relay: Splunk UF is not active")

    # ============================================================
    # End-to-End Syslog test
    # ============================================================
    probe_marker = config.get('e2e', 'probe_marker', fallback="watchdog_e2e_probe")
    test_index = config.get('e2e', 'test_index', fallback="watchdog")
    test_sourcetype = config.get('e2e', 'test_sourcetype', fallback="watchdog:e2e")
    search_delay = config.getint('e2e', 'search_delay', fallback=30)

    probe_id = f"{probe_marker}-{int(datetime.now().timestamp())}"
    probe_ts = datetime.now().strftime("%b %d %H:%M:%S")
    syslog_msg = f"<14>{probe_ts} watchdog-e2e: {probe_id}"

    # Send probe
    if not send_udp_syslog(ip, udp_port, syslog_msg):
        save_result(conn, "syslog_relay", "e2e_send", "fail", "Failed to send E2E probe")
        issues.append("[WARNING] Syslog Relay: E2E probe send failed")
    else:
        save_result(conn, "syslog_relay", "e2e_send", "ok", f"Probe sent: {probe_id}")
        logging.info(f"E2E: probe sent ({probe_id}), waiting {search_delay}s")

        time.sleep(search_delay)

        # Search Indexer for probe
        search_query = (
            f'search index={test_index} sourcetype="{test_sourcetype}" "{probe_id}" | head 1'
        )
        search_params = {
            "search": search_query,
            "output_mode": "json",
            "exec_mode": "oneshot",
        }

        idx_host = config.get('splunk', 'idx_host')
        idx_port = config.getint('splunk', 'idx_port')
        idx_user = config.get('splunk', 'idx_user')
        idx_pass = config.get('splunk', 'idx_pass', fallback='')
        idx_token = config.get('splunk', 'idx_token', fallback=None)

        try:
            url = f"https://{idx_host}:{idx_port}/services/search/jobs/export"
            if idx_token:
                headers = {"Authorization": f"Bearer {idx_token}"}
                response = requests.post(
                    url, headers=headers, verify=False,
                    data=search_params, timeout=search_delay + 30)
            else:
                response = requests.post(
                    url, auth=(idx_user, idx_pass), verify=False,
                    data=search_params, timeout=search_delay + 30)
            if response.status_code == 200:
                found = False
                for line in response.text.strip().split("\n"):
                    if not line.strip():
                        continue
                    try:
                        result = json.loads(line)
                        raw = result.get("result", {}).get("_raw", "")
                        if probe_id in raw:
                            found = True
                            break
                    except json.JSONDecodeError:
                        continue

                if found:
                    save_result(conn, "syslog_relay", "e2e_receive", "ok",
                                f"Probe found in index={test_index}")
                    logging.info(f"E2E: probe {probe_id} received successfully")
                else:
                    save_result(conn, "syslog_relay", "e2e_receive", "fail",
                                f"Probe NOT found in index={test_index} after {search_delay}s")
                    issues.append(
                        f"[CRITICAL] Syslog Relay: E2E probe not received "
                        f"in index={test_index} (sourcetype={test_sourcetype})"
                    )
            else:
                save_result(conn, "syslog_relay", "e2e_receive", "fail",
                            f"Search failed: HTTP {response.status_code}")
                issues.append(
                    f"[WARNING] Syslog Relay: E2E search failed - HTTP {response.status_code}"
                )
        except requests.exceptions.Timeout:
            save_result(conn, "syslog_relay", "e2e_receive", "fail", "Search timeout")
            issues.append("[WARNING] Syslog Relay: E2E search timeout")
        except Exception as e:
            save_result(conn, "syslog_relay", "e2e_receive", "fail", str(e)[:100])
            issues.append(f"[WARNING] Syslog Relay: E2E search error - {str(e)[:100]}")

    return issues


def check_ti_mirror(conn, ip):
    issues = []

    if not ping_host(ip):
        save_result(conn, "ti_mirror", "ping", "fail", f"Ping to {ip} failed")
        return [f"[CRITICAL] TI Mirror ({ip}): Ping failed"]
    save_result(conn, "ti_mirror", "ping", "ok", f"Ping to {ip} OK")

    ssh_port = config.getint('network', 'ssh_port')
    if not check_tcp_port(ip, ssh_port):
        save_result(conn, "ti_mirror", "port_ssh", "fail", f"TCP {ssh_port} closed")
        issues.append(f"[CRITICAL] TI Mirror: SSH port {ssh_port} closed")
        return issues
    save_result(conn, "ti_mirror", "port_ssh", "ok", f"TCP {ssh_port} open")

    host = config.get('splunk', 'ti_host')
    user = config.get('splunk', 'ti_user')
    password = config.get('splunk', 'ti_pass', fallback='')

    # ────────────────────────────────────────────────────────
    # 1. Disk usage
    # ────────────────────────────────────────────────────────
    ok, out, err = ssh_exec(host, ssh_port, user, password,
                            "df -h / | tail -1 | awk '{print $5}'")
    if not ok:
        save_result(conn, "ti_mirror", "disk", "fail", f"SSH failed: {err}")
        issues.append(f"[CRITICAL] TI Mirror: Cannot check disk - {err[:100]}")
    elif out.strip():
        usage_str = out.strip().replace('%', '')
        try:
            usage = int(usage_str)
            if usage >= DISK_CRIT:
                save_result(conn, "ti_mirror", "disk", "fail", f"Disk usage {usage}%")
                issues.append(f"[CRITICAL] TI Mirror: Disk usage critical ({usage}%)")
            elif usage >= DISK_WARN:
                save_result(conn, "ti_mirror", "disk", "warn", f"Disk usage {usage}%")
                issues.append(f"[WARNING] TI Mirror: Disk usage high ({usage}%)")
            else:
                save_result(conn, "ti_mirror", "disk", "ok", f"Disk usage {usage}%")
        except ValueError:
            pass

    # ────────────────────────────────────────────────────────
    # 2. Logrotate — based on recent .gz file creation
    # ────────────────────────────────────────────────────────
    ok, out, err = ssh_exec(
        host, ssh_port, user, password,
        "find /var/log -maxdepth 1 -name 'ti-mirror*.gz' -ctime -2 2>/dev/null | wc -l"
    )
    if not ok:
        save_result(conn, "ti_mirror", "logrotate", "fail", f"SSH failed: {err}")
        issues.append(f"[WARNING] TI Mirror: Cannot check logrotate - {err[:100]}")
    else:
        try:
            count = int(out.strip())
            if count > 0:
                save_result(conn, "ti_mirror", "logrotate", "ok",
                            f"{count} recently rotated file(s)")
            else:
                save_result(conn, "ti_mirror", "logrotate", "warn",
                            "No recent rotated files")
                issues.append(
                    "[WARNING] TI Mirror: Log rotation may not be working "
                    "(no .gz in 2 days)"
                )
        except ValueError:
            save_result(conn, "ti_mirror", "logrotate", "unknown", out)

    # ────────────────────────────────────────────────────────
    # 3. Load average
    # ────────────────────────────────────────────────────────
    ok, out, err = ssh_exec(host, ssh_port, user, password,
                            "cat /proc/loadavg | awk '{print $1}'")
    if not ok:
        save_result(conn, "ti_mirror", "loadavg", "fail", f"SSH failed: {err}")
    elif out.strip():
        try:
            load = float(out.strip())
            if load > LOADAVG_WARN:
                save_result(conn, "ti_mirror", "loadavg", "warn", f"Load average {load}")
                issues.append(f"[WARNING] TI Mirror: High load average ({load})")
            else:
                save_result(conn, "ti_mirror", "loadavg", "ok", f"Load average {load}")
        except ValueError:
            pass

    # ────────────────────────────────────────────────────────
    # 4. Nginx service
    # ────────────────────────────────────────────────────────
    ok, out, err = ssh_exec(host, ssh_port, user, password,
                            "systemctl is-active nginx")
    if not ok:
        save_result(conn, "ti_mirror", "nginx_service", "fail", f"SSH failed: {err}")
        issues.append(f"[CRITICAL] TI Mirror: Cannot check nginx - {err[:100]}")
    elif out.strip() == "active":
        save_result(conn, "ti_mirror", "nginx_service", "ok", "nginx active")
    else:
        save_result(conn, "ti_mirror", "nginx_service", "fail", f"not active: {out}")
        issues.append("[CRITICAL] TI Mirror: nginx service is not active")

    # ────────────────────────────────────────────────────────
    # 5. Cron service
    # ────────────────────────────────────────────────────────
    ok, out, err = ssh_exec(host, ssh_port, user, password,
                            "systemctl is-active cron")
    if not ok:
        save_result(conn, "ti_mirror", "cron_service", "fail", f"SSH failed: {err}")
        issues.append(f"[WARNING] TI Mirror: Cannot check cron - {err[:100]}")
    elif out.strip() == "active":
        save_result(conn, "ti_mirror", "cron_service", "ok", "cron active")
    else:
        save_result(conn, "ti_mirror", "cron_service", "fail", f"not active: {out}")
        issues.append("[CRITICAL] TI Mirror: cron service is not active")

    # ────────────────────────────────────────────────────────
    # 6. Cron entry exists
    # ────────────────────────────────────────────────────────
    ok, out, err = ssh_exec(host, ssh_port, user, password,
                            "sudo crontab -l 2>/dev/null | grep -c 'update_feeds.py' || echo 0")
    if ok:
        try:
            count = int(out.strip())
            if count > 0:
                save_result(conn, "ti_mirror", "cron_entry", "ok",
                            f"{count} cron entry for update_feeds")
            else:
                save_result(conn, "ti_mirror", "cron_entry", "fail",
                            "No cron entry for update_feeds.py")
                issues.append("[CRITICAL] TI Mirror: No cron entry for update_feeds.py")
        except ValueError:
            pass


    # ────────────────────────────────────────────────────────
    # 7. Metadata: last_run age + ok_count + error_count
    # ────────────────────────────────────────────────────────
    ok, out, err = ssh_exec(host, ssh_port, user, password,
                            "cat /var/www/html/feeds/_metadata.json 2>/dev/null")
    if not ok or not out.strip():
        save_result(conn, "ti_mirror", "metadata", "fail",
                    "Cannot read _metadata.json")
        issues.append("[CRITICAL] TI Mirror: Cannot read _metadata.json")
    else:
        try:
            meta = json.loads(out)
            last_run_str = meta.get("last_run", "")
            ok_count = meta.get("ok_count", 0)
            error_count = meta.get("error_count", 0)

            # last_run age
            if last_run_str:
                try:
                    last_run = datetime.strptime(last_run_str, "%Y-%m-%dT%H:%M:%SZ")
                    last_run = last_run.replace(tzinfo=timezone.utc)
                    now_utc = datetime.now(timezone.utc)
                    age_hours = (now_utc - last_run).total_seconds() / 3600

                    if age_hours > 12:
                        save_result(conn, "ti_mirror", "metadata_age", "fail",
                                    f"Last run {age_hours:.1f}h ago")
                        issues.append(
                            f"[CRITICAL] TI Mirror: Last feed update was "
                            f"{age_hours:.1f}h ago (>12h)"
                        )
                    elif age_hours > 8:
                        save_result(conn, "ti_mirror", "metadata_age", "warn",
                                    f"Last run {age_hours:.1f}h ago")
                        issues.append(
                            f"[WARNING] TI Mirror: Last feed update was "
                            f"{age_hours:.1f}h ago (>8h)"
                        )
                    else:
                        save_result(conn, "ti_mirror", "metadata_age", "ok",
                                    f"Last run {age_hours:.1f}h ago")
                except ValueError:
                    save_result(conn, "ti_mirror", "metadata_age", "unknown",
                                f"Cannot parse last_run: {last_run_str}")
            else:
                save_result(conn, "ti_mirror", "metadata_age", "fail",
                            "No last_run in metadata")
                issues.append("[CRITICAL] TI Mirror: No last_run in metadata")

            # ok_count vs error_count
            if error_count > 0:
                # Extract names of failed feeds
                failed_feeds = [
                    f.get("name", "?")
                    for f in meta.get("feeds", [])
                    if f.get("status") == "error"
                ]

                # Filter out intentionally disabled feeds
                ignored_feeds = ["feodo", "urlhaus", "ipsum_l4", "binary_defense", "sslbl_ssl", "malwarebazaar_hash"]
                active_failures = [f for f in failed_feeds if f not in ignored_feeds]

                if active_failures:
                    failed_str = ", ".join(active_failures[:5])
                    save_result(conn, "ti_mirror", "feed_status", "warn",
                                f"{ok_count} ok, {len(active_failures)} error: {failed_str}")
                    issues.append(
                        f"[WARNING] TI Mirror: {len(active_failures)} feeds failed: {failed_str}"
                    )
                else:
                    save_result(conn, "ti_mirror", "feed_status", "ok",
                                f"{ok_count} feeds ok (some ignored)")
            else:
                save_result(conn, "ti_mirror", "feed_status", "ok",
                            f"{ok_count} feeds ok")
        except json.JSONDecodeError:
            save_result(conn, "ti_mirror", "metadata", "fail",
                        "Invalid JSON in _metadata.json")
            issues.append("[CRITICAL] TI Mirror: Invalid JSON in _metadata.json")

    # ────────────────────────────────────────────────────────
    # 8. Feed directory size
    # ────────────────────────────────────────────────────────
    ok, out, err = ssh_exec(host, ssh_port, user, password,
                            "du -sm /var/www/html/feeds/ 2>/dev/null | awk '{print $1}'")
    if ok and out.strip():
        try:
            size_mb = int(out.strip())
            if size_mb >= 1024:
                save_result(conn, "ti_mirror", "feeds_size", "fail",
                            f"Feeds dir is {size_mb} MB")
                issues.append(f"[CRITICAL] TI Mirror: Feeds directory is {size_mb} MB (>1GB)")
            elif size_mb >= 500:
                save_result(conn, "ti_mirror", "feeds_size", "warn",
                            f"Feeds dir is {size_mb} MB")
                issues.append(f"[WARNING] TI Mirror: Feeds directory is {size_mb} MB (>500MB)")
            else:
                save_result(conn, "ti_mirror", "feeds_size", "ok",
                            f"Feeds dir is {size_mb} MB")
        except ValueError:
            pass

    # ────────────────────────────────────────────────────────
    # 9. Feed file count
    # ────────────────────────────────────────────────────────
    ok, out, err = ssh_exec(host, ssh_port, user, password,
                            "find /var/www/html/feeds -maxdepth 1 -type f "
                            "\\( -name '*.txt' -o -name '*.csv' -o -name '*.json' \\) "
                            "| wc -l")
    if ok and out.strip():
        try:
            count = int(out.strip())
            if count < 15:
                save_result(conn, "ti_mirror", "feed_count", "warn",
                            f"Only {count} feed files")
                issues.append(
                    f"[WARNING] TI Mirror: Only {count} feed files (expected ≥15)"
                )
            else:
                save_result(conn, "ti_mirror", "feed_count", "ok",
                            f"{count} feed files")
        except ValueError:
            pass

    # ────────────────────────────────────────────────────────
    # 10. Age of key feed files (excluding disabled feeds)
    # ────────────────────────────────────────────────────────
    IGNORED_FEEDS = ["feodo.csv", "urlhaus.txt", "malwarebazaar_sha256.txt", "ipsum_l4.txt", "binary_defense.txt", "sslbl_certs.csv"]

    active_feeds = [f for f in ["feodo.csv", "afta_ip.txt", "urlhaus.txt", "malwarebazaar_sha256.txt"] if f not in IGNORED_FEEDS]

    if active_feeds:
        feed_list = " ".join(active_feeds)
        ok, out, err = ssh_exec(
            host, ssh_port, user, password,
            f"for f in {feed_list}; do "
            " p=\"/var/www/html/feeds/$f\"; "
            " if [ -f \"$p\" ]; then "
            " echo \"$f:$(stat -c %Y \"$p\")\"; "
            " else "
            " echo \"$f:MISSING\"; "
            " fi; "
            "done"
        )
        if ok and out.strip():
            now_ts = datetime.now().timestamp()
            for line in out.strip().split("\n"):
                if ":" not in line:
                    continue
                fname, val = line.split(":", 1)
                if val == "MISSING":
                    save_result(conn, "ti_mirror", f"feed_{fname}", "fail",
                                "File missing")
                    issues.append(f"[WARNING] TI Mirror: Feed file missing: {fname}")
                    continue
                try:
                    mtime = int(val)
                    age_h = (now_ts - mtime) / 3600
                    if age_h > 12:
                        save_result(conn, "ti_mirror", f"feed_{fname}", "fail",
                                    f"{age_h:.1f}h old")
                        issues.append(
                            f"[WARNING] TI Mirror: Feed {fname} is {age_h:.1f}h old"
                        )
                    elif age_h > 8:
                        save_result(conn, "ti_mirror", f"feed_{fname}", "warn",
                                    f"{age_h:.1f}h old")
                    else:
                        save_result(conn, "ti_mirror", f"feed_{fname}", "ok",
                                    f"{age_h:.1f}h old")
                except ValueError:
                    pass


    # ────────────────────────────────────────────────────────
    # 11. Recent errors in ti-mirror.log (last 24h)
    # ────────────────────────────────────────────────────────
    ok, out, err = ssh_exec(
        host, ssh_port, user, password,
        "find /var/log/ti-mirror.log -mtime -1 2>/dev/null | "
        "xargs -r grep -c 'ERROR\\|FAILED' 2>/dev/null || echo 0"
    )
    if ok:
        try:
            err_count = int(out.strip())
            if err_count > 0:
                save_result(conn, "ti_mirror", "log_errors", "warn",
                            f"{err_count} errors in last 24h")
                issues.append(
                    f"[WARNING] TI Mirror: {err_count} ERROR/FAILED entries "
                    f"in ti-mirror.log (last 24h)"
                )
            else:
                save_result(conn, "ti_mirror", "log_errors", "ok",
                            "No recent errors")
        except ValueError:
            pass

    return issues

def check_watchdog_self(conn):
    issues = []

    try:
        result = subprocess.run(["df", "-h", "/opt/splunk-watchdog"],
                                capture_output=True, text=True, timeout=5)
        lines = result.stdout.strip().split("\n")
        if len(lines) >= 2:
            parts = lines[1].split()
            usage_str = parts[4].replace('%', '')
            usage = int(usage_str)
            if usage >= WD_DISK_CRIT:
                save_result(conn, "watchdog", "disk", "fail", f"Disk usage {usage}%")
                issues.append(f"[CRITICAL] Watchdog: Own disk usage critical ({usage}%)")
            elif usage >= WD_DISK_WARN:
                save_result(conn, "watchdog", "disk", "warn", f"Disk usage {usage}%")
                issues.append(f"[WARNING] Watchdog: Own disk usage high ({usage}%)")
            else:
                save_result(conn, "watchdog", "disk", "ok", f"Disk usage {usage}%")
    except Exception as e:
        save_result(conn, "watchdog", "disk", "unknown", str(e)[:100])

    try:
        db_path = config.get('general', 'db_path')
        db_size_mb = os.path.getsize(db_path) / (1024 * 1024)
        if db_size_mb > 1000:
            save_result(conn, "watchdog", "db_size", "warn", f"DB size {db_size_mb:.1f} MB")
            issues.append(f"[WARNING] Watchdog: Database size is large ({db_size_mb:.1f} MB)")
        else:
            save_result(conn, "watchdog", "db_size", "ok", f"DB size {db_size_mb:.1f} MB")
    except Exception as e:
        save_result(conn, "watchdog", "db_size", "unknown", str(e)[:100])

    return issues


# ============================================================
# Main
# ============================================================

def main():
    logging.info("=" * 60)
    logging.info("Starting health check cycle")

    conn = init_db()
    all_issues = []

    checks = [
        ("search_head",  config.get('network', 'sh_ip'),    check_search_head),
        ("indexer",      config.get('network', 'idx_ip'),   check_indexer),
        ("syslog_relay", config.get('network', 'relay_ip'), check_syslog_relay),
        ("ti_mirror",    config.get('network', 'ti_ip'),    check_ti_mirror),
    ]

    for name, ip, func in checks:
        try:
            issues = func(conn, ip)
            all_issues.extend(issues)
        except Exception as e:
            logging.exception(f"Error checking {name}: {e}")
            all_issues.append(f"[CRITICAL] {name}: Internal error - {str(e)[:100]}")

    # ES check (only on Search Head)
    try:
        es_issues = check_es(conn)
        all_issues.extend(es_issues)
    except Exception as e:
        logging.exception(f"Error checking ES: {e}")
        all_issues.append(f"[CRITICAL] ES: Internal error - {str(e)[:100]}")

    # Watchdog self-check
    try:
        self_issues = check_watchdog_self(conn)
        all_issues.extend(self_issues)
    except Exception as e:
        logging.exception(f"Error in watchdog self-check: {e}")

    if all_issues:
        severity = "critical" if any("[CRITICAL]" in i for i in all_issues) else "warning"
        message = "\n".join(all_issues)
        logging.warning(f"Sending alert with {len(all_issues)} issues (severity={severity})")
        send_webhook(message, severity=severity)
    else:
        logging.info("All health checks passed")

    try:
        if should_send_heartbeat():
            logging.info("Heartbeat interval reached, sending heartbeat")
            send_heartbeat(conn, all_issues)
        else:
            logging.debug("Heartbeat not due yet")
    except Exception as e:
        logging.exception(f"Error sending heartbeat: {e}")

    conn.close()
    logging.info("Health check cycle completed")
    logging.info("=" * 60)


if __name__ == "__main__":
    main()

