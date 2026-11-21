# Runbook: Splunk Watchdog — Health Monitoring Service

**Version:** 1.0
**Last Updated:** 2026-10-14
**Environment:** Ubuntu 24.04 LTS, Splunk Enterprise 10.4.4, Splunk ES 8.6.1
**Author:** Splunk Operations Team

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Components](#3-components)
4. [Prerequisites](#4-prerequisites)
5. [Installation](#5-installation)
6. [Configuration](#6-configuration)
7. [Health Checks Reference](#7-health-checks-reference)
8. [Alerting & Notifications](#8-alerting--notifications)
9. [Self-Monitoring](#9-self-monitoring)
10. [Heartbeat](#10-heartbeat)
11. [Database Management](#11-database-management)
12. [Security](#12-security)
13. [Operations](#13-operations)
14. [Troubleshooting](#14-troubleshooting)
15. [Appendices](#15-appendices)

---

## 1. Overview

### 1.1 Purpose

The **Splunk Watchdog** is an external health monitoring service that continuously verifies the health and availability of the Splunk stack. It runs on a dedicated lightweight Linux VM and operates independently of the Splunk infrastructure it monitors.

### 1.2 Scope

The Watchdog monitors the following components:

| Component | Hostname | IP | Role |
|---|---|---|---|
| Search Head | `splunkweb.example.local` | `10.0.0.20` | Search, ES, KV Store |
| Indexer | `splunk.example.local` | `10.0.0.10` | Indexing, S2S receiving |
| Syslog Relay | `syslog.example.local` | `10.0.0.227` | Syslog collection, UF forwarding |
| TI Mirror | `ti.example.local` | `10.0.0.50` | Threat Intelligence feed mirror |
| Watchdog | `watchdog.example.local` | TBD | Health monitoring |

### 1.3 Key Features

- **68+ health checks** per 5-minute cycle
- **End-to-End Syslog verification** (probe → index confirmation)
- **Self-monitoring** every 30 minutes
- **Heartbeat** notification every 1 hour
- **Alert throttling** (15 minutes per severity)
- **SQLite storage** with 90-day retention
- **Bale messenger** integration for alerts
- **SSH Key** authentication for Syslog Relay and TI Mirror
- **Token-based** authentication for Splunk REST API

---

## 2. Architecture

### 2.1 High-Level Diagram

```
┌───────────────────────────────────────────────────────────────────────┐
│                          Splunk Stack                                 │
│                                                                       │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐               │
│  │ Search Head  │   │   Indexer    │   │ Syslog Relay │               │
│  │  (with ES)   │   │              │   │              │               │
│  │  .0.0.20     │   │  .0.0.10     │   │  .0.0.227    │               │
│  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘               │
│         │                  │                  │                       │
│         │ REST API         │ REST API         │ SSH                   │
│         │ (Token)          │ (Token)          │ (Key)                 │
│         │                  │                  │                       │
│  ┌──────┴──────────────────┴──────────────────┴───────┐               │
│  │                                                     │               │
│  │              Watchdog VM (.0.0.40)                  │               │
│  │                                                     │               │
│  │  ┌────────────────┐   ┌────────────────┐            │               │
│  │  │ health_check.py│   │ self_monitor.py│            │               │
│  │  │ (every 5 min)  │   │ (every 30 min) │            │               │
│  │  └────────┬───────┘   └────────┬───────┘            │               │
│  │           │                    │                    │               │
│  │           ▼                    ▼                    │               │
│  │  ┌──────────────────────────────────────┐           │               │
│  │  │         SQLite Database              │           │               │
│  │  │    /opt/splunk-watchdog/db/health.db │           │               │
│  │  └──────────────────────────────────────┘           │               │
│  │           │                                         │               │
│  │           ▼                                         │               │
│  │  ┌──────────────────────────────────────┐           │               │
│  │  │    Webhook → Bale Messenger          │           │               │
│  │  └──────────────────────────────────────┘           │               │
│  └─────────────────────────────────────────────────────┘               │
│                                                                       │
│  ┌──────────────┐                                                     │
│  │ TI Mirror    │◄──── SSH (Key) ─────────────────────────────────────┤
│  │  .0.0.50     │                                                     │
│  └──────────────┘                                                     │
└───────────────────────────────────────────────────────────────────────┘
```

### 2.2 Data Flow

1. **Every 5 minutes:** `health_check.py` runs via systemd timer
2. **Every 30 minutes:** `self_monitor.py` runs via systemd timer
3. **Every hour:** Heartbeat is sent to Bale
4. **Daily:** `cleanup_db.sh` removes records older than 90 days

### 2.3 Notification Flow

```
Watchdog → Webhook (Bale API) → Bale Group
```

- **Alerts:** Only when issues are detected (with 15-minute throttling)
- **Heartbeat:** Every hour (regardless of status)
- **Self-Monitoring Alerts:** Only when Watchdog itself has issues

---

## 3. Components

### 3.1 Directory Structure

```
/opt/splunk-watchdog/
├── config/
│   └── watchdog.ini                    (600 root:root)
├── scripts/
│   ├── health_check.py                 (755 root:root)
│   ├── self_monitor.py                 (755 root:root)
│   └── cleanup_db.sh                   (755 root:root)
├── db/
│   ├── health.db                       (SQLite database)
│   ├── .last_alert                     (throttling state)
│   └── .last_heartbeat                 (heartbeat state)
├── logs/
│   └── watchdog.log                    (main log)
└── venv/                               (Python virtual environment)

/root/.ssh/
├── id_ed25519                          (SSH private key)
└── id_ed25519.pub                      (SSH public key)

/etc/systemd/system/
├── splunk-watchdog.service
├── splunk-watchdog.timer
├── splunk-watchdog-selfmon.service
├── splunk-watchdog-selfmon.timer
├── splunk-watchdog-cleanup.service
└── splunk-watchdog-cleanup.timer
```

### 3.2 Systemd Timers

| Timer | Schedule | Purpose |
|---|---|---|
| `splunk-watchdog.timer` | Every 5 minutes | Main health checks |
| `splunk-watchdog-selfmon.timer` | Every 30 minutes | Self-monitoring |
| `splunk-watchdog-cleanup.timer` | Daily at midnight | Database cleanup |

---

## 4. Prerequisites

### 4.1 Watchdog VM

| Item | Value |
|---|---|
| OS | Ubuntu 24.04 LTS |
| CPU | 2 vCPU |
| RAM | 2 GB |
| Disk | 40 GB |
| Hostname | `watchdog.example.local` |
| IP | Static (e.g., `10.0.0.40`) |

### 4.2 Network Requirements

| Source | Destination | Port | Protocol | Purpose |
|---|---|---|---|---|
| Watchdog | Search Head | 8089 | TCP | REST API |
| Watchdog | Search Head | 8000 | TCP | Splunk Web check |
| Watchdog | Indexer | 8089 | TCP | REST API |
| Watchdog | Indexer | 9997 | TCP | S2S port check |
| Watchdog | Syslog Relay | 22 | TCP | SSH |
| Watchdog | Syslog Relay | 514 | UDP | Syslog probe |
| Watchdog | TI Mirror | 22 | TCP | SSH |
| Watchdog | Bale API | 443 | TCP | Webhook |

### 4.3 Splunk Prerequisites

- **Search Head:** Token created for Watchdog (`watchdog-token`)
- **Indexer:** Token created for Watchdog (`watchdog-token`)
- **Indexer:** `watchdog` index created
- **Syslog Relay:** SSH key-based auth configured for user `relayadmin`
- **TI Mirror:** SSH key-based auth configured for user `tiadmin`

---

## 5. Installation

### 5.1 Base System Setup

```bash
# Set hostname
sudo hostnamectl set-hostname watchdog.example.local

# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3 python3-pip python3-venv sqlite3 jq \
                    curl netcat-openbsd iputils-ping

# Create directory structure
sudo mkdir -p /opt/splunk-watchdog/{scripts,logs,db,config}
sudo chown -R $USER:$USER /opt/splunk-watchdog
```

### 5.2 Python Virtual Environment

```bash
cd /opt/splunk-watchdog
python3 -m venv venv
source venv/bin/activate
pip install requests paramiko -i https://pypi.example.com/simple/
deactivate
```

### 5.3 SSH Key Setup

```bash
# Generate SSH key
ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519 -N ""

# Copy to Syslog Relay
ssh-copy-id -i /root/.ssh/id_ed25519.pub relayadmin@10.0.0.227

# Copy to TI Mirror
ssh-copy-id -i /root/.ssh/id_ed25519.pub tiadmin@10.0.0.50

# Test
ssh -i /root/.ssh/id_ed25519 relayadmin@10.0.0.227 "hostname"
ssh -i /root/.ssh/id_ed25519 tiadmin@10.0.0.50 "hostname"
```

### 5.4 Splunk Token Creation

**For Search Head:**

1. Login to Splunk Web (`https://splunkweb.example.local:8000`)
2. Navigate to **Settings > Tokens**
3. Click **New Token**
4. Configure:
   - Name: `watchdog-token-sh`
   - Audience: `watchdog`
   - Expiration: `365 days`
5. Copy the token value

**For Indexer:** Repeat the same steps on `https://splunk.example.local:8000`

### 5.5 Watchdog Index Creation

On the Indexer:

```bash
/opt/splunk/bin/splunk add index watchdog -auth <ADMIN_USER>:<PASSWORD>
```

Verify:

```bash
/opt/splunk/bin/splunk list index -auth <ADMIN_USER>:<PASSWORD> | grep watchdog
```

---

## 6. Configuration

### 6.1 Main Configuration File

**Path:** `/opt/splunk-watchdog/config/watchdog.ini`

```ini
[general]
db_path = /opt/splunk-watchdog/db/health.db
log_path = /opt/splunk-watchdog/logs/watchdog.log

[splunk]
# Splunk Search Head (REST API)
sh_host = splunkweb.example.local
sh_port = 8089
sh_user = <SPLUNK_USER>
sh_token = <TOKEN>

# Splunk Indexer (REST API)
idx_host = splunk.example.local
idx_port = 8089
idx_user = <SPLUNK_USER>
idx_token = <TOKEN>

# Syslog Relay (SSH)
relay_host = syslog.example.local
relay_user = relayadmin

# TI Mirror (SSH)
ti_host = ti.example.local
ti_user = tiadmin

[e2e]
probe_marker = watchdog_e2e_probe
test_index = watchdog
test_sourcetype = watchdog:e2e
search_delay = 30
max_event_age = 300

[network]
# Ping targets
sh_ip = 10.0.0.20
idx_ip = 10.0.0.10
relay_ip = 10.0.0.227
ti_ip = 10.0.0.50

# Ports
splunk_web_port = 8000
splunk_mgmt_port = 8089
splunk_s2s_port = 9997
syslog_udp_port = 514
ssh_port = 22

[ssh]
key_path = /root/.ssh/id_ed25519

[thresholds]
# Disk usage
disk_warn = 80
disk_crit = 90

# Indexer queues
queue_warn = 70
queue_crit = 90

# Load average
loadavg_warn = 8.0

# Watchdog self-monitoring
watchdog_disk_warn = 80
watchdog_disk_crit = 90

[heartbeat]
enabled = true
interval_seconds = 3600
state_file = /opt/splunk-watchdog/db/.last_heartbeat

[webhook]
url = https://tapi.bale.ai/bot<TOKEN>/sendMessage?chat_id=<CHAT_ID>&text=$result.bale$
```

### 6.2 File Permissions

```bash
sudo chmod 600 /opt/splunk-watchdog/config/watchdog.ini
sudo chmod 755 /opt/splunk-watchdog/scripts/health_check.py
sudo chmod 755 /opt/splunk-watchdog/scripts/self_monitor.py
sudo chmod 755 /opt/splunk-watchdog/scripts/cleanup_db.sh
```

---

## 7. Health Checks Reference

### 7.1 Search Head Checks (9)

| # | Check | Method | Threshold | Severity |
|---|---|---|---|---|
| 1 | Ping | ICMP | Failure | CRITICAL |
| 2 | Management port (8089) | TCP | Closed | WARNING |
| 3 | Splunk Web (8000) | TCP | Closed | WARNING |
| 4 | splunkd health | REST API | Error | CRITICAL |
| 5 | KV Store | REST API | Disabled/Migration | CRITICAL/WARN |
| 6 | Search Peers | REST API | Down peer | CRITICAL |
| 7 | Search Scheduler | REST API | Disabled | CRITICAL |
| 8 | Disk usage (`/`) | REST API | >80% / >90% | WARN/CRIT |
| 9 | Search Jobs | REST API | >50 running | WARNING |

### 7.2 Indexer Checks (24)

| # | Check | Method | Threshold | Severity |
|---|---|---|---|---|
| 1 | Ping | ICMP | Failure | CRITICAL |
| 2 | Management port (8089) | TCP | Closed | WARNING |
| 3 | S2S port (9997) | TCP | Closed | WARNING |
| 4 | splunkd health | REST API | Error | CRITICAL |
| 5 | Introspection | REST API | status ≠ normal | WARNING |
| 6 | Ingestion rate | REST API | <1 KB/s | WARNING |
| 7 | Disk usage (`/opt`) | REST API | >80% / >90% | WARN/CRIT |
| 8 | Index count | REST API | <10 | WARNING |
| 9 | License daily usage | SPL | (report only) | - |
| 10-23 | Queue fill % (14 queues) | SPL | >70% / >90% | WARN/CRIT |
| 24 | Indexer queue overall | REST API | (report only) | - |

**Monitored queues:**
`aggQueue`, `auditQueue`, `execProcessorInternalQ`, `fschangemanager_queue`, `indexQueue`, `nullQueue`, `parsingQueue`, `rulesetQueue`, `splunktcpin`, `stashparsing`, `structuredparsingqueue`, `tcpin_queue`, `tcpout_default-autolb-group`, `typingQueue`

### 7.3 Enterprise Security Checks (5)

| # | Check | Method | Threshold | Severity |
|---|---|---|---|---|
| 1 | ES Apps | REST API | Any disabled (except ignored) | WARNING |
| 2 | Correlation Searches | SPL | None found | WARNING |
| 3 | Threat Intel Downloads (24h) | SPL | Any errors | WARNING |
| 4 | Threat Intel Age | SPL | >10h / >14h | WARN/CRIT |
| 5 | Notable Events (24h) | SPL | (report only) | - |

**Ignored apps:** `UEBA`, `SA-UEBA`, `DA-ESS-UEBA`

### 7.4 Syslog Relay Checks (11)

| # | Check | Method | Threshold | Severity |
|---|---|---|---|---|
| 1 | Ping | ICMP | Failure | CRITICAL |
| 2 | SSH port (22) | TCP | Closed | CRITICAL |
| 3 | UDP port (514) | UDP | Unreachable | WARNING |
| 4 | rsyslog service | SSH | Not active | CRITICAL |
| 5 | Port 514 listener | SSH | Not listening | WARNING |
| 6 | Disk usage | SSH | >80% / >90% | WARN/CRIT |
| 7 | Logrotate | SSH | No `.gz` in 2 days | WARNING |
| 8 | UF service | SSH | Not active | CRITICAL |
| 9 | UDP send test | UDP | Failure | WARNING |
| 10 | E2E send | UDP | Failure | WARNING |
| 11 | E2E receive | REST API | Not found in index | CRITICAL |

### 7.5 TI Mirror Checks (17)

| # | Check | Method | Threshold | Severity |
|---|---|---|---|---|
| 1 | Ping | ICMP | Failure | CRITICAL |
| 2 | SSH port (22) | TCP | Closed | CRITICAL |
| 3 | Disk usage | SSH | >80% / >90% | WARN/CRIT |
| 4 | Logrotate | SSH | No `.gz` in 2 days | WARNING |
| 5 | Load average | SSH | >8.0 | WARNING |
| 6 | Nginx service | SSH | Not active | CRITICAL |
| 7 | Cron service | SSH | Not active | CRITICAL |
| 8 | Cron entry | SSH | Missing | CRITICAL |
| 9 | Metadata age | SSH | >8h / >12h | WARN/CRIT |
| 10 | Feed status | SSH | error_count > 0 | WARNING |
| 11 | Feeds dir size | SSH | >500MB / >1GB | WARN/CRIT |
| 12 | Feed count | SSH | <15 | WARNING |
| 13-16 | Feed age (4 key files) | SSH | >8h / >12h | WARN/CRIT |
| 17 | Log errors (24h) | SSH | Any errors | WARNING |

**Key feeds monitored:** `feodo.csv`, `afta_ip.txt`, `urlhaus.txt`, `malwarebazaar_sha256.txt`

### 7.6 Watchdog Self-Checks (2)

| # | Check | Method | Threshold | Severity |
|---|---|---|---|---|
| 1 | Disk usage | OS | >80% / >90% | WARN/CRIT |
| 2 | Database size | OS | >1000 MB | WARNING |

---

## 8. Alerting & Notifications

### 8.1 Alert Severity Levels

| Level | Prefix | Trigger |
|---|---|---|
| CRITICAL | `[CRITICAL]` | Service down, disk critical, auth failure |
| WARNING | `[WARNING]` | Disk high, queue high, delayed feeds |
| INFO | `[INFO]` | Heartbeat, informational |

### 8.2 Alert Throttling

- **Throttle window:** 15 minutes per severity
- **State file:** `/opt/splunk-watchdog/db/.last_alert`
- **Behavior:** If a `CRITICAL` alert was sent in the last 15 minutes, subsequent `CRITICAL` alerts are suppressed

**Manual reset:**

```bash
rm -f /opt/splunk-watchdog/db/.last_alert
```

### 8.3 Webhook Format (Bale Messenger)

**Alert message:**

```
*[CRITICAL] Splunk Watchdog Alert*

[CRITICAL] Search Head: splunkd health failed - HTTP 401
[WARNING] Indexer: Queue parsingQueue at 75%
```

**Heartbeat message:**

```
*[HEARTBEAT] Splunk Watchdog Alive*

Heartbeat: All systems OK
Time: 2026-10-14 12:57:05
Components checked: 4
Checks per cycle: 68+
```

### 8.4 Testing Webhook

```bash
cd /opt/splunk-watchdog
source venv/bin/activate

python3 << 'EOF'
import importlib.util
spec = importlib.util.spec_from_file_location("hc", "/opt/splunk-watchdog/scripts/health_check.py")
hc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hc)

hc.send_webhook(
    "Test message from Watchdog",
    severity="info",
    force=True
)
print("Test webhook sent. Check Bale.")
EOF
```

---

## 9. Self-Monitoring

### 9.1 Purpose

The Self-Monitoring script verifies that the Watchdog itself is functioning correctly. It runs every 30 minutes and checks:

| # | Check | Threshold |
|---|---|---|
| 1 | Systemd timer active | `active` |
| 2 | Last health check run | <15 minutes ago |
| 3 | Heartbeat file freshness | <90 minutes ago |
| 4 | Recent DB records | <15 minutes ago |
| 5 | Main script exists and executable | - |
| 6 | Watchdog disk usage | >80% / >90% |
| 7 | Failed systemd units | None |

### 9.2 Self-Monitoring Alerts

When Self-Monitoring detects a problem, it sends an alert to Bale with prefix:

```
*[CRITICAL] [SELF-MONITOR] Watchdog Problem*

Watchdog self-monitoring detected problems:

[CRITICAL] Systemd timer active: Timer status: inactive
```

**Note:** Self-Monitoring has **no throttling** — it sends an alert every 30 minutes until the issue is resolved.

### 9.3 Testing Self-Monitoring

```bash
cd /opt/splunk-watchdog
source venv/bin/activate
python3 scripts/self_monitor.py

grep "selfmon" /opt/splunk-watchdog/logs/watchdog.log | tail -20
```

### 9.4 Simulating Failure

To test Self-Monitoring:

```bash
# Stop the main timer
sudo systemctl stop splunk-watchdog.timer

# Run self-monitor manually
python3 scripts/self_monitor.py

# Check the alert was sent
# Restore the timer
sudo systemctl start splunk-watchdog.timer
```

---

## 10. Heartbeat

### 10.1 Purpose

The Heartbeat is a periodic "I'm alive" message sent to Bale every hour. If the Heartbeat stops arriving, it indicates a serious problem with the Watchdog.

### 10.2 Configuration

```ini
[heartbeat]
enabled = true
interval_seconds = 3600
state_file = /opt/splunk-watchdog/db/.last_heartbeat
```

### 10.3 Heartbeat State

The heartbeat state is stored in `/opt/splunk-watchdog/db/.last_heartbeat`:

```bash
cat /opt/splunk-watchdog/db/.last_heartbeat
# Output: 2026-10-14T12:57:05.233361
```

**Manual reset:**

```bash
rm -f /opt/splunk-watchdog/db/.last_heartbeat
```

---

## 11. Database Management

### 11.1 Database Schema

**Table: `health_checks`**

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER | Primary key |
| `timestamp` | TEXT | ISO 8601 timestamp |
| `component` | TEXT | Component name |
| `check_type` | TEXT | Check type |
| `status` | TEXT | `ok`, `warn`, `fail`, `unknown` |
| `details` | TEXT | Additional details |

**Table: `heartbeat`**

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER | Primary key |
| `timestamp` | TEXT | ISO 8601 timestamp |
| `status` | TEXT | `OK` or `ISSUES` |
| `details` | TEXT | Heartbeat summary |

### 11.2 Common Queries

**Last 10 failures:**

```sql
SELECT timestamp, component, check_type, details
FROM health_checks
WHERE status IN ('fail', 'warn')
ORDER BY id DESC
LIMIT 10;
```

**Summary of last hour:**

```sql
SELECT component, status, COUNT(*) as cnt
FROM health_checks
WHERE timestamp > datetime('now', '-1 hour')
GROUP BY component, status
ORDER BY component, status;
```

**Component-specific history:**

```sql
SELECT timestamp, check_type, status, details
FROM health_checks
WHERE component = 'indexer'
  AND timestamp > datetime('now', '-1 day')
ORDER BY id DESC;
```

### 11.3 Retention Policy

- **Retention:** 90 days
- **Cleanup:** Daily at midnight via `splunk-watchdog-cleanup.timer`

**Manual cleanup:**

```bash
/opt/splunk-watchdog/scripts/cleanup_db.sh
```

**Manual cleanup with custom retention:**

```bash
sqlite3 /opt/splunk-watchdog/db/health.db "
DELETE FROM health_checks
WHERE datetime(timestamp) < datetime('now', '-30 days');
"
sqlite3 /opt/splunk-watchdog/db/health.db "VACUUM;"
```

### 11.4 Database Size Monitoring

```bash
ls -lh /opt/splunk-watchdog/db/health.db

# Row counts
sqlite3 /opt/splunk-watchdog/db/health.db "
SELECT
  (SELECT COUNT(*) FROM health_checks) as health_records,
  (SELECT COUNT(*) FROM heartbeat) as heartbeat_records;
"
```

---

## 12. Security

### 12.1 Authentication Methods

| Component | Method | Details |
|---|---|---|
| Search Head | Token | Bearer token via HTTP header |
| Indexer | Token | Bearer token via HTTP header |
| Syslog Relay | SSH Key | Ed25519 key at `/root/.ssh/id_ed25519` |
| TI Mirror | SSH Key | Ed25519 key at `/root/.ssh/id_ed25519` |
| Bale | Webhook URL | Token embedded in URL |

### 12.2 File Permissions

```bash
# Configuration file (contains tokens)
chmod 600 /opt/splunk-watchdog/config/watchdog.ini

# SSH private key
chmod 600 /root/.ssh/id_ed25519

# Scripts (executable by root only)
chmod 755 /opt/splunk-watchdog/scripts/*.py
chmod 755 /opt/splunk-watchdog/scripts/*.sh
```

### 12.3 Token Rotation

**Every 365 days** (or per security policy):

1. Create new token in Splunk Web
2. Update `/opt/splunk-watchdog/config/watchdog.ini`
3. Revoke old token in Splunk Web
4. Test: `python3 /opt/splunk-watchdog/scripts/health_check.py`

### 12.4 SSH Key Rotation

**Every 365 days** (or per security policy):

```bash
# Generate new key
ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519_new -N ""

# Distribute
ssh-copy-id -i /root/.ssh/id_ed25519_new.pub relayadmin@10.0.0.227
ssh-copy-id -i /root/.ssh/id_ed25519_new.pub tiadmin@10.0.0.50

# Test
ssh -i /root/.ssh/id_ed25519_new relayadmin@10.0.0.227 "hostname"

# Replace old key
mv /root/.ssh/id_ed25519_new /root/.ssh/id_ed25519
mv /root/.ssh/id_ed25519_new.pub /root/.ssh/id_ed25519.pub
```

---

## 13. Operations

### 13.1 Daily Operations

**Check timer status:**

```bash
systemctl list-timers --all | grep watchdog
```

**Check recent alerts:**

```bash
sqlite3 /opt/splunk-watchdog/db/health.db "
SELECT timestamp, component, check_type, details
FROM health_checks
WHERE status IN ('fail', 'warn')
  AND timestamp > datetime('now', '-1 day')
ORDER BY id DESC;
"
```

**Check heartbeat:**

```bash
sqlite3 /opt/splunk-watchdog/db/health.db "
SELECT * FROM heartbeat ORDER BY id DESC LIMIT 5;
"
```

### 13.2 Weekly Operations

**Review failures:**

```bash
sqlite3 /opt/splunk-watchdog/db/health.db "
SELECT DATE(timestamp) as day, component, check_type, COUNT(*) as cnt
FROM health_checks
WHERE status IN ('fail', 'warn')
  AND timestamp > datetime('now', '-7 days')
GROUP BY day, component, check_type
ORDER BY day DESC, cnt DESC;
"
```

**Check database size:**

```bash
ls -lh /opt/splunk-watchdog/db/health.db
```

**Review Self-Monitoring logs:**

```bash
grep "selfmon" /opt/splunk-watchdog/logs/watchdog.log | tail -30
```

### 13.3 Monthly Operations

**Rotate logs manually (if needed):**

```bash
sudo logrotate -fv /etc/logrotate.d/splunk-watchdog 2>/dev/null || \
sudo truncate -s 0 /opt/splunk-watchdog/logs/watchdog.log
```

**Review disk usage:**

```bash
df -h /opt/splunk-watchdog
du -sh /opt/splunk-watchdog/*
```

### 13.4 Service Management

```bash
# Main service
sudo systemctl status splunk-watchdog.timer
sudo systemctl start splunk-watchdog.timer
sudo systemctl stop splunk-watchdog.timer
sudo systemctl restart splunk-watchdog.timer

# Self-monitoring
sudo systemctl status splunk-watchdog-selfmon.timer
sudo systemctl restart splunk-watchdog-selfmon.timer

# Cleanup
sudo systemctl status splunk-watchdog-cleanup.timer
```

### 13.5 Manual Execution

```bash
cd /opt/splunk-watchdog
source venv/bin/activate

# Run health check
python3 scripts/health_check.py

# Run self-monitor
python3 scripts/self_monitor.py

# Run cleanup
./scripts/cleanup_db.sh
```

---

## 14. Troubleshooting

### 14.1 Common Issues

#### Issue: Alerts not reaching Bale

**Symptoms:** No messages in Bale group

**Diagnosis:**

```bash
grep -E "Webhook|throttled" /opt/splunk-watchdog/logs/watchdog.log | tail -20
```

**Resolution:**

1. Verify webhook URL in config:
   ```bash
   grep "url" /opt/splunk-watchdog/config/watchdog.ini
   ```

2. Test webhook manually:
   ```bash
   cd /opt/splunk-watchdog
   source venv/bin/activate
   python3 -c "
   import importlib.util
   spec = importlib.util.spec_from_file_location('hc', 'scripts/health_check.py')
   hc = importlib.util.module_from_spec(spec)
   spec.loader.exec_module(hc)
   hc.send_webhook('Test', severity='info', force=True)
   "
   ```

3. Check throttle state:
   ```bash
   cat /opt/splunk-watchdog/db/.last_alert
   rm -f /opt/splunk-watchdog/db/.last_alert
   ```

#### Issue: SSH authentication failing

**Symptoms:** `SSH authentication failed` in logs

**Diagnosis:**

```bash
ssh -i /root/.ssh/id_ed25519 -v tiadmin@10.0.0.50 "hostname"
```

**Resolution:**

1. Verify key exists:
   ```bash
   ls -la /root/.ssh/id_ed25519*
   ```

2. Verify key permissions:
   ```bash
   chmod 600 /root/.ssh/id_ed25519
   ```

3. Re-distribute key:
   ```bash
   ssh-copy-id -i /root/.ssh/id_ed25519.pub tiadmin@10.0.0.50
   ```

4. Check fail2ban on remote host:
   ```bash
   ssh tiadmin@10.0.0.50 "sudo fail2ban-client status sshd"
   ```

#### Issue: HTTP 401/403 from Splunk REST API

**Symptoms:** `HTTP 401` or `HTTP 403` in logs

**Diagnosis:**

```bash
cd /opt/splunk-watchdog
source venv/bin/activate
python3 << 'EOF'
import configparser, requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

config = configparser.ConfigParser(interpolation=None)
config.read('config/watchdog.ini')
host = config.get('splunk', 'sh_host')
port = config.getint('splunk', 'sh_port')
token = config.get('splunk', 'sh_token')

url = f"https://{host}:{port}/services/server/health/splunkd"
headers = {"Authorization": f"Bearer {token}"}
r = requests.get(url, headers=headers, verify=False, timeout=10)
print(f"Status: {r.status_code}")
print(r.text[:200])
EOF
```

**Resolution:**

1. Verify token is correct (not expired)
2. Verify token has correct audience (`watchdog`)
3. Create new token if needed
4. Update `watchdog.ini`

#### Issue: Timer not running

**Symptoms:** No new records in database

**Diagnosis:**

```bash
systemctl status splunk-watchdog.timer
systemctl list-timers --all | grep watchdog
```

**Resolution:**

```bash
sudo systemctl daemon-reload
sudo systemctl restart splunk-watchdog.timer
sudo systemctl enable splunk-watchdog.timer
```

#### Issue: E2E Syslog failing

**Symptoms:** `e2e_receive: fail` in database

**Diagnosis:**

```bash
# Check relay log file
ssh relayadmin@10.0.0.227 "sudo tail -5 /var/log/remote/watchdog/*/*.log"

# Check Splunk index
sqlite3 /opt/splunk-watchdog/db/health.db "
SELECT * FROM health_checks
WHERE check_type = 'e2e_receive'
ORDER BY id DESC LIMIT 5;
"
```

**Resolution:**

1. Verify rsyslog rule on relay:
   ```bash
   ssh relayadmin@10.0.0.227 "sudo cat /etc/rsyslog.d/01-watchdog.conf"
   ```

2. Verify UF monitors the directory:
   ```bash
   ssh relayadmin@10.0.0.227 "sudo /opt/splunkforwarder/bin/splunk list monitor | grep watchdog"
   ```

3. Verify index exists on Indexer
4. Increase `search_delay` in config (e.g., from 30 to 60)

### 14.2 Diagnostic Commands

```bash
# Full health check with output
cd /opt/splunk-watchdog
source venv/bin/activate
python3 scripts/health_check.py

# Check all recent logs
tail -100 /opt/splunk-watchdog/logs/watchdog.log

# Check errors only
grep -E "ERROR|CRITICAL|FAIL" /opt/splunk-watchdog/logs/watchdog.log | tail -30

# Check SSH activity
grep -E "SSH|publickey|password" /opt/splunk-watchdog/logs/watchdog.log | tail -20

# Check Webhook activity
grep -E "Webhook|alert" /opt/splunk-watchdog/logs/watchdog.log | tail -20

# Database integrity
sqlite3 /opt/splunk-watchdog/db/health.db "PRAGMA integrity_check;"
```

### 14.3 Recovery Procedures

#### Full restart of Watchdog

```bash
# Stop all timers
sudo systemctl stop splunk-watchdog.timer
sudo systemctl stop splunk-watchdog-selfmon.timer
sudo systemctl stop splunk-watchdog-cleanup.timer

# Reload systemd
sudo systemctl daemon-reload

# Start all timers
sudo systemctl start splunk-watchdog.timer
sudo systemctl start splunk-watchdog-selfmon.timer
sudo systemctl start splunk-watchdog-cleanup.timer

# Verify
systemctl list-timers --all | grep watchdog
```

#### Reset throttle state

```bash
rm -f /opt/splunk-watchdog/db/.last_alert
```

#### Reset heartbeat state

```bash
rm -f /opt/splunk-watchdog/db/.last_heartbeat
```

#### Rebuild database

```bash
# Backup old database
mv /opt/splunk-watchdog/db/health.db /opt/splunk-watchdog/db/health.db.bak

# Run health check to recreate
cd /opt/splunk-watchdog
source venv/bin/activate
python3 scripts/health_check.py

# Verify
sqlite3 /opt/splunk-watchdog/db/health.db ".tables"
```

---

## 15. Appendices

### Appendix A — Systemd Unit Files

#### A.1 `splunk-watchdog.service`

```ini
[Unit]
Description=Splunk Watchdog Health Check
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/splunk-watchdog
ExecStart=/opt/splunk-watchdog/venv/bin/python3 /opt/splunk-watchdog/scripts/health_check.py
TimeoutStartSec=300
StandardOutput=journal
StandardError=journal
```

#### A.2 `splunk-watchdog.timer`

```ini
[Unit]
Description=Run Splunk Watchdog every 5 minutes

[Timer]
OnCalendar=*-*-* *:0/5:00
Persistent=true
RandomizedDelaySec=30
Unit=splunk-watchdog.service

[Install]
WantedBy=timers.target
```

#### A.3 `splunk-watchdog-selfmon.service`

```ini
[Unit]
Description=Splunk Watchdog Self-Monitoring
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/splunk-watchdog
ExecStart=/opt/splunk-watchdog/venv/bin/python3 /opt/splunk-watchdog/scripts/self_monitor.py
TimeoutStartSec=120
StandardOutput=journal
StandardError=journal
```

#### A.4 `splunk-watchdog-selfmon.timer`

```ini
[Unit]
Description=Run Splunk Watchdog Self-Monitoring every 30 minutes

[Timer]
OnCalendar=*-*-* *:00,30:00
Persistent=true
RandomizedDelaySec=60
Unit=splunk-watchdog-selfmon.service

[Install]
WantedBy=timers.target
```

#### A.5 `splunk-watchdog-cleanup.service`

```ini
[Unit]
Description=Cleanup old health check records

[Service]
Type=oneshot
ExecStart=/opt/splunk-watchdog/scripts/cleanup_db.sh
```

#### A.6 `splunk-watchdog-cleanup.timer`

```ini
[Unit]
Description=Daily cleanup of health check DB

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

### Appendix B — cleanup_db.sh

```bash
#!/bin/bash
# Cleanup old health check records
# Path: /opt/splunk-watchdog/scripts/cleanup_db.sh

DB="/opt/splunk-watchdog/db/health.db"
RETENTION_DAYS=90

sqlite3 "$DB" "DELETE FROM health_checks WHERE datetime(timestamp) < datetime('now', '-${RETENTION_DAYS} days');"
sqlite3 "$DB" "DELETE FROM heartbeat WHERE datetime(timestamp) < datetime('now', '-${RETENTION_DAYS} days');"
sqlite3 "$DB" "VACUUM;"
```

### Appendix C — rsyslog Configuration (Syslog Relay)

**Path:** `/etc/rsyslog.d/01-watchdog.conf`

```conf
# Watchdog E2E probe - global rule, catches messages before any ruleset
if $rawmsg contains 'watchdog_e2e_probe' then {
    $template WatchdogLogs,"/var/log/remote/watchdog/%FROMHOST-IP%/%$year%-%$month%-%$day%-%$hour%.log"
    *.* ?WatchdogLogs
    & stop
}
```

### Appendix D — Splunk UF Configuration (Syslog Relay)

**Path:** `/opt/splunkforwarder/etc/system/local/inputs.conf`

```ini
[monitor:///var/log/remote/watchdog]
disabled = 0
index = watchdog
sourcetype = watchdog:e2e
persistentQueueSize = 256MB
initCrcLength = 2048
whitelist = \.log$
```

### Appendix E — Bale Webhook URL Format

```
https://tapi.bale.ai/bot<TOKEN>/sendMessage?chat_id=<CHAT_ID>&text=$result.bale$
```

**Payload:**

```json
{
  "name": "[CRITICAL] Splunk Watchdog Alert",
  "result": {
    "bale": "URL-encoded message text"
  }
}
```

### Appendix F — Change Log

| Date | Version | Changes | Author |
|---|---|---|---|
| 2026-10-14 | 1.0 | Initial runbook | Ops Team |

### Appendix G — Related Documents

| Document | Location |
|---|---|
| TI-Mirror Runbook | Internal Wiki |
| Splunk ES Configuration Guide | Splunk Docs |
| Bale Messenger API | https://docs.bale.ai |

---

**End of Runbook**