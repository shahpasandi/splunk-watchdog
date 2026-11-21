# Splunk Watchdog

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Ubuntu%2024.04%20LTS-orange.svg)](https://ubuntu.com/)
[![Splunk](https://img.shields.io/badge/Splunk-Enterprise%2010.x-green.svg)](https://www.splunk.com/)

An external, independent health monitoring service for Splunk environments. The Watchdog runs on a dedicated lightweight Linux VM and continuously verifies the health and availability of the Splunk stack it monitors — completely decoupled from the infrastructure it watches.

---

## Overview

**Splunk Watchdog** is an out-of-band monitoring solution that runs **68+ health checks every 5 minutes** against your Splunk deployment and its supporting services. It stores results in a local SQLite database, sends throttled alerts to a webhook (Bale Messenger), and emits an hourly heartbeat so you know the Watchdog itself is alive.

Because it runs **outside** of Splunk, it can detect failures that Splunk's own internal monitoring cannot — including a completely down Search Head, unreachable indexers, broken syslog pipelines, or stale Threat Intelligence feeds.

### What it monitors

| Component | Type | Description |
|---|---|---|
| **Splunk Search Head** | Core | Splunkd health, KV Store, search peers, scheduler, disk, search jobs |
| **Splunk Indexer** | Core | Splunkd health, ingestion rate, queues, disks, indexes, license usage |
| **Splunk Enterprise Security** | Core | ES apps, correlation searches, Threat Intel downloads, notable events |
| **Syslog Relay** | Companion | rsyslog, UF, disk, logrotate, **end-to-end syslog verification** |
| **TI Mirror** | Companion | Nginx, cron, feed freshness, metadata age, feed status |
| **Watchdog itself** | Self | Disk, DB size, timer health, heartbeat freshness |

The **Syslog Relay** and **TI Mirror** components are themselves open-source projects, both of which are monitored by this Watchdog:

- 🔗 [shahpasandi/ti-mirror](https://github.com/shahpasandi/ti-mirror) — Air-gapped Threat Intelligence feed mirror for Splunk ES
- 🔗 [shahpasandi/syslog-relay](https://github.com/shahpasandi/syslog-relay) — Production-grade syslog relay with UF forwarding

> ⚠️ **Roadmap:** The component list is actively growing. The goal is to eventually monitor **the entire Splunk cluster** — including deployment servers, cluster masters, license masters, heavy forwarders, and more. Watch this repository for updates.

---

## Key Features

- ✅ **68+ health checks** per 5-minute cycle, covering 6 component types
- 🔁 **End-to-end syslog verification** — injects a probe, confirms it lands in the index
- 🩺 **Self-monitoring** every 30 minutes (timer, heartbeat, DB freshness, disk, systemd)
- 💓 **Hourly heartbeat** to confirm the Watchdog is alive
- 🔕 **Alert throttling** — 15 minutes per severity, prevents alert storms
- 🗄️ **SQLite storage** with 90-day retention and automatic daily cleanup
- 🔐 **Token-based auth** for Splunk REST API, **SSH key auth** for remote hosts
- 📊 **Fullscreen web dashboard** with Linux user authentication (`/etc/shadow`)
- 🚀 **Systemd timers** — no cron, no daemons, just clean units
- 🧩 **Config-driven** — every threshold, endpoint, and credential in one INI file

---

## Architecture

![Splunk Watchdog Architecture](docs/images/architecture.webp)

*High-level architecture: the Watchdog VM monitors the Splunk stack (Search Head, Indexer) plus the companion Syslog Relay and TI Mirror projects over REST API, SSH, and UDP.*

---

## Repository Structure

```
splunk-watchdog/
├── config/
│   └── watchdog.ini.example          # Sanitized config template
├── scripts/
│   ├── health_check.py               # Main health check engine
│   ├── self_monitor.py               # Watchdog self-monitoring
│   ├── cleanup_db.sh                 # 90-day retention cleanup
│   └── dashboard.py                  # Flask web dashboard
├── systemd/
│   ├── splunk-watchdog.service       # Main check service
│   ├── splunk-watchdog.timer         # Every 5 minutes
│   ├── splunk-watchdog-selfmon.service
│   ├── splunk-watchdog-selfmon.timer # Every 30 minutes
│   ├── splunk-watchdog-cleanup.service
│   ├── splunk-watchdog-cleanup.timer # Daily
│   └── splunk-watchdog-dashboard.service
├── syslog-relay/
│   ├── inputs.conf                   # Splunk UF inputs configuration
│   └── remote.conf.example           # rsyslog routing template
├── docs/
│   ├── RUNBOOK.md                    # Full operations runbook
│   └── images/
│       └── architecture.webp         # Architecture diagram
└── README.md
```

---

## Quick Start

### Prerequisites

- Ubuntu 24.04 LTS VM (2 vCPU, 2 GB RAM, 40 GB disk)
- Network access from Watchdog to Splunk REST API (8089), Splunk Web (8000), S2S (9997), SSH (22), Syslog (514/UDP)
- Splunk REST tokens created for Watchdog (see [docs/RUNBOOK.md](docs/RUNBOOK.md) §5.4)
- SSH key-based auth to Syslog Relay and TI Mirror hosts

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/shahpasandi/splunk-watchdog.git
cd splunk-watchdog

# 2. Run base system setup (see RUNBOOK §5.1)
sudo apt install -y python3 python3-pip python3-venv sqlite3 jq \
                    curl netcat-openbsd iputils-ping

# 3. Create the Python virtual environment
sudo mkdir -p /opt/splunk-watchdog/{scripts,logs,db,config}
sudo cp -r scripts/* /opt/splunk-watchdog/scripts/
cd /opt/splunk-watchdog
python3 -m venv venv
source venv/bin/activate
pip install requests paramiko flask flask-httpauth
deactivate

# 4. Configure
sudo cp config/watchdog.ini.example /opt/splunk-watchdog/config/watchdog.ini
sudo chmod 600 /opt/splunk-watchdog/config/watchdog.ini
sudo nano /opt/splunk-watchdog/config/watchdog.ini   # fill in your values

# 5. Install systemd units
sudo cp systemd/*.service systemd/*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now splunk-watchdog.timer
sudo systemctl enable --now splunk-watchdog-selfmon.timer
sudo systemctl enable --now splunk-watchdog-cleanup.timer
sudo systemctl enable --now splunk-watchdog-dashboard.service

# 6. Verify
systemctl list-timers --all | grep watchdog
```

For full step-by-step instructions, see **[docs/RUNBOOK.md](docs/RUNBOOK.md)**.

---

## Configuration

All configuration lives in a single INI file: `/opt/splunk-watchdog/config/watchdog.ini` (mode `600`).

```ini
[splunk]
sh_host     = splunkweb.example.local
sh_port     = 8089
sh_token    = <YOUR_SH_TOKEN>

idx_host    = splunk.example.local
idx_port    = 8089
idx_token   = <YOUR_IDX_TOKEN>

relay_host  = syslog.example.local
relay_user  = relayadmin

ti_host     = ti.example.local
ti_user     = tiadmin

[network]
sh_ip       = 10.0.0.20
idx_ip      = 10.0.0.10
relay_ip    = 10.0.0.227
ti_ip       = 10.0.0.50

[webhook]
url = https://tapi.bale.ai/bot<TOKEN>/sendMessage?chat_id=<CHAT_ID>&text=$result.bale$
```

Copy `config/watchdog.ini.example` and fill in your own values. **Never commit the real `watchdog.ini`.**

---

## Health Checks at a Glance

| Component | Checks | Notable validations |
|---|---|---|
| Search Head | 9 | KV Store state, search peers, scheduler, disk, active jobs |
| Indexer | 24 | Introspection, ingestion rate, **14 queues**, disks, indexes, license |
| Enterprise Security | 5 | ES apps, correlation searches, **Threat Intel age**, notable events |
| Syslog Relay | 11 | rsyslog, UF, disk, logrotate, **end-to-end syslog probe** |
| TI Mirror | 17 | Nginx, cron, feed freshness, metadata age, feed status |
| Watchdog itself | 2 | Own disk, DB size |

Full reference: **[docs/RUNBOOK.md §7](docs/RUNBOOK.md)**.

---

## Alerting

Alerts are sent to **Bale Messenger** (a popular Iranian messenger) via webhook, with:

- **Severity levels:** `[CRITICAL]`, `[WARNING]`, `[INFO]`
- **Throttling:** 15 minutes per severity (prevents alert storms)
- **Heartbeat:** every 60 minutes, regardless of status
- **Self-monitoring alerts:** every 30 minutes when the Watchdog itself has problems

The webhook format is intentionally generic and can be adapted to Slack, Telegram, Discord, or any HTTP endpoint.

---

## Dashboard

The project ships with a **fullscreen Flask dashboard** (`scripts/dashboard.py`) that provides:

- 📈 Summary cards: total checks, issues, last run time
- 🕒 Recent health checks with time-range filter (1h / 6h / 24h / 7d) and pagination
- ⚠️ Issue list (last 24h)
- 📊 Status distribution bar (OK / WARN / FAIL / UNKNOWN)
- 🔐 **Linux system user authentication** via `/etc/shadow` (no extra user DB)

Access it at `http://<watchdog-ip>:8080/`.

---

## Related Projects

This Watchdog was built to complement and supervise two other open-source projects:

| Project | Description |
|---|---|
| 🔗 [**ti-mirror**](https://github.com/shahpasandi/ti-mirror) | Air-gapped Threat Intelligence mirror for Splunk ES. Downloads 20+ free TI feeds, normalizes them, serves over an ACL-protected Nginx endpoint. |
| 🔗 [**syslog-relay**](https://github.com/shahpasandi/syslog-relay) | Production-grade syslog relay for Splunk. Writes to disk before forwarding with UF — nothing is lost during Splunk outages. |

Together, these three projects form an end-to-end **Splunk operations toolkit**: ingest, enrich, monitor.

> 🗺️ **Roadmap:** The component list is actively growing. The plan is to eventually monitor the **entire Splunk cluster** — deployment servers, cluster master, license master, heavy forwarders, monitoring console, and more. Follow the repo to be notified.

---

## Requirements

| Component | Version |
|---|---|
| OS | Ubuntu 24.04 LTS |
| Python | 3.10+ |
| Splunk Enterprise | 10.x (ES 8.x compatible) |
| Python libs | `requests`, `paramiko`, `flask`, `flask-httpauth` |
| Splunk REST tokens | One per monitored Splunk instance |
| SSH access | Key-based to Syslog Relay and TI Mirror |

---

## Security

- 🔐 Config file with tokens is `chmod 600`, owned by `root`
- 🔐 SSH private key is `chmod 600`
- 🔐 Dashboard requires valid **Linux system credentials** (`/etc/shadow`)
- 🔐 Splunk REST access uses **bearer tokens** (not passwords)
- 🔐 All HTTP to Splunk is over TLS (cert verification disabled for self-signed)
- 🔁 Tokens and SSH keys should be rotated every 365 days (see [RUNBOOK §12](docs/RUNBOOK.md))

**Never commit `watchdog.ini` (the real one), SSH private keys, or webhook tokens.** See `.gitignore` for the default exclusions.

---

## Contributing

Contributions are welcome — especially new health checks for other Splunk components. Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-check`)
3. Add your check in `scripts/health_check.py`
4. Update `docs/RUNBOOK.md` with the new check's threshold and severity
5. Open a Pull Request

For bugs or feature requests, please [open an issue](https://github.com/shahpasandi/splunk-watchdog/issues).

---

## License

Licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for the full text.

```
Copyright 2026 Mohammad Shahpasandi

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

## Author

**Mohammad Shahpasandi** — Splunk Engineer

- 🌐 Website: [https://shahpasandi.github.io](https://shahpasandi.github.io)
- 💻 GitHub: [@shahpasandi](https://github.com/shahpasandi)

---

**If this project helps you run your Splunk environment more reliably, please ⭐ star the repo — it helps others find it.**

---