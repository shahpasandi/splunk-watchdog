#!/bin/bash

DB="/opt/splunk-watchdog/db/health.db"
RETENTION_DAYS=90

# Wait up to 30 seconds if the database is locked
sqlite3 "$DB" "PRAGMA busy_timeout = 30000;" "DELETE FROM health_checks WHERE datetime(timestamp) < datetime('now', '-${RETENTION_DAYS} days');"
sqlite3 "$DB" "PRAGMA busy_timeout = 30000;" "DELETE FROM heartbeat WHERE datetime(timestamp) < datetime('now', '-${RETENTION_DAYS} days');"
sqlite3 "$DB" "PRAGMA busy_timeout = 30000;" "VACUUM;"
