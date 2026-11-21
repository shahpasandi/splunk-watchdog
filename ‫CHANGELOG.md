# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-10-14

### Added
- Initial release of Splunk Watchdog.
- 68+ health checks for Splunk Search Head, Indexer, and ES.
- Self-monitoring and heartbeat mechanisms.
- End-to-End (E2E) syslog verification pipeline.
- SQLite database with 90-day retention policy.
- Bale Messenger webhook integration with 15-minute throttling.
- Flask-based fullscreen dashboard with Linux system auth.
- Systemd timers for automated scheduling.
- Support for monitoring `syslog-relay` and `ti-mirror` projects.