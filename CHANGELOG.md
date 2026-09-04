# Changelog

All notable changes to this project are documented in this file.

## [0.1.0] - 2026-09-04

First release. Liveness monitoring for shared hosting (FreeBSD, no root) and small VPS fleets.

### Added

- `heartpost-agent`: one-shot collector that cron runs; POSTs an HMAC-signed heartbeat and exits
- Rental collectors (9): host, loadavg, memory, disk, cron, process, cpu, network, apache_log
- VPS collectors (8): system, process, cron, services, ssl, ssh, nginx, updates
- `heartpost-monitor`: receives reports, stores JSONL, marks a host down when reports stop, notifies once via webhook, and serves a listing page
- Agent refuses to start unless the key file mode is 600
- `scripts/install-agent.sh` copies the agent over SSH and installs one crontab line
- systemd unit and timer templates for Linux (not yet verified on a live host)
- Release binaries: linux/amd64, linux/arm64, freebsd/amd64
- Build with Go 1.25.13 so the standard library includes current security fixes
