# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added

- `httpoutcome` package: trusted receipts for deliberate outbound HTTP calls
  (operation tag, `X-HTTP-Operation-ID`, JSONL file sink).
- `http_outcome` VPS collector, and an optional trailing `"op=<hex32>"` field in the
  nginx access-log parser exposed as `request_id`.

## [0.3.0] - 2026-10-25

### Added

- Public `agent` runtime for one-shot and interval collection, multiple report
  targets, delivery failure policies, optional licensing and signed token caches.
  Shutdown joins collectors, delivery requests and license heartbeats.
- Optional audit log, backup, fail2ban, honeypot, Nextcloud, extracted event,
  object storage and threat collectors with explicit deployment configuration.
- Opt-in HTTP decoy handler, shared audit event type and object storage operations
  helper for embedding applications.
- Blocking `agentlicense.RunHeartbeat` helper without changing the existing
  verifier interface or asynchronous heartbeat entry point.

### Changed

- The standard agent command uses the shared runtime while preserving its
  one-shot behavior, configuration, report encoding and failure handling.

## [0.2.0] - 2026-10-25

### Added

- Public `agentlicense` Go package for license signatures, signed tokens, offline
  licenses, and monitor authentication, with explicit per-verifier configuration.
- Explicit signed offline header types for embedding applications, while the
  original issuance function preserves its existing wire bytes.
- Public `filelock` Go package for nonblocking Unix and Windows locks, with a
  shared contention sentinel across the public and internal import paths.

### Changed

- Internal file locking delegates to the public package. Agent commands and
  heartbeat report formats retain their existing behavior.

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
