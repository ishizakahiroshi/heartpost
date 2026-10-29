# heartpost

Liveness monitoring for shared hosting and small VPS fleets.

An agent runs from cron on each server, collects a few basic metrics, and POSTs a
signed heartbeat to a monitor you host yourself. The monitor stores the reports and
**tells you when a server stops reporting**. That last part is the point.

Japanese overview page: <https://ishizakahiroshi.com/articles/heartpost/usage.html>

Work page: <https://ishizakahiroshi.com/work?id=heartpost>

## What it is

- A one-shot agent that runs under cron, needs no root, and works on shared hosting
  (FreeBSD, no daemon, no package installation)
- A single-binary monitor that receives HMAC-signed reports, keeps them, shows one
  page listing every server, and alerts once when a server goes quiet — and once more
  when it comes back
- Optional collectors for a Linux VPS, so the box running the monitor is watched too

## What it is not

- Not an APM or a tracing system
- Not a log aggregation platform
- Not a metrics time-series database with dashboards and query languages
- Not a hosted service. You run the monitor yourself

If you want graphs, alert routing trees, and a query language, use Prometheus,
Zabbix, or a commercial uptime service. heartpost answers one question: *is it still
reporting?*

## How it fits together

```
cron (every 5 min)                     your own VPS
  heartpost-agent  --HMAC-signed JSON-->  heartpost-monitor  --> webhook
  (shared host, no root)                  (JSONL on disk, one page)
```

Copy `config/agent.example.toml` onto each server, `config/monitor.example.toml`
onto the box that receives. `scripts/install-agent.sh` does the agent side over SSH.

### Keep the cron interval and the silence threshold in step

The agent posts once per cron tick. The monitor calls a server *down* when nothing
has arrived for longer than its threshold. Those two numbers live in different files
on different machines, so they drift apart unless you change them together:

- agent: the cron line, `*/5 * * * *` by default
- monitor: `liveness.agent_interval`, `5m` by default. The threshold is three times
  that unless you set `down_threshold` yourself

Three times the interval is deliberate. One missed run is normal — a slow host, a
cron tick that overlapped a backup. Alerting on the first miss trains you to ignore
the alerts.

### Watch the monitor itself

heartpost tells you when a server stops reporting. It cannot tell you when *it* stops
listening: a monitor that is down looks exactly like a world where every server is
healthy and quiet. Point something outside this system at the monitor's `/healthz` —
an uptime service, a cron job on another host, anything that is not this monitor.

This is not a gap to be fixed later. Any single-point liveness checker has it. Plan
for it instead of assuming the dashboard is honest when it is silent.

## Go library packages

Other monitoring applications can reuse the collectors, report types, and report
signatures without running the heartpost commands. The following additional
packages are available for applications that embed these helpers:

| Import path | Purpose |
|---|---|
| `github.com/ishizakahiroshi/heartpost/agent` | Shared collection and delivery runner, one-shot or interval scheduling, ordered tasks, multiple targets, optional license verification and token caching. |
| `github.com/ishizakahiroshi/heartpost/agentlicense` | License signatures, signed tokens, offline licenses, and monitor authentication. The Go package name is `license`. |
| `github.com/ishizakahiroshi/heartpost/filelock` | Nonblocking file locks on Unix and Windows. `ErrLocked` identifies contention separately from I/O errors. |
| `github.com/ishizakahiroshi/heartpost/collector/optional` | Explicit configuration and adapters for opt-in audit, backup, fail2ban, honeypot, Nextcloud, extraction, object storage and threat collectors. |
| `github.com/ishizakahiroshi/heartpost/honeypotserver` | Optional HTTP decoy handler and JSONL event output. The caller owns its listener and shutdown. |
| `github.com/ishizakahiroshi/heartpost/audit` | Audit event wire type shared by log producers and collectors. |
| `github.com/ishizakahiroshi/heartpost/r2` | Object storage operations statistics helper. |
| `github.com/ishizakahiroshi/heartpost/httpoutcome` | Trusted receipts for deliberate outbound HTTP calls (`WithOperation`, `NewTransport`, `NewFileSink`), so a consumer can tell an expected 404/405 from a real failure. |

Construct `agent.New(agent.Options{...})` without starting work, then call
`Run(ctx)`. `Close(ctx)` cancels an active run and waits for its collectors and
requests. One runner may be active per process because collectors share their
timezone and cancellation settings. `ReturnFailure` returns when every target
fails; in interval mode it also cancels and joins the other groups. `WarnFailure`
logs delivery failures and continues the schedule.

Optional collectors are library components. The standard command keeps its
existing one-shot defaults and collector set. Embedding applications explicitly
supply the input and state paths, permissions, timezone and background services.
Log collectors may maintain derived JSONL files and checkpoints in those paths.
No optional collector or decoy listener is enabled by importing a package.

### Correlating receipts with nginx

The `httpoutcome` transport adds a random `X-HTTP-Operation-ID` request header and
writes one JSONL receipt per call. To let a consumer join receipts with the proxy's
view of the same request, append the header as a last quoted field of the access
log format. The nginx collector reads an optional trailing `"op=<hex32 or ->"` after
the user agent and reports it as the event's `request_id` (only when it is 32
lowercase hex characters; lines without the field parse as before):

```nginx
log_format hp_combined '$remote_addr - $remote_user [$time_local] "$request" '
                       '$status $body_bytes_sent "$http_referer" "$http_user_agent" '
                       '"op=$http_x_http_operation_id"';
access_log /var/log/nginx/access.log hp_combined;
```

nginx logs an absent header as `-`. The proxy should drop any client-supplied
`X-HTTP-Operation-ID` on requests that did not come from a trusted producer, since
only the producer's own receipt vouches for the id. Receipt files are listed in the
agent's `[vps] http_outcome_logs` and are read only if owned by the agent user, not
symlinks and not group/world-writable.

When the producer runs as a different account than the agent, add it to
`[vps] http_outcome_trusted_owners` (user names or numeric uids). Only the listed
accounts are trusted in addition to the agent user; root is not implied. The file
must still not be group/world-writable, and no directory in its path may be a
symlink or writable by group or world. An unknown name causes the files to be
skipped with the reason logged. In Go this is `httpoutcome.VerifyTrustedPathWithOwners`.

Construct a license verifier with `license.NewWithConfig(license.Config{...})`.
The calling application supplies its signing material and trusted public keys;
each verifier keeps its own configuration and current token. No shared package
setting changes another verifier's keys. Token verification and HTTP responses
retain the existing wire formats; application-specific authorization remains the
calling application's responsibility.

`license.IssueOfflineLicenseWithType` accepts an application's explicit signed
offline header type. The original `IssueOfflineLicense` preserves its existing
wire identifier and bytes; verification authenticates the signed header too.

The license helpers are optional. The one-shot `heartpost-agent` command keeps
its existing heartbeat behavior. File locks use real OS locking on Windows as
well as Unix, and releasing a lock keeps the lock file in place.

## Status

Published binaries are on [GitHub Releases](https://github.com/ishizakahiroshi/heartpost/releases)
(linux/amd64, linux/arm64, freebsd/amd64).

## License

Apache License 2.0. See [LICENSE](LICENSE).
