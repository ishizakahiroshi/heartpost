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

## Status

v0.1.0 is on [GitHub Releases](https://github.com/ishizakahiroshi/heartpost/releases/tag/v0.1.0)
(linux/amd64, linux/arm64, freebsd/amd64).

## License

Apache License 2.0. See [LICENSE](LICENSE).
