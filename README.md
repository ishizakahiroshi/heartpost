# heartpost

Liveness monitoring for shared hosting and small VPS fleets.

An agent runs from cron on each server, collects a few basic metrics, and POSTs a
signed heartbeat to a monitor you host yourself. The monitor stores the reports and
**tells you when a server stops reporting**. That last part is the point.

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

## Status

Early development. Nothing is released yet.

## License

Apache License 2.0. See [LICENSE](LICENSE).
