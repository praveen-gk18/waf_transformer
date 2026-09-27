# WAF monitoring dashboard — 2026-09-27

_Generated 2026-09-27T13:55:16+00:00 — `python3 -m waf_transformer.pipeline.monitor`._

## Headlines

- requests today: **21**
- actions: {'allow': 21}
- shadow would-block / would-challenge: **8 / 1** (false-positive watchlist)
- latency p50/p95/p99: **{'p50': 20.745, 'p95': 37.495, 'p99': 1342.663}** vs budget 5.0/8.0/10.0 ms
- score mean: 0.5277  | drift baseline: day 2026-09-27

## Alerts

- **latency** (2026-09-27): p95 37.495 ms over budget 8.0 ms

## Drift (PSI vs baseline)

| day | PSI | volume ratio | would-block ratio |
|---|---|---|---|
| 2026-09-27 | 0.0 | None | None |

## Latency vs budget by day

| day | p50 | p95 | p99 | p95 ok |
|---|---|---|---|---|
| 2026-09-27 | 20.745 | 37.495 | 1342.663 | ❌ |
