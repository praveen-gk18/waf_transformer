# Step 15 — Monitoring Dashboard (and Step 19 — Drift)

The plan: *"Build a monitoring dashboard. Track latency vs budget, accuracy,
false positive rate."* … later: *"monitor for drift"*.

## The dashboard

Two views, one data source (`data/decisions/*.jsonl` + `data/reports/monitor.json`):

- **Live** — `GET /dashboard` on the gateway: current counters, latency
  percentiles, policy/model versions, plus the latest aggregated metrics.
- **Historical** — `python3 -m waf_transformer.pipeline.monitor` (Makefile:
  `make monitor-run`; scheduled with the nightly batch in
  `scripts/run_nightly.sh`) writes:
  - `data/reports/monitor.json` — machine-readable (feed it to Grafana later),
  - `data/reports/dashboard-<day>.md` — human report.

## What is tracked

| signal | why | alert condition |
|---|---|---|
| volume | attack waves / broken collector | ≥ 3× recent average |
| action rates, shadow would-block/challenge | **false-positive watchlist** | would-block rate ≥ 2× recent average |
| latency p50/p95/p99 vs `[latency]` budget | SLO | p95 over budget |
| score distribution | **drift (Step 19)** | PSI ≥ 0.2 vs baseline |
| accuracy (when labels arrive) | model health | via retraining eval (Step 16) |

## Drift (Step 19)

The score distribution is compared day-over-day against a **baseline** (the
first traffic day; rotate it deliberately after retrains). PSI over decile
histograms catches both kinds of drift:

- **data drift** — traffic shape changed (new routes, new clients, an attack
  campaign): scores shift even though the model is unchanged;
- **model drift** — the world moved on: yesterday's attacks mutate, scores
  slide below threshold (watch `recall` on the labeled review stream).

`drift` entries in `monitor.json` carry `psi`, `volume_ratio`,
`wouldblock_ratio` per day; `alerts` are plain-English. PSI ≥ 0.2 → investigate
before ramping enforcement further; recurring drift → retrain (Step 16).

## Wiring into the ops schedule

```cron
10 2 * * *  cd /srv/waf_transformer && bash scripts/run_nightly.sh   # batch + monitor
```
