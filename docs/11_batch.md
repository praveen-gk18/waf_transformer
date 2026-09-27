# Step 11 — Batch Pipeline (nightly)

## What it does

The plan:

> *"Build a nightly job that pulls the day's logs from storage. This job
> should do two things: (1) Analyze the day's traffic for patterns the
> streaming model might have missed (slower, deeper analysis). (2) Prepare new
> training data by labeling any newly discovered attacks."*

`python3 -m waf_transformer.pipeline.batch --day YYYY-MM-DD` reads that day's
decision log (`data/decisions/decisions-*.jsonl`, written by the stream
consumer and/or the enforcement gateway) and produces:

| output | contents |
|---|---|
| `data/batch/report-YYYY-MM-DD.md` | human report: decision volume, score histogram, latency vs budget, top paths by mean score, possible-probing paths (aggregate mid-score activity the stream can't see), would-be-action watchlist |
| `data/batch/summary-YYYY-MM-DD.json` | the same numbers, machine-readable (Step 15 dashboard input) |
| `data/batch/candidates.jsonl` | **new training data**: every flagged request, heuristically typed (`label --corrections`'s `type_attack`) and labeled `label_source="heuristic"` — ready for analyst review |

## Closing the loop

```
candidates.jsonl ──▶ review sample ──▶ analyst corrects/accepts (MD table)
                   ──▶ review merge ──▶ label --corrections ──▶ build_dataset
                   ──▶ train (Step 16 retraining) ──▶ nightly again
```

The candidates carry `label_source="heuristic"` and `in_scope` flags exactly
like the seeded labels from Step 4, so the existing review workflow needs no
changes.

## Scheduling

Cron:

```cron
10 2 * * *  cd /srv/waf_transformer && bash scripts/run_nightly.sh
```

Airflow: one `BashOperator` running the same script — the job is a single
idempotent command; re-running a day overwrites that day's report/candidates
from the immutable decision log.

## Deeper analysis (batch vs stream)

The stream scores requests **in isolation** (no time, no neighbours). The
batch job additionally computes per-path aggregates: a path with many
sub-threshold requests can be active probing even when nothing crossed the
challenge threshold — reported under `possible_probing` for the analyst.

## What "missed" means here

The report's `shadow_actions` field lists decisions the model *would* have
taken outside shadow mode. Watching those across days is how false positives
get caught before enforcement (Phase 5, Step 13).
