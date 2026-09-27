# Step 16 — Retraining Loop

The plan: *"Set up a pipeline for periodically retraining with newly labeled
data — new attacks show up constantly."*

## The loop

```
live traffic ──▶ nightly batch ──▶ candidates.jsonl (heuristic labels)
                                        │
        analyst review (docs/05) ◀──────┤
                                        ▼
            corrections ──▶ label --corrections ──▶ build_dataset (leak-free)
                                        ▼
              model-train (artifacts/run2) ──▶ model-evaluate vs run1
                                        ▼
                    promote? ──▶ restart gateway/consumer
```

One script runs it: **`make model-retrain`** (`scripts/run_retrain.sh`).

1. `review sample` exports an analyst queue from `data/batch/candidates.jsonl`
   (the daily harvest of flagged traffic). The script **stops here** until
   corrections exist — humans label; machines don't self-certify.
2. `review merge` turns the filled queue into corrections JSONL.
3. `label --corrections` folds them into the corpus with provenance priority
   (manual wins), `build_dataset` rebuilds leak-free group-aware splits.
4. `model-train` writes `artifacts/run2/` + `model-evaluate` scores it against
   the same tests (test + unseen-technique + adversarial).

## Promotion policy

Promote `run2/best.pt` over `run1/best.pt` **only if** the eval report holds
the bar: recall at the operating point, unseen-technique recall, adversarial
recall, and no FPR regression — then restart the serving process
(`gateway-serve` / `consumer`) to load the new checkpoint. The model version
in every decision (`sha256:<12>`) makes the cutover auditable.

## Cadence

- **weekly** during active rollout (fresh watchlist data, small batches),
- **monthly** in steady state,
- **immediately** when the monitor reports sustained drift (Step 15/19) or a
  novel attack family hits the watchlist.

Retraining is deliberately cheap at this size (3.4M params, CPU-minutes); the
expensive part is the analyst loop — which is why candidates arrive typed and
pre-scored.
