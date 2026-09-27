# Step 18 — MLOps: CI/CD and the release path

The plan: *"Set up CI/CD... so model improvements ship like software."*

## CI (`.github/workflows/ci.yml`)

Every push/PR runs:

1. the full unit suite on Python 3.11/3.12 — stdlib-only, torch-gated tests
   auto-skip (`python -m unittest discover -s tests -t .`);
2. the offline data-pipeline smoke (`scripts/run_data_pipeline.sh demo`);
3. a pipeline smoke: publish → consumer → decisions with a fake detector.

Model training is deliberately **not** in CI (CPU-hours, flaky on shared
runners). Model quality gates live in the release path instead.

## The release path (CD-lite)

| stage | gate | tooling |
|---|---|---|
| retrain | tests green | `make model-retrain` |
| evaluate | recall/FPR vs current on test + unseen + adversarial | `model-evaluate` (report: `data/reports/model_report.md`) |
| latency | p99 vs budget on the student if deploying edge | `model-benchmark`, `model-distill` |
| promote | human sign-off on the report | swap checkpoint path, restart gateway/consumer |
| verify | decision `model_version` changes; shadow watchlist clean | `monitor-run`, `/health` |

## Reproducibility

- `config/scope.toml` is the single contract (seeds, budgets, thresholds);
- every decision carries `model_version` + `policy_version`;
- datasets are regenerable (`make data-pipeline`) with sha256 manifests
  (`data/reports/fetch_manifest.json`).

## Future hardening (not yet built)

GitHub Actions model-training job on a schedule with artifact promotion, model
registry (MLflow), automatic rollback on watchlist regression. The contracts
above are what those tools would plug into.
