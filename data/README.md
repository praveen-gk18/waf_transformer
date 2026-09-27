# data/ — layout and conventions

| Path | In Git? | Contents |
|---|---|---|
| `raw/` | ❌ | Public corpora (CSIC 2010, ECML/PKDD 2007) + synthetic generator output + `MANIFEST.json` (sha256 provenance) |
| `interim/` | ❌ | `unified.jsonl` (parsed), `labeled.jsonl` (post-adjudication) |
| `processed/` | ❌ | `train|val|test|test_unseen.jsonl.gz`, `splits_index.json`, `stats.json` — the Phase-2 training dataset |
| `review/` | ❌ | `review_queue.csv` (analyst workflow), `corrections.jsonl` |
| `reports/` | ✅ | `dataset_report.md`, `stats.json`, `fetch_manifest.json` — the auditable build record |
| `samples/` | ✅ | `preview.jsonl` — tiny stratified schema preview |

## Why not commit the datasets?

1. **Reproducible**: `make data-pipeline` refetches the public corpora and
   rebuilds every artifact deterministically (seeded; sha256 manifest records
   exactly what was fetched).
2. **They'll grow**: the same layout will hold weeks of live traffic
   (S3/MinIO convention from the plan) — Git is the wrong store for that.
3. **Reviewable anyway**: `reports/` + `samples/` give anyone a full picture
   of label quality and composition without downloading 600 MB.

## Regenerating

```bash
make data-pipeline     # everything, fresh
make data-fetch        # just the public corpora into raw/
make data-demo         # synthetic-only smoke run (no network)
make clean-data        # wipe raw/interim/processed/review
```

Stage-by-stage equivalents are in the Makefile if you need to re-run just
labeling after a review (`--corrections data/review/corrections.jsonl`) or
rebuild splits after a config change.
