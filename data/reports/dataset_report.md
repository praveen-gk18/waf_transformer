# waf_transformer — Phase 2 dataset report

_Generated 2026-09-27 by `python3 -m waf_transformer.data.report`. Do not edit by hand — regenerate._

## 1. Source inventory (Step 3–4)

| dataset | fetch strategy | files | size |
|---|---|---|---|
| csic_2010 | git_clone | 3 | 60.9 MB |
| ecml_pkdd_2007 | git_clone | 2 | 82.7 MB |

## 2. Label distribution (Step 5)

| split | records | groups | benign | attack | attack ratio |
|---|---|---|---|---|---|
| test | 21044 | 15654 | 16501 | 4543 | 21.6% |
| train | 98204 | 73097 | 77004 | 21200 | 21.6% |
| val | 21044 | 15653 | 16501 | 4543 | 21.6% |
| test_unseen | 2469 | 1306 | 0 | 2469 | 100.0% |

- Train attack ratio: **21.6%** (floor 5%, oversample target 8%)
- Leakage audit: **passed** (no session/source/generator group straddles splits)

## 3. Composition by source

| source | records |
|---|---|
| csic_2010 | 95237 |
| ecml_pkdd_2007 | 38135 |
| synthetic:attack_simulator | 3920 |
| synthetic:normal_profile | 3000 |

## 4. Attack categories (train+val+test)

| category | records | v1 scope |
|---|---|---|
| untyped | 20909 | in-scope |
| sql_injection | 5398 | in-scope |
| xss | 3979 | in-scope |

## 5. Unseen-technique holdout (Step 9 preparation)

Techniques reserved for Phase-3 generalization evaluation: `dom_xss`, `time_based_sql`.
`test_unseen.jsonl.gz` holds 2469 attack records that never appear in train/val/test.
- 685 records sharing a session/source group with a holdout attack were excluded from the main splits (campaign contamination guard).
- 11735 records of out-of-scope attack families (path traversal, command injection, …) were excluded from the v1 splits — re-include with `build_dataset --include-out-of-scope`.

## 6. Edge-case handling (Step 17)

- Bodies truncated at 8192 bytes: **0** records (flagged with `body_truncated`; file uploads beyond this are a Phase-4 parsing concern)
- Headers kept verbatim, capped at 64 headers / 2048 bytes per value at ingest
- Encrypted traffic is out of scope here by design — the engine sits behind TLS termination

## 7. Scope echo (config/scope.toml)

- Objective: **binary** classification of full HTTP requests
- In-scope attack families: `sql_injection`, `xss`
- Latency budget: p50 ≤ 5.0 ms, p95 ≤ 8.0 ms, p99 ≤ 10.0 ms (hard cap 10.0 ms)

## 8. Reproduce this build

```bash
make data-pipeline   # fetch -> generate -> ingest -> label -> build -> report
make test            # unit tests
```

Artifacts: `data/processed/{train,val,test,test_unseen}.jsonl.gz`, `splits_index.json`, `stats.json` (gitignored; regenerate locally). Only `data/reports/` and `data/samples/` are versioned.
