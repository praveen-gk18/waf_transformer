# waf_transformer — Phase 3 model evaluation report

_Generated 2026-09-27 by `python3 -m waf_transformer.modeling.evaluate`. Do not edit by hand — regenerate._

## 1. Checkpoint

- selected epoch: **3**
- operating threshold (val-selected @ recall ≥ target): **0.138**
- val metrics at selection: `{"threshold": 0.5, "precision": 0.7118, "recall": 0.8934, "f1": 0.7923, "accuracy": 0.899, "fpr": 0.0995, "tp": 578, "fp": 234, "tn": 2118, "fn": 69}`

## 2. Results (Step 8–9)

### Main test split (unseen records, seen techniques)

- records: 21044
- @ 0.50: precision **0.7252**, recall **0.8932**, F1 0.8005, FPR 0.0932 (tp 4058, fp 1538, fn 485, tn 14963)
- operating point (recall ≥ 0.95): threshold 0.135, precision 0.5591, recall 0.9500

| category | support | recall |
|---|---|---|
| sql_injection | 821 | 0.7881 |
| untyped | 3153 | 0.9248 |
| xss | 569 | 0.8699 |

### Unseen-technique holdout (time_based_sql, dom_xss — never trained on)

- records: 2469
- @ 0.50: precision **1.0000**, recall **0.8947**, F1 0.9444, FPR 0.0000 (tp 2209, fp 0, fn 260, tn 0)
- operating point (recall ≥ 0.95): threshold 0.102, precision 1.0000, recall 0.9502

| category | support | recall |
|---|---|---|
| sql_injection | 1644 | 0.9580 |
| xss | 825 | 0.7685 |

### Adversarial variants (test attacks + 1 extra encoding layer)

- records: 4543
- @ 0.50: precision **1.0000**, recall **0.9969**, F1 0.9985, FPR 0.0000 (tp 4529, fp 0, fn 14, tn 0)
- operating point (recall ≥ 0.95): threshold 0.996, precision 1.0000, recall 0.9500

| category | support | recall |
|---|---|---|
| sql_injection | 821 | 0.9866 |
| untyped | 3153 | 1.0000 |
| xss | 569 | 0.9947 |

## 3. Latency budget

- budget (scope.toml): p99 ≤ **10.0 ms** end-to-end (p50 5.0 ms)
- measured ladder: `data/reports/latency_report.md` + `latency_report.json`
  (eager / jit / int8 / onnx variants, batch-1 on real requests)

## 4. Reproduce

```bash
make model-train model-evaluate model-benchmark
```
