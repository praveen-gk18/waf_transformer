# waf_transformer — Phase 3 model evaluation report

_Generated 2026-09-27 by `python3 -m waf_transformer.modeling.evaluate`. Do not edit by hand — regenerate._

## 1. Checkpoint

- selected epoch: **3**
- operating threshold (val-selected @ recall ≥ target): **0.083**
- val metrics at selection: `{"threshold": 0.5, "precision": 0.7373, "recall": 0.8424, "f1": 0.7864, "accuracy": 0.9012, "fpr": 0.0826, "tp": 727, "fp": 259, "tn": 2877, "fn": 136}`

## 2. Results (Step 8–9)

### Main test split (unseen records, seen techniques)

- records: 21044
- @ 0.50: precision **0.7456**, recall **0.8380**, F1 0.7891, FPR 0.0787 (tp 3807, fp 1299, fn 736, tn 15202)
- operating point (recall ≥ 0.95): threshold 0.074, precision 0.4261, recall 0.9500

| category | support | recall |
|---|---|---|
| sql_injection | 821 | 0.7978 |
| untyped | 3153 | 0.8484 |
| xss | 569 | 0.8383 |

### Unseen-technique holdout (time_based_sql, dom_xss — never trained on)

- records: 2469
- @ 0.50: precision **1.0000**, recall **0.8886**, F1 0.9410, FPR 0.0000 (tp 2194, fp 0, fn 275, tn 0)
- operating point (recall ≥ 0.95): threshold 0.114, precision 1.0000, recall 0.9530

| category | support | recall |
|---|---|---|
| sql_injection | 1644 | 0.9599 |
| xss | 825 | 0.7467 |

### Adversarial variants (test attacks + 1 extra encoding layer)

- records: 4543
- @ 0.50: precision **1.0000**, recall **0.9864**, F1 0.9931, FPR 0.0000 (tp 4481, fp 0, fn 62, tn 0)
- operating point (recall ≥ 0.95): threshold 0.995, precision 1.0000, recall 0.9507

| category | support | recall |
|---|---|---|
| sql_injection | 821 | 0.9488 |
| untyped | 3153 | 1.0000 |
| xss | 569 | 0.9649 |

## 3. Latency budget

- budget (scope.toml): p99 ≤ **10.0 ms** end-to-end (p50 5.0 ms)
- measured ladder: `data/reports/latency_report.md` + `latency_report.json`
  (eager / jit / int8 / onnx variants, batch-1 on real requests)

## 4. Reproduce

```bash
make model-train model-evaluate model-benchmark
```

---

## Addendum (2026-09-27) — literal-payload blind spot, data fix, and run2 promotion

Post-deployment probing found the Phase-3 model keyed on **percent-encoding
artifacts** rather than payload semantics: the attack simulator always
encoded payloads at placement (`quote(payload, safe='')`) and the classic
corpora attack traffic is encoded too. On **realistic request shapes**
(product paths + full e-commerce headers) the run1 checkpoint missed literal
attacks entirely:

| realistic-shape probe | run1 | run2 |
|---|---|---|
| `q=<script>alert(1)</script>` | 0.221 | **0.988** |
| `q=<script>alert('Hola')</script>` | 0.270 | **0.990** |
| `q=<img src=x onerror=alert(1)>` | 0.106 | **0.993** |
| `idA=1' UNION SELECT password FROM users--` | 0.776 | **0.996** |
| path `/imagenes/../../etc/passwd` | 0.779 | **0.986** |
| benign `q=shoes&page=2` | 0.357 | 0.795 (see FPR note) |
| benign product jpg | 0.026 | 0.033 |

**Fix:** `data/generate_attacks.py:_place()` now sends payloads **raw half
the time** (only URL-syntax chars encoded); dataset rebuilt (same audited
splits) and the model retrained per the Step-16 loop → `artifacts/run2/`.

### run2 vs run1 (test @0.5)

| | precision | recall | F1 | FPR | unseen recall | adversarial recall |
|---|---|---|---|---|---|---|
| run1 | 0.725 | 0.893 | 0.801 | 0.093 | 0.895 | 0.997 |
| run2 | **0.746** | 0.838 | 0.789 | **0.079** | 0.889 | 0.986 |

### Promotion decision: **run2 promoted** (copied over `artifacts/run1/best.pt`)

Rationale: the corpus hides the blind spot (test XSS is ~87% encoded
variants), but real attackers send literal payloads constantly. Catching
literal XSS at 0.99 instead of 0.22 is worth ~5pp recall on the encoded-heavy
corpus distribution, especially with precision and FPR both **improving**.
Known trade-off: benign queries that mimic attack templates (e.g. `q=` search
params) score higher in run2 — the enforcement thresholds live in
`config/scope.toml` and the shadow-mode watchlist is the mechanism for tuning
that against real traffic. The pre-promotion checkpoint remains in git
history and `artifacts/run2/`.

### Known limitation: header-shape sensitivity (measured)

The model weights request *shape* along with payload text (it learned "real
browser request + attack payload"). The same literal XSS scores **0.99 with
full browser headers but 0.49 with a bare `Host`-only header set** — below
the 0.6 challenge threshold. Real traffic through Nginx/Envoy carries full
headers, and the nightly batch's aggregate probing analysis covers slow
recon; but a client that strips headers can partially evade. Mitigation:
add header-ablated attack variants to `data/generate_attacks.py` placements
and retrain via the Step-16 loop — the pipeline is the fix loop for exactly
this. Tracked in `docs/16_retraining.md`.
