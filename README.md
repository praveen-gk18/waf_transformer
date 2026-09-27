# waf_transformer

Transformer-based request classifier for a web application firewall: given a
**full HTTP request** (method, path, query, headers, body), output
`p(malicious)` within a **10 ms p99 latency budget**.

Built in phases, per the construction plan:

| # | Task | Phase | Status |
|---|---|---|---|
| 1 | Define scope and latency budget | Foundation | ✅ [`docs/01_scope.md`](docs/01_scope.md) + [`config/scope.toml`](config/scope.toml) |
| 2 | Choose tech stack | Foundation | ✅ [`docs/02_tech_stack.md`](docs/02_tech_stack.md) + [`infra/`](infra/) |
| 3 | Collect raw traffic logs | Data | ✅ contract + configs ([`docs/03_log_collection.md`](docs/03_log_collection.md)) |
| 4 | Gather attack data | Data | ✅ fetcher + attack simulator ([`docs/04_attack_data.md`](docs/04_attack_data.md)) |
| 5 | Label everything | Data | ✅ labeling + review workflow ([`docs/05_labeling.md`](docs/05_labeling.md)) |
| 6 | Design tokenizer | Model | ✅ byte-level + HTTP field tokens ([`docs/06_tokenizer.md`](docs/06_tokenizer.md)) |
| 7 | Choose architecture | Model | ✅ 3.4M-param encoder ([`docs/07_model.md`](docs/07_model.md)) |
| 8 | Train the model | Model | ✅ weighted BCE, precision/recall-first ([`docs/08_training.md`](docs/08_training.md)) |
| 9 | Evaluate and harden | Model | ✅ unseen + adversarial + latency bench ([`docs/09_evaluation.md`](docs/09_evaluation.md)) |
| 10–12 | Streaming/batch plumbing + enforcement | Plumbing | ✅ Steps 10–12 ([`docs/10_streaming.md`](docs/10_streaming.md), [`docs/11_batch.md`](docs/11_batch.md), [`docs/12_enforcement.md`](docs/12_enforcement.md)) |
| 13–15 | Shadow mode → blocking → monitoring | Go Live | ✅ Steps 13–15 ([`docs/13_shadow_rollout.md`](docs/13_shadow_rollout.md), [`docs/14_blocking_rollout.md`](docs/14_blocking_rollout.md), [`docs/15_monitoring.md`](docs/15_monitoring.md)) |
| 16–17 | Retraining loop, edge cases | Ongoing | ✅ Steps 16–17 ([`docs/16_retraining.md`](docs/16_retraining.md), [`docs/17_edge_cases.md`](docs/17_edge_cases.md)) |
| 18–20 | MLOps CI/CD, drift, distillation | Scale | ✅ Steps 18–20 ([`docs/18_mlops.md`](docs/18_mlops.md), [`docs/20_distillation.md`](docs/20_distillation.md)) |

**👉 New here? Read [`docs/GUIDE.md`](docs/GUIDE.md) — the complete usage guide.**

## Current state (all plan steps implemented)

- **Scope contract** — SQLi + XSS first, binary objective, e-commerce + JSON
  API "normal" profile with weird-but-benign tripwires, p99 ≤ 10 ms budget.
  Machine-readable in `config/scope.toml`; every pipeline stage reads it.
- **Data pipeline** (pure stdlib Python, no dependencies) —
  `fetch → generate → ingest → label → review-sample → build → report`:
  - Public corpora: **CSIC 2010** (97,065 reqs) + **ECML/PKDD 2007** (50,116
    reqs), auto-fetched from the GSI mirror with GitHub fallback, sha256
    manifest.
  - Attack simulator: 5,000 obfuscated SQLi/XSS requests (techniques ×
    placements × encoding mutators).
  - Synthetic normal traffic: 3,000 requests matching the Phase-1 profile.
  - Labeling: provenance-priority adjudication (manual > waf_export > dataset >
    synthetic > heuristic), decoded-pattern family typing, review queue.
  - Dataset build: **leak-free group-aware 70/15/15 splits** (audited),
    attack-ratio floor policy, unseen-technique holdout for Step-9 evaluation.

Latest build: **155,181 labeled records → 140,292 in splits (21.6% attack) +
2,469 unseen-technique holdout**, leakage audit passed — see
[`data/reports/dataset_report.md`](data/reports/dataset_report.md).

## Phase 3 — the model (complete)

- **Tokenizer** (Step 6): byte-level tokens + `[METH]/[PATH]/[QUERY]/[HDR]/[BODY]`
  field separators — zero OOV, obfuscation-proof, 384-token cap with `[TRUNC]`
  flags. Where something appears is part of the input.
- **Encoder** (Step 7): 4-layer / d=256 / 8-head transformer, ~3.4M params,
  binary logit head. Trained from scratch (pretrained-BERT tradeoffs in
  `docs/07_model.md`).
- **Training** (Step 8): class-weighted BCE (focal optional), leak-free Phase-2
  splits, precision & recall monitored separately, high-recall operating point
  selected on val and stored in the checkpoint.
- **Hardening** (Step 9): held-out **unseen techniques** (`time_based_sql`,
  `dom_xss`), **adversarial re-encoded** variants, and p50/p95/p99 latency
  benchmarking vs the 10 ms p99 budget with a quantization/ONNX ladder.
- Results: [`data/reports/model_report.md`](data/reports/model_report.md) +
  `data/reports/latency_report.md`; deployable `artifacts/model.onnx`.

## Phase 4 — the plumbing (complete)

- **Streaming** (Step 10): broker abstraction (`file` for demos/tests, `kafka`
  for production) → `StreamConsumer` scores each request and emits a `Decision`
  (score, action, versions, latency) to `http.requests.decisions` + an
  append-only audit log. At-least-once, offsets after persist.
- **Batch** (Step 11): nightly job (`scripts/run_nightly.sh`, cron/Airflow)
  analyzes the day's decisions for aggregate patterns the stream can't see,
  and writes **new training data** (`candidates.jsonl`, heuristically typed)
  into the existing analyst-review workflow.
- **Enforcement** (Step 12): `> 0.9 block / > 0.6 challenge / allow` with
  thresholds in `config/scope.toml [enforcement]` — **hot-reloaded, no model
  redeploy**. The gateway bridge answers `200/403/429` so Nginx `auth_request`
  (Kong/Envoy ext-authz) enforces: *the model decides, the gateway enforces*
  ([`infra/nginx/waf_enforcement.conf`](infra/nginx/waf_enforcement.conf)).
  `mode = "shadow"` (default) records would-be actions without blocking —
  the Phase-5 rollout path.
- Try it: `make stream-demo` (end-to-end), `make gateway-serve` (decision API
  + demo page), `make batch-run`.

## Phase 5–6 — go live & operate (complete)

- **Shadow → staged blocking** (Steps 13–14): `mode = "shadow"` is the
  default; promote through `challenge` → `block` with `enforce_percent`
  deterministic traffic sampling (sticky per client key) — every rung is one
  hot-reloaded config edit.
- **Monitoring + drift** (Steps 15/19): `make monitor-run` aggregates the
  audit log into dashboard + PSI drift + plain-English alerts (volume,
  false-positive watchlist growth, latency vs budget). Live view at
  `GET /dashboard`.
- **Retraining loop** (Step 16): `make model-retrain` harvests the batch job's
  candidates into an analyst queue → corrections → leak-free rebuild →
  `artifacts/run2` + evaluation gate.
- **Edge cases** (Step 17): multipart uploads, GraphQL bodies, binary bodies,
  oversized echoes — defined behavior + tests (`docs/17_edge_cases.md`).
- **MLOps CI** (Step 18): GitHub Actions runs the suite + offline smokes per
  push; model promotion stays human-gated.
- **Distillation** (Step 20): `make model-distill` produces a ~0.4M-param
  student in the same checkpoint format — **p99 3.8 ms (jit) / 6.7 ms
  (eager)** vs the teacher's ~21–23 ms: this is how the 10 ms budget is met
  on modest CPUs.

## Quickstart

Data pipeline: Python ≥ 3.11, stdlib only. Model pipeline: `pip install -r
requirements-model.txt` (or `python3 -m venv .venv` first — the Makefile
auto-detects `.venv`).

```bash
make test            # 96 unit tests
make data-pipeline   # Phase 2: fetch public corpora -> build dataset
make data-demo       # offline smoke run (synthetic sources only)
make model-train     # Phase 3: train the encoder (config/scope.toml [training])
make model-evaluate  # test + unseen-technique + adversarial evaluation
make model-export    # ONNX for serving
make model-benchmark # latency p50/p95/p99 vs the 10 ms budget
make model-demo      # score one request with block/challenge/allow decision
make stream-demo     # Phase 4: publish -> detect -> decide -> nightly batch
make gateway-serve   # Phase 4: enforcement bridge (live decision API + demo page)
make batch-run       # Phase 4: nightly analysis + new training data
make monitor-run     # Phase 5: dashboard + drift + alerts
make model-retrain   # Phase 6: analyst review -> rebuild -> retrain -> evaluate
make model-distill   # Phase 6: small student model (meets the latency budget)
```

Individual stages (`make data-fetch`, `data-synth`, `data-ingest`,
`data-label`, `data-review-sample`, `data-build`, `data-report`) are
independently runnable — see `Makefile` and `scripts/run_data_pipeline.sh`.

## Repo layout

```
config/scope.toml          Phase-1 scope & budget contract (single source of truth)
docs/                      Steps 1–12 decision records
infra/                     Kafka/MinIO/Postgres + nginx/filebeat + waf enforcement snippet
waf_transformer/
  config.py                typed scope loader
  data/                    fetch / parse / generate / label / review / build / report
  modeling/                tokenizer, encoder, train / evaluate / benchmark / export
  engine/                  policy (hot thresholds) + detector (record -> decision)
  pipeline/                broker, stream consumer, nightly batch, gateway bridge
tests/                     unit tests + corpus fixtures
artifacts/                 trained checkpoints + ONNX exports (release artifacts)
data/
  reports/                 committed build + model reports, provenance manifests
  samples/                 committed schema preview (tiny)
  batch/                   committed nightly reports (tiny)
  raw|interim|processed|review|stream|decisions/   gitignored; regenerate with make
```

## Data convention

Datasets are **not committed** (they're regenerable in one command and will
grow with live traffic — same convention as the S3/MinIO store for raw logs).
`data/reports/` and `data/samples/` are versioned so reviewers can verify
what was built without downloading anything. See [`data/README.md`](data/README.md).

## Next up — operate it

Everything in the plan is implemented. The operating story is in
[`docs/GUIDE.md`](docs/GUIDE.md): run shadow for a week, ramp
`enforce_percent`, watch the nightly dashboard, retrain from the candidates
the batch job harvests. Not built (documented as future work in
`docs/18_mlops.md`): model registry, automatic rollback, scheduled CI
training.
