# waf_transformer — User Guide

Everything you need to run, operate, and improve this WAF, in the order you'll
need it. Each phase has a decision-record doc (`docs/01`–`docs/20`) if you want
the *why*; this guide is the *how*.

---

## 1. What this is (60 seconds)

A machine-learning Web Application Firewall **decision engine**. It reads a
full HTTP request (method, path, query, headers, body) and returns
`p(malicious)`, mapped to `allow` / `challenge` / `block`.

Key design facts:

- **The model decides; the gateway enforces.** Your Nginx/Kong/Envoy asks this
  service per request (status code = decision). Nothing here terminates
  traffic itself.
- **Thresholds are config, not code** (`config/scope.toml [enforcement]`),
  hot-reloaded — change behavior without redeploying the model.
- **Shadow mode by default**: it records what it *would* do and blocks
  nothing, so you can trust it before it hurts anyone.
- **Everything is auditable**: every decision logs score, action, model
  version, policy version, latency.

Quality/speed numbers (promoted model `run1/best.pt`, test set @0.5):
precision 0.75 / recall 0.84 / F1 0.79, FPR 0.079; recall 0.95 at the
operating point; unseen attacks 0.89 recall. An earlier checkpoint missed
**literal** (unencoded) attacks badly — that blind spot is documented and
fixed in `data/reports/model_report.md`. The distilled edge student meets the
10 ms p99 budget where the teacher doesn't (`docs/20_distillation.md`).

---

## 2. Setup

Requirements: Python ≥ 3.11 (3.11 tested), ~2 GB RAM for training.

```bash
git clone <this repo> && cd waf_transformer

# data pipeline is stdlib-only; the model needs:
python3 -m venv .venv
.venv/bin/pip install -r requirements-model.txt   # torch, onnxruntime, torchao...

make test          # 96 unit tests — should say OK
```

---

## 3. The 10-minute tour (offline, no data needed)

```bash
make data-demo       # synthetic dataset: attack simulator + normal traffic
make model-train     # train the encoder (~minutes on CPU)
make model-evaluate  # quality report -> data/reports/model_report.md
make model-demo      # score ONE request, see the decision
make stream-demo     # Step 10-11 end-to-end: publish -> detect -> decide -> nightly batch
make gateway-serve   # live decision API + demo page on :8089
```

Open the gateway: `/` is an interactive page (paste a request, hit *decide*),
`/dashboard` is the monitoring view, `/health` and `/stats` are JSON.

Prebuilt artifacts ship in `artifacts/` — if you skip training, everything
works against `artifacts/run1/best.pt` immediately.

---

## 4. Producing the real dataset (Phase 2)

```bash
make data-pipeline   # fetch CSIC 2010 + ECML/PKDD 2007, simulate attacks,
                     # synthesize normal traffic, label, review-sample, build splits
```

Outputs `data/processed/{train,val,test,test_unseen}.jsonl.gz` (gitignored —
regenerable in one command) and `data/reports/dataset_report.md`. Seeded
(reviewable) labels live in `data/review/`.

---

## 5. Serving decisions in production (Steps 10 & 12)

### 5a. The enforcement bridge (most common)

```bash
make gateway-serve                     # or:
python3 -m waf_transformer.pipeline.gateway \
    --checkpoint artifacts/run1/best.pt --host 0.0.0.0 --port 8089
```

Endpoints:

| endpoint | use |
|---|---|
| `POST /waf/decision` | enforcement: raw HTTP request or JSON record in → **200 allow / 403 block / 429 challenge** + `X-WAF-Score`, `X-WAF-Action`, `X-WAF-Shadow-Action` |
| `POST /score` | score only, never enforces |
| `GET /` `GET /dashboard` | demo page / monitoring |
| `GET /health` `GET /stats` `POST /reload` | ops |

Wire it into Nginx with **`infra/nginx/waf_enforcement.conf`** (`auth_request`
snippet included; Kong/Envoy ext-authz is the same shape).

```bash
# smoke test:
curl -sS -D- --data-binary @sample.raw http://127.0.0.1:8089/waf/decision
```

### 5b. The streaming consumer (Kafka-style)

```bash
python3 -m waf_transformer.pipeline.consumer --once          # drain backlog
python3 -m waf_transformer.pipeline.consumer --follow        # production
python3 -m waf_transformer.pipeline.consumer --follow --broker kafka --brokers kafka:9092
```

In-topic `http.requests.raw` → out-topic `http.requests.decisions` +
audit JSONL `data/decisions/decisions-YYYY-MM-DD.jsonl`. At-least-once;
offsets commit after persist.

---

## 6. Turning it from observer to enforcer (Steps 13–14)

`config/scope.toml`:

```toml
[enforcement]
mode = "shadow"          # -> "challenge" -> "block"
block_above = 0.9        # >= this: block (403)
challenge_above = 0.6    # >= this: challenge (429)
enforce_percent = 100    # staged rollout: 5 -> 25 -> 50 -> 100
```

The ladder (details in `docs/13_shadow_rollout.md`, `docs/14_blocking_rollout.md`):

1. **shadow** (default) — watch `shadow would-block` in the nightly reports
   for false positives; let it run a week against real traffic;
2. **challenge** — CAPTCHA/rate-limit only, never hard 403;
3. **block + enforce_percent = 5** — canary;
4. ramp `enforce_percent` while `make monitor-run` stays quiet;
5. **block, 100%** — steady state.

Each step is one file edit, picked up on the **next request** (or
`POST /reload`). Rollback is the same edit in reverse.

---

## 7. Operating it day to day (Steps 11, 15, 19)

```cron
# crontab — nightly analysis + monitoring
10 2 * * *  cd /srv/waf_transformer && bash scripts/run_nightly.sh
```

- **`make batch-run`** — the day's decisions → report, would-block watchlist,
  and `candidates.jsonl` (new training data).
- **`make monitor-run`** — dashboard + drift: volume spikes, score-distribution
  drift (PSI), false-positive watchlist growth, latency vs budget. Alerts are
  plain-English in `data/reports/dashboard-<day>.md` and `monitor.json`.
- **`/dashboard`** on the gateway — live counters whenever you want a look.

Rule of thumb: if **alerts** fire, check the watchlist before ramping
enforcement; if **drift** persists for days, retrain.

---

## 8. Improving the model (Steps 16, 20)

### Retrain with what production taught you

```bash
make model-retrain
# 1) exports an analyst queue from data/batch/candidates.jsonl, then STOPS
# 2) human fills the queue (docs/05_labeling.md), review merge -> corrections
# 3) re-run the script: relabel -> rebuild splits -> train artifacts/run2 -> evaluate
```

Promote `run2/best.pt` only if the eval report beats the current model; then
restart the gateway/consumer. Every decision records `model_version`, so the
cutover is auditable.

### Get under the latency budget (edge deployment)

```bash
make model-distill     # teacher -> ~0.4M-param student (artifacts/distill/student.pt)
```

On this class of CPU the student is **p99 6.7 ms eager / 3.8 ms JIT** vs the
teacher's ~21–23 ms — i.e. the student is how the 10 ms budget is met. Serve
with `--checkpoint artifacts/distill/student.pt`. Caveat: re-distill on the
full dataset before real promotion (`docs/20_distillation.md`).

---

## 9. Where things live

```
config/scope.toml       THE contract: budget, tokenizer, training, enforcement thresholds
waf_transformer/
  data/                 fetch, parse, generate, label, review, build dataset
  modeling/             tokenizer, encoder, train/eval/benchmark/export/distill
  engine/               policy (thresholds, hot-reload, rollout) + detector (request -> decision)
  pipeline/             broker, stream consumer, nightly batch, monitor, gateway bridge
docs/                   decision records 01–20 + this guide
infra/                  docker-compose (Kafka/MinIO/Postgres), filebeat, nginx enforcement
artifacts/              run1/best.pt (teacher), distill/student.pt, model.onnx
data/reports/           committed reports: quality, latency, dataset, monitor
scripts/                run_data_pipeline.sh, demo_streaming.sh, run_nightly.sh, run_retrain.sh
```

---

## 10. Troubleshooting

| symptom | fix |
|---|---|
| gateway returns 400 | body wasn't parseable HTTP or valid JSON record — check `Content-Type: application/json` for records |
| everything is `allow` with `shadow_action` set | you're in shadow mode — that's by design; follow §6 to enforce |
| `challenge` where you expect `block` | `mode = "challenge"` maps blocks→challenges; use `mode = "block"` |
| latency alerts (p95 over budget) | expected on small CPUs with the teacher; deploy the student (`make model-distill`) or more cores; tokenization is negligible (~0.01 ms) |
| training OOMs | keep `max_len = 384`, `torch.set_num_threads(2)`, effective batch 32 via grad accumulation (already in config) |
| tests skip 5 cases | torch isn't installed in that interpreter — run with `.venv/bin/python` |
| want to change thresholds mid-traffic | edit `config/scope.toml`, done — next request uses them (`/health` shows the live policy) |
| drifted / novel attacks slipping through | `make monitor-run` (drift), then `make model-retrain` (feed it the watchlist) |
| attacks with stripped headers score low | known limitation (model_report addendum) — real traffic has full headers; add header-ablated variants via `make model-retrain` |

---

## 11. Status & what's next

All 20 plan steps are implemented (see the README table). Deliberately *not*
built yet: a model registry, automatic rollback, and scheduled CI training —
the contracts they'd plug into are documented in `docs/18_mlops.md`. The v1
scope excludes websocket/gRPC stream bodies (`docs/17_edge_cases.md`).
