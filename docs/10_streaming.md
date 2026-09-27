# Step 10 — Streaming Pipeline

## Architecture

```
web server / gateway ──publish──▶ broker ──consume──▶ detector ──publish──▶ broker
 (nginx, filebeat,      http.requests.raw   tokenize → model →            http.requests.decisions
  app, crawler)         (Kafka topic /      allow/block/challenge         + audit JSONL
                        file-backed)        within latency budget
```

The plan:

> *"Write a script that subscribes to your message broker (Kafka, Redis
> Streams, or cloud pub/sub). For each message: decode the request, tokenize
> it, run the model, and make an allow/block/challenge decision within your
> latency budget. Push the decision to another topic or database for audit."*

## Components

- **`waf_transformer/pipeline/broker.py`** — `MessageBroker` abstraction with
  two backends: `file` (JSONL topics + consumer-group offsets; used for tests,
  demos, single-box deployments) and `kafka` (via `kafka-python`, same
  interface, at-least-once). Select with `--broker kafka --brokers host:port`.
- **`waf_transformer/pipeline/consumer.py`** — `StreamConsumer`:
  in-topic `http.requests.raw` → tokenize → model → policy decision →
  out-topic `http.requests.decisions` **and** an append-only audit log
  `data/decisions/decisions-YYYY-MM-DD.jsonl`. Offsets are committed only
  after the decision is persisted (at-least-once; a reprocessed message
  simply produces a second audit entry).
- **`waf_transformer/engine/detector.py`** — loads the Phase-3 checkpoint
  **once**; `evaluate(record)` returns a `Decision` (score, action,
  shadow_action, policy+model versions, per-request latency).

## Usage

```bash
# single pass (drain whatever is queued — good for cron-ish loops)
python3 -m waf_transformer.pipeline.consumer --once

# follow the topic; exit after 3s idle (good for demos)
python3 -m waf_transformer.pipeline.consumer --follow --idle-exit 3

# real Kafka instead of the file broker
python3 -m waf_transformer.pipeline.consumer --follow --broker kafka --brokers kafka:9092
```

End-to-end demo (also generates a day of synthetic traffic):

```bash
bash scripts/demo_streaming.sh
```

## Latency budget

Per-request `latency_ms` (tokenize + forward + policy) is recorded on every
decision; the consumer prints p50/p95/p99 at exit and the nightly job (Step 11)
tracks them against `config/scope.toml [latency]`. See
`data/reports/latency_report.md` for the capacity-planning reality: the model
itself is ~14 ms/call on the dev sandbox CPU (budget: p99 ≤ 10 ms), so a
streaming deployment needs server-class cores / intra-op parallelism or the
planned distillation (Step 20) — the pipeline itself adds sub-millisecond
overhead.

## Failure semantics

- Unparseable messages → `parse_errors` counter + logged line, never crash the
  consumer.
- Missing checkpoint → fail fast at startup.
- Broker offsets make replay safe: re-running `--once` after a crash
  reprocesses only uncommitted messages.
