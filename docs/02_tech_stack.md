# Step 2 — Tech Stack Decisions

**Status: decided.** This is the Week-1–2 stack contract; nothing here is
deployed yet, but everything chosen is representable in `infra/` and runnable
without rewriting the data pipeline.

## Decisions and rationale

| Concern | Choice | Why | Alternative if scale says no |
|---|---|---|---|
| Message broker | **Apache Kafka** (single broker locally, KRaft) | Industry standard, replayable streams = shadow-mode gold (Phase 5 re-reads raw traffic), log retention doubles as raw-log storage | RabbitMQ if we stay small and never need replay |
| Batch processing | **Python batch jobs first**, Spark-ready layout | Our data volumes (weeks of HTTP logs) fit scheduled Python; jobs read/write JSONL so a Spark port is mechanical | Spark when a single node can't finish the nightly job in the window |
| Model framework | **PyTorch** | Research ecosystem, easier debugging, exports cleanly to ONNX | TensorFlow only if org-standard |
| Model serving | **ONNX Runtime first**, Triton if multi-model | Fastest path to the <10 ms p99 budget on CPU; TorchServe if we want PyTorch-native | Triton when several models/versions share infra |
| Raw log storage | **MinIO locally / S3 in prod** | Cheap immutable storage for full requests (Step 3 needs *full* request detail) | GCS/Azure blob equivalents |
| Labels + results | **PostgreSQL** | Labels, review workflow state, decision audit log — transactional and queryable | Elasticsearch if we need log-search UX |
| Monitoring | Prometheus + Grafana | p50/p95/p99 latency, block rate, score histograms (Step 15) | — |
| Orchestration (batch + retrain) | **cron now, Airflow later** | Plan's own guidance; the nightly job is one entry point (`make data-pipeline`) | Airflow/Dagster when retraining becomes multi-step |

## How this shapes the repo now (Phases 1–2)

- **The data pipeline is pure stdlib Python** — it must run anywhere (dev
  laptops, CI, the training box) without conda/docker. Dependencies arrive
  with Phase 3 (PyTorch).
- `infra/docker-compose.yml` stands up the Kafka/MinIO/Postgres triad plus an
  OpenResty log emitter and Filebeat shipper — the Step-3 collection path.
- On-disk interchange is **JSONL** (optionally gzipped): trivially consumable
  from Python, Spark, and notebooks alike.

## Serving-side latency plan (ties to the budget in `scope.toml`)

1. Tokenizer: precompiled vocab, C/Rust-backed BPE via ONNX-free path
   (budget 1.5 ms).
2. Encoder: 4–6 layers, d_model 256–512, 8 heads (Step 7) → ONNX int8
   quantized if p99 > 5 ms.
3. Decision: config-file thresholds (`[enforcement]`), no model redeploy to
   tune (Step 12).
