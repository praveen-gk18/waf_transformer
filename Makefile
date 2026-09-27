# waf_transformer — Phase 1–3 workflow targets
PY := python3
# Phase-3 targets need torch; prefer the local venv when it exists.
PY_MODEL := $(shell test -x .venv/bin/python && echo .venv/bin/python || echo python3)
SEED := 20260927

.PHONY: test data-fetch data-synth data-ingest data-label data-review-sample data-samples data-build data-report data-pipeline data-demo clean-data model-train model-evaluate model-export model-benchmark model-demo

test:
	$(PY) -m unittest discover -s tests -v

# ---- Phase 2 data pipeline (each step is independently runnable) ----
data-fetch:
	$(PY) -m waf_transformer.data.fetch_datasets --dest data/raw

data-synth:
	$(PY) -m waf_transformer.data.generate_attacks --out data/raw/synthetic/attacks.jsonl --count 5000 --seed $(SEED)
	$(PY) -m waf_transformer.data.synthesize_normal --out data/raw/synthetic/normal.jsonl --count 3000 --seed $(SEED)

data-ingest:
	$(PY) -m waf_transformer.data.ingest --raw-dir data/raw --out data/interim/unified.jsonl

data-label:
	$(PY) -m waf_transformer.data.label --input data/interim/unified.jsonl --out data/interim/labeled.jsonl

data-review-sample:
	$(PY) -m waf_transformer.data.review sample --input data/interim/labeled.jsonl --out data/review/review_queue.csv

data-samples:
	$(PY) -m waf_transformer.data.export_samples --input data/interim/labeled.jsonl --out data/samples/preview.jsonl

data-build:
	$(PY) -m waf_transformer.data.build_dataset --input data/interim/labeled.jsonl --out-dir data/processed

data-report:
	$(PY) -m waf_transformer.data.report --stats data/processed/stats.json --manifest data/raw/MANIFEST.json --out-dir data/reports

# Full Phase-2 run: public corpora + synthetic -> labeled, split, reported.
data-pipeline:
	sh scripts/run_data_pipeline.sh full

# Offline smoke run: synthetic sources only (no network).
data-demo:
	sh scripts/run_data_pipeline.sh demo

clean-data:
	rm -rf data/raw data/interim data/processed data/review

# ---- Phase 3 model pipeline (Steps 6–9) ----
model-train:
	$(PY_MODEL) -m waf_transformer.modeling.train --train data/processed/train.jsonl.gz --val data/processed/val.jsonl.gz --out artifacts/run1

model-evaluate:
	$(PY_MODEL) -m waf_transformer.modeling.evaluate --checkpoint artifacts/run1/best.pt --test data/processed/test.jsonl.gz --unseen data/processed/test_unseen.jsonl.gz

model-export:
	$(PY_MODEL) -m waf_transformer.modeling.export_onnx --checkpoint artifacts/run1/best.pt

model-benchmark:
	$(PY_MODEL) -m waf_transformer.modeling.benchmark --checkpoint artifacts/run1/best.pt

model-demo:
	$(PY_MODEL) -m waf_transformer.modeling.predict --checkpoint artifacts/run1/best.pt --request "GET /tienda1/publico/caracteristicas.jsp?idA=2'+UNION+SELECT+password+FROM+users-- HTTP/1.1\nHost: shop.example.local\nCookie: JSESSIONID=ABC\nConnection: close"

# ---- Phase 4 streaming / batch / enforcement (Steps 10–12) ----
# End-to-end: publish -> detect -> decide -> nightly batch.
stream-demo:
	sh scripts/demo_streaming.sh

# Enforcement bridge (live): GET / demo page, POST /waf/decision, /health, /stats.
gateway-serve:
	$(PY_MODEL) -m waf_transformer.pipeline.gateway

batch-run:
	$(PY) -m waf_transformer.pipeline.batch

# ---- Phase 5/6: rollout, monitoring, retraining, distillation (Steps 13–20) ----
monitor-run:
	$(PY) -m waf_transformer.pipeline.monitor

model-retrain:
	sh scripts/run_retrain.sh

model-distill:
	$(PY_MODEL) -m waf_transformer.modeling.distill --out artifacts/distill
