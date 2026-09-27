#!/bin/sh
# Phase-2 end-to-end data pipeline (Steps 3–5).
#
#   sh scripts/run_data_pipeline.sh full   # public corpora + synthetic (default)
#   sh scripts/run_data_pipeline.sh demo   # synthetic only, no network
#
# Steps: fetch -> generate -> ingest -> label -> review-sample -> build -> report.
# Every step is idempotent and re-runnable; outputs land under data/ (gitignored
# except data/reports/ and data/samples/).
set -eu

MODE="${1:-full}"
SEED="${SEED:-20260927}"
PY="${PY:-python3}"

echo "== waf_transformer data pipeline [$MODE] =="

if [ "$MODE" = "full" ]; then
    echo "-- Step 4a: fetch public corpora (CSIC 2010, ECML/PKDD 2007)"
    $PY -m waf_transformer.data.fetch_datasets --dest data/raw || {
        echo "WARNING: corpus fetch failed; continuing with synthetic sources only." >&2
    }
fi

echo "-- Step 4b: generate synthetic attack + normal traffic"
$PY -m waf_transformer.data.generate_attacks --out data/raw/synthetic/attacks.jsonl --count 5000 --seed "$SEED"
$PY -m waf_transformer.data.synthesize_normal --out data/raw/synthetic/normal.jsonl --count 3000 --seed "$SEED"

echo "-- Ingest: unify raw sources -> data/interim/unified.jsonl"
$PY -m waf_transformer.data.ingest --raw-dir data/raw --out data/interim/unified.jsonl

echo "-- Step 5: label (dataset + synthetic + heuristics -> data/interim/labeled.jsonl)"
$PY -m waf_transformer.data.label --input data/interim/unified.jsonl --out data/interim/labeled.jsonl

echo "-- Step 5: draw manual-review queue -> data/review/review_queue.csv"
$PY -m waf_transformer.data.review sample --input data/interim/labeled.jsonl --out data/review/review_queue.csv

echo "-- Export schema preview -> data/samples/preview.jsonl (committed)"
$PY -m waf_transformer.data.export_samples --input data/interim/labeled.jsonl --out data/samples/preview.jsonl

echo "-- Steps 5/8: build leak-free splits -> data/processed/"
$PY -m waf_transformer.data.build_dataset --input data/interim/labeled.jsonl --out-dir data/processed

echo "-- Report -> data/reports/dataset_report.md"
$PY -m waf_transformer.data.report --stats data/processed/stats.json --manifest data/raw/MANIFEST.json --out-dir data/reports

echo "== done =="
