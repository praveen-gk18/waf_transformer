#!/usr/bin/env bash
# Step 16 — the retraining loop: live traffic -> analyst review -> dataset -> train.
#
#   1. Export the analyst queue from the batch job's candidates (or any JSONL).
#   2. HUMAN fills the queue (docs/05_labeling.md), producing a corrections file.
#   3. Corrections are merged into the labeled corpus and the dataset rebuilt.
#   4. Retrain + evaluate + (optional) export.
#
# Usage:
#   bash scripts/run_retrain.sh data/batch/candidates.jsonl
#
# The script stops after step 1 if no corrections exist yet — re-run it after
# the analyst finishes (`review merge`). Nothing is destructive: dataset build
# writes to data/processed/ (regenerable), training to artifacts/run2/.
set -euo pipefail
cd "$(dirname "$0")/.."
PY_MODEL=${PYTHON:-$(test -x .venv/bin/python && echo .venv/bin/python || echo python3)}
CANDIDATES=${1:-data/batch/candidates.jsonl}
QUEUE=data/review/queue_live.csv
CORR=data/interim/corrections_live.jsonl

if [ ! -f "$CANDIDATES" ]; then
  echo "no candidates at ${CANDIDATES} — run the nightly batch first (make batch-run)" >&2
  exit 1
fi

echo "== 1. export analyst queue =="
$PY_MODEL -m waf_transformer.data.review sample --input "$CANDIDATES" --out "$QUEUE" --per-stratum 40
echo "   queue: ${QUEUE}"

if [ ! -f "$CORR" ]; then
  echo "== 2. analyst review needed =="
  echo "   Fill ${QUEUE} (docs/05_labeling.md), then run:"
  echo "   $PY_MODEL -m waf_transformer.data.review merge --queue ${QUEUE} --out ${CORR}"
  echo "   and re-run this script."
  exit 0
fi

echo "== 2. merge corrections into corpus =="
$PY_MODEL -m waf_transformer.data.review merge --queue "$QUEUE" --out "$CORR"
if [ -f data/interim/unified.jsonl ]; then
  $PY_MODEL -m waf_transformer.data.label --input data/interim/unified.jsonl \
    --corrections "$CORR" --out data/interim/labeled.jsonl
else
  echo "   (no data/interim/unified.jsonl — labeling corrections only)"
fi

echo "== 3. rebuild leak-free splits =="
$PY_MODEL -m waf_transformer.data.build_dataset

echo "== 4. retrain (artifacts/run2) + evaluate =="
$PY_MODEL -m waf_transformer.modeling.train \
  --train data/processed/train.jsonl.gz --val data/processed/val.jsonl.gz \
  --out artifacts/run2
$PY_MODEL -m waf_transformer.modeling.evaluate \
  --checkpoint artifacts/run2/best.pt \
  --test data/processed/test.jsonl.gz --unseen data/processed/test_unseen.jsonl.gz

echo "retrained. promote artifacts/run2/best.pt over artifacts/run1/best.pt when the"
echo "eval report beats the current model (then restart the gateway/consumer)."
