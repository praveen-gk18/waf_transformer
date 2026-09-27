#!/usr/bin/env bash
# Step 10 demo end-to-end: publish traffic -> consume + detect + decide -> nightly batch.
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PYTHON:-python3}

echo "== 1. publish a synthetic traffic burst to the broker =="
$PY - <<'EOF'
from waf_transformer.data.generate_attacks import make_attack_records
from waf_transformer.data.synthesize_normal import make_normal_records
from waf_transformer.pipeline.broker import build_broker

br = build_broker("file")
recs = make_normal_records(10, seed=20260927) + make_attack_records(8, seed=20260927)
for rec in recs:
    br.publish("http.requests.raw", rec.to_json())
print(f"published {len(recs)} requests to http.requests.raw")
EOF

echo "== 2. consume -> tokenize -> model -> allow/block/challenge =="
$PY -m waf_transformer.pipeline.consumer --once

echo "== 3. nightly batch: deeper analysis + new training data =="
$PY -m waf_transformer.pipeline.batch

echo "done. see data/decisions/ (audit) and data/batch/ (report + candidates)."
