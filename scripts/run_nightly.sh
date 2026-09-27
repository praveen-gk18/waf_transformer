#!/usr/bin/env bash
# Nightly batch job (Step 11) — cron/Airflow entry point.
#   10 2 * * *  cd /srv/waf_transformer && bash scripts/run_nightly.sh
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PYTHON:-python3}
DAY=${1:-$(date +%F)}

echo "nightly batch for ${DAY}"
$PY -m waf_transformer.pipeline.batch --day "$DAY"
