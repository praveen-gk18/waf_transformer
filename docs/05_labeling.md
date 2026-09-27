# Step 5 — Labeling Protocol

**Status: implemented** (`label.py`, `review.py`, `build_dataset.py`).
This document is the operating procedure; the code enforces it.

## Label model

Every record carries a `label` with provenance:

| Field | Values | Meaning |
|---|---|---|
| `class` | `benign` / `attack` / `unknown` | binary ground truth for v1 |
| `attack_category` | `sql_injection`, `xss`, … , `untyped`, `null` | family metadata |
| `attack_technique` | `union_sql`, `dom_xss`, … , `null` | fine-grained; also seeds the unseen-technique holdout |
| `label_source` | `manual` / `waf_export` / `dataset` / `synthetic` / `heuristic` / `unknown` | who said so |
| `confidence` | 0.0–1.0 | 1.0 for dataset/manual; 0.6–0.9 for heuristics |

**Priority when sources disagree** (highest wins):
`manual > waf_export > dataset > synthetic > heuristic > unknown`.

## Automated labeling (first pass)

1. **Dataset-provided labels** — CSIC `Valid/Attack`, ECML's 8-class labels
   (`dataset`, confidence 1.0).
2. **WAF block export** — anything a real WAF blocked → `attack`
   (`waf_export`), family typed by heuristics where possible.
3. **Heuristic rules** (`label.py`) — decoded-pattern detectors (SQLi/XSS
   first, other families typed for completeness). Two roles:
   - **enrich** untyped attacks (CSIC) with family/technique;
   - **label** fully unlabelled logs, `label_source=heuristic`.
   Strong signals (e.g. `UNION…SELECT`, `<script`, `onerror=`, `SLEEP(`) score
   0.9; weak signals (bare comments, `alert(`) 0.6. **Anything with no signal
   stays `unknown` — never silently "benign".**

## Manual review (second pass) — the workflow

```bash
# 1. draw a stratified sample: 40 per (source × label) stratum, seeded
python3 -m waf_transformer.data.review sample \
    --input data/interim/labeled.jsonl --out data/review/review_queue.csv

# 2. analysts fill reviewer_class (benign|attack|unsure) + reviewer_category
#    + reviewer_notes in the CSV

# 3. merge; returns agreement stats + corrections file
python3 -m waf_transformer.data.review merge \
    --queue data/review/review_queue.csv --out data/review/corrections.jsonl

# 4. relabel with corrections applied (label_source becomes "manual")
python3 -m waf_transformer.data.label --input data/interim/unified.jsonl \
    --out data/interim/labeled.jsonl --corrections data/review/corrections.jsonl
```

Review rules:

- **`unsure` is a first-class verdict** — it removes the row from training
  rather than forcing a coin flip.
- Reviewers see the full request preview, never just the payload.
- The **weird-but-benign tripwires** from `scope.toml` (apostrophe product
  names, SQL words in prose, unicode searches) are must-agree rows: if the
  sample contains them and reviewers mark them attack, the *heuristics* or
  reviewer guidance get fixed — these are exactly the false positives that
  hurt in production.
- `merge` reports **agreement rate** (auto vs. manual) per source — a direct
  measurement of automated-label noise, which the plan calls out as the
  reason automated labels can't be trusted blindly.

## Class balance (the 5–10% rule)

The plan: *"aim for a dataset where at least 5–10% of samples are attacks…*
*oversample the attack data during training."* Implemented as a **floor +
resample policy** in `build_dataset.py` (see `[dataset]` in scope.toml):

- Real traffic is ~0.1% attacks → **oversample attacks up to 8%** in train
  (duplicates flagged `meta.oversampled`, ids suffixed `#ovN`).
- Public corpora run ~25–30% attacks → floor is already satisfied; **nothing
  is resampled or thrown away**.
- **Val/test are never rebalanced** — evaluation must reflect the real
  distribution, or precision/recall numbers lie.

## Split hygiene (Step 8's "don't leak")

- Splits are **group-aware**: session cookie → client IP → generator family
  → record id (in that order; `dataset.group_key_priority`). One session's
  shopping spree, one attacker's campaign, one payload template's mutations
  land in exactly one split.
- The builder **hard-fails** (`LeakageError`) if any group straddles splits,
  and re-audits after the holdout carve-out. The audit result is recorded in
  `stats.json` (`leakage_audit: "passed"`).
- Holdout techniques (`time_based_sql`, `dom_xss` by default) are carved out
  *before* splitting into `test_unseen.jsonl.gz` — the Step-9 unseen-attack
  evaluation set, untouchable during training. **Quarantine rule**: any record
  sharing a session/source/generator group with a holdout attack is excluded
  from the main splits entirely, so an attacker campaign can't teach the model
  its "unseen" technique's fingerprint via a sibling request.

## Dataset artifacts

| File | Committed? | Contents |
|---|---|---|
| `data/processed/{train,val,test}.jsonl.gz` | no (regenerable) | final splits |
| `data/processed/test_unseen.jsonl.gz` | no | unseen-technique holdout |
| `data/processed/splits_index.json` | no | group → split map for audits |
| `data/processed/stats.json` | copy in `data/reports/` | every count in this doc |
| `data/reports/dataset_report.md` | **yes** | human-readable build report |
| `data/samples/preview.jsonl` | **yes** | schema examples for eyeballing |
