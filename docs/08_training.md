# Step 8 — Training

**Status: implemented** (`waf_transformer/modeling/train.py`, `losses.py`,
`data.py`, `metrics.py`). Config: `[training]` in `config/scope.toml`.

## Data

The Phase-2 build already made the plan's split decisions real:

* **70/15/15, group-aware** — no session/attacker-IP/payload-template leaks
  across splits (hard-failed build otherwise).
* **Train at 21.6% attack** — the plan's 5–10% attack floor is satisfied a
  priori by public corpora; no artificial resampling. Val/test stay natural.
* `test_unseen.jsonl.gz` never touches training (Step 9's evaluation set).

Run settings (this sandbox: 2 CPU cores, 3 GB RAM — recorded so results are
reproducible):

| Setting | Value | Note |
|---|---|---|
| train records | 12,000 stratified | of 98,204; `max_train_records=0` trains on all |
| epochs | 3 (early stop patience 2) | selection on val F1 |
| batch | ≤ 32, length-bucketed, memory-capped | attention is O(L²); long batches shrink |
| optimizer | AdamW, lr 5e-4, wd 0.01 | cosine decay, 6% warmup |
| grad clip | 1.0 | |

## Loss: class-weighted BCE (focal available)

The plan: *"binary cross-entropy loss… use class weighting or focal loss."*
Default is **BCE-with-logits + `pos_weight = n_benign/n_attack`** (auto from
the train split); `--loss focal` switches to sigmoid focal loss (γ=2, α=0.25)
for harder imbalance. Both unit-tested (`tests/test_model.py`).

## What we monitor (the plan's core warning)

> *"A model that labels everything 'safe' will have 99.9% accuracy but is
> useless."*

Every epoch reports **precision and recall separately** (never accuracy
alone), at two operating points:

1. **threshold 0.5** — the reporting default.
2. **operating point** — highest precision with recall ≥ 0.95
   (`threshold_for_min_recall`), selected on val and saved into the
   checkpoint. This encodes *"high recall while keeping precision
   acceptable"* into the artifact itself; Phase 5 tunes the same knob against
   live shadow-mode traffic.

Model selection: best val F1 @ 0.5 (`artifacts/run1/best.pt`), with
`history.json` + `summary.json` logged for the training curve.

## Reproduce

```bash
make model-train    # reads config/scope.toml [training] + data/processed/
```

Deterministic per seed (record sampling, init, batch order). The only
environment caveat: CPU-vs-GPU floating point drift.
