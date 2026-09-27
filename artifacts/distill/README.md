# artifacts/distill — distilled student model (Step 20)

Produced by `python3 -m waf_transformer.modeling.distill` (Makefile: `make
model-distill`). The student is a 2-layer / d128 / 4-head / FF512 encoder
(~0.4M params vs the teacher's 3.4M) trained on the teacher's soft targets
plus hard labels (`alpha = 0.5`), saved in the SAME checkpoint schema as
`run1/best.pt` — `Detector`, `benchmark`, `predict` and `export_onnx` load it
unchanged via `--checkpoint artifacts/distill/student.pt`.

## Demo-run results (synthetic demo data, 1,500 train samples, 2 epochs)

This was a **feasibility run** on the offline demo dataset — numbers are NOT
comparable to the full-data teacher (`data/reports/model_report.md`). The
recipe for a production student: run `model-distill` against the full
`data/processed/train.jsonl.gz` (Phase-2 build) with `--max-samples 0`.

- quality on demo val @0.5: student P 0.990 / R 0.993 / F1 0.990
  (teacher on same val: P 0.875 / R 0.914 / F1 0.894 — demo-val is easy)
- **single-request latency (100 real requests, sandbox CPU, budget p99 ≤ 10 ms):**
  - eager: **p99 6.696 ms — WITHIN BUDGET** (teacher was 23.1 ms)
  - torch.jit frozen: **p99 3.844 ms — WITHIN BUDGET** (teacher was 20.7 ms)
  - torchao int8: p99 14.672 ms (slower — same finding as the teacher ladder)
  - onnxruntime: p99 36.561 ms (prefer jit on CPU; re-export if targeting ORT GPU)

`report.json` in this directory holds the training history + batched latency.

**This is how the 10 ms p99 budget is met on modest hardware** — the full-size
model stays the quality reference (`artifacts/run1/best.pt`); the student is
the deployable edge variant. Serve it with:

```bash
python3 -m waf_transformer.pipeline.gateway --checkpoint artifacts/distill/student.pt
```
