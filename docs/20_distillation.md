# Step 20 — Distillation

The plan: *"If the latency budget is hard to meet, distill the model into a
smaller one."* Step 9's benchmark said the truth plainly: every full-size
variant misses p99 ≤ 10 ms on modest CPUs. Distillation is the fix.

## Method

`waf_transformer/modeling/distill.py` (Makefile: `make model-distill`) trains
a **student** — 2 layers / d128 / 4 heads / FF512, ~0.4M params (vs 3.4M) —
on a mix of the teacher's soft targets and hard labels:

```
loss = α · BCE(student, sigmoid(teacher_logit))  +  (1−α) · BCE(student, label)
```

The student checkpoint uses the **same schema** as `run1/best.pt`, so
`Detector` / `benchmark` / `predict` / `export_onnx` load it unchanged.

## Results (demo run — `artifacts/distill/`)

Feasibility run on the offline synthetic demo set (1,500 samples, 2 epochs,
~2 min on the sandbox CPU). Single-request latency (100 requests, budget
p99 ≤ 10 ms):

| variant | teacher p99 | student p99 | within budget? |
|---|---|---|---|
| eager | 23.1 ms | **6.7 ms** | ✅ student |
| torch.jit frozen | 20.7 ms | **3.8 ms** | ✅ student |
| torchao int8 | 32.3 ms | 14.7 ms | ❌ (int8 slow on this CPU) |
| onnxruntime | 22.9 ms | 36.6 ms | ❌ (prefer jit on CPU) |

**The student meets the Phase-1 latency contract on the same hardware where
the teacher misses it** — and quality was preserved on the demo val set
(student F1 0.990 vs teacher 0.894 there; demo-val is easy, see the caveat).

## Honest caveats

- The demo numbers come from the **synthetic demo dataset**. A production
  student must be distilled on the full Phase-2 split
  (`--max-samples 0`) and gated by the Step-16 evaluation bar before promotion.
- Soft-label distillation on a 2-core box is tractable because the student is
  tiny; budget minutes, not hours.

## Serving the student

```bash
python3 -m waf_transformer.pipeline.gateway --checkpoint artifacts/distill/student.pt
# or stream:
python3 -m waf_transformer.pipeline.consumer --follow --checkpoint artifacts/distill/student.pt
```

Deployment rule of thumb: **teacher for the origin/central WAF** (server-class
CPU, quality first), **student for edge boxes and CPU-constrained hosts**.
