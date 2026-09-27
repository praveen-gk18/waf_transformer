# Step 9 — Evaluate and Harden

**Status: implemented** (`waf_transformer/modeling/evaluate.py`,
`benchmark.py`, `export_onnx.py`). Config: `[evaluation]` in `scope.toml`.
Results: `data/reports/model_report.md` + `data/reports/latency_report.json`.

## The three evaluation surfaces

1. **Main test split** (21k records, never trained on) — precision/recall/F1
   at 0.5 and at the operating threshold, FPR (the false-alarm number that
   costs real users), and **recall broken down by attack category**
   (untyped / sql_injection / xss).
2. **Unseen-technique holdout** — `test_unseen.jsonl.gz` (time_based_sql +
   dom_xss + campaign-quarantined siblings; ~2.5k attacks). These attack
   *techniques* never appear in train/val by construction. This is the plan's
   *"test against attacks the model has never seen"*.
3. **Adversarial variants** — test attacks re-encoded with an extra
   URL-encoding layer (obfuscation beyond anything training saw). The gap to
   surface 1 quantifies evasion risk; the plan's remedy (retrain on fooled
   examples — adversarial training) is the follow-up if recall collapses.

## Latency: benchmark against the Phase-1 budget

`benchmark.py` measures tokenize → forward → decision at batch 1 on real
test requests and reports p50/p95/p99 per variant:

| Variant | What it tests |
|---|---|
| eager | plain PyTorch (the honest baseline) |
| jit | `torch.jit.trace` |
| quantized | dynamic int8 (Linear) |
| onnx | ONNX Runtime (`artifacts/model.onnx`) |

Budget: **p99 ≤ 10 ms end-to-end** (`scope.toml [latency_budget]`). If eager
misses it — expected on a 2-core sandbox CPU — the ladder above is exactly the
plan's optimization path (quantization, ONNX Runtime; distillation next if
still short). Numbers are hardware-dependent; the *report* is what production
capacity planning uses.

## Optimization / export

```bash
make model-export    # artifacts/model.onnx (single-file, dynamic axes)
make model-benchmark # latency table vs budget
```

`artifacts/model.onnx` is the Phase-4 serving artifact (ONNX Runtime per
docs/02_tech_stack.md). Notes from this run's ladder: ORT's int8 quantizer
hits a shape-inference bug on this exporter's graph, and torch-2.14's
`torch.ao.quantization` shim is broken mid-migration to torchao — dynamic
int8 works via `torchao.quantization.quantize_` but is *slower* on CPUs
without fast-int8 kernels (measured; see `latency_report.md`). Always
benchmark the ladder on the target hardware before assuming quantization
helps.

## Decision thresholds are NOT baked into the model

`predict.py` applies `[enforcement]` (block > 0.9, challenge > 0.6) from
config — configurable without redeploying the model (the plan's Step 12
requirement, honored from day one).
