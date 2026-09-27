# artifacts/ — trained model release artifacts

Unlike `data/` (gitignored, regenerable), the **trained model is a release
artifact and is committed** — it is the deliverable of Phase 3 and cannot be
regenerated without a training run. When a model registry exists (Phase 4+),
move storage there and re-ignore this directory.

| File | What it is |
|---|---|
| `run1/best.pt` | best checkpoint (model weights + tokenizer/model specs + val metrics + operating threshold) |
| `run1/history.json` | per-epoch training curve (loss, val precision/recall/F1, operating point) |
| `run1/summary.json` | selected-epoch summary |
| `model.onnx` | ONNX export (single file, dynamic axes, for ONNX Runtime serving) |
| `eval/eval.json` | Step-9 evaluation results (test / unseen-technique / adversarial) |

Note: ORT int8 quantization and torch dynamic int8 were both benchmarked —
see `data/reports/latency_report.md` for why neither ships as an artifact here
(slow/unsupported on the current torch release and CPU); `model.onnx` is the
serving artifact.

Regenerate with:

```bash
make model-train model-evaluate model-export
```

Every run is seeded from `config/scope.toml [training]` — training data,
sampling, and batch order are deterministic.
