# artifacts/ — trained model release artifacts

Unlike `data/` (gitignored, regenerable), the **trained model is a release
artifact and is committed** — it is the deliverable of Phase 3 and cannot be
regenerated without a training run. When a model registry exists (Phase 4+),
move storage there and re-ignore this directory.

| File | What it is |
|---|---|
| `run1/best.pt` | **serving checkpoint** — currently the promoted run2 model (weights + specs + val metrics + operating threshold) |
| `run1/history.json` | per-epoch training curve of the original Phase-3 run |
| `run1/summary.json` | selected-epoch summary (original Phase-3 run) |
| `run2/` | Step-16 retrain artifacts (history, summary, checkpoint copy) — see model_report addendum |
| `model.onnx` | ONNX export of the serving checkpoint (dynamic axes, ONNX Runtime) |
| `distill/` | Step-20 distilled student (edge deployment) + its report |
| `eval/eval.json` | evaluation results of the serving checkpoint (test / unseen / adversarial) |

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
