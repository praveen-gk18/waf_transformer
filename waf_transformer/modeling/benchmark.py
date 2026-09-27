"""Step 9 — inference latency benchmark vs the Phase-1 budget.

Measures the full per-request path at batch size 1 on realistic inputs:
tokenize -> forward -> sigmoid -> decision, reporting p50/p95/p99 in ms for
each variant:

* ``eager``          — plain PyTorch forward
* ``jit``            — torch.jit.trace + freeze (frozen params)
* ``int8_torchao``   — dynamic int8 via torchao (torch.ao shim is broken in 2.14)
* ``onnx``           — ONNX Runtime (if artifacts/model.onnx exists)

The budget: p99 ≤ 10 ms end-to-end (scope.toml). If a variant misses it, the
plan's remedies are quantization / distillation / ONNX Runtime — this tool
shows exactly how much each buys on the target CPU.

Usage::

    python3 -m waf_transformer.modeling.benchmark \
        --checkpoint artifacts/run1/best.pt \
        --data data/processed/test.jsonl.gz --samples 300
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import torch

from ..config import DEFAULT_CONFIG_PATH, load_config
from .data import load_records
from .metrics import percentile
from .model import build_model
from .tokenizer import VOCAB_SIZE, HttpByteTokenizer
from .evaluate import load_checkpoint


def bench_fn(fn, samples: list, warmup: int = 30) -> dict:
    for s in samples[:warmup]:
        fn(s)
    times = []
    for s in samples:
        t0 = time.perf_counter()
        fn(s)
        times.append((time.perf_counter() - t0) * 1000.0)
    return {
        "n": len(times),
        "p50_ms": round(percentile(times, 50), 3),
        "p95_ms": round(percentile(times, 95), 3),
        "p99_ms": round(percentile(times, 99), 3),
        "max_ms": round(max(times), 3),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Benchmark inference latency")
    ap.add_argument("--checkpoint", type=Path, default=Path("artifacts/run1/best.pt"))
    ap.add_argument("--data", type=Path, default=Path("data/processed/test.jsonl.gz"))
    ap.add_argument("--onnx", type=Path, default=Path("artifacts/model.onnx"))
    ap.add_argument("--out", type=Path, default=Path("data/reports/latency_report.json"))
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    ap.add_argument("--samples", type=int, default=300)
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    device = torch.device("cpu")
    torch.set_num_threads(2)
    model, _ = load_checkpoint(args.checkpoint, device)
    tokenizer = HttpByteTokenizer(cfg.tokenizer)

    recs = load_records(args.data, 0)[: args.samples]
    samples = [tokenizer.encode_record(r) for r in recs]
    print(f"benchmarking on {len(samples)} real requests (batch=1, cpu)")

    results = {"budget_ms": {"p50": cfg.latency.p50, "p95": cfg.latency.p95, "p99": cfg.latency.p99}}

    # tokenize-only cost (bytes -> ids)
    t_times = []
    for r in recs[: len(samples)]:
        t0 = time.perf_counter()
        tokenizer.encode_record(r)
        t_times.append((time.perf_counter() - t0) * 1000.0)
    results["tokenize"] = {
        "p50_ms": round(percentile(t_times, 50), 3),
        "p95_ms": round(percentile(t_times, 95), 3),
        "p99_ms": round(percentile(t_times, 99), 3),
    }

    def make_forward(m):
        def fn(s):
            ids = torch.tensor([s.ids], dtype=torch.long)
            mask = (ids != 0).long()
            with torch.no_grad():
                logit = m(ids, mask)
            return float(torch.sigmoid(logit))

        return fn

    results["eager"] = bench_fn(make_forward(model), samples)

    # JIT traced (params must be frozen or trace captures them as constants)
    try:
        for p in model.parameters():
            p.requires_grad_(False)
        with torch.no_grad():
            traced = torch.jit.trace(model, (torch.tensor([samples[0].ids]), (torch.tensor([samples[0].ids]) != 0).long()))
            traced = torch.jit.freeze(traced)
        results["jit"] = bench_fn(make_forward(traced), samples)
    except Exception as exc:  # noqa: BLE001
        results["jit"] = {"error": f"{type(exc).__name__}: {exc}"[:200]}

    # dynamic int8 via torchao (torch.ao.quantization.quantize_dynamic is a
    # broken shim in torch 2.14 — the migration to torchao is incomplete)
    try:
        from torchao.quantization import Int8DynamicActivationInt8WeightConfig, quantize_

        qmodel, _ = load_checkpoint(args.checkpoint, device)
        quantize_(qmodel, Int8DynamicActivationInt8WeightConfig())
        results["int8_torchao"] = bench_fn(make_forward(qmodel), samples)
    except Exception as exc:  # noqa: BLE001
        results["int8_torchao"] = {"error": f"{type(exc).__name__}: {exc}"[:200]}

    # ONNX Runtime
    if args.onnx.exists():
        try:
            import numpy as np
            import onnxruntime as ort

            sess = ort.InferenceSession(str(args.onnx), providers=["CPUExecutionProvider"])

            def ort_fn(s):
                ids = np.array([s.ids], dtype=np.int64)
                mask = (ids != 0).astype(np.int64)
                out = sess.run(None, {"ids": ids, "mask": mask})
                return float(1 / (1 + pow(2.718281828, -out[0][0])))

            results["onnx"] = bench_fn(ort_fn, samples)
        except Exception as exc:  # noqa: BLE001
            results["onnx"] = {"error": str(exc)}

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2) + "\n")

    budget_p99 = cfg.latency.p99
    lines = [
        "# Latency benchmark vs Phase-1 budget",
        "",
        f"_Generated by `python3 -m waf_transformer.modeling.benchmark` "
        f"({len(samples)} real requests, batch=1, {args.threads if hasattr(args, 'threads') else 2} CPU threads)._",
        "",
        f"Budget: p50 ≤ {cfg.latency.p50} ms, p95 ≤ {cfg.latency.p95} ms, **p99 ≤ {budget_p99} ms**.",
        "",
        "| variant | p50 ms | p95 ms | p99 ms | verdict |",
        "|---|---|---|---|---|",
    ]
    for variant in ("tokenize", "eager", "jit", "int8_torchao", "onnx"):
        v = results.get(variant, {})
        if "p99_ms" in v:
            verdict = "within budget" if v["p99_ms"] <= budget_p99 else "**over budget**"
            lines.append(
                f"| {variant} | {v['p50_ms']:.3f} | {v['p95_ms']:.3f} | {v['p99_ms']:.3f} | {verdict} |"
            )
        elif "error" in v:
            lines.append(f"| {variant} | — | — | — | error: {v['error'][:60]} |")
    lines += [
        "",
        "Hardware caveat: absolute numbers are CPU-dependent; this run is on a",
        "2-core sandbox vCPU. The ladder (eager → jit → int8 → ONNX) shows what",
        "each optimization buys on the target hardware before capacity planning.",
        "",
    ]
    (args.out.parent / "latency_report.md").write_text("\n".join(lines))

    for variant in ("eager", "jit", "int8_torchao", "onnx"):
        v = results.get(variant, {})
        if "p99_ms" in v:
            status = "WITHIN BUDGET" if v["p99_ms"] <= budget_p99 else "over budget"
            print(f"{variant:12s} p99 {v['p99_ms']:7.3f} ms  -> {status}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
