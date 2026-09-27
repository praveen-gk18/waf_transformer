"""Step 9 — evaluate and harden.

Three evaluation surfaces, per the plan:

1. **Main test split** (never trained on, same distribution) — precision,
   recall, F1 at 0.5 and at the operating threshold, plus per-category recall.
2. **Unseen techniques** (``test_unseen.jsonl.gz`` — time_based_sql, dom_xss,
   never in train/val) — the "attacks the model has never seen" check.
3. **Adversarial variants** — test attacks with an EXTRA url-encoding layer
   applied (double/triple obfuscation beyond what training saw). If recall
   collapses, the plan's answer is adversarial training (retrain on the
   fooled examples) — this tool quantifies the gap.

Writes ``artifacts/eval/<name>.json`` and renders ``data/reports/model_report.md``.

Usage::

    python3 -m waf_transformer.modeling.evaluate \
        --checkpoint artifacts/run1/best.pt \
        --test data/processed/test.jsonl.gz \
        --unseen data/processed/test_unseen.jsonl.gz
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import json
import sys
import urllib.parse
from pathlib import Path

import torch

from ..config import DEFAULT_CONFIG_PATH, load_config
from ..data.schema import RequestRecord
from .data import RequestDataset, make_loader
from .metrics import precision_recall_f1, recall_by_group, threshold_for_min_recall
from .model import build_model
from .tokenizer import VOCAB_SIZE, HttpByteTokenizer
from .train import evaluate as run_inference


def make_adversarial(records: list[RequestRecord], layers: int = 1) -> list[RequestRecord]:
    """Re-encode path/query/body/headers one more time (training saw at most
    one encoding pass per payload — this simulates a smarter evader)."""
    out = []
    for r in records:
        if r.label.class_ != "attack":
            continue
        adv = copy.deepcopy(r)
        for _ in range(layers):
            adv.path = urllib.parse.quote(adv.path, safe="/")
            adv.query_string = urllib.parse.quote(adv.query_string, safe="")
            adv.body = urllib.parse.quote(adv.body, safe="")
            adv.headers = [(k, urllib.parse.quote(v, safe="")) for k, v in adv.headers]
        adv.id = r.id + "#adv"
        adv.meta["adversarial"] = True
        out.append(adv)
    return out


def load_checkpoint(path: Path, device: torch.device):
    ckpt = torch.load(path, map_location=device, weights_only=False)
    spec_dict = ckpt["model_spec"]
    from ..config import ModelSpec

    mspec = ModelSpec(**spec_dict)
    max_len = int((ckpt.get("tokenizer_spec") or {}).get("max_len", 512))
    model = build_model(VOCAB_SIZE, mspec, max_len)
    model.load_state_dict(ckpt["model_state"])
    model.to(device).eval()
    return model, ckpt


def eval_split(name: str, records: list, model, tokenizer, device, batch_size: int, threshold: float, recall_target: float) -> dict:
    ds = RequestDataset(records, tokenizer)
    loader = make_loader(ds, batch_size, shuffle=False)
    ys, ss = run_inference(model, loader, device)
    m50 = precision_recall_f1(ys, ss, threshold)
    op = threshold_for_min_recall(ys, ss, recall_target)
    categories = [r.label.attack_category or "benign" for r in records]
    by_cat = recall_by_group(ys, ss, categories, threshold)
    return {
        "name": name,
        "records": len(records),
        "metrics_at_threshold": m50,
        "operating_point": op,
        "recall_by_category": by_cat,
    }


def render_report(results: dict, ckpt_meta: dict, budget: dict) -> str:
    today = dt.date.today().isoformat()
    lines = [
        "# waf_transformer — Phase 3 model evaluation report",
        "",
        f"_Generated {today} by `python3 -m waf_transformer.modeling.evaluate`. "
        "Do not edit by hand — regenerate._",
        "",
        "## 1. Checkpoint",
        "",
        f"- selected epoch: **{ckpt_meta.get('epoch')}**",
        f"- operating threshold (val-selected @ recall ≥ target): "
        f"**{ckpt_meta.get('operating_threshold', 0.5):.3f}**",
        f"- val metrics at selection: `{json.dumps(ckpt_meta.get('val_metrics', {}))}`",
        "",
        "## 2. Results (Step 8–9)",
        "",
    ]
    for key in ("test", "test_unseen", "adversarial"):
        res = results.get(key)
        if not res:
            continue
        m = res["metrics_at_threshold"]
        op = res["operating_point"]
        lines += [
            f"### {res['name']}",
            "",
            f"- records: {res['records']}",
            f"- @ {m['threshold']:.2f}: precision **{m['precision']:.4f}**, "
            f"recall **{m['recall']:.4f}**, F1 {m['f1']:.4f}, FPR {m['fpr']:.4f} "
            f"(tp {m['tp']}, fp {m['fp']}, fn {m['fn']}, tn {m['tn']})",
            f"- operating point (recall ≥ {op['recall']:.2f}): threshold {op['threshold']:.3f}, "
            f"precision {op['precision']:.4f}, recall {op['recall']:.4f}",
            "",
        ]
        if res.get("recall_by_category"):
            lines.append("| category | support | recall |")
            lines.append("|---|---|---|")
            for cat, v in res["recall_by_category"].items():
                lines.append(f"| {cat} | {v['support']} | {v['recall']:.4f} |")
            lines.append("")
    lines += [
        "## 3. Latency budget",
        "",
        f"- budget (scope.toml): p99 ≤ **{budget['p99']} ms** end-to-end (p50 {budget['p50']} ms)",
        "- measured ladder: `data/reports/latency_report.md` + `latency_report.json`",
        "  (eager / jit / int8 / onnx variants, batch-1 on real requests)",
        "",
        "## 4. Reproduce",
        "",
        "```bash",
        "make model-train model-evaluate model-benchmark",
        "```",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Evaluate the WAF encoder (test + unseen + adversarial)")
    ap.add_argument("--checkpoint", type=Path, default=Path("artifacts/run1/best.pt"))
    ap.add_argument("--test", type=Path, default=Path("data/processed/test.jsonl.gz"))
    ap.add_argument("--unseen", type=Path, default=Path("data/processed/test_unseen.jsonl.gz"))
    ap.add_argument("--out", type=Path, default=Path("artifacts/eval"))
    ap.add_argument("--report", type=Path, default=Path("data/reports/model_report.md"))
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    ap.add_argument("--batch-size", type=int, default=16)
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    espec = cfg.evaluation
    device = torch.device("cpu")
    model, ckpt = load_checkpoint(args.checkpoint, device)
    tokenizer = HttpByteTokenizer(cfg.tokenizer)

    results = {}
    from ..data.schema import read_jsonl

    test_recs = list(read_jsonl(args.test))
    unseen_recs = []
    if args.unseen.exists():
        unseen_recs = list(read_jsonl(args.unseen))

    thr = espec.probability_threshold
    tgt = espec.operating_recall_target
    results["test"] = eval_split("Main test split (unseen records, seen techniques)", test_recs, model, tokenizer, device, args.batch_size, thr, tgt)
    if unseen_recs:
        results["test_unseen"] = eval_split(
            "Unseen-technique holdout (time_based_sql, dom_xss — never trained on)",
            unseen_recs, model, tokenizer, device, args.batch_size, thr, tgt,
        )
    adv_recs = make_adversarial(test_recs, espec.adversarial_extra_encoding_layers)
    if adv_recs:
        results["adversarial"] = eval_split(
            f"Adversarial variants (test attacks + {espec.adversarial_extra_encoding_layers} extra encoding layer)",
            adv_recs, model, tokenizer, device, args.batch_size, thr, tgt,
        )

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "eval.json").write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        render_report(results, ckpt, {"p50": cfg.latency.p50, "p99": cfg.latency.p99})
    )
    for key, res in results.items():
        m = res["metrics_at_threshold"]
        print(f"{key:12s}  P {m['precision']:.4f}  R {m['recall']:.4f}  F1 {m['f1']:.4f}  (n={res['records']})")
    print(f"report -> {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
