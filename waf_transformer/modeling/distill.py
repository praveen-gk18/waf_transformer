"""Step 20 — distillation: shrink the 3.4M teacher for latency headroom.

Why: `data/reports/latency_report.md` shows every full-size variant over the
10 ms p99 budget on modest CPUs. The production answer is capacity planning;
the on-box answer is a **student** (2 layers / d128 / 4 heads / FF 512, ~0.4M
params) trained on the teacher's soft targets plus hard labels:

    loss = alpha * BCE(student, sigmoid(teacher_logit))   # soft
         + (1 - alpha) * BCE(student, label)              # hard

The student is saved in the SAME checkpoint schema as ``run1/best.pt``
(``model_spec``/``model_state``/``tokenizer_spec``/``operating_threshold``),
so ``Detector`` and ``evaluate.load_checkpoint`` load it unchanged — swap the
checkpoint path and you are serving the student.

Usage (demo-sized run on CPU; scale up on real hardware)::

    python3 -m waf_transformer.modeling.distill \
        --teacher artifacts/run1/best.pt \
        --train data/processed/train.jsonl.gz \
        --val data/processed/val.jsonl.gz \
        --out artifacts/distill --max-samples 2000 --epochs 2

Then compare latency with:
    python3 -m waf_transformer.modeling.benchmark --checkpoint artifacts/distill/student.pt
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import torch
import torch.nn.functional as F

from ..config import ModelSpec
from .data import load_records, make_loader, RequestDataset
from .evaluate import load_checkpoint
from .metrics import percentile, precision_recall_f1
from .model import build_model
from .tokenizer import VOCAB_SIZE, HttpByteTokenizer
from .train import evaluate as run_inference


def distill(teacher, student, loader, device, alpha: float, epochs: int, lr: float):
    opt = torch.optim.AdamW(student.parameters(), lr=lr)
    history = []
    for epoch in range(1, epochs + 1):
        student.train()
        total, n = 0.0, 0
        t0 = time.perf_counter()
        for ids, mask, y in loader:
            ids, mask, y = ids.to(device), mask.to(device), y.to(device)
            with torch.no_grad():
                t_logit = teacher(ids, mask).squeeze(-1)
                soft = torch.sigmoid(t_logit)
            s_logit = student(ids, mask).squeeze(-1)
            loss_soft = F.binary_cross_entropy_with_logits(s_logit, soft)
            loss_hard = F.binary_cross_entropy_with_logits(s_logit, y)
            loss = alpha * loss_soft + (1.0 - alpha) * loss_hard
            opt.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(student.parameters(), 1.0)
            opt.step()
            total += float(loss) * len(y)
            n += len(y)
        entry = {"epoch": epoch, "loss": round(total / max(n, 1), 5),
                 "seconds": round(time.perf_counter() - t0, 1)}
        history.append(entry)
        print(f"epoch {epoch}: loss={entry['loss']} ({entry['seconds']}s)", flush=True)
    return history


def latency_probe(model, loader, device, batches: int = 20) -> dict:
    model.eval()
    times = []
    with torch.no_grad():
        for i, (ids, mask, _y) in enumerate(loader):
            if i >= batches:
                break
            ids, mask = ids.to(device), mask.to(device)
            t0 = time.perf_counter()
            model(ids, mask)
            times.append((time.perf_counter() - t0) * 1000.0 / ids.size(0))
    return {
        "per_request_ms": {
            "p50": round(percentile(times, 50), 3),
            "p95": round(percentile(times, 95), 3),
            "p99": round(percentile(times, 99), 3),
        } if times else None,
        "note": "per-request derived from batched forward; see benchmark.py for single-request truth",
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Distill the teacher into a small student")
    ap.add_argument("--teacher", default="artifacts/run1/best.pt")
    ap.add_argument("--train", default="data/processed/train.jsonl.gz")
    ap.add_argument("--val", default="data/processed/val.jsonl.gz")
    ap.add_argument("--out", default="artifacts/distill")
    ap.add_argument("--max-samples", type=int, default=2000)
    ap.add_argument("--epochs", type=int, default=2)
    ap.add_argument("--batch-size", type=int, default=32)
    ap.add_argument("--lr", type=float, default=2e-3)
    ap.add_argument("--alpha", type=float, default=0.5, help="weight on soft (teacher) loss")
    ap.add_argument("--student-layers", type=int, default=2)
    ap.add_argument("--student-dim", type=int, default=128)
    ap.add_argument("--student-heads", type=int, default=4)
    ap.add_argument("--student-ff", type=int, default=512)
    ap.add_argument("--seed", type=int, default=20260927)
    ap.add_argument("--config", default=None)
    args = ap.parse_args(argv)

    torch.manual_seed(args.seed)
    torch.set_num_threads(2)  # sandbox OOM/CPU recipe — remove on real hardware
    device = torch.device("cpu")

    teacher, tckpt = load_checkpoint(Path(args.teacher), device)
    for p in teacher.parameters():
        p.requires_grad_(False)

    from ..config import load_config

    cfg = load_config(args.config) if args.config else load_config()
    tok = HttpByteTokenizer(cfg.tokenizer)
    max_len = cfg.tokenizer.max_len

    train_recs = load_records(Path(args.train), max_records=args.max_samples, seed=args.seed)
    val_recs = load_records(Path(args.val), max_records=min(args.max_samples, 2000), seed=args.seed)
    print(f"teacher: {args.teacher} | distill on {len(train_recs)} train / {len(val_recs)} val", flush=True)

    student_spec = dict(tckpt["model_spec"])
    student_spec.update(
        d_model=args.student_dim, nhead=args.student_heads,
        num_layers=args.student_layers, dim_feedforward=args.student_ff,
    )
    student = build_model(
        VOCAB_SIZE,
        ModelSpec(**student_spec),
        max_len,
    ).to(device)
    n_t = sum(p.numel() for p in teacher.parameters())
    n_s = sum(p.numel() for p in student.parameters())
    print(f"params: teacher {n_t:,} -> student {n_s:,} ({n_s / n_t:.1%})", flush=True)

    loader = make_loader(RequestDataset(train_recs, tok), args.batch_size, shuffle=True)
    history = distill(teacher, student, loader, device, args.alpha, args.epochs, args.lr)

    # quick quality check at 0.5
    vloader = make_loader(RequestDataset(val_recs, tok), args.batch_size, shuffle=False)
    ys, ss = run_inference(student, vloader, device)
    metrics = precision_recall_f1(ys, ss, 0.5)
    ys_t, ss_t = run_inference(teacher, vloader, device)
    metrics_t = precision_recall_f1(ys_t, ss_t, 0.5)
    lat = latency_probe(student, vloader, device)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    ckpt = {
        "model_spec": student_spec,
        "model_state": student.state_dict(),
        "tokenizer_spec": {"max_len": max_len},
        "operating_threshold": tckpt.get("operating_threshold", 0.5),
        "distill_meta": {
            "teacher": args.teacher, "alpha": args.alpha, "epochs": args.epochs,
            "train_samples": len(train_recs), "seed": args.seed,
            "student_params": n_s, "teacher_params": n_t,
        },
    }
    torch.save(ckpt, out / "student.pt")
    report = {
        "history": history,
        "student_val_at_0.5": metrics,
        "teacher_val_at_0.5": metrics_t,
        "student_latency": lat,
    }
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"student": str(out / "student.pt"), "val": metrics,
                      "teacher_val": metrics_t, "latency": lat}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
