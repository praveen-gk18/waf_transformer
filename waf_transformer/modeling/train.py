"""Step 8 — train the WAF encoder.

Reads the leak-free Phase-2 splits, trains with class-weighted BCE (or focal),
evaluates per epoch on val, and selects:

* **best checkpoint** by val F1 @ 0.5,
* **operating threshold** = best precision at recall >= operating_recall_target
  (the plan's "high recall while keeping precision acceptable").

Usage::

    python3 -m waf_transformer.modeling.train \
        --train data/processed/train.jsonl.gz --val data/processed/val.jsonl.gz \
        --out artifacts/run1
"""

from __future__ import annotations

import argparse
import json
import math
import random
import sys
import time
from pathlib import Path

import torch

from ..config import DEFAULT_CONFIG_PATH, ScopeConfig, load_config
from .data import RequestDataset, load_records, make_loader
from .losses import focal_bce, weighted_bce
from .metrics import precision_recall_f1, threshold_for_min_recall
from .model import build_model
from .tokenizer import VOCAB_SIZE, HttpByteTokenizer


def set_seed(seed: int) -> None:
    random.seed(seed)
    torch.manual_seed(seed)


@torch.no_grad()
def evaluate(model, loader, device) -> tuple[list[int], list[float]]:
    model.eval()
    ys, ss = [], []
    for ids, mask, labels in loader:
        ids, mask = ids.to(device), mask.to(device)
        logits = model(ids, mask)
        ys.extend(int(x) for x in labels)
        ss.extend(float(x) for x in torch.sigmoid(logits))
    return ys, ss


def lr_at(step: int, total: int, warmup: int, base_lr: float) -> float:
    if step < warmup:
        return base_lr * (step + 1) / max(warmup, 1)
    progress = (step - warmup) / max(total - warmup, 1)
    return base_lr * 0.5 * (1 + math.cos(math.pi * min(progress, 1.0)))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Train the WAF encoder")
    ap.add_argument("--train", type=Path, default=Path("data/processed/train.jsonl.gz"))
    ap.add_argument("--val", type=Path, default=Path("data/processed/val.jsonl.gz"))
    ap.add_argument("--out", type=Path, default=Path("artifacts/run1"))
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    ap.add_argument("--epochs", type=int, default=None)
    ap.add_argument("--batch-size", type=int, default=None)
    ap.add_argument("--max-train-records", type=int, default=None, help="0 = all")
    ap.add_argument("--max-val-records", type=int, default=4000, help="0 = all; per-epoch monitor subset")
    ap.add_argument("--loss", choices=["bce", "focal"], default=None)
    ap.add_argument("--device", default="cpu")
    args = ap.parse_args(argv)

    cfg: ScopeConfig = load_config(args.config)
    tspec, mspec, espec = cfg.training, cfg.model, cfg.evaluation
    assert tspec and mspec and espec, "scope.toml missing [training]/[model]/[evaluation]"
    epochs = args.epochs or tspec.epochs
    batch_size = args.batch_size or tspec.batch_size
    loss_kind = args.loss or tspec.loss
    max_train = tspec.max_train_records if args.max_train_records is None else args.max_train_records
    device = torch.device(args.device)
    set_seed(tspec.seed)

    tokenizer = HttpByteTokenizer(cfg.tokenizer)
    args.out.mkdir(parents=True, exist_ok=True)

    print(f"loading train={args.train} val={args.val}")
    train_recs = load_records(args.train, max_train, tspec.seed)
    val_recs = load_records(args.val, args.max_val_records, tspec.seed + 1)
    n_att = sum(1 for r in train_recs if r.label.class_ == "attack")
    n_ben = len(train_recs) - n_att
    pos_weight = n_ben / max(n_att, 1)
    print(f"train={len(train_recs)} (attack {n_att}, benign {n_ben}, pos_weight={pos_weight:.3f})  val={len(val_recs)}")

    train_ds = RequestDataset(train_recs, tokenizer)
    val_ds = RequestDataset(val_recs, tokenizer)
    train_loader = make_loader(train_ds, batch_size, shuffle=True, seed=tspec.seed, bucket=True)
    val_loader = make_loader(val_ds, batch_size, shuffle=False, bucket=True)

    model = build_model(VOCAB_SIZE, mspec, cfg.tokenizer.max_len if cfg.tokenizer else 512).to(device)
    print(f"model params: {model.count_parameters():,}")

    opt = torch.optim.AdamW(model.parameters(), lr=tspec.learning_rate, weight_decay=tspec.weight_decay)
    total_steps = len(train_loader) * epochs
    warmup = int(total_steps * tspec.warmup_fraction)

    history = []
    best = {"f1": -1.0}
    bad_epochs = 0
    step = 0
    for epoch in range(1, epochs + 1):
        model.train()
        t0 = time.time()
        running = 0.0
        n_batches = 0
        effective_batch = batch_size  # gradient accumulation target (samples)
        accumulated = 0
        opt.zero_grad()
        for ids, mask, labels in train_loader:
            ids, mask, labels = ids.to(device), mask.to(device), labels.to(device)
            for g in opt.param_groups:
                g["lr"] = lr_at(step, total_steps, warmup, tspec.learning_rate)
            logits = model(ids, mask)
            if loss_kind == "focal":
                loss = focal_bce(logits, labels, tspec.focal_gamma, tspec.focal_alpha)
            else:
                loss = weighted_bce(logits, labels, pos_weight)
            # Micro-batches are memory-capped by length; accumulate gradients
            # until ~effective_batch samples seen, then step (3 GB box safety).
            (loss * ids.shape[0] / effective_batch).backward()
            accumulated += ids.shape[0]
            running += float(loss.detach())
            n_batches += 1
            step += 1
            if accumulated >= effective_batch:
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                opt.step()
                opt.zero_grad()
                accumulated = 0
        if accumulated:
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            opt.zero_grad()

        ys, ss = evaluate(model, val_loader, device)
        m50 = precision_recall_f1(ys, ss, 0.5)
        op = threshold_for_min_recall(ys, ss, espec.operating_recall_target)
        elapsed = time.time() - t0
        n_seen = len(train_recs)
        row = {
            "epoch": epoch,
            "train_loss": round(running / max(n_batches, 1), 4),
            "val_at_0.5": m50,
            "val_operating_point": op,
            "seconds": round(elapsed, 1),
            "samples_per_sec": round(n_seen / max(elapsed, 1e-9), 2),
        }
        history.append(row)
        print(
            f"epoch {epoch}/{epochs}  loss {row['train_loss']:.4f}  "
            f"val P {m50['precision']:.4f} R {m50['recall']:.4f} F1 {m50['f1']:.4f}  "
            f"op@R>={espec.operating_recall_target}: thr {op['threshold']:.3f} P {op['precision']:.4f}  "
            f"({elapsed:.0f}s, {row['samples_per_sec']} req/s)"
        )

        if m50["f1"] > best["f1"]:
            bad_epochs = 0
            best = {
                "f1": m50["f1"],
                "epoch": epoch,
                "operating_threshold": op["threshold"],
                "val_metrics": m50,
                "val_operating_point": op,
            }
            torch.save(
                {
                    "model_state": model.state_dict(),
                    "model_spec": mspec.__dict__,
                    "tokenizer_spec": cfg.tokenizer.__dict__ if cfg.tokenizer else None,
                    "pos_weight": pos_weight,
                    "epoch": epoch,
                    "val_metrics": m50,
                    "operating_threshold": op["threshold"],
                },
                args.out / "best.pt",
            )
        else:
            bad_epochs += 1
            if bad_epochs >= tspec.early_stop_patience:
                print(f"early stop after epoch {epoch} (patience {tspec.early_stop_patience})")
                break

    (args.out / "history.json").write_text(json.dumps(history, indent=2) + "\n")
    (args.out / "summary.json").write_text(json.dumps(best, indent=2) + "\n")
    print(json.dumps(best, indent=2))
    print(f"best checkpoint -> {args.out / 'best.pt'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
