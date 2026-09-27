"""Score a single HTTP request with the trained model (demo / debugging).

Parses a raw HTTP request (same format as the corpus fixtures), scores it,
and applies the scope.toml [enforcement] thresholds (Phase-4 decision logic).

Usage::

    python3 -m waf_transformer.modeling.predict \
        --checkpoint artifacts/run1/best.pt \
        --request-file request.txt

    python3 -m waf_transformer.modeling.predict \
        --checkpoint artifacts/run1/best.pt \
        --request "GET /item?id=1'+UNION+SELECT+password+FROM+users-- HTTP/1.1
    Host: shop.example.local"
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import torch

from ..config import DEFAULT_CONFIG_PATH, load_config
from ..data.http_request import parse_request_text
from .evaluate import load_checkpoint
from .tokenizer import HttpByteTokenizer


def decide(score: float, enforcement: dict) -> str:
    if score >= float(enforcement.get("block_above", 0.9)):
        return "block (403)"
    if score >= float(enforcement.get("challenge_above", 0.6)):
        return "challenge (CAPTCHA / rate-limit)"
    return "allow"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Score one HTTP request")
    ap.add_argument("--checkpoint", type=Path, default=Path("artifacts/run1/best.pt"))
    ap.add_argument("--request", type=str, default=None, help="raw request text")
    ap.add_argument("--request-file", type=Path, default=None)
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    args = ap.parse_args(argv)

    text = args.request
    if args.request_file:
        text = args.request_file.read_text(encoding="utf-8", errors="replace")
    if not text:
        print("error: provide --request or --request-file", file=sys.stderr)
        return 2
    # allow "GET ...\nHost: ..." one-liners from shells/make
    text = text.replace("\\r\\n", "\n").replace("\\n", "\n")

    raw = parse_request_text(text.strip("\n"))
    if raw is None:
        print("error: could not parse request", file=sys.stderr)
        return 2

    cfg = load_config(args.config)
    model, ckpt = load_checkpoint(args.checkpoint, torch.device("cpu"))
    tokenizer = HttpByteTokenizer(cfg.tokenizer)
    enc = tokenizer.encode(raw.method, raw.path, raw.query_string, raw.headers, raw.body)
    ids = torch.tensor([enc.ids], dtype=torch.long)
    mask = (ids != 0).long()
    with torch.no_grad():
        score = float(torch.sigmoid(model(ids, mask)))

    thr = ckpt.get("operating_threshold", 0.5)
    print(f"p(malicious)   = {score:.4f}")
    print(f"op threshold   = {thr:.3f}   (0.5 reporting threshold)")
    print(f"decision       = {decide(score, cfg.enforcement)}")
    if enc.truncated_fields:
        print(f"truncated      = {enc.truncated_fields}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
