"""Export a small stratified preview of the labeled data (committed artifact).

``data/samples/preview.jsonl`` is a tiny, human-inspectable slice of the real
dataset — a few records per (source × class) stratum — so reviewers can see the
schema and label quality without downloading the corpora. Committed on purpose;
everything else under data/ stays out of Git.

Usage::

    python3 -m waf_transformer.data.export_samples \
        --input data/interim/labeled.jsonl --out data/samples/preview.jsonl
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .review import draw_sample
from .schema import read_jsonl, write_jsonl


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Export a small stratified data preview")
    ap.add_argument("--input", type=Path, default=Path("data/interim/labeled.jsonl"))
    ap.add_argument("--out", type=Path, default=Path("data/samples/preview.jsonl"))
    ap.add_argument("--per-stratum", type=int, default=3)
    ap.add_argument("--seed", type=int, default=20260927)
    args = ap.parse_args(argv)

    records = list(read_jsonl(args.input))
    sample = draw_sample(records, args.per_stratum, args.seed)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    write_jsonl(args.out, sample)
    print(f"wrote {len(sample)} preview records -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
