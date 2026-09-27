"""Ingest stage: parse fetched corpora + synthetic sources into unified JSONL.

Reads everything under ``data/raw/`` (public corpora in either on-disk format,
plus the synthetic generators' JSONL output) and emits one interleaved,
deduplicated stream of :class:`RequestRecord` at ``data/interim/unified.jsonl``.

Usage::

    python3 -m waf_transformer.data.ingest --raw-dir data/raw --out data/interim/unified.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..config import DEFAULT_CONFIG_PATH, load_config
from .parsers import parse_corpus_file
from .schema import RequestRecord, read_jsonl, write_jsonl


def ingest_raw_dir(
    raw_dir: Path,
    session_cookie_names: tuple[str, ...],
    body_max_bytes: int,
    verbose: bool = True,
) -> list[RequestRecord]:
    """Parse every corpus under raw_dir plus any synthetic *.jsonl dumps."""
    records: list[RequestRecord] = []
    seen_ids: set[str] = set()

    # 1) Public corpora (text files, one dataset per subdirectory)
    for sub in sorted(p for p in raw_dir.iterdir() if p.is_dir() and p.name != "synthetic"):
        source = sub.name
        for f in sorted(sub.glob("*.txt")):
            n = 0
            for rec in parse_corpus_file(f, source, session_cookie_names, body_max_bytes):
                if rec.id in seen_ids:
                    continue
                seen_ids.add(rec.id)
                records.append(rec)
                n += 1
            if verbose:
                print(f"  parsed {n:>7} records  {sub.name}/{f.name}")

    # 2) Synthetic generators (already JSONL RequestRecords)
    synth_dir = raw_dir / "synthetic"
    if synth_dir.exists():
        for f in sorted(synth_dir.glob("*.jsonl")):
            n = 0
            for rec in read_jsonl(f):
                if rec.id in seen_ids:
                    continue
                seen_ids.add(rec.id)
                records.append(rec)
                n += 1
            if verbose:
                print(f"  parsed {n:>7} records  synthetic/{f.name}")
    return records


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Unify raw corpora + synthetic data into JSONL")
    ap.add_argument("--raw-dir", type=Path, default=Path("data/raw"))
    ap.add_argument("--out", type=Path, default=Path("data/interim/unified.jsonl"))
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    if not args.raw_dir.exists():
        print(f"error: {args.raw_dir} does not exist — run fetch_datasets first", file=sys.stderr)
        return 2

    records = ingest_raw_dir(
        args.raw_dir,
        cfg.dataset.session_cookie_names,
        cfg.dataset.body_max_bytes,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    write_jsonl(args.out, records)
    print(f"wrote {len(records)} unified records -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
