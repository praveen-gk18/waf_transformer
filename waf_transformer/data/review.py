"""Manual review workflow (Step 5: "then do manual review on a sample").

Automated labels have mistakes. This module exports a stratified review queue
(source x label) with empty analyst columns, and later merges filled-in
corrections back into the pipeline (``--corrections`` on the label stage).

Workflow (see docs/05_labeling.md)::

    # 1. draw the sample
    python3 -m waf_transformer.data.review sample \
        --input data/interim/labeled.jsonl --out data/review/review_queue.csv

    # 2. analysts fill reviewer_class / reviewer_category / reviewer_notes
    #    in the CSV (benign|attack|unsure)

    # 3. merge corrections + measure auto-vs-manual agreement
    python3 -m waf_transformer.data.review merge \
        --queue data/review/review_queue.csv --out data/review/corrections.jsonl
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from pathlib import Path

from .schema import RequestRecord, read_jsonl

VALID_REVIEWER_CLASSES = {"benign", "attack", "unsure"}
QUEUE_COLUMNS = [
    "id",
    "source",
    "auto_class",
    "auto_category",
    "auto_label_source",
    "request_preview",
    "reviewer_class",
    "reviewer_category",
    "reviewer_notes",
]


def _preview(rec: RequestRecord, limit: int = 240) -> str:
    text = f"{rec.method} {rec.request_target()}"
    if rec.body:
        text += f" | body: {rec.body}"
    return text[:limit]


def draw_sample(records: list[RequestRecord], per_stratum: int, seed: int) -> list[RequestRecord]:
    """Stratified random sample: up to `per_stratum` records per (source, class)."""
    rng = random.Random(seed)
    strata: dict[tuple[str, str], list[RequestRecord]] = {}
    for rec in records:
        strata.setdefault((rec.source, rec.label.class_), []).append(rec)
    sample: list[RequestRecord] = []
    for key in sorted(strata):
        pool = strata[key]
        take = min(per_stratum, len(pool))
        sample.extend(rng.sample(pool, take))
    rng.shuffle(sample)
    return sample


def write_queue(sample: list[RequestRecord], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=QUEUE_COLUMNS)
        writer.writeheader()
        for rec in sample:
            writer.writerow(
                {
                    "id": rec.id,
                    "source": rec.source,
                    "auto_class": rec.label.class_,
                    "auto_category": rec.label.attack_category or "",
                    "auto_label_source": rec.label.label_source,
                    "request_preview": _preview(rec),
                    "reviewer_class": "",
                    "reviewer_category": "",
                    "reviewer_notes": "",
                }
            )


def merge_queue(queue_path: Path, out_path: Path) -> dict:
    """Validate filled-in queue rows -> corrections JSONL + agreement stats."""
    corrections = []
    stats = {"rows": 0, "filled": 0, "agreements": 0, "disagreements": 0, "unsure": 0, "by_source": {}}
    with queue_path.open("r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            stats["rows"] += 1
            verdict = (row.get("reviewer_class") or "").strip().lower()
            if not verdict:
                continue
            if verdict not in VALID_REVIEWER_CLASSES:
                raise ValueError(f"row {row['id']}: reviewer_class must be one of {sorted(VALID_REVIEWER_CLASSES)}")
            stats["filled"] += 1
            src = row["source"]
            stats["by_source"].setdefault(src, {"filled": 0, "agreements": 0})
            stats["by_source"][src]["filled"] += 1
            if verdict == "unsure":
                stats["unsure"] += 1
                continue
            agrees = verdict == row["auto_class"]
            if agrees:
                stats["agreements"] += 1
                stats["by_source"][src]["agreements"] += 1
            else:
                stats["disagreements"] += 1
            corrections.append(
                {
                    "id": row["id"],
                    "class": verdict,
                    "attack_category": (row.get("reviewer_category") or "").strip() or None,
                    "reviewer_notes": (row.get("reviewer_notes") or "").strip(),
                }
            )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        for obj in corrections:
            fh.write(json.dumps(obj, sort_keys=True) + "\n")

    judged = stats["agreements"] + stats["disagreements"]
    stats["agreement_rate"] = round(stats["agreements"] / judged, 4) if judged else None
    return stats


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Manual review queue: sample / merge")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_sample = sub.add_parser("sample", help="export a stratified review queue CSV")
    p_sample.add_argument("--input", type=Path, required=True)
    p_sample.add_argument("--out", type=Path, required=True)
    p_sample.add_argument("--per-stratum", type=int, default=40)
    p_sample.add_argument("--seed", type=int, default=20260927)

    p_merge = sub.add_parser("merge", help="merge filled-in queue -> corrections JSONL")
    p_merge.add_argument("--queue", type=Path, required=True)
    p_merge.add_argument("--out", type=Path, required=True)

    args = ap.parse_args(argv)
    if args.cmd == "sample":
        records = list(read_jsonl(args.input))
        sample = draw_sample(records, args.per_stratum, args.seed)
        write_queue(sample, args.out)
        print(f"review queue with {len(sample)} rows -> {args.out}")
        return 0

    stats = merge_queue(args.queue, args.out)
    print(json.dumps(stats, indent=2, sort_keys=True))
    print(f"corrections -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
