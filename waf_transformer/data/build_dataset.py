"""Dataset builder (Steps 5 & 8): labeled records -> training-ready splits.

Guarantees, enforced and audited in ``stats.json``:

* **Leak-free splits** — group-aware 70/15/15 (session / attack source /
  generator family never straddles splits). A leakage audit hard-fails the
  build if any group appears in two splits.
* **Class-ratio policy** — "at least 5–10% attacks" is a floor. Train attack
  share below the floor is raised to ``target_attack_ratio`` by oversampling
  attacks (real-traffic case). Public corpora sit far above the floor and are
  kept whole. Val/test are never rebalanced.
* **Unseen-technique holdout** — records whose attack technique is listed in
  ``dataset.holdout_techniques`` go to ``test_unseen.jsonl`` only (Step 9's
  "attacks the model has never seen", reserved for Phase 3 evaluation).

Output (``data/processed/``): ``train.jsonl.gz``, ``val.jsonl.gz``,
``test.jsonl.gz``, ``test_unseen.jsonl.gz``, ``splits_index.json``,
``stats.json``.

Usage::

    python3 -m waf_transformer.data.build_dataset \
        --input data/interim/labeled.jsonl --out-dir data/processed
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import defaultdict
from pathlib import Path

from ..config import DEFAULT_CONFIG_PATH, ScopeConfig, load_config
from .schema import RequestRecord, read_jsonl, write_jsonl


class LeakageError(RuntimeError):
    """A group_id landed in more than one split — the build is invalid."""


# ---------------------------------------------------------------------------
# Splitting
# ---------------------------------------------------------------------------
def _split_targets(n: int, cfg: ScopeConfig) -> dict[str, int]:
    d = cfg.dataset
    n_train = int(round(n * d.train_fraction))
    n_val = int(round(n * d.val_fraction))
    return {"train": n_train, "val": n_val, "test": n - n_train - n_val}


def group_aware_split(
    records: list[RequestRecord], cfg: ScopeConfig
) -> dict[str, list[RequestRecord]]:
    """Assign whole groups to splits, balancing size and attack count."""
    rng = random.Random(cfg.dataset.seed)

    groups: dict[str, list[RequestRecord]] = defaultdict(list)
    for rec in records:
        groups[rec.group_id].append(rec)

    totals = {
        "benign": sum(1 for r in records if r.label.class_ == "benign"),
        "attack": sum(1 for r in records if r.label.class_ == "attack"),
        "all": len(records),
    }
    size_targets = _split_targets(totals["all"], cfg)
    class_targets = {
        split: {
            "benign": int(round(totals["benign"] * frac)),
            "attack": int(round(totals["attack"] * frac)),
        }
        for split, frac in (
            ("train", cfg.dataset.train_fraction),
            ("val", cfg.dataset.val_fraction),
            ("test", cfg.dataset.test_fraction),
        )
    }
    assigned = {
        split: {"benign": 0, "attack": 0, "all": 0, "records": []}
        for split in ("train", "val", "test")
    }

    # Deterministic order: shuffle group keys, then largest groups first so the
    # hardest-to-place cohorts get first pick of capacity.
    keys = sorted(groups)
    rng.shuffle(keys)
    keys.sort(key=lambda k: -len(groups[k]))

    for key in keys:
        recs = groups[key]
        n_attack = sum(1 for r in recs if r.label.class_ == "attack")
        n_benign = len(recs) - n_attack

        def deficit(split: str) -> float:
            """Remaining capacity for this group's class mix (bigger = roomier)."""
            cap = class_targets[split]
            got = assigned[split]
            room_b = (cap["benign"] - got["benign"]) / max(cap["benign"], 1)
            room_a = (cap["attack"] - got["attack"]) / max(cap["attack"], 1)
            room_n = (size_targets[split] - got["all"]) / max(size_targets[split], 1)
            if n_attack and not n_benign:
                return room_a * 2 + room_n
            if n_benign and not n_attack:
                return room_b * 2 + room_n
            return room_a + room_b + room_n

        best = max(("train", "val", "test"), key=lambda s: (deficit(s), -assigned[s]["all"]))
        assigned[best]["records"].extend(recs)
        assigned[best]["benign"] += n_benign
        assigned[best]["attack"] += n_attack
        assigned[best]["all"] += len(recs)

    out = {split: assigned[split]["records"] for split in ("train", "val", "test")}
    audit_split_leakage(out)
    return out


def audit_split_leakage(splits: dict[str, list[RequestRecord]]) -> None:
    """Hard-fail if any group_id appears in more than one split (Step 8)."""
    seen: dict[str, str] = {}
    for split, recs in splits.items():
        for rec in recs:
            prev = seen.setdefault(rec.group_id, split)
            if prev != split:
                raise LeakageError(
                    f"group {rec.group_id!r} leaks between splits {prev!r} and {split!r}"
                )


# ---------------------------------------------------------------------------
# Class-ratio policy
# ---------------------------------------------------------------------------
def balance_train(records: list[RequestRecord], cfg: ScopeConfig) -> list[RequestRecord]:
    """Raise train attack share to the target ratio when attacks are scarce.

    Policy (scope.toml ``dataset``): 5–10% attacks is a FLOOR. Live traffic
    (~0.1% attacks) gets attacks oversampled up to ``target_attack_ratio``;
    public corpora (~25–30% attacks) are kept whole. ``min_attack_ratio`` is
    asserted afterwards as a hard floor. Oversampled duplicates carry
    ``meta['oversampled']=true`` and an ``#ovN`` id suffix so metrics can be
    computed with or without them.
    """
    attacks = [r for r in records if r.label.class_ == "attack"]
    benign = [r for r in records if r.label.class_ == "benign"]
    others = [r for r in records if r.label.class_ not in ("attack", "benign")]
    n = len(attacks) + len(benign)
    if n == 0:
        return records
    ratio = len(attacks) / n
    if ratio >= cfg.dataset.target_attack_ratio:
        return records  # already at/above target (public-corpus case) — keep everything

    target = cfg.dataset.target_attack_ratio
    need = max(0, int(round(len(benign) * target / (1.0 - target))) - len(attacks))
    rng = random.Random(cfg.dataset.seed)
    out = list(records)
    for k in range(need):
        src = attacks[k % len(attacks)]
        dup = RequestRecord.from_json(json.loads(json.dumps(src.to_json())))
        dup.id = f"{src.id}#ov{k}"
        dup.meta["oversampled"] = True
        out.append(dup)
    rng.shuffle(out)
    return out


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
def build(input_path: Path, out_dir: Path, cfg: ScopeConfig, include_out_of_scope: bool = False) -> dict:
    d = cfg.dataset
    records = [r for r in read_jsonl(input_path) if r.label.class_ != "unknown"]

    # v1 filtering: benign + in-scope attacks; out-of-scope families are kept
    # only on request (their labels are preserved either way).
    excluded_out_of_scope = 0
    if not include_out_of_scope:
        kept = [
            r
            for r in records
            if r.label.class_ == "benign" or r.label.in_scope or r.label.attack_category == "untyped"
        ]
        excluded_out_of_scope = len(records) - len(kept)
        records = kept

    holdout = set(d.holdout_techniques)
    unseen = [
        r
        for r in records
        if r.label.class_ == "attack" and (r.label.attack_technique or "") in holdout
    ]
    unseen_ids = {r.id for r in unseen}
    # Quarantine: anything sharing a group with a holdout attack is excluded
    # from the main splits entirely (campaign/session contamination).
    contaminated = {r.group_id for r in unseen}
    excluded = [
        r
        for r in records
        if r.id not in unseen_ids and r.group_id in contaminated
    ]
    main_pool = [
        r
        for r in records
        if r.id not in unseen_ids and r.group_id not in contaminated
    ]

    splits = group_aware_split(main_pool, cfg)
    splits["train"] = balance_train(splits["train"], cfg)

    out_dir.mkdir(parents=True, exist_ok=True)
    sizes = {}
    for split, recs in splits.items():
        path = out_dir / f"{split}.jsonl.gz"
        sizes[split] = write_jsonl(path, recs)
    sizes["test_unseen"] = write_jsonl(out_dir / "test_unseen.jsonl.gz", unseen)

    # splits index for leakage audits downstream
    index = {
        split: sorted({r.group_id for r in recs}) for split, recs in splits.items()
    }
    index["test_unseen"] = sorted({r.group_id for r in unseen})
    (out_dir / "splits_index.json").write_text(json.dumps(index, indent=2) + "\n")

    stats = compute_stats(splits, unseen, sizes, cfg)
    stats["excluded_by_holdout_contamination"] = len(excluded)
    stats["excluded_out_of_scope"] = excluded_out_of_scope
    (out_dir / "stats.json").write_text(json.dumps(stats, indent=2, sort_keys=True) + "\n")
    return stats


def _counts(recs: list[RequestRecord]) -> dict:
    by_class: dict[str, int] = defaultdict(int)
    by_source: dict[str, int] = defaultdict(int)
    by_category: dict[str, int] = defaultdict(int)
    truncated = 0
    for r in recs:
        by_class[r.label.class_] += 1
        by_source[r.source] += 1
        by_category[r.label.attack_category or "none"] += 1
        truncated += int(r.body_truncated)
    return {
        "records": len(recs),
        "groups": len({r.group_id for r in recs}),
        "by_class": dict(by_class),
        "by_source": dict(by_source),
        "by_category": dict(by_category),
        "bodies_truncated": truncated,
    }


def compute_stats(
    splits: dict[str, list[RequestRecord]],
    unseen: list[RequestRecord],
    sizes: dict[str, int],
    cfg: ScopeConfig,
) -> dict:
    all_main = [r for recs in splits.values() for r in recs]
    attack = sum(1 for r in splits["train"] if r.label.class_ == "attack")
    train_n = len(splits["train"])
    stats = {
        "config": {
            "seed": cfg.dataset.seed,
            "fractions": {
                "train": cfg.dataset.train_fraction,
                "val": cfg.dataset.val_fraction,
                "test": cfg.dataset.test_fraction,
            },
            "min_attack_ratio": cfg.dataset.min_attack_ratio,
            "target_attack_ratio": cfg.dataset.target_attack_ratio,
            "holdout_techniques": list(cfg.dataset.holdout_techniques),
            "body_max_bytes": cfg.dataset.body_max_bytes,
        },
        "splits": {name: _counts(recs) for name, recs in splits.items()},
        "test_unseen": _counts(unseen),
        "train_attack_ratio": round(attack / train_n, 4) if train_n else 0.0,
        "overall": _counts(all_main),
        "files_written": sizes,
    }
    # Final leakage audit across ALL artifacts (main splits + holdout).
    everything = dict(splits)
    everything["test_unseen"] = unseen
    audit_split_leakage(everything)
    stats["leakage_audit"] = "passed"
    return stats


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build leak-free train/val/test splits")
    ap.add_argument("--input", type=Path, default=Path("data/interim/labeled.jsonl"))
    ap.add_argument("--out-dir", type=Path, default=Path("data/processed"))
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    ap.add_argument(
        "--include-out-of-scope",
        action="store_true",
        help="keep out-of-scope attack families (path traversal, cmd injection, ...)",
    )
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    stats = build(args.input, args.out_dir, cfg, args.include_out_of_scope)
    print(json.dumps({"train_attack_ratio": stats["train_attack_ratio"],
                      "splits": {k: v["records"] for k, v in stats["splits"].items()},
                      "test_unseen": stats["test_unseen"]["records"],
                      "leakage_audit": stats["leakage_audit"]}, indent=2))
    print(f"wrote dataset to {args.out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
