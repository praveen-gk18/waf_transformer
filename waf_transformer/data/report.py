"""Render the Phase-2 dataset report from pipeline stats + fetch manifest.

Writes ``data/reports/dataset_report.md`` and copies ``stats.json`` there.
The report is the human-readable proof of what was built: source inventory,
label distribution per split, class ratios, group/leakage audit, and the exact
commands that reproduce everything.

Usage::

    python3 -m waf_transformer.data.report \
        --stats data/processed/stats.json --manifest data/raw/MANIFEST.json \
        --out-dir data/reports
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
import sys
from pathlib import Path

from ..config import DEFAULT_CONFIG_PATH, load_config


def _table(headers: list[str], rows: list[list[str]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(lines)


def render(stats: dict, manifest: dict, cfg_path: Path) -> str:
    cfg = load_config(cfg_path)
    today = dt.date.today().isoformat()

    out: list[str] = []
    out.append("# waf_transformer — Phase 2 dataset report")
    out.append("")
    out.append(f"_Generated {today} by `python3 -m waf_transformer.data.report`. "
               "Do not edit by hand — regenerate._")
    out.append("")

    # ---- source inventory ----
    out.append("## 1. Source inventory (Step 3–4)")
    out.append("")
    rows = []
    for name, entry in sorted(manifest.items()):
        nfiles = len(entry.get("files", {}))
        rows.append([
            name,
            entry.get("strategy", "?"),
            str(nfiles),
            f"{sum(f['bytes'] for f in entry.get('files', {}).values()) / 1e6:.1f} MB",
        ])
    if rows:
        out.append(_table(["dataset", "fetch strategy", "files", "size"], rows))
    else:
        out.append("_No fetch manifest found — synthetic-only build._")
    out.append("")

    # ---- label distribution ----
    out.append("## 2. Label distribution (Step 5)")
    out.append("")
    out.append(_table(
        ["split", "records", "groups", "benign", "attack", "attack ratio"],
        [
            [
                name,
                str(s["records"]),
                str(s["groups"]),
                str(s["by_class"].get("benign", 0)),
                str(s["by_class"].get("attack", 0)),
                f"{s['by_class'].get('attack', 0) / max(s['records'], 1):.1%}",
            ]
            for name, s in stats["splits"].items()
        ]
        + [
            [
                "test_unseen",
                str(stats["test_unseen"]["records"]),
                str(stats["test_unseen"]["groups"]),
                str(stats["test_unseen"]["by_class"].get("benign", 0)),
                str(stats["test_unseen"]["by_class"].get("attack", 0)),
                f"{stats['test_unseen']['by_class'].get('attack', 0) / max(stats['test_unseen']['records'], 1):.1%}",
            ]
        ],
    ))
    out.append("")
    out.append(f"- Train attack ratio: **{stats['train_attack_ratio']:.1%}** "
               f"(floor {cfg.dataset.min_attack_ratio:.0%}, "
               f"oversample target {cfg.dataset.target_attack_ratio:.0%})")
    out.append(f"- Leakage audit: **{stats['leakage_audit']}** "
               "(no session/source/generator group straddles splits)")
    out.append("")

    # ---- by source ----
    out.append("## 3. Composition by source")
    out.append("")
    overall_sources = stats["overall"]["by_source"]
    out.append(_table(
        ["source", "records"],
        [[k, str(v)] for k, v in sorted(overall_sources.items(), key=lambda kv: -kv[1])],
    ))
    out.append("")

    # ---- by category ----
    out.append("## 4. Attack categories (train+val+test)")
    out.append("")
    cats = {k: v for k, v in stats["overall"]["by_category"].items() if k != "none"}
    out.append(_table(
        ["category", "records", "v1 scope"],
        [
            [k, str(v), "in-scope" if k in cfg.in_scope_categories or k == "untyped" else "out-of-scope"]
            for k, v in sorted(cats.items(), key=lambda kv: -kv[1])
        ],
    ))
    out.append("")

    # ---- holdout ----
    out.append("## 5. Unseen-technique holdout (Step 9 preparation)")
    out.append("")
    techs = sorted(stats["config"]["holdout_techniques"])
    out.append(f"Techniques reserved for Phase-3 generalization evaluation: "
               f"{', '.join(f'`{t}`' for t in techs) or '_none_'}.")
    out.append(f"`test_unseen.jsonl.gz` holds {stats['test_unseen']['records']} attack records "
               "that never appear in train/val/test.")
    excluded = stats.get("excluded_by_holdout_contamination", 0)
    if excluded:
        out.append(f"- {excluded} records sharing a session/source group with a holdout "
                   "attack were excluded from the main splits (campaign contamination guard).")
    oos = stats.get("excluded_out_of_scope", 0)
    if oos:
        out.append(f"- {oos} records of out-of-scope attack families (path traversal, command "
                   "injection, …) were excluded from the v1 splits — re-include with "
                   "`build_dataset --include-out-of-scope`.")
    out.append("")

    # ---- truncation ----
    trunc = sum(s["bodies_truncated"] for s in stats["splits"].values())
    out.append("## 6. Edge-case handling (Step 17)")
    out.append("")
    out.append(f"- Bodies truncated at {cfg.dataset.body_max_bytes} bytes: **{trunc}** records "
               "(flagged with `body_truncated`; file uploads beyond this are a Phase-4 parsing concern)")
    out.append(f"- Headers kept verbatim, capped at {cfg.dataset.header_max_count} "
               f"headers / {cfg.dataset.header_value_max_bytes} bytes per value at ingest")
    out.append("- Encrypted traffic is out of scope here by design — the engine sits behind TLS termination")
    out.append("")

    # ---- scope echo ----
    out.append("## 7. Scope echo (config/scope.toml)")
    out.append("")
    out.append(f"- Objective: **{cfg.objective}** classification of full HTTP requests")
    out.append(f"- In-scope attack families: {', '.join(f'`{c}`' for c in cfg.in_scope_categories)}")
    out.append(f"- Latency budget: p50 ≤ {cfg.latency.p50} ms, p95 ≤ {cfg.latency.p95} ms, "
               f"p99 ≤ {cfg.latency.p99} ms (hard cap {cfg.latency.hard_cap} ms)")
    out.append("")

    # ---- reproducibility ----
    out.append("## 8. Reproduce this build")
    out.append("")
    out.append("```bash")
    out.append("make data-pipeline   # fetch -> generate -> ingest -> label -> build -> report")
    out.append("make test            # unit tests")
    out.append("```")
    out.append("")
    out.append("Artifacts: `data/processed/{train,val,test,test_unseen}.jsonl.gz`, "
               "`splits_index.json`, `stats.json` (gitignored; regenerate locally). "
               "Only `data/reports/` and `data/samples/` are versioned.")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Render Phase-2 dataset report")
    ap.add_argument("--stats", type=Path, default=Path("data/processed/stats.json"))
    ap.add_argument("--manifest", type=Path, default=Path("data/raw/MANIFEST.json"))
    ap.add_argument("--out-dir", type=Path, default=Path("data/reports"))
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    args = ap.parse_args(argv)

    stats = json.loads(args.stats.read_text())
    manifest = {}
    if args.manifest.exists():
        manifest = json.loads(args.manifest.read_text())

    args.out_dir.mkdir(parents=True, exist_ok=True)
    report = render(stats, manifest, args.config)
    (args.out_dir / "dataset_report.md").write_text(report)
    shutil.copyfile(args.stats, args.out_dir / "stats.json")
    if args.manifest.exists():
        shutil.copyfile(args.manifest, args.out_dir / "fetch_manifest.json")
    print(report)
    print(f"report -> {args.out_dir / 'dataset_report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
