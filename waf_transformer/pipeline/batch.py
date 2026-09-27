"""Step 11 — nightly batch job: deeper analysis + training-data preparation.

The plan: *"Build a nightly job that pulls the day's logs from storage. This
job should do two things: (1) Analyze the day's traffic for patterns the
streaming model might have missed (slower, deeper analysis). (2) Prepare new
training data by labeling any newly discovered attacks."*

Input:  the day's decision logs (``data/decisions/decisions-YYYY-MM-DD.jsonl``,
written by the stream consumer and/or the enforcement gateway).
Output: ``data/batch/report-YYYY-MM-DD.md`` + ``summary.json`` +
``candidates.jsonl`` (heuristically-typed attack candidates → feed into the
Phase-2 review workflow: ``review sample`` → analyst → ``review merge`` →
``label --corrections`` → retrain).

Schedule with cron (see scripts/run_nightly.sh) or Airflow — the job is one
idempotent command.

Usage::

    python3 -m waf_transformer.pipeline.batch --day 2026-09-27
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections import defaultdict
from pathlib import Path

from ..data.label import type_attack
from ..data.schema import Label, RequestRecord
from ..modeling.metrics import percentile

SCORE_BUCKETS = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 1.01]


def load_day(decisions_dir: Path, day: str) -> list[dict]:
    path = decisions_dir / f"decisions-{day}.jsonl"
    if not path.exists():
        return []
    out = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                out.append(json.loads(line))
    return out


def analyze(decisions: list[dict]) -> dict:
    """Deeper analysis the streaming path doesn't have time for."""
    n = len(decisions)
    scores = [d["score"] for d in decisions]
    lat = [d["latency_ms"] for d in decisions]
    actions = defaultdict(int)
    shadow = defaultdict(int)
    buckets = defaultdict(int)
    path_scores: dict[str, list[float]] = defaultdict(list)
    flagged = []
    for d in decisions:
        actions[d["action"]] += 1
        if d.get("shadow_action"):
            shadow[d["shadow_action"]] += 1
        s = d["score"]
        for lo, hi in zip(SCORE_BUCKETS, SCORE_BUCKETS[1:]):
            if lo <= s < hi:
                buckets[f"{lo:.2f}-{hi:.2f}"] += 1
                break
        path_scores[d.get("path") or "?"].append(s)
        if d.get("shadow_action") in ("block", "challenge") or d["action"] in ("block", "challenge"):
            flagged.append(d)

    top_paths = sorted(
        (
            {"path": p, "n": len(v), "mean_score": round(sum(v) / len(v), 4), "max_score": round(max(v), 4)}
            for p, v in path_scores.items()
            if len(v) >= 3
        ),
        key=lambda x: -x["mean_score"],
    )[:15]

    # "Patterns the streaming model might have missed":
    # sessions/paths with several mid-score requests that individually looked
    # benign — probing behaviour visible only in aggregate.
    probes = sorted(
        (
            {"path": p, "n": len(v), "mid_score_requests": sum(1 for x in v if 0.3 <= x < 0.6)}
            for p, v in path_scores.items()
        ),
        key=lambda x: -x["mid_score_requests"],
    )[:10]

    return {
        "requests": n,
        "actions": dict(actions),
        "shadow_actions": dict(shadow),
        "score_histogram": dict(buckets),
        "score_mean": round(sum(scores) / n, 4) if n else 0.0,
        "latency_ms": {
            "p50": round(percentile(lat, 50), 3),
            "p95": round(percentile(lat, 95), 3),
            "p99": round(percentile(lat, 99), 3),
            "max": round(max(lat), 3) if lat else 0.0,
        } if lat else None,
        "top_paths_by_score": top_paths,
        "possible_probing": [p for p in probes if p["mid_score_requests"] >= 3],
        "flagged_count": len(flagged),
    }


def build_candidates(decisions: list[dict]) -> list[dict]:
    """(2) Prepare new training data: flagged requests get heuristic typing and
    land in candidates.jsonl — the Phase-2 review workflow labels them."""
    out = []
    for d in decisions:
        flagged = d.get("shadow_action") in ("block", "challenge") or d["action"] in ("block", "challenge")
        if not flagged or "request" not in d:
            continue
        req = d["request"]
        blob = "\n".join([
            req.get("method", ""), req.get("path", ""), req.get("query_string", ""),
            req.get("body", ""),
            *(f"{k}:{v}" for k, v in req.get("headers", [])),
        ])
        category, technique, conf = type_attack(blob)
        rec = RequestRecord(
            id=f"batch:{d['request_id']}",
            source="live:batch_candidates",
            method=req.get("method", "GET"),
            path=req.get("path", "/"),
            query_string=req.get("query_string", ""),
            http_version="HTTP/1.1",
            headers=[tuple(h) for h in req.get("headers", [])],
            body=req.get("body", ""),
            label=Label(
                class_="attack" if category else "unknown",
                attack_category=category,
                attack_technique=technique,
                in_scope=category in ("sql_injection", "xss", None),
                label_source="heuristic",
                confidence=conf or d["score"],
            ),
            meta={"model_score": d["score"], "action": d["action"], "shadow_action": d.get("shadow_action"),
                  "day": d["ts"][:10]},
        )
        out.append(rec.to_json())
    return out


def render_report(day: str, analysis: dict, candidates: int, budget: dict) -> str:
    a = analysis
    lat = a.get("latency_ms") or {}
    lines = [
        f"# Nightly batch report — {day}",
        "",
        f"_Generated by `python3 -m waf_transformer.pipeline.batch` at "
        f"{dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')}._",
        "",
        "## 1. Volume and decisions",
        "",
        f"- requests analyzed: **{a['requests']}**",
        f"- actions: {a['actions']}",
        f"- shadow-mode would-be actions: {a.get('shadow_actions') or '{}'} "
        f"(**false-positive watchlist** for Phase-5 shadow review)",
        "",
        "## 2. Score distribution",
        "",
        f"- mean score: {a['score_mean']}",
        "| bucket | count |",
        "|---|---|",
    ]
    for bucket in [f"{lo:.2f}-{hi:.2f}" for lo, hi in zip(SCORE_BUCKETS, SCORE_BUCKETS[1:])]:
        if bucket in a["score_histogram"]:
            lines.append(f"| {bucket} | {a['score_histogram'][bucket]} |")
    lines += [
        "",
        "## 3. Latency vs budget (Step 15 dashboard input)",
        "",
        f"- p50 {lat.get('p50')} ms (budget {budget.get('p50')}), "
        f"p95 {lat.get('p95')} ms (budget {budget.get('p95')}), "
        f"p99 {lat.get('p99')} ms (budget {budget.get('p99')})",
        "",
        "## 4. Patterns the stream may have missed",
        "",
        f"- top paths by mean score: `{json.dumps(a['top_paths_by_score'][:5])}`",
        f"- possible probing (3+ mid-score requests on one path): "
        f"`{json.dumps(a['possible_probing'][:5])}`",
        "",
        "## 5. New training data",
        "",
        f"- attack candidates for analyst review: **{candidates}** -> `candidates.jsonl`",
        "- route into the Phase-2 workflow: `review sample` -> analyst -> "
        "`review merge` -> `label --corrections` -> `build_dataset` -> retrain (Step 16)",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Nightly batch: analyze decisions + prep training data")
    ap.add_argument("--day", default=dt.date.today().isoformat())
    ap.add_argument("--decisions-dir", default="data/decisions")
    ap.add_argument("--out-dir", default="data/batch")
    ap.add_argument("--config", default=None)
    args = ap.parse_args(argv)

    decisions = load_day(Path(args.decisions_dir), args.day)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not decisions:
        print(f"no decisions found for {args.day} in {args.decisions_dir}", file=sys.stderr)
        (out_dir / f"report-{args.day}.md").write_text(
            f"# Nightly batch report — {args.day}\n\n_No decisions logged._\n"
        )
        return 1

    analysis = analyze(decisions)
    candidates = build_candidates(decisions)

    from ..config import load_config

    cfg = load_config(args.config) if args.config else load_config()
    budget = {"p50": cfg.latency.p50, "p95": cfg.latency.p95, "p99": cfg.latency.p99}

    (out_dir / f"report-{args.day}.md").write_text(render_report(args.day, analysis, len(candidates), budget))
    (out_dir / f"summary-{args.day}.json").write_text(json.dumps(analysis, indent=2, sort_keys=True) + "\n")
    with (out_dir / "candidates.jsonl").open("w", encoding="utf-8") as fh:
        for obj in candidates:
            fh.write(json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n")

    print(json.dumps({"day": args.day, "requests": analysis["requests"],
                      "flagged": analysis["flagged_count"], "candidates": len(candidates),
                      "report": str(out_dir / f"report-{args.day}.md")}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
