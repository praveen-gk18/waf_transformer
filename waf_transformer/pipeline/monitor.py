"""Steps 15 & 19 — monitoring dashboard + model/data drift.

The plan: *"Build a monitoring dashboard. Track latency vs budget, accuracy,
false positive rate."* and later *"monitor for drift"*.

This job aggregates the decision audit logs (``data/decisions/``) into:

* ``data/reports/monitor.json``     — machine-readable metrics + drift state
* ``data/reports/dashboard-<day>.md`` — human dashboard for the day

What is tracked per day:

- volume + action rates (and shadow-mode would-be actions — the false-positive
  watchlist while not yet enforcing),
- latency p50/p95/p99 vs the ``[latency]`` budget,
- **drift**: PSI of the score distribution vs a stable baseline (deciles),
  plus volume and would-block-rate anomalies vs recent history,
- alerts with plain-English reasons (budget breach, drift, spikes).

The gateway serves this as ``GET /dashboard``; run it from cron next to the
nightly batch (``scripts/run_nightly.sh`` calls both).

Usage::

    python3 -m waf_transformer.pipeline.monitor            # today
    python3 -m waf_transformer.pipeline.monitor --day 2026-09-27
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections import defaultdict
from pathlib import Path

from ..modeling.metrics import percentile

DECILES = [i / 10 for i in range(11)]
PSI_ALERT = 0.2        # conventional "significant shift" bound
VOLUME_SPIKE = 3.0     # x recent average
WOULDBLOCK_SPIKE = 2.0  # x recent average


def _load_days(decisions_dir: Path) -> dict[str, list[dict]]:
    days: dict[str, list[dict]] = defaultdict(list)
    for path in sorted(decisions_dir.glob("decisions-*.jsonl")):
        day = path.stem.split("-", 1)[1]
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    days[day].append(json.loads(line))
    return days


def _hist(scores: list[float]) -> list[float]:
    """Decile histogram with Laplace smoothing (PSI needs non-zero bins)."""
    n = len(scores)
    counts = [1.0] * 10
    for s in scores:
        counts[min(int(s * 10), 9)] += 1.0
    total = sum(counts)
    return [c / total for c in counts]


def psi(actual: list[float], baseline: list[float]) -> float:
    """Population Stability Index over decile histograms."""
    import math

    total = 0.0
    for a, b in zip(actual, baseline):
        if a > 0 and b > 0:
            total += (a - b) * math.log(a / b)
    return total


def day_metrics(day: str, decisions: list[dict], budget: dict) -> dict:
    n = len(decisions)
    scores = [d["score"] for d in decisions]
    lat = [d["latency_ms"] for d in decisions]
    actions = defaultdict(int)
    shadow = defaultdict(int)
    for d in decisions:
        actions[d["action"]] += 1
        if d.get("shadow_action"):
            shadow[d["shadow_action"]] += 1
    p50, p95, p99 = (percentile(lat, q) for q in (50, 95, 99)) if lat else (0.0, 0.0, 0.0)
    return {
        "day": day,
        "requests": n,
        "actions": dict(actions),
        "shadow_would_block": shadow.get("block", 0),
        "shadow_would_challenge": shadow.get("challenge", 0),
        "score_mean": round(sum(scores) / n, 4) if n else 0.0,
        "score_hist": _hist(scores) if n else [],
        "latency_ms": {"p50": round(p50, 3), "p95": round(p95, 3), "p99": round(p99, 3)},
        "budget_ok": {"p50": p50 <= budget.get("p50", 1e9),
                      "p95": p95 <= budget.get("p95", 1e9),
                      "p99": p99 <= budget.get("p99", 1e9)},
    }


def build_monitor(days: dict[str, list[dict]], budget: dict) -> dict:
    ordered = sorted(days)
    per_day = [day_metrics(d, days[d], budget) for d in ordered]
    if not per_day:
        return {"days": [], "baseline_day": None, "drift": [], "alerts": []}

    # Baseline: the first day with traffic (stable reference until rotated).
    baseline = per_day[0]
    recent = per_day[-7:]
    drift = []
    alerts = []
    for m in per_day:
        entry = {"day": m["day"], "psi": None, "volume_ratio": None, "wouldblock_ratio": None}
        if baseline["score_hist"] and m["score_hist"]:
            entry["psi"] = round(psi(m["score_hist"], baseline["score_hist"]), 4)
        vols = [x["requests"] for x in recent if x["day"] != m["day"]]
        if vols:
            avg_v = sum(vols) / len(vols) or 1.0
            entry["volume_ratio"] = round(m["requests"] / avg_v, 2)
            wbs = [x["shadow_would_block"] / (x["requests"] or 1) for x in recent if x["day"] != m["day"]]
            avg_wb = sum(wbs) / len(wbs) or 1e-6
            entry["wouldblock_ratio"] = round(
                (m["shadow_would_block"] / (m["requests"] or 1)) / avg_wb, 2
            )
        drift.append(entry)

        if entry["psi"] is not None and entry["psi"] >= PSI_ALERT:
            alerts.append({"day": m["day"], "type": "drift",
                           "detail": f"score distribution PSI {entry['psi']} >= {PSI_ALERT} vs baseline {baseline['day']}"})
        if entry["volume_ratio"] is not None and entry["volume_ratio"] >= VOLUME_SPIKE:
            alerts.append({"day": m["day"], "type": "volume",
                           "detail": f"traffic volume {entry['volume_ratio']}x recent average"})
        if entry["wouldblock_ratio"] is not None and entry["wouldblock_ratio"] >= WOULDBLOCK_SPIKE:
            alerts.append({"day": m["day"], "type": "false_positives",
                           "detail": f"would-block rate {entry['wouldblock_ratio']}x recent average — review watchlist"})
        if not m["budget_ok"]["p95"]:
            alerts.append({"day": m["day"], "type": "latency",
                           "detail": f"p95 {m['latency_ms']['p95']} ms over budget {budget.get('p95')} ms"})

    latest = per_day[-1]
    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "baseline_day": baseline["day"],
        "days": per_day,
        "drift": drift,
        "alerts": alerts,
        "latest": latest,
    }


def render_dashboard(mon: dict, budget: dict) -> str:
    latest = mon.get("latest") or {}
    lines = [
        f"# WAF monitoring dashboard — {latest.get('day', 'n/a')}",
        "",
        f"_Generated {mon.get('generated_at')} — `python3 -m waf_transformer.pipeline.monitor`._",
        "",
        "## Headlines",
        "",
        f"- requests today: **{latest.get('requests', 0)}**",
        f"- actions: {latest.get('actions')}",
        f"- shadow would-block / would-challenge: "
        f"**{latest.get('shadow_would_block', 0)} / {latest.get('shadow_would_challenge', 0)}** "
        f"(false-positive watchlist)",
        f"- latency p50/p95/p99: **{latest.get('latency_ms')}** vs budget "
        f"{budget.get('p50')}/{budget.get('p95')}/{budget.get('p99')} ms",
        f"- score mean: {latest.get('score_mean')}  | drift baseline: day {mon.get('baseline_day')}",
        "",
        "## Alerts",
        "",
    ]
    if mon["alerts"]:
        lines += [f"- **{a['type']}** ({a['day']}): {a['detail']}" for a in mon["alerts"]]
    else:
        lines.append("- none")
    lines += ["", "## Drift (PSI vs baseline)", "",
              "| day | PSI | volume ratio | would-block ratio |", "|---|---|---|---|"]
    for e in mon["drift"]:
        flag = " ⚠" if (e["psi"] or 0) >= PSI_ALERT else ""
        lines.append(f"| {e['day']} | {e['psi']}{flag} | {e['volume_ratio']} | {e['wouldblock_ratio']} |")
    lines += ["", "## Latency vs budget by day", "",
              "| day | p50 | p95 | p99 | p95 ok |", "|---|---|---|---|---|"]
    for m in mon["days"]:
        ok = "✅" if m["budget_ok"]["p95"] else "❌"
        lines.append(f"| {m['day']} | {m['latency_ms']['p50']} | {m['latency_ms']['p95']} | "
                     f"{m['latency_ms']['p99']} | {ok} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Monitoring dashboard + drift")
    ap.add_argument("--decisions-dir", default="data/decisions")
    ap.add_argument("--out-dir", default="data/reports")
    ap.add_argument("--day", default=dt.date.today().isoformat())
    ap.add_argument("--config", default=None)
    args = ap.parse_args(argv)

    from ..config import load_config

    cfg = load_config(args.config) if args.config else load_config()
    budget = {"p50": cfg.latency.p50, "p95": cfg.latency.p95, "p99": cfg.latency.p99}

    days = _load_days(Path(args.decisions_dir))
    mon = build_monitor(days, budget)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "monitor.json").write_text(json.dumps(mon, indent=2, sort_keys=True) + "\n")
    (out / f"dashboard-{args.day}.md").write_text(render_dashboard(mon, budget))

    n_alerts = len(mon["alerts"])
    print(json.dumps({"days": len(mon["days"]), "alerts": n_alerts,
                      "monitor": str(out / "monitor.json")}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
