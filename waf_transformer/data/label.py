"""Labeling stage (Step 5: label everything).

Label provenance priority (config ``labeling.priority``, highest wins)::

    manual > waf_export > dataset > synthetic > heuristic > unknown

Roles of this module:

1. **Adjudicate labels** when several sources describe the same record
   (dataset claims vs. WAF-block export vs. analyst corrections).
2. **Type unlabelled attacks** — e.g. CSIC's binary ``Attack`` rows — with
   decoded-pattern heuristics (SQLi/XSS families first, per v1 scope).
3. **Label unlabelled logs** (future live traffic) with heuristic class +
   category; anything unfamilar stays ``unknown`` and goes to the review
   queue — never silently labeled benign.

Heuristic typing is intentionally conservative (strong/weak signal scoring);
it enriches categories, and only assigns ``class`` when there is no better
source of truth at all.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from .http_request import decode_layers
from .schema import Label, RequestRecord, category_in_scope, read_jsonl, write_jsonl

# ---------------------------------------------------------------------------
# Heuristic attack-family rules on DECODED request text.
# Each rule: (compiled regex, category, technique, strength 3=strong / 1=weak)
# ---------------------------------------------------------------------------
def _rx(p: str) -> re.Pattern[str]:
    return re.compile(p, re.IGNORECASE | re.MULTILINE)


HEURISTIC_RULES: list[tuple[re.Pattern[str], str, str, int]] = [
    # ---- SQL injection ----
    (_rx(r"\bunion\b[\s\S]{0,40}\bselect\b"), "sql_injection", "union_sql", 3),
    (_rx(r"\bselect\b[\s\S]{0,80}\bfrom\b[\s\S]{0,60}\bwhere\b"), "sql_injection", "union_sql", 3),
    (_rx(r"\b(sleep|pg_sleep)\s*\(|waitfor\s+delay|benchmark\s*\("), "sql_injection", "time_based_sql", 3),
    (_rx(r"\b(extractvalue|updatexml)\s*\(|floor\s*\(\s*rand|exp\s*\(\s*~"), "sql_injection", "error_based_sql", 3),
    (_rx(r";\s*(drop|update|insert|delete|exec|truncate|alter)\b"), "sql_injection", "stacked_sql", 3),
    (_rx(r"'\s*;\s*"), "sql_injection", "stacked_sql", 3),
    (_rx(r"(\bor\b|\band\b)\s*['\"]?[\w\s]*['\"]?\s*(=|like)\s*['\"]?\s*[\w'\"]+"), "sql_injection", "boolean_blind_sql", 1),
    (_rx(r"'\s*(or|and)\s*'?"), "sql_injection", "boolean_blind_sql", 1),
    (_rx(r"\b(information_schema|@@version|load_file\s*\(|into\s+(out|dump)file|xp_cmdshell)\b"), "sql_injection", "union_sql", 3),
    (_rx(r"\bconcat\s*\(\s*0x|\bchar\s*\(\s*\d+(\s*,\s*\d+){2,}|0x[0-9a-f]{8,}\b"), "sql_injection", "error_based_sql", 1),
    (_rx(r"(--\s|#\s|/\*[\s\S]*?\*/)"), "sql_injection", "unknown", 1),
    # ---- XSS ----
    (_rx(r"<\s*script\b"), "xss", "reflected_xss", 3),
    (_rx(r"\bon(error|load|click|mouseover|focus|blur|submit|toggle|animationstart|begin)\s*="), "xss", "reflected_xss", 3),
    (_rx(r"javascript\s*:"), "xss", "reflected_xss", 3),
    (_rx(r"data\s*:\s*text/html"), "xss", "reflected_xss", 3),
    (_rx(r"<\s*(img|svg|iframe|body|video|audio|details|marquee|input|object|embed|form|link|meta|base)\b"), "xss", "reflected_xss", 1),
    (_rx(r"document\s*\.\s*(cookie|write|domain|location)|window\s*\.\s*(location|name)\b"), "xss", "dom_xss", 3),
    (_rx(r"\balert\s*\(|\beval\s*\(|String\s*\.\s*fromCharCode|\batob\s*\("), "xss", "dom_xss", 1),
    (_rx(r"<\s*/?\s*(script|svg|iframe|img|body|video|details)\b[^>]*>"), "xss", "reflected_xss", 1),
    # ---- out-of-scope families (typed for taxonomy completeness) ----
    (_rx(r"(\.\./|\.\.\\|%2e%2e[/%]|\.%2e[/%])"), "path_traversal", "unknown", 3),
    (_rx(r"(\||;|&&|\$\(|`)\s*(cat|ls|id|whoami|uname|curl|wget|nc|bash|sh|powershell|cmd)\b"), "command_injection", "unknown", 3),
    (_rx(r"(\*\)\(|\(\s*\|\||&\(|\(\s*(uid|cn|sn)=\*|\(\s*objectclass=)"), "ldap_injection", "unknown", 3),
    (_rx(r"'\]\s*\|\s*//|child::\w+|text\s*\(\s*\)\s*\[\s*position|\/\/\w+\[\w+=\s*'"), "xpath_injection", "unknown", 3),
    (_rx(r"<!--\s*#\s*(exec|include|echo|env)"), "ssi", "unknown", 3),
]

STRONG_SCORE = 3
CONF_STRONG = 0.9
CONF_WEAK = 0.6


def type_attack(text: str) -> tuple[str | None, str | None, float]:
    """Score decoded request text against heuristic rules.

    Returns (category, technique, confidence). Best-scoring category wins;
    ties break toward the v1 in-scope families (sql_injection, xss).
    """
    blob = decode_layers(text)
    scores: dict[str, list] = {}
    for rx, category, technique, strength in HEURISTIC_RULES:
        if rx.search(blob):
            entry = scores.setdefault(category, [0.0, "unknown"])
            entry[0] += strength
            if strength == STRONG_SCORE and entry[1] == "unknown":
                entry[1] = technique
    if not scores:
        return None, None, 0.0
    priority = {"sql_injection": 2, "xss": 2}
    best = max(scores.items(), key=lambda kv: (kv[1][0], priority.get(kv[0], 0)))
    category, (score, technique) = best
    conf = CONF_STRONG if score >= STRONG_SCORE else CONF_WEAK
    return category, (technique if technique != "unknown" else None), conf


# ---------------------------------------------------------------------------
# WAF-export ingestion: anything your existing WAF blocked IS an attack.
# ---------------------------------------------------------------------------
def label_from_waf_export(blocked_ids: dict[str, str | None]) -> dict[str, Label]:
    """Map record-id -> Label from an existing WAF's block log export.

    ``blocked_ids``: {request_id: attack_category_hint_or_None}. Records in a
    block log get class=attack, label_source=waf_export.
    """
    out: dict[str, Label] = {}
    for rid, hint in blocked_ids.items():
        out[rid] = Label(
            class_="attack",
            attack_category=hint,
            label_source="waf_export",
            confidence=1.0,
        )
    return out


# ---------------------------------------------------------------------------
# Adjudication + enrichment
# ---------------------------------------------------------------------------
_PRIORITY = {
    "manual": 5,
    "waf_export": 4,
    "dataset": 3,
    "synthetic": 3,
    "heuristic": 1,
    "unknown": 0,
}


def _rank(label: Label) -> int:
    return _PRIORITY.get(label.label_source, 0)


def adjudicate(*labels: Label) -> Label:
    """Pick the highest-priority label; class conflicts with a stronger source
    are resolved in favor of the stronger source."""
    valid = [lb for lb in labels if lb.class_ != "unknown"]
    return max(valid, key=_rank) if valid else labels[-1]


def enrich(record: RequestRecord) -> RequestRecord:
    """Fill missing attack category/technique via heuristics; never downgrades.

    - class='unknown' + heuristic hit  -> becomes attack (label_source=heuristic)
    - class='attack' + untyped         -> category/technique enriched in place
    - class='benign'                   -> left alone (weird-benign stays benign)
    """
    lb = record.label
    if lb.class_ == "benign":
        return record
    category, technique, conf = type_attack(record.blob())
    if lb.class_ == "unknown":
        if category:
            record.label = Label(
                class_="attack",
                attack_category=category,
                attack_technique=technique,
                in_scope=category_in_scope("attack", category),
                label_source="heuristic",
                confidence=conf,
            )
        return record
    if (lb.attack_category in (None, "untyped")) and category:
        lb.attack_category = category
        lb.attack_technique = technique
    elif lb.attack_category and not lb.attack_technique and technique:
        lb.attack_technique = technique
    if lb.class_ == "attack":
        lb.in_scope = category_in_scope("attack", lb.attack_category)
    return record


def apply_corrections(record: RequestRecord, corrections: dict[str, dict]) -> RequestRecord:
    """Apply analyst corrections (from the review workflow) — source 'manual'."""
    fix = corrections.get(record.id)
    if not fix:
        return record
    record.label = Label(
        class_=fix["class"],
        attack_category=fix.get("attack_category"),
        attack_technique=fix.get("attack_technique"),
        in_scope=fix.get("in_scope", True),
        label_source="manual",
        confidence=1.0,
    )
    return record


def label_records(
    records: list[RequestRecord],
    corrections: dict[str, dict] | None = None,
    waf_labels: dict[str, Label] | None = None,
) -> tuple[list[RequestRecord], dict]:
    """Full labeling pass. Returns (records, stats)."""
    corrections = corrections or {}
    waf_labels = waf_labels or {}
    stats = {"total": 0, "by_class": {}, "by_source": {}, "by_category": {}, "unknown": 0}
    out: list[RequestRecord] = []
    for rec in records:
        if rec.id in waf_labels:
            rec.label = adjudicate(rec.label, waf_labels[rec.id])
        rec = apply_corrections(rec, corrections)
        rec = enrich(rec)
        out.append(rec)
        stats["total"] += 1
        stats["by_class"][rec.label.class_] = stats["by_class"].get(rec.label.class_, 0) + 1
        stats["by_source"][rec.label.label_source] = stats["by_source"].get(rec.label.label_source, 0) + 1
        key = rec.label.attack_category or "none"
        stats["by_category"][key] = stats["by_category"].get(key, 0) + 1
        if rec.label.class_ == "unknown":
            stats["unknown"] += 1
    return out, stats


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Label unified request records")
    ap.add_argument("--input", type=Path, required=True, help="data/interim/unified.jsonl")
    ap.add_argument("--out", type=Path, required=True, help="data/interim/labeled.jsonl")
    ap.add_argument("--corrections", type=Path, default=None, help="review corrections JSONL")
    ap.add_argument("--waf-log", type=Path, default=None, help="WAF block-log export JSONL {id, category}")
    args = ap.parse_args(argv)

    corrections: dict[str, dict] = {}
    if args.corrections and args.corrections.exists():
        for line in args.corrections.read_text(encoding="utf-8").splitlines():
            if line.strip():
                obj = json.loads(line)
                corrections[obj["id"]] = obj

    waf_labels: dict[str, Label] = {}
    if args.waf_log and args.waf_log.exists():
        blocked: dict[str, str | None] = {}
        for line in args.waf_log.read_text(encoding="utf-8").splitlines():
            if line.strip():
                obj = json.loads(line)
                blocked[obj["id"]] = obj.get("attack_category")
        waf_labels = label_from_waf_export(blocked)

    records = list(read_jsonl(args.input))
    labeled, stats = label_records(records, corrections, waf_labels)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    write_jsonl(args.out, labeled)
    print(json.dumps(stats, indent=2, sort_keys=True))
    print(f"wrote {len(labeled)} labeled records -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
