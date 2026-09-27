"""Step 8 — classification metrics. Pure Python so tests run without torch.

The plan is explicit: monitor precision and recall SEPARATELY — accuracy is a
trap when traffic is 99.9% benign. All functions take (y_true, y_score) with
y_score = p(malicious).
"""

from __future__ import annotations


def binary_confusion(y_true: list[int], y_score: list[float], threshold: float = 0.5) -> dict[str, int]:
    tp = fp = tn = fn = 0
    for t, s in zip(y_true, y_score):
        pred = 1 if s >= threshold else 0
        if pred == 1 and t == 1:
            tp += 1
        elif pred == 1 and t == 0:
            fp += 1
        elif pred == 0 and t == 0:
            tn += 1
        else:
            fn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def precision_recall_f1(y_true: list[int], y_score: list[float], threshold: float = 0.5) -> dict[str, float]:
    c = binary_confusion(y_true, y_score, threshold)
    tp, fp, fn, tn = c["tp"], c["fp"], c["fn"], c["tn"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "threshold": threshold,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round((tp + tn) / max(tp + tn + fp + fn, 1), 4),
        "fpr": round(fp / (fp + tn), 4) if fp + tn else 0.0,
        **{k: v for k, v in c.items()},
    }


def threshold_for_min_recall(
    y_true: list[int], y_score: list[float], min_recall: float = 0.95
) -> dict[str, float]:
    """Highest-precision threshold achieving recall >= min_recall.

    This is the operating-point selection the plan wants: chase high recall
    (don't miss attacks) while keeping precision acceptable (don't block real
    users). Scans candidate thresholds at observed score midpoints.
    """
    candidates = sorted(set(y_score))
    if not candidates:
        return {"threshold": 0.5, "precision": 0.0, "recall": 0.0}
    probes = [candidates[0] - 1e-9] + [(a + b) / 2 for a, b in zip(candidates, candidates[1:])] + [candidates[-1] + 1e-9]
    best = None
    for thr in probes:
        m = precision_recall_f1(y_true, y_score, thr)
        if m["recall"] >= min_recall:
            if best is None or m["precision"] > best["precision"] or (
                m["precision"] == best["precision"] and m["threshold"] > best["threshold"]
            ):
                best = m
    return best or precision_recall_f1(y_true, y_score, 0.5)


def recall_by_group(
    y_true: list[int], y_score: list[float], groups: list[str], threshold: float = 0.5
) -> dict[str, dict[str, float]]:
    """Per-group recall (groups = attack category, technique, source...)."""
    out: dict[str, dict[str, float]] = {}
    seen: dict[str, list[tuple[int, float]]] = {}
    for t, s, g in zip(y_true, y_score, groups):
        seen.setdefault(g, []).append((t, s))
    for g, pairs in seen.items():
        pos = [(t, s) for t, s in pairs if t == 1]
        if not pos:
            continue
        caught = sum(1 for _, s in pos if s >= threshold)
        out[g] = {"support": len(pos), "recall": round(caught / len(pos), 4)}
    return dict(sorted(out.items()))


def percentile(values: list[float], q: float) -> float:
    """Nearest-rank percentile (q in [0, 100]) for latency numbers."""
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = max(0, min(len(ordered) - 1, int(round(q / 100 * (len(ordered) - 1)))))
    return ordered[idx]
