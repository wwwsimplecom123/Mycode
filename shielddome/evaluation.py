"""Offline metrics and threshold search for confirmed analysis labels."""

from __future__ import annotations

from itertools import product
from typing import Any, Iterable


POSITIVE_LABELS = {"phishing", "suspicious"}


def evaluate_dataset(rows: Iterable[dict[str, Any]], threshold: int) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    for row in rows:
        snapshot = row.get("snapshot") or {}
        result = row.get("result") or row.get("quick_result") or {}
        score = int(snapshot.get("risk_score", result.get("risk_score", 0)) or 0)
        actual = str(row.get("label") or "") in POSITIVE_LABELS
        predicted = score >= threshold
        if actual and predicted:
            tp += 1
        elif actual:
            fn += 1
        elif predicted:
            fp += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    false_positive_rate = fp / (fp + tn) if fp + tn else 0.0
    return {
        "sample_count": tp + fp + tn + fn,
        "threshold": threshold,
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "false_positive_rate": round(false_positive_rate, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0,
    }


def recommend_thresholds(rows: list[dict[str, Any]]) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    for medium, high, critical in product(range(25, 46, 5), range(55, 76, 5), range(80, 96, 5)):
        if not medium < high < critical:
            continue
        metrics = evaluate_dataset(rows, medium)
        candidates.append({"thresholds": {"medium": medium, "high": high, "critical": critical}, "metrics": metrics})
    eligible = [item for item in candidates if item["metrics"]["recall"] >= 0.98 and item["metrics"]["false_positive_rate"] <= 0.005]
    ranked = eligible or candidates
    ranked.sort(key=lambda item: (item["metrics"]["f1"], item["metrics"]["recall"], -item["metrics"]["false_positive_rate"]), reverse=True)
    return {
        "sample_count": len(rows),
        "meets_release_gate": bool(eligible) and bool(rows),
        "recommended": ranked[0] if ranked else None,
        "release_gate": {"minimum_recall": 0.98, "maximum_false_positive_rate": 0.005},
    }
