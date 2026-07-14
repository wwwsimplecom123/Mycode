"""Structured evidence, grouped scoring and user-readable explanations."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable


GROUP_CAPS = {
    "reputation": 95,
    "sender_identity": 55,
    "impersonation": 55,
    "url_deception": 70,
    "sensitive_intent": 35,
    "attachment": 90,
    "authentication": 35,
    "campaign": 45,
    "rag_similarity": 25,
    "model_semantics": 20,
}

GROUP_LABELS = {
    "reputation": "高风险域名或信誉异常",
    "sender_identity": "发件人身份异常",
    "impersonation": "身份冒充特征",
    "url_deception": "邮件链接异常",
    "sensitive_intent": "敏感操作意图",
    "attachment": "附件安全风险",
    "authentication": "邮件身份验证异常",
    "campaign": "批量攻击特征",
    "rag_similarity": "历史案例相似度",
    "model_semantics": "智能语义分析",
}


@dataclass(frozen=True)
class Evidence:
    rule_id: str
    title: str
    explanation: str
    group: str
    base_weight: int
    confidence: float = 1.0
    entity_key: str = "message"
    polarity: str = "risk"
    rule_version: int = 1
    suppression_factor: float = 1.0
    suppression_reasons: tuple[str, ...] = field(default_factory=tuple)
    source: str = "quick_rule"
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def effective_weight(self) -> int:
        sign = -1 if self.polarity == "protective" else 1
        return sign * round(abs(self.base_weight) * max(0.0, min(1.0, self.confidence)) * max(0.0, min(1.0, self.suppression_factor)))

    def to_dict(self, effective_weight: int | None = None, deduplicated: bool = False) -> dict[str, Any]:
        value = asdict(self)
        value["suppression_reasons"] = list(self.suppression_reasons)
        value["effective_weight"] = self.effective_weight if effective_weight is None else effective_weight
        value["suppressed"] = self.suppression_factor < 1.0 or deduplicated
        value["deduplicated"] = deduplicated
        return value


def evidence_from_dict(value: dict[str, Any]) -> Evidence:
    allowed = {
        "rule_id", "title", "explanation", "group", "base_weight", "confidence",
        "entity_key", "polarity", "rule_version", "suppression_factor",
        "suppression_reasons", "source", "attributes",
    }
    payload = {key: item for key, item in value.items() if key in allowed}
    payload["suppression_reasons"] = tuple(payload.get("suppression_reasons") or ())
    return Evidence(**payload)


def aggregate_evidence(values: Iterable[Evidence], thresholds: dict[str, int]) -> dict[str, Any]:
    """Deduplicate one fact per group/entity, cap groups, then explain the result."""
    items = list(values)
    winners: dict[tuple[str, str, str], Evidence] = {}
    duplicates: set[int] = set()
    for index, item in enumerate(items):
        # Risk and protective evidence must not cancel during deduplication.
        key = (item.group, item.entity_key, item.polarity)
        current = winners.get(key)
        if current is None or abs(item.effective_weight) > abs(current.effective_weight):
            if current is not None:
                duplicates.add(items.index(current))
            winners[key] = item
        else:
            duplicates.add(index)

    group_raw: dict[str, int] = {}
    for item in winners.values():
        group_raw[item.group] = group_raw.get(item.group, 0) + item.effective_weight

    group_scores: dict[str, int] = {}
    for group, raw in group_raw.items():
        cap = GROUP_CAPS.get(group, 100)
        group_scores[group] = max(-cap, min(cap, raw))

    raw_score = sum(group_scores.values())
    final_score = max(0, min(100, raw_score))
    serialized: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        serialized.append(item.to_dict(0 if index in duplicates else None, index in duplicates))

    calculation_items = [
        {
            "group": item.group,
            "title": item.title,
            "explanation": item.explanation,
            "score": item.effective_weight,
        }
        for item in winners.values()
        if item.effective_weight
    ]
    calculation_items.sort(key=lambda item: abs(int(item["score"])), reverse=True)
    level = _risk_level(final_score, thresholds)
    threshold = thresholds["critical"] if level == "critical" else thresholds["high"] if level == "high" else thresholds["medium"] if level == "medium" else 0
    return {
        "score": final_score,
        "raw_score": raw_score,
        "risk_level": level,
        "evidences": serialized,
        "group_scores": group_scores,
        "calculation": {
            "items": calculation_items[:5],
            "raw_score": raw_score,
            "final_score": final_score,
            "capped": raw_score != final_score,
            "thresholds": dict(thresholds),
            "decision_explanation": f"最终 {final_score} 分，{_level_label(level)}起始分为 {threshold} 分。" if threshold else f"最终 {final_score} 分，低于中风险起始分 {thresholds['medium']} 分。",
        },
    }


def explain_final_score(
    base_group_scores: dict[str, int],
    adjustments: list[dict[str, Any]],
    final_score: int,
    thresholds: dict[str, int],
) -> dict[str, Any]:
    """Create a concise, arithmetically exact explanation for a final decision."""
    items = [
        {
            "group": group,
            "title": GROUP_LABELS.get(group, group),
            "explanation": "该类检测证据的综合贡献。",
            "score": int(score),
        }
        for group, score in base_group_scores.items()
        if int(score)
    ]
    items.extend({**item, "score": int(item.get("score") or 0)} for item in adjustments if int(item.get("score") or 0))
    explained = sum(int(item["score"]) for item in items)
    correction = int(final_score) - explained
    if correction:
        items.append({
            "group": "calibration",
            "title": "系统校准",
            "explanation": "根据证据强度、分组上限和等级安全条件进行调整。",
            "score": correction,
        })
    items.sort(key=lambda item: abs(int(item["score"])), reverse=True)
    if len(items) > 5:
        visible, remainder = items[:4], items[4:]
        visible.append({
            "group": "other",
            "title": "其他综合因素",
            "explanation": "其余较小的风险增加项和降低项已合并显示。",
            "score": sum(int(item["score"]) for item in remainder),
        })
        items = visible
    level = _risk_level(int(final_score), thresholds)
    threshold = thresholds["critical"] if level == "critical" else thresholds["high"] if level == "high" else thresholds["medium"] if level == "medium" else 0
    return {
        "items": items,
        "raw_score": explained,
        "final_score": int(final_score),
        "capped_or_calibrated": bool(correction),
        "thresholds": dict(thresholds),
        "decision_explanation": f"最终 {final_score} 分，{_level_label(level)}起始分为 {threshold} 分。" if threshold else f"最终 {final_score} 分，低于中风险起始分 {thresholds['medium']} 分。",
    }


def aggregate_rag_matches(matches: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate trusted and phishing references independently and order-independently."""
    phishing = [float(item.get("score") or 0) for item in matches if item.get("source_type") == "phishing_case" and float(item.get("score") or 0) >= 0.72]
    trusted = [float(item.get("score") or 0) for item in matches if item.get("source_type") == "trusted_email" and float(item.get("score") or 0) >= 0.82]
    phishing_confidence = max(phishing, default=0.0)
    trusted_confidence = max(trusted, default=0.0)
    conflict = phishing_confidence >= 0.85 and trusted_confidence >= 0.85
    if conflict:
        delta = 0
    else:
        risk = round(phishing_confidence * 25)
        protection = round(trusted_confidence * 10)
        delta = max(-10, min(25, risk - protection))
    return {
        "risk_delta": delta,
        "phishing_confidence": round(phishing_confidence, 4),
        "trusted_confidence": round(trusted_confidence, 4),
        "conflict": conflict,
        "requires_manual_review": conflict,
    }


def _risk_level(score: int, thresholds: dict[str, int]) -> str:
    if score >= thresholds["critical"]:
        return "critical"
    if score >= thresholds["high"]:
        return "high"
    if score >= thresholds["medium"]:
        return "medium"
    return "low"


def _level_label(level: str) -> str:
    return {"critical": "严重风险", "high": "高风险", "medium": "中风险", "low": "低风险"}[level]
