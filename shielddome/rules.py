"""Millisecond-level quick triage rules."""

from __future__ import annotations

from typing import Any

from .config import BLACKLISTED_DOMAINS, HIGH_RISK_KEYWORDS, RISK_THRESHOLDS
from .links import is_trusted_domain, normalize_domain, structuralize_links


def _contains_high_risk_keyword(text: str, keywords: set[str]) -> bool:
    lowered = text.lower()
    return any(keyword.lower() in lowered for keyword in keywords)


def _domain_in_set(domain: str, candidates: set[str]) -> bool:
    return any(domain == item or domain.endswith(f".{item}") for item in candidates)


def _level_and_action(score: int, thresholds: dict[str, int] | None = None) -> tuple[str, str]:
    thresholds = thresholds or RISK_THRESHOLDS
    if score >= thresholds["critical"]:
        return "critical", "block"
    if score >= thresholds["high"]:
        return "high", "block"
    if score >= thresholds["medium"]:
        return "medium", "warn"
    return "low", "allow"


def analyze_quick(
    payload: dict[str, Any],
    trusted_domains: set[str] | None = None,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    policy = policy or {}
    if "trusted_domains" in policy:
        trusted_domains = {str(value).lower() for value in policy["trusted_domains"]}
    trusted_ip_ranges = {str(value) for value in policy.get("trusted_ip_ranges", [])}
    trusted_urls = {str(value) for value in policy.get("trusted_urls", [])}
    trusted_include_subdomains = bool(policy.get("trusted_include_subdomains", True))
    blacklisted_domains = (
        {str(value).lower() for value in policy["blacklisted_domains"]}
        if "blacklisted_domains" in policy
        else BLACKLISTED_DOMAINS
    )
    high_risk_keywords = (
        {str(value) for value in policy["high_risk_keywords"]}
        if "high_risk_keywords" in policy
        else HIGH_RISK_KEYWORDS
    )
    thresholds = dict(policy.get("risk_thresholds") or RISK_THRESHOLDS)
    subject = str(payload.get("subject") or "")
    sender = str(payload.get("sender") or "")
    body_summary = str(payload.get("body_summary") or payload.get("body_text") or "")[:4000]
    links = structuralize_links(
        payload.get("links") or payload.get("links_structural") or [],
        trusted_domains,
        trusted_ip_ranges,
        trusted_include_subdomains,
        trusted_urls,
    )
    sender_domain = normalize_domain(sender)
    text_blob = " ".join(
        [
            subject,
            sender,
            body_summary,
            " ".join(link["display_text"] for link in links),
            " ".join(link["context_before"] + " " + link["context_after"] for link in links),
        ]
    )

    matched_rules: list[str] = []
    evidence: dict[str, Any] = {"links": links, "sender_domain": sender_domain}
    score_breakdown: dict[str, int] = {}
    score = 0

    external_links = [
        link for link in links if link["href_domain"] and link.get("is_web_link", True) and not link["trusted_href"]
    ]
    mismatched_links = [link for link in links if link["display_href_mismatch"]]
    blacklisted_links = [
        link for link in links if link["href_domain"] and _domain_in_set(link["href_domain"], blacklisted_domains)
    ]
    high_risk_intent = _contains_high_risk_keyword(text_blob, high_risk_keywords)

    def add_score(rule: str, value: int) -> None:
        nonlocal score
        score += value
        score_breakdown[rule] = value
        matched_rules.append(rule)

    if blacklisted_links:
        add_score("blacklisted_domain", 90)

    if mismatched_links:
        add_score("display_href_mismatch", 50)

    if external_links:
        add_score("external_link", 8)

    if high_risk_intent:
        add_score("high_risk_keyword", 7)

    if high_risk_intent and external_links:
        add_score("internal_intent_external_link", 15)

    if mismatched_links and any(is_trusted_domain(link.get("display_domain", ""), trusted_domains, trusted_include_subdomains) for link in mismatched_links):
        add_score("trusted_display_external_href", 25)

    if sender_domain and not is_trusted_domain(sender_domain, trusted_domains, trusted_include_subdomains) and high_risk_intent:
        add_score("external_sender_high_risk_intent", 5)

    score = min(score, 100)
    risk_level, action = _level_and_action(score, thresholds)
    deep_scan_required = risk_level in {"low", "medium", "high"}

    if "blacklisted_domain" in matched_rules:
        reason = "命中黑名单域名，已直接阻断。"
    elif "display_href_mismatch" in matched_rules:
        reason = "链接显示文本与真实跳转地址不一致。"
    elif "internal_intent_external_link" in matched_rules:
        reason = "邮件要求进行敏感业务操作，但包含外部链接。"
    elif external_links:
        reason = "邮件包含外部链接，已进入深度检测。"
    elif high_risk_intent:
        reason = "邮件包含敏感业务词汇，已进入深度检测。"
    else:
        reason = "未命中强规则，正在进行深度检测。"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "action": action,
        "reason": reason,
        "matched_rules": matched_rules,
        "deep_scan_required": deep_scan_required,
        "evidence": {
            **evidence,
            "score_breakdown": score_breakdown,
            "policy_summary": {
                "trusted_domains": len(trusted_domains or []),
                "trusted_urls": len(trusted_urls),
                "trusted_include_subdomains": trusted_include_subdomains,
                "trusted_ip_ranges": len(trusted_ip_ranges),
                "blacklisted_domains": len(blacklisted_domains),
                "high_risk_keywords": len(high_risk_keywords),
                "risk_thresholds": thresholds,
            },
        },
    }
