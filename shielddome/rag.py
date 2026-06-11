"""Trusted notification style fingerprints for the MVP RAG layer."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

from .links import is_trusted_domain, normalize_domain


@dataclass
class TrustedStyleFingerprint:
    style_id: str
    notification_type: str
    subject_terms: list[str]
    body_terms: list[str]
    allowed_sender_domains: list[str]
    allowed_link_domains: list[str]
    expected_actions: list[str]


DEFAULT_FINGERPRINTS = [
    TrustedStyleFingerprint(
        style_id="oa-approval-v1",
        notification_type="OA approval",
        subject_terms=["审批", "OA", "待办", "流程"],
        body_terms=["审批系统", "待办", "流程", "登录OA"],
        allowed_sender_domains=["company.com", "oa.company.com", "comservice.com"],
        allowed_link_domains=["oa.company.com", "sso.company.com"],
        expected_actions=["login", "approve"],
    ),
    TrustedStyleFingerprint(
        style_id="password-reset-v1",
        notification_type="password reset",
        subject_terms=["密码", "重置", "账号"],
        body_terms=["统一身份认证", "重置密码", "验证码"],
        allowed_sender_domains=["sso.company.com", "mail.company.com"],
        allowed_link_domains=["sso.company.com"],
        expected_actions=["reset_password"],
    ),
    TrustedStyleFingerprint(
        style_id="invoice-notice-v1",
        notification_type="invoice notice",
        subject_terms=["发票", "电子发票", "报销"],
        body_terms=["发票系统", "电子发票", "查验"],
        allowed_sender_domains=["invoice.company.com", "mail.company.com"],
        allowed_link_domains=["invoice.company.com"],
        expected_actions=["open_invoice"],
    ),
]


class TrustedStyleIndex:
    def __init__(self, fingerprints: list[TrustedStyleFingerprint] | None = None):
        self._fingerprints = list(fingerprints or DEFAULT_FINGERPRINTS)

    @property
    def fingerprints(self) -> list[TrustedStyleFingerprint]:
        return list(self._fingerprints)

    def add_fingerprint(self, fingerprint: TrustedStyleFingerprint) -> None:
        self._fingerprints.append(fingerprint)

    def match(self, subject: str, body: str, sender: str, links: list[dict[str, Any]]) -> dict[str, Any]:
        best: dict[str, Any] | None = None
        text = f"{subject}\n{body}"
        sender_domain = normalize_domain(sender)
        link_domains = {normalize_domain(link.get("href_domain") or link.get("href")) for link in links}
        link_domains.discard("")

        for fingerprint in self._fingerprints:
            subject_hits = sum(1 for term in fingerprint.subject_terms if term.lower() in subject.lower())
            body_hits = sum(1 for term in fingerprint.body_terms if term.lower() in text.lower())
            denominator = max(1, len(fingerprint.subject_terms) + len(fingerprint.body_terms))
            similarity = min(1.0, (subject_hits + body_hits) / denominator)

            sender_allowed = any(
                sender_domain == domain or sender_domain.endswith(f".{domain}")
                for domain in fingerprint.allowed_sender_domains
            )
            link_allowed = all(
                any(link_domain == domain or link_domain.endswith(f".{domain}") for domain in fingerprint.allowed_link_domains)
                for link_domain in link_domains
            )
            link_external_to_enterprise = any(not is_trusted_domain(link_domain) for link_domain in link_domains)
            anomaly_score = 0
            anomalies: list[str] = []

            if similarity >= 0.35 and sender_domain and not sender_allowed:
                anomaly_score += 25
                anomalies.append("trusted_style_sender_domain_mismatch")
            if similarity >= 0.35 and link_domains and not link_allowed:
                anomaly_score += 25
                anomalies.append("trusted_style_link_domain_mismatch")
            if similarity >= 0.35 and link_external_to_enterprise:
                anomaly_score += 10
                anomalies.append("trusted_style_external_link")

            candidate = {
                "style": asdict(fingerprint),
                "similarity": round(similarity, 3),
                "anomaly_score": anomaly_score,
                "anomalies": anomalies,
            }
            if best is None or candidate["similarity"] + candidate["anomaly_score"] / 100 > best["similarity"] + best["anomaly_score"] / 100:
                best = candidate

        return best or {
            "style": None,
            "similarity": 0,
            "anomaly_score": 0,
            "anomalies": [],
        }

