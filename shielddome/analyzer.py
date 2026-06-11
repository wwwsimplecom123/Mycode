"""Application service orchestration for ShieldDome MVP."""

from __future__ import annotations

import threading
import time
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Callable

from .config import HIGH_RISK_KEYWORDS, RISK_THRESHOLDS
from .entities import generalize_entities
from .llm import LLMClient
from .rag import TrustedStyleFingerprint, TrustedStyleIndex
from .rules import analyze_quick


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def level_and_action(score: int, thresholds: dict[str, int] | None = None) -> tuple[str, str]:
    thresholds = thresholds or RISK_THRESHOLDS
    if score >= thresholds["critical"]:
        return "critical", "block"
    if score >= thresholds["high"]:
        return "high", "block"
    if score >= thresholds["medium"]:
        return "medium", "warn"
    return "low", "allow"


def calibrate_score(
    score: int,
    matched_rules: list[str],
    attachment_indicators: list[str] | None = None,
    thresholds: dict[str, int] | None = None,
) -> tuple[int, list[str]]:
    thresholds = thresholds or RISK_THRESHOLDS
    rules = set(matched_rules)
    indicators = set(attachment_indicators or [])
    notes: list[str] = []
    strong_rules = {
        "blacklisted_domain",
        "display_href_mismatch",
        "trusted_display_external_href",
        "suspicious_attachment",
        "dmarc_fail",
    }
    critical_indicators = {
        "portable_executable_magic",
        "office_auto_execution_marker",
        "archive_contains_executable",
    }
    if score >= thresholds["high"] and not rules.intersection(strong_rules):
        score = thresholds["high"] - 1
        notes.append("high_risk_requires_strong_deterministic_evidence")
    if score >= thresholds["critical"] and "blacklisted_domain" not in rules and not indicators.intersection(critical_indicators):
        score = thresholds["critical"] - 1
        notes.append("critical_risk_requires_blacklist_or_malicious_attachment_evidence")
    return max(0, min(100, score)), notes


class AnalyzerService:
    def __init__(
        self,
        deep_delay_seconds: float = 0.8,
        llm_client: LLMClient | None = None,
        policy_provider: Callable[[], dict[str, Any]] | None = None,
    ):
        self._records: dict[str, dict[str, Any]] = {}
        self._tickets: dict[str, dict[str, Any]] = {}
        self._action_logs: list[dict[str, Any]] = []
        self._lock = threading.RLock()
        self._style_index = TrustedStyleIndex()
        self._deep_delay_seconds = deep_delay_seconds
        self._llm_client = llm_client or LLMClient()
        self._policy_provider = policy_provider

    def quick_analyze(
        self,
        payload: dict[str, Any],
        start_background: bool = True,
        actor: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        analysis_id = str(uuid.uuid4())
        policy = self._policy_provider() if self._policy_provider else {}
        quick = analyze_quick(payload, policy=policy)
        record = {
            "analysis_id": analysis_id,
            "created_at": utc_now(),
            "payload": deepcopy(payload),
            "quick_result": quick,
            "deep_status": "pending" if quick["deep_scan_required"] else "skipped",
            "deep_result": None,
            "policy": deepcopy(policy),
            "actor": deepcopy(actor or {}),
        }
        with self._lock:
            self._records[analysis_id] = record

        if quick["deep_scan_required"] and start_background:
            thread = threading.Thread(target=self.deep_analyze, args=(analysis_id,), daemon=True)
            thread.start()

        return {
            "analysis_id": analysis_id,
            "risk_level": quick["risk_level"],
            "action": quick["action"],
            "reason": quick["reason"],
            "matched_rules": quick["matched_rules"],
            "deep_scan_required": quick["deep_scan_required"],
        }

    def deep_analyze(self, analysis_id: str) -> dict[str, Any]:
        if self._deep_delay_seconds:
            time.sleep(self._deep_delay_seconds)

        with self._lock:
            record = self._records.get(analysis_id)
            if not record:
                raise KeyError(f"Unknown analysis_id: {analysis_id}")
            record["deep_status"] = "running"
            payload = deepcopy(record["payload"])
            quick = deepcopy(record["quick_result"])
            policy = deepcopy(record.get("policy") or {})

        subject = str(payload.get("subject") or "")
        sender = str(payload.get("sender") or "")
        body = str(payload.get("body_text") or payload.get("body_summary") or "")
        links = quick.get("evidence", {}).get("links", [])
        generalized_subject = generalize_entities(subject)
        generalized = generalize_entities(body, sender=sender)
        rag_match = self._style_index.match(generalized_subject["text"], generalized["text"], sender, links)

        score = int(quick.get("risk_score") or 0)
        semantic_signals: list[str] = []

        score += int(rag_match.get("anomaly_score") or 0)
        if rag_match.get("anomalies"):
            semantic_signals.extend(rag_match["anomalies"])

        has_external_link = any(not link.get("trusted_href") for link in links if link.get("href_domain"))
        has_mismatch = any(link.get("display_href_mismatch") for link in links)
        text_for_semantics = f"{subject}\n{generalized['text']}".lower()

        if has_mismatch:
            score += 15
            semantic_signals.append("llm_semantic_link_camouflage")

        semantic_keywords = policy.get("high_risk_keywords") or HIGH_RISK_KEYWORDS
        if has_external_link and any(str(token).lower() in text_for_semantics for token in semantic_keywords):
            score += 20
            semantic_signals.append("llm_semantic_sensitive_action_external_link")

        if "[INTERNAL_EXECUTIVE_NAME_A]" in generalized["text"] and "[AMOUNT_RANGE_HIGH]" in generalized["text"]:
            score += 20
            semantic_signals.append("llm_semantic_executive_payment_request")

        llm_result = self._llm_client.analyze_email(
            {
                "subject": generalized_subject["text"],
                "sender": self._generalized_sender(generalized["labels"]),
                "generalized_body": generalized["text"],
                "links": self._model_safe_links(links),
                "quick_rules": quick.get("matched_rules", []),
                "rag_match": rag_match,
            }
        )
        score += int(llm_result.get("risk_delta") or 0)
        semantic_signals.extend(f"model:{signal}" for signal in llm_result.get("signals", []))

        thresholds = policy.get("risk_thresholds") or RISK_THRESHOLDS
        score, calibration_notes = calibrate_score(score, quick.get("matched_rules", []), thresholds=thresholds)
        risk_level, action = level_and_action(score, thresholds)
        reason = self._deep_reason(risk_level, semantic_signals, rag_match, llm_result)

        deep_result = {
            "analysis_id": analysis_id,
            "risk_score": score,
            "risk_level": risk_level,
            "action": action,
            "reason": reason,
            "evidence": {
                "entity_labels": generalized_subject["labels"] + generalized["labels"],
                "generalized_text_preview": generalized["text"][:600],
                "rag_match": rag_match,
                "semantic_signals": semantic_signals,
                "llm": llm_result,
                "links": links,
                "calibration_notes": calibration_notes,
            },
        }

        with self._lock:
            self._records[analysis_id]["deep_status"] = "completed"
            self._records[analysis_id]["deep_result"] = deep_result

        return deep_result

    def status(self, analysis_id: str, expected_user_id: str | None = None) -> dict[str, Any]:
        with self._lock:
            record = deepcopy(self._records.get(analysis_id))
        if not record:
            raise KeyError(f"Unknown analysis_id: {analysis_id}")
        actor = record.get("actor") or {}
        if expected_user_id and actor.get("id") != expected_user_id:
            raise PermissionError("无权查看其他用户提交的插件检测")
        return {
            "analysis_id": analysis_id,
            "quick_result": record["quick_result"],
            "deep_status": record["deep_status"],
            "deep_result": record["deep_result"],
            "submitted_by": actor,
        }

    def log_action(self, payload: dict[str, Any]) -> dict[str, Any]:
        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": utc_now(),
            "analysis_id": payload.get("analysis_id"),
            "user_id": payload.get("user_id") or "anonymous",
            "action_type": payload.get("action_type"),
            "details": payload.get("details") or {},
        }
        with self._lock:
            self._action_logs.append(event)
        return event

    def create_false_positive_ticket(self, payload: dict[str, Any]) -> dict[str, Any]:
        analysis_id = str(payload.get("analysis_id") or "")
        with self._lock:
            if analysis_id not in self._records:
                raise KeyError(f"Unknown analysis_id: {analysis_id}")
            ticket_id = str(uuid.uuid4())
            ticket = {
                "ticket_id": ticket_id,
                "analysis_id": analysis_id,
                "user_id": payload.get("user_id") or "anonymous",
                "comment": payload.get("comment") or "",
                "status": "open",
                "created_at": utc_now(),
                "review": None,
            }
            self._tickets[ticket_id] = ticket
        return ticket

    def review_ticket(self, payload: dict[str, Any]) -> dict[str, Any]:
        ticket_id = str(payload.get("ticket_id") or "")
        review_result = str(payload.get("review_result") or "").lower()
        reviewer = payload.get("reviewer") or "soc"
        with self._lock:
            ticket = self._tickets.get(ticket_id)
            if not ticket:
                raise KeyError(f"Unknown ticket_id: {ticket_id}")
            ticket["status"] = "approved" if review_result == "approved" else "rejected"
            ticket["review"] = {
                "reviewer": reviewer,
                "review_result": ticket["status"],
                "comment": payload.get("comment") or "",
                "reviewed_at": utc_now(),
            }
            record = deepcopy(self._records[ticket["analysis_id"]])

        added_fingerprint = None
        if ticket["status"] == "approved":
            added_fingerprint = self._fingerprint_from_record(record)
            self._style_index.add_fingerprint(added_fingerprint)

        result = deepcopy(ticket)
        if added_fingerprint:
            result["added_fingerprint"] = {
                "style_id": added_fingerprint.style_id,
                "notification_type": added_fingerprint.notification_type,
                "subject_terms": added_fingerprint.subject_terms,
                "allowed_sender_domains": added_fingerprint.allowed_sender_domains,
                "allowed_link_domains": added_fingerprint.allowed_link_domains,
            }
        return result

    def list_records(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {
                    "analysis_id": record["analysis_id"],
                    "created_at": record["created_at"],
                    "subject": record["payload"].get("subject"),
                    "sender": record["payload"].get("sender"),
                    "quick_result": record["quick_result"],
                    "deep_status": record["deep_status"],
                    "deep_result": record["deep_result"],
                }
                for record in self._records.values()
            ]

    def list_tickets(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(deepcopy(self._tickets).values())

    def llm_config(self) -> dict[str, Any]:
        return self._llm_client.public_config()

    def configure_llm(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._llm_client.configure(payload)

    def _fingerprint_from_record(self, record: dict[str, Any]) -> TrustedStyleFingerprint:
        payload = record["payload"]
        quick_links = record["quick_result"].get("evidence", {}).get("links", [])
        subject = str(payload.get("subject") or "")
        sender = str(payload.get("sender") or "")
        sender_domain = sender.rsplit("@", 1)[-1].lower() if "@" in sender else sender.lower()
        link_domains = sorted({link.get("href_domain") for link in quick_links if link.get("href_domain")})
        generalized = generalize_entities(str(payload.get("body_text") or ""), sender=sender)
        terms = [term for term in ["审批", "密码", "发票", "通知", "待办", "付款", "OA", "SSO"] if term in subject + generalized["text"]]
        if not terms:
            terms = ["通知"]

        return TrustedStyleFingerprint(
            style_id=f"soc-approved-{uuid.uuid4()}",
            notification_type="SOC approved business notification",
            subject_terms=terms[:4],
            body_terms=terms[:6],
            allowed_sender_domains=[sender_domain] if sender_domain else [],
            allowed_link_domains=link_domains,
            expected_actions=[],
        )

    @staticmethod
    def _generalized_sender(labels: list[dict[str, Any]]) -> str:
        for label in labels:
            if label.get("source_type") == "sender":
                return str(label.get("label") or "")
        return "[UNKNOWN_SENDER]"

    @staticmethod
    def _model_safe_links(links: list[dict[str, Any]]) -> list[dict[str, Any]]:
        safe_links: list[dict[str, Any]] = []
        for link in links:
            context = generalize_entities(
                f"{link.get('context_before', '')} {link.get('display_text', '')} {link.get('context_after', '')}"
            )
            safe_links.append(
                {
                    "display_domain": link.get("display_domain") or "",
                    "href_domain": link.get("href_domain") or "",
                    "display_href_mismatch": bool(link.get("display_href_mismatch")),
                    "trusted_href": bool(link.get("trusted_href")),
                    "generalized_context": context["text"][:300],
                }
            )
        return safe_links

    @staticmethod
    def _deep_reason(
        risk_level: str,
        semantic_signals: list[str],
        rag_match: dict[str, Any],
        llm_result: dict[str, Any],
    ) -> str:
        if llm_result.get("status") == "completed" and llm_result.get("reason"):
            return str(llm_result["reason"])
        if risk_level in {"critical", "high"}:
            if rag_match.get("anomalies"):
                return "邮件样式接近企业可信通知，但发件或链接来源不匹配。"
            if "llm_semantic_link_camouflage" in semantic_signals:
                return "深度检测确认存在链接伪装风险。"
            return "深度检测确认存在高风险业务意图。"
        if risk_level == "medium":
            return "深度检测发现可疑特征，建议谨慎处理。"
        return "深度检测未发现明显钓鱼特征。"
