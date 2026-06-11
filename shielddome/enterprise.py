"""Enterprise detection orchestration, RAG and durable ingestion."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
from pathlib import Path
from typing import Any

from .analyzer import calibrate_score, level_and_action
from .auth import AuthService
from .entities import generalize_entities, sanitize_model_value
from .mail_parser import parse_eml
from .links import normalize_domain
from .providers import SiliconFlowProvider
from .raw_store import RawStore
from .rules import analyze_quick
from .secret_store import EncryptedSecretStore
from .settings import SETTINGS
from .storage import Database


class EnterpriseService:
    def __init__(self, database: Database | None = None, provider: SiliconFlowProvider | None = None):
        self.db = database or Database()
        self.provider = provider or SiliconFlowProvider()
        self.db.initialize()
        self.auth = AuthService(self.db)
        self.auth.bootstrap_admin()
        self.secret_store = EncryptedSecretStore(self.db.state_directory, SETTINGS.data_encryption_key)
        self._provider_configuration_error = ""
        self._sync_provider_settings()
        self._sync_provider_secret()
        SETTINGS.raw_storage_dir.mkdir(parents=True, exist_ok=True)
        self.raw_store = RawStore(SETTINGS.raw_storage_dir, SETTINGS.data_encryption_key)

    def ingest_eml(self, filename: str, raw: bytes) -> dict[str, Any]:
        if not raw:
            raise ValueError("EML 文件为空")
        if len(raw) > SETTINGS.max_upload_bytes:
            raise ValueError(f"EML 文件超过 {SETTINGS.max_upload_bytes // 1024 // 1024} MB 限制")
        parsed = parse_eml(raw)
        quick_payload = {
            "subject": parsed["subject"],
            "sender": parsed["sender"],
            "body_text": parsed["body_text"],
            "body_summary": parsed["body_summary"],
            "links": parsed["links"],
        }
        policy = self.detection_policy()
        quick = analyze_quick(quick_payload, policy=policy)
        quick = self._add_auth_and_attachment_signals(quick, parsed, policy["risk_thresholds"])
        digest = hashlib.sha256(raw).hexdigest()
        raw_path = self.raw_store.put(digest, raw)
        analysis_id = self.db.create_analysis(filename, str(raw_path), parsed, quick)
        self.db.record_audit(
            "api",
            "analysis.created",
            analysis_id,
            {"filename": filename, "sha256": digest, "raw_storage_encrypted": self.raw_store.encrypted},
        )
        return {
            "analysis_id": analysis_id,
            "status": "queued",
            "quick_result": quick,
            "raw_storage_encrypted": self.raw_store.encrypted,
        }

    def process_analysis(self, analysis_id: str) -> tuple[dict[str, Any], bool]:
        self._sync_provider_secret()
        analysis = self.db.get_analysis(analysis_id)
        if not analysis:
            raise KeyError(f"Unknown analysis_id: {analysis_id}")
        parsed = analysis["parsed_message"]
        quick = analysis["quick_result"]
        thresholds = self.detection_policy()["risk_thresholds"]
        generalized_subject = generalize_entities(parsed.get("subject") or "")
        generalized_body = generalize_entities(parsed.get("body_text") or "", sender=parsed.get("sender") or "")
        query = f"{generalized_subject['text']}\n{generalized_body['text'][:6000]}"
        rag = self.search_knowledge(query, limit=5)

        score = int(quick.get("risk_score") or 0)
        rag_delta = 0
        for item in rag:
            if item["source_type"] == "phishing_case":
                rag_delta = max(rag_delta, round(item["score"] * 25))
            elif item["source_type"] == "trusted_email":
                rag_delta = min(rag_delta, -round(item["score"] * 10))
        score += rag_delta

        authentication = parsed.get("authentication") or {}
        known_authentication = {key: value for key, value in authentication.items() if value != "unknown"}
        structural_links = quick.get("evidence", {}).get("links", [])
        llm_context = {
            "subject": generalized_subject["text"][:500],
            "sender": self._generalized_sender(parsed.get("sender") or ""),
            "body": generalized_body["text"][:6000],
            "authentication": known_authentication,
            "authentication_results_available": bool(known_authentication),
            "links": [
                {
                    "display_domain": link.get("display_domain") or "",
                    "href_domain": link.get("href_domain") or "",
                    "display_href_mismatch": bool(link.get("display_href_mismatch")),
                    "internal_network": bool(link.get("internal_network")),
                }
                for link in structural_links[:30]
                if link.get("is_web_link", True)
            ],
            "attachments": [
                {
                    "content_type": item.get("content_type"),
                    "extension": item.get("extension"),
                    "size": item.get("size"),
                    "indicators": item.get("indicators"),
                }
                for item in parsed.get("attachments", [])
            ],
            "quick_rules": quick.get("matched_rules") or [],
            "rag_references": [
                {
                    "title": generalize_entities(item["title"])["text"][:300],
                    "source_type": item["source_type"],
                    "score": item["score"],
                }
                for item in rag
            ],
        }
        llm = self.provider.chat(sanitize_model_value(llm_context))
        score += int(llm.get("risk_delta") or 0)
        attachment_indicators = [
            indicator
            for attachment in parsed.get("attachments", [])
            for indicator in attachment.get("indicators", [])
        ]
        score, calibration_notes = calibrate_score(score, quick.get("matched_rules", []), attachment_indicators, thresholds)
        risk_level, _ = level_and_action(score, thresholds)
        degraded = llm.get("status") in {"failed", "not_configured"}
        if "high_risk_requires_strong_deterministic_evidence" in calibration_notes:
            reason = "模型或语义分析发现可疑特征，但缺少强规则证据，已限制为中风险并建议复核。"
        else:
            reason = llm.get("reason") or quick.get("reason")
        result = {
            "analysis_id": analysis_id,
            "risk_score": score,
            "risk_level": risk_level,
            "recommended_action": "notify" if risk_level in {"medium", "high", "critical"} else "allow",
            "enforcement": "observe_only",
            "reason": reason,
            "quick_result": quick,
            "authentication": parsed.get("authentication") or {},
            "attachments": parsed.get("attachments") or [],
            "rag": {"risk_delta": rag_delta, "references": rag},
            "llm": llm,
            "calibration": {"notes": calibration_notes},
            "privacy": {
                "model_context_sanitized": True,
                "raw_body_sent_to_llm": False,
                "raw_attachments_sent_to_llm": False,
                "raw_link_display_text_sent_to_llm": False,
                "raw_rag_titles_sent_to_llm": False,
            },
        }
        self.db.record_audit("worker", "analysis.completed", analysis_id, {"risk_level": risk_level, "degraded": degraded})
        return result, degraded

    def import_knowledge(self, title: str, source_type: str, content: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        self._sync_provider_secret()
        if source_type not in {"trusted_email", "phishing_case", "security_rule", "soc_review"}:
            raise ValueError("Unsupported knowledge source_type")
        generalized = generalize_entities(content)["text"]
        item_id = self.db.add_knowledge(title, source_type, content, generalized, metadata or {})
        embedded = self.provider.embed([generalized[:8000]])
        if embedded.get("vectors"):
            self.db.update_knowledge(item_id, embedding=embedded["vectors"][0])
        self.db.record_audit("admin", "knowledge.imported", item_id, {"title": title, "source_type": source_type})
        return {"id": item_id, "status": "pending", "embedding_status": embedded.get("status")}

    def approve_knowledge(self, item_id: str) -> dict[str, Any]:
        self.db.update_knowledge(item_id, status="published")
        self.db.record_audit("admin", "knowledge.published", item_id)
        return {"id": item_id, "status": "published"}

    def disable_knowledge(self, item_id: str) -> dict[str, Any]:
        self.db.update_knowledge(item_id, status="disabled")
        self.db.record_audit("admin", "knowledge.disabled", item_id)
        return {"id": item_id, "status": "disabled"}

    def reindex_knowledge(self) -> dict[str, Any]:
        self._sync_provider_secret()
        completed = 0
        failed = 0
        for item in self.db.list_knowledge():
            result = self.provider.embed([str(item.get("generalized_content") or "")[:8000]])
            if result.get("vectors"):
                self.db.update_knowledge(item["id"], embedding=result["vectors"][0])
                completed += 1
            else:
                failed += 1
        self.db.record_audit("admin", "knowledge.reindexed", "knowledge", {"completed": completed, "failed": failed})
        return {"completed": completed, "failed": failed}

    def configure_provider(self, values: dict[str, Any]) -> dict[str, Any]:
        allowed = {key: values[key] for key in ("chat_endpoint", "chat_model", "embedding_endpoint", "embedding_model", "timeout") if key in values}
        persisted = self.db.get_policy("provider_settings", {})
        persisted = dict(persisted) if isinstance(persisted, dict) else {}
        persisted.update(allowed)
        if allowed and hasattr(self.provider, "configure_public"):
            self.provider.configure_public(allowed)
        self.db.set_policy("provider_settings", persisted)
        api_key = str(values.get("api_key") or "").strip()
        clear_api_key = bool(values.get("clear_api_key"))
        if api_key:
            self.db.set_policy("provider_secret", {"ciphertext": self.secret_store.encrypt(api_key)})
            if hasattr(self.provider, "set_api_key"):
                self.provider.set_api_key(api_key, "encrypted_database")
        elif clear_api_key:
            self.db.set_policy("provider_secret", {})
            if hasattr(self.provider, "reset_api_key"):
                self.provider.reset_api_key()
            elif hasattr(self.provider, "set_api_key"):
                self.provider.set_api_key("", "not_configured")
        self.db.record_audit("admin", "provider.updated", "provider", {"fields": sorted(allowed)})
        return self.provider_config()

    def provider_config(self) -> dict[str, Any]:
        self._sync_provider_secret()
        config = self.provider.public_config()
        config["secret_encryption"] = self.secret_store.key_source
        config["configuration_error"] = self._provider_configuration_error
        return config

    def detection_policy(self) -> dict[str, Any]:
        return {
            "trusted_domains": self.db.get_policy("trusted_domains", []) or [],
            "trusted_ip_ranges": self.db.get_policy("trusted_ip_ranges", []) or [],
            "blacklisted_domains": self.db.get_policy("blacklisted_domains", []) or [],
            "high_risk_keywords": self.db.get_policy("high_risk_keywords", []) or [],
            "risk_thresholds": self.db.get_policy("risk_thresholds", {}) or {},
        }

    def configure_detection_policy(self, values: dict[str, Any], actor: str = "admin") -> dict[str, Any]:
        policy = {
            "trusted_domains": self._validated_domains(values.get("trusted_domains"), "可信域名"),
            "trusted_ip_ranges": self._validated_ip_ranges(values.get("trusted_ip_ranges")),
            "blacklisted_domains": self._validated_domains(values.get("blacklisted_domains"), "黑名单域名"),
            "high_risk_keywords": self._validated_keywords(values.get("high_risk_keywords")),
            "risk_thresholds": self._validated_thresholds(values.get("risk_thresholds")),
        }
        for key, value in policy.items():
            self.db.set_policy(key, value)
        self.db.record_audit(
            actor,
            "detection_policy.updated",
            "detection_policy",
            {key: len(value) if isinstance(value, list) else value for key, value in policy.items()},
        )
        return policy

    def test_provider(self) -> dict[str, Any]:
        self._sync_provider_secret()
        if not hasattr(self.provider, "test_connections"):
            return {"ok": True, "chat": {"status": "test_not_supported"}, "embedding": {"status": "test_not_supported"}}
        result = self.provider.test_connections()
        self.db.record_audit(
            "admin",
            "provider.connection_tested",
            "provider",
            {"ok": bool(result.get("ok")), "chat": result.get("chat", {}).get("status"), "embedding": result.get("embedding", {}).get("status")},
        )
        return result

    def _sync_provider_secret(self) -> None:
        self._sync_provider_settings()
        if not hasattr(self.provider, "set_api_key"):
            return
        secret = self.db.get_policy("provider_secret", {})
        ciphertext = secret.get("ciphertext") if isinstance(secret, dict) else ""
        if ciphertext:
            try:
                self.provider.set_api_key(self.secret_store.decrypt(str(ciphertext)), "encrypted_database")
            except Exception:
                self.provider.set_api_key("", "encrypted_database_error")
        elif str(getattr(self.provider, "secret_source", "")).startswith("encrypted_database") and hasattr(self.provider, "reset_api_key"):
            self.provider.reset_api_key()

    def _sync_provider_settings(self) -> None:
        settings = self.db.get_policy("provider_settings", {})
        if settings and hasattr(self.provider, "configure_public"):
            try:
                self.provider.configure_public(settings)
                self._provider_configuration_error = ""
            except ValueError as exc:
                self._provider_configuration_error = str(exc)

    def search_knowledge(self, query: str, limit: int = 5) -> list[dict[str, Any]]:
        self._sync_provider_secret()
        query_generalized = generalize_entities(query)["text"]
        query_tokens = self._tokens(query_generalized)
        embedded = self.provider.embed([query_generalized[:8000]])
        query_vector = embedded.get("vectors", [None])[0] if embedded.get("vectors") else None
        items = self.db.vector_knowledge(query_vector, limit=50) if query_vector else self.db.published_knowledge()
        ranked: list[dict[str, Any]] = []
        for item in items:
            tokens = self._tokens(item.get("generalized_content") or "")
            keyword_score = len(query_tokens & tokens) / max(1, len(query_tokens | tokens))
            vector_score = float(item.get("vector_score") or 0.0)
            if query_vector and not vector_score:
                vector_score = self.provider.cosine(query_vector, item.get("embedding") or [])
            score = round(keyword_score * 0.45 + max(0.0, vector_score) * 0.55, 4)
            if score > 0:
                ranked.append(
                    {
                        "id": item["id"],
                        "title": item["title"],
                        "source_type": item["source_type"],
                        "score": score,
                        "excerpt": str(item.get("generalized_content") or "")[:300],
                    }
                )
        return sorted(ranked, key=lambda item: item["score"], reverse=True)[: max(1, min(limit, 20))]

    def feedback(self, analysis_id: str, verdict: str, comment: str) -> dict[str, Any]:
        if not self.db.get_analysis(analysis_id):
            raise KeyError(f"Unknown analysis_id: {analysis_id}")
        self.db.record_audit("soc", "analysis.feedback", analysis_id, {"verdict": verdict, "comment": comment[:1000]})
        return {"analysis_id": analysis_id, "status": "recorded", "knowledge_promotion": "requires_manual_review"}

    @staticmethod
    def _add_auth_and_attachment_signals(
        quick: dict[str, Any],
        parsed: dict[str, Any],
        thresholds: dict[str, int] | None = None,
    ) -> dict[str, Any]:
        authentication = parsed.get("authentication") or {}
        score = int(quick.get("risk_score") or 0)
        matched = list(quick.get("matched_rules") or [])
        score_breakdown = dict(quick.get("evidence", {}).get("score_breakdown") or {})
        authentication_score = 0
        for name in ("spf", "dkim", "dmarc"):
            if authentication.get(name) == "fail":
                matched.append(f"{name}_fail")
                authentication_score += 20 if name == "dmarc" else 8
        if authentication_score:
            authentication_score = min(25, authentication_score)
            score += authentication_score
            score_breakdown["authentication_failures"] = authentication_score
        attachment_indicators = [
            indicator
            for attachment in parsed.get("attachments", [])
            for indicator in attachment.get("indicators", [])
        ]
        if attachment_indicators:
            attachment_score = min(40, 15 + len(attachment_indicators) * 5)
            score += attachment_score
            score_breakdown["suspicious_attachment"] = attachment_score
            matched.append("suspicious_attachment")
        score = min(score, 100)
        risk_level, _ = level_and_action(score, thresholds)
        result = dict(quick)
        result.update({"risk_score": score, "risk_level": risk_level, "action": "warn" if risk_level != "low" else "allow", "matched_rules": matched})
        result.setdefault("evidence", {})["authentication"] = authentication
        result["evidence"]["attachment_indicators"] = attachment_indicators
        result["evidence"]["score_breakdown"] = score_breakdown
        return result

    @staticmethod
    def _tokens(text: str) -> set[str]:
        return {token.lower() for token in re.findall(r"[\w\u4e00-\u9fff]{2,}", text)}

    @staticmethod
    def _generalized_sender(sender: str) -> str:
        return str(generalize_entities("", sender=sender)["labels"][-1]["label"]) if sender else "[UNKNOWN_SENDER]"

    @staticmethod
    def _domain_only(value: str) -> str:
        match = re.search(r"(?i)(?:https?://)?([^/:?#\s]+)", value)
        return match.group(1).lower() if match else ""

    @staticmethod
    def _validated_domains(values: Any, label: str) -> list[str]:
        if not isinstance(values, list):
            raise ValueError(f"{label}必须是列表")
        result: set[str] = set()
        for value in values:
            raw = str(value).strip()
            normalized = normalize_domain(raw)
            if not normalized or "/" in raw or " " in raw or "." not in normalized:
                raise ValueError(f"{label}包含无效域名：{raw or '(空值)'}")
            result.add(normalized)
        if len(result) > 5000:
            raise ValueError(f"{label}最多允许 5000 项")
        return sorted(result)

    @staticmethod
    def _validated_ip_ranges(values: Any) -> list[str]:
        if not isinstance(values, list):
            raise ValueError("可信 IP / CIDR 必须是列表")
        result: set[str] = set()
        for value in values:
            raw = str(value).strip()
            try:
                network = ipaddress.ip_network(raw, strict=False)
            except ValueError as exc:
                raise ValueError(f"可信 IP / CIDR 包含无效值：{raw or '(空值)'}") from exc
            result.add(str(network))
        if len(result) > 5000:
            raise ValueError("可信 IP / CIDR 最多允许 5000 项")
        return sorted(result)

    @staticmethod
    def _validated_keywords(values: Any) -> list[str]:
        if not isinstance(values, list):
            raise ValueError("高风险关键词必须是列表")
        result = sorted({str(value).strip() for value in values if str(value).strip()})
        if any(len(value) > 100 for value in result):
            raise ValueError("单个高风险关键词不能超过 100 个字符")
        if len(result) > 5000:
            raise ValueError("高风险关键词最多允许 5000 项")
        return result

    @staticmethod
    def _validated_thresholds(values: Any) -> dict[str, int]:
        if not isinstance(values, dict):
            raise ValueError("风险阈值必须是对象")
        try:
            thresholds = {key: int(values[key]) for key in ("medium", "high", "critical")}
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("风险阈值必须包含 medium、high、critical 整数") from exc
        if not 0 < thresholds["medium"] < thresholds["high"] < thresholds["critical"] <= 100:
            raise ValueError("风险阈值必须满足 0 < 中风险 < 高风险 < 严重风险 <= 100")
        return thresholds
