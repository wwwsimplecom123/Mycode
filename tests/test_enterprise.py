import tempfile
import unittest
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.api import check_rate_limit
from shielddome.enterprise import EnterpriseService
from shielddome.analyzer import AnalyzerService
from shielddome.mail_parser import parse_eml
from shielddome.storage import Database
from shielddome.providers import SiliconFlowProvider


SAMPLE_EML = b"""From: Superior Notice <notice@superior.example>
To: employee@company.com
Subject: Urgent password verification
Message-ID: <test-1@superior.example>
Authentication-Results: mx.company.com; spf=pass; dkim=pass; dmarc=pass
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html><body>Please reset password now:
<a href="https://evil-login.com/reset">https://sso.company.com/reset</a>
</body></html>
"""

BENIGN_PRIVATE_LINK_EML = b"""From: SOC Notice <soc@partner.example>
To: employee@company.com
Subject: Security device access notice
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html><body>Device username and password:
<a href="https://10.24.200.9/">https://10.24.200.9</a>
https://10.24.200.9user@password@tail
</body></html>
"""

MODEL_ONLY_EML = b"""From: Notice <notice@partner.example>
To: employee@company.com
Subject: Password verification notice
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html><body>Please verify password at
<a href="https://partner.example/account">account page</a>.
</body></html>
"""

PRIVACY_EML = b"""From: Contact Alice <alice.private@partner.example>
To: employee@company.com
Subject: Contact Alice payment notice 13800138000
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html><body>Contact Alice phone 010-59510316 mobile 13800138000
ID 11010519491231002X card 6222020202020202020 token raw-secret-token
password SecretPass-2026 amount CNY 280000.
<a href="https://partner.example/reset?token=raw-secret-token">Contact Alice private link</a>
</body></html>
"""


class FakeProvider:
    def public_config(self):
        return {"configured": True}

    def embed(self, texts):
        return {"status": "completed", "vectors": [[0.1, 0.2, 0.3] for _ in texts]}

    def chat(self, context):
        return {
            "status": "completed",
            "risk_delta": 20,
            "reason": "Detected sensitive action to external domain.",
            "signals": ["external_sensitive_action"],
        }

    @staticmethod
    def cosine(left, right):
        return 1.0 if left and right else 0.0


class AggressiveProvider(FakeProvider):
    def chat(self, context):
        return {
            "status": "completed",
            "risk_delta": 30,
            "reason": "Model-only high risk judgment.",
            "signals": ["model_only_high_risk"],
        }


class RecordingProvider(FakeProvider):
    def __init__(self):
        self.chat_contexts = []
        self.embedding_inputs = []

    def embed(self, texts):
        self.embedding_inputs.extend(texts)
        return super().embed(texts)

    def chat(self, context):
        self.chat_contexts.append(context)
        return super().chat(context)


class TimeoutProvider(SiliconFlowProvider):
    def _post(self, endpoint, payload):
        raise TimeoutError("The read operation timed out")


class EnterpriseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Database(f"sqlite:///{Path(self.temp.name) / 'test.db'}")
        self.service = EnterpriseService(database=self.db, provider=FakeProvider())

    def tearDown(self):
        hashes = {
            __import__("hashlib").sha256(raw).hexdigest()
            for raw in (SAMPLE_EML, BENIGN_PRIVATE_LINK_EML, MODEL_ONLY_EML, PRIVACY_EML)
        }
        for path in Path("data/raw").glob("*.eml*"):
            if any(path.name.startswith(digest) for digest in hashes):
                path.unlink()
        self.temp.cleanup()

    def test_eml_parser_extracts_authentication_and_link(self):
        parsed = parse_eml(SAMPLE_EML)
        self.assertEqual(parsed["authentication"]["dmarc"], "pass")
        self.assertEqual(parsed["links"][0]["href"], "https://evil-login.com/reset")

    def test_parser_discards_glued_invalid_url_and_private_link_stays_low_risk(self):
        parsed = parse_eml(BENIGN_PRIVATE_LINK_EML)
        self.assertEqual([link["href"] for link in parsed["links"]], ["https://10.24.200.9/"])

        queued = self.service.ingest_eml("benign-private-link.eml", BENIGN_PRIVATE_LINK_EML)
        quick = queued["quick_result"]
        self.assertEqual(quick["risk_level"], "low")
        self.assertNotIn("external_link", quick["matched_rules"])
        self.assertEqual(quick["evidence"]["authentication"]["dmarc"], "unknown")

    def test_detection_policy_controls_ip_keywords_domains_and_thresholds(self):
        policy = self.service.configure_detection_policy(
            {
                "trusted_domains": ["partner.example"],
                "trusted_ip_ranges": [],
                "blacklisted_domains": ["blocked.example"],
                "high_risk_keywords": ["device password"],
                "risk_thresholds": {"medium": 40, "high": 70, "critical": 90},
            },
            "policy-admin",
        )
        queued = self.service.ingest_eml("policy-private-link.eml", BENIGN_PRIVATE_LINK_EML)

        self.assertEqual(policy["trusted_domains"], ["partner.example"])
        self.assertEqual(queued["quick_result"]["risk_level"], "low")
        self.assertIn("external_link", queued["quick_result"]["matched_rules"])
        self.assertEqual(queued["quick_result"]["evidence"]["policy_summary"]["risk_thresholds"]["medium"], 40)
        self.assertEqual(self.db.get_policy("trusted_ip_ranges"), [])

    def test_trusted_domain_policy_can_disable_subdomain_inheritance(self):
        policy = self.service.detection_policy()
        policy.update(
            {
                "trusted_domains": ["partner.example"],
                "trusted_include_subdomains": False,
                "trusted_ip_ranges": [],
                "blacklisted_domains": [],
                "high_risk_keywords": ["password"],
                "risk_thresholds": {"medium": 35, "high": 65, "critical": 85},
            }
        )
        self.service.configure_detection_policy(policy)
        queued = self.service.ingest_browser_probe(
            {
                "subject": "Password notice",
                "sender": "notice@sub.partner.example",
                "body_text": "Please check password at https://sub.partner.example/reset",
                "links": [{"href": "https://sub.partner.example/reset", "display_text": "reset"}],
            },
            {"id": "actor-1", "username": "actor", "display_name": "Actor", "role": "analyst"},
        )

        links = queued["quick_result"]["evidence"]["links"]
        self.assertFalse(links[0]["trusted_href"])
        self.assertIn("external_link", queued["quick_result"]["matched_rules"])

    def test_detection_policy_validates_ip_ranges_and_threshold_order(self):
        policy = self.service.detection_policy()
        policy["trusted_ip_ranges"] = ["10.24.0.0/not-a-prefix"]
        with self.assertRaisesRegex(ValueError, "无效值"):
            self.service.configure_detection_policy(policy)

        policy = self.service.detection_policy()
        policy["risk_thresholds"] = {"medium": 70, "high": 60, "critical": 90}
        with self.assertRaisesRegex(ValueError, "必须满足"):
            self.service.configure_detection_policy(policy)

    def test_durable_analysis_completes_and_does_not_trust_passed_dmarc(self):
        queued = self.service.ingest_eml("internal-phish.eml", SAMPLE_EML)
        task = self.db.claim_task("test-worker")
        result, degraded = self.service.process_analysis(queued["analysis_id"])
        self.db.complete_task(task["id"], task["analysis_id"], result, degraded)
        stored = self.db.get_analysis(queued["analysis_id"])

        self.assertIn(stored["status"], {"completed", "degraded"})
        self.assertIn(stored["risk_level"], {"high", "critical"})
        self.assertEqual(stored["result"]["authentication"]["dmarc"], "pass")

    def test_stale_running_task_is_recovered(self):
        queued = self.service.ingest_eml("internal-phish.eml", SAMPLE_EML)
        task = self.db.claim_task("stale-worker")
        old = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        self.db._execute_direct("UPDATE tasks SET updated_at = ? WHERE id = ?", [old, task["id"]])

        recovered = self.service.recover_stale_tasks(1800)
        stored = self.db.get_analysis(queued["analysis_id"])

        self.assertEqual(recovered, 1)
        self.assertEqual(stored["status"], "queued")

    def test_failed_analysis_can_be_retried(self):
        queued = self.service.ingest_eml("internal-phish.eml", SAMPLE_EML)
        task = self.db.claim_task("failed-worker")
        self.db.fail_task({"id": task["id"], "analysis_id": task["analysis_id"], "attempts": 2}, "boom", 3)

        result = self.service.retry_analysis(queued["analysis_id"], "admin")
        stats = self.db.queue_stats()

        self.assertEqual(result["status"], "queued")
        self.assertGreaterEqual(stats["queued"], 1)

    def test_completed_task_serializes_uuid_values_in_result(self):
        queued = self.service.ingest_eml("internal-phish.eml", SAMPLE_EML)
        task = self.db.claim_task("uuid-worker")
        reference_id = uuid.uuid4()

        self.db.complete_task(
            task["id"],
            task["analysis_id"],
            {
                "analysis_id": task["analysis_id"],
                "risk_level": "low",
                "rag": {"references": [{"id": reference_id, "title": "UUID reference"}]},
            },
            False,
        )
        stored = self.db.get_analysis(queued["analysis_id"])

        self.assertEqual(stored["status"], "completed")
        self.assertEqual(stored["result"]["rag"]["references"][0]["id"], str(reference_id))

    def test_worker_heartbeat_is_recorded_in_system_status(self):
        self.db.record_worker_heartbeat("worker-a")
        self.db.record_worker_heartbeat("worker-a")
        status = self.service.system_status()

        self.assertEqual(status["workers"][0]["worker_id"], "worker-a")
        self.assertIn("queue", status)

    def test_external_model_and_embedding_inputs_are_sanitized(self):
        provider = RecordingProvider()
        service = EnterpriseService(database=self.db, provider=provider)
        knowledge = service.import_knowledge(
            "Contact Alice confirmed case",
            "phishing_case",
            "Contact Alice phone 010-59510316 token knowledge-secret payment notice",
        )
        service.approve_knowledge(knowledge["id"])
        queued = service.ingest_eml("privacy.eml", PRIVACY_EML)
        result, _ = service.process_analysis(queued["analysis_id"])
        external_payloads = str(provider.embedding_inputs) + str(provider.chat_contexts)

        for secret in (
            "Alice",
            "alice.private",
            "010-59510316",
            "13800138000",
            "11010519491231002X",
            "6222020202020202020",
            "raw-secret-token",
            "knowledge-secret",
            "SecretPass-2026",
            "280000",
            "/reset?token=",
        ):
            self.assertNotIn(secret, external_payloads)
        self.assertIn("partner.example", external_payloads)
        self.assertNotIn("display_text", str(provider.chat_contexts))
        self.assertTrue(result["privacy"]["model_context_sanitized"])
        self.assertFalse(result["privacy"]["raw_link_display_text_sent_to_llm"])

    def test_knowledge_requires_approval_and_is_searchable(self):
        item = self.service.import_knowledge("OA phishing", "phishing_case", "password reset evil login")
        self.assertEqual(self.service.search_knowledge("password reset"), [])
        self.service.approve_knowledge(item["id"])
        self.assertEqual(self.service.search_knowledge("password reset")[0]["title"], "OA phishing")

    def test_feedback_creates_pending_review_knowledge_without_raw_body_in_audit(self):
        queued = self.service.ingest_eml("internal-phish.eml", SAMPLE_EML)
        result = self.service.feedback(queued["analysis_id"], "confirmed_phishing", "Confirmed by analyst")

        self.assertEqual(result["knowledge_promotion"], "pending_review")
        item = next(item for item in self.db.list_knowledge() if item["id"] == result["knowledge_id"])
        self.assertEqual(item["status"], "pending")
        self.assertEqual(item["source_type"], "phishing_case")
        self.assertNotIn("evil-login.com/reset", str(self.db.list_audit()))

    def test_local_admin_login_creates_revocable_session(self):
        login = self.service.auth.login("admin", "ChangeMe-Before-Production")
        self.assertEqual(login["user"]["role"], "admin")
        self.assertEqual(self.service.auth.authenticate(login["token"])["username"], "admin")
        self.service.auth.logout(login["token"])
        self.assertIsNone(self.service.auth.authenticate(login["token"]))

    def test_user_management_revokes_sessions_and_protects_last_admin(self):
        managed = self.service.auth.create_user("analyst.one", "Analyst-Password-2026", "分析员一号", "analyst")
        login = self.service.auth.login("analyst.one", "Analyst-Password-2026")
        self.assertEqual(login["user"]["role"], "analyst")
        self.assertNotIn("password_hash", managed)

        self.service.auth.update_user(managed["id"], "分析员一号", "analyst", True)
        self.assertIsNone(self.service.auth.authenticate(login["token"]))
        with self.assertRaisesRegex(ValueError, "最后一个"):
            admin = self.db.get_user_by_username("admin")
            self.service.auth.update_user(admin["id"], "系统管理员", "auditor", False)

    def test_user_password_reset_invalidates_old_password(self):
        managed = self.service.auth.create_user("auditor.one", "Auditor-Password-2026", "审计员一号", "auditor")
        self.service.auth.reset_password(managed["id"], "Auditor-New-Password-2026")
        with self.assertRaises(PermissionError):
            self.service.auth.login("auditor.one", "Auditor-Password-2026")
        self.assertEqual(self.service.auth.login("auditor.one", "Auditor-New-Password-2026")["user"]["role"], "auditor")

    def test_browser_probe_compatibility_analysis_completes(self):
        probe = AnalyzerService(deep_delay_seconds=0)
        quick = probe.quick_analyze({"subject": "normal meeting", "body_text": "agenda attached", "links": []})
        status = probe.status(quick["analysis_id"])
        self.assertIn(status["deep_status"], {"skipped", "pending", "running", "completed"})

    def test_browser_probe_ingest_is_durable_and_updates_dashboard(self):
        managed = self.service.auth.create_user("probe.durable", "Probe-Password-2026", "Probe Durable", "analyst")
        before = self.db.dashboard()["total"]
        queued = self.service.ingest_browser_probe(
            {
                "message_id": "browser-message-1",
                "subject": "Reset password notice",
                "sender": "security@example.com",
                "body_text": "Please reset password at https://example.com/reset",
                "links": [{"href": "https://example.com/reset", "display_text": "reset"}],
                "mail_client": "browser-extension:webmail.example",
                "page_url": "https://webmail.example/read?id=secret",
            },
            managed,
        )
        stored = self.db.get_analysis(queued["analysis_id"])

        self.assertEqual(self.db.dashboard()["total"], before + 1)
        self.assertEqual(stored["parsed_message"]["submitted_by"]["username"], "probe.durable")
        self.assertEqual(stored["status"], "queued")
        self.assertTrue(queued["deep_scan_required"])

    def test_browser_probe_ingest_normalizes_unexpected_payload_shapes(self):
        managed = self.service.auth.create_user("probe.shapes", "Probe-Password-2026", "Probe Shapes", "analyst")
        queued = self.service.ingest_browser_probe(
            {
                "message_id": {"nested": "id"},
                "subject": ["Security", "Notice"],
                "sender": None,
                "body_text": {"text": "Please review the security notice"},
                "links": "not-a-list",
                "mail_client": "browser-extension:test",
            },
            managed,
        )
        stored = self.db.get_analysis(queued["analysis_id"])

        self.assertEqual(stored["parsed_message"]["links"], [])
        self.assertIn("Security", stored["parsed_message"]["subject"])
        self.assertEqual(stored["parsed_message"]["submitted_by"]["username"], "probe.shapes")

    def test_user_plugin_token_is_hashed_rotatable_and_revocable(self):
        managed = self.service.auth.create_user("probe.user", "Probe-Password-2026", "Probe User", "analyst")
        issued = self.service.auth.issue_plugin_token(managed["id"])

        self.assertTrue(issued["token"].startswith("sdp_"))
        self.assertEqual(self.service.auth.authenticate_plugin_token(issued["token"])["username"], "probe.user")
        self.assertNotIn(issued["token"], str(self.db.list_users()))
        stored = self.db._fetchone("SELECT token_hash FROM plugin_tokens WHERE user_id = ? AND revoked = 0", [managed["id"]])
        self.assertNotEqual(stored["token_hash"], issued["token"])
        listed = next(item for item in self.db.list_users() if item["id"] == managed["id"])
        self.assertTrue(listed["plugin_token_configured"])
        self.assertEqual(listed["plugin_token_prefix"], issued["token"][:12])

        rotated = self.service.auth.issue_plugin_token(managed["id"])
        self.assertIsNone(self.service.auth.authenticate_plugin_token(issued["token"]))
        self.assertEqual(self.service.auth.authenticate_plugin_token(rotated["token"])["id"], managed["id"])

        self.service.auth.update_user(managed["id"], "Probe User", "analyst", True)
        self.assertIsNone(self.service.auth.authenticate_plugin_token(rotated["token"]))

    def test_browser_probe_status_is_isolated_by_user(self):
        probe = AnalyzerService(deep_delay_seconds=0)
        actor = {"id": "user-a", "username": "user.a", "display_name": "User A", "role": "analyst"}
        quick = probe.quick_analyze(
            {"subject": "normal meeting", "body_text": "agenda attached", "links": []},
            start_background=False,
            actor=actor,
        )

        self.assertEqual(probe.status(quick["analysis_id"], expected_user_id="user-a")["submitted_by"]["username"], "user.a")
        with self.assertRaises(PermissionError):
            probe.status(quick["analysis_id"], expected_user_id="user-b")

    def test_dashboard_trend_always_contains_fourteen_days(self):
        trend = self.db.dashboard()["trend"]
        self.assertEqual(len(trend), 14)
        self.assertEqual(trend[-1]["count"], 0)

    def test_provider_key_is_encrypted_and_restored_without_plaintext_exposure(self):
        provider = SiliconFlowProvider()
        service = EnterpriseService(database=self.db, provider=provider)
        key = "sk-secret-provider-key-2026"
        config = service.configure_provider({"api_key": key, "embedding_model": "BAAI/bge-m3"})

        stored = self.db.get_policy("provider_secret", {})
        self.assertNotIn(key, str(stored))
        self.assertTrue(str(stored.get("ciphertext")).startswith("SDSEC1:"))
        self.assertNotIn(key, str(config))
        self.assertEqual(config["api_key_masked"], "sk-s...2026")

        restored = EnterpriseService(database=self.db, provider=SiliconFlowProvider())
        self.assertEqual(restored.provider.api_key, key)
        restored.configure_provider({"clear_api_key": True})
        self.assertEqual(self.db.get_policy("provider_secret"), {})

    def test_provider_rejects_reranker_as_chat_without_partial_update(self):
        provider = SiliconFlowProvider()
        original_endpoint = provider.chat_endpoint
        with self.assertRaisesRegex(ValueError, "Chat API"):
            provider.configure_public(
                {
                    "chat_endpoint": "https://api.siliconflow.cn/v1/rerank",
                    "embedding_model": "Pro/BAAI/bge-m3",
                }
            )
        self.assertEqual(provider.chat_endpoint, original_endpoint)

    def test_provider_rejects_captioner_as_chat_model(self):
        provider = SiliconFlowProvider()
        with self.assertRaisesRegex(ValueError, "Captioner"):
            provider.configure_public({"chat_model": "Qwen/Qwen3-Omni-30B-A3B-Captioner"})

    def test_provider_applies_final_sanitization_before_external_requests(self):
        provider = SiliconFlowProvider()
        provider.set_api_key("sk-test-provider-key")
        requests = []

        def fake_post(endpoint, payload):
            requests.append(payload)
            if "embeddings" in endpoint:
                return {"data": [{"index": 0, "embedding": [0.1, 0.2, 0.3]}]}
            return {"choices": [{"message": {"content": '{"risk_delta":0,"reason":"ok","signals":[]}'}}]}

        provider._post = fake_post
        raw = "Contact Alice phone 010-59510316 token raw-secret-token https://example.com/path?secret=value"
        provider.embed([raw])
        provider.chat({"body": raw})
        external_payloads = str(requests)

        for secret in ("Alice", "010-59510316", "raw-secret-token", "/path?secret=value"):
            self.assertNotIn(secret, external_payloads)
        self.assertIn("example.com", external_payloads)

    def test_provider_timeout_returns_actionable_reason(self):
        provider = TimeoutProvider()
        provider.set_api_key("sk-test-provider-key")
        result = provider.test_connections()

        self.assertFalse(result["ok"])
        self.assertIn("提高超时设置", result["chat"]["reason"])
        self.assertIn("提高超时设置", result["embedding"]["error"])

    def test_provider_retries_without_json_mode_for_unsupported_model(self):
        provider = SiliconFlowProvider()
        provider.set_api_key("sk-test-provider-key")
        requests = []

        def fake_post(endpoint, payload):
            requests.append(payload)
            if len(requests) == 1:
                raise RuntimeError('HTTP 400 Bad Request: {"message":"Json mode is not supported for this model."}')
            return {
                "model": "zai-org/GLM-4.5V",
                "choices": [
                    {
                        "message": {
                            "content": '```json\n{"risk_delta":0,"reason":"ok","signals":[]}\n```'
                        }
                    }
                ],
            }

        provider._post = fake_post
        result = provider.chat({"body": "synthetic"})

        self.assertEqual(result["status"], "completed")
        self.assertIn("response_format_removed", result["compatibility_fallbacks"])
        self.assertIn("response_format", requests[0])
        self.assertNotIn("response_format", requests[1])

        second = provider.chat({"body": "synthetic again"})
        self.assertEqual(second["status"], "completed")
        self.assertIn("response_format_skipped", second["compatibility_fallbacks"])
        self.assertNotIn("response_format", requests[2])

    def test_invalid_persisted_provider_settings_do_not_block_startup(self):
        self.db.set_policy(
            "provider_settings",
            {
                "chat_endpoint": "https://api.siliconflow.cn/v1/rerank",
                "chat_model": "Qwen/Qwen3-VL-Reranker-8B",
            },
        )
        service = EnterpriseService(database=self.db, provider=SiliconFlowProvider())
        self.assertIn("Chat API", service.provider_config()["configuration_error"])

    def test_model_cannot_raise_analysis_above_medium_without_strong_rule_evidence(self):
        service = EnterpriseService(database=self.db, provider=AggressiveProvider())
        queued = service.ingest_eml("model-only-risk.eml", MODEL_ONLY_EML)
        result, _ = service.process_analysis(queued["analysis_id"])

        self.assertEqual(queued["quick_result"]["risk_level"], "medium")
        self.assertEqual(result["risk_level"], "medium")
        self.assertEqual(result["risk_score"], 64)
        self.assertIn("high_risk_requires_strong_deterministic_evidence", result["calibration"]["notes"])

    def test_memory_rate_limiter_blocks_after_limit(self):
        bucket = defaultdict(deque)

        self.assertTrue(check_rate_limit(bucket, "login:user", 2, 60))
        self.assertTrue(check_rate_limit(bucket, "login:user", 2, 60))
        self.assertFalse(check_rate_limit(bucket, "login:user", 2, 60))


if __name__ == "__main__":
    unittest.main()
