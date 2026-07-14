import time
import unittest

from shielddome.analyzer import AnalyzerService
from shielddome.entities import generalize_entities, sanitize_model_value
from shielddome.evidence import Evidence, aggregate_evidence, aggregate_rag_matches, explain_final_score
from shielddome.links import structuralize_links
from shielddome.rules import analyze_quick


class ShieldDomeAnalyzerTests(unittest.TestCase):
    def test_rag_aggregation_is_order_independent_and_reports_conflict(self):
        matches = [
            {"source_type": "phishing_case", "score": 0.9},
            {"source_type": "trusted_email", "score": 0.88},
        ]
        forward = aggregate_rag_matches(matches)
        reverse = aggregate_rag_matches(list(reversed(matches)))

        self.assertEqual(forward, reverse)
        self.assertTrue(forward["conflict"])
        self.assertEqual(forward["risk_delta"], 0)
        self.assertTrue(forward["requires_manual_review"])

    def test_structured_evidence_deduplicates_one_fact_and_explains_exact_score(self):
        thresholds = {"medium": 35, "high": 65, "critical": 85}
        aggregated = aggregate_evidence(
            [
                Evidence("external_link", "外部链接", "包含外部链接", "url_deception", 8, entity_key="url:1"),
                Evidence("display_href_mismatch", "链接伪装", "显示与跳转不一致", "url_deception", 50, entity_key="url:1"),
                Evidence("high_risk_keyword", "敏感操作", "要求重新登录", "sensitive_intent", 7),
            ],
            thresholds,
        )

        self.assertEqual(aggregated["score"], 57)
        external = next(item for item in aggregated["evidences"] if item["rule_id"] == "external_link")
        self.assertTrue(external["deduplicated"])
        self.assertEqual(external["effective_weight"], 0)
        explanation = explain_final_score(aggregated["group_scores"], [], aggregated["score"], thresholds)
        self.assertEqual(sum(item["score"] for item in explanation["items"]), explanation["final_score"])

    def test_trusted_internal_keyword_evidence_is_suppressed_but_visible(self):
        result = analyze_quick({
            "subject": "OA 密码重置提醒",
            "sender": "security@company.com",
            "body_text": "请按流程重置密码",
            "links": [],
        })

        evidence = next(item for item in result["evidence"]["evidences"] if item["rule_id"] == "high_risk_keyword")
        self.assertTrue(evidence["suppressed"])
        self.assertEqual(evidence["effective_weight"], 4)
        self.assertTrue(evidence["suppression_reasons"])

    def test_quick_blocks_display_href_mismatch_with_sensitive_intent(self):
        payload = {
            "subject": "紧急：OA 密码重置",
            "sender": "hr-dept@external.com",
            "body_text": "请立即登录 OA 系统重置密码，否则账号将被冻结。",
            "links": [
                {
                    "display_text": "https://oa.company.com/reset",
                    "href": "https://evil-login.com/reset",
                    "context_before": "请立即登录",
                    "context_after": "完成重置",
                }
            ],
        }

        result = analyze_quick(payload)

        self.assertEqual(result["risk_level"], "critical")
        self.assertEqual(result["action"], "block")
        self.assertIn("display_href_mismatch", result["matched_rules"])
        self.assertIn("blacklisted_domain", result["matched_rules"])

    def test_entity_labeling_preserves_domain_and_security_semantics(self):
        text = "王总要求 hr-dept@external.com 今日付款 280000 元，并登录 OA 审批系统确认。"

        result = generalize_entities(text, sender="hr-dept@external.com")

        sanitized = result["text"]
        self.assertIn("[EXTERNAL_EMAIL_DOMAIN: external.com]", sanitized)
        self.assertIn("[INTERNAL_EXECUTIVE_NAME_A]", sanitized)
        self.assertIn("[AMOUNT_RANGE_HIGH]", sanitized)
        self.assertIn("[INTERNAL_SYSTEM: OA]", sanitized)
        self.assertNotIn("hr-dept@external.com", sanitized)
        self.assertNotIn("王总", sanitized)

    def test_model_sanitizer_removes_sensitive_values_and_is_idempotent(self):
        text = (
            "Contact Alice phone 010-59510316 mobile 13800138000 "
            "ID 11010519491231002X card 6222020202020202020 "
            "token raw-secret-token password SecretPass-2026 CNY 280000 "
            "验证码839201 private link https://secret.example.com/reset?token=raw-secret-token"
        )

        sanitized = str(sanitize_model_value(text))
        sanitized_twice = str(sanitize_model_value(sanitized))

        for secret in (
            "Alice",
            "010-59510316",
            "13800138000",
            "11010519491231002X",
            "6222020202020202020",
            "raw-secret-token",
            "SecretPass-2026",
            "839201",
            "280000",
            "/reset?token=",
        ):
            self.assertNotIn(secret, sanitized)
        self.assertIn("[PERSON_NAME]", sanitized)
        self.assertIn("[LANDLINE_NUMBER]", sanitized)
        self.assertIn("[SECRET_VALUE]", sanitized)
        self.assertIn("[URL_DOMAIN: secret.example.com]", sanitized)
        self.assertIn("private link", sanitized)
        self.assertEqual(sanitized, sanitized_twice)

    def test_structural_link_features_bind_display_href_and_context(self):
        links = structuralize_links(
            [
                {
                    "display_text": "https://oa.company.com/reset",
                    "href": "https://external.example/reset",
                    "context_before": "请点击",
                    "context_after": "重置密码",
                }
            ]
        )

        link = links[0]
        self.assertEqual(link["display_domain"], "oa.company.com")
        self.assertEqual(link["href_domain"], "external.example")
        self.assertTrue(link["display_href_mismatch"])
        self.assertFalse(link["trusted_href"])

    def test_trusted_url_policy_matches_only_the_exact_url(self):
        policy = {
            "trusted_domains": [],
            "trusted_urls": ["https://portal.example/login?source=mail"],
            "trusted_ip_ranges": [],
            "blacklisted_domains": [],
            "high_risk_keywords": [],
            "risk_thresholds": {"medium": 35, "high": 65, "critical": 85},
        }
        trusted = analyze_quick(
            {"links": [{"href": "https://portal.example/login?source=mail", "display_text": "portal"}]},
            policy=policy,
        )
        different_path = analyze_quick(
            {"links": [{"href": "https://portal.example/admin", "display_text": "portal"}]},
            policy=policy,
        )

        self.assertTrue(trusted["evidence"]["links"][0]["trusted_url"])
        self.assertNotIn("external_link", trusted["matched_rules"])
        self.assertFalse(different_path["evidence"]["links"][0]["trusted_url"])
        self.assertIn("external_link", different_path["matched_rules"])

    def test_deep_analysis_does_not_raise_semantic_anomaly_above_medium_without_strong_rule(self):
        service = AnalyzerService(deep_delay_seconds=0)
        quick = service.quick_analyze(
            {
                "subject": "OA 审批待办流程通知",
                "sender": "notice@external.com",
                "body_text": "您有一条新的 OA 审批待办，请登录 OA 审批系统查看流程详情。",
                "links": [
                    {
                        "display_text": "OA 审批系统",
                        "href": "https://external.com/oa/todo",
                        "context_before": "请登录",
                        "context_after": "查看流程详情",
                    }
                ],
            },
            start_background=False,
        )

        deep = service.deep_analyze(quick["analysis_id"])
        anomalies = deep["evidence"]["rag_match"]["anomalies"]

        self.assertEqual(deep["risk_level"], "medium")
        self.assertIn("trusted_style_sender_domain_mismatch", anomalies)
        self.assertIn("trusted_style_link_domain_mismatch", anomalies)
        self.assertIn("high_risk_requires_strong_deterministic_evidence", deep["evidence"]["calibration_notes"])

    def test_mailto_links_are_not_external_or_display_mismatches(self):
        result = analyze_quick(
            {
                "subject": "日志抽查任务回复",
                "sender": "employee@external.example",
                "body_text": "请查看 web 系统登录日志，联系人如下。",
                "links": [
                    {"display_text": "employee.name", "href": "mailto:employee@external.example"},
                    {"display_text": "http://www.example.com", "href": "http://www.example.com"},
                ],
            }
        )

        self.assertEqual(result["risk_level"], "low")
        self.assertNotIn("display_href_mismatch", result["matched_rules"])
        self.assertEqual(result["matched_rules"], ["external_link"])

    def test_private_ip_link_is_trusted_only_when_policy_configures_its_network(self):
        payload = {
            "subject": "安全设备操作权限开通通知",
            "sender": "soc@external.example",
            "body_text": "设备地址及用户名密码如下。",
            "links": [{"display_text": "https://10.24.200.9", "href": "https://10.24.200.9/"}],
        }

        unconfigured = analyze_quick(payload, policy={"trusted_ip_ranges": []})
        self.assertEqual(unconfigured["risk_level"], "medium")
        self.assertIn("external_link", unconfigured["matched_rules"])
        self.assertFalse(unconfigured["evidence"]["links"][0]["internal_network"])

        result = analyze_quick(
            payload,
            policy={"trusted_ip_ranges": ["10.24.0.0/16"]},
        )

        self.assertEqual(result["risk_level"], "low")
        self.assertNotIn("external_link", result["matched_rules"])
        self.assertTrue(result["evidence"]["links"][0]["internal_network"])

    def test_malformed_glued_url_is_not_treated_as_external(self):
        result = analyze_quick(
            {
                "subject": "设备密码通知",
                "sender": "soc@external.example",
                "body_text": "设备密码如下。",
                "links": [
                    {
                        "display_text": "https://10.24.200.9user@password@tail",
                        "href": "https://10.24.200.9user@password@tail",
                    }
                ],
            }
        )

        self.assertEqual(result["risk_level"], "low")
        self.assertNotIn("external_link", result["matched_rules"])
        self.assertFalse(result["evidence"]["links"][0]["is_web_link"])

    def test_analyzer_service_uses_runtime_policy_provider(self):
        service = AnalyzerService(
            deep_delay_seconds=0,
            policy_provider=lambda: {
                "trusted_domains": [],
                "trusted_ip_ranges": ["10.24.0.0/16"],
                "blacklisted_domains": [],
                "high_risk_keywords": [],
                "risk_thresholds": {"medium": 35, "high": 65, "critical": 85},
            },
        )
        quick = service.quick_analyze(
            {
                "subject": "设备密码通知",
                "sender": "soc@external.example",
                "body_text": "设备密码如下。",
                "links": [{"display_text": "https://10.24.200.9", "href": "https://10.24.200.9/"}],
            },
            start_background=False,
        )

        self.assertEqual(quick["risk_level"], "low")
        self.assertEqual(quick["matched_rules"], [])

    def test_false_positive_review_adds_style_fingerprint_without_raw_body(self):
        service = AnalyzerService(deep_delay_seconds=0)
        quick = service.quick_analyze(
            {
                "subject": "电子发票通知",
                "sender": "notice@invoice.company.com",
                "body_text": "请前往发票系统查验电子发票。",
                "links": [
                    {
                        "display_text": "发票系统",
                        "href": "https://invoice.company.com/view/123",
                    }
                ],
            },
            start_background=False,
        )
        service.deep_analyze(quick["analysis_id"])
        ticket = service.create_false_positive_ticket(
            {
                "analysis_id": quick["analysis_id"],
                "user_id": "employee",
                "comment": "正常业务邮件",
            }
        )

        review = service.review_ticket(
            {
                "ticket_id": ticket["ticket_id"],
                "review_result": "approved",
                "reviewer": "soc",
            }
        )

        self.assertEqual(review["status"], "approved")
        self.assertIn("added_fingerprint", review)
        self.assertNotIn("body_text", review["added_fingerprint"])

    def test_background_deep_scan_completes_for_progressive_ui_polling(self):
        service = AnalyzerService(deep_delay_seconds=0.01)
        quick = service.quick_analyze(
            {
                "subject": "OA 审批待办通知",
                "sender": "notice@oa.company.com",
                "body_text": "您有一条新的 OA 审批待办，请登录 OA 审批系统查看。",
                "links": [
                    {
                        "display_text": "OA 审批系统",
                        "href": "https://oa.company.com/todo/123",
                    }
                ],
            }
        )

        status = service.status(quick["analysis_id"])
        for _ in range(20):
            if status["deep_status"] == "completed":
                break
            time.sleep(0.01)
            status = service.status(quick["analysis_id"])

        self.assertEqual(status["deep_status"], "completed")
        self.assertEqual(status["deep_result"]["risk_level"], "low")


if __name__ == "__main__":
    unittest.main()
