import unittest

from shielddome.analyzer import AnalyzerService
from shielddome.llm import LLMClient, LLMSettings


class FakeLLMClient:
    def public_config(self):
        return {
            "configured": True,
            "endpoint": "https://example.test/v1/chat/completions",
            "model": "test-model",
            "api_key_masked": "test...-key",
            "storage": "server_memory_or_environment",
        }

    def configure(self, payload):
        return self.public_config()

    def analyze_email(self, context):
        self.context = context
        return {
            "status": "completed",
            "model": "test-model",
            "risk_delta": 30,
            "reason": "模型识别到外部链接诱导敏感操作。",
            "signals": ["external_sensitive_action"],
            "usage": {"total_tokens": 100},
        }


class ShieldDomeLLMTests(unittest.TestCase):
    def test_runtime_config_masks_api_key(self):
        client = LLMClient(LLMSettings())

        config = client.configure(
            {
                "api_key": "sk-1234567890-secret",
                "model": "test-model",
                "endpoint": "https://example.test/v1/chat/completions",
            }
        )

        self.assertTrue(config["configured"])
        self.assertEqual(config["api_key_masked"], "sk-1...cret")
        self.assertNotIn("sk-1234567890-secret", str(config))

    def test_deep_analysis_combines_real_model_result(self):
        fake_llm = FakeLLMClient()
        service = AnalyzerService(deep_delay_seconds=0, llm_client=fake_llm)
        quick = service.quick_analyze(
            {
                "subject": "普通业务通知",
                "sender": "supplier@external.com",
                "body_text": "请查看本次业务安排。",
                "links": [
                    {
                        "display_text": "业务页面",
                        "href": "https://external.com/info",
                    }
                ],
            },
            start_background=False,
        )

        deep = service.deep_analyze(quick["analysis_id"])

        self.assertEqual(deep["evidence"]["llm"]["status"], "completed")
        self.assertIn("model:external_sensitive_action", deep["evidence"]["semantic_signals"])
        self.assertEqual(deep["reason"], "模型识别到外部链接诱导敏感操作。")
        self.assertIn("[EXTERNAL_SENDER_DOMAIN: external.com]", str(fake_llm.context))
        self.assertNotIn("supplier@external.com", str(fake_llm.context))
        self.assertNotIn("https://external.com/info", str(fake_llm.context))

    def test_remote_endpoint_requires_https(self):
        client = LLMClient(LLMSettings())

        with self.assertRaises(ValueError):
            client.configure(
                {
                    "api_key": "sk-test",
                    "model": "test-model",
                    "endpoint": "http://external.example/v1/chat/completions",
                }
            )


if __name__ == "__main__":
    unittest.main()
