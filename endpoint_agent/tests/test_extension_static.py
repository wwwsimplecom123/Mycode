import json
from pathlib import Path
import re
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
EXTENSION_ROOT = ENDPOINT_ROOT / "extension"
DEVELOPMENT_ORIGIN = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/"


class ExtensionStaticTests(unittest.TestCase):
    def test_manifest_has_exact_mv3_permissions_and_chinaccs_match(self):
        manifest = json.loads((EXTENSION_ROOT / "manifest.json").read_text(encoding="utf-8"))

        self.assertEqual(manifest["manifest_version"], 3)
        self.assertEqual(manifest["permissions"], ["nativeMessaging"])
        self.assertNotIn("host_permissions", manifest)
        self.assertNotIn("optional_host_permissions", manifest)
        self.assertEqual(manifest["background"], {"service_worker": "background.js"})
        self.assertEqual(len(manifest["content_scripts"]), 1)
        script = manifest["content_scripts"][0]
        self.assertEqual(script["matches"], ["https://webmail.chinaccs.cn/*"])
        self.assertEqual(script["js"], ["adapters/chinaccs.js", "content.js"])
        self.assertEqual(script["css"], ["style.css"])
        self.assertNotIn("<all_urls>", json.dumps(manifest))
        for icon_path in manifest["icons"].values():
            self.assertTrue(icon_path.endswith(".png"))
            self.assertTrue((EXTENSION_ROOT / icon_path).is_file())

    def test_extension_sources_have_no_network_secret_or_remote_code_capability(self):
        sources = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (
                EXTENSION_ROOT / "background.js",
                EXTENSION_ROOT / "content.js",
                EXTENSION_ROOT / "adapters" / "chinaccs.js",
            )
        )
        forbidden = (
            r"\bfetch\s*\(",
            r"\bXMLHttpRequest\b",
            r"\bWebSocket\b",
            r"\bEventSource\b",
            r"\bsendBeacon\b",
            r"\baxios\b",
            r"\b(?:localStorage|sessionStorage)\b",
            r"document\.cookie",
            r"\btoken\b",
            r"\bapi[_-]?key\b",
            r"\bserver[_-]?address\b",
            r"\b(?:eval|importScripts)\s*\(",
            r"\bnew\s+Function\s*\(",
            r"https?://",
        )
        for pattern in forbidden:
            with self.subTest(pattern=pattern):
                self.assertIsNone(re.search(pattern, sources, re.IGNORECASE))
        self.assertIn('chrome.runtime.sendNativeMessage(HOST_NAME', sources)

    def test_chinaccs_adapter_uses_specific_roots_and_safe_fact_extraction(self):
        source = (EXTENSION_ROOT / "adapters" / "chinaccs.js").read_text(encoding="utf-8")

        for required in (
            "#mailContent",
            "sanitized_body_text",
            "recipient_summary",
            "normalized_links",
            "attachment_metadata",
            "language_hint",
            "crypto.subtle.digest",
            "source_message_id",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "document.body.innerText",
            "document.body.textContent",
            'querySelectorAll("td")',
            "location.href",
            "location.search",
            "searchParams",
            ".click(",
            "window.open",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("body_not_recognized", source)

    def test_content_status_bar_covers_required_states_without_internal_evidence(self):
        content = (EXTENSION_ROOT / "content.js").read_text(encoding="utf-8")
        css = (EXTENSION_ROOT / "style.css").read_text(encoding="utf-8")

        for label in (
            "检测中",
            "风险等级",
            "纯规则模式",
            "模型未安装",
            "不确定",
            "Agent 未启动",
            "Host 不存在",
            "协议错误",
            "请求超限",
            "当前页面未识别正文",
            "local event ID",
            "通用建议",
        ):
            self.assertIn(label, content)
        self.assertIn("shielddome-endpoint-status", content)
        self.assertIn("MutationObserver", content)
        self.assertIn("remove()", content)
        self.assertIn(
            "activeIdentity === pageIdentity && document.getElementById(STATUS_ID)",
            content,
        )
        self.assertNotIn("position: fixed", css.lower())
        self.assertNotIn("gradient", css.lower())
        for internal in ("probability", "rule_id", "score_contribution", "strong_evidence", "model_version"):
            self.assertNotIn(internal, content)

    def test_native_host_manifest_has_one_fixed_development_origin(self):
        manifest_path = ENDPOINT_ROOT / "native_host" / "com.shielddome.endpoint_agent.development.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        self.assertEqual(manifest["name"], "cn.shielddome.endpoint_agent")
        self.assertEqual(manifest["type"], "stdio")
        self.assertEqual(manifest["allowed_origins"], [DEVELOPMENT_ORIGIN])
        self.assertNotIn("*", manifest["allowed_origins"][0])
        self.assertFalse(manifest["allowed_origins"][0].startswith(("http://", "https://")))
        self.assertIn("DEVELOPMENT", manifest["description"])
        self.assertTrue(Path(manifest["path"]).is_absolute())


if __name__ == "__main__":
    unittest.main()
