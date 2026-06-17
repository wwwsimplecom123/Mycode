import unittest

from fastapi import HTTPException

import app.api as api_module


class DummyRequest:
    def __init__(self, headers=None):
        self.headers = headers or {}


class FakeAuth:
    def __init__(self, user=None):
        self.user = user

    def authenticate_plugin_token(self, _token):
        return self.user


class FailingAuditDb:
    def record_audit(self, *_args, **_kwargs):
        raise RuntimeError("audit unavailable")


class FakeService:
    def __init__(self, user=None):
        self.auth = FakeAuth(user)
        self.db = FailingAuditDb()
        self.seen_payload = None
        self.seen_actor = None

    def ingest_browser_probe(self, payload, actor):
        self.seen_payload = payload
        self.seen_actor = actor
        return {
            "analysis_id": "analysis-test",
            "status": "queued",
            "risk_level": "low",
            "action": "allow",
            "reason": "quick ok",
            "matched_rules": [],
            "deep_scan_required": True,
            "quick_result": {"risk_level": "low"},
        }


class BrowserProbeApiTests(unittest.TestCase):
    def setUp(self):
        self.original_service = api_module.SERVICE
        self.original_optional = api_module.PLUGIN_AUTH_OPTIONAL

    def tearDown(self):
        api_module.SERVICE = self.original_service
        api_module.PLUGIN_AUTH_OPTIONAL = self.original_optional

    def test_plugin_token_is_required_by_default(self):
        api_module.SERVICE = FakeService(user=None)
        api_module.PLUGIN_AUTH_OPTIONAL = False

        with self.assertRaises(HTTPException) as raised:
            api_module.require_browser_probe("")

        self.assertEqual(raised.exception.status_code, 401)

    def test_optional_plugin_auth_allows_test_probe_without_token(self):
        api_module.SERVICE = FakeService(user=None)
        api_module.PLUGIN_AUTH_OPTIONAL = True

        actor = api_module.require_browser_probe("")
        result = api_module.browser_probe_quick(
            {"message_id": "m1", "body_text": "meeting agenda " * 3, "links": None},
            DummyRequest(),
            actor,
        )

        self.assertEqual(result["submitted_by"]["username"], "browser-probe")
        self.assertEqual(result["analysis_id"], "analysis-test")

    def test_bad_content_length_and_audit_failure_do_not_return_500(self):
        api_module.SERVICE = FakeService(
            user={"id": "u1", "username": "probe.user", "display_name": "Probe User", "role": "analyst"}
        )
        api_module.PLUGIN_AUTH_OPTIONAL = False
        actor = api_module.require_browser_probe("sdp_test")

        result = api_module.browser_probe_quick(
            {
                "message_id": "m2",
                "body_text": "security notice " * 3,
                "links": "not-a-list",
            },
            DummyRequest(headers={"content-length": "not-a-number"}),
            actor,
        )

        self.assertEqual(result["analysis_id"], "analysis-test")
        self.assertEqual(result["submitted_by"]["username"], "probe.user")

    def test_analysis_visibility_rejects_other_non_admin_users(self):
        item = {"parsed_message": {"submitted_by": {"id": "owner-1", "username": "owner.one"}}}

        api_module.ensure_analysis_visible(item, {"id": "owner-1", "username": "owner.one", "role": "analyst"})
        api_module.ensure_analysis_visible(item, {"id": "admin-1", "username": "admin", "role": "admin"})
        with self.assertRaises(HTTPException) as raised:
            api_module.ensure_analysis_visible(item, {"id": "owner-2", "username": "owner.two", "role": "analyst"})

        self.assertEqual(raised.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()
