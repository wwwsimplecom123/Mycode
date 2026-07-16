import unittest

from fastapi import HTTPException

import app.api as api_module
from shielddome.permissions import analysis_scope, has_permission, is_readonly_actor, permissions_for_role


class PermissionMatrixTests(unittest.TestCase):
    def test_roles_separate_write_and_audit_capabilities(self):
        analyst = {"id": "a1", "role": "analyst", "permissions": permissions_for_role("analyst")}
        auditor = {"id": "u1", "role": "auditor", "permissions": permissions_for_role("auditor")}

        self.assertTrue(has_permission(analyst, "analysis:feedback"))
        self.assertFalse(has_permission(auditor, "analysis:feedback"))
        self.assertTrue(has_permission(auditor, "audit:read:any"))
        self.assertFalse(has_permission(auditor, "application:download"))
        self.assertTrue(is_readonly_actor({**auditor, "data_scope": "all_readonly"}))
        self.assertEqual(
            analysis_scope(analyst),
            {"kind": "team", "owner_user_id": "a1", "assigned_analyst_id": "a1", "security_team_id": ""},
        )
        self.assertEqual(analysis_scope(auditor), {"kind": "all"})
        department = {
            "id": "d1", "role": "analyst", "permissions": permissions_for_role("analyst"),
            "data_scope": "team", "organization_id": "org-1", "department_id": "soc", "security_team_id": "soc",
        }
        self.assertEqual(
            analysis_scope(department),
            {"kind": "team", "owner_user_id": "d1", "assigned_analyst_id": "d1", "security_team_id": "soc"},
        )
        regular = {"id": "u1", "role": "user", "permissions": permissions_for_role("user")}
        self.assertTrue(has_permission(regular, "me:mail"))
        self.assertEqual(analysis_scope(regular), {"kind": "self", "owner_user_id": "u1"})


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


class FakeKnowledgeService:
    def __init__(self):
        self.approved = []
        self.disabled = []

    def approve_knowledge(self, item_id):
        self.approved.append(item_id)
        return {"id": item_id, "status": "published"}

    def disable_knowledge(self, item_id):
        self.disabled.append(item_id)
        return {"id": item_id, "status": "disabled"}


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

    def test_team_visibility_allows_same_security_team_only(self):
        item = {"owner_user_id": "owner-1", "security_team_id": "soc-a", "parsed_message": {"submitted_by": {"id": "owner-1"}}}

        api_module.ensure_analysis_visible(item, {"id": "analyst-1", "role": "analyst", "data_scope": "team", "security_team_id": "soc-a"})
        with self.assertRaises(HTTPException) as raised:
            api_module.ensure_analysis_visible(item, {"id": "analyst-2", "role": "analyst", "data_scope": "team", "security_team_id": "soc-b"})

        self.assertEqual(raised.exception.status_code, 403)

    def test_user_and_auditor_analysis_views_are_redacted(self):
        item = {
            "id": "a1",
            "raw_path": "secret.eml",
            "error": "worker stack",
            "parsed_message": {
                "subject": "Sensitive payment notice",
                "sender": "alice@example.com",
                "recipient": "bob@example.com",
                "body_text": "secret body",
                "headers": {"x": "y"},
                "links": [{"href": "https://example.com/path?token=secret", "display_text": "secret", "html_snippet": "<a>"}],
                "attachments": [{"filename": "payroll.xlsx", "sha256": "abc"}],
            },
            "quick_result": {"evidence": {"score_breakdown": {"x": 1}, "group_scores": {"x": 1}, "evidences": [{"rule_id": "x"}]}},
            "result": {"llm": {"status": "completed", "model": "hidden"}, "rag": {"references": [{"excerpt": "hidden"}]}, "group_scores": {"x": 1}},
        }

        user_view = api_module.sanitize_analysis_for_actor(item, {"role": "user"})
        auditor_view = api_module.sanitize_analysis_for_actor(item, {"role": "auditor"})

        self.assertNotIn("raw_path", user_view)
        self.assertNotIn("body_text", user_view["parsed_message"])
        self.assertNotIn("group_scores", user_view["result"])
        self.assertEqual(user_view["result"]["llm"], {"status": "completed", "error_type": ""})
        self.assertNotIn("error", auditor_view)
        self.assertEqual(auditor_view["data_view"], "redacted")
        self.assertEqual(auditor_view["parsed_message"]["links"][0]["href"], "https://example.com/path")

    def test_bulk_knowledge_actions_call_each_item(self):
        service = FakeKnowledgeService()
        api_module.SERVICE = service
        request = api_module.KnowledgeBulkRequest(ids=["k1", "k2"])

        approved = api_module.bulk_approve_knowledge(request, _actor="admin")
        disabled = api_module.bulk_disable_knowledge(request, _actor="admin")

        self.assertEqual(approved["completed"], 2)
        self.assertEqual(disabled["completed"], 2)
        self.assertEqual(service.approved, ["k1", "k2"])
        self.assertEqual(service.disabled, ["k1", "k2"])


if __name__ == "__main__":
    unittest.main()
