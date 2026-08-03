from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))


OBSERVED_AT = datetime(2026, 8, 3, 8, 0, tzinfo=timezone.utc)


def valid_detect_message():
    return {
        "protocol_version": "1.0",
        "message_type": "detect_mail",
        "mail": {
            "source_message_id": "a" * 64,
            "subject": "季度流程确认",
            "sender": "sender@example.test",
            "reply_to": None,
            "recipient_summary": ["current-user"],
            "sanitized_body_text": "请通过正常公司流程确认。",
            "normalized_links": ["https://portal.example.test/notice"],
            "attachment_metadata": [
                {
                    "name": "notice.pdf",
                    "declared_type": "application/pdf",
                    "displayed_size": "12 KB",
                }
            ],
            "language_hint": "zh",
        },
    }


class NativePayloadTests(unittest.TestCase):
    def test_parses_exact_ping_request(self):
        from shielddome_endpoint.native_payload import PingRequest, parse_native_request

        request = parse_native_request(
            {"protocol_version": "1.0", "message_type": "ping"}
        )

        self.assertEqual(request, PingRequest())

    def test_parses_detect_mail_and_builds_observation_facts(self):
        from shielddome_endpoint.native_payload import (
            DetectMailRequest,
            parse_native_request,
            to_mail_observation,
        )

        request = parse_native_request(valid_detect_message())
        observation = to_mail_observation(request, OBSERVED_AT)

        self.assertIsInstance(request, DetectMailRequest)
        self.assertEqual(observation.source_kind, "browser_native")
        self.assertEqual(observation.source_message_id, "a" * 64)
        self.assertEqual(observation.observed_at, OBSERVED_AT)
        self.assertEqual(
            observation.attachment_metadata,
            (
                ("name", "notice.pdf"),
                ("declared_type", "application/pdf"),
                ("displayed_size", "12 KB"),
            ),
        )

    def test_rejects_unknown_protocol_message_type_and_fields(self):
        from shielddome_endpoint.native_protocol import NativeProtocolError
        from shielddome_endpoint.native_payload import parse_native_request

        cases = []
        wrong_version = valid_detect_message()
        wrong_version["protocol_version"] = "2.0"
        cases.append((wrong_version, "unsupported_protocol_version"))
        wrong_type = valid_detect_message()
        wrong_type["message_type"] = "analyze"
        cases.append((wrong_type, "unknown_message_type"))
        root_extra = valid_detect_message()
        root_extra["origin"] = "chrome-extension://untrusted/"
        cases.append((root_extra, "unknown_field"))
        mail_extra = valid_detect_message()
        mail_extra["mail"]["risk_level"] = "critical"
        cases.append((mail_extra, "unknown_field"))
        attachment_extra = valid_detect_message()
        attachment_extra["mail"]["attachment_metadata"][0]["content"] = "secret"
        cases.append((attachment_extra, "unknown_field"))

        for message, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaises(NativeProtocolError) as caught:
                    parse_native_request(message)
                self.assertEqual(caught.exception.error_code, expected)

    def test_rejects_every_client_risk_identity_and_secret_injection(self):
        from shielddome_endpoint.native_protocol import NativeProtocolError
        from shielddome_endpoint.native_payload import parse_native_request

        forbidden = (
            "RuleAssessment",
            "rule_id",
            "score_contribution",
            "strong_evidence",
            "final_risk_score",
            "risk_level",
            "ModelAssessment",
            "model_probability",
            "probability",
            "execution_state",
            "generic_action",
            "Token",
            "server_address",
            "api_key",
            "user_role",
            "permission",
        )
        for field in forbidden:
            with self.subTest(field=field):
                message = valid_detect_message()
                message["mail"][field] = "untrusted-private-value"
                with self.assertRaises(NativeProtocolError) as caught:
                    parse_native_request(message)
                self.assertEqual(caught.exception.error_code, "unknown_field")
                self.assertNotIn("untrusted-private-value", repr(caught.exception))

    def test_rejects_missing_fields_and_type_errors(self):
        from shielddome_endpoint.native_protocol import NativeProtocolError
        from shielddome_endpoint.native_payload import parse_native_request

        cases = []
        missing_mail = valid_detect_message()
        del missing_mail["mail"]["sender"]
        cases.append(missing_mail)
        boolean_mail = valid_detect_message()
        boolean_mail["mail"] = True
        cases.append(boolean_mail)
        wrong_recipients = valid_detect_message()
        wrong_recipients["mail"]["recipient_summary"] = "current-user"
        cases.append(wrong_recipients)
        wrong_attachment = valid_detect_message()
        wrong_attachment["mail"]["attachment_metadata"] = ["notice.pdf"]
        cases.append(wrong_attachment)
        wrong_language = valid_detect_message()
        wrong_language["mail"]["language_hint"] = "fr"
        cases.append(wrong_language)
        wrong_identity = valid_detect_message()
        wrong_identity["mail"]["source_message_id"] = "raw-message-id"
        cases.append(wrong_identity)

        for message in cases:
            with self.subTest(message=message):
                with self.assertRaises(NativeProtocolError) as caught:
                    parse_native_request(message)
                self.assertEqual(caught.exception.error_code, "invalid_field_type")

    def test_rejects_values_and_arrays_above_central_limits(self):
        from shielddome_endpoint.native_protocol import NATIVE_LIMITS, NativeProtocolError
        from shielddome_endpoint.native_payload import parse_native_request

        cases = []
        field_lengths = (
            ("subject", NATIVE_LIMITS.subject_characters),
            ("sender", NATIVE_LIMITS.address_characters),
            ("sanitized_body_text", NATIVE_LIMITS.body_characters),
        )
        for field, limit in field_lengths:
            message = valid_detect_message()
            message["mail"][field] = "x" * (limit + 1)
            cases.append(message)
        too_many_recipients = valid_detect_message()
        too_many_recipients["mail"]["recipient_summary"] = [
            "user"
        ] * (NATIVE_LIMITS.recipient_items + 1)
        cases.append(too_many_recipients)
        too_many_links = valid_detect_message()
        too_many_links["mail"]["normalized_links"] = [
            "https://example.test/"
        ] * (NATIVE_LIMITS.link_items + 1)
        cases.append(too_many_links)
        too_many_attachments = valid_detect_message()
        too_many_attachments["mail"]["attachment_metadata"] = [
            {"name": "a.pdf", "declared_type": None, "displayed_size": None}
        ] * (NATIVE_LIMITS.attachment_items + 1)
        cases.append(too_many_attachments)
        long_recipient = valid_detect_message()
        long_recipient["mail"]["recipient_summary"] = [
            "x" * (NATIVE_LIMITS.recipient_characters + 1)
        ]
        cases.append(long_recipient)
        long_link = valid_detect_message()
        long_link["mail"]["normalized_links"] = [
            "x" * (NATIVE_LIMITS.link_characters + 1)
        ]
        cases.append(long_link)
        for field, limit in (
            ("name", NATIVE_LIMITS.attachment_name_characters),
            ("declared_type", NATIVE_LIMITS.attachment_type_characters),
            ("displayed_size", NATIVE_LIMITS.attachment_size_characters),
        ):
            message = valid_detect_message()
            message["mail"]["attachment_metadata"][0][field] = "x" * (limit + 1)
            cases.append(message)

        for message in cases:
            with self.subTest():
                with self.assertRaises(NativeProtocolError) as caught:
                    parse_native_request(message)
                self.assertEqual(caught.exception.error_code, "payload_limit_exceeded")

    def test_values_exactly_at_limits_are_accepted(self):
        from shielddome_endpoint.native_protocol import NATIVE_LIMITS
        from shielddome_endpoint.native_payload import parse_native_request

        message = valid_detect_message()
        mail = message["mail"]
        mail["subject"] = "s" * NATIVE_LIMITS.subject_characters
        mail["sanitized_body_text"] = "b" * NATIVE_LIMITS.body_characters
        mail["recipient_summary"] = [
            "r" * NATIVE_LIMITS.recipient_characters
        ] * NATIVE_LIMITS.recipient_items
        mail["normalized_links"] = [
            "l" * NATIVE_LIMITS.link_characters
        ] * NATIVE_LIMITS.link_items

        self.assertEqual(parse_native_request(message).subject, mail["subject"])


if __name__ == "__main__":
    unittest.main()
