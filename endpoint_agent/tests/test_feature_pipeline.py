from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ENDPOINT_ROOT / "src"
sys.path.insert(0, str(SOURCE_ROOT))

from shielddome_endpoint.domain import FEATURE_SCHEMA_VERSION, MailObservation
from shielddome_endpoint.feature_pipeline import (
    FEATURE_ATTACHMENT_MAX_ITEMS,
    FEATURE_AUTHENTICATION_MAX_ITEMS,
    FEATURE_TEXT_MAX_CHARACTERS,
    FEATURE_URL_MAX_ITEMS,
    FeaturePipeline,
)


EXPECTED_NUMERIC_NAMES = (
    "subject_present",
    "subject_length",
    "body_present",
    "body_length",
    "sender_present",
    "sender_length",
    "reply_to_present",
    "reply_to_length",
    "sender_reply_domain_match",
    "auth_spf_present",
    "auth_dkim_present",
    "auth_dmarc_present",
    "url_count",
    "https_url_count",
    "ip_literal_url_count",
    "suspicious_port_url_count",
    "unique_domain_count",
    "punycode_domain_count",
    "unicode_domain_count",
    "attachment_count",
    "double_extension_count",
    "dangerous_extension_count",
    "intent_credential_count",
    "intent_payment_count",
    "intent_urgency_count",
    "intent_impersonation_count",
)
EXPECTED_CATEGORICAL_NAMES = (
    "sender_domain_state",
    "reply_to_domain_state",
    "auth_spf_value",
    "auth_dkim_value",
    "auth_dmarc_value",
    "language",
)
EXPECTED_TEXT_VECTOR_DIGEST = (
    "b8ff6c2a6cace9575743ec9a70e0084433342fb4fc22cdb6c275d0f3745e32a4"
)


def make_observation(
    *,
    subject: str = "Ab",
    sanitized_body_text: str = "中",
) -> MailObservation:
    return MailObservation(
        source_kind="browser",
        source_message_id="synthetic-message-001",
        subject=subject,
        sender="security@example.test",
        reply_to="security@example.test",
        recipient_summary=("current-user",),
        sanitized_body_text=sanitized_body_text,
        authentication_observations=(
            ("spf", "pass"),
            ("dkim", "pass"),
            ("dmarc", "pass"),
        ),
        normalized_links=(),
        attachment_metadata=(),
        language_hint="mixed",
        observed_at=datetime(2026, 7, 30, tzinfo=timezone.utc),
    )


class FeaturePipelineTests(unittest.TestCase):
    def test_transform_bounds_url_processing_and_saturates_counts(self):
        safe_links = tuple(
            f"https://safe-{index}.example.test/path"
            for index in range(FEATURE_URL_MAX_ITEMS)
        )
        observation = replace(
            make_observation(),
            normalized_links=safe_links + ("http://192.0.2.10:8080/private",),
        )

        vector = FeaturePipeline().transform(observation)
        numeric = dict(vector.numeric_features)

        self.assertEqual(numeric["url_count"], float(FEATURE_URL_MAX_ITEMS))
        self.assertEqual(numeric["https_url_count"], float(FEATURE_URL_MAX_ITEMS))
        self.assertEqual(numeric["ip_literal_url_count"], 0.0)
        self.assertEqual(numeric["suspicious_port_url_count"], 0.0)
        self.assertEqual(
            numeric["unique_domain_count"],
            float(FEATURE_URL_MAX_ITEMS),
        )

    def test_transform_bounds_attachment_metadata_processing(self):
        safe_metadata = tuple(
            ("name", f"notice-{index}.txt")
            for index in range(FEATURE_ATTACHMENT_MAX_ITEMS)
        )
        observation = replace(
            make_observation(),
            attachment_metadata=safe_metadata + (("name", "invoice.pdf.exe"),),
        )

        vector = FeaturePipeline().transform(observation)
        numeric = dict(vector.numeric_features)

        self.assertEqual(
            numeric["attachment_count"],
            float(FEATURE_ATTACHMENT_MAX_ITEMS),
        )
        self.assertEqual(numeric["double_extension_count"], 0.0)
        self.assertEqual(numeric["dangerous_extension_count"], 0.0)

    def test_transform_bounds_authentication_observations(self):
        unrelated_observations = tuple(
            (f"x-auth-{index}", "pass")
            for index in range(FEATURE_AUTHENTICATION_MAX_ITEMS)
        )
        observation = replace(
            make_observation(),
            authentication_observations=unrelated_observations
            + (("spf", "fail"), ("dkim", "fail"), ("dmarc", "fail")),
        )

        vector = FeaturePipeline().transform(observation)
        numeric = dict(vector.numeric_features)
        categorical = dict(vector.categorical_features)

        self.assertEqual(numeric["auth_spf_present"], 0.0)
        self.assertEqual(numeric["auth_dkim_present"], 0.0)
        self.assertEqual(numeric["auth_dmarc_present"], 0.0)
        self.assertEqual(categorical["auth_spf_value"], "missing")
        self.assertEqual(categorical["auth_dkim_value"], "missing")
        self.assertEqual(categorical["auth_dmarc_value"], "missing")
        self.assertEqual(
            vector.missing_value_mask,
            ("auth_spf", "auth_dkim", "auth_dmarc"),
        )

    def test_transform_bounds_all_text_processing(self):
        bounded_prefix = "a" * FEATURE_TEXT_MAX_CHARACTERS
        first = replace(
            make_observation(
                subject="",
                sanitized_body_text=(
                    bounded_prefix + " password 紧急 中文 private-tail-one"
                ),
            ),
            language_hint=None,
        )
        second = replace(
            make_observation(
                subject="",
                sanitized_body_text=(
                    bounded_prefix + " wire urgent 中文 private-tail-two"
                ),
            ),
            language_hint=None,
        )

        first_vector = FeaturePipeline().transform(first)
        second_vector = FeaturePipeline().transform(second)
        numeric = dict(first_vector.numeric_features)
        categorical = dict(first_vector.categorical_features)

        self.assertEqual(first_vector.schema_version, "2.0")
        self.assertEqual(
            numeric["body_length"],
            float(FEATURE_TEXT_MAX_CHARACTERS),
        )
        self.assertEqual(numeric["intent_credential_count"], 0.0)
        self.assertEqual(numeric["intent_payment_count"], 0.0)
        self.assertEqual(numeric["intent_urgency_count"], 0.0)
        self.assertEqual(categorical["language"], "en")
        self.assertEqual(first_vector.text_vector, second_vector.text_vector)

    def test_transform_is_deterministic_versioned_ordered_and_private(self):
        observation = make_observation()

        first = FeaturePipeline().transform(observation)
        second = FeaturePipeline().transform(observation)

        self.assertEqual(first, second)
        self.assertEqual(first.schema_version, FEATURE_SCHEMA_VERSION)
        self.assertIsNone(first.text_input)
        self.assertEqual(len(first.text_vector or ()), 64)
        self.assertTrue(
            math.isclose(
                math.sqrt(sum(value * value for value in first.text_vector or ())),
                1.0,
                rel_tol=1e-12,
            )
        )
        self.assertEqual(
            tuple(name for name, _ in first.numeric_features),
            EXPECTED_NUMERIC_NAMES,
        )
        self.assertEqual(
            tuple(name for name, _ in first.categorical_features),
            EXPECTED_CATEGORICAL_NAMES,
        )
        vector_json = json.dumps(first.text_vector, separators=(",", ":"))
        self.assertEqual(
            hashlib.sha256(vector_json.encode("utf-8")).hexdigest(),
            EXPECTED_TEXT_VECTOR_DIGEST,
        )
        self.assertNotIn(observation.sanitized_body_text, repr(first))

        script = """
from datetime import datetime, timezone
import json
from shielddome_endpoint.domain import MailObservation
from shielddome_endpoint.feature_pipeline import FeaturePipeline
observation = MailObservation(
    source_kind="browser",
    source_message_id="synthetic-message-001",
    subject="Ab",
    sender="security@example.test",
    reply_to="security@example.test",
    recipient_summary=("current-user",),
    sanitized_body_text="中",
    authentication_observations=(("spf", "pass"), ("dkim", "pass"), ("dmarc", "pass")),
    normalized_links=(),
    attachment_metadata=(),
    language_hint="mixed",
    observed_at=datetime(2026, 7, 30, tzinfo=timezone.utc),
)
print(json.dumps(FeaturePipeline().transform(observation).text_vector, separators=(",", ":")))
"""
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(SOURCE_ROOT)
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=ENDPOINT_ROOT.parent,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), list(first.text_vector or ()))

    def test_training_and_endpoint_use_the_same_public_transform(self):
        from shielddome_endpoint import FeaturePipeline as PublicFeaturePipeline

        observation = make_observation(
            subject="Synthetic account notice",
            sanitized_body_text="Use the usual company channel.",
        )

        endpoint_vector = PublicFeaturePipeline().transform(observation)
        training_vectors = tuple(
            PublicFeaturePipeline().transform(item) for item in (observation,)
        )

        self.assertEqual(training_vectors[0], endpoint_vector)
        self.assertIsNone(endpoint_vector.text_input)

    def test_transform_extracts_structured_mail_features(self):
        observation = MailObservation(
            source_kind="browser",
            source_message_id="synthetic-message-002",
            subject="紧急 Invoice payment",
            sender="Security Team <alerts@corp.test>",
            reply_to="help@support.test",
            recipient_summary=("current-user",),
            sanitized_body_text=(
                "CEO 要求立即登录 verify password and wire payment."
            ),
            authentication_observations=(("spf", "pass"), ("dkim", "fail")),
            normalized_links=(
                "https://portal.corp.test/login",
                "http://192.0.2.10:8080/reset?token=fictional",
                "http://xn--fsqu00a.test:80/path",
                "https://例子.test/通知",
            ),
            attachment_metadata=(
                ("name", "invoice.pdf.exe"),
                ("declared_type", "application/pdf"),
                ("name", "notice.txt"),
            ),
            language_hint=None,
            observed_at=datetime(2026, 7, 30, tzinfo=timezone.utc),
        )

        vector = FeaturePipeline().transform(observation)
        numeric = dict(vector.numeric_features)
        categorical = dict(vector.categorical_features)

        self.assertEqual(numeric["subject_present"], 1.0)
        self.assertEqual(numeric["subject_length"], float(len(observation.subject)))
        self.assertEqual(numeric["body_present"], 1.0)
        self.assertEqual(
            numeric["body_length"],
            float(len(observation.sanitized_body_text)),
        )
        self.assertEqual(numeric["sender_present"], 1.0)
        self.assertEqual(numeric["sender_length"], float(len(observation.sender)))
        self.assertEqual(numeric["reply_to_present"], 1.0)
        self.assertEqual(
            numeric["reply_to_length"],
            float(len(observation.reply_to or "")),
        )
        self.assertEqual(numeric["sender_reply_domain_match"], 0.0)
        self.assertEqual(numeric["auth_spf_present"], 1.0)
        self.assertEqual(numeric["auth_dkim_present"], 1.0)
        self.assertEqual(numeric["auth_dmarc_present"], 0.0)
        self.assertEqual(numeric["url_count"], 4.0)
        self.assertEqual(numeric["https_url_count"], 2.0)
        self.assertEqual(numeric["ip_literal_url_count"], 1.0)
        self.assertEqual(numeric["suspicious_port_url_count"], 1.0)
        self.assertEqual(numeric["unique_domain_count"], 3.0)
        self.assertEqual(numeric["punycode_domain_count"], 1.0)
        self.assertEqual(numeric["unicode_domain_count"], 1.0)
        self.assertEqual(numeric["attachment_count"], 2.0)
        self.assertEqual(numeric["double_extension_count"], 1.0)
        self.assertEqual(numeric["dangerous_extension_count"], 1.0)
        self.assertEqual(numeric["intent_credential_count"], 2.0)
        self.assertEqual(numeric["intent_payment_count"], 4.0)
        self.assertEqual(numeric["intent_urgency_count"], 2.0)
        self.assertEqual(numeric["intent_impersonation_count"], 1.0)
        self.assertEqual(categorical["auth_spf_value"], "pass")
        self.assertEqual(categorical["auth_dkim_value"], "fail")
        self.assertEqual(categorical["auth_dmarc_value"], "missing")
        self.assertEqual(categorical["language"], "mixed")
        self.assertEqual(
            vector.missing_value_mask,
            ("auth_dmarc", "language_hint"),
        )
