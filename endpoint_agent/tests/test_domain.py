from dataclasses import FrozenInstanceError, fields
from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))


class MailObservationTests(unittest.TestCase):
    def test_mail_observation_has_public_fields_version_and_is_immutable(self):
        from shielddome_endpoint.domain import (
            MAIL_OBSERVATION_SCHEMA_VERSION,
            MailObservation,
        )

        observation = MailObservation(
            source_kind="browser",
            source_message_id="message-001",
            subject="Account notice",
            sender="security@example.test",
            reply_to=None,
            recipient_summary=("current-user",),
            sanitized_body_text="Verify the account through the usual channel.",
            authentication_observations=(("spf", "pass"),),
            normalized_links=("https://example.test/notice",),
            attachment_metadata=(("name", "notice.pdf"),),
            language_hint="en",
            observed_at=datetime(2026, 7, 29, tzinfo=timezone.utc),
        )

        self.assertEqual(
            [field.name for field in fields(MailObservation)],
            [
                "source_kind",
                "source_message_id",
                "subject",
                "sender",
                "reply_to",
                "recipient_summary",
                "sanitized_body_text",
                "authentication_observations",
                "normalized_links",
                "attachment_metadata",
                "language_hint",
                "observed_at",
                "schema_version",
            ],
        )
        self.assertEqual(MAIL_OBSERVATION_SCHEMA_VERSION, "1.0")
        self.assertEqual(observation.schema_version, "1.0")
        with self.assertRaises(FrozenInstanceError):
            observation.subject = "Changed"


class FeatureVectorTests(unittest.TestCase):
    def test_feature_vector_has_public_fields_version_and_is_immutable(self):
        from shielddome_endpoint.domain import FEATURE_SCHEMA_VERSION, FeatureVector

        vector = FeatureVector(
            numeric_features=(("url_count", 2.0),),
            categorical_features=(("language", "mixed"),),
            text_input="sanitized account notice",
            text_vector=(0.25, -0.5),
            missing_value_mask=("dkim",),
        )

        self.assertEqual(
            [field.name for field in fields(FeatureVector)],
            [
                "numeric_features",
                "categorical_features",
                "text_input",
                "text_vector",
                "missing_value_mask",
                "schema_version",
            ],
        )
        self.assertEqual(FEATURE_SCHEMA_VERSION, "1.0")
        self.assertEqual(vector.schema_version, "1.0")
        with self.assertRaises(FrozenInstanceError):
            vector.schema_version = "2.0"


class ModelAssessmentTests(unittest.TestCase):
    def test_model_assessment_has_public_fields_and_is_immutable(self):
        from shielddome_endpoint.domain import ModelAssessment

        assessment = ModelAssessment(
            probability=0.72,
            confidence_state="uncertain",
            execution_status="completed",
            model_version="unified-0",
            feature_schema_version="1.0",
            duration_ms=18,
        )

        self.assertEqual(
            [field.name for field in fields(ModelAssessment)],
            [
                "probability",
                "confidence_state",
                "execution_status",
                "model_version",
                "feature_schema_version",
                "duration_ms",
                "error_code",
            ],
        )
        self.assertEqual(assessment.feature_schema_version, "1.0")
        self.assertIsNone(assessment.error_code)
        with self.assertRaises(FrozenInstanceError):
            assessment.probability = 0.2


class DetectionOutcomeTests(unittest.TestCase):
    def test_detection_outcome_has_public_fields_version_and_is_immutable(self):
        from shielddome_endpoint.domain import (
            DETECTION_OUTCOME_SCHEMA_VERSION,
            DetectionOutcome,
        )

        outcome = DetectionOutcome(
            local_event_id="event-001",
            final_risk_score=63,
            risk_level="high",
            generic_action="verify sender",
            execution_state="complete",
            structured_private_evidence=(("rule_id", "sender_mismatch"),),
            minimal_plugin_projection=(("risk_level", "high"),),
            evidence_retention_until=datetime(2026, 8, 13, tzinfo=timezone.utc),
        )

        self.assertEqual(
            [field.name for field in fields(DetectionOutcome)],
            [
                "local_event_id",
                "final_risk_score",
                "risk_level",
                "generic_action",
                "execution_state",
                "structured_private_evidence",
                "minimal_plugin_projection",
                "evidence_retention_until",
                "schema_version",
            ],
        )
        self.assertEqual(DETECTION_OUTCOME_SCHEMA_VERSION, "1.0")
        self.assertEqual(outcome.schema_version, "1.0")
        with self.assertRaises(FrozenInstanceError):
            outcome.risk_level = "low"
