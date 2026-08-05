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
        self.assertEqual(FEATURE_SCHEMA_VERSION, "2.0")
        self.assertEqual(vector.schema_version, "2.0")
        with self.assertRaises(FrozenInstanceError):
            vector.schema_version = "2.0"


class ModelAssessmentTests(unittest.TestCase):
    def test_model_assessment_has_public_fields_and_is_immutable(self):
        from shielddome_endpoint.domain import (
            FEATURE_SCHEMA_VERSION,
            MODEL_ASSESSMENT_SCHEMA_VERSION,
            ModelAssessment,
            ModelConfidenceState,
            ModelExecutionStatus,
        )

        assessment = ModelAssessment(
            probability=0.72,
            confidence_state=ModelConfidenceState.UNCERTAIN,
            execution_status=ModelExecutionStatus.SUCCESS,
            model_version="unified-0",
            feature_schema_version=FEATURE_SCHEMA_VERSION,
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
                "schema_version",
            ],
        )
        self.assertEqual(MODEL_ASSESSMENT_SCHEMA_VERSION, "1.0")
        self.assertEqual(assessment.feature_schema_version, "2.0")
        self.assertEqual(assessment.schema_version, "1.0")
        self.assertIsNone(assessment.error_code)
        with self.assertRaises(FrozenInstanceError):
            assessment.probability = 0.2


class DetectionOutcomeTests(unittest.TestCase):
    def test_detection_outcome_has_public_fields_version_and_is_immutable(self):
        from shielddome_endpoint.domain import (
            DETECTION_OUTCOME_SCHEMA_VERSION,
            DetectionExecutionState,
            DetectionOutcome,
            GenericAction,
            RiskLevel,
            StructuredPrivateEvidence,
        )

        private_evidence = StructuredPrivateEvidence(
            rule_evidence=(),
            rule_score=63,
            model_adjustment=0,
            risk_floor=0,
            model_execution_status=None,
            execution_state=DetectionExecutionState.RULES_ONLY,
            degraded=False,
            error_code=None,
            assessment_schema_version=None,
            model_version=None,
            feature_schema_version="2.0",
            detection_outcome_schema_version="3.0",
        )
        outcome = DetectionOutcome(
            local_event_id="event-001",
            final_risk_score=63,
            risk_level=RiskLevel.HIGH,
            generic_action=GenericAction.VERIFY_SENDER,
            execution_state=DetectionExecutionState.RULES_ONLY,
            structured_private_evidence=private_evidence,
            minimal_plugin_projection=(
                ("local_event_id", "event-001"),
                ("risk_level", "high"),
                ("execution_state", "rules_only"),
                ("generic_action", "verify_sender"),
            ),
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
        self.assertEqual(DETECTION_OUTCOME_SCHEMA_VERSION, "3.0")
        self.assertEqual(outcome.schema_version, "3.0")
        with self.assertRaises(FrozenInstanceError):
            outcome.risk_level = "low"


class RuleAssessmentTests(unittest.TestCase):
    def test_rule_assessment_has_minimal_non_sensitive_immutable_contract(self):
        from shielddome_endpoint.domain import (
            GenericAction,
            RuleAssessment,
            RuleCategory,
            RuleSeverity,
        )

        assessment = RuleAssessment(
            rule_id="authentication_failure",
            category=RuleCategory.AUTHENTICATION,
            severity=RuleSeverity.HIGH,
            score_contribution=45,
            strong_evidence=True,
            evidence_code="dmarc_deterministic_failure",
            generic_action=GenericAction.CONTACT_SECURITY,
        )

        self.assertEqual(
            [field.name for field in fields(RuleAssessment)],
            [
                "rule_id",
                "category",
                "severity",
                "score_contribution",
                "strong_evidence",
                "evidence_code",
                "generic_action",
            ],
        )
        with self.assertRaises(FrozenInstanceError):
            assessment.score_contribution = 0
