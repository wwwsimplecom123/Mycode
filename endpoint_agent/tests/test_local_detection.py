from dataclasses import replace
from datetime import datetime, timezone
import inspect
from pathlib import Path
import sys
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))

from _detection_fakes import FakeModelAdapter
from shielddome_endpoint.domain import (
    DetectionExecutionState,
    MailObservation,
    RiskLevel,
)
from shielddome_endpoint.local_detection import LocalDetectionService


OBSERVED_NOW = datetime(2026, 7, 31, 8, 30, tzinfo=timezone.utc)


def make_observation(**changes) -> MailObservation:
    values = {
        "source_kind": "browser",
        "source_message_id": "synthetic-local-detection",
        "subject": "Routine notice",
        "sender": "sender@corp.test",
        "reply_to": "sender@corp.test",
        "recipient_summary": ("current-user",),
        "sanitized_body_text": "Use the normal company process.",
        "authentication_observations": (
            ("spf", "pass"),
            ("dkim", "pass"),
            ("dmarc", "pass"),
        ),
        "normalized_links": (),
        "attachment_metadata": (),
        "language_hint": "en",
        "observed_at": OBSERVED_NOW,
    }
    values.update(changes)
    return MailObservation(**values)


class LocalDetectionServiceTests(unittest.TestCase):
    def test_observation_is_transformed_and_rules_are_generated_locally(self):
        outcome = LocalDetectionService().detect(
            make_observation(reply_to="other@outside.test"),
            local_event_id="event-local-chain",
            observed_now=OBSERVED_NOW,
        )

        self.assertEqual(
            tuple(
                item.evidence_code
                for item in outcome.structured_private_evidence.rule_evidence
            ),
            ("sender_reply_domain_mismatch",),
        )
        self.assertEqual(outcome.final_risk_score, 12)

    def test_detect_interface_cannot_accept_client_risk_judgments(self):
        signature = inspect.signature(LocalDetectionService.detect)

        self.assertEqual(
            tuple(signature.parameters),
            ("self", "observation", "local_event_id", "observed_now"),
        )
        for forbidden_argument in (
            "rule_assessments",
            "score_contribution",
            "strong_evidence",
            "final_risk_score",
            "risk_level",
            "model_assessment",
            "execution_state",
            "generic_action",
            "retention_deadline",
            "user_role",
            "owner_id",
        ):
            with self.subTest(forbidden_argument=forbidden_argument):
                with self.assertRaises(TypeError):
                    LocalDetectionService().detect(
                        make_observation(),
                        local_event_id="event-trust-interface",
                        observed_now=OBSERVED_NOW,
                        **{forbidden_argument: "untrusted"},
                    )

    def test_default_unavailable_model_returns_complete_rule_result(self):
        outcome = LocalDetectionService().detect(
            make_observation(sanitized_body_text="password urgent"),
            local_event_id="event-rules-default",
            observed_now=OBSERVED_NOW,
        )

        self.assertIs(
            outcome.execution_state,
            DetectionExecutionState.MODEL_UNAVAILABLE,
        )
        self.assertEqual(outcome.final_risk_score, 22)
        self.assertIs(outcome.risk_level, RiskLevel.LOW)
        self.assertTrue(outcome.structured_private_evidence.degraded)
        self.assertEqual(
            outcome.structured_private_evidence.error_code,
            "model_not_configured",
        )

    def test_strong_local_rule_establishes_risk_floor_without_model(self):
        outcome = LocalDetectionService().detect(
            make_observation(
                attachment_metadata=(("name", "synthetic.pdf.exe"),),
            ),
            local_event_id="event-strong-floor",
            observed_now=OBSERVED_NOW,
        )

        self.assertEqual(outcome.final_risk_score, 70)
        self.assertIs(outcome.risk_level, RiskLevel.HIGH)
        self.assertTrue(
            outcome.structured_private_evidence.rule_evidence[0].strong_evidence
        )

    def test_adapter_exception_preserves_local_rules(self):
        service = LocalDetectionService(
            FakeModelAdapter(error=RuntimeError("private body token=fictional"))
        )

        outcome = service.detect(
            make_observation(reply_to="other@outside.test"),
            local_event_id="event-adapter-exception",
            observed_now=OBSERVED_NOW,
        )

        self.assertEqual(outcome.final_risk_score, 12)
        self.assertIs(outcome.execution_state, DetectionExecutionState.MODEL_ERROR)
        self.assertEqual(
            outcome.structured_private_evidence.error_code,
            "model_adapter_exception",
        )
        self.assertNotIn("private body", repr(outcome))

    def test_same_observation_identity_and_time_produce_same_outcome(self):
        service = LocalDetectionService()
        observation = make_observation(
            normalized_links=("http://192.0.2.10/login",),
            sanitized_body_text="Verify password",
        )

        first = service.detect(
            observation,
            local_event_id="event-deterministic-local",
            observed_now=OBSERVED_NOW,
        )
        second = service.detect(
            observation,
            local_event_id="event-deterministic-local",
            observed_now=OBSERVED_NOW,
        )

        self.assertEqual(first, second)

    def test_invalid_observation_contract_is_rejected_before_detection(self):
        cases = (
            replace(make_observation(), schema_version="future"),
            replace(
                make_observation(),
                observed_at=datetime(2026, 7, 31, 8, 30),
            ),
            "not-an-observation",
        )

        for observation in cases:
            with self.subTest(observation=observation):
                with self.assertRaisesRegex(
                    ValueError,
                    "^invalid_mail_observation$",
                ):
                    LocalDetectionService().detect(
                        observation,
                        local_event_id="event-invalid-observation",
                        observed_now=OBSERVED_NOW,
                    )


if __name__ == "__main__":
    unittest.main()
