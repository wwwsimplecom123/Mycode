from dataclasses import replace
from dataclasses import fields
from datetime import datetime, timedelta, timezone
import math
from pathlib import Path
import sys
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))

from _detection_fakes import FakeModelAdapter
from test_inference import make_feature_vector, make_success_assessment
from test_risk_fusion import make_rule

from shielddome_endpoint.detection_kernel import DetectionKernel
from shielddome_endpoint.domain import (
    DETECTION_OUTCOME_SCHEMA_VERSION,
    DetectionExecutionState,
    DetectionOutcome,
    ModelAssessment,
    ModelConfidenceState,
    ModelExecutionStatus,
    RiskLevel,
)
from shielddome_endpoint.inference import InferenceContext
from shielddome_endpoint.inference import UnavailableModelAdapter
from shielddome_endpoint.privacy import PrivacyScanner
from shielddome_endpoint.example_calibration import (
    ExampleCalibration,
    ExampleCalibrationStatus,
)


DETECTED_AT = datetime(2026, 7, 30, 9, 15, tzinfo=timezone.utc)


class DetectionKernelTests(unittest.TestCase):
    def test_applied_example_calibration_is_private_and_plugin_projection_stays_minimal(self):
        calibration = ExampleCalibration(
            status=ExampleCalibrationStatus.EXACT_APPLIED,
            adjustment=18,
            supporting_examples=1,
        )

        outcome = DetectionKernel().detect(
            make_feature_vector(),
            (make_rule(score_contribution=20),),
            local_event_id="event-calibration",
            detected_at=DETECTED_AT,
            inference_context=InferenceContext(3_000),
            example_calibration=calibration,
        )

        self.assertEqual(outcome.final_risk_score, 38)
        self.assertEqual(
            outcome.structured_private_evidence.example_adjustment,
            18,
        )
        self.assertEqual(
            outcome.structured_private_evidence.example_calibration_status,
            "exact_applied",
        )
        self.assertEqual(
            outcome.structured_private_evidence.example_supporting_count,
            1,
        )
        self.assertEqual(outcome.schema_version, "3.0")
        self.assertEqual(
            tuple(name for name, _ in outcome.minimal_plugin_projection),
            (
                "local_event_id",
                "risk_level",
                "execution_state",
                "generic_action",
            ),
        )
        serialized_projection = repr(outcome.minimal_plugin_projection)
        for forbidden in (
            "example_adjustment",
            "similarity",
            "fingerprint",
            "supporting_count",
        ):
            self.assertNotIn(forbidden, serialized_projection)

    def test_success_returns_deterministic_outcome_with_injected_identity_and_time(self):
        adapter = FakeModelAdapter(make_success_assessment())
        kernel = DetectionKernel(adapter)
        vector = make_feature_vector()
        rules = (make_rule(score_contribution=20),)
        context = InferenceContext(max_duration_ms=3_000)

        first = kernel.detect(
            vector,
            rules,
            local_event_id="event-20260730-001",
            detected_at=DETECTED_AT,
            inference_context=context,
        )
        second = kernel.detect(
            vector,
            rules,
            local_event_id="event-20260730-001",
            detected_at=DETECTED_AT,
            inference_context=context,
        )

        self.assertIsInstance(first, DetectionOutcome)
        self.assertEqual(first, second)
        self.assertEqual(first.local_event_id, "event-20260730-001")
        self.assertEqual(
            first.evidence_retention_until,
            DETECTED_AT + timedelta(days=15),
        )
        self.assertIs(first.execution_state, DetectionExecutionState.MODEL_SUCCESS)
        self.assertIs(first.risk_level, RiskLevel.MEDIUM)
        self.assertEqual(first.schema_version, DETECTION_OUTCOME_SCHEMA_VERSION)
        self.assertEqual(adapter.calls, [(vector, context), (vector, context)])

    def test_uncertain_and_explicit_rules_only_states_are_distinct(self):
        uncertain_assessment = replace(
            make_success_assessment(),
            probability=0.5,
            confidence_state=ModelConfidenceState.UNCERTAIN,
        )
        uncertain = DetectionKernel(
            FakeModelAdapter(uncertain_assessment)
        ).detect(
            make_feature_vector(),
            (make_rule(score_contribution=30),),
            local_event_id="event-uncertain",
            detected_at=DETECTED_AT,
            inference_context=InferenceContext(3_000),
        )
        rules_only = DetectionKernel().detect(
            make_feature_vector(),
            (make_rule(score_contribution=30),),
            local_event_id="event-rules-only",
            detected_at=DETECTED_AT,
            inference_context=InferenceContext(3_000),
        )

        self.assertIs(
            uncertain.execution_state,
            DetectionExecutionState.MODEL_UNCERTAIN,
        )
        self.assertEqual(uncertain.final_risk_score, 30)
        self.assertFalse(uncertain.structured_private_evidence.degraded)
        self.assertIs(
            rules_only.execution_state,
            DetectionExecutionState.RULES_ONLY,
        )
        self.assertEqual(rules_only.final_risk_score, 30)
        self.assertFalse(rules_only.structured_private_evidence.degraded)

    def test_returned_model_failures_degrade_to_same_rule_result(self):
        cases = (
            (
                UnavailableModelAdapter(),
                DetectionExecutionState.MODEL_UNAVAILABLE,
                ModelExecutionStatus.UNAVAILABLE,
            ),
            (
                FakeModelAdapter(
                    ModelAssessment(
                        probability=None,
                        confidence_state=None,
                        execution_status=ModelExecutionStatus.TIMEOUT,
                        model_version=None,
                        feature_schema_version=None,
                        duration_ms=3_000,
                        error_code="runtime_timeout",
                    )
                ),
                DetectionExecutionState.MODEL_TIMEOUT,
                ModelExecutionStatus.TIMEOUT,
            ),
            (
                FakeModelAdapter(
                    ModelAssessment(
                        probability=None,
                        confidence_state=None,
                        execution_status=ModelExecutionStatus.ERROR,
                        model_version=None,
                        feature_schema_version=None,
                        duration_ms=10,
                        error_code="runtime_error",
                    )
                ),
                DetectionExecutionState.MODEL_ERROR,
                ModelExecutionStatus.ERROR,
            ),
        )

        for adapter, expected_state, expected_model_status in cases:
            with self.subTest(expected_state=expected_state):
                outcome = DetectionKernel(adapter).detect(
                    make_feature_vector(),
                    (make_rule(score_contribution=35),),
                    local_event_id=f"event-{expected_state.value}",
                    detected_at=DETECTED_AT,
                    inference_context=InferenceContext(3_000),
                )

                self.assertEqual(outcome.final_risk_score, 35)
                self.assertIs(outcome.execution_state, expected_state)
                self.assertTrue(outcome.structured_private_evidence.degraded)
                self.assertIs(
                    outcome.structured_private_evidence.model_execution_status,
                    expected_model_status,
                )

    def test_invalid_and_over_budget_outputs_degrade_without_model_evidence(self):
        cases = (
            (
                replace(make_success_assessment(), probability=math.nan),
                DetectionExecutionState.MODEL_INVALID_OUTPUT,
            ),
            (
                replace(make_success_assessment(), duration_ms=3_001),
                DetectionExecutionState.MODEL_TIMEOUT,
            ),
            (
                replace(
                    make_success_assessment(),
                    feature_schema_version="future",
                ),
                DetectionExecutionState.MODEL_INVALID_OUTPUT,
            ),
        )

        for assessment, expected_state in cases:
            with self.subTest(expected_state=expected_state):
                outcome = DetectionKernel(
                    FakeModelAdapter(assessment)
                ).detect(
                    make_feature_vector(),
                    (make_rule(score_contribution=25),),
                    local_event_id=f"event-{expected_state.value}",
                    detected_at=DETECTED_AT,
                    inference_context=InferenceContext(3_000),
                )

                self.assertEqual(outcome.final_risk_score, 25)
                self.assertIs(outcome.execution_state, expected_state)
                self.assertTrue(outcome.structured_private_evidence.degraded)
                self.assertEqual(
                    outcome.structured_private_evidence.model_adjustment,
                    0,
                )

    def test_adapter_exception_is_sanitized_and_does_not_block_rules(self):
        private_message = (
            "C:\\Users\\Private\\model.onnx token=fictional private body"
        )

        outcome = DetectionKernel(
            FakeModelAdapter(error=RuntimeError(private_message))
        ).detect(
            make_feature_vector(),
            (make_rule(score_contribution=40),),
            local_event_id="event-adapter-error",
            detected_at=DETECTED_AT,
            inference_context=InferenceContext(3_000),
        )

        self.assertEqual(outcome.final_risk_score, 40)
        self.assertIs(
            outcome.execution_state,
            DetectionExecutionState.MODEL_ERROR,
        )
        self.assertEqual(
            outcome.structured_private_evidence.error_code,
            "model_adapter_exception",
        )
        self.assertIs(
            outcome.structured_private_evidence.model_execution_status,
            ModelExecutionStatus.ERROR,
        )
        self.assertNotIn(private_message, repr(outcome))

    def test_invalid_detection_context_fails_with_stable_code(self):
        invalid_contexts = (
            ("C:\\Users\\Private\\event", DETECTED_AT),
            ("event-naive-time", datetime(2026, 7, 30, 9, 15)),
        )

        for local_event_id, detected_at in invalid_contexts:
            with self.subTest(local_event_id=local_event_id):
                with self.assertRaisesRegex(
                    ValueError,
                    "^invalid_detection_context$",
                ):
                    DetectionKernel().detect(
                        make_feature_vector(),
                        (),
                        local_event_id=local_event_id,
                        detected_at=detected_at,
                        inference_context=InferenceContext(3_000),
                    )

    def test_minimal_plugin_projection_has_exact_allowed_fields_only(self):
        outcome = DetectionKernel(
            FakeModelAdapter(make_success_assessment(probability=0.91))
        ).detect(
            make_feature_vector(),
            (make_rule(score_contribution=30),),
            local_event_id="event-plugin-projection",
            detected_at=DETECTED_AT,
            inference_context=InferenceContext(3_000),
        )

        self.assertEqual(
            tuple(name for name, _ in outcome.minimal_plugin_projection),
            (
                "local_event_id",
                "risk_level",
                "execution_state",
                "generic_action",
            ),
        )
        self.assertEqual(
            dict(outcome.minimal_plugin_projection),
            {
                "local_event_id": "event-plugin-projection",
                "risk_level": outcome.risk_level.value,
                "execution_state": outcome.execution_state.value,
                "generic_action": outcome.generic_action.value,
            },
        )
        serialized_projection = repr(outcome.minimal_plugin_projection)
        for forbidden in (
            "unified_release_test",
            "0.91",
            "sender_mismatch",
            "sender_domain_mismatch",
            "30",
            "rule_score",
            "model_adjustment",
            "similar",
            "body",
            "url",
            "private.user@example.test",
        ):
            self.assertNotIn(forbidden, serialized_projection.casefold())

    def test_private_evidence_has_exact_safe_summary_and_no_source_content(self):
        private_values = (
            "private body text",
            "private.user@example.test",
            "https://portal.example.test/login?token=fictional",
            "token=fictional",
            "password=fictional",
            "C:\\Users\\Private\\model.onnx",
        )
        vector = replace(
            make_feature_vector(),
            text_input=" ".join(private_values),
        )

        outcome = DetectionKernel(
            FakeModelAdapter(make_success_assessment())
        ).detect(
            vector,
            (make_rule(score_contribution=20),),
            local_event_id="event-private-evidence",
            detected_at=DETECTED_AT,
            inference_context=InferenceContext(3_000),
        )
        evidence = outcome.structured_private_evidence
        scan = PrivacyScanner().scan_detection_outcome(
            outcome,
            forbidden_values=private_values,
        )

        self.assertEqual(
            tuple(field.name for field in fields(type(evidence))),
            (
                "rule_evidence",
                "rule_score",
                "model_adjustment",
                "risk_floor",
                "model_execution_status",
                "execution_state",
                "degraded",
                "error_code",
                "assessment_schema_version",
                "model_version",
                "feature_schema_version",
                "detection_outcome_schema_version",
                "example_adjustment",
                "example_calibration_status",
                "example_supporting_count",
            ),
        )
        self.assertEqual(
            tuple(field.name for field in fields(type(evidence.rule_evidence[0]))),
            (
                "evidence_code",
                "category",
                "status",
                "score_contribution",
                "strong_evidence",
            ),
        )
        self.assertEqual(evidence.rule_evidence[0].evidence_code, "sender_domain_mismatch")
        self.assertEqual(evidence.rule_score, 20)
        self.assertEqual(evidence.feature_schema_version, "2.0")
        self.assertEqual(evidence.detection_outcome_schema_version, "3.0")
        self.assertTrue(scan.safe)
        self.assertEqual(scan.violations, ())
        for private_value in private_values:
            self.assertNotIn(private_value, repr(outcome))


if __name__ == "__main__":
    unittest.main()
