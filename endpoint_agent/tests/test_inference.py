from pathlib import Path
from dataclasses import replace
import math
import socket
import sys
import unittest
from unittest.mock import patch


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))

from shielddome_endpoint.domain import FEATURE_SCHEMA_VERSION, FeatureVector
from shielddome_endpoint.domain import (
    DetectionExecutionState,
    ModelAssessment,
    ModelConfidenceState,
)
from shielddome_endpoint.inference import (
    InferenceContext,
    LocalInference,
    ModelExecutionStatus,
    UnavailableModelAdapter,
    validate_model_assessment,
)


def make_feature_vector() -> FeatureVector:
    return FeatureVector(
        numeric_features=(("url_count", 1.0),),
        categorical_features=(("language", "mixed"),),
        text_input=None,
        text_vector=(0.0,) * 64,
        missing_value_mask=(),
        schema_version=FEATURE_SCHEMA_VERSION,
    )


def make_success_assessment(**changes) -> ModelAssessment:
    assessment = ModelAssessment(
        probability=0.72,
        confidence_state=ModelConfidenceState.CONFIDENT_PHISHING,
        execution_status=ModelExecutionStatus.SUCCESS,
        model_version="unified_release_2026_07",
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        duration_ms=18,
    )
    return replace(assessment, **changes)


class LocalInferenceTests(unittest.TestCase):
    def test_unavailable_adapter_returns_empty_stable_assessment_without_side_effects(self):
        adapter: LocalInference = UnavailableModelAdapter()
        context = InferenceContext(max_duration_ms=3_000)

        with (
            patch.object(Path, "open", side_effect=AssertionError("file_access")),
            patch.object(Path, "read_bytes", side_effect=AssertionError("file_access")),
            patch.object(Path, "write_bytes", side_effect=AssertionError("file_access")),
            patch.object(socket, "socket", side_effect=AssertionError("network_access")),
        ):
            assessment = adapter.infer(make_feature_vector(), context)

        self.assertIs(assessment.execution_status, ModelExecutionStatus.UNAVAILABLE)
        self.assertIsNone(assessment.probability)
        self.assertIsNone(assessment.confidence_state)
        self.assertIsNone(assessment.model_version)
        self.assertIsNone(assessment.feature_schema_version)
        self.assertEqual(assessment.duration_ms, 0)
        self.assertEqual(assessment.error_code, "model_not_configured")


class ModelAssessmentValidationTests(unittest.TestCase):
    def test_valid_success_assessment_is_accepted(self):
        assessment = make_success_assessment()

        validated = validate_model_assessment(
            assessment,
            expected_feature_schema_version=FEATURE_SCHEMA_VERSION,
            context=InferenceContext(max_duration_ms=3_000),
        )

        self.assertEqual(validated.assessment, assessment)
        self.assertIs(validated.execution_state, DetectionExecutionState.MODEL_SUCCESS)
        self.assertFalse(validated.degraded)
        self.assertIsNone(validated.error_code)

    def test_non_finite_and_out_of_range_probabilities_are_invalid(self):
        for probability in (
            math.nan,
            math.inf,
            -math.inf,
            -0.001,
            1.001,
        ):
            with self.subTest(probability=probability):
                validated = validate_model_assessment(
                    make_success_assessment(probability=probability),
                    expected_feature_schema_version=FEATURE_SCHEMA_VERSION,
                    context=InferenceContext(max_duration_ms=3_000),
                )

                self.assertIsNone(validated.assessment)
                self.assertIs(
                    validated.execution_state,
                    DetectionExecutionState.MODEL_INVALID_OUTPUT,
                )
                self.assertTrue(validated.degraded)
                self.assertEqual(validated.error_code, "invalid_model_assessment")

    def test_invalid_success_contract_is_rejected_without_echoing_values(self):
        invalid_assessments = (
            make_success_assessment(confidence_state="invented"),
            make_success_assessment(confidence_state="confident-phishing"),
            make_success_assessment(execution_status="invented"),
            make_success_assessment(execution_status="success"),
            make_success_assessment(feature_schema_version="future"),
            make_success_assessment(duration_ms=-1),
            make_success_assessment(duration_ms=True),
            make_success_assessment(duration_ms=1.5),
            make_success_assessment(duration_ms=60_001),
            make_success_assessment(model_version=None),
            make_success_assessment(model_version="C:\\Private\\model.onnx"),
            make_success_assessment(error_code="success_with_error"),
            make_success_assessment(schema_version="future"),
            ModelAssessment(
                probability=None,
                confidence_state=None,
                execution_status=ModelExecutionStatus.ERROR,
                model_version=None,
                feature_schema_version=None,
                duration_ms=1,
                error_code="C:\\Private\\error.txt",
            ),
        )

        for assessment in invalid_assessments:
            with self.subTest(assessment=assessment):
                validated = validate_model_assessment(
                    assessment,
                    expected_feature_schema_version=FEATURE_SCHEMA_VERSION,
                    context=InferenceContext(max_duration_ms=60_000),
                )

                self.assertIsNone(validated.assessment)
                self.assertIs(
                    validated.execution_state,
                    DetectionExecutionState.MODEL_INVALID_OUTPUT,
                )
                self.assertNotIn("Private", repr(validated))

    def test_failure_statuses_map_to_stable_degraded_execution_states(self):
        cases = (
            (
                ModelExecutionStatus.UNAVAILABLE,
                DetectionExecutionState.MODEL_UNAVAILABLE,
                "model_not_configured",
            ),
            (
                ModelExecutionStatus.TIMEOUT,
                DetectionExecutionState.MODEL_TIMEOUT,
                "runtime_timeout",
            ),
            (
                ModelExecutionStatus.ERROR,
                DetectionExecutionState.MODEL_ERROR,
                "runtime_error",
            ),
        )

        for status, expected_state, error_code in cases:
            with self.subTest(status=status):
                assessment = ModelAssessment(
                    probability=None,
                    confidence_state=None,
                    execution_status=status,
                    model_version=None,
                    feature_schema_version=None,
                    duration_ms=2,
                    error_code=error_code,
                )

                validated = validate_model_assessment(
                    assessment,
                    expected_feature_schema_version=FEATURE_SCHEMA_VERSION,
                    context=InferenceContext(max_duration_ms=3_000),
                )

                self.assertEqual(validated.assessment, assessment)
                self.assertIs(validated.execution_state, expected_state)
                self.assertTrue(validated.degraded)
                self.assertEqual(validated.error_code, error_code)

    def test_uncertain_success_maps_to_uncertain_execution_state(self):
        assessment = make_success_assessment(
            probability=0.5,
            confidence_state=ModelConfidenceState.UNCERTAIN,
        )

        validated = validate_model_assessment(
            assessment,
            expected_feature_schema_version=FEATURE_SCHEMA_VERSION,
            context=InferenceContext(max_duration_ms=3_000),
        )

        self.assertEqual(validated.assessment, assessment)
        self.assertIs(
            validated.execution_state,
            DetectionExecutionState.MODEL_UNCERTAIN,
        )
        self.assertFalse(validated.degraded)

    def test_failure_status_cannot_carry_success_payload(self):
        assessment = make_success_assessment(
            execution_status=ModelExecutionStatus.ERROR,
            error_code="runtime_error",
        )

        validated = validate_model_assessment(
            assessment,
            expected_feature_schema_version=FEATURE_SCHEMA_VERSION,
            context=InferenceContext(max_duration_ms=3_000),
        )

        self.assertIs(
            validated.execution_state,
            DetectionExecutionState.MODEL_INVALID_OUTPUT,
        )
        self.assertIsNone(validated.assessment)

    def test_assessment_over_invocation_budget_becomes_timeout(self):
        assessment = make_success_assessment(duration_ms=3_001)

        validated = validate_model_assessment(
            assessment,
            expected_feature_schema_version=FEATURE_SCHEMA_VERSION,
            context=InferenceContext(max_duration_ms=3_000),
        )

        self.assertIsNone(validated.assessment)
        self.assertIs(
            validated.execution_state,
            DetectionExecutionState.MODEL_TIMEOUT,
        )
        self.assertTrue(validated.degraded)
        self.assertEqual(validated.error_code, "inference_budget_exceeded")

    def test_inference_context_rejects_invalid_budgets(self):
        for budget in (True, 0, -1, 60_001, 1.5):
            with self.subTest(budget=budget):
                with self.assertRaisesRegex(
                    ValueError,
                    "^invalid_inference_context$",
                ):
                    InferenceContext(max_duration_ms=budget)


if __name__ == "__main__":
    unittest.main()
