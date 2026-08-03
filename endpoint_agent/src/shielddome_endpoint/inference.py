from dataclasses import dataclass
import math
import re
from typing import Protocol

from .domain import (
    DetectionExecutionState,
    FEATURE_SCHEMA_VERSION,
    FeatureVector,
    MODEL_ASSESSMENT_SCHEMA_VERSION,
    ModelAssessment,
    ModelConfidenceState,
    ModelExecutionStatus,
)


MAX_INFERENCE_DURATION_MS = 60_000
_SAFE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SAFE_MODEL_VERSION = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


@dataclass(frozen=True, slots=True)
class InferenceContext:
    max_duration_ms: int

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_duration_ms, bool)
            or not isinstance(self.max_duration_ms, int)
            or not 1 <= self.max_duration_ms <= MAX_INFERENCE_DURATION_MS
        ):
            raise ValueError("invalid_inference_context")


class LocalInference(Protocol):
    def infer(
        self,
        feature_vector: FeatureVector,
        context: InferenceContext,
    ) -> ModelAssessment: ...


@dataclass(frozen=True, slots=True)
class ValidatedModelAssessment:
    assessment: ModelAssessment | None
    execution_state: DetectionExecutionState
    degraded: bool
    error_code: str | None


def validate_model_assessment(
    assessment: ModelAssessment,
    *,
    expected_feature_schema_version: str,
    context: InferenceContext,
) -> ValidatedModelAssessment:
    invalid = ValidatedModelAssessment(
        assessment=None,
        execution_state=DetectionExecutionState.MODEL_INVALID_OUTPUT,
        degraded=True,
        error_code="invalid_model_assessment",
    )
    if not isinstance(assessment, ModelAssessment):
        return invalid
    if (
        assessment.schema_version != MODEL_ASSESSMENT_SCHEMA_VERSION
        or expected_feature_schema_version != FEATURE_SCHEMA_VERSION
        or not isinstance(assessment.execution_status, ModelExecutionStatus)
        or isinstance(assessment.duration_ms, bool)
        or not isinstance(assessment.duration_ms, int)
        or not 0 <= assessment.duration_ms <= MAX_INFERENCE_DURATION_MS
        or (
            assessment.error_code is not None
            and (
                not isinstance(assessment.error_code, str)
                or _SAFE_CODE.fullmatch(assessment.error_code) is None
            )
        )
    ):
        return invalid

    allowed_statuses = {
        ModelExecutionStatus.SUCCESS,
        ModelExecutionStatus.UNAVAILABLE,
        ModelExecutionStatus.TIMEOUT,
        ModelExecutionStatus.ERROR,
    }
    if assessment.execution_status not in allowed_statuses:
        return invalid

    if assessment.execution_status is ModelExecutionStatus.SUCCESS:
        if (
            not isinstance(assessment.confidence_state, ModelConfidenceState)
            or assessment.confidence_state
            not in {
                ModelConfidenceState.CONFIDENT_BENIGN,
                ModelConfidenceState.UNCERTAIN,
                ModelConfidenceState.CONFIDENT_PHISHING,
            }
            or isinstance(assessment.probability, bool)
            or not isinstance(assessment.probability, (int, float))
            or not math.isfinite(assessment.probability)
            or not 0.0 <= assessment.probability <= 1.0
            or not isinstance(assessment.model_version, str)
            or _SAFE_MODEL_VERSION.fullmatch(assessment.model_version) is None
            or assessment.feature_schema_version
            != expected_feature_schema_version
            or assessment.error_code is not None
        ):
            return invalid
    elif (
        assessment.probability is not None
        or assessment.confidence_state is not None
        or assessment.model_version is not None
        or assessment.feature_schema_version is not None
    ):
        return invalid

    if assessment.duration_ms > context.max_duration_ms:
        return ValidatedModelAssessment(
            assessment=None,
            execution_state=DetectionExecutionState.MODEL_TIMEOUT,
            degraded=True,
            error_code="inference_budget_exceeded",
        )

    if assessment.execution_status is ModelExecutionStatus.SUCCESS:
        state = (
            DetectionExecutionState.MODEL_UNCERTAIN
            if assessment.confidence_state is ModelConfidenceState.UNCERTAIN
            else DetectionExecutionState.MODEL_SUCCESS
        )
        return ValidatedModelAssessment(
            assessment=assessment,
            execution_state=state,
            degraded=False,
            error_code=None,
        )

    failure_states = {
        ModelExecutionStatus.UNAVAILABLE: DetectionExecutionState.MODEL_UNAVAILABLE,
        ModelExecutionStatus.TIMEOUT: DetectionExecutionState.MODEL_TIMEOUT,
        ModelExecutionStatus.ERROR: DetectionExecutionState.MODEL_ERROR,
    }
    return ValidatedModelAssessment(
        assessment=assessment,
        execution_state=failure_states[assessment.execution_status],
        degraded=True,
        error_code=assessment.error_code,
    )


class UnavailableModelAdapter:
    def infer(
        self,
        feature_vector: FeatureVector,
        context: InferenceContext,
    ) -> ModelAssessment:
        return ModelAssessment(
            probability=None,
            confidence_state=None,
            execution_status=ModelExecutionStatus.UNAVAILABLE,
            model_version=None,
            feature_schema_version=None,
            duration_ms=0,
            error_code="model_not_configured",
        )


__all__ = [
    "InferenceContext",
    "LocalInference",
    "MAX_INFERENCE_DURATION_MS",
    "ModelConfidenceState",
    "ModelExecutionStatus",
    "UnavailableModelAdapter",
    "ValidatedModelAssessment",
    "validate_model_assessment",
]
