from datetime import datetime, timedelta
import re

from .domain import (
    DETECTION_OUTCOME_SCHEMA_VERSION,
    DetectionExecutionState,
    DetectionOutcome,
    FeatureVector,
    ModelExecutionStatus,
    PrivateRuleEvidence,
    RuleAssessment,
    StructuredPrivateEvidence,
)
from .inference import (
    InferenceContext,
    LocalInference,
    ValidatedModelAssessment,
    validate_model_assessment,
)
from .risk_fusion import RiskFusionResult, fuse_risk


EVIDENCE_RETENTION_DAYS = 15
_LOCAL_EVENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _minimal_plugin_projection(
    local_event_id: str,
    fusion: RiskFusionResult,
    execution_state: DetectionExecutionState,
) -> tuple[tuple[str, str], ...]:
    return (
        ("local_event_id", local_event_id),
        ("risk_level", fusion.risk_level.value),
        ("execution_state", execution_state.value),
        ("generic_action", fusion.generic_action.value),
    )


class DetectionKernel:
    def __init__(self, inference: LocalInference | None = None) -> None:
        self._inference = inference

    def detect(
        self,
        feature_vector: FeatureVector,
        rule_assessments: tuple[RuleAssessment, ...],
        *,
        local_event_id: str,
        detected_at: datetime,
        inference_context: InferenceContext,
    ) -> DetectionOutcome:
        if (
            not isinstance(local_event_id, str)
            or _LOCAL_EVENT_ID.fullmatch(local_event_id) is None
            or not isinstance(detected_at, datetime)
            or detected_at.tzinfo is None
            or detected_at.utcoffset() is None
        ):
            raise ValueError("invalid_detection_context")

        if self._inference is None:
            validated = ValidatedModelAssessment(
                assessment=None,
                execution_state=DetectionExecutionState.RULES_ONLY,
                degraded=False,
                error_code=None,
            )
        else:
            try:
                assessment = self._inference.infer(
                    feature_vector,
                    inference_context,
                )
            except Exception:
                validated = ValidatedModelAssessment(
                    assessment=None,
                    execution_state=DetectionExecutionState.MODEL_ERROR,
                    degraded=True,
                    error_code="model_adapter_exception",
                )
            else:
                validated = validate_model_assessment(
                    assessment,
                    expected_feature_schema_version=feature_vector.schema_version,
                    context=inference_context,
                )

        fusion = fuse_risk(
            rule_assessments,
            model_assessment=validated.assessment,
            execution_state=validated.execution_state,
        )
        assessment = validated.assessment
        fallback_model_status = {
            DetectionExecutionState.MODEL_UNAVAILABLE: ModelExecutionStatus.UNAVAILABLE,
            DetectionExecutionState.MODEL_TIMEOUT: ModelExecutionStatus.TIMEOUT,
            DetectionExecutionState.MODEL_ERROR: ModelExecutionStatus.ERROR,
        }.get(validated.execution_state)
        private_evidence = StructuredPrivateEvidence(
            rule_evidence=tuple(
                PrivateRuleEvidence(
                    evidence_code=rule.evidence_code,
                    category=rule.category,
                    status="active",
                    score_contribution=rule.score_contribution,
                    strong_evidence=rule.strong_evidence,
                )
                for rule in fusion.rule_assessments
            ),
            rule_score=fusion.rule_score,
            model_adjustment=fusion.model_adjustment,
            risk_floor=fusion.risk_floor,
            model_execution_status=(
                assessment.execution_status
                if assessment is not None
                else fallback_model_status
            ),
            execution_state=validated.execution_state,
            degraded=validated.degraded,
            error_code=validated.error_code,
            assessment_schema_version=(
                assessment.schema_version if assessment is not None else None
            ),
            model_version=(
                assessment.model_version if assessment is not None else None
            ),
            feature_schema_version=feature_vector.schema_version,
            detection_outcome_schema_version=DETECTION_OUTCOME_SCHEMA_VERSION,
        )
        return DetectionOutcome(
            local_event_id=local_event_id,
            final_risk_score=fusion.final_risk_score,
            risk_level=fusion.risk_level,
            generic_action=fusion.generic_action,
            execution_state=validated.execution_state,
            structured_private_evidence=private_evidence,
            minimal_plugin_projection=_minimal_plugin_projection(
                local_event_id,
                fusion,
                validated.execution_state,
            ),
            evidence_retention_until=detected_at
            + timedelta(days=EVIDENCE_RETENTION_DAYS),
        )


__all__ = ["DetectionKernel", "EVIDENCE_RETENTION_DAYS"]
