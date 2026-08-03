from dataclasses import dataclass

from .domain import (
    DetectionExecutionState,
    GenericAction,
    ModelAssessment,
    ModelConfidenceState,
    ModelExecutionStatus,
    RuleAssessment,
    RuleSeverity,
    RiskLevel,
)


@dataclass(frozen=True, slots=True)
class RiskFusionResult:
    final_risk_score: int
    risk_level: RiskLevel
    generic_action: GenericAction
    rule_score: int
    model_adjustment: int
    risk_floor: int
    has_strong_evidence: bool
    rule_assessments: tuple[RuleAssessment, ...]


def _risk_level(score: int) -> RiskLevel:
    if score >= 80:
        return RiskLevel.CRITICAL
    if score >= 50:
        return RiskLevel.HIGH
    if score >= 25:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


_ACTION_PRIORITY = {
    GenericAction.CONTINUE: 0,
    GenericAction.VERIFY_SENDER: 1,
    GenericAction.AVOID_CREDENTIALS: 2,
    GenericAction.CONTACT_SECURITY: 3,
}
_SEVERITY_PRIORITY = {
    RuleSeverity.LOW: 0,
    RuleSeverity.MEDIUM: 1,
    RuleSeverity.HIGH: 2,
    RuleSeverity.CRITICAL: 3,
}
_STRONG_RISK_FLOORS = {
    RuleSeverity.LOW: 20,
    RuleSeverity.MEDIUM: 40,
    RuleSeverity.HIGH: 70,
    RuleSeverity.CRITICAL: 90,
}


def _deduplicate_rules(
    rule_assessments: tuple[RuleAssessment, ...],
) -> tuple[RuleAssessment, ...]:
    selected: dict[str, RuleAssessment] = {}
    for assessment in rule_assessments:
        current = selected.get(assessment.rule_id)
        selection_key = (
            assessment.strong_evidence,
            _SEVERITY_PRIORITY[assessment.severity],
            assessment.score_contribution,
            _ACTION_PRIORITY[assessment.generic_action],
            assessment.category.value,
            assessment.evidence_code,
        )
        if current is None or selection_key > (
            current.strong_evidence,
            _SEVERITY_PRIORITY[current.severity],
            current.score_contribution,
            _ACTION_PRIORITY[current.generic_action],
            current.category.value,
            current.evidence_code,
        ):
            selected[assessment.rule_id] = assessment
    return tuple(selected[rule_id] for rule_id in sorted(selected))


def fuse_risk(
    rule_assessments: tuple[RuleAssessment, ...],
    *,
    model_assessment: ModelAssessment | None,
    execution_state: DetectionExecutionState,
) -> RiskFusionResult:
    ordered_rules = _deduplicate_rules(rule_assessments)
    rule_score = min(100, sum(item.score_contribution for item in ordered_rules))
    strong_rules = tuple(item for item in ordered_rules if item.strong_evidence)
    risk_floor = max(
        (_STRONG_RISK_FLOORS[item.severity] for item in strong_rules),
        default=0,
    )
    model_adjustment = 0
    if (
        execution_state is DetectionExecutionState.MODEL_SUCCESS
        and model_assessment is not None
        and model_assessment.execution_status is ModelExecutionStatus.SUCCESS
    ):
        if (
            model_assessment.confidence_state
            is ModelConfidenceState.CONFIDENT_PHISHING
        ):
            model_adjustment = min(
                25,
                int(round(float(model_assessment.probability or 0.0) * 25)),
            )
        elif (
            model_assessment.confidence_state
            is ModelConfidenceState.CONFIDENT_BENIGN
        ):
            model_adjustment = -5

    adjusted_score = max(0, min(100, rule_score + model_adjustment))
    if model_adjustment > 0 and rule_score < 80 and adjusted_score >= 80:
        adjusted_score = 79
    final_score = max(adjusted_score, risk_floor)
    action = max(
        (item.generic_action for item in ordered_rules),
        key=lambda item: _ACTION_PRIORITY[item],
        default=GenericAction.CONTINUE,
    )
    if (
        model_adjustment > 0
        or execution_state is DetectionExecutionState.MODEL_UNCERTAIN
    ) and action is GenericAction.CONTINUE:
        action = GenericAction.VERIFY_SENDER
    return RiskFusionResult(
        final_risk_score=final_score,
        risk_level=_risk_level(final_score),
        generic_action=action,
        rule_score=rule_score,
        model_adjustment=model_adjustment,
        risk_floor=risk_floor,
        has_strong_evidence=bool(strong_rules),
        rule_assessments=ordered_rules,
    )
