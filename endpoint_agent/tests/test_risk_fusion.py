from pathlib import Path
import sys
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))

from shielddome_endpoint.domain import (
    DetectionExecutionState,
    FEATURE_SCHEMA_VERSION,
    GenericAction,
    ModelAssessment,
    ModelConfidenceState,
    ModelExecutionStatus,
    RuleAssessment,
    RuleCategory,
    RuleSeverity,
    RiskLevel,
)
from shielddome_endpoint.risk_fusion import fuse_risk


def make_rule(
    rule_id: str = "sender_mismatch",
    *,
    category: RuleCategory = RuleCategory.SENDER,
    severity: RuleSeverity = RuleSeverity.LOW,
    score_contribution: int = 15,
    strong_evidence: bool = False,
    evidence_code: str = "sender_domain_mismatch",
    generic_action: GenericAction = GenericAction.VERIFY_SENDER,
) -> RuleAssessment:
    return RuleAssessment(
        rule_id=rule_id,
        category=category,
        severity=severity,
        score_contribution=score_contribution,
        strong_evidence=strong_evidence,
        evidence_code=evidence_code,
        generic_action=generic_action,
    )


def make_model_assessment(
    probability: float,
    confidence_state: ModelConfidenceState,
) -> ModelAssessment:
    return ModelAssessment(
        probability=probability,
        confidence_state=confidence_state,
        execution_status=ModelExecutionStatus.SUCCESS,
        model_version="unified_release_test",
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        duration_ms=10,
    )


class PureRuleRiskFusionTests(unittest.TestCase):
    def test_no_evidence_in_rules_only_mode_is_deterministic_low_risk(self):
        first = fuse_risk(
            (),
            model_assessment=None,
            execution_state=DetectionExecutionState.RULES_ONLY,
        )
        second = fuse_risk(
            (),
            model_assessment=None,
            execution_state=DetectionExecutionState.RULES_ONLY,
        )

        self.assertEqual(first, second)
        self.assertEqual(first.final_risk_score, 0)
        self.assertIs(first.risk_level, RiskLevel.LOW)
        self.assertIs(first.generic_action, GenericAction.CONTINUE)
        self.assertEqual(first.rule_score, 0)
        self.assertEqual(first.model_adjustment, 0)
        self.assertEqual(first.risk_floor, 0)
        self.assertFalse(first.has_strong_evidence)
        self.assertEqual(first.rule_assessments, ())

    def test_one_weak_rule_contributes_score_and_action(self):
        rule = make_rule()

        result = fuse_risk(
            (rule,),
            model_assessment=None,
            execution_state=DetectionExecutionState.RULES_ONLY,
        )

        self.assertEqual(result.final_risk_score, 15)
        self.assertIs(result.risk_level, RiskLevel.LOW)
        self.assertIs(result.generic_action, GenericAction.VERIFY_SENDER)
        self.assertEqual(result.rule_score, 15)
        self.assertEqual(result.rule_assessments, (rule,))

    def test_multiple_rules_accumulate_and_score_is_clamped(self):
        rules = (
            make_rule("weak_one", score_contribution=20),
            make_rule(
                "weak_two",
                category=RuleCategory.INTENT,
                severity=RuleSeverity.MEDIUM,
                score_contribution=35,
                evidence_code="credential_request",
                generic_action=GenericAction.AVOID_CREDENTIALS,
            ),
            make_rule(
                "weak_three",
                category=RuleCategory.ATTACHMENT,
                severity=RuleSeverity.HIGH,
                score_contribution=80,
                evidence_code="dangerous_extension",
                generic_action=GenericAction.CONTACT_SECURITY,
            ),
        )

        result = fuse_risk(
            rules,
            model_assessment=None,
            execution_state=DetectionExecutionState.RULES_ONLY,
        )

        self.assertEqual(result.rule_score, 100)
        self.assertEqual(result.final_risk_score, 100)
        self.assertIs(result.risk_level, RiskLevel.CRITICAL)
        self.assertIs(result.generic_action, GenericAction.CONTACT_SECURITY)

    def test_strong_rule_establishes_severity_risk_floor(self):
        expected_floors = {
            RuleSeverity.LOW: 20,
            RuleSeverity.MEDIUM: 40,
            RuleSeverity.HIGH: 70,
            RuleSeverity.CRITICAL: 90,
        }

        for severity, expected_floor in expected_floors.items():
            with self.subTest(severity=severity):
                result = fuse_risk(
                    (
                        make_rule(
                            f"strong_{severity.value}",
                            severity=severity,
                            score_contribution=1,
                            strong_evidence=True,
                        ),
                    ),
                    model_assessment=None,
                    execution_state=DetectionExecutionState.RULES_ONLY,
                )

                self.assertEqual(result.risk_floor, expected_floor)
                self.assertEqual(result.final_risk_score, expected_floor)
                self.assertTrue(result.has_strong_evidence)

    def test_input_order_and_duplicate_rule_ids_do_not_change_or_double_score(self):
        conservative = make_rule(
            "duplicate_rule",
            severity=RuleSeverity.HIGH,
            score_contribution=35,
            strong_evidence=True,
            generic_action=GenericAction.CONTACT_SECURITY,
        )
        weaker_duplicate = make_rule(
            "duplicate_rule",
            severity=RuleSeverity.LOW,
            score_contribution=10,
        )
        independent = make_rule(
            "independent_rule",
            score_contribution=5,
        )

        forward = fuse_risk(
            (weaker_duplicate, independent, conservative),
            model_assessment=None,
            execution_state=DetectionExecutionState.RULES_ONLY,
        )
        reverse = fuse_risk(
            (conservative, independent, weaker_duplicate),
            model_assessment=None,
            execution_state=DetectionExecutionState.RULES_ONLY,
        )

        self.assertEqual(forward, reverse)
        self.assertEqual(
            tuple(item.rule_id for item in forward.rule_assessments),
            ("duplicate_rule", "independent_rule"),
        )
        self.assertEqual(forward.rule_score, 40)
        self.assertEqual(forward.risk_floor, 70)
        self.assertEqual(forward.final_risk_score, 70)

    def test_rule_contract_rejects_sensitive_or_invalid_fields(self):
        invalid_changes = (
            {"rule_id": "C:\\Private\\rule"},
            {"evidence_code": "token=fictional"},
            {"score_contribution": -1},
            {"score_contribution": 101},
            {"strong_evidence": 1},
            {"severity": "high"},
        )

        for changes in invalid_changes:
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(
                    ValueError,
                    "^invalid_rule_assessment$",
                ):
                    make_rule(**changes)


class ModelRuleRiskFusionTests(unittest.TestCase):
    def test_uncertain_without_rules_is_not_projected_as_safe_to_continue(self):
        result = fuse_risk(
            (),
            model_assessment=make_model_assessment(
                0.5,
                ModelConfidenceState.UNCERTAIN,
            ),
            execution_state=DetectionExecutionState.MODEL_UNCERTAIN,
        )

        self.assertEqual(result.final_risk_score, 0)
        self.assertIs(result.risk_level, RiskLevel.LOW)
        self.assertEqual(result.model_adjustment, 0)
        self.assertIs(result.generic_action, GenericAction.VERIFY_SENDER)

    def test_confident_phishing_adds_bounded_risk_without_model_only_critical(self):
        model = make_model_assessment(
            1.0,
            ModelConfidenceState.CONFIDENT_PHISHING,
        )

        model_only = fuse_risk(
            (),
            model_assessment=model,
            execution_state=DetectionExecutionState.MODEL_SUCCESS,
        )
        with_rule = fuse_risk(
            (make_rule(score_contribution=20),),
            model_assessment=model,
            execution_state=DetectionExecutionState.MODEL_SUCCESS,
        )

        self.assertEqual(model_only.model_adjustment, 25)
        self.assertEqual(model_only.final_risk_score, 25)
        self.assertIs(model_only.risk_level, RiskLevel.MEDIUM)
        self.assertEqual(with_rule.final_risk_score, 45)

    def test_confident_benign_has_only_limited_protective_effect(self):
        result = fuse_risk(
            (make_rule(score_contribution=40),),
            model_assessment=make_model_assessment(
                0.0,
                ModelConfidenceState.CONFIDENT_BENIGN,
            ),
            execution_state=DetectionExecutionState.MODEL_SUCCESS,
        )

        self.assertEqual(result.model_adjustment, -5)
        self.assertEqual(result.final_risk_score, 35)
        self.assertIs(result.risk_level, RiskLevel.MEDIUM)

    def test_uncertain_and_degraded_states_do_not_adjust_rule_score(self):
        uncertain = make_model_assessment(0.5, ModelConfidenceState.UNCERTAIN)
        confident_phishing = make_model_assessment(
            1.0,
            ModelConfidenceState.CONFIDENT_PHISHING,
        )
        cases = (
            (DetectionExecutionState.MODEL_UNCERTAIN, uncertain),
            (DetectionExecutionState.MODEL_UNAVAILABLE, None),
            (DetectionExecutionState.MODEL_TIMEOUT, None),
            (DetectionExecutionState.MODEL_ERROR, None),
            (DetectionExecutionState.MODEL_INVALID_OUTPUT, None),
            (DetectionExecutionState.RULES_ONLY, None),
            (DetectionExecutionState.MODEL_ERROR, confident_phishing),
        )

        for execution_state, assessment in cases:
            with self.subTest(execution_state=execution_state):
                result = fuse_risk(
                    (make_rule(score_contribution=30),),
                    model_assessment=assessment,
                    execution_state=execution_state,
                )

                self.assertEqual(result.model_adjustment, 0)
                self.assertEqual(result.final_risk_score, 30)
                self.assertIs(result.risk_level, RiskLevel.MEDIUM)

    def test_confident_benign_cannot_reduce_strong_rule_floor(self):
        result = fuse_risk(
            (
                make_rule(
                    severity=RuleSeverity.CRITICAL,
                    score_contribution=1,
                    strong_evidence=True,
                    generic_action=GenericAction.CONTACT_SECURITY,
                ),
            ),
            model_assessment=make_model_assessment(
                0.0,
                ModelConfidenceState.CONFIDENT_BENIGN,
            ),
            execution_state=DetectionExecutionState.MODEL_SUCCESS,
        )

        self.assertEqual(result.model_adjustment, -5)
        self.assertEqual(result.risk_floor, 90)
        self.assertEqual(result.final_risk_score, 90)
        self.assertIs(result.risk_level, RiskLevel.CRITICAL)
        self.assertIs(result.generic_action, GenericAction.CONTACT_SECURITY)


if __name__ == "__main__":
    unittest.main()
