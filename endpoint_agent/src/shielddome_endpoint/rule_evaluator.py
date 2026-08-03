from dataclasses import dataclass
import math
from typing import Callable

from .domain import (
    FEATURE_SCHEMA_VERSION,
    FeatureVector,
    GenericAction,
    RuleAssessment,
    RuleCategory,
    RuleSeverity,
)
from .feature_pipeline import CATEGORICAL_FEATURE_NAMES, NUMERIC_FEATURE_NAMES


class FeatureVectorValidationError(ValueError):
    """A stable rejection at the local rule-evaluation seam."""


@dataclass(frozen=True, slots=True)
class _ValidatedFeatures:
    numeric: dict[str, float]
    categorical: dict[str, str]


@dataclass(frozen=True, slots=True)
class _RulePolicy:
    rule_id: str
    category: RuleCategory
    severity: RuleSeverity
    score_contribution: int
    strong_evidence: bool
    evidence_code: str
    generic_action: GenericAction
    matches: Callable[[_ValidatedFeatures], bool]

    def assessment(self) -> RuleAssessment:
        return RuleAssessment(
            rule_id=self.rule_id,
            category=self.category,
            severity=self.severity,
            score_contribution=self.score_contribution,
            strong_evidence=self.strong_evidence,
            evidence_code=self.evidence_code,
            generic_action=self.generic_action,
        )


def _authentication_failure_count(features: _ValidatedFeatures) -> int:
    return sum(
        features.categorical[name] in {"fail", "softfail"}
        for name in ("auth_spf_value", "auth_dkim_value", "auth_dmarc_value")
    )


_RULE_POLICIES = (
    _RulePolicy(
        "auth_dmarc_fail",
        RuleCategory.AUTHENTICATION,
        RuleSeverity.HIGH,
        24,
        False,
        "auth_dmarc_failure",
        GenericAction.VERIFY_SENDER,
        lambda features: features.categorical["auth_dmarc_value"] == "fail",
    ),
    _RulePolicy(
        "auth_spf_fail",
        RuleCategory.AUTHENTICATION,
        RuleSeverity.MEDIUM,
        14,
        False,
        "auth_spf_failure",
        GenericAction.VERIFY_SENDER,
        lambda features: features.categorical["auth_spf_value"] == "fail",
    ),
    _RulePolicy(
        "auth_spf_softfail",
        RuleCategory.AUTHENTICATION,
        RuleSeverity.LOW,
        8,
        False,
        "auth_spf_soft_failure",
        GenericAction.VERIFY_SENDER,
        lambda features: features.categorical["auth_spf_value"] == "softfail",
    ),
    _RulePolicy(
        "auth_dkim_fail",
        RuleCategory.AUTHENTICATION,
        RuleSeverity.MEDIUM,
        14,
        False,
        "auth_dkim_failure",
        GenericAction.VERIFY_SENDER,
        lambda features: features.categorical["auth_dkim_value"] == "fail",
    ),
    _RulePolicy(
        "auth_multiple_failures",
        RuleCategory.AUTHENTICATION,
        RuleSeverity.HIGH,
        20,
        False,
        "auth_multiple_failures",
        GenericAction.VERIFY_SENDER,
        lambda features: _authentication_failure_count(features) >= 2,
    ),
    _RulePolicy(
        "sender_reply_mismatch",
        RuleCategory.SENDER,
        RuleSeverity.MEDIUM,
        12,
        False,
        "sender_reply_domain_mismatch",
        GenericAction.VERIFY_SENDER,
        lambda features: features.numeric["reply_to_present"] > 0
        and features.numeric["sender_reply_domain_match"] == 0,
    ),
    _RulePolicy(
        "link_ip_literal",
        RuleCategory.LINK,
        RuleSeverity.MEDIUM,
        20,
        False,
        "link_ip_literal_present",
        GenericAction.AVOID_CREDENTIALS,
        lambda features: features.numeric["ip_literal_url_count"] > 0,
    ),
    _RulePolicy(
        "link_suspicious_port",
        RuleCategory.LINK,
        RuleSeverity.MEDIUM,
        12,
        False,
        "link_suspicious_port_present",
        GenericAction.VERIFY_SENDER,
        lambda features: features.numeric["suspicious_port_url_count"] > 0,
    ),
    _RulePolicy(
        "link_punycode_domain",
        RuleCategory.LINK,
        RuleSeverity.MEDIUM,
        10,
        False,
        "link_punycode_domain_present",
        GenericAction.VERIFY_SENDER,
        lambda features: features.numeric["punycode_domain_count"] > 0,
    ),
    _RulePolicy(
        "link_unicode_domain",
        RuleCategory.LINK,
        RuleSeverity.MEDIUM,
        8,
        False,
        "link_unicode_domain_present",
        GenericAction.VERIFY_SENDER,
        lambda features: features.numeric["unicode_domain_count"] > 0,
    ),
    _RulePolicy(
        "link_count_high",
        RuleCategory.LINK,
        RuleSeverity.MEDIUM,
        10,
        False,
        "link_count_above_normal",
        GenericAction.VERIFY_SENDER,
        lambda features: features.numeric["url_count"] > 20,
    ),
    _RulePolicy(
        "attachment_dangerous_extension",
        RuleCategory.ATTACHMENT,
        RuleSeverity.HIGH,
        35,
        True,
        "attachment_dangerous_extension_present",
        GenericAction.CONTACT_SECURITY,
        lambda features: features.numeric["dangerous_extension_count"] > 0,
    ),
    _RulePolicy(
        "attachment_double_extension",
        RuleCategory.ATTACHMENT,
        RuleSeverity.MEDIUM,
        18,
        False,
        "attachment_double_extension_present",
        GenericAction.CONTACT_SECURITY,
        lambda features: features.numeric["double_extension_count"] > 0,
    ),
    _RulePolicy(
        "intent_credential_urgency",
        RuleCategory.INTENT,
        RuleSeverity.HIGH,
        22,
        False,
        "intent_credential_with_urgency",
        GenericAction.AVOID_CREDENTIALS,
        lambda features: features.numeric["intent_credential_count"] > 0
        and features.numeric["intent_urgency_count"] > 0,
    ),
    _RulePolicy(
        "intent_payment_urgency",
        RuleCategory.INTENT,
        RuleSeverity.MEDIUM,
        20,
        False,
        "intent_payment_with_urgency",
        GenericAction.CONTACT_SECURITY,
        lambda features: features.numeric["intent_payment_count"] > 0
        and features.numeric["intent_urgency_count"] > 0,
    ),
    _RulePolicy(
        "intent_impersonation_credential",
        RuleCategory.INTENT,
        RuleSeverity.HIGH,
        24,
        False,
        "intent_impersonation_with_credential",
        GenericAction.AVOID_CREDENTIALS,
        lambda features: features.numeric["intent_impersonation_count"] > 0
        and features.numeric["intent_credential_count"] > 0,
    ),
    _RulePolicy(
        "intent_impersonation_payment",
        RuleCategory.INTENT,
        RuleSeverity.HIGH,
        24,
        False,
        "intent_impersonation_with_payment",
        GenericAction.CONTACT_SECURITY,
        lambda features: features.numeric["intent_impersonation_count"] > 0
        and features.numeric["intent_payment_count"] > 0,
    ),
    _RulePolicy(
        "link_ip_credential",
        RuleCategory.LINK,
        RuleSeverity.HIGH,
        35,
        True,
        "link_ip_literal_with_credential",
        GenericAction.AVOID_CREDENTIALS,
        lambda features: features.numeric["ip_literal_url_count"] > 0
        and features.numeric["intent_credential_count"] > 0,
    ),
    _RulePolicy(
        "auth_failures_impersonation",
        RuleCategory.AUTHENTICATION,
        RuleSeverity.HIGH,
        35,
        True,
        "auth_failures_with_impersonation",
        GenericAction.CONTACT_SECURITY,
        lambda features: _authentication_failure_count(features) >= 2
        and features.numeric["intent_impersonation_count"] > 0,
    ),
)


def _validated_features(features: FeatureVector) -> _ValidatedFeatures:
    if not isinstance(features, FeatureVector):
        raise FeatureVectorValidationError("invalid_feature_vector")
    if features.schema_version != FEATURE_SCHEMA_VERSION:
        raise FeatureVectorValidationError("incompatible_feature_schema")

    numeric: dict[str, float] = {}
    if not isinstance(features.numeric_features, tuple):
        raise FeatureVectorValidationError("invalid_numeric_features")
    for item in features.numeric_features:
        if (
            not isinstance(item, tuple)
            or len(item) != 2
            or not isinstance(item[0], str)
            or item[0] in numeric
            or isinstance(item[1], bool)
            or not isinstance(item[1], (int, float))
            or not math.isfinite(item[1])
            or item[1] < 0
        ):
            raise FeatureVectorValidationError("invalid_numeric_features")
        numeric[item[0]] = float(item[1])
    if set(numeric) != set(NUMERIC_FEATURE_NAMES):
        raise FeatureVectorValidationError("invalid_numeric_features")

    categorical: dict[str, str] = {}
    if not isinstance(features.categorical_features, tuple):
        raise FeatureVectorValidationError("invalid_categorical_features")
    for item in features.categorical_features:
        if (
            not isinstance(item, tuple)
            or len(item) != 2
            or not isinstance(item[0], str)
            or item[0] in categorical
            or not isinstance(item[1], str)
        ):
            raise FeatureVectorValidationError("invalid_categorical_features")
        categorical[item[0]] = item[1]
    if set(categorical) != set(CATEGORICAL_FEATURE_NAMES):
        raise FeatureVectorValidationError("invalid_categorical_features")

    return _ValidatedFeatures(numeric=numeric, categorical=categorical)


class LocalRuleEvaluator:
    def evaluate(self, features: FeatureVector) -> tuple[RuleAssessment, ...]:
        validated = _validated_features(features)
        return tuple(
            policy.assessment()
            for policy in _RULE_POLICIES
            if policy.matches(validated)
        )


__all__ = ["FeatureVectorValidationError", "LocalRuleEvaluator"]
