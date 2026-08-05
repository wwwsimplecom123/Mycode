from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
import re


MAIL_OBSERVATION_SCHEMA_VERSION = "1.0"
FEATURE_SCHEMA_VERSION = "2.0"
MODEL_ASSESSMENT_SCHEMA_VERSION = "1.0"
DETECTION_OUTCOME_SCHEMA_VERSION = "3.0"


class ModelConfidenceState(StrEnum):
    CONFIDENT_BENIGN = "confident-benign"
    UNCERTAIN = "uncertain"
    CONFIDENT_PHISHING = "confident-phishing"


class ModelExecutionStatus(StrEnum):
    SUCCESS = "success"
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    ERROR = "error"


class DetectionExecutionState(StrEnum):
    MODEL_SUCCESS = "model_success"
    MODEL_UNCERTAIN = "model_uncertain"
    MODEL_UNAVAILABLE = "model_unavailable"
    MODEL_TIMEOUT = "model_timeout"
    MODEL_ERROR = "model_error"
    MODEL_INVALID_OUTPUT = "model_invalid_output"
    RULES_ONLY = "rules_only"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class GenericAction(StrEnum):
    CONTINUE = "continue"
    VERIFY_SENDER = "verify_sender"
    AVOID_CREDENTIALS = "avoid_credentials"
    CONTACT_SECURITY = "contact_security"


class RuleCategory(StrEnum):
    AUTHENTICATION = "authentication"
    LINK = "link"
    SENDER = "sender"
    ATTACHMENT = "attachment"
    INTENT = "intent"
    POLICY = "policy"
    OTHER = "other"


class RuleSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_STABLE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


@dataclass(frozen=True, slots=True)
class RuleAssessment:
    rule_id: str
    category: RuleCategory
    severity: RuleSeverity
    score_contribution: int
    strong_evidence: bool
    evidence_code: str
    generic_action: GenericAction

    def __post_init__(self) -> None:
        if (
            not isinstance(self.rule_id, str)
            or _STABLE_CODE.fullmatch(self.rule_id) is None
            or not isinstance(self.category, RuleCategory)
            or not isinstance(self.severity, RuleSeverity)
            or isinstance(self.score_contribution, bool)
            or not isinstance(self.score_contribution, int)
            or not 0 <= self.score_contribution <= 100
            or not isinstance(self.strong_evidence, bool)
            or not isinstance(self.evidence_code, str)
            or _STABLE_CODE.fullmatch(self.evidence_code) is None
            or not isinstance(self.generic_action, GenericAction)
        ):
            raise ValueError("invalid_rule_assessment")


@dataclass(frozen=True, slots=True)
class MailObservation:
    source_kind: str
    source_message_id: str
    subject: str
    sender: str
    reply_to: str | None
    recipient_summary: tuple[str, ...]
    sanitized_body_text: str
    authentication_observations: tuple[tuple[str, str], ...]
    normalized_links: tuple[str, ...]
    attachment_metadata: tuple[tuple[str, str], ...]
    language_hint: str | None
    observed_at: datetime
    schema_version: str = MAIL_OBSERVATION_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class FeatureVector:
    numeric_features: tuple[tuple[str, float], ...]
    categorical_features: tuple[tuple[str, str], ...]
    text_input: str | None
    text_vector: tuple[float, ...] | None
    missing_value_mask: tuple[str, ...]
    schema_version: str = FEATURE_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class ModelAssessment:
    probability: float | None
    confidence_state: ModelConfidenceState | None
    execution_status: ModelExecutionStatus
    model_version: str | None
    feature_schema_version: str | None
    duration_ms: int
    error_code: str | None = None
    schema_version: str = MODEL_ASSESSMENT_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class PrivateRuleEvidence:
    evidence_code: str
    category: RuleCategory
    status: str
    score_contribution: int
    strong_evidence: bool


@dataclass(frozen=True, slots=True)
class StructuredPrivateEvidence:
    rule_evidence: tuple[PrivateRuleEvidence, ...]
    rule_score: int
    model_adjustment: int
    risk_floor: int
    model_execution_status: ModelExecutionStatus | None
    execution_state: DetectionExecutionState
    degraded: bool
    error_code: str | None
    assessment_schema_version: str | None
    model_version: str | None
    feature_schema_version: str
    detection_outcome_schema_version: str
    example_adjustment: int = 0
    example_calibration_status: str = "no_examples"
    example_supporting_count: int = 0


@dataclass(frozen=True, slots=True)
class DetectionOutcome:
    local_event_id: str
    final_risk_score: int
    risk_level: RiskLevel
    generic_action: GenericAction
    execution_state: DetectionExecutionState
    structured_private_evidence: StructuredPrivateEvidence
    minimal_plugin_projection: tuple[tuple[str, str], ...]
    evidence_retention_until: datetime
    schema_version: str = DETECTION_OUTCOME_SCHEMA_VERSION
