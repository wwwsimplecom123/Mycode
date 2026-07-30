from dataclasses import dataclass
from datetime import datetime


MAIL_OBSERVATION_SCHEMA_VERSION = "1.0"
FEATURE_SCHEMA_VERSION = "1.0"
DETECTION_OUTCOME_SCHEMA_VERSION = "1.0"


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
    probability: float
    confidence_state: str
    execution_status: str
    model_version: str
    feature_schema_version: str
    duration_ms: int
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class DetectionOutcome:
    local_event_id: str
    final_risk_score: int
    risk_level: str
    generic_action: str
    execution_state: str
    structured_private_evidence: tuple[tuple[str, str], ...]
    minimal_plugin_projection: tuple[tuple[str, str], ...]
    evidence_retention_until: datetime
    schema_version: str = DETECTION_OUTCOME_SCHEMA_VERSION
