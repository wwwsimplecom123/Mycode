from .domain import (
    DETECTION_OUTCOME_SCHEMA_VERSION,
    FEATURE_SCHEMA_VERSION,
    MAIL_OBSERVATION_SCHEMA_VERSION,
    DetectionOutcome,
    FeatureVector,
    MailObservation,
    ModelAssessment,
)


__version__ = "0.1.0"

__all__ = [
    "__version__",
    "MAIL_OBSERVATION_SCHEMA_VERSION",
    "FEATURE_SCHEMA_VERSION",
    "DETECTION_OUTCOME_SCHEMA_VERSION",
    "MailObservation",
    "FeatureVector",
    "ModelAssessment",
    "DetectionOutcome",
]
