from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import re

from .domain import (
    DetectionExecutionState,
    DetectionOutcome,
    GenericAction,
    ModelExecutionStatus,
    RiskLevel,
)


EVIDENCE_RECORD_SCHEMA_VERSION = "1.0"
EVIDENCE_RETENTION_DAYS = 15
EVIDENCE_RECORD_MAX_BYTES = 65_536

_LOCAL_EVENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_STABLE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SOURCE_KIND = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_SERIALIZED_FIELDS = frozenset(
    {
        "abstained",
        "degraded",
        "detected_at",
        "detection_status",
        "error_code",
        "generic_action",
        "local_event_id",
        "model_execution_status",
        "retention_until",
        "risk_level",
        "rule_codes",
        "schema_version",
        "source_kind",
    }
)


class EvidenceRecordValidationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class EndpointEvidenceRecord:
    local_event_id: str
    detected_at: datetime
    retention_until: datetime
    risk_level: RiskLevel
    detection_status: DetectionExecutionState
    generic_action: GenericAction
    source_kind: str
    rule_codes: tuple[str, ...]
    abstained: bool
    degraded: bool
    model_execution_status: ModelExecutionStatus | None
    error_code: str | None
    schema_version: str = EVIDENCE_RECORD_SCHEMA_VERSION

    def __post_init__(self) -> None:
        aware_times = (
            isinstance(self.detected_at, datetime)
            and self.detected_at.tzinfo is not None
            and self.detected_at.utcoffset() is not None
            and isinstance(self.retention_until, datetime)
            and self.retention_until.tzinfo is not None
            and self.retention_until.utcoffset() is not None
        )
        valid_error = self.error_code is None or (
            isinstance(self.error_code, str)
            and _STABLE_CODE.fullmatch(self.error_code) is not None
        )
        if (
            not isinstance(self.local_event_id, str)
            or _LOCAL_EVENT_ID.fullmatch(self.local_event_id) is None
            or not aware_times
            or self.retention_until
            != self.detected_at + timedelta(days=EVIDENCE_RETENTION_DAYS)
            or not isinstance(self.risk_level, RiskLevel)
            or not isinstance(self.detection_status, DetectionExecutionState)
            or not isinstance(self.generic_action, GenericAction)
            or not isinstance(self.source_kind, str)
            or _SOURCE_KIND.fullmatch(self.source_kind) is None
            or not isinstance(self.rule_codes, tuple)
            or len(self.rule_codes) > 64
            or any(
                not isinstance(code, str)
                or _STABLE_CODE.fullmatch(code) is None
                for code in self.rule_codes
            )
            or len(set(self.rule_codes)) != len(self.rule_codes)
            or not isinstance(self.abstained, bool)
            or self.abstained
            != (self.detection_status is DetectionExecutionState.MODEL_UNCERTAIN)
            or not isinstance(self.degraded, bool)
            or not (
                self.model_execution_status is None
                or isinstance(self.model_execution_status, ModelExecutionStatus)
            )
            or not valid_error
            or self.schema_version != EVIDENCE_RECORD_SCHEMA_VERSION
        ):
            raise EvidenceRecordValidationError("invalid_evidence_record")

    def to_json_bytes(self) -> bytes:
        payload = {
            "abstained": self.abstained,
            "degraded": self.degraded,
            "detected_at": self.detected_at.isoformat(),
            "detection_status": self.detection_status.value,
            "error_code": self.error_code,
            "generic_action": self.generic_action.value,
            "local_event_id": self.local_event_id,
            "model_execution_status": (
                self.model_execution_status.value
                if self.model_execution_status is not None
                else None
            ),
            "retention_until": self.retention_until.isoformat(),
            "risk_level": self.risk_level.value,
            "rule_codes": list(self.rule_codes),
            "schema_version": self.schema_version,
            "source_kind": self.source_kind,
        }
        return json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, payload: bytes) -> "EndpointEvidenceRecord":
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise EvidenceRecordValidationError("invalid_evidence_record")
                result[key] = value
            return result

        try:
            if (
                not isinstance(payload, bytes)
                or not payload
                or len(payload) > EVIDENCE_RECORD_MAX_BYTES
            ):
                raise ValueError
            values = json.loads(
                payload.decode("utf-8", errors="strict"),
                object_pairs_hook=unique_object,
            )
            if not isinstance(values, dict) or set(values) != _SERIALIZED_FIELDS:
                raise ValueError
            if not isinstance(values["rule_codes"], list):
                raise ValueError
            model_status = values["model_execution_status"]
            return cls(
                local_event_id=values["local_event_id"],
                detected_at=datetime.fromisoformat(values["detected_at"]),
                retention_until=datetime.fromisoformat(values["retention_until"]),
                risk_level=RiskLevel(values["risk_level"]),
                detection_status=DetectionExecutionState(
                    values["detection_status"]
                ),
                generic_action=GenericAction(values["generic_action"]),
                source_kind=values["source_kind"],
                rule_codes=tuple(values["rule_codes"]),
                abstained=values["abstained"],
                degraded=values["degraded"],
                model_execution_status=(
                    ModelExecutionStatus(model_status)
                    if model_status is not None
                    else None
                ),
                error_code=values["error_code"],
                schema_version=values["schema_version"],
            )
        except EvidenceRecordValidationError:
            raise
        except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError):
            raise EvidenceRecordValidationError("invalid_evidence_record") from None

    @classmethod
    def from_detection_outcome(
        cls,
        outcome: DetectionOutcome,
        *,
        detected_at: datetime,
        source_kind: str,
    ) -> "EndpointEvidenceRecord":
        evidence = outcome.structured_private_evidence
        return cls(
            local_event_id=outcome.local_event_id,
            detected_at=detected_at,
            retention_until=outcome.evidence_retention_until,
            risk_level=outcome.risk_level,
            detection_status=outcome.execution_state,
            generic_action=outcome.generic_action,
            source_kind=source_kind,
            rule_codes=tuple(item.evidence_code for item in evidence.rule_evidence),
            abstained=(
                outcome.execution_state
                is DetectionExecutionState.MODEL_UNCERTAIN
            ),
            degraded=evidence.degraded,
            model_execution_status=evidence.model_execution_status,
            error_code=evidence.error_code,
        )


__all__ = [
    "EVIDENCE_RECORD_SCHEMA_VERSION",
    "EVIDENCE_RETENTION_DAYS",
    "EndpointEvidenceRecord",
    "EvidenceRecordValidationError",
]
