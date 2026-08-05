from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
import json

from . import __version__
from .confirmed_examples import CONFIRMED_EXAMPLE_SCHEMA_VERSION
from .domain import (
    DETECTION_OUTCOME_SCHEMA_VERSION,
    FEATURE_SCHEMA_VERSION,
    MAIL_OBSERVATION_SCHEMA_VERSION,
    MODEL_ASSESSMENT_SCHEMA_VERSION,
    DetectionExecutionState,
    ModelExecutionStatus,
    RiskLevel,
)
from .evidence_record import EVIDENCE_RECORD_SCHEMA_VERSION
from .example_store import ExampleLibraryAggregate, ExampleStore
from .evidence_store import EvidenceStore
from .native_protocol import PROTOCOL_VERSION


DIAGNOSTIC_SCHEMA_VERSION = "1.0"
DIAGNOSTIC_LOOKBACK_DAYS = 15
DIAGNOSTIC_MAX_EVIDENCE_RECORDS = 4_096
DIAGNOSTIC_MAX_ERROR_CODE_KINDS = 32
DIAGNOSTIC_MAX_SOURCE_KINDS = 32
_EVIDENCE_PAGE_SIZE = 100
_HEALTH_ERROR_CODES = frozenset(
    {"evidence_store_unavailable", "example_library_unavailable"}
)


class DiagnosticCollectionError(RuntimeError):
    pass


class DiagnosticHealthStatus(StrEnum):
    HEALTHY = "healthy"
    EMPTY = "empty"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class DiagnosticStoreHealth:
    status: DiagnosticHealthStatus
    item_count: int
    error_code: str | None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.status, DiagnosticHealthStatus)
            or isinstance(self.item_count, bool)
            or not isinstance(self.item_count, int)
            or self.item_count < 0
            or (
                self.status is DiagnosticHealthStatus.UNAVAILABLE
                and (
                    self.item_count != 0
                    or self.error_code not in _HEALTH_ERROR_CODES
                )
            )
            or (
                self.status is not DiagnosticHealthStatus.UNAVAILABLE
                and self.error_code is not None
            )
            or (
                self.status is DiagnosticHealthStatus.EMPTY
                and self.item_count != 0
            )
            or (
                self.status is DiagnosticHealthStatus.HEALTHY
                and self.item_count == 0
            )
        ):
            raise ValueError("invalid_diagnostic_store_health")

    def to_payload(self) -> dict[str, object]:
        return {
            "error_code": self.error_code,
            "item_count": self.item_count,
            "status": self.status.value,
        }


@dataclass(frozen=True, slots=True)
class SanitizedDiagnostics:
    generated_at: datetime
    versions: tuple[tuple[str, str], ...]
    evidence_store_health: DiagnosticStoreHealth
    example_library_health: DiagnosticStoreHealth
    event_count: int
    events_by_date: tuple[tuple[str, int], ...]
    risk_level_counts: tuple[tuple[str, int], ...]
    source_counts: tuple[tuple[str, int], ...]
    detection_state_counts: tuple[tuple[str, int], ...]
    model_execution_status_counts: tuple[tuple[str, int], ...]
    rules_only_count: int
    model_available_count: int
    model_abstained_count: int
    model_degraded_count: int
    stable_error_code_counts: tuple[tuple[str, int], ...]
    example_total_rows: int
    example_unique_count: int
    example_benign_label_count: int
    example_phishing_label_count: int
    example_conflict_count: int
    lookback_days: int = DIAGNOSTIC_LOOKBACK_DAYS
    schema_version: str = DIAGNOSTIC_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            not isinstance(self.generated_at, datetime)
            or self.generated_at.tzinfo is None
            or self.generated_at.utcoffset() is None
            or self.lookback_days != DIAGNOSTIC_LOOKBACK_DAYS
            or self.schema_version != DIAGNOSTIC_SCHEMA_VERSION
        ):
            raise ValueError("invalid_sanitized_diagnostics")
        count_values = (
            self.event_count,
            self.rules_only_count,
            self.model_available_count,
            self.model_abstained_count,
            self.model_degraded_count,
            self.example_total_rows,
            self.example_unique_count,
            self.example_benign_label_count,
            self.example_phishing_label_count,
            self.example_conflict_count,
        )
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in count_values
        ):
            raise ValueError("invalid_sanitized_diagnostics")

    def to_payload(self) -> dict[str, object]:
        return {
            "detection_state_counts": dict(self.detection_state_counts),
            "event_count": self.event_count,
            "events_by_date": [
                {"count": count, "date": date}
                for date, count in self.events_by_date
            ],
            "evidence_store_health": self.evidence_store_health.to_payload(),
            "example_library_counts": {
                "benign_labels": self.example_benign_label_count,
                "conflicts": self.example_conflict_count,
                "phishing_labels": self.example_phishing_label_count,
                "total_rows": self.example_total_rows,
                "unique_examples": self.example_unique_count,
            },
            "example_library_health": self.example_library_health.to_payload(),
            "generated_at_utc": self.generated_at.astimezone(timezone.utc).isoformat(
                timespec="seconds"
            ),
            "lookback_days": self.lookback_days,
            "model_abstained_count": self.model_abstained_count,
            "model_available_count": self.model_available_count,
            "model_degraded_count": self.model_degraded_count,
            "model_execution_status_counts": dict(
                self.model_execution_status_counts
            ),
            "risk_level_counts": dict(self.risk_level_counts),
            "rules_only_count": self.rules_only_count,
            "schema_version": self.schema_version,
            "source_counts": dict(self.source_counts),
            "stable_error_code_counts": dict(self.stable_error_code_counts),
            "versions": dict(self.versions),
        }

    def to_json_bytes(self) -> bytes:
        return (
            json.dumps(
                self.to_payload(),
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")


class DiagnosticsCollector:
    def __init__(
        self,
        *,
        evidence_store: object | None = None,
        example_store: object | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._evidence_store = evidence_store or EvidenceStore()
        self._example_store = example_store or ExampleStore()
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def _read_evidence(self) -> tuple[tuple[object, ...], DiagnosticStoreHealth]:
        records: list[object] = []
        try:
            while True:
                if len(records) == DIAGNOSTIC_MAX_EVIDENCE_RECORDS:
                    extra = self._evidence_store.list_page(
                        offset=len(records),
                        limit=1,
                    )
                    if extra:
                        raise DiagnosticCollectionError(
                            "diagnostic_record_limit_exceeded"
                        )
                    break
                page_limit = min(
                    _EVIDENCE_PAGE_SIZE,
                    DIAGNOSTIC_MAX_EVIDENCE_RECORDS - len(records),
                )
                page = self._evidence_store.list_page(
                    offset=len(records),
                    limit=page_limit,
                )
                if not page:
                    break
                records.extend(page)
                if len(records) == DIAGNOSTIC_MAX_EVIDENCE_RECORDS:
                    extra = self._evidence_store.list_page(
                        offset=len(records),
                        limit=1,
                    )
                    if extra:
                        raise DiagnosticCollectionError(
                            "diagnostic_record_limit_exceeded"
                        )
                    break
                if len(page) < page_limit:
                    break
        except DiagnosticCollectionError:
            raise
        except Exception:
            return (), DiagnosticStoreHealth(
                DiagnosticHealthStatus.UNAVAILABLE,
                0,
                "evidence_store_unavailable",
            )
        status = (
            DiagnosticHealthStatus.HEALTHY
            if records
            else DiagnosticHealthStatus.EMPTY
        )
        return tuple(records), DiagnosticStoreHealth(status, len(records), None)

    def _read_examples(self) -> tuple[ExampleLibraryAggregate, DiagnosticStoreHealth]:
        try:
            aggregate = self._example_store.diagnostic_aggregate()
            if not isinstance(aggregate, ExampleLibraryAggregate):
                raise ValueError
        except Exception as error:
            if error.args == ("example_diagnostic_limit_exceeded",):
                raise DiagnosticCollectionError(
                    "diagnostic_record_limit_exceeded"
                ) from None
            return ExampleLibraryAggregate(0, 0, 0, 0, 0), DiagnosticStoreHealth(
                DiagnosticHealthStatus.UNAVAILABLE,
                0,
                "example_library_unavailable",
            )
        status = (
            DiagnosticHealthStatus.HEALTHY
            if aggregate.total_rows
            else DiagnosticHealthStatus.EMPTY
        )
        return aggregate, DiagnosticStoreHealth(
            status,
            aggregate.total_rows,
            None,
        )

    def collect(self) -> SanitizedDiagnostics:
        now = self._clock()
        if (
            not isinstance(now, datetime)
            or now.tzinfo is None
            or now.utcoffset() is None
        ):
            raise DiagnosticCollectionError("invalid_diagnostic_time")
        now = now.astimezone(timezone.utc)
        records, evidence_health = self._read_evidence()
        examples, example_health = self._read_examples()
        cutoff = now - timedelta(days=DIAGNOSTIC_LOOKBACK_DAYS)
        recent = tuple(
            record
            for record in records
            if cutoff <= record.detected_at.astimezone(timezone.utc) <= now
        )

        dates = Counter(
            record.detected_at.astimezone(timezone.utc).date().isoformat()
            for record in recent
        )
        risks = Counter(record.risk_level.value for record in recent)
        sources = Counter(record.source_kind for record in recent)
        states = Counter(record.detection_status.value for record in recent)
        model_statuses = Counter(
            record.model_execution_status.value
            if record.model_execution_status is not None
            else "none"
            for record in recent
        )
        error_codes = Counter(
            record.error_code for record in recent if record.error_code is not None
        )
        if len(sources) > DIAGNOSTIC_MAX_SOURCE_KINDS:
            raise DiagnosticCollectionError("diagnostic_source_limit_exceeded")
        if len(error_codes) > DIAGNOSTIC_MAX_ERROR_CODE_KINDS:
            raise DiagnosticCollectionError("diagnostic_error_code_limit_exceeded")

        versions = (
            ("agent", __version__),
            ("confirmed_example", CONFIRMED_EXAMPLE_SCHEMA_VERSION),
            ("detection_outcome", DETECTION_OUTCOME_SCHEMA_VERSION),
            ("diagnostic", DIAGNOSTIC_SCHEMA_VERSION),
            ("endpoint_evidence_record", EVIDENCE_RECORD_SCHEMA_VERSION),
            ("feature_schema", FEATURE_SCHEMA_VERSION),
            ("mail_observation", MAIL_OBSERVATION_SCHEMA_VERSION),
            ("model_assessment", MODEL_ASSESSMENT_SCHEMA_VERSION),
            ("native_messaging_protocol", PROTOCOL_VERSION),
        )
        return SanitizedDiagnostics(
            generated_at=now,
            versions=versions,
            evidence_store_health=evidence_health,
            example_library_health=example_health,
            event_count=len(recent),
            events_by_date=tuple(sorted(dates.items())),
            risk_level_counts=tuple(
                (value.value, risks[value.value]) for value in RiskLevel
            ),
            source_counts=tuple(sorted(sources.items())),
            detection_state_counts=tuple(
                (value.value, states[value.value])
                for value in DetectionExecutionState
            ),
            model_execution_status_counts=tuple(
                (value.value, model_statuses[value.value])
                for value in ModelExecutionStatus
            )
            + (("none", model_statuses["none"]),),
            rules_only_count=states[DetectionExecutionState.RULES_ONLY.value],
            model_available_count=model_statuses[
                ModelExecutionStatus.SUCCESS.value
            ],
            model_abstained_count=sum(record.abstained for record in recent),
            model_degraded_count=sum(record.degraded for record in recent),
            stable_error_code_counts=tuple(sorted(error_codes.items())),
            example_total_rows=examples.total_rows,
            example_unique_count=examples.unique_examples,
            example_benign_label_count=examples.benign_labels,
            example_phishing_label_count=examples.phishing_labels,
            example_conflict_count=examples.conflicts,
        )


__all__ = [
    "DIAGNOSTIC_LOOKBACK_DAYS",
    "DIAGNOSTIC_MAX_ERROR_CODE_KINDS",
    "DIAGNOSTIC_MAX_EVIDENCE_RECORDS",
    "DIAGNOSTIC_MAX_SOURCE_KINDS",
    "DIAGNOSTIC_SCHEMA_VERSION",
    "DiagnosticCollectionError",
    "DiagnosticHealthStatus",
    "DiagnosticStoreHealth",
    "DiagnosticsCollector",
    "SanitizedDiagnostics",
]
