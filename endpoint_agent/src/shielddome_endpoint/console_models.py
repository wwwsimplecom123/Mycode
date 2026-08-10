from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
import re


CONSOLE_VIEW_MODEL_SCHEMA_VERSION = "1.0"

_CATEGORY = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_LOCAL_TIMEZONE = re.compile(r"^[A-Za-z0-9_+./:-]{1,64}$")
_LOCAL_EVENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_EXAMPLE_ID = re.compile(r"^example-[0-9a-f]{32}$")
_RISK_LEVELS = frozenset({"low", "medium", "high", "critical"})
_DETECTION_STATES = frozenset(
    {
        "model_success",
        "model_uncertain",
        "model_unavailable",
        "model_timeout",
        "model_error",
        "model_invalid_output",
        "rules_only",
    }
)
_GENERIC_ACTIONS = frozenset(
    {"continue", "verify_sender", "avoid_credentials", "contact_security"}
)
_MODEL_EXECUTION_STATUSES = frozenset({"success", "unavailable", "timeout", "error"})
_EXAMPLE_LABELS = frozenset({"benign", "phishing"})


class ConsoleHealthStatus(StrEnum):
    HEALTHY = "healthy"
    EMPTY = "empty"
    UNAVAILABLE = "unavailable"


class ModelRuntimeStatus(StrEnum):
    UNKNOWN = "unknown"
    AVAILABLE = "available"
    ABSTAINED = "abstained"
    DEGRADED = "degraded"
    RULES_ONLY = "rules_only"


class ConsoleStatusCode(StrEnum):
    SUCCESS = "success"
    INVALID_REQUEST = "invalid_request"
    NOT_FOUND = "not_found"
    CONFIRMATION_REQUIRED = "confirmation_required"
    QUERY_LIMIT_EXCEEDED = "query_limit_exceeded"
    EVIDENCE_STORE_UNAVAILABLE = "evidence_store_unavailable"
    EXAMPLE_STORE_UNAVAILABLE = "example_store_unavailable"
    EXAMPLE_ADDED = "example_added"
    EXAMPLE_DUPLICATE = "example_duplicate"
    EXAMPLE_CONFLICT = "example_conflict"
    EXAMPLE_CAPACITY_EXCEEDED = "example_capacity_exceeded"
    DIAGNOSTIC_EXPORTED = "diagnostic_exported"
    DIAGNOSTIC_OUTPUT_EXISTS = "diagnostic_output_exists"
    DIAGNOSTIC_EXPORT_FAILED = "diagnostic_export_failed"
    LOCAL_DATA_DELETE_PARTIAL_FAILURE = "local_data_delete_partial_failure"
    COMMAND_FAILED = "command_failed"


class ConsoleExampleLabel(StrEnum):
    BENIGN = "benign"
    PHISHING = "phishing"


def _valid_count(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= 0


def _valid_utc_time(value: object) -> bool:
    return (
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() == timezone.utc.utcoffset(value)
    )


def _valid_schema(value: object) -> bool:
    return value == CONSOLE_VIEW_MODEL_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class ConsoleOperationResult:
    code: ConsoleStatusCode
    payload: object | None
    affected_items: int = 0
    schema_version: str = CONSOLE_VIEW_MODEL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            not isinstance(self.code, ConsoleStatusCode)
            or not (
                self.payload is None
                or isinstance(
                    self.payload,
                    (
                        DashboardViewModel,
                        EventDetailViewModel,
                        EventPageViewModel,
                        ConfirmedExamplePageViewModel,
                    ),
                )
            )
            or not _valid_count(self.affected_items)
            or not _valid_schema(self.schema_version)
        ):
            raise ValueError("invalid_console_result")


@dataclass(frozen=True, slots=True)
class StoreHealthViewModel:
    status: ConsoleHealthStatus
    item_count: int
    error_code: str | None
    schema_version: str = CONSOLE_VIEW_MODEL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        unavailable = self.status is ConsoleHealthStatus.UNAVAILABLE
        if (
            not isinstance(self.status, ConsoleHealthStatus)
            or not _valid_count(self.item_count)
            or (unavailable and (self.item_count != 0 or self.error_code is None))
            or (not unavailable and self.error_code is not None)
            or (self.status is ConsoleHealthStatus.EMPTY and self.item_count != 0)
            or (self.status is ConsoleHealthStatus.HEALTHY and self.item_count == 0)
            or (
                self.error_code is not None
                and (
                    not isinstance(self.error_code, str)
                    or _CATEGORY.fullmatch(self.error_code) is None
                )
            )
            or not _valid_schema(self.schema_version)
        ):
            raise ValueError("invalid_console_view_model")


@dataclass(frozen=True, slots=True)
class AgentStatusSummary:
    agent_status: ConsoleHealthStatus
    model_status: ModelRuntimeStatus
    rules_only: bool
    evidence_store_health: StoreHealthViewModel
    example_library_health: StoreHealthViewModel
    schema_version: str = CONSOLE_VIEW_MODEL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            not isinstance(self.agent_status, ConsoleHealthStatus)
            or not isinstance(self.model_status, ModelRuntimeStatus)
            or not isinstance(self.rules_only, bool)
            or not isinstance(self.evidence_store_health, StoreHealthViewModel)
            or not isinstance(self.example_library_health, StoreHealthViewModel)
            or not _valid_schema(self.schema_version)
        ):
            raise ValueError("invalid_console_view_model")


@dataclass(frozen=True, slots=True)
class DailyDetectionCount:
    local_date: str
    count: int
    schema_version: str = CONSOLE_VIEW_MODEL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        try:
            valid_date = datetime.strptime(self.local_date, "%Y-%m-%d").date().isoformat()
        except (TypeError, ValueError):
            valid_date = None
        if (
            valid_date != self.local_date
            or not _valid_count(self.count)
            or not _valid_schema(self.schema_version)
        ):
            raise ValueError("invalid_console_view_model")


@dataclass(frozen=True, slots=True)
class DistributionCount:
    category: str
    count: int
    schema_version: str = CONSOLE_VIEW_MODEL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            not isinstance(self.category, str)
            or _CATEGORY.fullmatch(self.category) is None
            or not _valid_count(self.count)
            or not _valid_schema(self.schema_version)
        ):
            raise ValueError("invalid_console_view_model")


@dataclass(frozen=True, slots=True)
class DashboardViewModel:
    generated_at_utc: datetime
    local_timezone: str
    agent_status: AgentStatusSummary
    today_detection_count: int
    daily_trend: tuple[DailyDetectionCount, ...]
    risk_distribution: tuple[DistributionCount, ...]
    source_distribution: tuple[DistributionCount, ...]
    model_abstention_count: int
    model_failure_count: int
    rules_only_degradation_count: int
    schema_version: str = CONSOLE_VIEW_MODEL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            not isinstance(self.daily_trend, tuple)
            or not all(isinstance(item, DailyDetectionCount) for item in self.daily_trend)
            or not isinstance(self.risk_distribution, tuple)
            or not all(isinstance(item, DistributionCount) for item in self.risk_distribution)
            or not isinstance(self.source_distribution, tuple)
            or not all(isinstance(item, DistributionCount) for item in self.source_distribution)
        ):
            raise ValueError("invalid_console_view_model")
        daily_dates = tuple(item.local_date for item in self.daily_trend)
        risk_categories = tuple(item.category for item in self.risk_distribution)
        source_categories = tuple(item.category for item in self.source_distribution)
        risk_positions = tuple(
            ("low", "medium", "high", "critical").index(category)
            for category in risk_categories
            if category in _RISK_LEVELS
        )
        if (
            not _valid_utc_time(self.generated_at_utc)
            or not isinstance(self.local_timezone, str)
            or _LOCAL_TIMEZONE.fullmatch(self.local_timezone) is None
            or not isinstance(self.agent_status, AgentStatusSummary)
            or any(
                not _valid_count(value)
                for value in (
                    self.today_detection_count,
                    self.model_abstention_count,
                    self.model_failure_count,
                    self.rules_only_degradation_count,
                )
            )
            or daily_dates != tuple(sorted(set(daily_dates)))
            or len(risk_positions) != len(risk_categories)
            or risk_positions != tuple(sorted(set(risk_positions)))
            or source_categories != tuple(sorted(set(source_categories)))
            or not _valid_schema(self.schema_version)
        ):
            raise ValueError("invalid_console_view_model")


def _valid_event_values(
    *,
    local_event_id: object,
    detected_at_utc: object,
    risk_level: object,
    detection_status: object,
    generic_action: object,
    source_kind: object,
    abstained: object,
    degraded: object,
    model_execution_status: object,
    error_code: object,
) -> bool:
    return (
        isinstance(local_event_id, str)
        and _LOCAL_EVENT_ID.fullmatch(local_event_id) is not None
        and _valid_utc_time(detected_at_utc)
        and risk_level in _RISK_LEVELS
        and detection_status in _DETECTION_STATES
        and generic_action in _GENERIC_ACTIONS
        and isinstance(source_kind, str)
        and _CATEGORY.fullmatch(source_kind) is not None
        and isinstance(abstained, bool)
        and isinstance(degraded, bool)
        and (
            model_execution_status is None
            or model_execution_status in _MODEL_EXECUTION_STATUSES
        )
        and (
            error_code is None
            or (
                isinstance(error_code, str)
                and _CATEGORY.fullmatch(error_code) is not None
            )
        )
    )


@dataclass(frozen=True, slots=True)
class EventListItemViewModel:
    local_event_id: str
    detected_at_utc: datetime
    risk_level: str
    detection_status: str
    generic_action: str
    source_kind: str
    abstained: bool
    degraded: bool
    model_execution_status: str | None
    error_code: str | None
    schema_version: str = CONSOLE_VIEW_MODEL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not _valid_event_values(
            local_event_id=self.local_event_id,
            detected_at_utc=self.detected_at_utc,
            risk_level=self.risk_level,
            detection_status=self.detection_status,
            generic_action=self.generic_action,
            source_kind=self.source_kind,
            abstained=self.abstained,
            degraded=self.degraded,
            model_execution_status=self.model_execution_status,
            error_code=self.error_code,
        ) or not _valid_schema(self.schema_version):
            raise ValueError("invalid_console_view_model")


@dataclass(frozen=True, slots=True)
class EventDetailViewModel:
    local_event_id: str
    detected_at_utc: datetime
    risk_level: str
    detection_status: str
    generic_action: str
    source_kind: str
    abstained: bool
    degraded: bool
    model_execution_status: str | None
    error_code: str | None
    rule_codes: tuple[str, ...]
    schema_version: str = CONSOLE_VIEW_MODEL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            not _valid_event_values(
                local_event_id=self.local_event_id,
                detected_at_utc=self.detected_at_utc,
                risk_level=self.risk_level,
                detection_status=self.detection_status,
                generic_action=self.generic_action,
                source_kind=self.source_kind,
                abstained=self.abstained,
                degraded=self.degraded,
                model_execution_status=self.model_execution_status,
                error_code=self.error_code,
            )
            or not isinstance(self.rule_codes, tuple)
            or len(self.rule_codes) > 64
            or len(set(self.rule_codes)) != len(self.rule_codes)
            or any(
                not isinstance(code, str) or _CATEGORY.fullmatch(code) is None
                for code in self.rule_codes
            )
            or not _valid_schema(self.schema_version)
        ):
            raise ValueError("invalid_console_view_model")


@dataclass(frozen=True, slots=True)
class EventPageViewModel:
    generated_at_utc: datetime
    offset: int
    limit: int
    total_matches: int
    has_more: bool
    items: tuple[EventListItemViewModel, ...]
    schema_version: str = CONSOLE_VIEW_MODEL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            not _valid_utc_time(self.generated_at_utc)
            or not _valid_count(self.offset)
            or self.offset > 4_096
            or not _valid_count(self.limit)
            or not 1 <= self.limit <= 50
            or not _valid_count(self.total_matches)
            or not isinstance(self.has_more, bool)
            or not isinstance(self.items, tuple)
            or len(self.items) > self.limit
            or not all(isinstance(item, EventListItemViewModel) for item in self.items)
            or self.has_more != (self.offset + len(self.items) < self.total_matches)
            or not _valid_schema(self.schema_version)
        ):
            raise ValueError("invalid_console_view_model")


@dataclass(frozen=True, slots=True)
class ConfirmedExampleListItemViewModel:
    example_id: str
    label: str
    source: str
    confirmed_at_utc: datetime
    conflict: bool
    schema_version: str = CONSOLE_VIEW_MODEL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            not isinstance(self.example_id, str)
            or _EXAMPLE_ID.fullmatch(self.example_id) is None
            or self.label not in _EXAMPLE_LABELS
            or not isinstance(self.source, str)
            or _CATEGORY.fullmatch(self.source) is None
            or not _valid_utc_time(self.confirmed_at_utc)
            or not isinstance(self.conflict, bool)
            or not _valid_schema(self.schema_version)
        ):
            raise ValueError("invalid_console_view_model")


@dataclass(frozen=True, slots=True)
class ConfirmedExamplePageViewModel:
    generated_at_utc: datetime
    offset: int
    limit: int
    total_matches: int
    has_more: bool
    label_filter: str | None
    items: tuple[ConfirmedExampleListItemViewModel, ...]
    schema_version: str = CONSOLE_VIEW_MODEL_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            not _valid_utc_time(self.generated_at_utc)
            or not _valid_count(self.offset)
            or self.offset > 256
            or not _valid_count(self.limit)
            or not 1 <= self.limit <= 50
            or not _valid_count(self.total_matches)
            or not isinstance(self.has_more, bool)
            or not (self.label_filter is None or self.label_filter in _EXAMPLE_LABELS)
            or not isinstance(self.items, tuple)
            or len(self.items) > self.limit
            or not all(
                isinstance(item, ConfirmedExampleListItemViewModel)
                for item in self.items
            )
            or self.has_more != (self.offset + len(self.items) < self.total_matches)
            or not _valid_schema(self.schema_version)
        ):
            raise ValueError("invalid_console_view_model")


__all__ = [
    "CONSOLE_VIEW_MODEL_SCHEMA_VERSION",
    "AgentStatusSummary",
    "ConsoleHealthStatus",
    "ConsoleExampleLabel",
    "ConsoleOperationResult",
    "ConsoleStatusCode",
    "ConfirmedExampleListItemViewModel",
    "ConfirmedExamplePageViewModel",
    "DailyDetectionCount",
    "DashboardViewModel",
    "DistributionCount",
    "EventDetailViewModel",
    "EventListItemViewModel",
    "EventPageViewModel",
    "ModelRuntimeStatus",
    "StoreHealthViewModel",
]
