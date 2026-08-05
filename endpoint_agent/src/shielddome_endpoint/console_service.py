from collections import Counter
from collections.abc import Callable
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
import re
from uuid import uuid4

from .console_models import (
    AgentStatusSummary,
    ConfirmedExampleListItemViewModel,
    ConfirmedExamplePageViewModel,
    ConsoleHealthStatus,
    ConsoleOperationResult,
    ConsoleStatusCode,
    DailyDetectionCount,
    DashboardViewModel,
    DistributionCount,
    EventDetailViewModel,
    EventListItemViewModel,
    EventPageViewModel,
    ModelRuntimeStatus,
    StoreHealthViewModel,
)
from .domain import (
    DetectionExecutionState,
    FeatureVector,
    ModelExecutionStatus,
    RiskLevel,
)
from .diagnostic_export import DiagnosticExporter
from .diagnostics import DiagnosticsCollector
from .confirmed_examples import ExampleLabel
from .evidence_store import EvidenceStore
from .example_store import ExampleLibraryAggregate, ExampleStore
from .key_protection import default_user_data_directory
from .local_data_commands import LocalDataCommands


CONSOLE_EVIDENCE_SCAN_MAX_RECORDS = 4_096
CONSOLE_EVENT_PAGE_MAX_ITEMS = 50
CONSOLE_EVENT_PAGE_MAX_OFFSET = 4_096
CONSOLE_EXAMPLE_SCAN_MAX_ROWS = 512
CONSOLE_EXAMPLE_PAGE_MAX_ITEMS = 50
CONSOLE_EXAMPLE_PAGE_MAX_OFFSET = 256
CONSOLE_LOOKBACK_DAYS = 15
_EVIDENCE_READ_PAGE_SIZE = 100
_LOCAL_EVENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class _EvidenceQueryLimitError(RuntimeError):
    pass


class PersonalConsoleService:
    def __init__(
        self,
        *,
        evidence_store: object | None = None,
        example_store: object | None = None,
        clock: Callable[[], datetime] | None = None,
        local_timezone: tzinfo | None = None,
        example_id_factory: Callable[[], str] | None = None,
        local_data_commands: object | None = None,
    ) -> None:
        self._evidence_store = evidence_store or EvidenceStore()
        self._example_store = example_store or ExampleStore()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._local_timezone = local_timezone or datetime.now().astimezone().tzinfo
        if self._local_timezone is None:
            self._local_timezone = timezone.utc
        self._example_id_factory = example_id_factory or (lambda: uuid4().hex)
        self._example_command_targets: dict[str, tuple[str, ExampleLabel]] = {}
        if local_data_commands is not None:
            self._commands = local_data_commands
        else:
            collector = DiagnosticsCollector(
                evidence_store=self._evidence_store,
                example_store=self._example_store,
                clock=self._clock,
            )
            self._commands = LocalDataCommands(
                evidence_store=self._evidence_store,
                example_store=self._example_store,
                diagnostic_exporter=DiagnosticExporter(
                    collector=collector,
                    clock=self._clock,
                ),
                clock=self._clock,
                data_root=default_user_data_directory(),
            )

    def _now_utc(self) -> datetime:
        now = self._clock()
        if (
            not isinstance(now, datetime)
            or now.tzinfo is None
            or now.utcoffset() is None
        ):
            raise ValueError("invalid_console_time")
        return now.astimezone(timezone.utc)

    def _timezone_name(self, now_utc: datetime) -> str:
        key = getattr(self._local_timezone, "key", None)
        if isinstance(key, str) and key:
            return key
        offset = now_utc.astimezone(self._local_timezone).utcoffset()
        if offset is None:
            offset = timedelta(0)
        total_minutes = int(offset.total_seconds() // 60)
        sign = "+" if total_minutes >= 0 else "-"
        absolute_minutes = abs(total_minutes)
        hours, minutes = divmod(absolute_minutes, 60)
        return f"UTC{sign}{hours:02d}:{minutes:02d}"

    def _read_evidence(self) -> tuple[object, ...]:
        records: list[object] = []
        while len(records) < CONSOLE_EVIDENCE_SCAN_MAX_RECORDS:
            limit = min(
                _EVIDENCE_READ_PAGE_SIZE,
                CONSOLE_EVIDENCE_SCAN_MAX_RECORDS - len(records),
            )
            page = self._evidence_store.list_page(
                offset=len(records),
                limit=limit,
            )
            if not isinstance(page, tuple):
                raise RuntimeError("invalid_evidence_page")
            records.extend(page)
            if len(page) < limit:
                return tuple(records)
        extra = self._evidence_store.list_page(
            offset=CONSOLE_EVIDENCE_SCAN_MAX_RECORDS,
            limit=1,
        )
        if extra:
            raise _EvidenceQueryLimitError("query_limit_exceeded")
        return tuple(records)

    def _read_evidence_health(
        self,
    ) -> tuple[tuple[object, ...], StoreHealthViewModel, ConsoleStatusCode]:
        try:
            records = self._read_evidence()
        except _EvidenceQueryLimitError:
            return (
                (),
                StoreHealthViewModel(
                    ConsoleHealthStatus.UNAVAILABLE,
                    0,
                    "query_limit_exceeded",
                ),
                ConsoleStatusCode.QUERY_LIMIT_EXCEEDED,
            )
        except Exception:
            return (
                (),
                StoreHealthViewModel(
                    ConsoleHealthStatus.UNAVAILABLE,
                    0,
                    "evidence_store_unavailable",
                ),
                ConsoleStatusCode.EVIDENCE_STORE_UNAVAILABLE,
            )
        status = ConsoleHealthStatus.HEALTHY if records else ConsoleHealthStatus.EMPTY
        return (
            records,
            StoreHealthViewModel(status, len(records), None),
            ConsoleStatusCode.SUCCESS,
        )

    def _read_example_health(
        self,
    ) -> tuple[StoreHealthViewModel, ConsoleStatusCode]:
        try:
            aggregate = self._example_store.diagnostic_aggregate()
            if not isinstance(aggregate, ExampleLibraryAggregate):
                raise ValueError("invalid_example_aggregate")
        except Exception:
            return (
                StoreHealthViewModel(
                    ConsoleHealthStatus.UNAVAILABLE,
                    0,
                    "example_store_unavailable",
                ),
                ConsoleStatusCode.EXAMPLE_STORE_UNAVAILABLE,
            )
        status = (
            ConsoleHealthStatus.HEALTHY
            if aggregate.total_rows
            else ConsoleHealthStatus.EMPTY
        )
        return (
            StoreHealthViewModel(status, aggregate.total_rows, None),
            ConsoleStatusCode.SUCCESS,
        )

    def _recent_records(
        self,
        records: tuple[object, ...],
        now_utc: datetime,
    ) -> tuple[object, ...]:
        today = now_utc.astimezone(self._local_timezone).date()
        first_date = today - timedelta(days=CONSOLE_LOOKBACK_DAYS - 1)
        return tuple(
            record
            for record in records
            if record.detected_at.astimezone(timezone.utc) <= now_utc
            and first_date
            <= record.detected_at.astimezone(self._local_timezone).date()
            <= today
        )

    @staticmethod
    def _model_status(records: tuple[object, ...]) -> tuple[ModelRuntimeStatus, bool]:
        if not records:
            return ModelRuntimeStatus.UNKNOWN, True
        latest = records[0]
        if latest.detection_status is DetectionExecutionState.MODEL_UNCERTAIN:
            return ModelRuntimeStatus.ABSTAINED, False
        if (
            latest.model_execution_status is ModelExecutionStatus.SUCCESS
            and not latest.degraded
        ):
            return ModelRuntimeStatus.AVAILABLE, False
        if latest.detection_status is DetectionExecutionState.RULES_ONLY:
            return ModelRuntimeStatus.RULES_ONLY, True
        return ModelRuntimeStatus.DEGRADED, True

    def get_dashboard(self) -> ConsoleOperationResult:
        try:
            now_utc = self._now_utc()
            records, evidence_health, evidence_code = self._read_evidence_health()
            example_health, example_code = self._read_example_health()
            recent = self._recent_records(records, now_utc)
            local_today = now_utc.astimezone(self._local_timezone).date()
            date_counts = Counter(
                record.detected_at.astimezone(self._local_timezone).date()
                for record in recent
            )
            daily_trend = tuple(
                DailyDetectionCount(
                    (local_today - timedelta(days=offset)).isoformat(),
                    date_counts[local_today - timedelta(days=offset)],
                )
                for offset in range(CONSOLE_LOOKBACK_DAYS - 1, -1, -1)
            )
            risk_counts = Counter(record.risk_level.value for record in recent)
            source_counts = Counter(record.source_kind for record in recent)
            model_status, rules_only = self._model_status(recent)
            dashboard = DashboardViewModel(
                generated_at_utc=now_utc,
                local_timezone=self._timezone_name(now_utc),
                agent_status=AgentStatusSummary(
                    agent_status=(
                        ConsoleHealthStatus.UNAVAILABLE
                        if evidence_health.status is ConsoleHealthStatus.UNAVAILABLE
                        else ConsoleHealthStatus.HEALTHY
                    ),
                    model_status=model_status,
                    rules_only=rules_only,
                    evidence_store_health=evidence_health,
                    example_library_health=example_health,
                ),
                today_detection_count=date_counts[local_today],
                daily_trend=daily_trend,
                risk_distribution=tuple(
                    DistributionCount(level.value, risk_counts[level.value])
                    for level in RiskLevel
                ),
                source_distribution=tuple(
                    DistributionCount(source, count)
                    for source, count in sorted(source_counts.items())
                ),
                model_abstention_count=sum(record.abstained for record in recent),
                model_failure_count=sum(
                    record.model_execution_status
                    in {ModelExecutionStatus.TIMEOUT, ModelExecutionStatus.ERROR}
                    or record.detection_status
                    is DetectionExecutionState.MODEL_INVALID_OUTPUT
                    for record in recent
                ),
                rules_only_degradation_count=sum(record.degraded for record in recent),
            )
            code = evidence_code if evidence_code is not ConsoleStatusCode.SUCCESS else example_code
            return ConsoleOperationResult(code=code, payload=dashboard)
        except Exception:
            return ConsoleOperationResult(
                code=ConsoleStatusCode.INVALID_REQUEST,
                payload=None,
            )

    @staticmethod
    def _event_list_item(record: object) -> EventListItemViewModel:
        return EventListItemViewModel(
            local_event_id=record.local_event_id,
            detected_at_utc=record.detected_at.astimezone(timezone.utc),
            risk_level=record.risk_level.value,
            detection_status=record.detection_status.value,
            generic_action=record.generic_action.value,
            source_kind=record.source_kind,
            abstained=record.abstained,
            degraded=record.degraded,
            model_execution_status=(
                record.model_execution_status.value
                if record.model_execution_status is not None
                else None
            ),
            error_code=record.error_code,
        )

    def list_recent_events(
        self,
        *,
        offset: int = 0,
        limit: int = CONSOLE_EVENT_PAGE_MAX_ITEMS,
    ) -> ConsoleOperationResult:
        if (
            isinstance(offset, bool)
            or not isinstance(offset, int)
            or not 0 <= offset <= CONSOLE_EVENT_PAGE_MAX_OFFSET
            or isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= CONSOLE_EVENT_PAGE_MAX_ITEMS
        ):
            return ConsoleOperationResult(ConsoleStatusCode.INVALID_REQUEST, None)
        try:
            now_utc = self._now_utc()
            records, _health, code = self._read_evidence_health()
            if code is not ConsoleStatusCode.SUCCESS:
                return ConsoleOperationResult(code, None)
            recent = self._recent_records(records, now_utc)
            selected = recent[offset : offset + limit]
            page = EventPageViewModel(
                generated_at_utc=now_utc,
                offset=offset,
                limit=limit,
                total_matches=len(recent),
                has_more=offset + len(selected) < len(recent),
                items=tuple(self._event_list_item(record) for record in selected),
            )
            return ConsoleOperationResult(ConsoleStatusCode.SUCCESS, page)
        except Exception:
            return ConsoleOperationResult(
                ConsoleStatusCode.EVIDENCE_STORE_UNAVAILABLE,
                None,
            )

    def get_event_detail(self, local_event_id: str) -> ConsoleOperationResult:
        if (
            not isinstance(local_event_id, str)
            or _LOCAL_EVENT_ID.fullmatch(local_event_id) is None
        ):
            return ConsoleOperationResult(ConsoleStatusCode.INVALID_REQUEST, None)
        try:
            now_utc = self._now_utc()
            records, _health, code = self._read_evidence_health()
            if code is not ConsoleStatusCode.SUCCESS:
                return ConsoleOperationResult(code, None)
            record = next(
                (
                    item
                    for item in self._recent_records(records, now_utc)
                    if item.local_event_id == local_event_id
                ),
                None,
            )
            if record is None:
                return ConsoleOperationResult(ConsoleStatusCode.NOT_FOUND, None)
            detail = EventDetailViewModel(
                local_event_id=record.local_event_id,
                detected_at_utc=record.detected_at.astimezone(timezone.utc),
                risk_level=record.risk_level.value,
                detection_status=record.detection_status.value,
                generic_action=record.generic_action.value,
                source_kind=record.source_kind,
                abstained=record.abstained,
                degraded=record.degraded,
                model_execution_status=(
                    record.model_execution_status.value
                    if record.model_execution_status is not None
                    else None
                ),
                error_code=record.error_code,
                rule_codes=record.rule_codes,
            )
            return ConsoleOperationResult(ConsoleStatusCode.SUCCESS, detail)
        except Exception:
            return ConsoleOperationResult(
                ConsoleStatusCode.EVIDENCE_STORE_UNAVAILABLE,
                None,
            )

    def list_confirmed_examples(
        self,
        *,
        offset: int = 0,
        limit: int = CONSOLE_EXAMPLE_PAGE_MAX_ITEMS,
        label: ExampleLabel | None = None,
    ) -> ConsoleOperationResult:
        if (
            isinstance(offset, bool)
            or not isinstance(offset, int)
            or not 0 <= offset <= CONSOLE_EXAMPLE_PAGE_MAX_OFFSET
            or isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= CONSOLE_EXAMPLE_PAGE_MAX_ITEMS
            or not (label is None or isinstance(label, ExampleLabel))
        ):
            return ConsoleOperationResult(ConsoleStatusCode.INVALID_REQUEST, None)
        try:
            now_utc = self._now_utc()
            examples = self._example_store.list_for_calibration()
            if not isinstance(examples, tuple):
                raise RuntimeError("invalid_example_page")
            if len(examples) > CONSOLE_EXAMPLE_SCAN_MAX_ROWS:
                return ConsoleOperationResult(
                    ConsoleStatusCode.QUERY_LIMIT_EXCEEDED,
                    None,
                )
            examples = tuple(
                sorted(
                    examples,
                    key=lambda item: (
                        item.confirmed_at.astimezone(timezone.utc),
                        item.keyed_fingerprint,
                        item.label.value,
                    ),
                    reverse=True,
                )
            )
            labels_by_fingerprint: dict[str, set[ExampleLabel]] = {}
            for example in examples:
                labels_by_fingerprint.setdefault(
                    example.keyed_fingerprint,
                    set(),
                ).add(example.label)
            filtered = tuple(
                example
                for example in examples
                if label is None or example.label is label
            )
            selected = filtered[offset : offset + limit]
            self._example_command_targets.clear()
            items = []
            for example in selected:
                token = self._example_id_factory()
                if (
                    not isinstance(token, str)
                    or re.fullmatch(r"[0-9a-f]{32}", token) is None
                ):
                    raise RuntimeError("invalid_example_command_id")
                example_id = f"example-{token}"
                if example_id in self._example_command_targets:
                    raise RuntimeError("duplicate_example_command_id")
                self._example_command_targets[example_id] = (
                    example.keyed_fingerprint,
                    example.label,
                )
                items.append(
                    ConfirmedExampleListItemViewModel(
                        example_id=example_id,
                        label=example.label.value,
                        source=example.source.value,
                        confirmed_at_utc=example.confirmed_at.astimezone(timezone.utc),
                        conflict=(
                            len(labels_by_fingerprint[example.keyed_fingerprint]) > 1
                        ),
                    )
                )
            page = ConfirmedExamplePageViewModel(
                generated_at_utc=now_utc,
                offset=offset,
                limit=limit,
                total_matches=len(filtered),
                has_more=offset + len(selected) < len(filtered),
                label_filter=label.value if label is not None else None,
                items=tuple(items),
            )
            return ConsoleOperationResult(ConsoleStatusCode.SUCCESS, page)
        except Exception:
            self._example_command_targets.clear()
            return ConsoleOperationResult(
                ConsoleStatusCode.EXAMPLE_STORE_UNAVAILABLE,
                None,
            )

    def confirm_benign(
        self,
        feature_vector: FeatureVector,
        *,
        confirmed: bool,
    ) -> ConsoleOperationResult:
        try:
            return self._commands.confirm_benign(
                feature_vector,
                confirmed=confirmed,
            )
        except Exception:
            return ConsoleOperationResult(ConsoleStatusCode.COMMAND_FAILED, None)

    def confirm_phishing(
        self,
        feature_vector: FeatureVector,
        *,
        confirmed: bool,
    ) -> ConsoleOperationResult:
        try:
            return self._commands.confirm_phishing(
                feature_vector,
                confirmed=confirmed,
            )
        except Exception:
            return ConsoleOperationResult(ConsoleStatusCode.COMMAND_FAILED, None)

    def delete_confirmed_example(self, example_id: str) -> ConsoleOperationResult:
        if not isinstance(example_id, str):
            return ConsoleOperationResult(ConsoleStatusCode.INVALID_REQUEST, None)
        target = self._example_command_targets.pop(example_id, None)
        if target is None:
            return ConsoleOperationResult(ConsoleStatusCode.NOT_FOUND, None)
        try:
            return self._commands.delete_example(*target)
        except Exception:
            return ConsoleOperationResult(ConsoleStatusCode.COMMAND_FAILED, None)

    def clear_confirmed_examples(self, *, confirmed: bool) -> ConsoleOperationResult:
        self._example_command_targets.clear()
        try:
            return self._commands.clear_examples(confirmed=confirmed)
        except Exception:
            return ConsoleOperationResult(ConsoleStatusCode.COMMAND_FAILED, None)

    def export_diagnostics(
        self,
        output_path: str | Path,
        *,
        confirmed: bool,
        overwrite: bool = False,
    ) -> ConsoleOperationResult:
        try:
            return self._commands.export_diagnostics(
                output_path,
                confirmed=confirmed,
                overwrite=overwrite,
            )
        except Exception:
            return ConsoleOperationResult(ConsoleStatusCode.COMMAND_FAILED, None)

    def delete_all_local_data(self, *, confirmed: bool) -> ConsoleOperationResult:
        self._example_command_targets.clear()
        try:
            return self._commands.delete_all_local_data(confirmed=confirmed)
        except Exception:
            return ConsoleOperationResult(ConsoleStatusCode.COMMAND_FAILED, None)


__all__ = [
    "CONSOLE_EVIDENCE_SCAN_MAX_RECORDS",
    "CONSOLE_EVENT_PAGE_MAX_ITEMS",
    "CONSOLE_EVENT_PAGE_MAX_OFFSET",
    "CONSOLE_EXAMPLE_PAGE_MAX_ITEMS",
    "CONSOLE_EXAMPLE_PAGE_MAX_OFFSET",
    "CONSOLE_EXAMPLE_SCAN_MAX_ROWS",
    "CONSOLE_LOOKBACK_DAYS",
    "PersonalConsoleService",
]
