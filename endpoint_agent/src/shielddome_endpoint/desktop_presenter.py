from dataclasses import dataclass, replace
from enum import StrEnum

from .console_models import (
    ConsoleHealthStatus,
    ConsoleExampleLabel,
    ConsoleOperationResult,
    ConsoleStatusCode,
    ConfirmedExamplePageViewModel,
    DashboardViewModel,
    EventDetailViewModel,
    EventPageViewModel,
    ModelRuntimeStatus,
)


DESKTOP_EVENT_PAGE_SIZE = 10
DESKTOP_EXAMPLE_PAGE_SIZE = 10
DELETE_ALL_CONFIRMATION_TEXT = "删除全部本地数据"


class DesktopLoadState(StrEnum):
    LOADING = "loading"
    READY = "ready"
    EMPTY = "empty"
    DEGRADED = "degraded"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class ChartValue:
    key: str
    label: str
    value: int


@dataclass(frozen=True, slots=True)
class AgentStatusDisplay:
    key: str
    title: str
    detail: str
    tone: str


@dataclass(frozen=True, slots=True)
class EventRowDisplay:
    local_event_id: str
    detected_at_text: str
    risk_key: str
    risk_label: str
    detection_status_text: str
    generic_action_text: str
    source_text: str
    model_status_text: str
    degraded: bool


@dataclass(frozen=True, slots=True)
class EventDetailDisplay:
    local_event_id: str
    detected_at_text: str
    risk_key: str
    risk_label: str
    detection_status_text: str
    generic_action_text: str
    source_text: str
    model_status_text: str
    error_code_text: str
    rule_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EventPageDisplay:
    offset: int
    page_number: int
    total_pages: int
    total_matches: int
    can_previous: bool
    can_next: bool
    rows: tuple[EventRowDisplay, ...]
    empty_message: str | None


@dataclass(frozen=True, slots=True)
class ExampleRowDisplay:
    example_id: str
    confirmed_at_text: str
    label_key: str
    label_text: str
    source_text: str
    conflict: bool
    conflict_text: str


@dataclass(frozen=True, slots=True)
class ExamplePageDisplay:
    offset: int
    page_number: int
    total_pages: int
    total_matches: int
    label_filter: str | None
    can_previous: bool
    can_next: bool
    rows: tuple[ExampleRowDisplay, ...]
    empty_message: str | None


@dataclass(frozen=True, slots=True)
class DesktopConsoleState:
    load_state: DesktopLoadState
    generated_at_text: str
    timezone_text: str
    agent_status: AgentStatusDisplay
    today_count: str
    model_abstention_count: str
    model_failure_count: str
    rules_only_degradation_count: str
    trend: tuple[ChartValue, ...]
    risk_distribution: tuple[ChartValue, ...]
    source_distribution: tuple[ChartValue, ...]
    events: EventPageDisplay
    detail: EventDetailDisplay | None
    notice_title: str | None
    notice_body: str | None
    examples: ExamplePageDisplay
    operation_title: str | None
    operation_body: str | None


_RISK_LABELS = {
    "low": "低风险",
    "medium": "中风险",
    "high": "高风险",
    "critical": "严重",
}
_SOURCE_LABELS = {
    "browser_native": "浏览器插件",
    "manual_local": "本地检测",
}
_EVENT_RISK_LABELS = {
    "low": "低",
    "medium": "中",
    "high": "高",
    "critical": "严重",
}
_EVENT_SOURCE_LABELS = {
    "browser_native": "浏览器",
    "manual_local": "本地",
}
_MODEL_STATUS = {
    ModelRuntimeStatus.UNKNOWN: ("unknown", "等待检测", "尚无模型运行记录", "neutral"),
    ModelRuntimeStatus.AVAILABLE: ("available", "本地防护正常", "模型与规则链路可用", "healthy"),
    ModelRuntimeStatus.ABSTAINED: ("abstained", "模型已拒判", "本次由规则继续完成判断", "warning"),
    ModelRuntimeStatus.DEGRADED: ("degraded", "本地防护已降级", "模型故障，规则检测仍在工作", "warning"),
    ModelRuntimeStatus.RULES_ONLY: ("rules_only", "纯规则模式", "本地模型未参与最近一次检测", "warning"),
}
_DETECTION_STATUS_LABELS = {
    "model_success": "模型完成",
    "model_uncertain": "模型拒判",
    "model_unavailable": "模型不可用",
    "model_timeout": "模型超时",
    "model_error": "模型故障",
    "model_invalid_output": "模型输出无效",
    "rules_only": "纯规则完成",
}
_EVENT_STATUS_LABELS = {
    "model_success": "模型完成",
    "model_uncertain": "模型拒判",
    "model_unavailable": "不可用",
    "model_timeout": "模型超时",
    "model_error": "模型故障",
    "model_invalid_output": "输出无效",
    "rules_only": "规则完成",
}
_ACTION_LABELS = {
    "continue": "可继续查看",
    "verify_sender": "核实发件人",
    "avoid_credentials": "不要提交凭据",
    "contact_security": "联系安全人员",
}
_MODEL_EXECUTION_LABELS = {
    None: "未运行",
    "success": "运行成功",
    "unavailable": "不可用",
    "timeout": "超时",
    "error": "故障",
}


def _empty_event_page() -> EventPageDisplay:
    return EventPageDisplay(
        offset=0,
        page_number=1,
        total_pages=1,
        total_matches=0,
        can_previous=False,
        can_next=False,
        rows=(),
        empty_message="最近 15 天没有检测事件",
    )


def _empty_example_page() -> ExamplePageDisplay:
    return ExamplePageDisplay(0, 1, 1, 0, None, False, False, (), "暂无已确认样本")


def _initial_state(load_state: DesktopLoadState) -> DesktopConsoleState:
    return DesktopConsoleState(
        load_state=load_state,
        generated_at_text="—",
        timezone_text="本地时间",
        agent_status=AgentStatusDisplay(
            key="unknown",
            title="正在读取本地状态" if load_state is DesktopLoadState.LOADING else "状态不可用",
            detail="数据只从当前用户的本地加密记录读取",
            tone="neutral" if load_state is DesktopLoadState.LOADING else "danger",
        ),
        today_count="—" if load_state is DesktopLoadState.LOADING else "0",
        model_abstention_count="—" if load_state is DesktopLoadState.LOADING else "0",
        model_failure_count="—" if load_state is DesktopLoadState.LOADING else "0",
        rules_only_degradation_count="—" if load_state is DesktopLoadState.LOADING else "0",
        trend=(),
        risk_distribution=(),
        source_distribution=(),
        events=_empty_event_page(),
        detail=None,
        notice_title=None,
        notice_body=None,
        examples=_empty_example_page(),
        operation_title=None,
        operation_body=None,
    )


class PersonalConsolePresenter:
    def __init__(self, console_service: object) -> None:
        self._service = console_service
        self._event_offset = 0
        self._example_offset = 0
        self._example_label: ConsoleExampleLabel | None = None
        self._state = _initial_state(DesktopLoadState.LOADING)

    @property
    def state(self) -> DesktopConsoleState:
        return self._state

    def refresh(self) -> DesktopConsoleState:
        self._event_offset = 0
        try:
            dashboard_result = self._service.get_dashboard()
            event_result = self._service.list_recent_events(
                offset=0,
                limit=DESKTOP_EVENT_PAGE_SIZE,
            )
            self._state = self._map_results(dashboard_result, event_result)
        except Exception:
            self._state = self._error_state()
        return self._state

    def next_events(self) -> DesktopConsoleState:
        if not self._state.events.can_next:
            return self._state
        return self._load_event_page(
            self._state.events.offset + DESKTOP_EVENT_PAGE_SIZE
        )

    def previous_events(self) -> DesktopConsoleState:
        if not self._state.events.can_previous:
            return self._state
        return self._load_event_page(
            max(0, self._state.events.offset - DESKTOP_EVENT_PAGE_SIZE)
        )

    def select_event(self, local_event_id: str) -> DesktopConsoleState:
        try:
            result = self._service.get_event_detail(local_event_id)
            if (
                not isinstance(result, ConsoleOperationResult)
                or result.code is not ConsoleStatusCode.SUCCESS
                or not isinstance(result.payload, EventDetailViewModel)
            ):
                self._state = replace(
                    self._state,
                    detail=None,
                    notice_title="无法显示事件详情",
                    notice_body="该事件可能已到期或本地记录暂时不可读。",
                )
                return self._state
            self._state = replace(
                self._state,
                detail=self._event_detail(result.payload),
            )
        except Exception:
            self._state = replace(
                self._state,
                detail=None,
                notice_title="无法显示事件详情",
                notice_body="该事件可能已到期或本地记录暂时不可读。",
            )
        return self._state

    def refresh_examples(self, label: str | None = None) -> DesktopConsoleState:
        mapping = {None: None, "benign": ConsoleExampleLabel.BENIGN, "phishing": ConsoleExampleLabel.PHISHING}
        if label not in mapping:
            return replace(self._state, operation_title="无法筛选样本", operation_body="请选择全部、正常或钓鱼。")
        self._example_label = mapping[label]
        self._example_offset = 0
        return self._load_examples()

    def _confirm_event(self, local_event_id: str, *, confirmed: bool, phishing: bool) -> DesktopConsoleState:
        if confirmed is not True:
            self._state = replace(self._state, operation_title="已取消确认", operation_body="未保存任何样本。")
            return self._state
        try:
            method = self._service.confirm_event_phishing if phishing else self._service.confirm_event_benign
            result = method(local_event_id, confirmed=True)
            if result.code in {ConsoleStatusCode.EXAMPLE_ADDED, ConsoleStatusCode.EXAMPLE_DUPLICATE, ConsoleStatusCode.EXAMPLE_CONFLICT}:
                self._load_examples()
                self._state = replace(self._state, operation_title="确认已保存", operation_body="仅保存脱敏特征；邮件原文和附件未保存。")
            elif result.code in {ConsoleStatusCode.PENDING_CONTEXT_NOT_FOUND, ConsoleStatusCode.PENDING_CONTEXT_EXPIRED}:
                self._state = replace(self._state, operation_title="无法确认该事件", operation_body="待确认上下文不存在或已过期。")
            else:
                self._state = replace(self._state, operation_title="确认失败", operation_body="本地待确认数据暂时不可用，未删除可用上下文。")
        except Exception:
            self._state = replace(self._state, operation_title="确认失败", operation_body="本地待确认数据暂时不可用。")
        return self._state

    def confirm_event_benign(self, local_event_id: str, *, confirmed: bool) -> DesktopConsoleState:
        return self._confirm_event(local_event_id, confirmed=confirmed, phishing=False)

    def confirm_event_phishing(self, local_event_id: str, *, confirmed: bool) -> DesktopConsoleState:
        return self._confirm_event(local_event_id, confirmed=confirmed, phishing=True)

    def next_examples(self) -> DesktopConsoleState:
        if self._state.examples.can_next:
            self._example_offset += DESKTOP_EXAMPLE_PAGE_SIZE
            return self._load_examples()
        return self._state

    def previous_examples(self) -> DesktopConsoleState:
        if self._state.examples.can_previous:
            self._example_offset = max(0, self._example_offset - DESKTOP_EXAMPLE_PAGE_SIZE)
            return self._load_examples()
        return self._state

    def _load_examples(self) -> DesktopConsoleState:
        try:
            result = self._service.list_confirmed_examples(
                offset=self._example_offset,
                limit=DESKTOP_EXAMPLE_PAGE_SIZE,
                label=self._example_label,
            )
            if result.code is not ConsoleStatusCode.SUCCESS or not isinstance(result.payload, ConfirmedExamplePageViewModel):
                raise RuntimeError("example_page_unavailable")
            page = result.payload
            total_pages = max(1, (page.total_matches + DESKTOP_EXAMPLE_PAGE_SIZE - 1) // DESKTOP_EXAMPLE_PAGE_SIZE)
            display = ExamplePageDisplay(
                page.offset,
                page.offset // DESKTOP_EXAMPLE_PAGE_SIZE + 1,
                total_pages,
                page.total_matches,
                page.label_filter,
                page.offset > 0,
                page.has_more,
                tuple(
                    ExampleRowDisplay(
                        item.example_id,
                        item.confirmed_at_utc.strftime("%Y-%m-%d %H:%M UTC"),
                        item.label,
                        "正常" if item.label == "benign" else "钓鱼",
                        {"browser_native": "浏览器插件", "manual_local": "本地检测"}.get(item.source, item.source),
                        item.conflict,
                        "有冲突" if item.conflict else "无冲突",
                    )
                    for item in page.items
                ),
                "暂无已确认样本" if not page.items else None,
            )
            self._state = replace(self._state, examples=display, operation_title=None, operation_body=None)
        except Exception:
            self._state = replace(self._state, operation_title="无法读取样本库", operation_body="本地样本暂时不可用，请稍后重试。")
        return self._state

    def delete_example(self, example_id: str, *, confirmed: bool) -> DesktopConsoleState:
        if confirmed is not True:
            return replace(self._state, operation_title="已取消删除", operation_body="样本未更改。")
        try:
            result = self._service.delete_confirmed_example(example_id)
            if result.code is not ConsoleStatusCode.SUCCESS:
                raise RuntimeError("delete_failed")
            self._load_examples()
            self._state = replace(self._state, operation_title="样本已删除", operation_body="样本库已刷新。")
            return self._state
        except Exception:
            self._state = replace(self._state, operation_title="无法删除样本", operation_body="样本未更改，请稍后重试。")
            return self._state

    def clear_examples(self, *, confirmed: bool) -> DesktopConsoleState:
        if confirmed is not True:
            return replace(self._state, operation_title="已取消清空", operation_body="样本库未更改。")
        try:
            result = self._service.clear_confirmed_examples(confirmed=True)
            if result.code is not ConsoleStatusCode.SUCCESS:
                raise RuntimeError("clear_failed")
            self._example_offset = 0
            self._load_examples()
            self._state = replace(self._state, operation_title="样本库已清空", operation_body="列表已刷新。")
            return self._state
        except Exception:
            self._state = replace(self._state, operation_title="无法清空样本库", operation_body="样本未更改，请稍后重试。")
            return self._state

    def export_diagnostics(self, output_path, *, confirmed: bool, overwrite: bool = False) -> DesktopConsoleState:
        if not output_path or confirmed is not True:
            self._state = replace(self._state, operation_title="已取消导出", operation_body="未创建诊断包。")
            return self._state
        try:
            result = self._service.export_diagnostics(output_path, confirmed=True, overwrite=overwrite)
            if result.code is ConsoleStatusCode.DIAGNOSTIC_OUTPUT_EXISTS:
                return replace(self._state, operation_title="目标文件已存在", operation_body="如需覆盖，请再次确认。")
            if result.code is not ConsoleStatusCode.DIAGNOSTIC_EXPORTED:
                raise RuntimeError("export_failed")
            self._state = replace(self._state, operation_title="诊断包已导出", operation_body="文件已保存到所选位置。")
        except Exception:
            self._state = replace(self._state, operation_title="无法导出诊断包", operation_body="未创建诊断包，请稍后重试。")
        return self._state

    def delete_all_local_data(self, *, first_confirmed: bool, confirmation_text: str) -> DesktopConsoleState:
        if first_confirmed is not True or confirmation_text != DELETE_ALL_CONFIRMATION_TEXT:
            self._state = replace(self._state, operation_title="已取消删除", operation_body="本地数据未更改。")
            return self._state
        try:
            result = self._service.delete_all_local_data(confirmed=True)
            if result.code is not ConsoleStatusCode.SUCCESS:
                raise RuntimeError("delete_all_failed")
            self._state = self.refresh()
            self.refresh_examples(self._example_label.value if self._example_label else None)
            self._state = replace(self._state, operation_title="全部本地数据已删除", operation_body="看板和样本库已刷新。")
            return self._state
        except Exception:
            self._state = replace(self._state, operation_title="无法删除全部本地数据", operation_body="部分或全部数据未删除，请稍后重试。")
            return self._state

    def _load_event_page(self, offset: int) -> DesktopConsoleState:
        try:
            result = self._service.list_recent_events(
                offset=offset,
                limit=DESKTOP_EVENT_PAGE_SIZE,
            )
            if (
                not isinstance(result, ConsoleOperationResult)
                or result.code is not ConsoleStatusCode.SUCCESS
                or not isinstance(result.payload, EventPageViewModel)
            ):
                raise RuntimeError("event_page_unavailable")
            self._event_offset = offset
            self._state = replace(
                self._state,
                events=self._event_page(result.payload),
                detail=None,
            )
        except Exception:
            self._state = replace(
                self._state,
                notice_title="无法读取最近事件",
                notice_body="当前页保持不变；请稍后刷新个人安全看板。",
            )
        return self._state

    def _map_results(
        self,
        dashboard_result: object,
        event_result: object,
    ) -> DesktopConsoleState:
        if (
            not isinstance(dashboard_result, ConsoleOperationResult)
            or not isinstance(dashboard_result.payload, DashboardViewModel)
        ):
            return self._error_state()
        dashboard = dashboard_result.payload
        evidence_unavailable = (
            dashboard.agent_status.evidence_store_health.status
            is ConsoleHealthStatus.UNAVAILABLE
        )
        any_events = sum(item.count for item in dashboard.daily_trend) > 0
        if evidence_unavailable or (dashboard.agent_status.rules_only and any_events):
            load_state = DesktopLoadState.DEGRADED
        elif not any_events:
            load_state = DesktopLoadState.EMPTY
        else:
            load_state = DesktopLoadState.READY

        status_values = _MODEL_STATUS[dashboard.agent_status.model_status]
        notice_title = None
        notice_body = None
        if evidence_unavailable:
            notice_title = "本地记录暂时不可读"
            notice_body = "检测保护仍可运行；请稍后刷新，若持续出现请联系支持人员。"
        elif dashboard.agent_status.rules_only and any_events:
            notice_title = "当前使用纯规则检测"
            notice_body = "模型未参与最近一次检测，确定性规则结果仍然保留。"
        elif not any_events:
            notice_title = "暂无本地检测记录"
            notice_body = "最近 15 天没有检测事件；新结果会在完成本地检测后显示。"

        event_page = _empty_event_page()
        if (
            isinstance(event_result, ConsoleOperationResult)
            and event_result.code is ConsoleStatusCode.SUCCESS
            and isinstance(event_result.payload, EventPageViewModel)
        ):
            event_page = self._event_page(event_result.payload)

        return DesktopConsoleState(
            load_state=load_state,
            generated_at_text=dashboard.generated_at_utc.strftime("%Y-%m-%d %H:%M UTC"),
            timezone_text=dashboard.local_timezone,
            agent_status=AgentStatusDisplay(*status_values),
            today_count=str(dashboard.today_detection_count),
            model_abstention_count=str(dashboard.model_abstention_count),
            model_failure_count=str(dashboard.model_failure_count),
            rules_only_degradation_count=str(dashboard.rules_only_degradation_count),
            trend=tuple(
                ChartValue(item.local_date, item.local_date[5:], item.count)
                for item in dashboard.daily_trend
            ),
            risk_distribution=tuple(
                ChartValue(item.category, _RISK_LABELS[item.category], item.count)
                for item in dashboard.risk_distribution
            ),
            source_distribution=tuple(
                ChartValue(
                    item.category,
                    _SOURCE_LABELS.get(item.category, item.category),
                    item.count,
                )
                for item in dashboard.source_distribution
            ),
            events=event_page,
            detail=None,
            notice_title=notice_title,
            notice_body=notice_body,
            examples=self._state.examples,
            operation_title=self._state.operation_title,
            operation_body=self._state.operation_body,
        )

    @staticmethod
    def _event_row(item: object) -> EventRowDisplay:
        return EventRowDisplay(
            local_event_id=item.local_event_id,
            detected_at_text=item.detected_at_utc.strftime("%m-%d %H:%M"),
            risk_key=item.risk_level,
            risk_label=_EVENT_RISK_LABELS[item.risk_level],
            detection_status_text=_EVENT_STATUS_LABELS[item.detection_status],
            generic_action_text=_ACTION_LABELS[item.generic_action],
            source_text=_EVENT_SOURCE_LABELS.get(item.source_kind, item.source_kind),
            model_status_text=_MODEL_EXECUTION_LABELS[item.model_execution_status],
            degraded=item.degraded,
        )

    @classmethod
    def _event_page(cls, page: EventPageViewModel) -> EventPageDisplay:
        total_pages = max(
            1,
            (page.total_matches + DESKTOP_EVENT_PAGE_SIZE - 1)
            // DESKTOP_EVENT_PAGE_SIZE,
        )
        return EventPageDisplay(
            offset=page.offset,
            page_number=page.offset // DESKTOP_EVENT_PAGE_SIZE + 1,
            total_pages=total_pages,
            total_matches=page.total_matches,
            can_previous=page.offset > 0,
            can_next=page.has_more,
            rows=tuple(cls._event_row(item) for item in page.items),
            empty_message="最近 15 天没有检测事件" if not page.items else None,
        )

    @staticmethod
    def _event_detail(detail: EventDetailViewModel) -> EventDetailDisplay:
        return EventDetailDisplay(
            local_event_id=detail.local_event_id,
            detected_at_text=detail.detected_at_utc.strftime("%Y-%m-%d %H:%M UTC"),
            risk_key=detail.risk_level,
            risk_label=_RISK_LABELS[detail.risk_level],
            detection_status_text=_DETECTION_STATUS_LABELS[detail.detection_status],
            generic_action_text=_ACTION_LABELS[detail.generic_action],
            source_text=_SOURCE_LABELS.get(detail.source_kind, detail.source_kind),
            model_status_text=_MODEL_EXECUTION_LABELS[detail.model_execution_status],
            error_code_text=detail.error_code or "无",
            rule_codes=detail.rule_codes,
        )

    @staticmethod
    def _error_state() -> DesktopConsoleState:
        state = _initial_state(DesktopLoadState.ERROR)
        return DesktopConsoleState(
            load_state=state.load_state,
            generated_at_text=state.generated_at_text,
            timezone_text=state.timezone_text,
            agent_status=state.agent_status,
            today_count=state.today_count,
            model_abstention_count=state.model_abstention_count,
            model_failure_count=state.model_failure_count,
            rules_only_degradation_count=state.rules_only_degradation_count,
            trend=state.trend,
            risk_distribution=state.risk_distribution,
            source_distribution=state.source_distribution,
            events=state.events,
            detail=state.detail,
            notice_title="无法读取个人安全看板",
            notice_body="请确认本地 Agent 正在运行后重试；界面不会显示内部错误详情。",
            examples=state.examples,
            operation_title=state.operation_title,
            operation_body=state.operation_body,
        )


__all__ = [
    "DESKTOP_EVENT_PAGE_SIZE",
    "DESKTOP_EXAMPLE_PAGE_SIZE",
    "DELETE_ALL_CONFIRMATION_TEXT",
    "AgentStatusDisplay",
    "ChartValue",
    "DesktopConsoleState",
    "DesktopLoadState",
    "EventDetailDisplay",
    "EventPageDisplay",
    "EventRowDisplay",
    "ExamplePageDisplay",
    "ExampleRowDisplay",
    "PersonalConsolePresenter",
]
