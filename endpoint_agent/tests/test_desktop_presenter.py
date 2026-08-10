from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))


NOW = datetime(2026, 8, 10, 9, 30, tzinfo=timezone.utc)


def make_dashboard(*, today_count=4, rules_only=False, evidence_unavailable=False):
    from shielddome_endpoint.console_models import (
        AgentStatusSummary,
        ConsoleHealthStatus,
        DailyDetectionCount,
        DashboardViewModel,
        DistributionCount,
        ModelRuntimeStatus,
        StoreHealthViewModel,
    )

    first = NOW.date() - timedelta(days=14)
    return DashboardViewModel(
        generated_at_utc=NOW,
        local_timezone="Asia/Shanghai",
        agent_status=AgentStatusSummary(
            agent_status=(
                ConsoleHealthStatus.UNAVAILABLE
                if evidence_unavailable
                else ConsoleHealthStatus.HEALTHY
            ),
            model_status=(
                ModelRuntimeStatus.RULES_ONLY
                if rules_only
                else ModelRuntimeStatus.AVAILABLE
            ),
            rules_only=rules_only,
            evidence_store_health=StoreHealthViewModel(
                status=(
                    ConsoleHealthStatus.UNAVAILABLE
                    if evidence_unavailable
                    else (
                        ConsoleHealthStatus.HEALTHY
                        if today_count
                        else ConsoleHealthStatus.EMPTY
                    )
                ),
                item_count=0 if evidence_unavailable else today_count,
                error_code=(
                    "evidence_store_unavailable" if evidence_unavailable else None
                ),
            ),
            example_library_health=StoreHealthViewModel(
                status=ConsoleHealthStatus.EMPTY,
                item_count=0,
                error_code=None,
            ),
        ),
        today_detection_count=today_count,
        daily_trend=tuple(
            DailyDetectionCount(
                (first + timedelta(days=index)).isoformat(),
                today_count if index == 14 else 0,
            )
            for index in range(15)
        ),
        risk_distribution=tuple(
            DistributionCount(key, 1)
            for key in ("low", "medium", "high", "critical")
        ),
        source_distribution=(
            DistributionCount("browser_native", 3),
            DistributionCount("manual_local", 1),
        ),
        model_abstention_count=2,
        model_failure_count=1,
        rules_only_degradation_count=1,
    )


def make_empty_event_page(*, offset=0, limit=10):
    from shielddome_endpoint.console_models import EventPageViewModel

    return EventPageViewModel(
        generated_at_utc=NOW,
        offset=offset,
        limit=limit,
        total_matches=0,
        has_more=False,
        items=(),
    )


class StaticConsoleService:
    def __init__(self, dashboard_result, event_result, detail_results=None):
        self.dashboard_result = dashboard_result
        self.event_result = event_result
        self.detail_results = detail_results or {}
        self.event_calls = []

    def get_dashboard(self):
        return self.dashboard_result

    def list_recent_events(self, *, offset=0, limit=50):
        self.event_calls.append((offset, limit))
        return self.event_result

    def get_event_detail(self, local_event_id):
        return self.detail_results[local_event_id]


def make_event(local_event_id, index=0):
    from shielddome_endpoint.console_models import EventListItemViewModel

    return EventListItemViewModel(
        local_event_id=local_event_id,
        detected_at_utc=NOW - timedelta(minutes=index),
        risk_level=("low", "medium", "high", "critical")[index % 4],
        detection_status="model_success",
        generic_action="verify_sender",
        source_kind="browser_native",
        abstained=False,
        degraded=False,
        model_execution_status="success",
        error_code=None,
    )


class PagingConsoleService:
    def __init__(self, dashboard_result, events):
        self.dashboard_result = dashboard_result
        self.events = tuple(events)
        self.event_calls = []

    def get_dashboard(self):
        return self.dashboard_result

    def list_recent_events(self, *, offset=0, limit=50):
        from shielddome_endpoint.console_models import (
            ConsoleOperationResult,
            ConsoleStatusCode,
            EventPageViewModel,
        )

        self.event_calls.append((offset, limit))
        selected = self.events[offset : offset + limit]
        return ConsoleOperationResult(
            ConsoleStatusCode.SUCCESS,
            EventPageViewModel(
                generated_at_utc=NOW,
                offset=offset,
                limit=limit,
                total_matches=len(self.events),
                has_more=offset + len(selected) < len(self.events),
                items=selected,
            ),
        )

    def get_event_detail(self, local_event_id):
        from shielddome_endpoint.console_models import (
            ConsoleOperationResult,
            ConsoleStatusCode,
            EventDetailViewModel,
        )

        event = next(item for item in self.events if item.local_event_id == local_event_id)
        return ConsoleOperationResult(
            ConsoleStatusCode.SUCCESS,
            EventDetailViewModel(
                local_event_id=event.local_event_id,
                detected_at_utc=event.detected_at_utc,
                risk_level=event.risk_level,
                detection_status=event.detection_status,
                generic_action=event.generic_action,
                source_kind=event.source_kind,
                abstained=event.abstained,
                degraded=event.degraded,
                model_execution_status=event.model_execution_status,
                error_code=event.error_code,
                rule_codes=("sender_domain_mismatch",),
            ),
        )


class DesktopPresenterTests(unittest.TestCase):
    def test_dashboard_view_model_maps_to_complete_desktop_display_state(self):
        from shielddome_endpoint.console_models import (
            ConsoleOperationResult,
            ConsoleStatusCode,
        )
        from shielddome_endpoint.desktop_presenter import (
            DesktopLoadState,
            PersonalConsolePresenter,
        )

        service = StaticConsoleService(
            ConsoleOperationResult(ConsoleStatusCode.SUCCESS, make_dashboard()),
            ConsoleOperationResult(
                ConsoleStatusCode.SUCCESS,
                make_empty_event_page(),
            ),
        )

        state = PersonalConsolePresenter(service).refresh()

        self.assertIs(state.load_state, DesktopLoadState.READY)
        self.assertEqual(state.today_count, "4")
        self.assertEqual(tuple(point.value for point in state.trend), (0,) * 14 + (4,))
        self.assertEqual(
            {item.key: item.value for item in state.risk_distribution},
            {"low": 1, "medium": 1, "high": 1, "critical": 1},
        )
        self.assertEqual(
            {item.key: item.value for item in state.source_distribution},
            {"browser_native": 3, "manual_local": 1},
        )
        self.assertEqual(state.model_abstention_count, "2")
        self.assertEqual(state.model_failure_count, "1")
        self.assertEqual(state.rules_only_degradation_count, "1")
        self.assertEqual(service.event_calls, [(0, 10)])

    def test_empty_corrupt_and_unavailable_results_map_to_safe_fixed_states(self):
        from shielddome_endpoint.console_models import (
            ConsoleOperationResult,
            ConsoleStatusCode,
        )
        from shielddome_endpoint.desktop_presenter import (
            DesktopLoadState,
            PersonalConsolePresenter,
        )

        empty = PersonalConsolePresenter(
            StaticConsoleService(
                ConsoleOperationResult(
                    ConsoleStatusCode.SUCCESS,
                    make_dashboard(today_count=0),
                ),
                ConsoleOperationResult(
                    ConsoleStatusCode.SUCCESS,
                    make_empty_event_page(),
                ),
            )
        ).refresh()
        degraded = PersonalConsolePresenter(
            StaticConsoleService(
                ConsoleOperationResult(
                    ConsoleStatusCode.EVIDENCE_STORE_UNAVAILABLE,
                    make_dashboard(today_count=0, evidence_unavailable=True),
                ),
                ConsoleOperationResult(
                    ConsoleStatusCode.EVIDENCE_STORE_UNAVAILABLE,
                    None,
                ),
            )
        ).refresh()
        failed = PersonalConsolePresenter(
            StaticConsoleService(
                ConsoleOperationResult(
                    ConsoleStatusCode.EVIDENCE_STORE_UNAVAILABLE,
                    None,
                ),
                ConsoleOperationResult(
                    ConsoleStatusCode.EVIDENCE_STORE_UNAVAILABLE,
                    None,
                ),
            )
        ).refresh()

        self.assertIs(empty.load_state, DesktopLoadState.EMPTY)
        self.assertEqual(empty.notice_title, "暂无本地检测记录")
        self.assertEqual(empty.events.empty_message, "最近 15 天没有检测事件")
        self.assertIs(degraded.load_state, DesktopLoadState.DEGRADED)
        self.assertEqual(degraded.notice_title, "本地记录暂时不可读")
        self.assertIs(failed.load_state, DesktopLoadState.ERROR)
        serialized = repr((empty, degraded, failed))
        for forbidden in ("RuntimeError", "Traceback", "C:\\Users", "token=secret"):
            self.assertNotIn(forbidden, serialized)

    def test_recent_events_paginate_and_sanitized_detail_maps_through_service(self):
        from shielddome_endpoint.console_models import (
            ConsoleOperationResult,
            ConsoleStatusCode,
        )
        from shielddome_endpoint.desktop_presenter import PersonalConsolePresenter

        events = tuple(make_event(f"event-{index:02d}", index) for index in range(12))
        service = PagingConsoleService(
            ConsoleOperationResult(
                ConsoleStatusCode.SUCCESS,
                make_dashboard(today_count=12),
            ),
            events,
        )
        presenter = PersonalConsolePresenter(service)

        first = presenter.refresh()
        second = presenter.next_events()
        detail = presenter.select_event("event-11")
        previous = presenter.previous_events()

        self.assertEqual(len(first.events.rows), 10)
        self.assertEqual(first.events.rows[0].local_event_id, "event-00")
        self.assertEqual(first.events.rows[0].detected_at_text, "08-10 09:30")
        self.assertEqual(first.events.rows[0].risk_label, "低")
        self.assertEqual(first.events.rows[0].detection_status_text, "模型完成")
        self.assertEqual(first.events.rows[0].source_text, "浏览器")
        self.assertTrue(first.events.can_next)
        self.assertEqual(second.events.offset, 10)
        self.assertEqual(second.events.page_number, 2)
        self.assertEqual(len(second.events.rows), 2)
        self.assertTrue(second.events.can_previous)
        self.assertFalse(second.events.can_next)
        self.assertEqual(detail.detail.local_event_id, "event-11")
        self.assertEqual(detail.detail.rule_codes, ("sender_domain_mismatch",))
        self.assertEqual(previous.events.offset, 0)
        self.assertEqual(service.event_calls, [(0, 10), (10, 10), (0, 10)])


if __name__ == "__main__":
    unittest.main()
