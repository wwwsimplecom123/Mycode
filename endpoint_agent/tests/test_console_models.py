from dataclasses import FrozenInstanceError, fields
from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))


NOW = datetime(2026, 8, 5, 16, 30, tzinfo=timezone.utc)


class ConsoleModelTests(unittest.TestCase):
    def test_package_exports_console_contracts(self):
        from shielddome_endpoint import (
            CONSOLE_VIEW_MODEL_SCHEMA_VERSION,
            ConsoleOperationResult,
            ConsoleStatusCode,
            DashboardViewModel,
            EventPageViewModel,
        )

        self.assertEqual(CONSOLE_VIEW_MODEL_SCHEMA_VERSION, "1.0")
        for public_type in (
            ConsoleOperationResult,
            ConsoleStatusCode,
            DashboardViewModel,
            EventPageViewModel,
        ):
            self.assertIsNotNone(public_type)

    def test_operation_result_contains_only_stable_code_payload_and_count(self):
        from shielddome_endpoint.console_models import (
            ConsoleOperationResult,
            ConsoleStatusCode,
        )

        result = ConsoleOperationResult(
            code=ConsoleStatusCode.SUCCESS,
            payload=None,
            affected_items=2,
        )

        self.assertEqual(result.schema_version, "1.0")
        self.assertEqual(
            tuple(field.name for field in fields(type(result))),
            ("code", "payload", "affected_items", "schema_version"),
        )
        self.assertFalse(hasattr(result, "message"))
        self.assertFalse(hasattr(result, "exception"))
        self.assertFalse(hasattr(result, "traceback"))
        with self.assertRaisesRegex(ValueError, "^invalid_console_result$"):
            ConsoleOperationResult(
                code=ConsoleStatusCode.SUCCESS,
                payload=None,
                affected_items=-1,
            )

        from test_confirmed_examples import make_vector

        with self.assertRaisesRegex(ValueError, "^invalid_console_result$"):
            ConsoleOperationResult(
                code=ConsoleStatusCode.SUCCESS,
                payload=make_vector(),
            )

    def test_dashboard_contract_is_versioned_immutable_and_private(self):
        from shielddome_endpoint.console_models import (
            AgentStatusSummary,
            ConsoleHealthStatus,
            DailyDetectionCount,
            DashboardViewModel,
            DistributionCount,
            ModelRuntimeStatus,
            StoreHealthViewModel,
        )

        dashboard = DashboardViewModel(
            generated_at_utc=NOW,
            local_timezone="Asia/Shanghai",
            agent_status=AgentStatusSummary(
                agent_status=ConsoleHealthStatus.HEALTHY,
                model_status=ModelRuntimeStatus.DEGRADED,
                rules_only=True,
                evidence_store_health=StoreHealthViewModel(
                    status=ConsoleHealthStatus.HEALTHY,
                    item_count=1,
                    error_code=None,
                ),
                example_library_health=StoreHealthViewModel(
                    status=ConsoleHealthStatus.EMPTY,
                    item_count=0,
                    error_code=None,
                ),
            ),
            today_detection_count=1,
            daily_trend=(DailyDetectionCount("2026-08-05", 1),),
            risk_distribution=(DistributionCount("high", 1),),
            source_distribution=(DistributionCount("browser_native", 1),),
            model_abstention_count=0,
            model_failure_count=1,
            rules_only_degradation_count=1,
        )

        self.assertEqual(dashboard.schema_version, "1.0")
        with self.assertRaises(FrozenInstanceError):
            dashboard.today_detection_count = 2
        field_names = tuple(field.name for field in fields(type(dashboard)))
        for forbidden in (
            "body",
            "address",
            "url",
            "feature_vector",
            "fingerprint",
            "ciphertext",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertFalse(
                    any(forbidden in field_name.casefold() for field_name in field_names)
                )

    def test_event_and_example_view_models_have_exact_sanitized_fields(self):
        from shielddome_endpoint.console_models import (
            ConfirmedExampleListItemViewModel,
            ConfirmedExamplePageViewModel,
            EventDetailViewModel,
            EventListItemViewModel,
            EventPageViewModel,
        )

        event = EventListItemViewModel(
            local_event_id="event-safe-1",
            detected_at_utc=NOW,
            risk_level="high",
            detection_status="model_error",
            generic_action="contact_security",
            source_kind="browser_native",
            abstained=False,
            degraded=True,
            model_execution_status="error",
            error_code="runtime_error",
        )
        detail = EventDetailViewModel(
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
            rule_codes=("dangerous_attachment",),
        )
        event_page = EventPageViewModel(
            generated_at_utc=NOW,
            offset=0,
            limit=50,
            total_matches=1,
            has_more=False,
            items=(event,),
        )
        example = ConfirmedExampleListItemViewModel(
            example_id="example-0123456789abcdef0123456789abcdef",
            label="benign",
            source="browser_native",
            confirmed_at_utc=NOW,
            conflict=False,
        )
        example_page = ConfirmedExamplePageViewModel(
            generated_at_utc=NOW,
            offset=0,
            limit=50,
            total_matches=1,
            has_more=False,
            label_filter="benign",
            items=(example,),
        )

        self.assertEqual(event_page.items, (event,))
        self.assertEqual(detail.rule_codes, ("dangerous_attachment",))
        self.assertEqual(example_page.items, (example,))
        self.assertEqual(
            tuple(field.name for field in fields(EventListItemViewModel)),
            (
                "local_event_id",
                "detected_at_utc",
                "risk_level",
                "detection_status",
                "generic_action",
                "source_kind",
                "abstained",
                "degraded",
                "model_execution_status",
                "error_code",
                "schema_version",
            ),
        )
        self.assertEqual(
            tuple(field.name for field in fields(EventDetailViewModel)),
            (
                "local_event_id",
                "detected_at_utc",
                "risk_level",
                "detection_status",
                "generic_action",
                "source_kind",
                "abstained",
                "degraded",
                "model_execution_status",
                "error_code",
                "rule_codes",
                "schema_version",
            ),
        )
        serialized = repr((event_page, detail, example_page)).casefold()
        for forbidden in (
            "feature_vector",
            "fingerprint",
            "similarity",
            "ciphertext",
            "nonce",
            "authentication_tag",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, serialized)

    def test_invalid_counts_times_ordering_and_page_bounds_fail_closed(self):
        from shielddome_endpoint.console_models import (
            AgentStatusSummary,
            ConsoleHealthStatus,
            ConfirmedExampleListItemViewModel,
            DailyDetectionCount,
            DashboardViewModel,
            DistributionCount,
            EventPageViewModel,
            ModelRuntimeStatus,
            StoreHealthViewModel,
        )

        empty_health = StoreHealthViewModel(
            status=ConsoleHealthStatus.EMPTY,
            item_count=0,
            error_code=None,
        )
        status = AgentStatusSummary(
            agent_status=ConsoleHealthStatus.HEALTHY,
            model_status=ModelRuntimeStatus.UNKNOWN,
            rules_only=True,
            evidence_store_health=empty_health,
            example_library_health=empty_health,
        )
        invalid_factories = (
            lambda: DailyDetectionCount("2026-02-30", 0),
            lambda: DailyDetectionCount("2026-08-05", True),
            lambda: DashboardViewModel(
                generated_at_utc=NOW,
                local_timezone="Asia/Shanghai",
                agent_status=status,
                today_detection_count=0,
                daily_trend=(
                    DailyDetectionCount("2026-08-05", 0),
                    DailyDetectionCount("2026-08-04", 0),
                ),
                risk_distribution=(
                    DistributionCount("low", 0),
                    DistributionCount("low", 0),
                ),
                source_distribution=(),
                model_abstention_count=0,
                model_failure_count=0,
                rules_only_degradation_count=0,
            ),
            lambda: EventPageViewModel(
                generated_at_utc=NOW,
                offset=4097,
                limit=50,
                total_matches=0,
                has_more=False,
                items=(),
            ),
            lambda: ConfirmedExampleListItemViewModel(
                example_id="a" * 64,
                label="benign",
                source="browser_native",
                confirmed_at_utc=NOW.replace(tzinfo=None),
                conflict=False,
            ),
        )

        for factory in invalid_factories:
            with self.subTest(factory=factory):
                with self.assertRaisesRegex(
                    ValueError,
                    "^invalid_console_view_model$",
                ):
                    factory()


if __name__ == "__main__":
    unittest.main()
