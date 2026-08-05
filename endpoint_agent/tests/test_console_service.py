from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import os
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from zoneinfo import ZoneInfo


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))

from test_evidence_crypto import make_record

from shielddome_endpoint.example_store import ExampleLibraryAggregate
from shielddome_endpoint.confirmed_examples import (
    ConfirmedExample,
    ExampleLabel,
    ExampleSource,
)
from shielddome_endpoint.domain import (
    DetectionExecutionState,
    ModelExecutionStatus,
    RiskLevel,
)


NOW = datetime(2026, 8, 5, 15, 30, tzinfo=timezone.utc)
LOCAL_TIMEZONE = ZoneInfo("Asia/Shanghai")


class StaticEvidenceStore:
    def __init__(self, records=()):
        self.records = tuple(records)

    def list_page(self, *, offset=0, limit=50):
        return self.records[offset : offset + limit]


class StaticExampleStore:
    def __init__(self, aggregate=None):
        self.aggregate = aggregate or ExampleLibraryAggregate(0, 0, 0, 0, 0)

    def diagnostic_aggregate(self):
        return self.aggregate


class PartiallyFailingEvidenceStore:
    def __init__(self, record):
        self.record = record

    def list_page(self, *, offset=0, limit=50):
        if offset == 0:
            return (self.record,) * limit
        raise RuntimeError(
            "SUBJECT user@example.test https://private.test/?token=secret"
        )


class FailingExampleStore:
    def diagnostic_aggregate(self):
        raise RuntimeError(
            "C:\\Users\\private\\confirmed_examples.sqlite3 fingerprint-secret"
        )


class QueryExampleStore(StaticExampleStore):
    def __init__(self, examples):
        self.examples = tuple(examples)
        super().__init__(
            ExampleLibraryAggregate(
                total_rows=len(self.examples),
                unique_examples=len(
                    {item.keyed_fingerprint for item in self.examples}
                ),
                benign_labels=sum(
                    item.label is ExampleLabel.BENIGN for item in self.examples
                ),
                phishing_labels=sum(
                    item.label is ExampleLabel.PHISHING for item in self.examples
                ),
                conflicts=len(
                    {
                        fingerprint
                        for fingerprint in {
                            item.keyed_fingerprint for item in self.examples
                        }
                        if len(
                            {
                                item.label
                                for item in self.examples
                                if item.keyed_fingerprint == fingerprint
                            }
                        )
                        > 1
                    }
                ),
            )
        )

    def list_for_calibration(self):
        return self.examples


class RecordingCommands:
    def __init__(self):
        self.calls = []

    def confirm_benign(self, vector, *, confirmed):
        from shielddome_endpoint.console_models import (
            ConsoleOperationResult,
            ConsoleStatusCode,
        )

        self.calls.append(("confirm_benign", vector, confirmed))
        return ConsoleOperationResult(ConsoleStatusCode.EXAMPLE_ADDED, None, 1)

    def confirm_phishing(self, vector, *, confirmed):
        from shielddome_endpoint.console_models import (
            ConsoleOperationResult,
            ConsoleStatusCode,
        )

        self.calls.append(("confirm_phishing", vector, confirmed))
        return ConsoleOperationResult(ConsoleStatusCode.EXAMPLE_ADDED, None, 1)

    def delete_example(self, fingerprint, label):
        from shielddome_endpoint.console_models import (
            ConsoleOperationResult,
            ConsoleStatusCode,
        )

        self.calls.append(("delete_example", fingerprint, label))
        return ConsoleOperationResult(ConsoleStatusCode.SUCCESS, None, 1)

    def clear_examples(self, *, confirmed):
        from shielddome_endpoint.console_models import (
            ConsoleOperationResult,
            ConsoleStatusCode,
        )

        self.calls.append(("clear_examples", confirmed))
        return ConsoleOperationResult(ConsoleStatusCode.SUCCESS, None, 2)

    def export_diagnostics(self, output_path, *, confirmed, overwrite=False):
        from shielddome_endpoint.console_models import (
            ConsoleOperationResult,
            ConsoleStatusCode,
        )

        self.calls.append(("export_diagnostics", output_path, confirmed, overwrite))
        return ConsoleOperationResult(ConsoleStatusCode.DIAGNOSTIC_EXPORTED, None, 1)

    def delete_all_local_data(self, *, confirmed):
        from shielddome_endpoint.console_models import (
            ConsoleOperationResult,
            ConsoleStatusCode,
        )

        self.calls.append(("delete_all_local_data", confirmed))
        return ConsoleOperationResult(ConsoleStatusCode.SUCCESS, None, 4)


def record_at(local_event_id, detected_at, **changes):
    return replace(
        make_record(),
        local_event_id=local_event_id,
        detected_at=detected_at,
        retention_until=detected_at + timedelta(days=15),
        **changes,
    )


class PersonalConsoleServiceTests(unittest.TestCase):
    def test_named_windows_timezone_is_exposed_as_safe_utc_offset(self):
        from shielddome_endpoint.console_models import ConsoleStatusCode
        from shielddome_endpoint.console_service import PersonalConsoleService

        windows_timezone = timezone(
            timedelta(hours=8),
            name="China Standard Time",
        )
        result = PersonalConsoleService(
            evidence_store=StaticEvidenceStore(),
            example_store=StaticExampleStore(),
            clock=lambda: NOW,
            local_timezone=windows_timezone,
        ).get_dashboard()

        self.assertIs(result.code, ConsoleStatusCode.SUCCESS)
        self.assertEqual(result.payload.local_timezone, "UTC+08:00")

    def test_diagnostic_and_delete_all_commands_are_exposed_only_by_service(self):
        from shielddome_endpoint.console_models import ConsoleStatusCode
        from shielddome_endpoint.console_service import PersonalConsoleService

        commands = RecordingCommands()
        service = PersonalConsoleService(
            evidence_store=StaticEvidenceStore(),
            example_store=StaticExampleStore(),
            clock=lambda: NOW,
            local_timezone=LOCAL_TIMEZONE,
            local_data_commands=commands,
        )
        output_path = Path("C:/selected/support.diag.zip")

        exported = service.export_diagnostics(
            output_path,
            confirmed=True,
            overwrite=False,
        )
        deleted = service.delete_all_local_data(confirmed=True)

        self.assertIs(exported.code, ConsoleStatusCode.DIAGNOSTIC_EXPORTED)
        self.assertIs(deleted.code, ConsoleStatusCode.SUCCESS)
        self.assertEqual(
            commands.calls,
            [
                ("export_diagnostics", output_path, True, False),
                ("delete_all_local_data", True),
            ],
        )
    def test_feedback_and_sample_delete_commands_route_only_through_service(self):
        from test_confirmed_examples import make_vector
        from shielddome_endpoint.console_models import ConsoleStatusCode
        from shielddome_endpoint.console_service import PersonalConsoleService

        example = ConfirmedExample.create(
            make_vector(),
            label=ExampleLabel.BENIGN,
            source=ExampleSource.BROWSER_NATIVE,
            confirmed_at=NOW,
            keyed_fingerprint="c" * 64,
        )
        commands = RecordingCommands()
        service = PersonalConsoleService(
            evidence_store=StaticEvidenceStore(),
            example_store=QueryExampleStore((example,)),
            clock=lambda: NOW,
            local_timezone=LOCAL_TIMEZONE,
            example_id_factory=lambda: "2" * 32,
            local_data_commands=commands,
        )
        example_id = service.list_confirmed_examples().payload.items[0].example_id

        benign = service.confirm_benign(make_vector(), confirmed=True)
        phishing = service.confirm_phishing(make_vector(), confirmed=True)
        deleted = service.delete_confirmed_example(example_id)
        repeated = service.delete_confirmed_example(example_id)
        cleared = service.clear_confirmed_examples(confirmed=True)

        self.assertIs(benign.code, ConsoleStatusCode.EXAMPLE_ADDED)
        self.assertIs(phishing.code, ConsoleStatusCode.EXAMPLE_ADDED)
        self.assertIs(deleted.code, ConsoleStatusCode.SUCCESS)
        self.assertIs(repeated.code, ConsoleStatusCode.NOT_FOUND)
        self.assertIs(cleared.code, ConsoleStatusCode.SUCCESS)
        self.assertEqual(
            commands.calls[2],
            ("delete_example", "c" * 64, ExampleLabel.BENIGN),
        )
        self.assertNotIn("c" * 64, repr(deleted))
    def test_confirmed_example_page_filters_and_hides_vectors_and_fingerprints(self):
        from test_confirmed_examples import make_vector
        from shielddome_endpoint.console_models import ConsoleStatusCode
        from shielddome_endpoint.console_service import PersonalConsoleService

        shared_fingerprint = "a" * 64
        examples = (
            ConfirmedExample.create(
                make_vector(subject="Newest benign"),
                label=ExampleLabel.BENIGN,
                source=ExampleSource.BROWSER_NATIVE,
                confirmed_at=NOW,
                keyed_fingerprint=shared_fingerprint,
            ),
            ConfirmedExample.create(
                make_vector(subject="Newest benign"),
                label=ExampleLabel.PHISHING,
                source=ExampleSource.BROWSER_NATIVE,
                confirmed_at=NOW - timedelta(minutes=1),
                keyed_fingerprint=shared_fingerprint,
            ),
            ConfirmedExample.create(
                make_vector(subject="Older benign"),
                label=ExampleLabel.BENIGN,
                source=ExampleSource.BROWSER_NATIVE,
                confirmed_at=NOW - timedelta(minutes=2),
                keyed_fingerprint="b" * 64,
            ),
        )
        identifiers = iter(("0" * 32, "1" * 32))
        service = PersonalConsoleService(
            evidence_store=StaticEvidenceStore(),
            example_store=QueryExampleStore(examples),
            clock=lambda: NOW,
            local_timezone=LOCAL_TIMEZONE,
            example_id_factory=lambda: next(identifiers),
        )

        result = service.list_confirmed_examples(
            offset=0,
            limit=1,
            label=ExampleLabel.BENIGN,
        )

        self.assertIs(result.code, ConsoleStatusCode.SUCCESS)
        self.assertEqual(result.payload.total_matches, 2)
        self.assertTrue(result.payload.has_more)
        self.assertEqual(result.payload.items[0].label, "benign")
        self.assertEqual(
            result.payload.items[0].example_id,
            "example-00000000000000000000000000000000",
        )
        self.assertTrue(result.payload.items[0].conflict)
        self.assertFalse(hasattr(result.payload.items[0], "feature_vector"))
        self.assertNotIn(shared_fingerprint, repr(result))
        self.assertNotIn("text_vector", repr(result))
    def test_event_detail_is_sanitized_recent_and_not_found_outside_window(self):
        from dataclasses import fields
        from shielddome_endpoint.console_models import (
            ConsoleStatusCode,
            EventDetailViewModel,
        )
        from shielddome_endpoint.console_service import PersonalConsoleService

        recent = record_at(
            "event-detail-recent",
            NOW - timedelta(hours=1),
            rule_codes=("dangerous_attachment",),
        )
        old_time = NOW - timedelta(days=16)
        old = record_at("event-detail-old", old_time)
        service = PersonalConsoleService(
            evidence_store=StaticEvidenceStore((recent, old)),
            example_store=StaticExampleStore(),
            clock=lambda: NOW,
            local_timezone=LOCAL_TIMEZONE,
        )

        detail = service.get_event_detail("event-detail-recent")
        old_result = service.get_event_detail("event-detail-old")
        missing = service.get_event_detail("event-detail-missing")

        self.assertIs(detail.code, ConsoleStatusCode.SUCCESS)
        self.assertEqual(detail.payload.rule_codes, ("dangerous_attachment",))
        self.assertIs(old_result.code, ConsoleStatusCode.NOT_FOUND)
        self.assertIs(missing.code, ConsoleStatusCode.NOT_FOUND)
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

    def test_recent_event_list_is_paginated_newest_first_with_safe_fields(self):
        from dataclasses import fields
        from shielddome_endpoint.console_models import (
            ConsoleStatusCode,
            EventListItemViewModel,
        )
        from shielddome_endpoint.console_service import PersonalConsoleService

        records = tuple(
            record_at(
                f"event-page-{index}",
                NOW - timedelta(hours=index),
            )
            for index in range(3)
        )
        service = PersonalConsoleService(
            evidence_store=StaticEvidenceStore(records),
            example_store=StaticExampleStore(),
            clock=lambda: NOW,
            local_timezone=LOCAL_TIMEZONE,
        )

        result = service.list_recent_events(offset=1, limit=1)

        self.assertIs(result.code, ConsoleStatusCode.SUCCESS)
        self.assertEqual(result.payload.items[0].local_event_id, "event-page-1")
        self.assertEqual(result.payload.total_matches, 3)
        self.assertTrue(result.payload.has_more)
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

    def test_empty_dashboard_query_creates_no_database_key_or_sidecar(self):
        from shielddome_endpoint.console_models import ConsoleStatusCode
        from shielddome_endpoint.console_service import PersonalConsoleService
        from shielddome_endpoint.evidence_store import EvidenceStore
        from shielddome_endpoint.example_store import ExampleStore

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            with patch.dict(os.environ, {"LOCALAPPDATA": str(root)}):
                evidence_store = EvidenceStore(root)
                example_store = ExampleStore(root)
                result = PersonalConsoleService(
                    evidence_store=evidence_store,
                    example_store=example_store,
                    clock=lambda: NOW,
                    local_timezone=LOCAL_TIMEZONE,
                )
                dashboard_result = result.get_dashboard()
                detail_result = result.get_event_detail("event-empty")
                examples_result = result.list_confirmed_examples()

            self.assertIs(dashboard_result.code, ConsoleStatusCode.SUCCESS)
            self.assertEqual(dashboard_result.payload.today_detection_count, 0)
            self.assertIs(detail_result.code, ConsoleStatusCode.NOT_FOUND)
            self.assertIs(examples_result.code, ConsoleStatusCode.SUCCESS)
            self.assertEqual(examples_result.payload.items, ())
            forbidden_paths = (
                evidence_store.database_path,
                Path(f"{evidence_store.database_path}-wal"),
                Path(f"{evidence_store.database_path}-shm"),
                root / "keys" / "evidence.key",
                example_store.database_path,
                Path(f"{example_store.database_path}-wal"),
                Path(f"{example_store.database_path}-shm"),
                example_store.key_path,
            )
            for path in forbidden_paths:
                with self.subTest(path=path):
                    self.assertFalse(path.exists())

    def test_example_queries_enforce_filter_page_and_scan_limits(self):
        from test_confirmed_examples import make_vector
        from shielddome_endpoint.console_models import ConsoleStatusCode
        from shielddome_endpoint.console_service import PersonalConsoleService

        examples = tuple(
            ConfirmedExample.create(
                make_vector(subject=f"Bounded example {index}"),
                label=ExampleLabel.BENIGN,
                source=ExampleSource.BROWSER_NATIVE,
                confirmed_at=NOW - timedelta(minutes=index),
                keyed_fingerprint=f"{index + 1:064x}",
            )
            for index in range(2)
        )
        service = PersonalConsoleService(
            evidence_store=StaticEvidenceStore(),
            example_store=QueryExampleStore(examples),
            clock=lambda: NOW,
            local_timezone=LOCAL_TIMEZONE,
        )
        for arguments in (
            {"offset": True},
            {"offset": -1},
            {"offset": 257},
            {"limit": 0},
            {"limit": 51},
            {"label": "benign"},
        ):
            with self.subTest(arguments=arguments):
                self.assertIs(
                    service.list_confirmed_examples(**arguments).code,
                    ConsoleStatusCode.INVALID_REQUEST,
                )

        with patch(
            "shielddome_endpoint.console_service.CONSOLE_EXAMPLE_SCAN_MAX_ROWS",
            1,
        ):
            bounded = service.list_confirmed_examples()
        self.assertIs(bounded.code, ConsoleStatusCode.QUERY_LIMIT_EXCEEDED)
        self.assertIsNone(bounded.payload)

    def test_event_queries_enforce_page_and_scan_limits_without_partial_results(self):
        from shielddome_endpoint.console_models import ConsoleStatusCode
        from shielddome_endpoint.console_service import PersonalConsoleService

        records = tuple(
            record_at(f"event-bounded-{index}", NOW - timedelta(minutes=index))
            for index in range(3)
        )
        service = PersonalConsoleService(
            evidence_store=StaticEvidenceStore(records),
            example_store=StaticExampleStore(),
            clock=lambda: NOW,
            local_timezone=LOCAL_TIMEZONE,
        )
        for arguments in (
            {"offset": True},
            {"offset": -1},
            {"offset": 4097},
            {"limit": 0},
            {"limit": 51},
        ):
            with self.subTest(arguments=arguments):
                self.assertIs(
                    service.list_recent_events(**arguments).code,
                    ConsoleStatusCode.INVALID_REQUEST,
                )

        with patch(
            "shielddome_endpoint.console_service.CONSOLE_EVIDENCE_SCAN_MAX_RECORDS",
            2,
        ):
            bounded = service.list_recent_events()
        self.assertIs(bounded.code, ConsoleStatusCode.QUERY_LIMIT_EXCEEDED)
        self.assertIsNone(bounded.payload)

        corrupted = PersonalConsoleService(
            evidence_store=PartiallyFailingEvidenceStore(make_record()),
            example_store=StaticExampleStore(),
            clock=lambda: NOW,
            local_timezone=LOCAL_TIMEZONE,
        ).list_recent_events()
        self.assertIs(
            corrupted.code,
            ConsoleStatusCode.EVIDENCE_STORE_UNAVAILABLE,
        )
        self.assertIsNone(corrupted.payload)

    def test_other_windows_user_receives_no_dashboard_data(self):
        from test_key_protection import RecordingDpapiBackend
        from shielddome_endpoint.confirmed_examples import (
            ExampleSource,
            UserConfirmationAction,
        )
        from shielddome_endpoint.console_models import (
            ConsoleHealthStatus,
            ConsoleStatusCode,
        )
        from shielddome_endpoint.console_service import PersonalConsoleService
        from shielddome_endpoint.evidence_store import EvidenceStore
        from shielddome_endpoint.example_store import ExampleStore
        from shielddome_endpoint.key_protection import (
            CurrentUserKeyProtector,
            UserDataKeyManager,
        )
        from test_confirmed_examples import make_vector

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            backend = RecordingDpapiBackend()

            def manager(path, filename, identity):
                return UserDataKeyManager(
                    path,
                    protector=CurrentUserKeyProtector(
                        backend=backend,
                        scope_identity_provider=lambda: identity,
                    ),
                    database_filename=filename,
                )

            with patch.dict(os.environ, {"LOCALAPPDATA": str(root)}):
                user_a_evidence = EvidenceStore(
                    key_manager=manager(root, "evidence.sqlite3", "user-a")
                )
                user_a_examples = ExampleStore(
                    key_manager=manager(
                        root / "examples",
                        "confirmed_examples.sqlite3",
                        "user-a",
                    )
                )
                user_a_evidence.put(record_at("event-user-a", NOW))
                user_a_examples.confirm(
                    make_vector(),
                    action=UserConfirmationAction.CONFIRM_PHISHING,
                    source=ExampleSource.BROWSER_NATIVE,
                    confirmed_at=NOW,
                )
                result = PersonalConsoleService(
                    evidence_store=EvidenceStore(
                        key_manager=manager(root, "evidence.sqlite3", "user-b")
                    ),
                    example_store=ExampleStore(
                        key_manager=manager(
                            root / "examples",
                            "confirmed_examples.sqlite3",
                            "user-b",
                        )
                    ),
                    clock=lambda: NOW,
                    local_timezone=LOCAL_TIMEZONE,
                ).get_dashboard()

            self.assertIs(result.code, ConsoleStatusCode.EVIDENCE_STORE_UNAVAILABLE)
            self.assertIs(
                result.payload.agent_status.evidence_store_health.status,
                ConsoleHealthStatus.UNAVAILABLE,
            )
            self.assertIs(
                result.payload.agent_status.example_library_health.status,
                ConsoleHealthStatus.UNAVAILABLE,
            )
            self.assertEqual(result.payload.today_detection_count, 0)
            self.assertEqual(
                sum(item.count for item in result.payload.risk_distribution),
                0,
            )

    def test_dashboard_counts_risk_source_abstention_failure_and_degradation(self):
        from shielddome_endpoint.console_models import (
            ConsoleStatusCode,
            ModelRuntimeStatus,
        )
        from shielddome_endpoint.console_service import PersonalConsoleService

        records = (
            record_at(
                "event-model-success",
                NOW - timedelta(hours=1),
                risk_level=RiskLevel.HIGH,
                source_kind="browser_native",
                detection_status=DetectionExecutionState.MODEL_SUCCESS,
                abstained=False,
                degraded=False,
                model_execution_status=ModelExecutionStatus.SUCCESS,
                error_code=None,
            ),
            record_at(
                "event-model-abstained",
                NOW - timedelta(hours=2),
                risk_level=RiskLevel.MEDIUM,
                source_kind="browser_native",
                detection_status=DetectionExecutionState.MODEL_UNCERTAIN,
                abstained=True,
                degraded=False,
                model_execution_status=ModelExecutionStatus.SUCCESS,
                error_code=None,
            ),
            record_at(
                "event-model-error",
                NOW - timedelta(hours=3),
                risk_level=RiskLevel.LOW,
                source_kind="manual_local",
                detection_status=DetectionExecutionState.MODEL_ERROR,
                abstained=False,
                degraded=True,
                model_execution_status=ModelExecutionStatus.ERROR,
                error_code="runtime_error",
            ),
            record_at(
                "event-model-invalid",
                NOW - timedelta(hours=4),
                risk_level=RiskLevel.CRITICAL,
                source_kind="browser_native",
                detection_status=DetectionExecutionState.MODEL_INVALID_OUTPUT,
                abstained=False,
                degraded=True,
                model_execution_status=None,
                error_code="invalid_model_output",
            ),
        )
        service = PersonalConsoleService(
            evidence_store=StaticEvidenceStore(records),
            example_store=StaticExampleStore(
                ExampleLibraryAggregate(3, 2, 2, 1, 1)
            ),
            clock=lambda: NOW,
            local_timezone=LOCAL_TIMEZONE,
        )

        result = service.get_dashboard()

        self.assertIs(result.code, ConsoleStatusCode.SUCCESS)
        self.assertEqual(
            dict((item.category, item.count) for item in result.payload.risk_distribution),
            {"low": 1, "medium": 1, "high": 1, "critical": 1},
        )
        self.assertEqual(
            dict((item.category, item.count) for item in result.payload.source_distribution),
            {"browser_native": 3, "manual_local": 1},
        )
        self.assertEqual(result.payload.model_abstention_count, 1)
        self.assertEqual(result.payload.model_failure_count, 2)
        self.assertEqual(result.payload.rules_only_degradation_count, 2)
        self.assertIs(
            result.payload.agent_status.model_status,
            ModelRuntimeStatus.AVAILABLE,
        )
        self.assertEqual(
            result.payload.agent_status.example_library_health.item_count,
            3,
        )

    def test_partial_store_failures_return_controlled_health_without_partial_data(self):
        from shielddome_endpoint.console_models import (
            ConsoleHealthStatus,
            ConsoleStatusCode,
        )
        from shielddome_endpoint.console_service import PersonalConsoleService

        service = PersonalConsoleService(
            evidence_store=PartiallyFailingEvidenceStore(make_record()),
            example_store=FailingExampleStore(),
            clock=lambda: NOW,
            local_timezone=LOCAL_TIMEZONE,
        )

        result = service.get_dashboard()

        self.assertIs(result.code, ConsoleStatusCode.EVIDENCE_STORE_UNAVAILABLE)
        self.assertIs(
            result.payload.agent_status.evidence_store_health.status,
            ConsoleHealthStatus.UNAVAILABLE,
        )
        self.assertIs(
            result.payload.agent_status.example_library_health.status,
            ConsoleHealthStatus.UNAVAILABLE,
        )
        self.assertEqual(result.payload.today_detection_count, 0)
        self.assertEqual(sum(item.count for item in result.payload.daily_trend), 0)
        serialized = repr(result)
        for forbidden in (
            "SUBJECT",
            "user@example.test",
            "private.test",
            "token=secret",
            "C:\\Users",
            "fingerprint-secret",
            "RuntimeError",
            "Traceback",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, serialized)

    def test_today_and_fifteen_day_trend_use_local_calendar_boundaries(self):
        from shielddome_endpoint.console_models import (
            ConsoleStatusCode,
            DailyDetectionCount,
        )
        from shielddome_endpoint.console_service import PersonalConsoleService

        records = (
            record_at(
                "event-local-today",
                datetime(2026, 8, 4, 16, 1, tzinfo=timezone.utc),
            ),
            record_at(
                "event-local-yesterday",
                datetime(2026, 8, 4, 15, 59, tzinfo=timezone.utc),
            ),
        )
        service = PersonalConsoleService(
            evidence_store=StaticEvidenceStore(records),
            example_store=StaticExampleStore(),
            clock=lambda: NOW,
            local_timezone=LOCAL_TIMEZONE,
        )

        result = service.get_dashboard()

        self.assertIs(result.code, ConsoleStatusCode.SUCCESS)
        self.assertEqual(result.payload.today_detection_count, 1)
        self.assertEqual(len(result.payload.daily_trend), 15)
        self.assertEqual(
            result.payload.daily_trend[0],
            DailyDetectionCount("2026-07-22", 0),
        )
        self.assertEqual(
            result.payload.daily_trend[-2:],
            (
                DailyDetectionCount("2026-08-04", 1),
                DailyDetectionCount("2026-08-05", 1),
            ),
        )


if __name__ == "__main__":
    unittest.main()
