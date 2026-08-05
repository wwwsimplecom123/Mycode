from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))

from test_confirmed_examples import CONFIRMED_AT, make_vector
from test_evidence_crypto import make_record

from shielddome_endpoint.confirmed_examples import (
    ExampleSource,
    UserConfirmationAction,
)
from shielddome_endpoint.domain import (
    DetectionExecutionState,
    ModelExecutionStatus,
    RiskLevel,
)
from shielddome_endpoint.example_store import ExampleLibraryAggregate


NOW = datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc)


class StaticEvidenceStore:
    def __init__(self, records):
        self._records = tuple(records)

    def list_page(self, *, offset=0, limit=50):
        return self._records[offset : offset + limit]


class StaticExampleStore:
    def __init__(self, aggregate):
        self._aggregate = aggregate

    def diagnostic_aggregate(self):
        return self._aggregate


class PartiallyFailingEvidenceStore:
    def __init__(self, record):
        self._record = record

    def list_page(self, *, offset=0, limit=50):
        if offset == 0:
            return (self._record,) * limit
        raise RuntimeError(
            "SUBJECT-LEAK user@example.test https://private.test/?token=secret"
        )


class FailingExampleStore:
    def diagnostic_aggregate(self):
        raise RuntimeError(
            "C:\\Users\\private\\examples.sqlite3 fingerprint-deadbeef"
        )


class ExampleLibraryDiagnosticAggregateTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_diagnostic_aggregate_returns_counts_without_samples(self):
        from shielddome_endpoint.example_store import ExampleStore

        with TemporaryDirectory() as temporary_directory:
            store = ExampleStore(Path(temporary_directory))
            first = make_vector(subject="First confirmed example")
            second = make_vector(subject="Second confirmed example")
            store.confirm(
                first,
                action=UserConfirmationAction.CONFIRM_BENIGN,
                source=ExampleSource.BROWSER_NATIVE,
                confirmed_at=CONFIRMED_AT,
            )
            store.confirm(
                first,
                action=UserConfirmationAction.CONFIRM_PHISHING,
                source=ExampleSource.BROWSER_NATIVE,
                confirmed_at=CONFIRMED_AT + timedelta(minutes=1),
            )
            store.confirm(
                second,
                action=UserConfirmationAction.CONFIRM_BENIGN,
                source=ExampleSource.BROWSER_NATIVE,
                confirmed_at=CONFIRMED_AT + timedelta(minutes=2),
            )

            aggregate = store.diagnostic_aggregate()

            self.assertEqual(aggregate.total_rows, 3)
            self.assertEqual(aggregate.unique_examples, 2)
            self.assertEqual(aggregate.benign_labels, 2)
            self.assertEqual(aggregate.phishing_labels, 1)
            self.assertEqual(aggregate.conflicts, 1)
            self.assertFalse(hasattr(aggregate, "feature_vector"))
            self.assertFalse(hasattr(aggregate, "keyed_fingerprint"))

    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_diagnostic_aggregate_rejects_rows_above_the_fixed_limit(self):
        from shielddome_endpoint.example_store import (
            ExampleStore,
            ExampleStoreError,
        )

        with TemporaryDirectory() as temporary_directory:
            store = ExampleStore(Path(temporary_directory))
            for index in range(2):
                store.confirm(
                    make_vector(subject=f"Bounded example {index}"),
                    action=UserConfirmationAction.CONFIRM_BENIGN,
                    source=ExampleSource.BROWSER_NATIVE,
                    confirmed_at=CONFIRMED_AT + timedelta(minutes=index),
                )

            with patch(
                "shielddome_endpoint.example_store.EXAMPLE_CALIBRATION_SCAN_MAX_ROWS",
                1,
            ):
                with self.assertRaisesRegex(
                    ExampleStoreError,
                    "^example_diagnostic_limit_exceeded$",
                ):
                    store.diagnostic_aggregate()


class DiagnosticsCollectorTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_collecting_empty_stores_does_not_create_databases_or_keys(self):
        from shielddome_endpoint.diagnostics import (
            DiagnosticHealthStatus,
            DiagnosticsCollector,
        )
        from shielddome_endpoint.evidence_store import EvidenceStore
        from shielddome_endpoint.example_store import ExampleStore

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            evidence_store = EvidenceStore(root)
            example_store = ExampleStore(root)

            snapshot = DiagnosticsCollector(
                evidence_store=evidence_store,
                example_store=example_store,
                clock=lambda: NOW,
            ).collect()

            self.assertIs(
                snapshot.evidence_store_health.status,
                DiagnosticHealthStatus.EMPTY,
            )
            self.assertIs(
                snapshot.example_library_health.status,
                DiagnosticHealthStatus.EMPTY,
            )
            self.assertFalse(evidence_store.database_path.exists())
            self.assertFalse((root / "keys" / "evidence.key").exists())
            self.assertFalse(example_store.database_path.exists())
            self.assertFalse(example_store.key_path.exists())

    def test_collects_fixed_versions_and_recent_aggregate_counts_only(self):
        from shielddome_endpoint.diagnostics import DiagnosticsCollector

        base = make_record()
        recent_rules_only = replace(
            base,
            local_event_id="event-diagnostic-rules",
            detected_at=NOW - timedelta(days=1),
            retention_until=NOW + timedelta(days=14),
            risk_level=RiskLevel.HIGH,
            detection_status=DetectionExecutionState.RULES_ONLY,
            abstained=False,
            degraded=True,
            model_execution_status=None,
            error_code="model_not_configured",
        )
        recent_abstained = replace(
            base,
            local_event_id="event-diagnostic-abstained",
            detected_at=NOW - timedelta(days=1, hours=1),
            retention_until=NOW + timedelta(days=13, hours=23),
            risk_level=RiskLevel.MEDIUM,
            detection_status=DetectionExecutionState.MODEL_UNCERTAIN,
            abstained=True,
            degraded=False,
            model_execution_status=ModelExecutionStatus.SUCCESS,
            error_code=None,
        )
        old = replace(
            base,
            local_event_id="event-diagnostic-old",
            detected_at=NOW - timedelta(days=16),
            retention_until=NOW - timedelta(days=1),
        )

        snapshot = DiagnosticsCollector(
            evidence_store=StaticEvidenceStore(
                (recent_rules_only, recent_abstained, old)
            ),
            example_store=StaticExampleStore(
                ExampleLibraryAggregate(3, 2, 2, 1, 1)
            ),
            clock=lambda: NOW,
        ).collect()

        self.assertEqual(snapshot.schema_version, "1.0")
        self.assertEqual(snapshot.lookback_days, 15)
        self.assertEqual(snapshot.events_by_date, (("2026-08-04", 2),))
        self.assertEqual(dict(snapshot.risk_level_counts)["high"], 1)
        self.assertEqual(dict(snapshot.source_counts)["browser_native"], 2)
        self.assertEqual(snapshot.rules_only_count, 1)
        self.assertEqual(snapshot.model_available_count, 1)
        self.assertEqual(snapshot.model_abstained_count, 1)
        self.assertEqual(snapshot.model_degraded_count, 1)
        self.assertNotIn("2026-07-20", dict(snapshot.events_by_date))
        self.assertEqual(snapshot.example_unique_count, 2)
        self.assertEqual(snapshot.example_conflict_count, 1)

    def test_partial_store_failures_emit_only_controlled_health(self):
        from shielddome_endpoint.diagnostics import (
            DiagnosticHealthStatus,
            DiagnosticsCollector,
        )

        snapshot = DiagnosticsCollector(
            evidence_store=PartiallyFailingEvidenceStore(make_record()),
            example_store=FailingExampleStore(),
            clock=lambda: NOW,
        ).collect()
        serialized = snapshot.to_json_bytes()

        self.assertIs(
            snapshot.evidence_store_health.status,
            DiagnosticHealthStatus.UNAVAILABLE,
        )
        self.assertEqual(
            snapshot.evidence_store_health.error_code,
            "evidence_store_unavailable",
        )
        self.assertIs(
            snapshot.example_library_health.status,
            DiagnosticHealthStatus.UNAVAILABLE,
        )
        self.assertEqual(
            snapshot.example_library_health.error_code,
            "example_library_unavailable",
        )
        self.assertEqual(snapshot.event_count, 0)
        self.assertEqual(snapshot.example_total_rows, 0)
        for forbidden in (
            b"SUBJECT-LEAK",
            b"user@example.test",
            b"private.test",
            b"token=secret",
            b"C:\\\\Users",
            b"fingerprint-deadbeef",
            b"RuntimeError",
            b"Traceback",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, serialized)

    def test_other_windows_user_scope_cannot_generate_aggregate_data(self):
        from test_key_protection import RecordingDpapiBackend
        from shielddome_endpoint.diagnostics import (
            DiagnosticHealthStatus,
            DiagnosticsCollector,
        )
        from shielddome_endpoint.evidence_store import EvidenceStore
        from shielddome_endpoint.example_store import ExampleStore
        from shielddome_endpoint.key_protection import (
            CurrentUserKeyProtector,
            UserDataKeyManager,
        )

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            backend = RecordingDpapiBackend()

            def manager(path, database_filename, identity):
                return UserDataKeyManager(
                    path,
                    protector=CurrentUserKeyProtector(
                        backend=backend,
                        scope_identity_provider=lambda: identity,
                    ),
                    database_filename=database_filename,
                )

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
            user_a_evidence.put(make_record())
            user_a_examples.confirm(
                make_vector(),
                action=UserConfirmationAction.CONFIRM_PHISHING,
                source=ExampleSource.BROWSER_NATIVE,
                confirmed_at=CONFIRMED_AT,
            )

            snapshot = DiagnosticsCollector(
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
            ).collect()

            self.assertIs(
                snapshot.evidence_store_health.status,
                DiagnosticHealthStatus.UNAVAILABLE,
            )
            self.assertIs(
                snapshot.example_library_health.status,
                DiagnosticHealthStatus.UNAVAILABLE,
            )
            self.assertEqual(snapshot.event_count, 0)
            self.assertEqual(snapshot.example_total_rows, 0)

    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_damaged_databases_report_controlled_health_without_partial_counts(self):
        from shielddome_endpoint.diagnostics import (
            DiagnosticHealthStatus,
            DiagnosticsCollector,
        )
        from shielddome_endpoint.evidence_store import EvidenceStore
        from shielddome_endpoint.example_store import ExampleStore

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            evidence_store = EvidenceStore(root)
            example_store = ExampleStore(root)
            evidence_store.put(make_record())
            example_store.confirm(
                make_vector(),
                action=UserConfirmationAction.CONFIRM_BENIGN,
                source=ExampleSource.BROWSER_NATIVE,
                confirmed_at=CONFIRMED_AT,
            )
            for database_path, table in (
                (evidence_store.database_path, "endpoint_evidence"),
                (example_store.database_path, "confirmed_examples"),
            ):
                connection = sqlite3.connect(database_path)
                try:
                    tag = connection.execute(
                        f"SELECT authentication_tag FROM {table} LIMIT 1"
                    ).fetchone()[0]
                    connection.execute(
                        f"UPDATE {table} SET authentication_tag = ?",
                        (bytes([tag[0] ^ 1]) + tag[1:],),
                    )
                    connection.commit()
                finally:
                    connection.close()

            snapshot = DiagnosticsCollector(
                evidence_store=evidence_store,
                example_store=example_store,
                clock=lambda: NOW,
            ).collect()

            self.assertIs(
                snapshot.evidence_store_health.status,
                DiagnosticHealthStatus.UNAVAILABLE,
            )
            self.assertIs(
                snapshot.example_library_health.status,
                DiagnosticHealthStatus.UNAVAILABLE,
            )
            self.assertEqual(snapshot.event_count, 0)
            self.assertEqual(snapshot.example_total_rows, 0)
            self.assertNotIn(b"decryption", snapshot.to_json_bytes())

    def test_evidence_record_limit_fails_instead_of_truncating(self):
        from shielddome_endpoint.diagnostics import (
            DiagnosticCollectionError,
            DiagnosticsCollector,
        )

        base = make_record()
        records = tuple(
            replace(
                base,
                local_event_id=f"event-diagnostic-limit-{index}",
            )
            for index in range(3)
        )
        collector = DiagnosticsCollector(
            evidence_store=StaticEvidenceStore(records),
            example_store=StaticExampleStore(
                ExampleLibraryAggregate(0, 0, 0, 0, 0)
            ),
            clock=lambda: NOW,
        )

        with patch(
            "shielddome_endpoint.diagnostics.DIAGNOSTIC_MAX_EVIDENCE_RECORDS",
            2,
        ):
            with self.assertRaisesRegex(
                DiagnosticCollectionError,
                "^diagnostic_record_limit_exceeded$",
            ):
                collector.collect()

    def test_source_and_error_code_kind_limits_fail_closed(self):
        from shielddome_endpoint.diagnostics import (
            DiagnosticCollectionError,
            DiagnosticsCollector,
        )

        base = make_record()
        records = (
            replace(
                base,
                local_event_id="event-diagnostic-kind-a",
                source_kind="source_a",
                error_code="stable_error_a",
            ),
            replace(
                base,
                local_event_id="event-diagnostic-kind-b",
                source_kind="source_b",
                error_code="stable_error_b",
            ),
        )

        for constant_name, expected_code in (
            (
                "DIAGNOSTIC_MAX_SOURCE_KINDS",
                "diagnostic_source_limit_exceeded",
            ),
            (
                "DIAGNOSTIC_MAX_ERROR_CODE_KINDS",
                "diagnostic_error_code_limit_exceeded",
            ),
        ):
            with self.subTest(constant_name=constant_name):
                collector = DiagnosticsCollector(
                    evidence_store=StaticEvidenceStore(records),
                    example_store=StaticExampleStore(
                        ExampleLibraryAggregate(0, 0, 0, 0, 0)
                    ),
                    clock=lambda: NOW,
                )
                with patch(
                    f"shielddome_endpoint.diagnostics.{constant_name}",
                    1,
                ):
                    with self.assertRaisesRegex(
                        DiagnosticCollectionError,
                        f"^{expected_code}$",
                    ):
                        collector.collect()


if __name__ == "__main__":
    unittest.main()
