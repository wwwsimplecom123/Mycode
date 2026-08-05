from datetime import datetime, timezone
from pathlib import Path
import os
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))

from test_confirmed_examples import make_vector

from shielddome_endpoint.confirmed_examples import (
    ExampleSource,
    UserConfirmationAction,
)
from shielddome_endpoint.example_store import ExampleConfirmationStatus


NOW = datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc)


class RecordingExampleStore:
    def __init__(self, status=ExampleConfirmationStatus.ADDED):
        self.status = status
        self.confirm_calls = []
        self.delete_calls = []
        self.clear_calls = 0

    def confirm(self, feature_vector, *, action, source, confirmed_at):
        self.confirm_calls.append((feature_vector, action, source, confirmed_at))
        return self.status

    def delete(self, keyed_fingerprint, label):
        self.delete_calls.append((keyed_fingerprint, label))
        return True

    def clear(self):
        self.clear_calls += 1
        return 3


class RecordingDiagnosticExporter:
    def __init__(self, error=None):
        self.error = error
        self.calls = []

    def export(self, output_path, *, confirmed, overwrite=False):
        self.calls.append((output_path, confirmed, overwrite))
        if self.error is not None:
            raise self.error
        return object()


class RecordingEvidenceStore:
    def __init__(self, error=None):
        self.error = error
        self.delete_calls = 0

    def delete_all(self):
        self.delete_calls += 1
        if self.error is not None:
            raise self.error
        return 2


class LocalDataCommandTests(unittest.TestCase):
    def test_only_confirmed_command_creates_the_real_example_library(self):
        from test_key_protection import RecordingDpapiBackend
        from shielddome_endpoint.console_models import ConsoleStatusCode
        from shielddome_endpoint.example_store import ExampleStore
        from shielddome_endpoint.key_protection import (
            CurrentUserKeyProtector,
            UserDataKeyManager,
        )
        from shielddome_endpoint.local_data_commands import LocalDataCommands

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            backend = RecordingDpapiBackend()
            with patch.dict(os.environ, {"LOCALAPPDATA": str(root)}):
                example_store = ExampleStore(
                    key_manager=UserDataKeyManager(
                        root / "examples",
                        protector=CurrentUserKeyProtector(
                            backend=backend,
                            scope_identity_provider=lambda: "current-user",
                        ),
                        database_filename="confirmed_examples.sqlite3",
                    )
                )
                commands = LocalDataCommands(
                    evidence_store=RecordingEvidenceStore(),
                    example_store=example_store,
                    diagnostic_exporter=RecordingDiagnosticExporter(),
                    clock=lambda: NOW,
                    data_root=root,
                )
                rejected = commands.confirm_phishing(
                    make_vector(),
                    confirmed=False,
                )
                self.assertFalse(example_store.database_path.exists())
                self.assertFalse(example_store.key_path.exists())

                accepted = commands.confirm_phishing(
                    make_vector(),
                    confirmed=True,
                )

            self.assertIs(
                rejected.code,
                ConsoleStatusCode.CONFIRMATION_REQUIRED,
            )
            self.assertIs(accepted.code, ConsoleStatusCode.EXAMPLE_ADDED)
            self.assertTrue(example_store.database_path.exists())
            self.assertTrue(example_store.key_path.exists())
    def test_command_failures_do_not_change_the_detection_chain(self):
        from test_local_detection import OBSERVED_NOW, make_observation
        from shielddome_endpoint.console_models import ConsoleStatusCode
        from shielddome_endpoint.local_data_commands import LocalDataCommands
        from shielddome_endpoint.local_detection import LocalDetectionService

        class FailingExampleStore:
            def confirm(self, *args, **kwargs):
                raise RuntimeError(
                    "SUBJECT user@example.test token=secret fingerprint-private"
                )

            def clear(self):
                raise RuntimeError("C:\\Users\\private\\examples.sqlite3")

        class FailingExporter:
            def export(self, *args, **kwargs):
                raise RuntimeError("https://private.test/?token=secret")

        commands = LocalDataCommands(
            evidence_store=RecordingEvidenceStore(RuntimeError("private evidence")),
            example_store=FailingExampleStore(),
            diagnostic_exporter=FailingExporter(),
            clock=lambda: NOW,
            data_root=Path("C:/safe-test-root"),
        )
        observation = make_observation(reply_to="other@outside.test")
        detector = LocalDetectionService()
        before = detector.detect(
            observation,
            local_event_id="event-command-failure",
            observed_now=OBSERVED_NOW,
        )

        command_results = (
            commands.confirm_benign(make_vector(), confirmed=True),
            commands.export_diagnostics(
                Path("C:/selected/failure.diag.zip"),
                confirmed=True,
            ),
            commands.delete_all_local_data(confirmed=True),
        )
        after = detector.detect(
            observation,
            local_event_id="event-command-failure",
            observed_now=OBSERVED_NOW,
        )

        self.assertEqual(after, before)
        self.assertEqual(
            set(dict(after.minimal_plugin_projection)),
            {"local_event_id", "risk_level", "execution_state", "generic_action"},
        )
        self.assertTrue(
            all(
                result.code
                in {
                    ConsoleStatusCode.COMMAND_FAILED,
                    ConsoleStatusCode.LOCAL_DATA_DELETE_PARTIAL_FAILURE,
                }
                for result in command_results
            )
        )
        serialized = repr(command_results)
        for forbidden in (
            "SUBJECT",
            "user@example.test",
            "token=secret",
            "fingerprint-private",
            "C:\\Users",
            "https://",
            "RuntimeError",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_delete_all_removes_real_encrypted_stores_keys_sidecars_and_temp(self):
        from test_key_protection import RecordingDpapiBackend
        from test_evidence_crypto import make_record
        from shielddome_endpoint.confirmed_examples import (
            ExampleSource,
            UserConfirmationAction,
        )
        from shielddome_endpoint.console_models import ConsoleStatusCode
        from shielddome_endpoint.evidence_store import EvidenceStore
        from shielddome_endpoint.example_store import ExampleStore
        from shielddome_endpoint.key_protection import (
            CurrentUserKeyProtector,
            UserDataKeyManager,
        )
        from shielddome_endpoint.local_data_commands import LocalDataCommands

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            backend = RecordingDpapiBackend()

            def manager(path, filename):
                return UserDataKeyManager(
                    path,
                    protector=CurrentUserKeyProtector(
                        backend=backend,
                        scope_identity_provider=lambda: "current-user",
                    ),
                    database_filename=filename,
                )

            with patch.dict(os.environ, {"LOCALAPPDATA": str(root)}):
                evidence_store = EvidenceStore(
                    key_manager=manager(root, "evidence.sqlite3")
                )
                example_store = ExampleStore(
                    key_manager=manager(
                        root / "examples",
                        "confirmed_examples.sqlite3",
                    )
                )
                evidence_store.put(make_record())
                example_store.confirm(
                    make_vector(),
                    action=UserConfirmationAction.CONFIRM_BENIGN,
                    source=ExampleSource.BROWSER_NATIVE,
                    confirmed_at=NOW,
                )
                diagnostic_temp = root / "diagnostic-temp" / "export-real"
                diagnostic_temp.mkdir(parents=True)
                (diagnostic_temp / "package.diag.zip").write_bytes(b"temporary")
                commands = LocalDataCommands(
                    evidence_store=evidence_store,
                    example_store=example_store,
                    diagnostic_exporter=RecordingDiagnosticExporter(),
                    clock=lambda: NOW,
                    data_root=root,
                )
                result = commands.delete_all_local_data(confirmed=True)
                repeated = commands.delete_all_local_data(confirmed=True)

            self.assertIs(result.code, ConsoleStatusCode.SUCCESS)
            self.assertIs(repeated.code, ConsoleStatusCode.SUCCESS)
            owned_paths = (
                evidence_store.database_path,
                Path(f"{evidence_store.database_path}-wal"),
                Path(f"{evidence_store.database_path}-shm"),
                Path(f"{evidence_store.database_path}-journal"),
                evidence_store.database_path.with_name(
                    evidence_store.database_path.name + ".tmp"
                ),
                root / "keys" / "evidence.key",
                root / "keys" / "evidence.key.tmp",
                example_store.database_path,
                Path(f"{example_store.database_path}-wal"),
                Path(f"{example_store.database_path}-shm"),
                Path(f"{example_store.database_path}-journal"),
                example_store.database_path.with_name(
                    example_store.database_path.name + ".tmp"
                ),
                example_store.key_path,
                example_store.key_path.with_name(example_store.key_path.name + ".tmp"),
                root / "diagnostic-temp",
            )
            for path in owned_paths:
                with self.subTest(path=path):
                    self.assertFalse(path.exists())

    def test_delete_all_coordinates_both_stores_and_owned_temporary_files(self):
        from shielddome_endpoint.console_models import ConsoleStatusCode
        from shielddome_endpoint.local_data_commands import LocalDataCommands

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            temporary_root = root / "diagnostic-temp"
            nested = temporary_root / "export-1" / "nested"
            nested.mkdir(parents=True)
            (nested / "package.diag.zip").write_bytes(b"temporary")
            evidence_store = RecordingEvidenceStore()
            example_store = RecordingExampleStore()
            commands = LocalDataCommands(
                evidence_store=evidence_store,
                example_store=example_store,
                diagnostic_exporter=RecordingDiagnosticExporter(),
                clock=lambda: NOW,
                data_root=root,
            )

            rejected = commands.delete_all_local_data(confirmed=False)
            deleted = commands.delete_all_local_data(confirmed=True)

            self.assertIs(
                rejected.code,
                ConsoleStatusCode.CONFIRMATION_REQUIRED,
            )
            self.assertEqual(evidence_store.delete_calls, 1)
            self.assertEqual(example_store.clear_calls, 1)
            self.assertIs(deleted.code, ConsoleStatusCode.SUCCESS)
            self.assertEqual(deleted.affected_items, 5)
            self.assertFalse(temporary_root.exists())

    def test_delete_all_attempts_remaining_layers_after_private_failure(self):
        from shielddome_endpoint.console_models import ConsoleStatusCode
        from shielddome_endpoint.local_data_commands import LocalDataCommands

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            temporary_root = root / "diagnostic-temp"
            temporary_root.mkdir()
            (temporary_root / "private.tmp").write_text(
                "SUBJECT user@example.test token=secret",
                encoding="utf-8",
            )
            evidence_store = RecordingEvidenceStore(
                RuntimeError(
                    "SUBJECT user@example.test C:\\Users\\private\\evidence.sqlite3"
                )
            )
            example_store = RecordingExampleStore()
            result = LocalDataCommands(
                evidence_store=evidence_store,
                example_store=example_store,
                diagnostic_exporter=RecordingDiagnosticExporter(),
                clock=lambda: NOW,
                data_root=root,
            ).delete_all_local_data(confirmed=True)

            self.assertIs(
                result.code,
                ConsoleStatusCode.LOCAL_DATA_DELETE_PARTIAL_FAILURE,
            )
            self.assertEqual(evidence_store.delete_calls, 1)
            self.assertEqual(example_store.clear_calls, 1)
            self.assertFalse(temporary_root.exists())
            serialized = repr(result)
            for forbidden in (
                "SUBJECT",
                "user@example.test",
                "token=secret",
                "C:\\Users",
                "RuntimeError",
            ):
                self.assertNotIn(forbidden, serialized)

    def test_diagnostic_export_requires_explicit_confirmation_and_selected_path(self):
        from shielddome_endpoint.console_models import ConsoleStatusCode
        from shielddome_endpoint.local_data_commands import LocalDataCommands

        exporter = RecordingDiagnosticExporter()
        commands = LocalDataCommands(
            evidence_store=object(),
            example_store=RecordingExampleStore(),
            diagnostic_exporter=exporter,
            clock=lambda: NOW,
            data_root=Path("C:/safe-test-root"),
        )
        selected = Path("C:/selected/support.diag.zip")

        for invalid_confirmation in (False, 1, "yes", None):
            with self.subTest(invalid_confirmation=invalid_confirmation):
                result = commands.export_diagnostics(
                    selected,
                    confirmed=invalid_confirmation,
                )
                self.assertIs(
                    result.code,
                    ConsoleStatusCode.CONFIRMATION_REQUIRED,
                )
        exported = commands.export_diagnostics(
            selected,
            confirmed=True,
            overwrite=True,
        )

        self.assertEqual(exporter.calls, [(selected, True, True)])
        self.assertIs(exported.code, ConsoleStatusCode.DIAGNOSTIC_EXPORTED)
        self.assertIsNone(exported.payload)
        self.assertNotIn(str(selected), repr(exported))
    def test_delete_one_and_clear_examples_use_stable_results(self):
        from shielddome_endpoint.confirmed_examples import ExampleLabel
        from shielddome_endpoint.console_models import ConsoleStatusCode
        from shielddome_endpoint.local_data_commands import LocalDataCommands

        store = RecordingExampleStore()
        commands = LocalDataCommands(
            evidence_store=object(),
            example_store=store,
            diagnostic_exporter=object(),
            clock=lambda: NOW,
            data_root=Path("C:/safe-test-root"),
        )

        deleted = commands.delete_example("a" * 64, ExampleLabel.BENIGN)
        rejected_clear = commands.clear_examples(confirmed=False)
        cleared = commands.clear_examples(confirmed=True)

        self.assertIs(deleted.code, ConsoleStatusCode.SUCCESS)
        self.assertEqual(deleted.affected_items, 1)
        self.assertEqual(store.delete_calls, [("a" * 64, ExampleLabel.BENIGN)])
        self.assertIs(
            rejected_clear.code,
            ConsoleStatusCode.CONFIRMATION_REQUIRED,
        )
        self.assertEqual(store.clear_calls, 1)
        self.assertIs(cleared.code, ConsoleStatusCode.SUCCESS)
        self.assertEqual(cleared.affected_items, 3)

    def test_benign_and_phishing_commands_require_explicit_confirmation(self):
        from shielddome_endpoint.console_models import ConsoleStatusCode
        from shielddome_endpoint.local_data_commands import LocalDataCommands

        store = RecordingExampleStore()
        commands = LocalDataCommands(
            evidence_store=object(),
            example_store=store,
            diagnostic_exporter=object(),
            clock=lambda: NOW,
            data_root=Path("C:/safe-test-root"),
        )
        vector = make_vector()

        rejected = commands.confirm_benign(vector, confirmed=False)
        benign = commands.confirm_benign(vector, confirmed=True)
        phishing = commands.confirm_phishing(vector, confirmed=True)

        self.assertIs(rejected.code, ConsoleStatusCode.CONFIRMATION_REQUIRED)
        self.assertEqual(len(store.confirm_calls), 2)
        self.assertEqual(
            store.confirm_calls[0],
            (
                vector,
                UserConfirmationAction.CONFIRM_BENIGN,
                ExampleSource.BROWSER_NATIVE,
                NOW,
            ),
        )
        self.assertEqual(
            store.confirm_calls[1],
            (
                vector,
                UserConfirmationAction.CONFIRM_PHISHING,
                ExampleSource.BROWSER_NATIVE,
                NOW,
            ),
        )
        self.assertIs(benign.code, ConsoleStatusCode.EXAMPLE_ADDED)
        self.assertIs(phishing.code, ConsoleStatusCode.EXAMPLE_ADDED)


if __name__ == "__main__":
    unittest.main()
