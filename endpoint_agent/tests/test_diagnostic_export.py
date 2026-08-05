from pathlib import Path
from pathlib import PurePosixPath
import hashlib
import json
import os
import socket
import sqlite3
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from zipfile import ZipFile


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))

from test_diagnostics import (
    NOW,
    StaticEvidenceStore,
    StaticExampleStore,
)

from shielddome_endpoint.diagnostics import DiagnosticsCollector
from shielddome_endpoint.confirmed_examples import (
    ExampleSource,
    UserConfirmationAction,
)
from shielddome_endpoint.domain import MailObservation
from shielddome_endpoint.evidence_record import EndpointEvidenceRecord
from shielddome_endpoint.evidence_store import EvidenceStore
from shielddome_endpoint.example_store import ExampleLibraryAggregate
from shielddome_endpoint.example_store import ExampleStore
from shielddome_endpoint.feature_pipeline import FeaturePipeline
from shielddome_endpoint.local_detection import LocalDetectionService


def make_collector():
    return DiagnosticsCollector(
        evidence_store=StaticEvidenceStore(()),
        example_store=StaticExampleStore(
            ExampleLibraryAggregate(0, 0, 0, 0, 0)
        ),
        clock=lambda: NOW,
    )


class DiagnosticExporterTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_export_failure_does_not_change_detection_or_local_evidence(self):
        from shielddome_endpoint.diagnostic_export import (
            DiagnosticExportError,
            DiagnosticExporter,
        )

        observation = MailObservation(
            source_kind="browser_native",
            source_message_id="failure-isolation-message",
            subject="Routine internal notice",
            sender="sender@corp.test",
            reply_to="sender@corp.test",
            recipient_summary=("current-user",),
            sanitized_body_text="Use the normal company process.",
            authentication_observations=(),
            normalized_links=(),
            attachment_metadata=(),
            language_hint="en",
            observed_at=NOW,
        )
        service = LocalDetectionService()
        before = service.detect(
            observation,
            local_event_id="event-export-failure",
            observed_now=NOW,
        )
        record = EndpointEvidenceRecord.from_detection_outcome(
            before,
            detected_at=NOW,
            source_kind=observation.source_kind,
        )

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output_path = root / "failed.diag.zip"
            with patch.dict(os.environ, {"LOCALAPPDATA": str(root)}):
                evidence_store = EvidenceStore(root)
                evidence_store.put(record)
                exporter = DiagnosticExporter(
                    collector=DiagnosticsCollector(
                        evidence_store=evidence_store,
                        example_store=ExampleStore(root),
                        clock=lambda: NOW,
                    ),
                    clock=lambda: NOW,
                )
                with patch(
                    "shielddome_endpoint.diagnostic_export.DIAGNOSTIC_ARCHIVE_MAX_BYTES",
                    10,
                ):
                    with self.assertRaisesRegex(
                        DiagnosticExportError,
                        "^diagnostic_archive_size_exceeded$",
                    ):
                        exporter.export(output_path, confirmed=True)

                self.assertEqual(evidence_store.get(record.local_event_id), record)
                after = service.detect(
                    observation,
                    local_event_id="event-export-failure",
                    observed_now=NOW,
                )

            self.assertEqual(after, before)
            self.assertFalse(output_path.exists())

    def test_same_input_has_consistent_structure_and_explicit_overwrite_succeeds(self):
        from shielddome_endpoint.diagnostic_export import DiagnosticExporter

        def topology(value):
            if isinstance(value, dict):
                return tuple(
                    (key, topology(value[key])) for key in sorted(value)
                )
            if isinstance(value, list):
                return ("list", tuple(topology(item) for item in value))
            return type(value).__name__

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            first = root / "first.diag.zip"
            second = root / "second.diag.zip"
            overwritten = root / "overwritten.diag.zip"
            overwritten.write_bytes(b"old-package")
            with patch.dict(os.environ, {"LOCALAPPDATA": str(root)}):
                exporter = DiagnosticExporter(
                    collector=make_collector(),
                    clock=lambda: NOW,
                )
                exporter.export(first, confirmed=True)
                exporter.export(second, confirmed=True)
                exporter.export(
                    overwritten,
                    confirmed=True,
                    overwrite=True,
                )

            structures = []
            for path in (first, second, overwritten):
                with ZipFile(path) as archive:
                    structures.append(
                        (
                            tuple(archive.namelist()),
                            tuple(
                                (
                                    name,
                                    topology(json.loads(archive.read(name))),
                                )
                                for name in archive.namelist()
                            ),
                        )
                    )
            self.assertEqual(structures[0], structures[1])
            self.assertEqual(structures[0], structures[2])
            self.assertNotEqual(overwritten.read_bytes(), b"old-package")

    def test_size_failures_preserve_existing_output_and_clean_temporary_files(self):
        from shielddome_endpoint.diagnostic_export import (
            DiagnosticExportError,
            DiagnosticExporter,
        )

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output_path = root / "existing.diag.zip"
            output_path.write_bytes(b"existing-package")
            with patch.dict(os.environ, {"LOCALAPPDATA": str(root)}):
                exporter = DiagnosticExporter(
                    collector=make_collector(),
                    clock=lambda: NOW,
                )
                with patch(
                    "shielddome_endpoint.diagnostic_export.DIAGNOSTIC_FILE_MAX_BYTES",
                    10,
                ):
                    with self.assertRaisesRegex(
                        DiagnosticExportError,
                        "^diagnostic_file_size_exceeded$",
                    ):
                        exporter.export(
                            output_path,
                            confirmed=True,
                            overwrite=True,
                        )
                with patch(
                    "shielddome_endpoint.diagnostic_export.DIAGNOSTIC_ARCHIVE_MAX_BYTES",
                    10,
                ):
                    with self.assertRaisesRegex(
                        DiagnosticExportError,
                        "^diagnostic_archive_size_exceeded$",
                    ):
                        exporter.export(
                            output_path,
                            confirmed=True,
                            overwrite=True,
                        )

            self.assertEqual(output_path.read_bytes(), b"existing-package")
            temporary_parent = (
                root / "ShieldDome" / "EndpointAgent" / "diagnostic-temp"
            )
            if temporary_parent.exists():
                self.assertEqual(tuple(temporary_parent.iterdir()), ())
            self.assertEqual(tuple(root.glob(".*.tmp")), ())

    def test_success_and_zip_failure_cleanup_current_user_temporary_directory(self):
        from shielddome_endpoint.diagnostic_export import (
            DiagnosticExportError,
            DiagnosticExporter,
        )

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            temporary_parent = (
                root / "ShieldDome" / "EndpointAgent" / "diagnostic-temp"
            )
            exporter = DiagnosticExporter(
                collector=make_collector(),
                clock=lambda: NOW,
            )
            with patch.dict(os.environ, {"LOCALAPPDATA": str(root)}):
                exporter.export(root / "success.diag.zip", confirmed=True)
                self.assertEqual(tuple(temporary_parent.iterdir()), ())

                with patch(
                    "shielddome_endpoint.diagnostic_export.ZipFile.writestr",
                    side_effect=OSError(
                        "SUBJECT user@example.test C:\\Users\\private"
                    ),
                ):
                    with self.assertRaisesRegex(
                        DiagnosticExportError,
                        "^diagnostic_export_failed$",
                    ):
                        exporter.export(root / "failure.diag.zip", confirmed=True)

            self.assertFalse((root / "failure.diag.zip").exists())
            self.assertEqual(tuple(temporary_parent.iterdir()), ())

    def test_export_creates_no_network_connection_or_listener(self):
        from shielddome_endpoint.diagnostic_export import DiagnosticExporter

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output_path = root / "offline.diag.zip"
            with patch.dict(os.environ, {"LOCALAPPDATA": str(root)}):
                with patch.object(
                    socket,
                    "socket",
                    side_effect=AssertionError("network socket created"),
                ) as socket_factory, patch.object(
                    socket,
                    "create_connection",
                    side_effect=AssertionError("network connection created"),
                ) as create_connection:
                    DiagnosticExporter(
                        collector=make_collector(),
                        clock=lambda: NOW,
                    ).export(output_path, confirmed=True)

            socket_factory.assert_not_called()
            create_connection.assert_not_called()
            self.assertTrue(output_path.is_file())

    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_real_store_export_contains_no_mail_samples_or_crypto_material(self):
        from shielddome_endpoint.diagnostic_export import DiagnosticExporter

        private_values = (
            "SUBJECT-PRIVATE-6C-a21f",
            "BODY-PRIVATE-6C-f11d APIKEY-SECRET-6C",
            "sender-private-6c@example.test",
            "recipient-private-6c@example.test",
            "https://private-6c.example.test/login?token=secret-6c",
            "attachment-private-6c.pdf.exe",
            "source-message-private-6c",
        )
        observation = MailObservation(
            source_kind="browser_native",
            source_message_id=private_values[6],
            subject=private_values[0],
            sender=private_values[2],
            reply_to=private_values[2],
            recipient_summary=(private_values[3],),
            sanitized_body_text=private_values[1],
            authentication_observations=(),
            normalized_links=(private_values[4],),
            attachment_metadata=(("name", private_values[5]),),
            language_hint="en",
            observed_at=NOW,
        )
        outcome = LocalDetectionService().detect(
            observation,
            local_event_id="event-private-diagnostic",
            observed_now=NOW,
        )
        record = EndpointEvidenceRecord.from_detection_outcome(
            outcome,
            detected_at=NOW,
            source_kind=observation.source_kind,
        )

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output_path = root / "private-scan.diag.zip"
            with patch.dict(os.environ, {"LOCALAPPDATA": str(root)}):
                evidence_store = EvidenceStore(root)
                example_store = ExampleStore(root)
                evidence_store.put(record)
                example_store.confirm(
                    FeaturePipeline().transform(observation),
                    action=UserConfirmationAction.CONFIRM_PHISHING,
                    source=ExampleSource.BROWSER_NATIVE,
                    confirmed_at=NOW,
                )
                sample_fingerprint = example_store.list_page()[0].keyed_fingerprint
                connection = sqlite3.connect(evidence_store.database_path)
                try:
                    nonce, ciphertext, authentication_tag = connection.execute(
                        "SELECT nonce, ciphertext, authentication_tag "
                        "FROM endpoint_evidence"
                    ).fetchone()
                finally:
                    connection.close()
                protected_key = (root / "keys" / "evidence.key").read_bytes()

                DiagnosticExporter(
                    collector=DiagnosticsCollector(
                        evidence_store=evidence_store,
                        example_store=example_store,
                        clock=lambda: NOW,
                    ),
                    clock=lambda: NOW,
                ).export(output_path, confirmed=True)

            with ZipFile(output_path) as archive:
                combined = b"\n".join(
                    archive.read(name) for name in archive.namelist()
                )
            for forbidden in private_values:
                with self.subTest(forbidden=forbidden):
                    self.assertNotIn(forbidden.encode("utf-8"), combined)
            for forbidden in (
                sample_fingerprint.encode("ascii"),
                bytes(nonce),
                bytes(ciphertext),
                bytes(authentication_tag),
                protected_key,
                b"SQLite format 3",
                b"feature_vector",
                b"keyed_fingerprint",
                b"similarity",
                b"database_path",
                b"authentication_tag",
                b"ciphertext",
                b"nonce",
                b"rule_weight",
                b"model_reason",
                b"traceback",
            ):
                with self.subTest(forbidden=forbidden):
                    self.assertNotIn(forbidden, combined)

    def test_archive_has_fixed_safe_whitelist_and_verified_manifest(self):
        from shielddome_endpoint.diagnostic_export import (
            DIAGNOSTIC_ARCHIVE_NAMES,
            DiagnosticExporter,
        )

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output_path = root / "chosen.diag.zip"
            with patch.dict(os.environ, {"LOCALAPPDATA": str(root)}):
                result = DiagnosticExporter(
                    collector=make_collector(),
                    clock=lambda: NOW,
                ).export(output_path, confirmed=True)

            self.assertEqual(result.output_path, output_path.resolve())
            self.assertEqual(result.archive_size_bytes, output_path.stat().st_size)
            self.assertEqual(
                result.archive_sha256,
                hashlib.sha256(output_path.read_bytes()).hexdigest(),
            )
            with ZipFile(output_path) as archive:
                names = tuple(sorted(archive.namelist()))
                self.assertEqual(names, tuple(sorted(DIAGNOSTIC_ARCHIVE_NAMES)))
                for name in names:
                    with self.subTest(name=name):
                        member = PurePosixPath(name)
                        self.assertFalse(member.is_absolute())
                        self.assertNotIn("..", member.parts)
                        self.assertEqual(len(member.parts), 1)

                manifest = json.loads(archive.read("manifest.json"))
                self.assertEqual(manifest["schema_version"], "1.0")
                self.assertEqual(
                    tuple(manifest["archive_entries"]),
                    DIAGNOSTIC_ARCHIVE_NAMES,
                )
                self.assertEqual(
                    [item["name"] for item in manifest["files"]],
                    ["diagnostics.json", "compatibility.json"],
                )
                for item in manifest["files"]:
                    payload = archive.read(item["name"])
                    self.assertEqual(item["size_bytes"], len(payload))
                    self.assertEqual(
                        item["sha256"],
                        hashlib.sha256(payload).hexdigest(),
                    )

                compatibility = json.loads(archive.read("compatibility.json"))
                self.assertEqual(
                    set(compatibility),
                    {
                        "agent_package_version",
                        "operating_system",
                        "packaging_kind",
                        "python_implementation",
                        "python_version",
                        "schema_version",
                        "windows_major_version",
                    },
                )

    def test_requires_confirmation_and_separate_overwrite_choice(self):
        from shielddome_endpoint.diagnostic_export import (
            DiagnosticExportError,
            DiagnosticExporter,
        )

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output_path = root / "chosen.diag.zip"
            with patch.dict(os.environ, {"LOCALAPPDATA": str(root)}):
                exporter = DiagnosticExporter(
                    collector=make_collector(),
                    clock=lambda: NOW,
                )
                for invalid_confirmation in (False, 1, "yes", None):
                    with self.subTest(
                        invalid_confirmation=invalid_confirmation
                    ):
                        with self.assertRaisesRegex(
                            DiagnosticExportError,
                            "^diagnostic_confirmation_required$",
                        ):
                            exporter.export(
                                output_path,
                                confirmed=invalid_confirmation,
                            )
                self.assertFalse(output_path.exists())

                output_path.write_bytes(b"existing-package")
                with self.assertRaisesRegex(
                    DiagnosticExportError,
                    "^diagnostic_output_exists$",
                ):
                    exporter.export(output_path, confirmed=True)
                self.assertEqual(output_path.read_bytes(), b"existing-package")
                with self.assertRaisesRegex(
                    DiagnosticExportError,
                    "^invalid_diagnostic_export_request$",
                ):
                    exporter.export(
                        output_path,
                        confirmed=True,
                        overwrite=1,
                    )


if __name__ == "__main__":
    unittest.main()
