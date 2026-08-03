from dataclasses import replace
from datetime import timedelta
from pathlib import Path
import sqlite3
import sys
from tempfile import TemporaryDirectory
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))

from test_evidence_crypto import make_record
from test_evidence_record import DETECTED_AT

from shielddome_endpoint.domain import MailObservation
from shielddome_endpoint.evidence_record import EndpointEvidenceRecord
from shielddome_endpoint.local_detection import LocalDetectionService


class EvidenceStoreTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_put_get_and_deterministic_pagination(self):
        from shielddome_endpoint.evidence_store import EvidenceStore

        with TemporaryDirectory() as temporary_directory:
            store = EvidenceStore(Path(temporary_directory))
            first = make_record()
            second_detected_at = first.detected_at + timedelta(hours=1)
            second = replace(
                first,
                local_event_id="event-evidence-record-2",
                detected_at=second_detected_at,
                retention_until=second_detected_at + timedelta(days=15),
                rule_codes=("second_event_rule",),
            )

            store.put(first)
            store.put(second)

            self.assertEqual(store.get(first.local_event_id), first)
            self.assertEqual(store.get("event-missing"), None)
            self.assertEqual(store.list_page(offset=0, limit=1), (second,))
            self.assertEqual(store.list_page(offset=1, limit=1), (first,))

    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_cleanup_uses_the_exact_fifteen_day_boundary(self):
        from shielddome_endpoint.evidence_store import EvidenceStore

        with TemporaryDirectory() as temporary_directory:
            record = make_record()
            store = EvidenceStore(
                Path(temporary_directory),
                clock=lambda: record.retention_until,
            )
            store.put(record)

            before_boundary = store.cleanup_expired(
                now=record.retention_until - timedelta(microseconds=1)
            )
            at_boundary = store.cleanup_expired()

            self.assertEqual(before_boundary, 0)
            self.assertEqual(at_boundary, 1)
            self.assertIsNone(store.get(record.local_event_id))

    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_cleanup_of_an_empty_store_does_not_create_data_or_keys(self):
        from shielddome_endpoint.evidence_store import EvidenceStore

        with TemporaryDirectory() as temporary_directory:
            store = EvidenceStore(Path(temporary_directory))

            self.assertEqual(store.cleanup_expired(now=make_record().detected_at), 0)
            self.assertFalse(store.database_path.exists())
            self.assertFalse(
                (Path(temporary_directory) / "keys" / "evidence.key").exists()
            )

    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_delete_all_removes_records_key_wal_shm_journal_and_owned_temp_files(self):
        from shielddome_endpoint.evidence_store import EvidenceStore

        with TemporaryDirectory() as temporary_directory:
            store = EvidenceStore(Path(temporary_directory))
            store.put(make_record())
            database_path = store.database_path
            key_path = Path(temporary_directory) / "keys" / "evidence.key"
            related_paths = (
                Path(f"{database_path}-wal"),
                Path(f"{database_path}-shm"),
                Path(f"{database_path}-journal"),
                database_path.with_name(database_path.name + ".tmp"),
                key_path.with_name(key_path.name + ".tmp"),
            )
            for path in related_paths:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"owned-temporary-data")

            deleted = store.delete_all()

            self.assertEqual(deleted, 1)
            for path in (database_path, key_path, *related_paths):
                with self.subTest(path=path):
                    self.assertFalse(path.exists())
            self.assertEqual(store.delete_all(), 0)

    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_sqlite_contains_only_indexes_and_encrypted_evidence_without_mail_content(self):
        from shielddome_endpoint.evidence_store import EvidenceStore

        private_values = (
            "SUBJECT-PRIVATE-6A-7f2d90",
            "BODY-PRIVATE-6A-1c4481",
            "private-6a-user@example.test",
            "https://private-6a.example.test/login?token=unique-87d1",
            "attachment-private-6a-4b12.pdf.exe",
        )
        observation = MailObservation(
            source_kind="browser_native",
            source_message_id="c" * 64,
            subject=private_values[0],
            sender=private_values[2],
            reply_to=None,
            recipient_summary=("current-user",),
            sanitized_body_text=private_values[1],
            authentication_observations=(),
            normalized_links=(private_values[3],),
            attachment_metadata=(("name", private_values[4]),),
            language_hint="en",
            observed_at=DETECTED_AT,
        )
        outcome = LocalDetectionService().detect(
            observation,
            local_event_id="event-private-store",
            observed_now=DETECTED_AT,
        )
        record = EndpointEvidenceRecord.from_detection_outcome(
            outcome,
            detected_at=DETECTED_AT,
            source_kind=observation.source_kind,
        )

        with TemporaryDirectory() as temporary_directory:
            store = EvidenceStore(Path(temporary_directory))
            store.put(record)

            persisted = b"".join(
                path.read_bytes()
                for path in Path(temporary_directory).rglob("*")
                if path.is_file()
            )
            for private_value in private_values:
                with self.subTest(private_value=private_value):
                    self.assertNotIn(private_value.encode("utf-8"), persisted)

            connection = sqlite3.connect(store.database_path)
            try:
                columns = tuple(
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(endpoint_evidence)"
                    )
                )
            finally:
                connection.close()
            self.assertEqual(
                columns,
                (
                    "local_event_id",
                    "detected_at_utc",
                    "expires_at_utc",
                    "schema_version",
                    "nonce",
                    "ciphertext",
                    "authentication_tag",
                ),
            )

    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_tampered_ciphertext_or_damaged_key_returns_no_evidence(self):
        from shielddome_endpoint.evidence_store import (
            EvidenceStore,
            EvidenceStoreError,
        )

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            record = make_record()
            store = EvidenceStore(root)
            store.put(record)
            connection = sqlite3.connect(store.database_path)
            try:
                tag = connection.execute(
                    "SELECT authentication_tag FROM endpoint_evidence "
                    "WHERE local_event_id = ?",
                    (record.local_event_id,),
                ).fetchone()[0]
                modified_tag = bytes([tag[0] ^ 1]) + tag[1:]
                connection.execute(
                    "UPDATE endpoint_evidence SET authentication_tag = ? "
                    "WHERE local_event_id = ?",
                    (modified_tag, record.local_event_id),
                )
                connection.commit()
            finally:
                connection.close()

            with self.assertRaisesRegex(
                EvidenceStoreError,
                "^evidence_decryption_failed$",
            ):
                store.get(record.local_event_id)

            key_path = root / "keys" / "evidence.key"
            key_path.write_bytes(b"damaged-protected-key")
            reopened = EvidenceStore(root)
            with self.assertRaisesRegex(
                EvidenceStoreError,
                "^evidence_key_unavailable$",
            ):
                reopened.get(record.local_event_id)

    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_unknown_database_schema_version_is_rejected(self):
        from shielddome_endpoint.evidence_store import (
            EvidenceStore,
            EvidenceStoreError,
        )

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            record = make_record()
            store = EvidenceStore(root)
            store.put(record)
            connection = sqlite3.connect(store.database_path)
            try:
                connection.execute("PRAGMA user_version=99")
                connection.commit()
            finally:
                connection.close()

            reopened = EvidenceStore(root)
            with self.assertRaisesRegex(
                EvidenceStoreError,
                "^invalid_database_schema$",
            ):
                reopened.get(record.local_event_id)


if __name__ == "__main__":
    unittest.main()
