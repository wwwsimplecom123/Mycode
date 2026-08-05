from pathlib import Path
from datetime import timedelta
import sqlite3
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))

from test_confirmed_examples import CONFIRMED_AT, make_vector

from shielddome_endpoint.confirmed_examples import (
    ExampleLabel,
    ExampleSource,
    UserConfirmationAction,
)
from shielddome_endpoint.domain import MailObservation
from shielddome_endpoint.feature_pipeline import FeaturePipeline


class ExampleStoreTests(unittest.TestCase):
    def test_unconfirmed_input_cannot_enter_the_library(self):
        from shielddome_endpoint.example_store import ExampleStore, ExampleStoreError

        with TemporaryDirectory() as temporary_directory:
            store = ExampleStore(Path(temporary_directory))

            with self.assertRaisesRegex(
                ExampleStoreError,
                "^invalid_confirmation$",
            ):
                store.confirm(
                    make_vector(),
                    action=None,
                    source=ExampleSource.BROWSER_NATIVE,
                    confirmed_at=CONFIRMED_AT,
                )

            self.assertEqual(store.list_page(), ())
            self.assertFalse(hasattr(store, "put"))
            self.assertFalse(store.database_path.exists())
            self.assertFalse(store.key_path.exists())

    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_explicit_confirmation_is_encrypted_and_retrievable(self):
        from shielddome_endpoint.example_store import (
            ExampleConfirmationStatus,
            ExampleStore,
        )

        with TemporaryDirectory() as temporary_directory:
            store = ExampleStore(Path(temporary_directory))

            status = store.confirm(
                make_vector(),
                action=UserConfirmationAction.CONFIRM_BENIGN,
                source=ExampleSource.BROWSER_NATIVE,
                confirmed_at=CONFIRMED_AT,
            )
            page = store.list_page()

            self.assertIs(status, ExampleConfirmationStatus.ADDED)
            self.assertEqual(len(page), 1)
            self.assertIs(page[0].label, ExampleLabel.BENIGN)
            self.assertIs(page[0].source, ExampleSource.BROWSER_NATIVE)
            self.assertEqual(page[0].confirmed_at, CONFIRMED_AT)
            self.assertEqual(page[0].feature_vector, make_vector())
            self.assertEqual(len(page[0].keyed_fingerprint), 64)
            self.assertTrue(store.database_path.exists())
            self.assertTrue(store.key_path.exists())

    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_same_user_deduplicates_same_label_and_preserves_conflicting_labels(self):
        from shielddome_endpoint.example_store import (
            ExampleConfirmationStatus,
            ExampleStore,
        )

        with TemporaryDirectory() as temporary_directory:
            store = ExampleStore(Path(temporary_directory))
            vector = make_vector()

            first = store.confirm(
                vector,
                action=UserConfirmationAction.CONFIRM_BENIGN,
                source=ExampleSource.BROWSER_NATIVE,
                confirmed_at=CONFIRMED_AT,
            )
            duplicate = store.confirm(
                vector,
                action=UserConfirmationAction.CONFIRM_BENIGN,
                source=ExampleSource.BROWSER_NATIVE,
                confirmed_at=CONFIRMED_AT,
            )
            conflict = store.confirm(
                vector,
                action=UserConfirmationAction.CONFIRM_PHISHING,
                source=ExampleSource.BROWSER_NATIVE,
                confirmed_at=CONFIRMED_AT,
            )

            self.assertIs(first, ExampleConfirmationStatus.ADDED)
            self.assertIs(duplicate, ExampleConfirmationStatus.DUPLICATE)
            self.assertIs(conflict, ExampleConfirmationStatus.CONFLICT)
            self.assertEqual(len(store.list_page()), 2)
            self.assertEqual(
                {item.label for item in store.find_exact(vector)},
                {ExampleLabel.BENIGN, ExampleLabel.PHISHING},
            )

    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_pagination_label_filter_delete_one_and_clear_are_complete(self):
        from shielddome_endpoint.example_store import ExampleStore

        with TemporaryDirectory() as temporary_directory:
            store = ExampleStore(Path(temporary_directory))
            first_vector = make_vector(subject="First routine notice")
            second_vector = make_vector(subject="Second phishing notice")
            store.confirm(
                first_vector,
                action=UserConfirmationAction.CONFIRM_BENIGN,
                source=ExampleSource.BROWSER_NATIVE,
                confirmed_at=CONFIRMED_AT,
            )
            store.confirm(
                second_vector,
                action=UserConfirmationAction.CONFIRM_PHISHING,
                source=ExampleSource.BROWSER_NATIVE,
                confirmed_at=CONFIRMED_AT + timedelta(hours=1),
            )

            first_page = store.list_page(offset=0, limit=1)
            second_page = store.list_page(offset=1, limit=1)
            benign_page = store.list_page(label=ExampleLabel.BENIGN)

            self.assertIs(first_page[0].label, ExampleLabel.PHISHING)
            self.assertIs(second_page[0].label, ExampleLabel.BENIGN)
            self.assertEqual(benign_page, (second_page[0],))
            self.assertTrue(
                store.delete(
                    second_page[0].keyed_fingerprint,
                    ExampleLabel.BENIGN,
                )
            )
            self.assertFalse(
                store.delete(
                    second_page[0].keyed_fingerprint,
                    ExampleLabel.BENIGN,
                )
            )
            self.assertEqual(store.list_page(), first_page)
            self.assertEqual(store.clear(), 1)
            self.assertEqual(store.clear(), 0)
            self.assertEqual(store.list_page(), ())
            self.assertFalse(store.database_path.exists())
            self.assertFalse(store.key_path.exists())

    def test_different_user_scope_cannot_open_the_same_example_library(self):
        from test_key_protection import RecordingDpapiBackend
        from shielddome_endpoint.example_store import ExampleStore, ExampleStoreError
        from shielddome_endpoint.key_protection import (
            CurrentUserKeyProtector,
            UserDataKeyManager,
        )

        with TemporaryDirectory() as temporary_directory:
            example_root = Path(temporary_directory) / "examples"
            backend = RecordingDpapiBackend()
            user_a = UserDataKeyManager(
                example_root,
                protector=CurrentUserKeyProtector(
                    backend=backend,
                    scope_identity_provider=lambda: "S-1-5-21-user-a",
                ),
                database_filename="confirmed_examples.sqlite3",
            )
            user_b = UserDataKeyManager(
                example_root,
                protector=CurrentUserKeyProtector(
                    backend=backend,
                    scope_identity_provider=lambda: "S-1-5-21-user-b",
                ),
                database_filename="confirmed_examples.sqlite3",
            )
            first_store = ExampleStore(key_manager=user_a)
            first_store.confirm(
                make_vector(),
                action=UserConfirmationAction.CONFIRM_BENIGN,
                source=ExampleSource.BROWSER_NATIVE,
                confirmed_at=CONFIRMED_AT,
            )

            with self.assertRaisesRegex(
                ExampleStoreError,
                "^example_key_unavailable$",
            ):
                ExampleStore(key_manager=user_b).list_page()

    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_new_unique_fingerprint_is_rejected_at_capacity(self):
        from shielddome_endpoint.example_store import ExampleStore, ExampleStoreError

        with TemporaryDirectory() as temporary_directory:
            store = ExampleStore(Path(temporary_directory))
            with patch(
                "shielddome_endpoint.example_store.EXAMPLE_LIBRARY_MAX_FINGERPRINTS",
                2,
            ):
                for index in range(2):
                    store.confirm(
                        make_vector(subject=f"Allowed example {index}"),
                        action=UserConfirmationAction.CONFIRM_BENIGN,
                        source=ExampleSource.BROWSER_NATIVE,
                        confirmed_at=CONFIRMED_AT + timedelta(minutes=index),
                    )
                with self.assertRaisesRegex(
                    ExampleStoreError,
                    "^example_capacity_exceeded$",
                ):
                    store.confirm(
                        make_vector(subject="Rejected third example"),
                        action=UserConfirmationAction.CONFIRM_BENIGN,
                        source=ExampleSource.BROWSER_NATIVE,
                        confirmed_at=CONFIRMED_AT + timedelta(minutes=3),
                    )

            self.assertEqual(len(store.list_page()), 2)

    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_database_and_sidecars_contain_no_mail_source_values(self):
        from shielddome_endpoint.example_store import ExampleStore

        private_values = (
            "SUBJECT-PRIVATE-6B-81ea",
            "BODY-PRIVATE-6B-47c1",
            "private-6b-user@example.test",
            "https://private-6b.example.test/login?token=unique-19af",
            "attachment-private-6b-d921.pdf.exe",
            "source-message-private-6b-0031",
        )
        observation = MailObservation(
            source_kind="browser_native",
            source_message_id=private_values[5],
            subject=private_values[0],
            sender=private_values[2],
            reply_to=None,
            recipient_summary=("current-user",),
            sanitized_body_text=private_values[1],
            authentication_observations=(),
            normalized_links=(private_values[3],),
            attachment_metadata=(("name", private_values[4]),),
            language_hint="en",
            observed_at=CONFIRMED_AT,
        )

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            store = ExampleStore(root)
            store.confirm(
                FeaturePipeline().transform(observation),
                action=UserConfirmationAction.CONFIRM_PHISHING,
                source=ExampleSource.BROWSER_NATIVE,
                confirmed_at=CONFIRMED_AT,
            )

            persisted = b"".join(
                path.read_bytes()
                for path in root.rglob("*")
                if path.is_file()
            )
            for private_value in private_values:
                with self.subTest(private_value=private_value):
                    self.assertNotIn(private_value.encode("utf-8"), persisted)

    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
    def test_tampered_ciphertext_fails_closed_without_partial_results(self):
        from shielddome_endpoint.example_store import ExampleStore, ExampleStoreError

        with TemporaryDirectory() as temporary_directory:
            store = ExampleStore(Path(temporary_directory))
            store.confirm(
                make_vector(),
                action=UserConfirmationAction.CONFIRM_BENIGN,
                source=ExampleSource.BROWSER_NATIVE,
                confirmed_at=CONFIRMED_AT,
            )
            connection = sqlite3.connect(store.database_path)
            try:
                tag = connection.execute(
                    "SELECT authentication_tag FROM confirmed_examples"
                ).fetchone()[0]
                connection.execute(
                    "UPDATE confirmed_examples SET authentication_tag = ?",
                    (bytes([tag[0] ^ 1]) + tag[1:],),
                )
                connection.commit()
            finally:
                connection.close()

            with self.assertRaisesRegex(
                ExampleStoreError,
                "^example_decryption_failed$",
            ):
                store.list_page()

    def test_page_and_filter_queries_enforce_public_bounds(self):
        from shielddome_endpoint.example_store import ExampleStore, ExampleStoreError

        with TemporaryDirectory() as temporary_directory:
            store = ExampleStore(Path(temporary_directory))
            for arguments in (
                {"limit": 0},
                {"limit": 51},
                {"offset": -1},
                {"offset": 257},
                {"label": "benign"},
            ):
                with self.subTest(arguments=arguments):
                    with self.assertRaisesRegex(
                        ExampleStoreError,
                        "^invalid_store_request$",
                    ):
                        store.list_page(**arguments)


if __name__ == "__main__":
    unittest.main()
