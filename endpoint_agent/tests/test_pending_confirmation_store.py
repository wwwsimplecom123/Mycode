import os
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone

ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))

from shielddome_endpoint.domain import MailObservation
from shielddome_endpoint.feature_pipeline import FeaturePipeline
from shielddome_endpoint.key_protection import CurrentUserKeyProtector, UserDataKeyManager
from shielddome_endpoint.pending_confirmation_store import PendingConfirmationStore
from shielddome_endpoint.console_service import PersonalConsoleService
from shielddome_endpoint.console_models import ConsoleOperationResult, ConsoleStatusCode


class _Backend:
    def protect(self, value, *, flags): return b"protected:" + value
    def unprotect(self, value, *, flags): return value.removeprefix(b"protected:")


def _vector():
    return FeaturePipeline().transform(MailObservation(
        source_kind="browser_native", source_message_id="opaque", subject="Account notice",
        sender="sender@example.test", reply_to=None, recipient_summary=(),
        sanitized_body_text="Review account", authentication_observations=(),
        normalized_links=(), attachment_metadata=(), language_hint="en",
        observed_at=datetime(2026, 8, 10, tzinfo=timezone.utc),
    ))


class PendingConfirmationStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        os.environ["LOCALAPPDATA"] = self.temp.name
        root = Path(self.temp.name) / "ShieldDome" / "EndpointAgent" / "pending"
        protector = CurrentUserKeyProtector(backend=_Backend(), scope_identity_provider=lambda: "user-a")
        manager = UserDataKeyManager(root, protector=protector, database_filename="pending.sqlite3")
        self.store = PendingConfirmationStore(key_manager=manager)
        self.now = datetime(2026, 8, 10, tzinfo=timezone.utc)

    def test_round_trip_encrypts_vector_and_uses_random_nonce(self):
        vector = _vector()
        self.store.put("event-a", vector, created_at=self.now)
        self.store.put("event-b", vector, created_at=self.now)
        self.assertEqual(vector, self.store.get("event-a", now=self.now))
        raw = self.store.database_path.read_bytes()
        self.assertNotIn(b"numeric_features", raw)
        import sqlite3
        with closing(sqlite3.connect(self.store.database_path)) as db:
            nonces = [row[0] for row in db.execute("select nonce from pending_confirmation_contexts")]
        self.assertEqual(2, len(set(nonces)))

    def test_expiry_boundary_cleanup_and_clear_destroy_all_files(self):
        vector = _vector()
        self.store.put("event-a", vector, created_at=self.now)
        self.assertEqual(vector, self.store.get("event-a", now=self.now + timedelta(days=15) - timedelta(microseconds=1)))
        with self.assertRaisesRegex(RuntimeError, "pending_context_expired"):
            self.store.get("event-a", now=self.now + timedelta(days=15))
        self.store.put("event-b", vector, created_at=self.now)
        self.assertTrue(self.store.delete("event-b"))
        self.store.put("event-c", vector, created_at=self.now)
        key_path = self.store.key_path
        self.store.clear()
        self.assertFalse(self.store.database_path.exists())
        self.assertFalse(key_path.exists())

    def test_ciphertext_and_index_tampering_fail_closed(self):
        import sqlite3
        vector = _vector()
        self.store.put("event-a", vector, created_at=self.now)
        with closing(sqlite3.connect(self.store.database_path)) as db, db:
            db.execute("update pending_confirmation_contexts set ciphertext=x'00' where local_event_id='event-a'")
        with self.assertRaisesRegex(RuntimeError, "pending_context_corrupt"):
            self.store.get("event-a", now=self.now)

    def test_dedicated_key_rejects_another_windows_user(self):
        self.store.put("event-a", _vector(), created_at=self.now)
        protector = CurrentUserKeyProtector(backend=_Backend(), scope_identity_provider=lambda: "user-b")
        other = PendingConfirmationStore(key_manager=UserDataKeyManager(self.store.database_path.parents[1], protector=protector, database_filename="pending.sqlite3"))
        with self.assertRaisesRegex(RuntimeError, "pending_context_key_unavailable"):
            other.get("event-a", now=self.now)


class _Evidence:
    def list_page(self, **kwargs): return ()

class _Examples:
    def diagnostic_aggregate(self):
        from shielddome_endpoint.example_store import ExampleLibraryAggregate
        return ExampleLibraryAggregate(0, 0, 0, 0, 0)

class _Commands:
    def __init__(self, code=ConsoleStatusCode.EXAMPLE_ADDED): self.code=code; self.calls=[]
    def confirm_benign(self, vector, *, confirmed): self.calls.append((vector, confirmed)); return ConsoleOperationResult(self.code, None, 1)
    confirm_phishing = confirm_benign

class _Pending:
    def __init__(self, vector): self.vector=vector; self.deleted=[]
    def get(self, event_id, *, now): return self.vector
    def delete(self, event_id): self.deleted.append(event_id); return True

class ConfirmationOrchestrationTests(unittest.TestCase):
    def test_success_deletes_context_after_sample_write_and_duplicate_is_idempotent(self):
        pending = _Pending(_vector()); commands = _Commands()
        service = PersonalConsoleService(evidence_store=_Evidence(), example_store=_Examples(), clock=lambda: datetime(2026,8,10,tzinfo=timezone.utc), local_data_commands=commands, pending_confirmation_store=pending)
        result = service.confirm_event_benign("event-a", confirmed=True)
        self.assertEqual(ConsoleStatusCode.EXAMPLE_ADDED, result.code)
        self.assertEqual(["event-a"], pending.deleted)
        self.assertEqual(1, len(commands.calls))

    def test_sample_failure_retains_context_and_missing_is_stable(self):
        pending = _Pending(_vector()); commands = _Commands(ConsoleStatusCode.EXAMPLE_STORE_UNAVAILABLE)
        service = PersonalConsoleService(evidence_store=_Evidence(), example_store=_Examples(), clock=lambda: datetime(2026,8,10,tzinfo=timezone.utc), local_data_commands=commands, pending_confirmation_store=pending)
        self.assertEqual(ConsoleStatusCode.EXAMPLE_STORE_UNAVAILABLE, service.confirm_event_phishing("event-a", confirmed=True).code)
        self.assertEqual([], pending.deleted)
        pending.vector = None
        self.assertEqual(ConsoleStatusCode.PENDING_CONTEXT_NOT_FOUND, service.confirm_event_benign("event-a", confirmed=True).code)


if __name__ == "__main__":
    unittest.main()
