from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .confirmed_examples import canonical_feature_vector_bytes, validate_example_feature_vector
from .domain import FeatureVector
from .key_protection import KeyProtectionError, UserDataKeyManager, default_user_data_directory, secure_delete_owned_file
from .privacy import PrivacyScanner

PENDING_CONFIRMATION_SCHEMA_VERSION = "1.0"
PENDING_CONFIRMATION_RETENTION_DAYS = 15
PENDING_DATABASE_FILENAME = "pending_confirmations.sqlite3"
_NONCE_BYTES = 12
_TAG_BYTES = 16
_MAX_ROWS = 4096


class PendingConfirmationStoreError(RuntimeError):
    @property
    def code(self):
        return self.args[0] if self.args else "pending_context_unavailable"


def _utc(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise PendingConfirmationStoreError("invalid_pending_context")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _vector_from_bytes(payload: bytes) -> FeatureVector:
    try:
        value = json.loads(payload.decode("utf-8"))
        if set(value) != {"categorical_features", "missing_value_mask", "numeric_features", "schema_version", "text_input", "text_vector"}:
            raise ValueError
        vector = FeatureVector(
            numeric_features=tuple((item[0], item[1]) for item in value["numeric_features"]),
            categorical_features=tuple((item[0], item[1]) for item in value["categorical_features"]),
            text_input=value["text_input"], text_vector=tuple(value["text_vector"]),
            missing_value_mask=tuple(value["missing_value_mask"]), schema_version=value["schema_version"],
        )
        validate_example_feature_vector(vector)
        if not PrivacyScanner().scan_feature_vector(vector).safe:
            raise ValueError
        return vector
    except Exception:
        raise PendingConfirmationStoreError("pending_context_corrupt") from None


class PendingConfirmationStore:
    def __init__(self, data_directory: Path | None = None, *, key_manager: UserDataKeyManager | None = None):
        if key_manager is not None:
            if data_directory is not None:
                raise PendingConfirmationStoreError("invalid_store_configuration")
            self._key_manager = key_manager
        else:
            root = (default_user_data_directory() if data_directory is None else Path(data_directory)) / "pending_confirmations"
            self._key_manager = UserDataKeyManager(root, database_filename=PENDING_DATABASE_FILENAME)
        self.database_path = self._key_manager.database_path
        self.key_path = self._key_manager.key_path
        self._data_key = None

    def _key(self):
        if self._data_key is None:
            try: self._data_key = self._key_manager.load_or_create()
            except KeyProtectionError as error: raise PendingConfirmationStoreError("pending_context_key_unavailable") from None
        return self._data_key

    def _connect(self):
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            db = sqlite3.connect(self.database_path, timeout=5)
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA secure_delete=ON")
            db.execute("CREATE TABLE IF NOT EXISTS pending_confirmation_contexts (local_event_id TEXT PRIMARY KEY, schema_version TEXT NOT NULL, expires_at_utc TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, authentication_tag BLOB NOT NULL) WITHOUT ROWID")
            columns = tuple((row[1], row[2].upper(), row[3], row[5]) for row in db.execute("PRAGMA table_info(pending_confirmation_contexts)"))
            expected = (("local_event_id","TEXT",1,1),("schema_version","TEXT",1,0),("expires_at_utc","TEXT",1,0),("nonce","BLOB",1,0),("ciphertext","BLOB",1,0),("authentication_tag","BLOB",1,0))
            if columns != expected:
                db.close()
                raise PendingConfirmationStoreError("pending_context_corrupt")
            return db
        except sqlite3.Error:
            raise PendingConfirmationStoreError("pending_context_unavailable") from None

    @staticmethod
    def _aad(event_id, version, expires):
        return json.dumps({"expires_at_utc": expires, "local_event_id": event_id, "schema_version": version}, sort_keys=True, separators=(",", ":")).encode("ascii")

    def put(self, local_event_id: str, feature_vector: FeatureVector, *, created_at: datetime):
        if not isinstance(local_event_id, str) or not local_event_id or len(local_event_id) > 128:
            raise PendingConfirmationStoreError("invalid_pending_context")
        try:
            validate_example_feature_vector(feature_vector)
            if not PrivacyScanner().scan_feature_vector(feature_vector).safe: raise ValueError
            plaintext = canonical_feature_vector_bytes(feature_vector)
        except Exception: raise PendingConfirmationStoreError("invalid_pending_context") from None
        expires = _utc(created_at + timedelta(days=PENDING_CONFIRMATION_RETENTION_DAYS))
        nonce = secrets.token_bytes(_NONCE_BYTES)
        combined = AESGCM(self._key()).encrypt(nonce, plaintext, self._aad(local_event_id, PENDING_CONFIRMATION_SCHEMA_VERSION, expires))
        try:
            with closing(self._connect()) as db, db:
                count = db.execute("SELECT COUNT(*) FROM pending_confirmation_contexts").fetchone()[0]
                if count >= _MAX_ROWS and db.execute("SELECT 1 FROM pending_confirmation_contexts WHERE local_event_id=?", (local_event_id,)).fetchone() is None:
                    raise PendingConfirmationStoreError("pending_context_capacity_exceeded")
                db.execute("INSERT OR REPLACE INTO pending_confirmation_contexts VALUES (?,?,?,?,?,?)", (local_event_id, PENDING_CONFIRMATION_SCHEMA_VERSION, expires, nonce, combined[:-_TAG_BYTES], combined[-_TAG_BYTES:]))
        except sqlite3.Error: raise PendingConfirmationStoreError("pending_context_unavailable") from None

    def get(self, local_event_id: str, *, now: datetime):
        if not self.database_path.exists(): return None
        try:
            with closing(self._connect()) as db:
                row = db.execute("SELECT schema_version, expires_at_utc, nonce, ciphertext, authentication_tag FROM pending_confirmation_contexts WHERE local_event_id=?", (local_event_id,)).fetchone()
            if row is None: return None
            version, expires, nonce, ciphertext, tag = row
            if version != PENDING_CONFIRMATION_SCHEMA_VERSION: raise ValueError
            if _utc(now) >= expires:
                self.delete(local_event_id)
                raise PendingConfirmationStoreError("pending_context_expired")
            plain = AESGCM(self._key()).decrypt(bytes(nonce), bytes(ciphertext)+bytes(tag), self._aad(local_event_id, version, expires))
            return _vector_from_bytes(plain)
        except PendingConfirmationStoreError: raise
        except (InvalidTag, TypeError, ValueError, sqlite3.Error): raise PendingConfirmationStoreError("pending_context_corrupt") from None

    def cleanup_expired(self, *, now: datetime):
        if not self.database_path.exists(): return 0
        try:
            with closing(self._connect()) as db, db:
                cursor = db.execute("DELETE FROM pending_confirmation_contexts WHERE expires_at_utc <= ?", (_utc(now),))
                return cursor.rowcount
        except sqlite3.Error: raise PendingConfirmationStoreError("pending_context_unavailable") from None

    def delete(self, local_event_id: str):
        if not self.database_path.exists(): return False
        try:
            with closing(self._connect()) as db, db:
                return db.execute("DELETE FROM pending_confirmation_contexts WHERE local_event_id=?", (local_event_id,)).rowcount > 0
        except sqlite3.Error: raise PendingConfirmationStoreError("pending_context_unavailable") from None

    def clear(self):
        failed = False
        for path in (Path(str(self.database_path)+"-wal"), Path(str(self.database_path)+"-shm"), Path(str(self.database_path)+"-journal"), self.database_path):
            try: secure_delete_owned_file(path)
            except KeyProtectionError: failed = True
        try: self._key_manager.delete()
        except KeyProtectionError: failed = True
        self._data_key = None
        if failed: raise PendingConfirmationStoreError("pending_context_delete_failed")


__all__ = ["PendingConfirmationStore", "PendingConfirmationStoreError", "PENDING_CONFIRMATION_RETENTION_DAYS"]
