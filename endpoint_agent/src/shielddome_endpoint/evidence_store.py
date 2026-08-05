from collections.abc import Callable
from contextlib import closing
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sqlite3

from .evidence_crypto import (
    EncryptedEvidence,
    EvidenceCipher,
    EvidenceCryptoError,
)
from .evidence_record import (
    EVIDENCE_RECORD_SCHEMA_VERSION,
    EndpointEvidenceRecord,
    EvidenceRecordValidationError,
)
from .key_protection import KeyProtectionError, UserDataKeyManager


EVIDENCE_DATABASE_FILENAME = "evidence.sqlite3"
EVIDENCE_DATABASE_SCHEMA_VERSION = 1
EVIDENCE_PAGE_MAX_ITEMS = 100
_LOCAL_EVENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ERASE_CHUNK_BYTES = 1_048_576
_EXPECTED_TABLE_COLUMNS = (
    ("local_event_id", "TEXT", 1, 1),
    ("detected_at_utc", "TEXT", 1, 0),
    ("expires_at_utc", "TEXT", 1, 0),
    ("schema_version", "TEXT", 1, 0),
    ("nonce", "BLOB", 1, 0),
    ("ciphertext", "BLOB", 1, 0),
    ("authentication_tag", "BLOB", 1, 0),
)


class EvidenceStoreError(RuntimeError):
    pass


def _utc_text(value: datetime) -> str:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise EvidenceStoreError("invalid_store_time")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _associated_data(
    local_event_id: str,
    detected_at_utc: str,
    expires_at_utc: str,
    schema_version: str,
) -> bytes:
    return json.dumps(
        {
            "detected_at_utc": detected_at_utc,
            "expires_at_utc": expires_at_utc,
            "local_event_id": local_event_id,
            "schema_version": schema_version,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _overwrite_and_unlink(path: Path) -> bool:
    try:
        if not path.exists():
            return False
        if not path.is_file():
            raise EvidenceStoreError("evidence_delete_failed")
        size = path.stat().st_size
        with path.open("r+b", buffering=0) as stream:
            remaining = size
            zeroes = b"\x00" * min(_ERASE_CHUNK_BYTES, max(size, 1))
            while remaining:
                chunk_size = min(remaining, len(zeroes))
                stream.write(zeroes[:chunk_size])
                remaining -= chunk_size
            stream.flush()
            os.fsync(stream.fileno())
        path.unlink()
        return True
    except EvidenceStoreError:
        raise
    except OSError:
        raise EvidenceStoreError("evidence_delete_failed") from None


class EvidenceStore:
    def __init__(
        self,
        data_directory: Path | None = None,
        *,
        key_manager: UserDataKeyManager | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._key_manager = key_manager or UserDataKeyManager(
            data_directory,
            database_filename=EVIDENCE_DATABASE_FILENAME,
        )
        self.data_directory = self._key_manager.data_directory
        self.database_path = self._key_manager.database_path
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._cipher_instance: EvidenceCipher | None = None

    def _cipher(self) -> EvidenceCipher:
        if self._cipher_instance is None:
            try:
                self._cipher_instance = EvidenceCipher(
                    self._key_manager.load_or_create()
                )
            except (KeyProtectionError, EvidenceCryptoError):
                raise EvidenceStoreError("evidence_key_unavailable") from None
        return self._cipher_instance

    def _connect(self) -> sqlite3.Connection:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(self.database_path, timeout=5.0)
            database_version = int(
                connection.execute("PRAGMA user_version").fetchone()[0]
            )
            if database_version not in (0, EVIDENCE_DATABASE_SCHEMA_VERSION):
                raise EvidenceStoreError("invalid_database_schema")
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA secure_delete=ON")
            connection.execute("PRAGMA temp_store=MEMORY")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS endpoint_evidence (
                    local_event_id TEXT PRIMARY KEY NOT NULL,
                    detected_at_utc TEXT NOT NULL,
                    expires_at_utc TEXT NOT NULL,
                    schema_version TEXT NOT NULL,
                    nonce BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    authentication_tag BLOB NOT NULL
                ) WITHOUT ROWID
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS endpoint_evidence_expiry "
                "ON endpoint_evidence(expires_at_utc)"
            )
            actual_columns = tuple(
                (row[1], row[2].upper(), row[3], row[5])
                for row in connection.execute(
                    "PRAGMA table_info(endpoint_evidence)"
                )
            )
            if actual_columns != _EXPECTED_TABLE_COLUMNS:
                raise EvidenceStoreError("invalid_database_schema")
            if database_version == 0:
                connection.execute(
                    f"PRAGMA user_version={EVIDENCE_DATABASE_SCHEMA_VERSION}"
                )
            return connection
        except EvidenceStoreError:
            if connection is not None:
                connection.close()
            raise
        except (OSError, sqlite3.Error):
            if connection is not None:
                connection.close()
            raise EvidenceStoreError("evidence_database_unavailable") from None

    def put(self, record: EndpointEvidenceRecord) -> None:
        if not isinstance(record, EndpointEvidenceRecord):
            raise EvidenceStoreError("invalid_evidence_record")
        detected_at_utc = _utc_text(record.detected_at)
        expires_at_utc = _utc_text(record.retention_until)
        associated_data = _associated_data(
            record.local_event_id,
            detected_at_utc,
            expires_at_utc,
            record.schema_version,
        )
        try:
            encrypted = self._cipher().encrypt(
                record,
                associated_data=associated_data,
            )
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute(
                        """
                        INSERT INTO endpoint_evidence (
                            local_event_id,
                            detected_at_utc,
                            expires_at_utc,
                            schema_version,
                            nonce,
                            ciphertext,
                            authentication_tag
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(local_event_id) DO UPDATE SET
                            detected_at_utc=excluded.detected_at_utc,
                            expires_at_utc=excluded.expires_at_utc,
                            schema_version=excluded.schema_version,
                            nonce=excluded.nonce,
                            ciphertext=excluded.ciphertext,
                            authentication_tag=excluded.authentication_tag
                        """,
                        (
                            record.local_event_id,
                            detected_at_utc,
                            expires_at_utc,
                            record.schema_version,
                            encrypted.nonce,
                            encrypted.ciphertext,
                            encrypted.authentication_tag,
                        ),
                    )
        except EvidenceStoreError:
            raise
        except (EvidenceCryptoError, OSError, sqlite3.Error):
            raise EvidenceStoreError("evidence_write_failed") from None

    def _decode_row(self, row: tuple[object, ...]) -> EndpointEvidenceRecord:
        (
            local_event_id,
            detected_at_utc,
            expires_at_utc,
            schema_version,
            nonce,
            ciphertext,
            authentication_tag,
        ) = row
        try:
            if not all(
                isinstance(value, str)
                for value in (
                    local_event_id,
                    detected_at_utc,
                    expires_at_utc,
                    schema_version,
                )
            ):
                raise ValueError
            record = self._cipher().decrypt(
                EncryptedEvidence(
                    nonce=bytes(nonce),
                    ciphertext=bytes(ciphertext),
                    authentication_tag=bytes(authentication_tag),
                ),
                associated_data=_associated_data(
                    local_event_id,
                    detected_at_utc,
                    expires_at_utc,
                    schema_version,
                ),
            )
            if (
                record.local_event_id != local_event_id
                or _utc_text(record.detected_at) != detected_at_utc
                or _utc_text(record.retention_until) != expires_at_utc
                or record.schema_version != schema_version
            ):
                raise ValueError
            return record
        except (
            EvidenceCryptoError,
            EvidenceRecordValidationError,
            EvidenceStoreError,
            TypeError,
            ValueError,
        ):
            raise EvidenceStoreError("evidence_decryption_failed") from None

    def get(self, local_event_id: str) -> EndpointEvidenceRecord | None:
        if (
            not isinstance(local_event_id, str)
            or _LOCAL_EVENT_ID.fullmatch(local_event_id) is None
        ):
            raise EvidenceStoreError("invalid_store_request")
        self._cipher()
        try:
            with closing(self._connect()) as connection:
                row = connection.execute(
                    """
                    SELECT local_event_id, detected_at_utc, expires_at_utc,
                           schema_version, nonce, ciphertext, authentication_tag
                    FROM endpoint_evidence
                    WHERE local_event_id = ?
                    """,
                    (local_event_id,),
                ).fetchone()
        except EvidenceStoreError:
            raise
        except (OSError, sqlite3.Error):
            raise EvidenceStoreError("evidence_read_failed") from None
        return None if row is None else self._decode_row(row)

    def list_page(
        self,
        *,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[EndpointEvidenceRecord, ...]:
        if (
            isinstance(offset, bool)
            or not isinstance(offset, int)
            or offset < 0
            or isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= EVIDENCE_PAGE_MAX_ITEMS
        ):
            raise EvidenceStoreError("invalid_store_request")
        if not self.database_path.exists():
            return ()
        self._cipher()
        try:
            with closing(self._connect()) as connection:
                rows = connection.execute(
                    """
                    SELECT local_event_id, detected_at_utc, expires_at_utc,
                           schema_version, nonce, ciphertext, authentication_tag
                    FROM endpoint_evidence
                    ORDER BY detected_at_utc DESC, local_event_id DESC
                    LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
                ).fetchall()
        except EvidenceStoreError:
            raise
        except (OSError, sqlite3.Error):
            raise EvidenceStoreError("evidence_read_failed") from None
        return tuple(self._decode_row(row) for row in rows)

    def cleanup_expired(self, *, now: datetime | None = None) -> int:
        current_time = self._clock() if now is None else now
        cutoff = _utc_text(current_time)
        if not self.database_path.exists():
            return 0
        try:
            with closing(self._connect()) as connection:
                with connection:
                    cursor = connection.execute(
                        "DELETE FROM endpoint_evidence WHERE expires_at_utc <= ?",
                        (cutoff,),
                    )
                    deleted = cursor.rowcount
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            return max(deleted, 0)
        except EvidenceStoreError:
            raise
        except (OSError, sqlite3.Error):
            raise EvidenceStoreError("evidence_cleanup_failed") from None

    def delete_all(self) -> int:
        database_sidecars = (
            Path(f"{self.database_path}-wal"),
            Path(f"{self.database_path}-shm"),
            Path(f"{self.database_path}-journal"),
            self.database_path.with_name(self.database_path.name + ".tmp"),
        )
        deleted_records = 0
        deletion_failed = False

        for path in database_sidecars:
            try:
                _overwrite_and_unlink(path)
            except EvidenceStoreError:
                deletion_failed = True

        if self.database_path.exists():
            try:
                connection = sqlite3.connect(self.database_path, timeout=5.0)
                try:
                    connection.execute("PRAGMA journal_mode=DELETE")
                    connection.execute("PRAGMA secure_delete=ON")
                    row = connection.execute(
                        "SELECT COUNT(*) FROM endpoint_evidence"
                    ).fetchone()
                    deleted_records = int(row[0]) if row is not None else 0
                    with connection:
                        connection.execute("DELETE FROM endpoint_evidence")
                    connection.execute("VACUUM")
                finally:
                    connection.close()
            except (OSError, sqlite3.Error, TypeError, ValueError):
                deletion_failed = True
            try:
                _overwrite_and_unlink(self.database_path)
            except EvidenceStoreError:
                deletion_failed = True

        try:
            self._key_manager.delete()
        except KeyProtectionError:
            deletion_failed = True
        self._cipher_instance = None
        if deletion_failed:
            raise EvidenceStoreError("evidence_delete_failed")
        return deleted_records


__all__ = [
    "EVIDENCE_DATABASE_FILENAME",
    "EVIDENCE_DATABASE_SCHEMA_VERSION",
    "EVIDENCE_PAGE_MAX_ITEMS",
    "EvidenceStore",
    "EvidenceStoreError",
]
