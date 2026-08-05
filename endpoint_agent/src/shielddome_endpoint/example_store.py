from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .confirmed_examples import (
    CONFIRMED_EXAMPLE_SCHEMA_VERSION,
    ConfirmedExample,
    ConfirmedExampleValidationError,
    ExampleLabel,
    ExampleSource,
    UserConfirmationAction,
    keyed_feature_fingerprint,
    label_for_confirmation_action,
)
from .domain import FeatureVector
from .key_protection import (
    KeyProtectionError,
    UserDataKeyManager,
    default_user_data_directory,
)


EXAMPLE_DATABASE_FILENAME = "confirmed_examples.sqlite3"
EXAMPLE_LIBRARY_MAX_FINGERPRINTS = 256
EXAMPLE_PAGE_MAX_ITEMS = 50
EXAMPLE_PAGE_MAX_OFFSET = 256
EXAMPLE_CALIBRATION_SCAN_MAX_ROWS = 512
EXAMPLE_DATABASE_SCHEMA_VERSION = 1
_NONCE_BYTES = 12
_TAG_BYTES = 16
_EXPECTED_COLUMNS = (
    ("keyed_fingerprint", "TEXT", 1, 1),
    ("label", "TEXT", 1, 2),
    ("confirmed_at_utc", "TEXT", 1, 0),
    ("schema_version", "TEXT", 1, 0),
    ("nonce", "BLOB", 1, 0),
    ("ciphertext", "BLOB", 1, 0),
    ("authentication_tag", "BLOB", 1, 0),
)
_LOWER_HEX_256 = re.compile(r"^[0-9a-f]{64}$")
_ERASE_CHUNK_BYTES = 1_048_576


class ExampleConfirmationStatus(StrEnum):
    ADDED = "added"
    DUPLICATE = "duplicate"
    CONFLICT = "conflict"


class ExampleStoreError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ExampleLibraryAggregate:
    total_rows: int
    unique_examples: int
    benign_labels: int
    phishing_labels: int
    conflicts: int

    def __post_init__(self) -> None:
        values = (
            self.total_rows,
            self.unique_examples,
            self.benign_labels,
            self.phishing_labels,
            self.conflicts,
        )
        if (
            any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                for value in values
            )
            or self.total_rows != self.benign_labels + self.phishing_labels
            or self.unique_examples > self.total_rows
            or self.conflicts > self.unique_examples
        ):
            raise ValueError("invalid_example_library_aggregate")


def _overwrite_and_unlink(path: Path) -> bool:
    try:
        if not path.exists():
            return False
        if not path.is_file():
            raise ExampleStoreError("example_delete_failed")
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
    except ExampleStoreError:
        raise
    except OSError:
        raise ExampleStoreError("example_delete_failed") from None


class ExampleStore:
    def __init__(
        self,
        data_directory: Path | None = None,
        *,
        key_manager: UserDataKeyManager | None = None,
    ) -> None:
        if key_manager is not None:
            if data_directory is not None:
                raise ExampleStoreError("invalid_store_configuration")
            self._key_manager = key_manager
            self.example_directory = key_manager.data_directory
        else:
            root = (
                default_user_data_directory()
                if data_directory is None
                else Path(data_directory)
            )
            self.example_directory = root / "examples"
            self._key_manager = UserDataKeyManager(
                self.example_directory,
                database_filename=EXAMPLE_DATABASE_FILENAME,
            )
        self.database_path = self._key_manager.database_path
        self.key_path = self._key_manager.key_path
        self._data_key: bytes | None = None

    def _key(self) -> bytes:
        if self._data_key is None:
            try:
                self._data_key = self._key_manager.load_or_create()
            except KeyProtectionError:
                raise ExampleStoreError("example_key_unavailable") from None
        return self._data_key

    def _connect(self) -> sqlite3.Connection:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(self.database_path, timeout=5.0)
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in (0, EXAMPLE_DATABASE_SCHEMA_VERSION):
                raise ExampleStoreError("invalid_example_database_schema")
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA secure_delete=ON")
            connection.execute("PRAGMA temp_store=MEMORY")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS confirmed_examples (
                    keyed_fingerprint TEXT NOT NULL,
                    label TEXT NOT NULL,
                    confirmed_at_utc TEXT NOT NULL,
                    schema_version TEXT NOT NULL,
                    nonce BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    authentication_tag BLOB NOT NULL,
                    PRIMARY KEY (keyed_fingerprint, label)
                ) WITHOUT ROWID
                """
            )
            actual_columns = tuple(
                (row[1], row[2].upper(), row[3], row[5])
                for row in connection.execute(
                    "PRAGMA table_info(confirmed_examples)"
                )
            )
            if actual_columns != _EXPECTED_COLUMNS:
                raise ExampleStoreError("invalid_example_database_schema")
            if version == 0:
                connection.execute(
                    f"PRAGMA user_version={EXAMPLE_DATABASE_SCHEMA_VERSION}"
                )
            return connection
        except ExampleStoreError:
            if connection is not None:
                connection.close()
            raise
        except (OSError, sqlite3.Error):
            if connection is not None:
                connection.close()
            raise ExampleStoreError("example_database_unavailable") from None

    @staticmethod
    def _utc_text(value: datetime) -> str:
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() is None
        ):
            raise ExampleStoreError("invalid_confirmation")
        return value.astimezone(timezone.utc).isoformat(timespec="microseconds")

    @staticmethod
    def _associated_data(
        fingerprint: str,
        label: str,
        confirmed_at_utc: str,
        schema_version: str,
    ) -> bytes:
        return json.dumps(
            {
                "confirmed_at_utc": confirmed_at_utc,
                "keyed_fingerprint": fingerprint,
                "label": label,
                "schema_version": schema_version,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")

    def confirm(
        self,
        feature_vector: FeatureVector,
        *,
        action: UserConfirmationAction,
        source: ExampleSource,
        confirmed_at: datetime,
    ) -> ExampleConfirmationStatus:
        try:
            label = label_for_confirmation_action(action)
            if not isinstance(source, ExampleSource):
                raise ConfirmedExampleValidationError("invalid_confirmation")
            data_key = self._key()
            fingerprint = keyed_feature_fingerprint(feature_vector, data_key)
            record = ConfirmedExample.create(
                feature_vector,
                label=label,
                source=source,
                confirmed_at=confirmed_at,
                keyed_fingerprint=fingerprint,
            )
        except ConfirmedExampleValidationError:
            raise ExampleStoreError("invalid_confirmation") from None
        confirmed_at_utc = self._utc_text(record.confirmed_at)
        associated_data = self._associated_data(
            fingerprint,
            label.value,
            confirmed_at_utc,
            record.schema_version,
        )
        nonce = secrets.token_bytes(_NONCE_BYTES)
        combined = AESGCM(data_key).encrypt(
            nonce,
            record.to_json_bytes(),
            associated_data,
        )
        try:
            with closing(self._connect()) as connection:
                existing_rows = connection.execute(
                    """
                    SELECT keyed_fingerprint, label, confirmed_at_utc,
                           schema_version, nonce, ciphertext,
                           authentication_tag
                    FROM confirmed_examples
                    WHERE keyed_fingerprint = ?
                    ORDER BY label
                    """,
                    (fingerprint,),
                ).fetchall()
                existing = tuple(
                    self._decode_row(row) for row in existing_rows
                )
                if any(item.label is label for item in existing):
                    return ExampleConfirmationStatus.DUPLICATE
                distinct_count = int(
                    connection.execute(
                        "SELECT COUNT(DISTINCT keyed_fingerprint) "
                        "FROM confirmed_examples"
                    ).fetchone()[0]
                )
                if (
                    not existing
                    and distinct_count >= EXAMPLE_LIBRARY_MAX_FINGERPRINTS
                ):
                    raise ExampleStoreError("example_capacity_exceeded")
                with connection:
                    connection.execute(
                        """
                        INSERT INTO confirmed_examples (
                            keyed_fingerprint, label, confirmed_at_utc,
                            schema_version, nonce, ciphertext,
                            authentication_tag
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            fingerprint,
                            label.value,
                            confirmed_at_utc,
                            record.schema_version,
                            nonce,
                            combined[:-_TAG_BYTES],
                            combined[-_TAG_BYTES:],
                        ),
                    )
        except ExampleStoreError:
            raise
        except (OSError, sqlite3.Error):
            raise ExampleStoreError("example_write_failed") from None
        return (
            ExampleConfirmationStatus.CONFLICT
            if existing
            else ExampleConfirmationStatus.ADDED
        )

    def _decode_row(self, row: tuple[object, ...]) -> ConfirmedExample:
        (
            fingerprint,
            label,
            confirmed_at_utc,
            schema_version,
            nonce,
            ciphertext,
            authentication_tag,
        ) = row
        try:
            if not all(
                isinstance(value, str)
                for value in (
                    fingerprint,
                    label,
                    confirmed_at_utc,
                    schema_version,
                )
            ):
                raise ValueError
            associated_data = self._associated_data(
                fingerprint,
                label,
                confirmed_at_utc,
                schema_version,
            )
            plaintext = AESGCM(self._key()).decrypt(
                bytes(nonce),
                bytes(ciphertext) + bytes(authentication_tag),
                associated_data,
            )
            record = ConfirmedExample.from_json_bytes(plaintext)
            expected_fingerprint = keyed_feature_fingerprint(
                record.feature_vector,
                self._key(),
            )
            if (
                not hmac.compare_digest(record.keyed_fingerprint, fingerprint)
                or not hmac.compare_digest(expected_fingerprint, fingerprint)
                or record.label.value != label
                or self._utc_text(record.confirmed_at) != confirmed_at_utc
                or record.schema_version != schema_version
            ):
                raise ValueError
            return record
        except (
            ConfirmedExampleValidationError,
            ExampleStoreError,
            InvalidTag,
            TypeError,
            ValueError,
        ):
            raise ExampleStoreError("example_decryption_failed") from None

    def list_page(
        self,
        *,
        offset: int = 0,
        limit: int = EXAMPLE_PAGE_MAX_ITEMS,
        label: ExampleLabel | None = None,
    ) -> tuple[ConfirmedExample, ...]:
        if (
            isinstance(offset, bool)
            or not isinstance(offset, int)
            or not 0 <= offset <= EXAMPLE_PAGE_MAX_OFFSET
            or isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= EXAMPLE_PAGE_MAX_ITEMS
            or not (label is None or isinstance(label, ExampleLabel))
        ):
            raise ExampleStoreError("invalid_store_request")
        if not self.database_path.exists():
            return ()
        self._key()
        query = (
            "SELECT keyed_fingerprint, label, confirmed_at_utc, "
            "schema_version, nonce, ciphertext, authentication_tag "
            "FROM confirmed_examples"
        )
        parameters: tuple[object, ...]
        if label is None:
            parameters = (limit, offset)
        else:
            query += " WHERE label = ?"
            parameters = (label.value, limit, offset)
        query += (
            " ORDER BY confirmed_at_utc DESC, keyed_fingerprint DESC, "
            "label DESC LIMIT ? OFFSET ?"
        )
        try:
            with closing(self._connect()) as connection:
                rows = connection.execute(query, parameters).fetchall()
        except ExampleStoreError:
            raise
        except (OSError, sqlite3.Error):
            raise ExampleStoreError("example_read_failed") from None
        return tuple(self._decode_row(row) for row in rows)

    def find_exact(
        self,
        feature_vector: FeatureVector,
    ) -> tuple[ConfirmedExample, ...]:
        if not self.database_path.exists():
            return ()
        try:
            fingerprint = keyed_feature_fingerprint(
                feature_vector,
                self._key(),
            )
        except ConfirmedExampleValidationError:
            raise ExampleStoreError("invalid_store_request") from None
        try:
            with closing(self._connect()) as connection:
                rows = connection.execute(
                    """
                    SELECT keyed_fingerprint, label, confirmed_at_utc,
                           schema_version, nonce, ciphertext,
                           authentication_tag
                    FROM confirmed_examples
                    WHERE keyed_fingerprint = ?
                    ORDER BY label
                    """,
                    (fingerprint,),
                ).fetchall()
        except ExampleStoreError:
            raise
        except (OSError, sqlite3.Error):
            raise ExampleStoreError("example_read_failed") from None
        return tuple(self._decode_row(row) for row in rows)

    def list_for_calibration(self) -> tuple[ConfirmedExample, ...]:
        if not self.database_path.exists():
            return ()
        self._key()
        try:
            with closing(self._connect()) as connection:
                rows = connection.execute(
                    """
                    SELECT keyed_fingerprint, label, confirmed_at_utc,
                           schema_version, nonce, ciphertext,
                           authentication_tag
                    FROM confirmed_examples
                    ORDER BY confirmed_at_utc DESC, keyed_fingerprint DESC,
                             label DESC
                    LIMIT ?
                    """,
                    (EXAMPLE_CALIBRATION_SCAN_MAX_ROWS,),
                ).fetchall()
        except ExampleStoreError:
            raise
        except (OSError, sqlite3.Error):
            raise ExampleStoreError("example_read_failed") from None
        return tuple(self._decode_row(row) for row in rows)

    def diagnostic_aggregate(self) -> ExampleLibraryAggregate:
        if not self.database_path.exists():
            return ExampleLibraryAggregate(0, 0, 0, 0, 0)
        self._key()
        try:
            with closing(self._connect()) as connection:
                rows = connection.execute(
                    """
                    SELECT keyed_fingerprint, label, confirmed_at_utc,
                           schema_version, nonce, ciphertext,
                           authentication_tag
                    FROM confirmed_examples
                    ORDER BY keyed_fingerprint, label
                    LIMIT ?
                    """,
                    (EXAMPLE_CALIBRATION_SCAN_MAX_ROWS + 1,),
                ).fetchall()
        except ExampleStoreError:
            raise
        except (OSError, sqlite3.Error):
            raise ExampleStoreError("example_read_failed") from None
        if len(rows) > EXAMPLE_CALIBRATION_SCAN_MAX_ROWS:
            raise ExampleStoreError("example_diagnostic_limit_exceeded")
        examples = tuple(self._decode_row(row) for row in rows)
        labels_by_fingerprint: dict[str, set[ExampleLabel]] = {}
        for example in examples:
            labels_by_fingerprint.setdefault(
                example.keyed_fingerprint,
                set(),
            ).add(example.label)
        return ExampleLibraryAggregate(
            total_rows=len(examples),
            unique_examples=len(labels_by_fingerprint),
            benign_labels=sum(
                example.label is ExampleLabel.BENIGN for example in examples
            ),
            phishing_labels=sum(
                example.label is ExampleLabel.PHISHING for example in examples
            ),
            conflicts=sum(
                len(labels) > 1 for labels in labels_by_fingerprint.values()
            ),
        )

    def delete(self, keyed_fingerprint: str, label: ExampleLabel) -> bool:
        if (
            not isinstance(keyed_fingerprint, str)
            or _LOWER_HEX_256.fullmatch(keyed_fingerprint) is None
            or not isinstance(label, ExampleLabel)
        ):
            raise ExampleStoreError("invalid_store_request")
        if not self.database_path.exists():
            return False
        try:
            with closing(self._connect()) as connection:
                with connection:
                    cursor = connection.execute(
                        "DELETE FROM confirmed_examples "
                        "WHERE keyed_fingerprint = ? AND label = ?",
                        (keyed_fingerprint, label.value),
                    )
                    deleted = cursor.rowcount > 0
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            return deleted
        except ExampleStoreError:
            raise
        except (OSError, sqlite3.Error):
            raise ExampleStoreError("example_delete_failed") from None

    def clear(self) -> int:
        sidecars = (
            Path(f"{self.database_path}-wal"),
            Path(f"{self.database_path}-shm"),
            Path(f"{self.database_path}-journal"),
            self.database_path.with_name(self.database_path.name + ".tmp"),
        )
        deleted_rows = 0
        deletion_failed = False
        if self.database_path.exists():
            try:
                connection = sqlite3.connect(self.database_path, timeout=5.0)
                try:
                    connection.execute("PRAGMA journal_mode=DELETE")
                    connection.execute("PRAGMA secure_delete=ON")
                    row = connection.execute(
                        "SELECT COUNT(*) FROM confirmed_examples"
                    ).fetchone()
                    deleted_rows = int(row[0]) if row is not None else 0
                    with connection:
                        connection.execute("DELETE FROM confirmed_examples")
                    connection.execute("VACUUM")
                finally:
                    connection.close()
            except (OSError, sqlite3.Error, TypeError, ValueError):
                deletion_failed = True
        for path in (*sidecars, self.database_path):
            try:
                _overwrite_and_unlink(path)
            except ExampleStoreError:
                deletion_failed = True
        try:
            self._key_manager.delete()
        except KeyProtectionError:
            deletion_failed = True
        self._data_key = None
        if deletion_failed:
            raise ExampleStoreError("example_delete_failed")
        return deleted_rows


__all__ = [
    "EXAMPLE_CALIBRATION_SCAN_MAX_ROWS",
    "EXAMPLE_DATABASE_FILENAME",
    "EXAMPLE_DATABASE_SCHEMA_VERSION",
    "EXAMPLE_LIBRARY_MAX_FINGERPRINTS",
    "EXAMPLE_PAGE_MAX_ITEMS",
    "EXAMPLE_PAGE_MAX_OFFSET",
    "ExampleConfirmationStatus",
    "ExampleLibraryAggregate",
    "ExampleStore",
    "ExampleStoreError",
]
