from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import platform
import secrets
import sys
from tempfile import TemporaryDirectory
from zipfile import BadZipFile, ZIP_DEFLATED, ZipFile, ZipInfo

from . import __version__
from .diagnostics import (
    DIAGNOSTIC_SCHEMA_VERSION,
    DiagnosticCollectionError,
    DiagnosticsCollector,
    SanitizedDiagnostics,
)
from .key_protection import KeyProtectionError, default_user_data_directory


DIAGNOSTIC_ARCHIVE_NAMES = (
    "diagnostics.json",
    "compatibility.json",
    "manifest.json",
)
DIAGNOSTIC_MANIFEST_SCHEMA_VERSION = "1.0"
DIAGNOSTIC_FILE_MAX_BYTES = 262_144
DIAGNOSTIC_ARCHIVE_MAX_BYTES = 1_048_576


class DiagnosticExportError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class DiagnosticExportResult:
    output_path: Path
    archive_size_bytes: int
    archive_sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.output_path, Path)
            or isinstance(self.archive_size_bytes, bool)
            or not isinstance(self.archive_size_bytes, int)
            or self.archive_size_bytes <= 0
            or not isinstance(self.archive_sha256, str)
            or len(self.archive_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.archive_sha256)
        ):
            raise ValueError("invalid_diagnostic_export_result")


def _json_bytes(payload: dict[str, object]) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _compatibility_payload() -> dict[str, object]:
    implementation = platform.python_implementation()
    if implementation not in {"CPython", "PyPy"}:
        implementation = "other"
    if sys.platform == "win32" and hasattr(sys, "getwindowsversion"):
        windows_major = str(sys.getwindowsversion().major)
        operating_system = "Windows"
    else:
        windows_major = "unsupported"
        operating_system = "other"
    return {
        "agent_package_version": __version__,
        "operating_system": operating_system,
        "packaging_kind": "frozen" if getattr(sys, "frozen", False) else "source",
        "python_implementation": implementation,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
        "schema_version": DIAGNOSTIC_SCHEMA_VERSION,
        "windows_major_version": windows_major,
    }


def _safe_archive_name(name: str) -> bool:
    path = PurePosixPath(name)
    return (
        isinstance(name, str)
        and name in DIAGNOSTIC_ARCHIVE_NAMES
        and not path.is_absolute()
        and len(path.parts) == 1
        and ".." not in path.parts
        and "\\" not in name
        and ":" not in name
    )


def _zip_info(name: str) -> ZipInfo:
    if not _safe_archive_name(name):
        raise DiagnosticExportError("invalid_diagnostic_archive_name")
    info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o600 << 16
    return info


def _validate_payload_size(payload: bytes) -> None:
    if not payload or len(payload) > DIAGNOSTIC_FILE_MAX_BYTES:
        raise DiagnosticExportError("diagnostic_file_size_exceeded")


def _validate_archive(archive_path: Path) -> None:
    try:
        if archive_path.stat().st_size > DIAGNOSTIC_ARCHIVE_MAX_BYTES:
            raise DiagnosticExportError("diagnostic_archive_size_exceeded")
        with ZipFile(archive_path, "r") as archive:
            names = tuple(archive.namelist())
            if names != DIAGNOSTIC_ARCHIVE_NAMES or any(
                not _safe_archive_name(name) for name in names
            ):
                raise DiagnosticExportError("invalid_diagnostic_archive")
            if archive.testzip() is not None:
                raise DiagnosticExportError("invalid_diagnostic_archive")
            payloads = {name: archive.read(name) for name in names}
        for payload in payloads.values():
            _validate_payload_size(payload)
        manifest = json.loads(payloads["manifest.json"].decode("utf-8"))
        if (
            not isinstance(manifest, dict)
            or set(manifest) != {"archive_entries", "files", "schema_version"}
            or manifest["schema_version"] != DIAGNOSTIC_MANIFEST_SCHEMA_VERSION
            or manifest["archive_entries"] != list(DIAGNOSTIC_ARCHIVE_NAMES)
            or not isinstance(manifest["files"], list)
            or len(manifest["files"]) != 2
        ):
            raise DiagnosticExportError("invalid_diagnostic_manifest")
        expected_names = DIAGNOSTIC_ARCHIVE_NAMES[:2]
        for expected_name, item in zip(expected_names, manifest["files"]):
            if not isinstance(item, dict) or set(item) != {
                "name",
                "sha256",
                "size_bytes",
            }:
                raise DiagnosticExportError("invalid_diagnostic_manifest")
            payload = payloads[expected_name]
            if (
                item["name"] != expected_name
                or item["size_bytes"] != len(payload)
                or item["sha256"] != hashlib.sha256(payload).hexdigest()
            ):
                raise DiagnosticExportError("invalid_diagnostic_manifest")
    except DiagnosticExportError:
        raise
    except (BadZipFile, KeyError, OSError, TypeError, UnicodeError, ValueError):
        raise DiagnosticExportError("invalid_diagnostic_archive") from None


def _write_new_output(target: Path, payload: bytes) -> None:
    created = False
    try:
        with target.open("xb") as stream:
            created = True
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        raise DiagnosticExportError("diagnostic_output_exists") from None
    except OSError:
        if created:
            try:
                target.unlink(missing_ok=True)
            except OSError:
                pass
        raise DiagnosticExportError("diagnostic_output_write_failed") from None


def _replace_output(target: Path, payload: bytes) -> None:
    temporary = target.with_name(
        f".{target.name}.{secrets.token_hex(8)}.tmp"
    )
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    except OSError:
        raise DiagnosticExportError("diagnostic_output_write_failed") from None
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


class DiagnosticExporter:
    def __init__(
        self,
        *,
        collector: DiagnosticsCollector | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._collector = collector or DiagnosticsCollector()
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def export(
        self,
        output_path: str | Path,
        *,
        confirmed: bool,
        overwrite: bool = False,
    ) -> DiagnosticExportResult:
        if confirmed is not True:
            raise DiagnosticExportError("diagnostic_confirmation_required")
        if not isinstance(overwrite, bool):
            raise DiagnosticExportError("invalid_diagnostic_export_request")
        try:
            target = Path(output_path)
        except TypeError:
            raise DiagnosticExportError("invalid_diagnostic_output_path") from None
        if not target.name or not target.name.endswith(".diag.zip"):
            raise DiagnosticExportError("invalid_diagnostic_output_path")
        try:
            target = target.resolve(strict=False)
            if target.exists() and not overwrite:
                raise DiagnosticExportError("diagnostic_output_exists")
            if (
                not target.parent.is_dir()
                or (target.exists() and not target.is_file())
            ):
                raise DiagnosticExportError("invalid_diagnostic_output_path")
            generated_at = self._clock()
            if (
                not isinstance(generated_at, datetime)
                or generated_at.tzinfo is None
                or generated_at.utcoffset() is None
            ):
                raise DiagnosticExportError("invalid_diagnostic_time")
            snapshot = self._collector.collect()
            if not isinstance(snapshot, SanitizedDiagnostics):
                raise DiagnosticExportError("diagnostic_collection_failed")
            diagnostics_payload = snapshot.to_json_bytes()
            compatibility_payload = _json_bytes(_compatibility_payload())
            for payload in (diagnostics_payload, compatibility_payload):
                _validate_payload_size(payload)
            payloads = (
                ("diagnostics.json", diagnostics_payload),
                ("compatibility.json", compatibility_payload),
            )
            manifest_payload = _json_bytes(
                {
                    "archive_entries": list(DIAGNOSTIC_ARCHIVE_NAMES),
                    "files": [
                        {
                            "name": name,
                            "sha256": hashlib.sha256(payload).hexdigest(),
                            "size_bytes": len(payload),
                        }
                        for name, payload in payloads
                    ],
                    "schema_version": DIAGNOSTIC_MANIFEST_SCHEMA_VERSION,
                }
            )
            _validate_payload_size(manifest_payload)
            temporary_parent = (
                default_user_data_directory() / "diagnostic-temp"
            )
            temporary_parent.mkdir(parents=True, exist_ok=True)
            with TemporaryDirectory(
                prefix="export-",
                dir=temporary_parent,
            ) as temporary_directory:
                archive_path = Path(temporary_directory) / "package.diag.zip"
                with ZipFile(
                    archive_path,
                    "x",
                    compression=ZIP_DEFLATED,
                    compresslevel=9,
                ) as archive:
                    archive.writestr(
                        _zip_info("diagnostics.json"),
                        diagnostics_payload,
                    )
                    archive.writestr(
                        _zip_info("compatibility.json"),
                        compatibility_payload,
                    )
                    archive.writestr(
                        _zip_info("manifest.json"),
                        manifest_payload,
                    )
                _validate_archive(archive_path)
                archive_payload = archive_path.read_bytes()
            if len(archive_payload) > DIAGNOSTIC_ARCHIVE_MAX_BYTES:
                raise DiagnosticExportError("diagnostic_archive_size_exceeded")
            if overwrite and target.exists():
                _replace_output(target, archive_payload)
            else:
                _write_new_output(target, archive_payload)
            return DiagnosticExportResult(
                output_path=target,
                archive_size_bytes=len(archive_payload),
                archive_sha256=hashlib.sha256(archive_payload).hexdigest(),
            )
        except DiagnosticExportError:
            raise
        except DiagnosticCollectionError as error:
            code = (
                error.args[0]
                if error.args
                and error.args[0]
                in {
                    "diagnostic_error_code_limit_exceeded",
                    "diagnostic_record_limit_exceeded",
                    "diagnostic_source_limit_exceeded",
                    "invalid_diagnostic_time",
                }
                else "diagnostic_collection_failed"
            )
            raise DiagnosticExportError(code) from None
        except KeyProtectionError:
            raise DiagnosticExportError("diagnostic_temp_unavailable") from None
        except (OSError, TypeError, ValueError):
            raise DiagnosticExportError("diagnostic_export_failed") from None


__all__ = [
    "DIAGNOSTIC_ARCHIVE_MAX_BYTES",
    "DIAGNOSTIC_ARCHIVE_NAMES",
    "DIAGNOSTIC_FILE_MAX_BYTES",
    "DIAGNOSTIC_MANIFEST_SCHEMA_VERSION",
    "DiagnosticExportError",
    "DiagnosticExportResult",
    "DiagnosticExporter",
]
