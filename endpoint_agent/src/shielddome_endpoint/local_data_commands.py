from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
import re

from .confirmed_examples import (
    ExampleLabel,
    ExampleSource,
    UserConfirmationAction,
)
from .console_models import ConsoleOperationResult, ConsoleStatusCode
from .domain import FeatureVector
from .diagnostic_export import DiagnosticExportError
from .example_store import ExampleConfirmationStatus, ExampleStoreError


_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")


class LocalDataCommands:
    def __init__(
        self,
        *,
        evidence_store: object,
        example_store: object,
        diagnostic_exporter: object,
        clock: Callable[[], datetime],
        data_root: Path,
        pending_confirmation_store: object | None = None,
    ) -> None:
        self._evidence_store = evidence_store
        self._example_store = example_store
        self._diagnostic_exporter = diagnostic_exporter
        self._clock = clock
        self._data_root = Path(data_root).resolve(strict=False)
        self._pending_confirmation_store = pending_confirmation_store

    def _confirm(
        self,
        feature_vector: FeatureVector,
        *,
        action: UserConfirmationAction,
        confirmed: bool,
    ) -> ConsoleOperationResult:
        if confirmed is not True:
            return ConsoleOperationResult(
                ConsoleStatusCode.CONFIRMATION_REQUIRED,
                None,
            )
        try:
            confirmed_at = self._clock()
            if (
                not isinstance(confirmed_at, datetime)
                or confirmed_at.tzinfo is None
                or confirmed_at.utcoffset() is None
            ):
                return ConsoleOperationResult(
                    ConsoleStatusCode.INVALID_REQUEST,
                    None,
                )
            status = self._example_store.confirm(
                feature_vector,
                action=action,
                source=ExampleSource.BROWSER_NATIVE,
                confirmed_at=confirmed_at.astimezone(timezone.utc),
            )
            code = {
                ExampleConfirmationStatus.ADDED: ConsoleStatusCode.EXAMPLE_ADDED,
                ExampleConfirmationStatus.DUPLICATE: ConsoleStatusCode.EXAMPLE_DUPLICATE,
                ExampleConfirmationStatus.CONFLICT: ConsoleStatusCode.EXAMPLE_CONFLICT,
            }.get(status)
            if code is None:
                return ConsoleOperationResult(ConsoleStatusCode.COMMAND_FAILED, None)
            return ConsoleOperationResult(code, None, affected_items=1)
        except ExampleStoreError as error:
            code = {
                "invalid_confirmation": ConsoleStatusCode.INVALID_REQUEST,
                "example_capacity_exceeded": ConsoleStatusCode.EXAMPLE_CAPACITY_EXCEEDED,
            }.get(error.args[0] if error.args else "")
            return ConsoleOperationResult(
                code or ConsoleStatusCode.EXAMPLE_STORE_UNAVAILABLE,
                None,
            )
        except Exception:
            return ConsoleOperationResult(ConsoleStatusCode.COMMAND_FAILED, None)

    def confirm_benign(
        self,
        feature_vector: FeatureVector,
        *,
        confirmed: bool,
    ) -> ConsoleOperationResult:
        return self._confirm(
            feature_vector,
            action=UserConfirmationAction.CONFIRM_BENIGN,
            confirmed=confirmed,
        )

    def confirm_phishing(
        self,
        feature_vector: FeatureVector,
        *,
        confirmed: bool,
    ) -> ConsoleOperationResult:
        return self._confirm(
            feature_vector,
            action=UserConfirmationAction.CONFIRM_PHISHING,
            confirmed=confirmed,
        )

    def delete_example(
        self,
        keyed_fingerprint: str,
        label: ExampleLabel,
    ) -> ConsoleOperationResult:
        if (
            not isinstance(keyed_fingerprint, str)
            or _FINGERPRINT.fullmatch(keyed_fingerprint) is None
            or not isinstance(label, ExampleLabel)
        ):
            return ConsoleOperationResult(ConsoleStatusCode.INVALID_REQUEST, None)
        try:
            deleted = self._example_store.delete(keyed_fingerprint, label)
            if not isinstance(deleted, bool):
                return ConsoleOperationResult(ConsoleStatusCode.COMMAND_FAILED, None)
            return ConsoleOperationResult(
                ConsoleStatusCode.SUCCESS if deleted else ConsoleStatusCode.NOT_FOUND,
                None,
                affected_items=1 if deleted else 0,
            )
        except ExampleStoreError:
            return ConsoleOperationResult(
                ConsoleStatusCode.EXAMPLE_STORE_UNAVAILABLE,
                None,
            )
        except Exception:
            return ConsoleOperationResult(ConsoleStatusCode.COMMAND_FAILED, None)

    def clear_examples(self, *, confirmed: bool) -> ConsoleOperationResult:
        if confirmed is not True:
            return ConsoleOperationResult(
                ConsoleStatusCode.CONFIRMATION_REQUIRED,
                None,
            )
        try:
            deleted = self._example_store.clear()
            if isinstance(deleted, bool) or not isinstance(deleted, int) or deleted < 0:
                return ConsoleOperationResult(ConsoleStatusCode.COMMAND_FAILED, None)
            return ConsoleOperationResult(
                ConsoleStatusCode.SUCCESS,
                None,
                affected_items=deleted,
            )
        except ExampleStoreError:
            return ConsoleOperationResult(
                ConsoleStatusCode.EXAMPLE_STORE_UNAVAILABLE,
                None,
            )
        except Exception:
            return ConsoleOperationResult(ConsoleStatusCode.COMMAND_FAILED, None)

    def export_diagnostics(
        self,
        output_path: str | Path,
        *,
        confirmed: bool,
        overwrite: bool = False,
    ) -> ConsoleOperationResult:
        if confirmed is not True:
            return ConsoleOperationResult(
                ConsoleStatusCode.CONFIRMATION_REQUIRED,
                None,
            )
        if not isinstance(overwrite, bool):
            return ConsoleOperationResult(ConsoleStatusCode.INVALID_REQUEST, None)
        try:
            self._diagnostic_exporter.export(
                output_path,
                confirmed=True,
                overwrite=overwrite,
            )
            return ConsoleOperationResult(
                ConsoleStatusCode.DIAGNOSTIC_EXPORTED,
                None,
                affected_items=1,
            )
        except DiagnosticExportError as error:
            error_code = error.args[0] if error.args else ""
            if error_code == "diagnostic_output_exists":
                code = ConsoleStatusCode.DIAGNOSTIC_OUTPUT_EXISTS
            elif error_code in {
                "diagnostic_confirmation_required",
                "invalid_diagnostic_export_request",
                "invalid_diagnostic_output_path",
            }:
                code = ConsoleStatusCode.INVALID_REQUEST
            else:
                code = ConsoleStatusCode.DIAGNOSTIC_EXPORT_FAILED
            return ConsoleOperationResult(code, None)
        except Exception:
            return ConsoleOperationResult(ConsoleStatusCode.COMMAND_FAILED, None)

    @staticmethod
    def _remove_tree_without_following_links(path: Path) -> None:
        if not path.exists() and not path.is_symlink():
            return
        if path.is_symlink() or path.is_file():
            path.unlink()
            return
        if not path.is_dir():
            raise OSError("invalid_owned_temporary_path")
        for child in path.iterdir():
            LocalDataCommands._remove_tree_without_following_links(child)
        path.rmdir()

    def _clear_diagnostic_temporary_files(self) -> None:
        temporary_root = self._data_root / "diagnostic-temp"
        if temporary_root.parent != self._data_root:
            raise OSError("invalid_owned_temporary_path")
        self._remove_tree_without_following_links(temporary_root)

    def delete_all_local_data(
        self,
        *,
        confirmed: bool,
    ) -> ConsoleOperationResult:
        if confirmed is not True:
            return ConsoleOperationResult(
                ConsoleStatusCode.CONFIRMATION_REQUIRED,
                None,
            )
        affected_items = 0
        failed = False
        try:
            deleted_evidence = self._evidence_store.delete_all()
            if (
                isinstance(deleted_evidence, bool)
                or not isinstance(deleted_evidence, int)
                or deleted_evidence < 0
            ):
                failed = True
            else:
                affected_items += deleted_evidence
        except Exception:
            failed = True
        try:
            deleted_examples = self._example_store.clear()
            if (
                isinstance(deleted_examples, bool)
                or not isinstance(deleted_examples, int)
                or deleted_examples < 0
            ):
                failed = True
            else:
                affected_items += deleted_examples
        except Exception:
            failed = True
        try:
            self._clear_diagnostic_temporary_files()
        except Exception:
            failed = True
        if self._pending_confirmation_store is not None:
            try:
                self._pending_confirmation_store.clear()
            except Exception:
                failed = True
        return ConsoleOperationResult(
            (
                ConsoleStatusCode.LOCAL_DATA_DELETE_PARTIAL_FAILURE
                if failed
                else ConsoleStatusCode.SUCCESS
            ),
            None,
            affected_items=affected_items,
        )


__all__ = ["LocalDataCommands"]
