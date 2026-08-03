from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import sys
from collections.abc import Callable


CRYPTPROTECT_UI_FORBIDDEN = 0x1
CRYPTPROTECT_LOCAL_MACHINE = 0x4
_PROTECTED_KEY_MAGIC = b"SDDPAPI1"
_SCOPE_DIGEST_BYTES = 32
_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1
_ERROR_INSUFFICIENT_BUFFER = 122
DATA_KEY_BYTES = 32
PROTECTED_KEY_MAX_BYTES = 16_384
_ERASE_CHUNK_BYTES = 1_048_576


class KeyProtectionError(RuntimeError):
    pass


class _DataBlob(ctypes.Structure):
    _fields_ = (
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    )


class _SidAndAttributes(ctypes.Structure):
    _fields_ = (
        ("Sid", wintypes.LPVOID),
        ("Attributes", wintypes.DWORD),
    )


class _TokenUser(ctypes.Structure):
    _fields_ = (("User", _SidAndAttributes),)


def _current_user_sid() -> str:
    if sys.platform != "win32":
        raise KeyProtectionError("user_scope_unavailable")
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.OpenProcessToken.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    )
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = (
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPWSTR),
    )
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = (wintypes.HLOCAL,)
    kernel32.LocalFree.restype = wintypes.HLOCAL

    token = wintypes.HANDLE()
    sid_text = wintypes.LPWSTR()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        _TOKEN_QUERY,
        ctypes.byref(token),
    ):
        raise KeyProtectionError("user_scope_unavailable")
    try:
        required = wintypes.DWORD()
        advapi32.GetTokenInformation(
            token,
            _TOKEN_USER,
            None,
            0,
            ctypes.byref(required),
        )
        if (
            ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER
            or required.value == 0
        ):
            raise KeyProtectionError("user_scope_unavailable")
        buffer = ctypes.create_string_buffer(required.value)
        if not advapi32.GetTokenInformation(
            token,
            _TOKEN_USER,
            buffer,
            required,
            ctypes.byref(required),
        ):
            raise KeyProtectionError("user_scope_unavailable")
        token_user = ctypes.cast(buffer, ctypes.POINTER(_TokenUser)).contents
        if not advapi32.ConvertSidToStringSidW(
            token_user.User.Sid,
            ctypes.byref(sid_text),
        ):
            raise KeyProtectionError("user_scope_unavailable")
        result = sid_text.value
        if not result:
            raise KeyProtectionError("user_scope_unavailable")
        return result
    finally:
        if sid_text:
            kernel32.LocalFree(ctypes.cast(sid_text, wintypes.HLOCAL))
        kernel32.CloseHandle(token)


def _input_blob(value: bytes) -> tuple[_DataBlob, object]:
    buffer = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
    blob = _DataBlob(
        len(value),
        ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
    )
    return blob, buffer


class _WindowsDpapiBackend:
    def __init__(self) -> None:
        if sys.platform != "win32":
            raise KeyProtectionError("dpapi_unavailable")
        self._crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._crypt32.CryptProtectData.argtypes = (
            ctypes.POINTER(_DataBlob),
            wintypes.LPCWSTR,
            ctypes.POINTER(_DataBlob),
            wintypes.LPVOID,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(_DataBlob),
        )
        self._crypt32.CryptProtectData.restype = wintypes.BOOL
        self._crypt32.CryptUnprotectData.argtypes = (
            ctypes.POINTER(_DataBlob),
            ctypes.POINTER(wintypes.LPWSTR),
            ctypes.POINTER(_DataBlob),
            wintypes.LPVOID,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(_DataBlob),
        )
        self._crypt32.CryptUnprotectData.restype = wintypes.BOOL
        self._kernel32.LocalFree.argtypes = (wintypes.HLOCAL,)
        self._kernel32.LocalFree.restype = wintypes.HLOCAL

    def protect(self, plaintext: bytes, *, flags: int) -> bytes:
        input_blob, input_buffer = _input_blob(plaintext)
        output_blob = _DataBlob()
        success = self._crypt32.CryptProtectData(
            ctypes.byref(input_blob),
            "ShieldDome Endpoint Evidence Key",
            None,
            None,
            None,
            flags,
            ctypes.byref(output_blob),
        )
        del input_buffer
        if not success:
            raise KeyProtectionError("key_protection_failed")
        try:
            if not output_blob.pbData or output_blob.cbData == 0:
                raise KeyProtectionError("key_protection_failed")
            return ctypes.string_at(output_blob.pbData, output_blob.cbData)
        finally:
            if output_blob.pbData:
                self._kernel32.LocalFree(
                    ctypes.cast(output_blob.pbData, wintypes.HLOCAL)
                )

    def unprotect(self, protected: bytes, *, flags: int) -> bytes:
        input_blob, input_buffer = _input_blob(protected)
        output_blob = _DataBlob()
        description = wintypes.LPWSTR()
        success = self._crypt32.CryptUnprotectData(
            ctypes.byref(input_blob),
            ctypes.byref(description),
            None,
            None,
            None,
            flags,
            ctypes.byref(output_blob),
        )
        del input_buffer
        if not success:
            raise KeyProtectionError("key_unprotection_failed")
        try:
            if not output_blob.pbData or output_blob.cbData == 0:
                raise KeyProtectionError("key_unprotection_failed")
            return ctypes.string_at(output_blob.pbData, output_blob.cbData)
        finally:
            if output_blob.pbData:
                ctypes.memset(output_blob.pbData, 0, output_blob.cbData)
                self._kernel32.LocalFree(
                    ctypes.cast(output_blob.pbData, wintypes.HLOCAL)
                )
            if description:
                self._kernel32.LocalFree(ctypes.cast(description, wintypes.HLOCAL))


class CurrentUserKeyProtector:
    def __init__(
        self,
        *,
        backend: object | None = None,
        scope_identity_provider: Callable[[], str] | None = None,
    ) -> None:
        self._backend = backend or _WindowsDpapiBackend()
        self._scope_identity_provider = (
            scope_identity_provider or _current_user_sid
        )

    def _scope_digest(self) -> bytes:
        try:
            identity = self._scope_identity_provider()
        except KeyProtectionError:
            raise
        except Exception:
            raise KeyProtectionError("user_scope_unavailable") from None
        if not isinstance(identity, str) or not identity or len(identity) > 512:
            raise KeyProtectionError("user_scope_unavailable")
        return hashlib.sha256(identity.encode("utf-8")).digest()

    def protect(self, plaintext: bytes) -> bytes:
        if not isinstance(plaintext, bytes) or not plaintext:
            raise KeyProtectionError("invalid_key_material")
        flags = CRYPTPROTECT_UI_FORBIDDEN
        if flags & CRYPTPROTECT_LOCAL_MACHINE:
            raise KeyProtectionError("invalid_dpapi_scope")
        protected = self._backend.protect(plaintext, flags=flags)
        if not isinstance(protected, bytes) or not protected:
            raise KeyProtectionError("key_protection_failed")
        return _PROTECTED_KEY_MAGIC + self._scope_digest() + protected

    def unprotect(self, protected: bytes) -> bytes:
        if not isinstance(protected, bytes) or not protected:
            raise KeyProtectionError("invalid_protected_key")
        header_size = len(_PROTECTED_KEY_MAGIC) + _SCOPE_DIGEST_BYTES
        if len(protected) <= header_size or not protected.startswith(
            _PROTECTED_KEY_MAGIC
        ):
            raise KeyProtectionError("invalid_protected_key")
        stored_scope = protected[
            len(_PROTECTED_KEY_MAGIC) : header_size
        ]
        if not hmac.compare_digest(stored_scope, self._scope_digest()):
            raise KeyProtectionError("user_scope_mismatch")
        flags = CRYPTPROTECT_UI_FORBIDDEN
        if flags & CRYPTPROTECT_LOCAL_MACHINE:
            raise KeyProtectionError("invalid_dpapi_scope")
        plaintext = self._backend.unprotect(protected[header_size:], flags=flags)
        if not isinstance(plaintext, bytes) or not plaintext:
            raise KeyProtectionError("key_unprotection_failed")
        return plaintext


def default_user_data_directory() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        raise KeyProtectionError("local_app_data_unavailable")
    candidate = Path(local_app_data).resolve(strict=False)
    for variable in ("PROGRAMDATA", "ALLUSERSPROFILE", "PUBLIC"):
        shared_value = os.environ.get(variable)
        if not shared_value:
            continue
        shared_root = Path(shared_value).resolve(strict=False)
        if candidate == shared_root or candidate.is_relative_to(shared_root):
            raise KeyProtectionError("shared_data_directory_forbidden")
    return candidate / "ShieldDome" / "EndpointAgent"


def _overwrite_and_unlink(path: Path) -> bool:
    try:
        if not path.exists():
            return False
        if not path.is_file():
            raise KeyProtectionError("protected_key_delete_failed")
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
    except KeyProtectionError:
        raise
    except OSError:
        raise KeyProtectionError("protected_key_delete_failed") from None


class UserDataKeyManager:
    def __init__(
        self,
        data_directory: Path | None = None,
        *,
        protector: CurrentUserKeyProtector | None = None,
        database_filename: str = "evidence.sqlite3",
    ) -> None:
        if data_directory is None:
            self.data_directory = default_user_data_directory()
        else:
            local_app_data = os.environ.get("LOCALAPPDATA")
            if not local_app_data:
                raise KeyProtectionError("local_app_data_unavailable")
            local_root = Path(local_app_data).resolve(strict=False)
            candidate = Path(data_directory).resolve(strict=False)
            if not candidate.is_relative_to(local_root):
                raise KeyProtectionError("data_directory_outside_local_app_data")
            self.data_directory = candidate
        self.key_path = self.data_directory / "keys" / "evidence.key"
        self.database_path = self.data_directory / "data" / database_filename
        self._protector = protector or CurrentUserKeyProtector()

    def load_or_create(self) -> bytes:
        if self.key_path.exists():
            try:
                protected = self.key_path.read_bytes()
            except OSError:
                raise KeyProtectionError("protected_key_read_failed") from None
            if not protected or len(protected) > PROTECTED_KEY_MAX_BYTES:
                raise KeyProtectionError("invalid_protected_key")
            key = self._protector.unprotect(protected)
            if len(key) != DATA_KEY_BYTES:
                raise KeyProtectionError("invalid_data_key")
            return key

        if self.database_path.exists():
            raise KeyProtectionError("protected_key_missing")

        key = secrets.token_bytes(DATA_KEY_BYTES)
        protected = self._protector.protect(key)
        if not protected or len(protected) > PROTECTED_KEY_MAX_BYTES:
            raise KeyProtectionError("key_protection_failed")
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = self.key_path.with_name(self.key_path.name + ".tmp")
        try:
            descriptor = os.open(
                temporary_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            try:
                with os.fdopen(descriptor, "wb", closefd=True) as stream:
                    stream.write(protected)
                    stream.flush()
                    os.fsync(stream.fileno())
            except Exception:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                raise
            os.replace(temporary_path, self.key_path)
        except FileExistsError:
            try:
                temporary_path.unlink()
            except OSError:
                raise KeyProtectionError("protected_key_write_failed") from None
            return self.load_or_create()
        except OSError:
            raise KeyProtectionError("protected_key_write_failed") from None
        finally:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
        return key

    def delete(self) -> bool:
        temporary_path = self.key_path.with_name(self.key_path.name + ".tmp")
        removed_temporary = _overwrite_and_unlink(temporary_path)
        removed_key = _overwrite_and_unlink(self.key_path)
        return removed_temporary or removed_key


__all__ = [
    "CRYPTPROTECT_LOCAL_MACHINE",
    "CRYPTPROTECT_UI_FORBIDDEN",
    "CurrentUserKeyProtector",
    "DATA_KEY_BYTES",
    "KeyProtectionError",
    "UserDataKeyManager",
    "default_user_data_directory",
]
