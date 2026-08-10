from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
import sys


STARTUP_VALUE_NAME = "ShieldDome Endpoint Agent"
STARTUP_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


class StartupStatusCode(StrEnum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    UNAVAILABLE = "unavailable"
    FOREIGN_ENTRY = "foreign_entry"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class StartupStatus:
    code: StartupStatusCode
    enabled: bool


class CurrentUserRunRegistry:
    def read_current_user_value(self, name: str) -> str | None:
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, STARTUP_RUN_KEY) as key:
                value, value_type = winreg.QueryValueEx(key, name)
        except FileNotFoundError:
            return None
        if value_type != winreg.REG_SZ or not isinstance(value, str):
            return ""
        return value

    def write_current_user_value(self, name: str, value: str) -> None:
        import winreg

        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            STARTUP_RUN_KEY,
            0,
            winreg.KEY_SET_VALUE,
        ) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)

    def delete_current_user_value(self, name: str) -> None:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            STARTUP_RUN_KEY,
            0,
            winreg.KEY_SET_VALUE,
        ) as key:
            try:
                winreg.DeleteValue(key, name)
            except FileNotFoundError:
                pass


class WindowsStartupManager:
    def __init__(
        self,
        *,
        executable_path: str | Path | None = None,
        frozen: bool | None = None,
        registry: object | None = None,
    ) -> None:
        self._path = Path(executable_path if executable_path is not None else sys.executable)
        self._frozen = bool(getattr(sys, "frozen", False) if frozen is None else frozen)
        self._registry = registry or CurrentUserRunRegistry()

    def _owned_command(self) -> str | None:
        if not self._frozen or not self._path.is_absolute():
            return None
        resolved = self._path.resolve(strict=False)
        if resolved.name.casefold() != "shielddomeendpoint.exe" or not resolved.is_file():
            return None
        return f'"{resolved}"'

    def status(self) -> StartupStatus:
        command = self._owned_command()
        if command is None:
            return StartupStatus(StartupStatusCode.UNAVAILABLE, False)
        try:
            current = self._registry.read_current_user_value(STARTUP_VALUE_NAME)
        except Exception:
            return StartupStatus(StartupStatusCode.FAILED, False)
        if current is None:
            return StartupStatus(StartupStatusCode.DISABLED, False)
        if current == command:
            return StartupStatus(StartupStatusCode.ENABLED, True)
        return StartupStatus(StartupStatusCode.FOREIGN_ENTRY, False)

    def install(self) -> StartupStatus:
        current = self.status()
        if current.code is not StartupStatusCode.DISABLED:
            return current
        command = self._owned_command()
        if command is None:
            return StartupStatus(StartupStatusCode.UNAVAILABLE, False)
        try:
            self._registry.write_current_user_value(STARTUP_VALUE_NAME, command)
        except Exception:
            return StartupStatus(StartupStatusCode.FAILED, False)
        return StartupStatus(StartupStatusCode.ENABLED, True)

    def uninstall(self) -> StartupStatus:
        current = self.status()
        if current.code is StartupStatusCode.DISABLED:
            return current
        if current.code is not StartupStatusCode.ENABLED:
            return current
        try:
            self._registry.delete_current_user_value(STARTUP_VALUE_NAME)
        except Exception:
            return StartupStatus(StartupStatusCode.FAILED, True)
        return StartupStatus(StartupStatusCode.DISABLED, False)


__all__ = [
    "STARTUP_RUN_KEY",
    "STARTUP_VALUE_NAME",
    "CurrentUserRunRegistry",
    "StartupStatus",
    "StartupStatusCode",
    "WindowsStartupManager",
]
