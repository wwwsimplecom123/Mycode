from enum import StrEnum


class CloseDisposition(StrEnum):
    HIDE_TO_TRAY = "hide_to_tray"
    EXIT = "exit"


class DesktopLifecycle:
    def __init__(self, adapter: object) -> None:
        self._adapter = adapter
        self._is_quitting = False

    @property
    def is_quitting(self) -> bool:
        return self._is_quitting

    def show_console(self) -> None:
        if not self._is_quitting:
            self._adapter.show_window()

    def hide_console(self) -> None:
        if not self._is_quitting:
            self._adapter.hide_window()

    def handle_window_close(self) -> CloseDisposition:
        if self._is_quitting:
            return CloseDisposition.EXIT
        self._adapter.hide_window()
        return CloseDisposition.HIDE_TO_TRAY

    def quit_application(self) -> None:
        if self._is_quitting:
            return
        self._is_quitting = True
        self._adapter.hide_tray()
        self._adapter.quit_event_loop()


__all__ = ["CloseDisposition", "DesktopLifecycle"]
