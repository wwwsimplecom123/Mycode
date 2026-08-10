from pathlib import Path
import os
import sys
from tempfile import TemporaryDirectory
import threading
import time
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QPushButton

from shielddome_endpoint.console_models import ConsoleOperationResult, ConsoleStatusCode
from shielddome_endpoint.desktop_mail_intake import DesktopMailIntakePanel
from shielddome_endpoint.desktop_qt import create_desktop_application
from shielddome_endpoint.domain import (
    DetectionExecutionState,
    GenericAction,
    RiskLevel,
)
from shielddome_endpoint.local_mail_intake import LocalMailIntakeError
from test_desktop_presenter import PagingConsoleService, make_dashboard


def wait_until(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        QApplication.processEvents()
        if predicate():
            return
        time.sleep(0.01)
    raise RuntimeError("screenshot_state_timeout")


def save(window, path: Path, width: int, height: int):
    window.resize(width, height)
    window.show()
    QApplication.processEvents()
    if not window.grab().save(str(path), "PNG"):
        raise RuntimeError("screenshot_save_failed")


class Dialogs:
    def __init__(self):
        self.confirmed = False
        self.capture = None

    def choose_eml_path(self, parent):
        return None

    def confirm_mail_intake(self, parent):
        if self.capture is not None:
            self.capture()
            self.capture = None
        return self.confirmed


class MailIntake:
    def __init__(self):
        self.release = threading.Event()
        self.started = threading.Event()
        self.error_code = None

    def detect_file(self, path, *, confirmed_by_user):
        if confirmed_by_user is not True:
            raise AssertionError("confirmation_missing")
        self.started.set()
        self.release.wait(timeout=5)
        if self.error_code is not None:
            raise LocalMailIntakeError(self.error_code)
        return SimpleNamespace(
            local_event_id="event-local-capture-001",
            risk_level=RiskLevel.HIGH,
            execution_state=DetectionExecutionState.RULES_ONLY,
            generic_action=GenericAction.AVOID_CREDENTIALS,
        )


def main() -> int:
    output = ROOT / "dist" / "phase7c2" / "screenshots"
    output.mkdir(parents=True, exist_ok=True)
    dialogs = Dialogs()
    mail_intake = MailIntake()
    console = PagingConsoleService(
        ConsoleOperationResult(
            ConsoleStatusCode.SUCCESS,
            make_dashboard(today_count=0),
        ),
        (),
    )
    bundle = create_desktop_application(
        service=console,
        mail_intake_service=mail_intake,
        dialogs=dialogs,
        show=False,
        enable_tray=False,
    )
    bundle.window.findChild(QPushButton, "localIntakeNav").click()
    panel = bundle.window.findChild(DesktopMailIntakePanel, "mailIntakePanel")

    with TemporaryDirectory() as temporary_directory:
        mail_path = Path(temporary_directory) / "synthetic.eml"
        mail_path.write_text("Subject: synthetic\n\nsynthetic body", encoding="utf-8")

        save(bundle.window, output / "1366x768-initial.png", 1366, 768)

        dialogs.confirmed = False
        dialogs.capture = lambda: save(
            bundle.window,
            output / "1024x720-selected-confirmation.png",
            1024,
            720,
        )
        panel.select_path(str(mail_path))

        dialogs.confirmed = True
        mail_intake.release.clear()
        mail_intake.started.clear()
        panel.select_path(str(mail_path))
        wait_until(mail_intake.started.is_set)
        save(bundle.window, output / "1024x720-running.png", 1024, 720)
        mail_intake.release.set()
        wait_until(lambda: panel._thread is None)
        save(bundle.window, output / "1024x720-complete.png", 1024, 720)

        mail_intake.error_code = "file_too_large"
        mail_intake.release.set()
        mail_intake.started.clear()
        panel.select_path(str(mail_path))
        wait_until(lambda: panel._thread is None)
        save(bundle.window, output / "1024x720-file-too-large.png", 1024, 720)

    if Path(temporary_directory).exists():
        raise RuntimeError("temporary_mail_not_removed")
    panel.shutdown()
    bundle.window.hide()
    QApplication.processEvents()
    for screenshot in sorted(output.glob("*.png")):
        print(screenshot, screenshot.stat().st_size)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
