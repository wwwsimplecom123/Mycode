from pathlib import Path
import os
import sys
from tempfile import TemporaryDirectory
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtCore import QMimeData, QPoint, QPointF, QThread, Qt, QUrl
    from PySide6.QtGui import QDragEnterEvent, QDropEvent
    from PySide6.QtWidgets import QApplication, QLabel, QPushButton
except ImportError:
    QApplication = None


@unittest.skipUnless(QApplication is not None, "PySide6 unavailable")
class DesktopMailIntakeDropTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.application = QApplication.instance() or QApplication([])

    def test_one_local_eml_drop_is_accepted_as_selection_only(self):
        from shielddome_endpoint.desktop_mail_intake import EmlDropZone

        with TemporaryDirectory() as temporary_directory:
            mail_path = Path(temporary_directory) / "synthetic.eml"
            mail_path.write_text("Subject: synthetic\n\nbody", encoding="utf-8")
            mime_data = QMimeData()
            mime_data.setUrls([QUrl.fromLocalFile(str(mail_path))])
            zone = EmlDropZone()
            selected = []
            zone.fileSelected.connect(selected.append)
            drag = QDragEnterEvent(
                QPoint(4, 4),
                Qt.DropAction.CopyAction,
                mime_data,
                Qt.MouseButton.LeftButton,
                Qt.KeyboardModifier.NoModifier,
            )
            drop = QDropEvent(
                QPointF(4, 4),
                Qt.DropAction.CopyAction,
                mime_data,
                Qt.MouseButton.LeftButton,
                Qt.KeyboardModifier.NoModifier,
            )
            QApplication.sendEvent(zone, drag)
            QApplication.sendEvent(zone, drop)
            self.assertEqual(EmlDropZone.local_eml_path(mime_data), str(mail_path))
            self.assertTrue(drag.isAccepted())
            self.assertTrue(drop.isAccepted())
            self.assertEqual(selected, [str(mail_path)])

        self.assertFalse(Path(temporary_directory).exists())

    def test_uppercase_extension_is_accepted_and_other_local_inputs_are_rejected(self):
        from shielddome_endpoint.desktop_mail_intake import EmlDropZone

        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            upper = root / "synthetic.EML"
            upper.write_text("Subject: synthetic\n\nbody", encoding="utf-8")
            text_file = root / "synthetic.txt"
            text_file.write_text("synthetic", encoding="utf-8")

            accepted = QMimeData()
            accepted.setUrls([QUrl.fromLocalFile(str(upper))])
            self.assertEqual(EmlDropZone.local_eml_path(accepted), str(upper))

            rejected_values = []
            multiple = QMimeData()
            multiple.setUrls(
                [QUrl.fromLocalFile(str(upper)), QUrl.fromLocalFile(str(text_file))]
            )
            rejected_values.append(multiple)
            for path in (root, text_file):
                mime_data = QMimeData()
                mime_data.setUrls([QUrl.fromLocalFile(str(path))])
                rejected_values.append(mime_data)
            for remote in (
                "http://example.test/mail.eml",
                "https://example.test/mail.eml",
                "ftp://example.test/mail.eml",
            ):
                mime_data = QMimeData()
                mime_data.setUrls([QUrl(remote)])
                rejected_values.append(mime_data)
            plain_text = QMimeData()
            plain_text.setText("synthetic message")
            rejected_values.append(plain_text)
            html = QMimeData()
            html.setHtml("<p>synthetic message</p>")
            rejected_values.append(html)
            private_object = QMimeData()
            private_object.setData("application/x-outlook-message", b"synthetic")
            rejected_values.append(private_object)

            for mime_data in rejected_values:
                with self.subTest(formats=mime_data.formats()):
                    self.assertIsNone(EmlDropZone.local_eml_path(mime_data))

        self.assertFalse(Path(temporary_directory).exists())

    def test_stable_error_messages_do_not_echo_private_values(self):
        from shielddome_endpoint.desktop_mail_intake import safe_intake_error_text

        expected = {
            "confirmation_required": "需要确认后才能开始本地检测。",
            "unsupported_file": "请选择一个有效的 EML 邮件文件。",
            "unsafe_path": "无法安全访问所选邮件文件。",
            "file_not_found": "所选邮件文件已不存在，请重新选择。",
            "file_too_large": "邮件文件超过本地检测大小限制。",
            "mime_limit_exceeded": "邮件结构超过本地安全处理限制。",
            "malformed_message": "邮件格式无法安全解析。",
            "intake_failed": "本地检测未完成，请重新选择后重试。",
        }
        self.assertEqual(
            {code: safe_intake_error_text(code) for code in expected}, expected
        )
        unknown = safe_intake_error_text(
            "C:\\private\\secret.eml body https://example.test/?token=secret"
        )
        self.assertEqual(unknown, expected["intake_failed"])
        self.assertNotIn("private", unknown.casefold())
        self.assertNotIn("example.test", unknown.casefold())


class Dialogs:
    def __init__(self, *, confirmed: bool, chosen_path: str | None = None):
        self.confirmed = confirmed
        self.chosen_path = chosen_path
        self.confirm_calls = 0

    def choose_eml_path(self, parent):
        return self.chosen_path

    def confirm_mail_intake(self, parent):
        self.confirm_calls += 1
        return self.confirmed


class Intake:
    def __init__(self, *, release: threading.Event | None = None, error=None):
        self.release = release
        self.error = error
        self.calls = []
        self.started = threading.Event()

    def detect_file(self, path, *, confirmed_by_user):
        self.calls.append((path, confirmed_by_user, QThread.currentThread()))
        self.started.set()
        if self.release is not None:
            self.release.wait(timeout=5)
        if self.error is not None:
            raise self.error
        from shielddome_endpoint.domain import (
            DetectionExecutionState,
            GenericAction,
            RiskLevel,
        )

        return SimpleNamespace(
            local_event_id="event-local-ui-001",
            risk_level=RiskLevel.HIGH,
            execution_state=DetectionExecutionState.RULES_ONLY,
            generic_action=GenericAction.AVOID_CREDENTIALS,
        )


@unittest.skipUnless(QApplication is not None, "PySide6 unavailable")
class DesktopMailIntakePanelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.application = QApplication.instance() or QApplication([])

    def wait_until(self, predicate, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            QApplication.processEvents()
            if predicate():
                return
            time.sleep(0.01)
        self.fail("condition_not_reached")

    def test_unconfirmed_selection_does_not_call_intake_and_clears_path(self):
        from shielddome_endpoint.desktop_mail_intake import DesktopMailIntakePanel

        intake = Intake()
        dialogs = Dialogs(confirmed=False)
        panel = DesktopMailIntakePanel(
            intake,
            dialogs=dialogs,
            refresh_callback=lambda: None,
            open_events_callback=lambda: None,
        )

        panel.select_path(r"C:\private\selected.eml")

        self.assertEqual(dialogs.confirm_calls, 1)
        self.assertEqual(intake.calls, [])
        self.assertIsNone(panel._selected_path)
        self.assertNotIn(
            "C:\\private",
            " ".join(label.text() for label in panel.findChildren(QLabel)),
        )

    def test_confirmed_selection_runs_once_outside_ui_thread_and_is_single_flight(self):
        from shielddome_endpoint.desktop_mail_intake import (
            DesktopMailIntakePanel,
            EmlDropZone,
        )

        release = threading.Event()
        intake = Intake(release=release)
        panel = DesktopMailIntakePanel(
            intake,
            dialogs=Dialogs(confirmed=True),
            refresh_callback=lambda: None,
            open_events_callback=lambda: None,
        )

        panel.select_path(r"C:\temporary\first.eml")
        self.wait_until(intake.started.is_set)
        panel.select_path(r"C:\temporary\second.eml")

        self.assertEqual(len(intake.calls), 1)
        self.assertTrue(intake.calls[0][1])
        self.assertIsNot(intake.calls[0][2], QApplication.instance().thread())
        self.assertFalse(panel.findChild(QPushButton, "selectEmlButton").isEnabled())
        self.assertFalse(panel.findChild(EmlDropZone, "emlDropZone").isEnabled())
        self.assertEqual(
            panel.findChild(QLabel, "mailIntakeStatus").text(), "正在本地检测"
        )
        worker = panel._worker
        self.assertFalse(hasattr(worker, "result"))
        self.assertFalse(hasattr(worker, "outcome"))

        release.set()
        self.wait_until(lambda: panel._thread is None)
        self.assertIsNone(panel._selected_path)
        self.assertIsNone(worker._path)
        self.assertEqual(len(intake.calls), 1)

    def test_success_displays_only_four_minimal_result_fields_and_refreshes(self):
        from shielddome_endpoint.desktop_mail_intake import DesktopMailIntakePanel

        refreshes = []
        panel = DesktopMailIntakePanel(
            Intake(),
            dialogs=Dialogs(confirmed=True),
            refresh_callback=lambda: refreshes.append("refresh"),
            open_events_callback=lambda: None,
        )
        panel.select_path(r"C:\temporary\success.eml")
        self.wait_until(lambda: panel._thread is None)

        values = {
            name: panel.findChild(QLabel, name).text()
            for name in (
                "mailRiskValue",
                "mailDetectionValue",
                "mailAdviceValue",
                "mailEventIdValue",
            )
        }
        self.assertEqual(
            values,
            {
                "mailRiskValue": "高风险",
                "mailDetectionValue": "纯规则完成",
                "mailAdviceValue": "不要提交凭据",
                "mailEventIdValue": "event-local-ui-001",
            },
        )
        self.assertEqual(refreshes, ["refresh"])
        visible_text = " ".join(label.text() for label in panel.findChildren(QLabel))
        for forbidden in ("C:\\temporary", "FeatureVector", "规则明细", "模型原因"):
            self.assertNotIn(forbidden, visible_text)

    def test_file_picker_uses_eml_filter_and_cancel_is_silent(self):
        from shielddome_endpoint.desktop_qt import QtDialogAdapter

        adapter = QtDialogAdapter()
        with patch(
            "shielddome_endpoint.desktop_qt.QFileDialog.getOpenFileName",
            return_value=("", ""),
        ) as picker:
            self.assertIsNone(adapter.choose_eml_path(None))
        picker.assert_called_once_with(
            None,
            "选择 EML 邮件文件",
            "",
            "EML 邮件 (*.eml *.EML)",
        )

    def test_confirmation_copy_states_local_privacy_guarantees(self):
        from shielddome_endpoint.desktop_qt import QtDialogAdapter

        adapter = QtDialogAdapter()
        with patch.object(adapter, "confirm", return_value=False) as confirm:
            self.assertFalse(adapter.confirm_mail_intake(None))
        _parent, _title, text = confirm.call_args.args
        for required in ("只在本机处理", "不会上传", "不会打开", "预览", "解压", "执行附件", "加密结构化结果"):
            self.assertIn(required, text)

    def test_stable_failure_clears_path_and_does_not_echo_exception(self):
        from shielddome_endpoint.desktop_mail_intake import DesktopMailIntakePanel
        from shielddome_endpoint.local_mail_intake import LocalMailIntakeError

        panel = DesktopMailIntakePanel(
            Intake(error=LocalMailIntakeError("file_too_large")),
            dialogs=Dialogs(confirmed=True),
            refresh_callback=lambda: None,
            open_events_callback=lambda: None,
        )
        panel.select_path(r"C:\private\large-secret.eml")
        self.wait_until(lambda: panel._thread is None)

        self.assertIsNone(panel._selected_path)
        visible_text = " ".join(label.text() for label in panel.findChildren(QLabel))
        self.assertIn("超过本地检测大小限制", visible_text)
        self.assertEqual(
            panel.findChild(QLabel, "mailIntakeStatus").property("mailTone"),
            "warning",
        )
        self.assertNotIn("large-secret", visible_text)
        self.assertNotIn("C:\\private", visible_text)

    def test_shutdown_waits_for_worker_and_discards_queued_ui_callbacks(self):
        from shielddome_endpoint.desktop_mail_intake import DesktopMailIntakePanel

        release = threading.Event()
        intake = Intake(release=release)
        refreshes = []
        panel = DesktopMailIntakePanel(
            intake,
            dialogs=Dialogs(confirmed=True),
            refresh_callback=lambda: refreshes.append("refresh"),
            open_events_callback=lambda: None,
        )
        panel.select_path(r"C:\temporary\closing.eml")
        self.wait_until(intake.started.is_set)
        thread = panel._thread
        release.set()
        panel.shutdown()
        QApplication.processEvents()

        self.assertFalse(thread.isRunning())
        self.assertIsNone(panel._thread)
        self.assertIsNone(panel._worker)
        self.assertIsNone(panel._selected_path)
        self.assertEqual(refreshes, [])


if __name__ == "__main__":
    unittest.main()
