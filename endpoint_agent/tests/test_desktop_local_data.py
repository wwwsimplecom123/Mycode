from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))


class LocalDataServiceFake:
    def __init__(self):
        from shielddome_endpoint.console_models import (
            ConfirmedExampleListItemViewModel,
            ConfirmedExamplePageViewModel,
            ConsoleOperationResult,
            ConsoleStatusCode,
        )
        self.ConsoleOperationResult = ConsoleOperationResult
        self.ConsoleStatusCode = ConsoleStatusCode
        self.page_type = ConfirmedExamplePageViewModel
        self.item_type = ConfirmedExampleListItemViewModel
        self.calls = []

    def list_confirmed_examples(self, *, offset, limit, label):
        label_value = label.value if hasattr(label, "value") else label
        self.calls.append(("list", offset, limit, label_value))
        item = self.item_type(
            "example-" + "a" * 32,
            "benign",
            "browser_native",
            datetime(2026, 8, 10, 1, 2, tzinfo=timezone.utc),
            True,
        )
        return self.ConsoleOperationResult(
            self.ConsoleStatusCode.SUCCESS,
            self.page_type(
                datetime(2026, 8, 10, 2, tzinfo=timezone.utc),
                offset,
                limit,
                1,
                False,
                label_value,
                (item,),
            ),
        )

    def delete_confirmed_example(self, example_id):
        self.calls.append(("delete", example_id))
        return self.ConsoleOperationResult(self.ConsoleStatusCode.SUCCESS, None, 1)

    def clear_confirmed_examples(self, *, confirmed):
        self.calls.append(("clear", confirmed))
        return self.ConsoleOperationResult(self.ConsoleStatusCode.SUCCESS, None, 1)

    def export_diagnostics(self, path, *, confirmed, overwrite=False):
        self.calls.append(("export", str(path), confirmed, overwrite))
        return self.ConsoleOperationResult(self.ConsoleStatusCode.DIAGNOSTIC_EXPORTED, None, 1)

    def delete_all_local_data(self, *, confirmed):
        self.calls.append(("delete_all", confirmed))
        return self.ConsoleOperationResult(self.ConsoleStatusCode.SUCCESS, None, 2)

    def get_dashboard(self):
        self.calls.append(("dashboard",))
        return self.ConsoleOperationResult(self.ConsoleStatusCode.INVALID_REQUEST, None)

    def list_recent_events(self, *, offset, limit):
        return self.ConsoleOperationResult(self.ConsoleStatusCode.INVALID_REQUEST, None)


class DesktopLocalDataPresenterTests(unittest.TestCase):
    def test_samples_filter_delete_clear_and_sensitive_fields_are_absent(self):
        from shielddome_endpoint.desktop_presenter import PersonalConsolePresenter

        service = LocalDataServiceFake()
        presenter = PersonalConsolePresenter(service)
        state = presenter.refresh_examples("benign")
        self.assertEqual(state.examples.rows[0].label_text, "正常")
        self.assertEqual(state.examples.rows[0].conflict_text, "有冲突")
        self.assertFalse(hasattr(state.examples.rows[0], "feature_vector"))
        self.assertFalse(hasattr(state.examples.rows[0], "fingerprint"))
        presenter.delete_example(state.examples.rows[0].example_id, confirmed=True)
        presenter.clear_examples(confirmed=True)
        self.assertIn(("clear", True), service.calls)
        self.assertGreaterEqual(sum(call[0] == "list" for call in service.calls), 3)

    def test_export_requires_path_and_delete_all_requires_exact_double_confirmation(self):
        from shielddome_endpoint.desktop_presenter import PersonalConsolePresenter

        service = LocalDataServiceFake()
        presenter = PersonalConsolePresenter(service)
        presenter.export_diagnostics(None, confirmed=True)
        presenter.delete_all_local_data(first_confirmed=True, confirmation_text="wrong")
        self.assertFalse(any(call[0] in {"export", "delete_all"} for call in service.calls))
        presenter.export_diagnostics("safe.zip", confirmed=True)
        presenter.delete_all_local_data(
            first_confirmed=True,
            confirmation_text="删除全部本地数据",
        )
        self.assertIn(("export", "safe.zip", True, False), service.calls)
        self.assertIn(("delete_all", True), service.calls)


try:
    from PySide6.QtWidgets import QApplication, QPushButton, QTableWidget
except ImportError:
    QApplication = None


@unittest.skipUnless(QApplication is not None, "PySide6 unavailable")
class DesktopLocalDataQtTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.application = QApplication.instance() or QApplication([])

    def test_sample_page_and_development_startup_status_are_safe(self):
        from shielddome_endpoint.desktop_qt import create_desktop_application
        from shielddome_endpoint.startup_manager import StartupStatus, StartupStatusCode

        class Startup:
            def status(self):
                return StartupStatus(StartupStatusCode.UNAVAILABLE, False)

        class Dialogs:
            pass

        bundle = create_desktop_application(
            service=LocalDataServiceFake(),
            show=False,
            enable_tray=False,
            startup_manager=Startup(),
            dialogs=Dialogs(),
        )
        bundle.window.findChild(QPushButton, "examplesNav").click()
        bundle.window._refresh_examples()
        table = bundle.window.findChild(QTableWidget, "examplesTable")
        self.assertEqual(
            [table.horizontalHeaderItem(i).text() for i in range(5)],
            ["确认时间", "标签", "来源", "冲突", "操作"],
        )
        self.assertEqual(table.rowCount(), 1)
        self.assertEqual(
            bundle.window.findChild(QPushButton, "startupToggle").isEnabled(),
            False,
        )
        self.assertIn("安装版", bundle.window._startup_status.text())
        sources = " ".join(table.item(0, i).text() for i in range(4)).casefold()
        self.assertNotIn("fingerprint", sources)
        self.assertNotIn("featurevector", sources)
        bundle.lifecycle.quit_application()


if __name__ == "__main__":
    unittest.main()
