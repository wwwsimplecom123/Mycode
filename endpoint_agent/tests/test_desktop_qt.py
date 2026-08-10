from pathlib import Path
import os
import sys
import unittest


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))
sys.path.insert(0, str(ENDPOINT_ROOT / "tests"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtGui import QFontDatabase, QFontMetrics
    from PySide6.QtWidgets import (
        QApplication,
        QLabel,
        QPushButton,
        QStackedWidget,
        QTableWidget,
        QWidget,
    )
except ImportError:
    QApplication = None


@unittest.skipUnless(QApplication is not None, "PySide6 unavailable in core test environment")
class DesktopQtTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.application = QApplication.instance() or QApplication([])

    def test_real_qt_window_renders_dashboard_at_minimum_size(self):
        from test_desktop_presenter import (
            PagingConsoleService,
            make_dashboard,
            make_event,
        )
        from shielddome_endpoint.console_models import (
            ConsoleOperationResult,
            ConsoleStatusCode,
        )
        from shielddome_endpoint.desktop_qt import create_desktop_application

        service = PagingConsoleService(
            ConsoleOperationResult(
                ConsoleStatusCode.SUCCESS,
                make_dashboard(today_count=4),
            ),
            (make_event("event-gui-01"), make_event("event-gui-02", 1)),
        )

        bundle = create_desktop_application(
            service=service,
            show=False,
            enable_tray=False,
        )
        bundle.window.resize(1024, 720)
        bundle.window.show()
        QApplication.processEvents()

        self.assertEqual(bundle.window.minimumWidth(), 1024)
        self.assertEqual(bundle.window.minimumHeight(), 720)
        self.assertEqual(bundle.window.findChild(QLabel, "todayValue").text(), "4")
        self.assertEqual(
            bundle.window.findChild(QWidget, "trendChart").property("pointCount"),
            15,
        )
        self.assertEqual(
            bundle.window.findChild(QTableWidget, "eventsTable").rowCount(),
            2,
        )
        events_table = bundle.window.findChild(QTableWidget, "eventsTable")
        self.assertEqual(
            [
                events_table.horizontalHeaderItem(column).text()
                for column in range(events_table.columnCount())
            ],
            ["时间", "风险", "状态", "来源", "本地事件 ID"],
        )
        event_id = events_table.item(0, 4).text()
        self.assertGreaterEqual(events_table.columnWidth(4), 160)
        self.assertNotIn("UTC", events_table.item(0, 0).text())
        if QFontDatabase.families():
            for column in range(events_table.columnCount()):
                value = events_table.item(0, column).text()
                required_width = QFontMetrics(
                    events_table.item(0, column).font()
                ).horizontalAdvance(value) + 16
                self.assertGreaterEqual(
                    events_table.columnWidth(column),
                    required_width,
                    f"column {column} elides {value!r}",
                )
        rendered = bundle.window.grab()
        if QApplication.platformName() == "offscreen":
            self.assertEqual((rendered.width(), rendered.height()), (1024, 720))
        else:
            self.assertEqual(
                (bundle.window.width(), bundle.window.height()),
                (1024, 720),
            )
            self.assertGreaterEqual(rendered.width(), 1024)
            self.assertGreaterEqual(rendered.height(), 720)
        self.assertFalse(rendered.isNull())
        bundle.window._select_event_row(0, 0)
        QApplication.processEvents()
        self.assertEqual("确认正常", bundle.window.findChild(QPushButton, "confirmBenignButton").text())
        self.assertEqual("确认钓鱼", bundle.window.findChild(QPushButton, "confirmPhishingButton").text())
        detail_text = " ".join(label.text() for label in bundle.window.findChildren(QLabel))
        self.assertNotIn("FeatureVector", detail_text)
        self.assertNotIn("fingerprint", detail_text.casefold())
        self.assertNotIn("规则证据", detail_text)

        bundle.lifecycle.quit_application()
        QApplication.processEvents()

    def test_navigation_and_window_close_use_hide_to_tray_lifecycle(self):
        from test_desktop_presenter import (
            PagingConsoleService,
            make_dashboard,
        )
        from shielddome_endpoint.console_models import (
            ConsoleOperationResult,
            ConsoleStatusCode,
        )
        from shielddome_endpoint.desktop_qt import create_desktop_application

        service = PagingConsoleService(
            ConsoleOperationResult(
                ConsoleStatusCode.SUCCESS,
                make_dashboard(today_count=0),
            ),
            (),
        )
        bundle = create_desktop_application(
            service=service,
            show=False,
            enable_tray=False,
        )
        bundle.window.show()
        QApplication.processEvents()

        notice = bundle.window.findChild(QWidget, "noticePanel")
        self.assertTrue(notice.isVisible())
        self.assertEqual(
            bundle.window.findChild(QLabel, "noticeTitle").text(),
            "暂无本地检测记录",
        )

        bundle.window.findChild(QPushButton, "eventsNav").click()
        QApplication.processEvents()
        self.assertEqual(
            bundle.window.findChild(QStackedWidget, "contentPages").currentIndex(),
            1,
        )

        bundle.window.close()
        QApplication.processEvents()
        self.assertFalse(bundle.window.isVisible())
        self.assertFalse(bundle.lifecycle.is_quitting)

        bundle.lifecycle.show_console()
        QApplication.processEvents()
        self.assertTrue(bundle.window.isVisible())

        bundle.lifecycle.quit_application()
        QApplication.processEvents()

    def test_tray_menu_opens_hides_and_exits_the_real_qt_application(self):
        from test_desktop_presenter import PagingConsoleService, make_dashboard
        from shielddome_endpoint.console_models import (
            ConsoleOperationResult,
            ConsoleStatusCode,
        )
        from shielddome_endpoint.desktop_qt import create_desktop_application

        service = PagingConsoleService(
            ConsoleOperationResult(
                ConsoleStatusCode.SUCCESS,
                make_dashboard(today_count=0),
            ),
            (),
        )
        bundle = create_desktop_application(
            service=service,
            show=False,
            enable_tray=True,
        )
        actions = bundle.tray.contextMenu().actions()

        self.assertEqual(
            [action.text() for action in actions if not action.isSeparator()],
            ["本地防护正常", "打开控制台", "隐藏控制台", "退出"],
        )
        actions[2].trigger()
        QApplication.processEvents()
        self.assertTrue(bundle.window.isVisible())
        actions[3].trigger()
        QApplication.processEvents()
        self.assertFalse(bundle.window.isVisible())
        actions[5].trigger()
        QApplication.processEvents()
        self.assertTrue(bundle.lifecycle.is_quitting)


if __name__ == "__main__":
    unittest.main()
