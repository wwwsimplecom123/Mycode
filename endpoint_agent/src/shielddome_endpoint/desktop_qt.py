from dataclasses import dataclass
import sys

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import (
    QAction,
    QColor,
    QFont,
    QIcon,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QButtonGroup,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QInputDialog,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QStackedWidget,
    QStyle,
    QSystemTrayIcon,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .desktop_lifecycle import CloseDisposition, DesktopLifecycle
from .desktop_presenter import (
    ChartValue,
    DesktopConsoleState,
    DesktopLoadState,
    PersonalConsolePresenter,
    DELETE_ALL_CONFIRMATION_TEXT,
)
from .startup_manager import StartupStatusCode, WindowsStartupManager


GRAPHITE = "#202A2F"
PAPER = "#F4F5F2"
INK = "#172126"
MUTED = "#647177"
RULE = "#D4D9D7"
SIGNAL_TEAL = "#2B7772"
WARNING = "#B46B2A"
CRITICAL = "#A23A36"


def _clear_layout(layout: QVBoxLayout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.deleteLater()


class TrendChart(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._values: tuple[ChartValue, ...] = ()
        self.setObjectName("trendChart")
        self.setMinimumHeight(138)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setProperty("pointCount", 0)

    def set_values(self, values: tuple[ChartValue, ...]) -> None:
        self._values = tuple(values)
        self.setProperty("pointCount", len(self._values))
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.fillRect(self.rect(), QColor(PAPER))
        plot = QRectF(40, 10, max(1, self.width() - 52), max(1, self.height() - 36))
        painter.setPen(QPen(QColor(RULE), 1))
        for fraction in (0.0, 0.5, 1.0):
            y = plot.bottom() - plot.height() * fraction
            painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
        if not self._values:
            painter.setPen(QColor(MUTED))
            painter.drawText(plot, Qt.AlignmentFlag.AlignCenter, "正在读取 15 天趋势")
            return
        maximum = max(item.value for item in self._values)
        if maximum == 0:
            painter.setPen(QColor(MUTED))
            painter.drawText(plot, Qt.AlignmentFlag.AlignCenter, "最近 15 天暂无检测记录")
        denominator = max(1, maximum)
        step = plot.width() / max(1, len(self._values) - 1)
        points = tuple(
            QPointF(
                plot.left() + index * step,
                plot.bottom() - (item.value / denominator) * (plot.height() - 8),
            )
            for index, item in enumerate(self._values)
        )
        path = QPainterPath(points[0])
        for point in points[1:]:
            path.lineTo(point)
        painter.setPen(QPen(QColor(SIGNAL_TEAL), 2))
        painter.drawPath(path)
        painter.setBrush(QColor(PAPER))
        for point in points:
            painter.drawEllipse(point, 2.8, 2.8)
        painter.setFont(QFont("Cascadia Mono", 8))
        painter.setPen(QColor(MUTED))
        label_indexes = (0, 4, 9, 14) if len(self._values) == 15 else (0, len(self._values) - 1)
        for index in dict.fromkeys(label_indexes):
            if 0 <= index < len(self._values):
                x = plot.left() + index * step
                if index == 0:
                    label_rect = QRectF(x, plot.bottom() + 7, 52, 18)
                    alignment = Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
                elif index == len(self._values) - 1:
                    label_rect = QRectF(x - 52, plot.bottom() + 7, 52, 18)
                    alignment = Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
                else:
                    label_rect = QRectF(x - 26, plot.bottom() + 7, 52, 18)
                    alignment = Qt.AlignmentFlag.AlignCenter
                painter.drawText(
                    label_rect,
                    alignment,
                    self._values[index].label,
                )


class DistributionChart(QWidget):
    def __init__(self, *, object_name: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._values: tuple[ChartValue, ...] = ()
        self.setObjectName(object_name)
        self.setMinimumHeight(102)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    def set_values(self, values: tuple[ChartValue, ...]) -> None:
        self._values = tuple(values)
        self.update()

    @staticmethod
    def _bar_color(key: str) -> QColor:
        return QColor(
            {
                "low": "#6F8D7A",
                "medium": WARNING,
                "high": "#B64F43",
                "critical": "#7E2730",
            }.get(key, SIGNAL_TEAL)
        )

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.fillRect(self.rect(), QColor(PAPER))
        if not self._values:
            painter.setPen(QColor(MUTED))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "暂无分布数据")
            return
        maximum = max(1, max(item.value for item in self._values))
        row_height = max(18.0, self.height() / max(1, len(self._values)))
        label_width = min(92.0, self.width() * 0.34)
        value_width = 28.0
        bar_left = label_width + 8
        bar_width = max(20.0, self.width() - bar_left - value_width - 8)
        painter.setFont(QFont("Segoe UI", 9))
        for index, item in enumerate(self._values):
            y = index * row_height + 4
            center_y = y + row_height / 2 - 2
            painter.setPen(QColor(INK))
            painter.drawText(
                QRectF(0, y, label_width, row_height - 6),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                item.label,
            )
            background = QRectF(bar_left, center_y - 4, bar_width, 8)
            painter.fillRect(background, QColor("#E1E5E3"))
            fill = QRectF(
                bar_left,
                center_y - 4,
                bar_width * item.value / maximum,
                8,
            )
            painter.fillRect(fill, self._bar_color(item.key))
            painter.setFont(QFont("Cascadia Mono", 9))
            painter.drawText(
                QRectF(bar_left + bar_width + 6, y, value_width, row_height - 6),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                str(item.value),
            )
            painter.setFont(QFont("Segoe UI", 9))


class QtDialogAdapter:
    def choose_diagnostic_path(self, parent) -> str | None:
        path, _ = QFileDialog.getSaveFileName(parent, "导出诊断包", "", "ZIP 文件 (*.zip)")
        return path or None

    def confirm(self, parent, title: str, text: str) -> bool:
        return QMessageBox.question(parent, title, text, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No) is QMessageBox.StandardButton.Yes

    def confirmation_text(self, parent, title: str, text: str) -> str | None:
        value, accepted = QInputDialog.getText(parent, title, text)
        return value if accepted else None


class ShieldDomeMainWindow(QMainWindow):
    statusChanged = Signal(str, str)

    def __init__(self, presenter: PersonalConsolePresenter, *, startup_manager: object, dialogs: object) -> None:
        super().__init__()
        self._presenter = presenter
        self._startup_manager = startup_manager
        self._dialogs = dialogs
        self._lifecycle: DesktopLifecycle | None = None
        self._rendering = False
        self.setObjectName("shieldDomeMainWindow")
        self.setWindowTitle("ShieldDome Endpoint Agent")
        self.setMinimumSize(1024, 720)
        self.resize(1180, 740)
        self.setWindowIcon(create_shield_icon())
        self._build_interface()
        self._apply_style()
        self.refresh_dashboard()

    def set_lifecycle(self, lifecycle: DesktopLifecycle) -> None:
        self._lifecycle = lifecycle

    def _build_interface(self) -> None:
        root = QWidget()
        root.setObjectName("rootSurface")
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        self._pages = QStackedWidget()
        self._pages.setObjectName("contentPages")
        root_layout.addWidget(self._build_navigation())
        self._pages.addWidget(self._build_overview_page())
        self._pages.addWidget(self._build_events_page())
        self._pages.addWidget(self._build_examples_page())
        self._pages.addWidget(self._build_local_data_page())
        root_layout.addWidget(self._pages, 1)
        self.setCentralWidget(root)

    def _build_navigation(self) -> QWidget:
        navigation = QFrame()
        navigation.setObjectName("navigationRail")
        navigation.setFixedWidth(188)
        layout = QVBoxLayout(navigation)
        layout.setContentsMargins(20, 24, 20, 18)
        layout.setSpacing(8)
        brand = QLabel("SHIELDDOME")
        brand.setObjectName("brandLabel")
        subtitle = QLabel("ENDPOINT  /  本地防护")
        subtitle.setObjectName("brandSubtitle")
        layout.addWidget(brand)
        layout.addWidget(subtitle)
        layout.addSpacing(28)
        self._rail_status = QLabel("●  正在读取本地状态")
        self._rail_status.setObjectName("railStatus")
        self._rail_status.setWordWrap(True)
        layout.addWidget(self._rail_status)
        layout.addSpacing(24)
        self._nav_group = QButtonGroup(self)
        self._nav_group.setExclusive(True)
        self._overview_nav = QPushButton("安全概览")
        self._overview_nav.setObjectName("overviewNav")
        self._events_nav = QPushButton("最近事件")
        self._events_nav.setObjectName("eventsNav")
        self._examples_nav = QPushButton("已确认样本")
        self._examples_nav.setObjectName("examplesNav")
        self._local_data_nav = QPushButton("本地数据")
        self._local_data_nav.setObjectName("localDataNav")
        for index, button in enumerate((self._overview_nav, self._events_nav, self._examples_nav, self._local_data_nav)):
            button.setCheckable(True)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            self._nav_group.addButton(button, index)
            layout.addWidget(button)
        self._overview_nav.setChecked(True)
        self._nav_group.idClicked.connect(self._pages.setCurrentIndex)
        layout.addStretch(1)
        privacy = QLabel("只读控制台\n数据仅保留在当前用户设备")
        privacy.setObjectName("privacyLabel")
        privacy.setWordWrap(True)
        layout.addWidget(privacy)
        return navigation

    def _page_header(self, title: str, subtitle: str) -> tuple[QWidget, QLabel]:
        header = QWidget()
        header.setObjectName("pageHeader")
        layout = QHBoxLayout(header)
        layout.setContentsMargins(0, 0, 0, 12)
        text = QVBoxLayout()
        text.setSpacing(2)
        heading = QLabel(title)
        heading.setObjectName("pageTitle")
        caption = QLabel(subtitle)
        caption.setObjectName("pageSubtitle")
        text.addWidget(heading)
        text.addWidget(caption)
        layout.addLayout(text)
        layout.addStretch(1)
        refresh = QPushButton("刷新")
        refresh.setObjectName("refreshButton")
        refresh.setCursor(Qt.CursorShape.PointingHandCursor)
        refresh.clicked.connect(self.refresh_dashboard)
        layout.addWidget(refresh)
        return header, caption

    def _build_overview_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("overviewPage")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 18, 24, 16)
        layout.setSpacing(10)
        header, self._overview_subtitle = self._page_header(
            "个人安全概览",
            "当前 Windows 用户 · 最近 15 天本地加密证据",
        )
        layout.addWidget(header)
        layout.addWidget(self._build_metric_band())
        self._notice = QFrame()
        self._notice.setObjectName("noticePanel")
        notice_layout = QHBoxLayout(self._notice)
        notice_layout.setContentsMargins(12, 8, 12, 8)
        self._notice_title = QLabel()
        self._notice_title.setObjectName("noticeTitle")
        self._notice_body = QLabel()
        self._notice_body.setObjectName("noticeBody")
        self._notice_body.setWordWrap(True)
        notice_layout.addWidget(self._notice_title)
        notice_layout.addWidget(self._notice_body, 1)
        layout.addWidget(self._notice)
        charts = QHBoxLayout()
        charts.setSpacing(14)
        trend_section, self._trend_chart = self._chart_section(
            "15 天证据轨迹",
            "每日检测数量 · 缺失日期补零",
            TrendChart(),
        )
        charts.addWidget(trend_section, 3)
        distributions = QFrame()
        distributions.setObjectName("distributionSection")
        distribution_layout = QVBoxLayout(distributions)
        distribution_layout.setContentsMargins(0, 0, 0, 0)
        distribution_layout.setSpacing(6)
        risk_heading = QLabel("风险等级")
        risk_heading.setObjectName("sectionTitle")
        self._risk_chart = DistributionChart(object_name="riskChart")
        source_heading = QLabel("检测来源")
        source_heading.setObjectName("sectionTitle")
        self._source_chart = DistributionChart(object_name="sourceChart")
        distribution_layout.addWidget(risk_heading)
        distribution_layout.addWidget(self._risk_chart, 1)
        distribution_layout.addWidget(source_heading)
        distribution_layout.addWidget(self._source_chart, 1)
        charts.addWidget(distributions, 2)
        layout.addLayout(charts, 3)
        recent_header = QHBoxLayout()
        recent_title = QLabel("最近事件")
        recent_title.setObjectName("sectionTitle")
        recent_header.addWidget(recent_title)
        recent_header.addStretch(1)
        open_events = QPushButton("查看全部")
        open_events.setObjectName("textButton")
        open_events.clicked.connect(lambda: self._events_nav.click())
        recent_header.addWidget(open_events)
        layout.addLayout(recent_header)
        self._overview_table = self._create_event_table("overviewEventsTable", 4)
        layout.addWidget(self._overview_table, 2)
        return page

    def _build_examples_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("examplesPage")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 18, 24, 16)
        layout.setSpacing(10)
        header, _ = self._page_header("已确认样本", "只显示脱敏标签、来源、确认时间与冲突状态")
        layout.addWidget(header)
        toolbar = QHBoxLayout()
        toolbar.addWidget(QLabel("标签"))
        self._example_filter = QComboBox()
        self._example_filter.setObjectName("exampleFilter")
        self._example_filter.addItem("全部", None)
        self._example_filter.addItem("正常", "benign")
        self._example_filter.addItem("钓鱼", "phishing")
        self._example_filter.currentIndexChanged.connect(self._refresh_examples)
        toolbar.addWidget(self._example_filter)
        toolbar.addStretch(1)
        self._clear_examples_button = QPushButton("清空全部样本")
        self._clear_examples_button.setObjectName("dangerButton")
        self._clear_examples_button.clicked.connect(self._clear_examples)
        toolbar.addWidget(self._clear_examples_button)
        layout.addLayout(toolbar)
        self._examples_table = QTableWidget(0, 5)
        self._examples_table.setObjectName("examplesTable")
        self._examples_table.setHorizontalHeaderLabels(("确认时间", "标签", "来源", "冲突", "操作"))
        self._examples_table.verticalHeader().setVisible(False)
        self._examples_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._examples_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self._examples_table, 1)
        paging = QHBoxLayout()
        self._examples_previous = QPushButton("上一页")
        self._examples_previous.clicked.connect(lambda: self._render_examples(self._presenter.previous_examples()))
        self._examples_page_label = QLabel("第 1 / 1 页")
        self._examples_next = QPushButton("下一页")
        self._examples_next.clicked.connect(lambda: self._render_examples(self._presenter.next_examples()))
        paging.addWidget(self._examples_previous); paging.addStretch(1); paging.addWidget(self._examples_page_label); paging.addStretch(1); paging.addWidget(self._examples_next)
        layout.addLayout(paging)
        self._examples_status = QLabel("本地样本仅用于有限校准")
        self._examples_status.setObjectName("operationStatus")
        layout.addWidget(self._examples_status)
        return page

    def _build_local_data_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("localDataPage")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 18, 24, 16)
        layout.setSpacing(0)
        header, _ = self._page_header("本地数据", "当前 Windows 用户 · 所有操作均在本机完成")
        layout.addWidget(header)
        self._startup_status = QLabel()
        self._startup_status.setObjectName("startupStatus")
        self._startup_button = QPushButton("启用开机启动")
        self._startup_button.setObjectName("startupToggle")
        self._startup_button.clicked.connect(self._toggle_startup)
        layout.addWidget(self._settings_row("开机启动", "登录当前用户后启动本地防护", self._startup_status, self._startup_button))
        self._diagnostic_status = QLabel("由你选择保存位置，不会自动打开或上传")
        self._diagnostic_button = QPushButton("导出诊断包")
        self._diagnostic_button.setObjectName("diagnosticExportButton")
        self._diagnostic_button.clicked.connect(self._export_diagnostics)
        layout.addWidget(self._settings_row("诊断包", "只包含脱敏聚合与兼容性信息", self._diagnostic_status, self._diagnostic_button))
        self._delete_all_status = QLabel("删除证据、样本、密钥与诊断临时文件")
        self._delete_all_button = QPushButton("删除全部本地数据")
        self._delete_all_button.setObjectName("dangerButton")
        self._delete_all_button.clicked.connect(self._delete_all_data)
        danger_row = self._settings_row("危险操作", "不影响应用程序文件和浏览器插件", self._delete_all_status, self._delete_all_button)
        danger_row.setObjectName("dangerZone")
        layout.addWidget(danger_row)
        layout.addStretch(1)
        self._render_startup_status()
        return page

    def _settings_row(self, title: str, detail: str, status: QLabel, action: QPushButton) -> QFrame:
        row = QFrame()
        row.setObjectName("settingsRow")
        row.setMinimumHeight(116)
        grid = QGridLayout(row)
        heading = QLabel(title); heading.setObjectName("sectionTitle")
        caption = QLabel(detail); caption.setObjectName("sectionCaption")
        status.setWordWrap(True)
        grid.addWidget(heading, 0, 0); grid.addWidget(caption, 1, 0); grid.addWidget(status, 2, 0)
        grid.addWidget(action, 0, 1, 3, 1, Qt.AlignmentFlag.AlignVCenter)
        grid.setColumnStretch(0, 1)
        return row

    def _refresh_examples(self) -> None:
        self._render_examples(self._presenter.refresh_examples(self._example_filter.currentData()))

    def _render_examples(self, state: DesktopConsoleState) -> None:
        rows = state.examples.rows
        self._examples_table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            for column, text in enumerate((row.confirmed_at_text, row.label_text, row.source_text, row.conflict_text)):
                self._examples_table.setItem(index, column, QTableWidgetItem(text))
            button = QPushButton("删除")
            button.setProperty("exampleId", row.example_id)
            button.clicked.connect(lambda checked=False, eid=row.example_id: self._delete_example(eid))
            self._examples_table.setCellWidget(index, 4, button)
        self._examples_page_label.setText(f"第 {state.examples.page_number} / {state.examples.total_pages} 页")
        self._examples_previous.setEnabled(state.examples.can_previous)
        self._examples_next.setEnabled(state.examples.can_next)
        self._examples_status.setText(state.operation_title or state.examples.empty_message or "样本库已加载")

    def _delete_example(self, example_id: str) -> None:
        confirmed = self._dialogs.confirm(self, "删除样本", "删除这条已确认样本？此操作不会删除邮件。")
        self._render_examples(self._presenter.delete_example(example_id, confirmed=confirmed))

    def _clear_examples(self) -> None:
        confirmed = self._dialogs.confirm(self, "清空全部样本", "删除 Confirmed Example Library 中的全部本地样本？")
        self._render_examples(self._presenter.clear_examples(confirmed=confirmed))

    def _render_startup_status(self) -> None:
        status = self._startup_manager.status()
        text = {StartupStatusCode.ENABLED: "已启用", StartupStatusCode.DISABLED: "未启用", StartupStatusCode.UNAVAILABLE: "安装版提供开机启动", StartupStatusCode.FOREIGN_ENTRY: "同名启动项不属于 ShieldDome，未更改", StartupStatusCode.FAILED: "无法读取开机启动状态"}[status.code]
        self._startup_status.setText(text)
        self._startup_button.setText("停用开机启动" if status.enabled else "启用开机启动")
        self._startup_button.setEnabled(status.code in {StartupStatusCode.ENABLED, StartupStatusCode.DISABLED})

    def _toggle_startup(self) -> None:
        current = self._startup_manager.status()
        self._startup_manager.uninstall() if current.enabled else self._startup_manager.install()
        self._render_startup_status()

    def _export_diagnostics(self) -> None:
        path = self._dialogs.choose_diagnostic_path(self)
        if not path:
            self._diagnostic_status.setText("已取消，未创建诊断包")
            return
        if not self._dialogs.confirm(self, "导出诊断包", "将脱敏诊断包保存到你选择的位置？"):
            self._diagnostic_status.setText("已取消，未创建诊断包")
            return
        state = self._presenter.export_diagnostics(path, confirmed=True)
        if state.operation_title == "目标文件已存在" and self._dialogs.confirm(self, "覆盖现有文件", "目标文件已存在。确认覆盖？"):
            state = self._presenter.export_diagnostics(path, confirmed=True, overwrite=True)
        self._diagnostic_status.setText(state.operation_title or "诊断导出状态不可用")

    def _delete_all_data(self) -> None:
        if not self._dialogs.confirm(self, "删除全部本地数据", "将删除本地检测证据、已确认样本、加密密钥和诊断临时文件。应用程序和浏览器插件不会删除。继续？"):
            self._delete_all_status.setText("已取消，本地数据未更改")
            return
        value = self._dialogs.confirmation_text(self, "再次确认", f"请输入：{DELETE_ALL_CONFIRMATION_TEXT}")
        state = self._presenter.delete_all_local_data(first_confirmed=True, confirmation_text=value or "")
        self._delete_all_status.setText(state.operation_title or "本地数据操作已完成")
        self.render_state(state)
        self._render_examples(state)

    def _build_metric_band(self) -> QFrame:
        band = QFrame()
        band.setObjectName("metricBand")
        layout = QGridLayout(band)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setHorizontalSpacing(0)
        labels = (
            ("今日检测", "todayValue"),
            ("模型拒判", "abstentionValue"),
            ("模型故障", "failureValue"),
            ("纯规则降级", "degradationValue"),
        )
        self._metric_values = {}
        for column, (label_text, object_name) in enumerate(labels):
            cell = QFrame()
            cell.setObjectName("metricCell")
            cell_layout = QVBoxLayout(cell)
            cell_layout.setContentsMargins(14, 10, 14, 9)
            cell_layout.setSpacing(0)
            value = QLabel("—")
            value.setObjectName(object_name)
            value.setProperty("metricValue", True)
            label = QLabel(label_text)
            label.setObjectName("metricLabel")
            cell_layout.addWidget(value)
            cell_layout.addWidget(label)
            layout.addWidget(cell, 0, column)
            layout.setColumnStretch(column, 1)
            self._metric_values[object_name] = value
        return band

    def _chart_section(self, title: str, subtitle: str, chart: QWidget):
        section = QFrame()
        section.setObjectName("chartSection")
        layout = QVBoxLayout(section)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        heading = QLabel(title)
        heading.setObjectName("sectionTitle")
        caption = QLabel(subtitle)
        caption.setObjectName("sectionCaption")
        layout.addWidget(heading)
        layout.addWidget(caption)
        layout.addWidget(chart, 1)
        return section, chart

    def _build_events_page(self) -> QWidget:
        page = QWidget()
        page.setObjectName("eventsPage")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 18, 24, 16)
        layout.setSpacing(10)
        header, self._events_subtitle = self._page_header(
            "最近事件",
            "脱敏证据台账 · 只显示本地事件标识和结构化结论",
        )
        layout.addWidget(header)
        body = QHBoxLayout()
        body.setSpacing(16)
        ledger = QFrame()
        ledger.setObjectName("ledgerPanel")
        ledger_layout = QVBoxLayout(ledger)
        ledger_layout.setContentsMargins(0, 0, 0, 0)
        ledger_layout.setSpacing(8)
        self._events_table = self._create_event_table("eventsTable", 10)
        self._events_table.cellClicked.connect(self._select_event_row)
        ledger_layout.addWidget(self._events_table, 1)
        paging = QHBoxLayout()
        self._previous_button = QPushButton("上一页")
        self._previous_button.setObjectName("previousPageButton")
        self._previous_button.clicked.connect(self._previous_events)
        self._page_label = QLabel("第 1 / 1 页")
        self._page_label.setObjectName("pageLabel")
        self._next_button = QPushButton("下一页")
        self._next_button.setObjectName("nextPageButton")
        self._next_button.clicked.connect(self._next_events)
        paging.addWidget(self._previous_button)
        paging.addStretch(1)
        paging.addWidget(self._page_label)
        paging.addStretch(1)
        paging.addWidget(self._next_button)
        ledger_layout.addLayout(paging)
        body.addWidget(ledger, 5)
        detail = QFrame()
        detail.setObjectName("detailPanel")
        detail.setMinimumWidth(270)
        detail.setMaximumWidth(340)
        detail_layout = QVBoxLayout(detail)
        detail_layout.setContentsMargins(16, 14, 16, 14)
        detail_layout.setSpacing(8)
        detail_title = QLabel("事件详情")
        detail_title.setObjectName("sectionTitle")
        self._detail_hint = QLabel("选择一条事件查看脱敏详情")
        self._detail_hint.setObjectName("detailHint")
        self._detail_hint.setWordWrap(True)
        self._detail_content = QWidget()
        self._detail_layout = QVBoxLayout(self._detail_content)
        self._detail_layout.setContentsMargins(0, 4, 0, 0)
        self._detail_layout.setSpacing(6)
        detail_layout.addWidget(detail_title)
        detail_layout.addWidget(self._detail_hint)
        detail_layout.addWidget(self._detail_content, 1)
        body.addWidget(detail, 2)
        layout.addLayout(body, 1)
        self._footer_status = QLabel("本地只读 · 不连接网络")
        self._footer_status.setObjectName("footerStatus")
        layout.addWidget(self._footer_status)
        return page

    def _create_event_table(self, object_name: str, rows: int) -> QTableWidget:
        table = QTableWidget(0, 5)
        table.setObjectName(object_name)
        table.setHorizontalHeaderLabels(
            ("时间", "风险", "状态", "来源", "本地事件 ID")
        )
        table.verticalHeader().setVisible(False)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(False)
        table.setShowGrid(False)
        table.setWordWrap(False)
        table.verticalHeader().setDefaultSectionSize(30)
        header = table.horizontalHeader()
        fixed_widths = (96, 48, 76, 64)
        for column, width in enumerate(fixed_widths):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.Fixed)
            table.setColumnWidth(column, width)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        table.setMinimumHeight(rows * 30 + 34)
        return table

    def _apply_style(self) -> None:
        self.setStyleSheet(
            f"""
            QWidget {{ color: {INK}; font-family: 'Segoe UI'; font-size: 13px; }}
            #rootSurface, #overviewPage, #eventsPage {{ background: {PAPER}; }}
            #navigationRail {{ background: {GRAPHITE}; border: none; }}
            #brandLabel {{ color: #FFFFFF; font-family: 'Segoe UI Variable Display'; font-size: 17px; font-weight: 700; letter-spacing: 2px; }}
            #brandSubtitle {{ color: #AEBAB9; font-family: 'Cascadia Mono'; font-size: 9px; }}
            #railStatus {{ color: #CEE5DF; font-size: 11px; padding: 8px 0; border-top: 1px solid #3A474B; border-bottom: 1px solid #3A474B; }}
            #privacyLabel {{ color: #91A09F; font-size: 10px; line-height: 1.3; }}
            #navigationRail QPushButton {{ color: #C8D0CF; text-align: left; border: 0; padding: 10px 12px; border-radius: 3px; background: transparent; }}
            #navigationRail QPushButton:hover {{ background: #2A373C; color: white; }}
            #navigationRail QPushButton:checked {{ background: #34454A; color: white; border-left: 3px solid #65A59D; padding-left: 9px; }}
            #pageTitle {{ font-family: 'Segoe UI Variable Display'; font-size: 22px; font-weight: 650; }}
            #pageSubtitle, #sectionCaption, #footerStatus {{ color: {MUTED}; font-size: 11px; }}
            QPushButton#refreshButton, QPushButton#previousPageButton, QPushButton#nextPageButton {{ border: 1px solid #B8C0BD; background: #FFFFFF; padding: 6px 14px; border-radius: 3px; }}
            QPushButton#refreshButton:hover, QPushButton#previousPageButton:hover, QPushButton#nextPageButton:hover {{ border-color: {SIGNAL_TEAL}; color: {SIGNAL_TEAL}; }}
            QPushButton:focus {{ outline: none; border: 2px solid {SIGNAL_TEAL}; }}
            QPushButton:disabled {{ color: #9FA7A4; background: #ECEFEC; border-color: #D9DDDA; }}
            QPushButton#dangerButton {{ color: white; background: {CRITICAL}; border: 1px solid #842E2A; padding: 7px 14px; border-radius: 3px; }}
            #settingsRow {{ border-top: 1px solid {RULE}; background: transparent; }}
            #dangerZone {{ border-top: 2px solid {CRITICAL}; }}
            #operationStatus {{ color: {MUTED}; }}
            #metricBand {{ border-top: 1px solid {RULE}; border-bottom: 1px solid {RULE}; background: #F8F9F7; }}
            #metricCell {{ border-right: 1px solid {RULE}; }}
            QLabel[metricValue='true'] {{ font-family: 'Cascadia Mono'; font-size: 24px; font-weight: 600; color: {INK}; }}
            #metricLabel {{ color: {MUTED}; font-size: 11px; }}
            #noticePanel {{ border-left: 3px solid {WARNING}; background: #F1EEE7; }}
            #noticeTitle {{ font-weight: 600; color: #74471F; }}
            #noticeBody {{ color: #6C5C4E; font-size: 11px; }}
            #sectionTitle {{ font-size: 13px; font-weight: 650; }}
            QPushButton#textButton {{ border: 0; background: transparent; color: {SIGNAL_TEAL}; padding: 2px 4px; }}
            QTableWidget {{ background: transparent; border: 1px solid {RULE}; selection-background-color: #DCEAE6; selection-color: {INK}; }}
            QHeaderView::section {{ background: #E8EBE8; color: #4E5B60; border: 0; border-bottom: 1px solid #C9CFCC; padding: 6px; font-size: 10px; font-weight: 600; }}
            QTableWidget::item {{ border-bottom: 1px solid #E1E5E2; padding: 4px 6px; }}
            #detailPanel {{ background: #ECEFED; border-left: 1px solid #CCD2CF; }}
            #detailHint {{ color: {MUTED}; font-size: 11px; }}
            #detailPanel QLabel[detailValue='true'] {{ font-family: 'Cascadia Mono'; font-size: 11px; color: {INK}; }}
            #pageLabel {{ color: {MUTED}; font-family: 'Cascadia Mono'; font-size: 11px; }}
            """
        )

    def refresh_dashboard(self) -> None:
        if self._rendering:
            return
        self._rendering = True
        try:
            self._set_controls_enabled(False)
            self._notice.show()
            self._notice_title.setText("正在读取本地状态")
            self._notice_body.setText("只读取当前用户的本地加密记录。")
            QApplication.processEvents()
            self.render_state(self._presenter.refresh())
        finally:
            self._set_controls_enabled(True)
            self._render_startup_status()
            self._rendering = False

    def _set_controls_enabled(self, enabled: bool) -> None:
        for button in self.findChildren(QPushButton):
            button.setEnabled(enabled)

    def render_state(self, state: DesktopConsoleState) -> None:
        self._metric_values["todayValue"].setText(state.today_count)
        self._metric_values["abstentionValue"].setText(state.model_abstention_count)
        self._metric_values["failureValue"].setText(state.model_failure_count)
        self._metric_values["degradationValue"].setText(
            state.rules_only_degradation_count
        )
        self._trend_chart.set_values(state.trend)
        self._risk_chart.set_values(state.risk_distribution)
        self._source_chart.set_values(state.source_distribution)
        self._rail_status.setText(f"●  {state.agent_status.title}\n{state.agent_status.detail}")
        self._overview_subtitle.setText(
            f"{state.timezone_text} · 更新于 {state.generated_at_text}"
        )
        self._footer_status.setText(
            f"{state.agent_status.title} · 本地只读 · 不连接网络"
        )
        self._notice.setVisible(state.notice_title is not None)
        self._notice_title.setText(state.notice_title or "")
        self._notice_body.setText(state.notice_body or "")
        self._populate_table(self._overview_table, state.events.rows[:4])
        self._populate_table(self._events_table, state.events.rows)
        self._page_label.setText(
            f"第 {state.events.page_number} / {state.events.total_pages} 页"
        )
        self._previous_button.setEnabled(state.events.can_previous)
        self._next_button.setEnabled(state.events.can_next)
        self._render_detail(state)
        self.statusChanged.emit(state.agent_status.title, state.agent_status.detail)

    def _populate_table(self, table: QTableWidget, rows: tuple) -> None:
        table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            values = (
                row.detected_at_text,
                row.risk_label,
                row.detection_status_text,
                row.source_text,
                row.local_event_id,
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column in (0, 4):
                    item.setFont(QFont("Cascadia Mono", 9))
                if column == 1:
                    item.setForeground(
                        QColor(
                            {
                                "low": "#557363",
                                "medium": WARNING,
                                "high": "#A54037",
                                "critical": CRITICAL,
                            }[row.risk_key]
                        )
                    )
                item.setData(Qt.ItemDataRole.UserRole, row.local_event_id)
                table.setItem(row_index, column, item)

    def _render_detail(self, state: DesktopConsoleState) -> None:
        _clear_layout(self._detail_layout)
        if state.detail is None:
            self._detail_hint.show()
            return
        self._detail_hint.hide()
        detail = state.detail
        rows = (
            ("本地事件 ID", detail.local_event_id),
            ("检测时间", detail.detected_at_text),
            ("风险等级", detail.risk_label),
            ("检测状态", detail.detection_status_text),
            ("操作建议", detail.generic_action_text),
            ("检测来源", detail.source_text),
            ("错误代码", detail.error_code_text),
        )
        for label_text, value_text in rows:
            label = QLabel(label_text)
            label.setObjectName("detailFieldLabel")
            value = QLabel(value_text)
            value.setProperty("detailValue", True)
            value.setWordWrap(True)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self._detail_layout.addWidget(label)
            self._detail_layout.addWidget(value)
        actions = QHBoxLayout()
        benign = QPushButton("确认正常")
        benign.setObjectName("confirmBenignButton")
        phishing = QPushButton("确认钓鱼")
        phishing.setObjectName("confirmPhishingButton")
        benign.clicked.connect(lambda: self._confirm_selected_event(detail.local_event_id, False))
        phishing.clicked.connect(lambda: self._confirm_selected_event(detail.local_event_id, True))
        actions.addWidget(benign)
        actions.addWidget(phishing)
        self._detail_layout.addLayout(actions)
        if state.operation_title:
            confirmation_status = QLabel(
                f"{state.operation_title}\n{state.operation_body or ''}"
            )
            confirmation_status.setObjectName("confirmationStatus")
            confirmation_status.setWordWrap(True)
            self._detail_layout.addWidget(confirmation_status)
        self._detail_layout.addStretch(1)

    def _confirm_selected_event(self, local_event_id: str, phishing: bool) -> None:
        label = "钓鱼" if phishing else "正常"
        confirmed = self._dialogs.confirm(
            self,
            f"确认{label}",
            f"将此事件确认标记为{label}？只保存脱敏特征，不保存邮件原文和附件。",
        )
        state = (self._presenter.confirm_event_phishing(local_event_id, confirmed=confirmed) if phishing else self._presenter.confirm_event_benign(local_event_id, confirmed=confirmed))
        self.render_state(state)
        self._render_examples(state)

    def _next_events(self) -> None:
        self.render_state(self._presenter.next_events())

    def _previous_events(self) -> None:
        self.render_state(self._presenter.previous_events())

    def _select_event_row(self, row: int, column: int) -> None:
        item = self._events_table.item(row, 0)
        if item is None:
            return
        local_event_id = item.data(Qt.ItemDataRole.UserRole)
        if isinstance(local_event_id, str):
            self.render_state(self._presenter.select_event(local_event_id))

    def closeEvent(self, event) -> None:
        if self._lifecycle is None:
            self.hide()
            event.ignore()
            return
        disposition = self._lifecycle.handle_window_close()
        if disposition is CloseDisposition.EXIT:
            event.accept()
        else:
            event.ignore()


class QtDesktopAdapter:
    def __init__(
        self,
        application: QApplication,
        window: ShieldDomeMainWindow,
        tray: QSystemTrayIcon | None,
        tray_status_action: QAction | None,
    ) -> None:
        self._application = application
        self._window = window
        self._tray = tray
        self._tray_status_action = tray_status_action

    def show_window(self) -> None:
        self._window.showNormal()
        self._window.raise_()
        self._window.activateWindow()

    def hide_window(self) -> None:
        self._window.hide()

    def hide_tray(self) -> None:
        if self._tray is not None:
            self._tray.hide()

    def quit_event_loop(self) -> None:
        self._application.quit()

    def update_tray_status(self, title: str, detail: str) -> None:
        if self._tray is None:
            return
        self._tray.setToolTip(f"ShieldDome Endpoint Agent\n{title}\n{detail}")
        if self._tray_status_action is not None:
            self._tray_status_action.setText(title)


@dataclass(frozen=True, slots=True)
class DesktopApplicationBundle:
    application: QApplication
    window: ShieldDomeMainWindow
    tray: QSystemTrayIcon | None
    presenter: PersonalConsolePresenter
    lifecycle: DesktopLifecycle
    adapter: QtDesktopAdapter


def create_shield_icon() -> QIcon:
    pixmap = QPixmap(64, 64)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    shield = QPainterPath()
    shield.moveTo(32, 5)
    shield.lineTo(54, 13)
    shield.lineTo(51, 39)
    shield.cubicTo(49, 49, 40, 56, 32, 60)
    shield.cubicTo(24, 56, 15, 49, 13, 39)
    shield.lineTo(10, 13)
    shield.closeSubpath()
    painter.fillPath(shield, QColor(SIGNAL_TEAL))
    painter.setPen(QPen(QColor("#EAF5F1"), 4, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    painter.drawLine(22, 32, 29, 39)
    painter.drawLine(29, 39, 43, 23)
    painter.end()
    return QIcon(pixmap)


def create_desktop_application(
    service: object | None = None,
    *,
    show: bool = True,
    enable_tray: bool = True,
    startup_manager: object | None = None,
    dialogs: object | None = None,
) -> DesktopApplicationBundle:
    application = QApplication.instance() or QApplication(sys.argv[:1])
    application.setApplicationName("ShieldDome Endpoint Agent")
    application.setOrganizationName("ShieldDome")
    application.setQuitOnLastWindowClosed(False)
    if service is None:
        from .console_service import PersonalConsoleService

        service = PersonalConsoleService()
    presenter = PersonalConsolePresenter(service)
    window = ShieldDomeMainWindow(
        presenter,
        startup_manager=startup_manager or WindowsStartupManager(),
        dialogs=dialogs or QtDialogAdapter(),
    )
    tray = None
    tray_status_action = None
    if enable_tray:
        tray = QSystemTrayIcon(create_shield_icon(), application)
        menu = QMenu()
        tray_status_action = QAction("正在读取本地状态", menu)
        tray_status_action.setEnabled(False)
        open_action = QAction("打开控制台", menu)
        hide_action = QAction("隐藏控制台", menu)
        quit_action = QAction("退出", menu)
        menu.addAction(tray_status_action)
        menu.addSeparator()
        menu.addAction(open_action)
        menu.addAction(hide_action)
        menu.addSeparator()
        menu.addAction(quit_action)
        tray.setContextMenu(menu)
    adapter = QtDesktopAdapter(application, window, tray, tray_status_action)
    lifecycle = DesktopLifecycle(adapter)
    window.set_lifecycle(lifecycle)
    window.statusChanged.connect(adapter.update_tray_status)
    current = presenter.state.agent_status
    adapter.update_tray_status(current.title, current.detail)
    if tray is not None:
        actions = tray.contextMenu().actions()
        actions[2].triggered.connect(lifecycle.show_console)
        actions[3].triggered.connect(lifecycle.hide_console)
        actions[5].triggered.connect(lifecycle.quit_application)
        tray.activated.connect(
            lambda reason: lifecycle.show_console()
            if reason is QSystemTrayIcon.ActivationReason.DoubleClick
            else None
        )
        tray.show()
    if show:
        lifecycle.show_console()
    return DesktopApplicationBundle(
        application=application,
        window=window,
        tray=tray,
        presenter=presenter,
        lifecycle=lifecycle,
        adapter=adapter,
    )


__all__ = [
    "DesktopApplicationBundle",
    "DistributionChart",
    "QtDesktopAdapter",
    "ShieldDomeMainWindow",
    "TrendChart",
    "create_desktop_application",
    "create_shield_icon",
]
