import os

from PySide6.QtCore import QFileInfo, QMimeData, QObject, QThread, Signal, Slot
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from .local_mail_intake import LocalMailIntakeError


_INTAKE_ERROR_TEXT = {
    "confirmation_required": "需要确认后才能开始本地检测。",
    "unsupported_file": "请选择一个有效的 EML 邮件文件。",
    "unsafe_path": "无法安全访问所选邮件文件。",
    "file_not_found": "所选邮件文件已不存在，请重新选择。",
    "file_too_large": "邮件文件超过本地检测大小限制。",
    "mime_limit_exceeded": "邮件结构超过本地安全处理限制。",
    "malformed_message": "邮件格式无法安全解析。",
    "intake_failed": "本地检测未完成，请重新选择后重试。",
}


def safe_intake_error_text(code: str) -> str:
    return _INTAKE_ERROR_TEXT.get(code, _INTAKE_ERROR_TEXT["intake_failed"])


_RISK_TEXT = {
    "low": "低风险",
    "medium": "中风险",
    "high": "高风险",
    "critical": "严重风险",
}
_DETECTION_TEXT = {
    "model_success": "模型完成",
    "model_uncertain": "模型拒判",
    "model_unavailable": "模型不可用",
    "model_timeout": "模型超时",
    "model_error": "模型故障",
    "model_invalid_output": "模型输出无效",
    "rules_only": "纯规则完成",
}
_ACTION_TEXT = {
    "continue": "可继续查看",
    "verify_sender": "核实发件人",
    "avoid_credentials": "不要提交凭据",
    "contact_security": "联系安全人员",
}


class EmlDropZone(QFrame):
    fileSelected = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setAcceptDrops(True)

    @staticmethod
    def local_eml_path(mime_data: QMimeData) -> str | None:
        if mime_data.hasHtml() or not mime_data.hasUrls():
            return None
        urls = mime_data.urls()
        if len(urls) != 1 or not urls[0].isLocalFile():
            return None
        path = os.path.normpath(urls[0].toLocalFile())
        file_info = QFileInfo(path)
        if not file_info.isFile() or file_info.suffix().casefold() != "eml":
            return None
        return path

    def dragEnterEvent(self, event) -> None:
        if self.isEnabled() and self.local_eml_path(event.mimeData()) is not None:
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event) -> None:
        path = self.local_eml_path(event.mimeData()) if self.isEnabled() else None
        if path is None:
            event.ignore()
            return
        event.acceptProposedAction()
        self.fileSelected.emit(path)


class MailIntakeWorker(QObject):
    succeeded = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, intake: object, path: str) -> None:
        super().__init__()
        self._intake = intake
        self._path: str | None = path

    @Slot()
    def run(self) -> None:
        try:
            self.succeeded.emit(
                self._intake.detect_file(self._path, confirmed_by_user=True)
            )
        except LocalMailIntakeError as error:
            self.failed.emit(error.code)
        except Exception:
            self.failed.emit("intake_failed")
        finally:
            self._path = None
            self.finished.emit()


class DesktopMailIntakePanel(QWidget):
    def __init__(
        self,
        intake: object,
        *,
        dialogs: object,
        refresh_callback,
        open_events_callback,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("mailIntakePanel")
        self._intake = intake
        self._dialogs = dialogs
        self._refresh_callback = refresh_callback
        self._open_events_callback = open_events_callback
        self._selected_path: str | None = None
        self._worker: MailIntakeWorker | None = None
        self._thread: QThread | None = None
        self._accept_callbacks = True
        self._build_interface()

    def _build_interface(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        self._drop_zone = EmlDropZone()
        self._drop_zone.setObjectName("emlDropZone")
        self._drop_zone.setMinimumHeight(132)
        self._drop_zone.setMaximumHeight(172)
        self._drop_zone.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )
        drop_layout = QHBoxLayout(self._drop_zone)
        drop_layout.setContentsMargins(22, 18, 22, 18)
        drop_text = QVBoxLayout()
        drop_text.setSpacing(4)
        title = QLabel("将一个 EML 邮件文件拖到这里")
        title.setObjectName("dropZoneTitle")
        detail = QLabel("拖入只会选择文件；确认前不会读取邮件")
        detail.setObjectName("dropZoneDetail")
        drop_text.addWidget(title)
        drop_text.addWidget(detail)
        drop_layout.addLayout(drop_text, 1)
        self._select_button = QPushButton("选择邮件文件")
        self._select_button.setObjectName("selectEmlButton")
        drop_layout.addWidget(self._select_button)
        layout.addWidget(self._drop_zone)

        state_frame = QFrame()
        state_frame.setObjectName("mailIntakeStateRegion")
        state_frame.setMinimumHeight(220)
        state_layout = QGridLayout(state_frame)
        state_layout.setContentsMargins(0, 12, 0, 12)
        state_layout.setHorizontalSpacing(28)
        state_layout.setVerticalSpacing(7)
        status_heading = QLabel("检测状态")
        status_heading.setObjectName("sectionTitle")
        self._status = QLabel("等待选择邮件文件")
        self._status.setObjectName("mailIntakeStatus")
        self._status.setProperty("mailTone", "neutral")
        self._status.setWordWrap(True)
        self._selection = QLabel("邮件路径不会保留或显示")
        self._selection.setObjectName("mailSelectionSummary")
        self._selection.setWordWrap(True)
        state_layout.addWidget(status_heading, 0, 0)
        state_layout.addWidget(self._status, 1, 0)
        state_layout.addWidget(self._selection, 2, 0)
        result_heading = QLabel("最小检测结果")
        result_heading.setObjectName("sectionTitle")
        state_layout.addWidget(result_heading, 0, 1, 1, 2)
        self._result_values = {}
        result_rows = (
            ("风险等级", "mailRiskValue"),
            ("检测状态", "mailDetectionValue"),
            ("通用建议", "mailAdviceValue"),
            ("本地事件 ID", "mailEventIdValue"),
        )
        for row, (label_text, object_name) in enumerate(result_rows, 1):
            label = QLabel(label_text)
            label.setObjectName("mailResultLabel")
            value = QLabel("—")
            value.setObjectName(object_name)
            value.setProperty("mailResultValue", True)
            value.setWordWrap(True)
            state_layout.addWidget(label, row, 1)
            state_layout.addWidget(value, row, 2)
            self._result_values[object_name] = value
        state_layout.setColumnStretch(0, 2)
        state_layout.setColumnStretch(2, 3)
        layout.addWidget(state_frame)

        actions = QHBoxLayout()
        self._open_events = QPushButton("返回最近事件")
        self._open_events.setObjectName("openRecentEventsButton")
        self._open_events.clicked.connect(self._open_events_callback)
        actions.addWidget(self._open_events)
        actions.addStretch(1)
        privacy = QLabel("仅在本机处理 · 不上传邮件 · 只保存加密结构化结果")
        privacy.setObjectName("mailIntakePrivacy")
        actions.addWidget(privacy)
        layout.addLayout(actions)
        layout.addStretch(1)

        self._drop_zone.fileSelected.connect(self.select_path)
        self._select_button.clicked.connect(self.choose_file)

    @Slot()
    def choose_file(self) -> None:
        if self._thread is not None:
            return
        path = self._dialogs.choose_eml_path(self)
        if path:
            self.select_path(path)

    @Slot(str)
    def select_path(self, path: str) -> None:
        if self._thread is not None or not isinstance(path, str) or not path:
            return
        self._selected_path = path
        self._set_status("已选择一个邮件文件", "neutral")
        self._selection.setText("等待确认后开始本地检测")
        QApplication.processEvents()
        if self._dialogs.confirm_mail_intake(self) is not True:
            self._selected_path = None
            self._set_status("已取消检测", "neutral")
            self._selection.setText("未读取邮件文件")
            return
        self._start_detection()

    def _start_detection(self) -> None:
        if self._selected_path is None or self._thread is not None:
            return
        self._set_busy(True)
        self._set_status("正在本地检测", "active")
        self._selection.setText("邮件仅在本机内存中处理")
        thread = QThread(self)
        worker = MailIntakeWorker(self._intake, self._selected_path)
        worker.moveToThread(thread)
        self._thread = thread
        self._worker = worker
        thread.started.connect(worker.run)
        worker.succeeded.connect(self._handle_success)
        worker.failed.connect(self._handle_failure)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(self._handle_thread_finished)
        thread.finished.connect(thread.deleteLater)
        thread.start()

    def _set_busy(self, busy: bool) -> None:
        self._select_button.setEnabled(not busy)
        self._drop_zone.setEnabled(not busy)
        self._drop_zone.setAcceptDrops(not busy)

    def _set_status(self, text: str, tone: str) -> None:
        self._status.setText(text)
        self._status.setProperty("mailTone", tone)
        self._status.style().unpolish(self._status)
        self._status.style().polish(self._status)

    @Slot(object)
    def _handle_success(self, outcome: object) -> None:
        if not self._accept_callbacks:
            return
        try:
            risk = _RISK_TEXT[outcome.risk_level.value]
            detection = _DETECTION_TEXT[outcome.execution_state.value]
            action = _ACTION_TEXT[outcome.generic_action.value]
            event_id = outcome.local_event_id
            if not isinstance(event_id, str):
                raise ValueError("invalid_result")
        except Exception:
            self._handle_failure("intake_failed")
            return
        self._result_values["mailRiskValue"].setText(risk)
        self._result_values["mailDetectionValue"].setText(detection)
        self._result_values["mailAdviceValue"].setText(action)
        self._result_values["mailEventIdValue"].setText(event_id)
        self._set_status("检测完成", "healthy")
        self._selection.setText("邮件文件引用已清除")
        self._selected_path = None
        self._refresh_callback()
        if self._thread is not None:
            self._set_busy(True)

    @Slot(str)
    def _handle_failure(self, code: str) -> None:
        if not self._accept_callbacks:
            return
        for value in self._result_values.values():
            value.setText("—")
        self._set_status("检测未完成", "warning")
        self._selection.setText(safe_intake_error_text(code))
        self._selected_path = None

    @Slot()
    def _handle_thread_finished(self) -> None:
        self._selected_path = None
        self._worker = None
        self._thread = None
        if self._accept_callbacks:
            self._set_busy(False)

    def shutdown(self) -> None:
        self._accept_callbacks = False
        thread = self._thread
        if thread is not None and thread.isRunning():
            thread.quit()
            thread.wait()
        self._selected_path = None
        self._worker = None
        self._thread = None


__all__ = [
    "DesktopMailIntakePanel",
    "EmlDropZone",
    "MailIntakeWorker",
    "safe_intake_error_text",
]
