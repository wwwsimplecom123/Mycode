from datetime import datetime, timedelta, timezone
from pathlib import Path
import os
import sys
from tempfile import TemporaryDirectory


ENDPOINT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENDPOINT_ROOT / "src"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QPushButton, QTableWidget

from shielddome_endpoint.console_service import PersonalConsoleService
from shielddome_endpoint.desktop_qt import create_desktop_application
from shielddome_endpoint.domain import (
    DetectionExecutionState,
    GenericAction,
    ModelExecutionStatus,
    RiskLevel,
)
from shielddome_endpoint.evidence_record import EndpointEvidenceRecord
from shielddome_endpoint.evidence_store import EvidenceStore
from shielddome_endpoint.example_store import ExampleStore


NOW = datetime(2026, 8, 10, 8, 30, tzinfo=timezone.utc)


def make_record(index: int) -> EndpointEvidenceRecord:
    detected_at = NOW - timedelta(days=index % 15, hours=index % 5)
    mode = index % 7
    if mode == 0:
        detection_status = DetectionExecutionState.MODEL_ERROR
        model_status = ModelExecutionStatus.ERROR
        degraded = True
        abstained = False
        error_code = "runtime_error"
    elif mode == 1:
        detection_status = DetectionExecutionState.MODEL_UNCERTAIN
        model_status = ModelExecutionStatus.SUCCESS
        degraded = False
        abstained = True
        error_code = None
    elif mode == 2:
        detection_status = DetectionExecutionState.RULES_ONLY
        model_status = None
        degraded = True
        abstained = False
        error_code = "model_not_configured"
    else:
        detection_status = DetectionExecutionState.MODEL_SUCCESS
        model_status = ModelExecutionStatus.SUCCESS
        degraded = False
        abstained = False
        error_code = None
    risk = (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)[
        index % 4
    ]
    action = {
        RiskLevel.LOW: GenericAction.CONTINUE,
        RiskLevel.MEDIUM: GenericAction.VERIFY_SENDER,
        RiskLevel.HIGH: GenericAction.AVOID_CREDENTIALS,
        RiskLevel.CRITICAL: GenericAction.CONTACT_SECURITY,
    }[risk]
    return EndpointEvidenceRecord(
        local_event_id=f"event-20260810-{index + 1:03d}",
        detected_at=detected_at,
        retention_until=detected_at + timedelta(days=15),
        risk_level=risk,
        detection_status=detection_status,
        generic_action=action,
        source_kind="browser_native" if index % 3 else "manual_local",
        rule_codes=("sender_domain_mismatch",) if index % 2 else ("dangerous_attachment",),
        abstained=abstained,
        degraded=degraded,
        model_execution_status=model_status,
        error_code=error_code,
    )


def main() -> int:
    output_directory = ENDPOINT_ROOT / "dist" / "phase7b1" / "screenshots"
    output_directory.mkdir(parents=True, exist_ok=True)
    previous_local_app_data = os.environ.get("LOCALAPPDATA")
    with TemporaryDirectory() as temporary_directory:
        os.environ["LOCALAPPDATA"] = temporary_directory
        evidence_store = EvidenceStore()
        example_store = ExampleStore()
        for index in range(22):
            evidence_store.put(make_record(index))
        service = PersonalConsoleService(
            evidence_store=evidence_store,
            example_store=example_store,
            clock=lambda: NOW,
            local_timezone=timezone(timedelta(hours=8)),
        )
        bundle = create_desktop_application(
            service=service,
            show=False,
            enable_tray=False,
        )
        for width, height in ((1366, 768), (1024, 720)):
            bundle.window.resize(width, height)
            bundle.window.show()
            QApplication.processEvents()
            screenshot = output_directory / f"{width}x{height}.png"
            rendered = bundle.window.grab().toImage().scaled(
                width,
                height,
                Qt.AspectRatioMode.IgnoreAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            if not rendered.save(str(screenshot), "PNG"):
                raise RuntimeError("desktop_screenshot_failed")
            print(f"{screenshot} {screenshot.stat().st_size}")
        bundle.window.findChild(QPushButton, "eventsNav").click()
        events_table = bundle.window.findChild(QTableWidget, "eventsTable")
        events_table.cellClicked.emit(0, 0)
        QApplication.processEvents()
        detail_screenshot = output_directory / "1024x720-events-detail.png"
        detail_rendered = bundle.window.grab().toImage().scaled(
            1024,
            720,
            Qt.AspectRatioMode.IgnoreAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        if not detail_rendered.save(str(detail_screenshot), "PNG"):
            raise RuntimeError("desktop_screenshot_failed")
        print(f"{detail_screenshot} {detail_screenshot.stat().st_size}")
        bundle.lifecycle.quit_application()
        QApplication.processEvents()
    if previous_local_app_data is None:
        os.environ.pop("LOCALAPPDATA", None)
    else:
        os.environ["LOCALAPPDATA"] = previous_local_app_data
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
