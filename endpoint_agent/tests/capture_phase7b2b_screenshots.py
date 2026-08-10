from datetime import datetime, timedelta, timezone
from pathlib import Path
import os, sys
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src")); sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtWidgets import QApplication, QPushButton, QTableWidget
from shielddome_endpoint.console_models import ConsoleOperationResult, ConsoleStatusCode
from shielddome_endpoint.desktop_qt import create_desktop_application
from test_desktop_presenter import PagingConsoleService, make_dashboard, make_event

class Service(PagingConsoleService):
    def __init__(self):
        super().__init__(ConsoleOperationResult(ConsoleStatusCode.SUCCESS, make_dashboard(today_count=1)), (make_event("event-confirm-01"),))
        self.code = ConsoleStatusCode.EXAMPLE_ADDED
    def confirm_event_benign(self, event_id, *, confirmed): return ConsoleOperationResult(self.code, None, 1)
    confirm_event_phishing = confirm_event_benign

def save(window, path, width, height):
    window.resize(width, height); window.show(); QApplication.processEvents()
    if not window.grab().save(str(path), "PNG"): raise RuntimeError("capture_failed")

def main():
    out = ROOT / "dist" / "phase7b2b" / "screenshots"; out.mkdir(parents=True, exist_ok=True)
    service = Service(); bundle = create_desktop_application(service=service, show=False, enable_tray=False)
    bundle.window.findChild(QPushButton, "eventsNav").click(); table=bundle.window.findChild(QTableWidget,"eventsTable"); table.cellClicked.emit(0,0)
    save(bundle.window,out/"1366x768-event-confirmation.png",1366,768)
    save(bundle.window,out/"1024x720-event-confirmation.png",1024,720)
    state=bundle.presenter.confirm_event_benign("event-confirm-01",confirmed=True); bundle.window.render_state(state)
    save(bundle.window,out/"confirmation-success.png",1024,720)
    service.code=ConsoleStatusCode.PENDING_CONTEXT_EXPIRED
    state=bundle.presenter.confirm_event_phishing("event-confirm-01",confirmed=True); bundle.window.render_state(state)
    save(bundle.window,out/"confirmation-expired.png",1024,720)
    bundle.lifecycle.quit_application(); QApplication.processEvents()
    for p in out.glob("*.png"): print(p, p.stat().st_size)
if __name__ == "__main__": raise SystemExit(main())
