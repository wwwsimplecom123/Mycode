# Phase 7C.2 Safe EML Desktop Intake Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a compact PySide6 “本地检测” page that lets the current user select one local `.eml`, explicitly confirm local-only processing, run Phase 7C.1 off the Qt UI thread, and display only the four approved result fields.

**Architecture:** Keep `LocalMailIntakeService.detect_file(path, *, confirmed_by_user)` as the only external detection seam. A focused Qt desktop-intake module hides local-URL drag validation, file-dialog selection, stable display projection, one-task-at-a-time `QThread` ownership, path clearing, and shutdown behavior; `desktop_qt.py` composes that module into the existing window and refreshes the existing Presenter after success.

**Tech Stack:** Python 3.12, PySide6-Essentials 6.8.3 Qt Core/Gui/Widgets, immutable existing `DetectionOutcome`, standard-library `unittest`, offscreen Qt tests, and the existing zero-dependency offline Wheel builder.

## Global Constraints

- Modify only `endpoint_agent/`; do not modify `app/`, `shielddome/`, `frontend/`, `extension/`, `web/`, `deploy/`, or `scripts/`.
- Implement Phase 7C.2 only; do not implement Phase 8, Windows shell integration, directory scanning, file monitoring, desktop mail-client adapters, attachment-content inspection, networking, telemetry, subprocesses, or installation packaging.
- The desktop UI and its worker may call only `LocalMailIntakeService`; they must not import or call MIME parsing, `FeaturePipeline`, `EvidenceStore`, `PendingConfirmationStore`, crypto/storage implementations, or construct `MailObservation`/risk outcomes.
- Drag and file selection only choose one path. Detection starts only after a fresh explicit confirmation and always calls `confirmed_by_user=True` exactly once.
- Never persist or continuously display an absolute path. A safe basename may exist only during the current selection and must be cleared after success, failure, or cancellation.
- Do not open, preview, copy, extract, execute, move, delete, or inspect attachment content. Do not create a network connection or listen on a port.
- Qt tests use `QT_QPA_PLATFORM=offscreen`; synthetic `.eml` files are generated only in `TemporaryDirectory` and must be gone when each test ends.
- Do not commit or push. Replace plan commit checkpoints with fresh `git diff`/status scope audits.

## Confirmed Test Seams

- **Drag-selection seam:** `EmlDropZone` receives Qt drag/drop events and exposes only accepted local file paths through `fileSelected(str)`; tests use real `QMimeData`, `QUrl`, `QDragEnterEvent`, and `QDropEvent` objects.
- **Desktop-intake seam:** `DesktopMailIntakeController.select_path(path)` and its observable Qt signals/widget state cover selection, confirmation, concurrency, stable result/error projection, path clearing, and shutdown.
- **Phase 7C.1 seam:** a test adapter satisfying `detect_file(path, *, confirmed_by_user)` records only the two approved inputs and returns a real immutable `DetectionOutcome`; production injects `LocalMailIntakeService`.
- **Window composition seam:** `create_desktop_application(..., mail_intake_service=...)` proves navigation, refresh, minimum resolutions, and lifecycle behavior without testing MIME or persistence internals.

---

### Task 1: Qt drag-selection and stable display module

**Files:**
- Create: `endpoint_agent/src/shielddome_endpoint/desktop_mail_intake.py`
- Create: `endpoint_agent/tests/test_desktop_mail_intake.py`

**Interfaces:**
- Consumes: one `QMimeData` carrying exactly one `QUrl` for a local `.eml` file.
- Produces: `EmlDropZone.fileSelected(str)` without opening the file or starting detection.
- Produces: stable observable panel states for `idle`, `selected`, `running`, `succeeded`, and `failed` without exposing path or result internals.
- Produces: `safe_intake_error_text(code: str) -> str` for the eight stable Phase 7C.1 codes.

- [ ] **Step 1: Write and run the first failing real-Qt drag test**

```python
def test_one_local_eml_drop_selects_without_detecting(self):
    zone = EmlDropZone()
    mime = QMimeData()
    mime.setUrls((QUrl.fromLocalFile(str(self.mail_path)),))
    selected = []
    zone.fileSelected.connect(selected.append)
    self.send_drag_and_drop(zone, mime)
    self.assertEqual(selected, [str(self.mail_path)])
    self.assertEqual(self.intake.calls, [])
```

Run: `$env:QT_QPA_PLATFORM='offscreen'; .\endpoint_agent\.venv-ui\Scripts\python.exe -m unittest discover -s endpoint_agent/tests -p "test_desktop_mail_intake.py" -v`

Expected RED: `desktop_mail_intake` or `EmlDropZone` is absent.

- [ ] **Step 2: Implement the minimal drop zone and rerun to GREEN**

```python
class EmlDropZone(QFrame):
    fileSelected = Signal(str)

    @staticmethod
    def local_eml_path(mime_data: QMimeData) -> str | None:
        if mime_data.hasHtml() or not mime_data.hasUrls():
            return None
        urls = mime_data.urls()
        if len(urls) != 1 or not urls[0].isLocalFile():
            return None
        path = urls[0].toLocalFile()
        info = QFileInfo(path)
        if not info.isFile() or info.suffix().casefold() != "eml":
            return None
        return path
```

- [ ] **Step 3: Add one RED→GREEN slice at a time for drag rejection**

Use literal expected outcomes for: uppercase `.EML`; multiple URLs; directory; `.txt`; `http`, `https`, and `ftp` URLs; plain text; HTML; and a custom mail-client MIME object. Each rejected event must remain unaccepted, emit no path, and make no detection call. Keep `local_eml_path` as a quick interaction check only; do not add final path-safety logic from Phase 7C.1.

- [ ] **Step 4: Add and implement fixed display/error projections**

```python
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
```

Assert unknown errors map to `intake_failed`; no message contains a path, basename, exception text, traceback, body, address, URL, attachment value, or implementation name.

- [ ] **Step 5: Audit the task diff instead of committing**

Run: `git diff --check -- endpoint_agent/src/shielddome_endpoint/desktop_mail_intake.py endpoint_agent/tests/test_desktop_mail_intake.py`

### Task 2: Explicit file selection, confirmation, and one-call gate

**Files:**
- Modify: `endpoint_agent/src/shielddome_endpoint/desktop_mail_intake.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/desktop_qt.py`
- Modify: `endpoint_agent/tests/test_desktop_mail_intake.py`

**Interfaces:**
- Consumes: `QtDialogAdapter.choose_eml_path(parent) -> str | None` using `QFileDialog.getOpenFileName` with `EML 邮件 (*.eml *.EML)`.
- Consumes: `QtDialogAdapter.confirm_mail_intake(parent) -> bool` with fixed local-only privacy copy.
- Produces: `DesktopMailIntakeController.select_path(path)` which shows only `Path(path).name`, asks once, and makes no service call when selection or confirmation is cancelled.

- [ ] **Step 1: Write RED tests for picker cancellation and safe filtering**

Patch `QFileDialog.getOpenFileName` to return `("", "")` and assert no service call and no error. Patch it to return a synthetic `.eml` and assert the call uses caption `选择 EML 邮件文件`, filter `EML 邮件 (*.eml *.EML)`, an empty starting directory, and no preview-specific code or file read.

- [ ] **Step 2: Implement the picker adapter and file-selection button to GREEN**

```python
def choose_eml_path(self, parent) -> str | None:
    path, _ = QFileDialog.getOpenFileName(
        parent,
        "选择 EML 邮件文件",
        "",
        "EML 邮件 (*.eml *.EML)",
    )
    return path or None
```

- [ ] **Step 3: Write RED tests for explicit confirmation**

Assert the dialog states: local processing; no upload; no opening, preview, extraction, or execution of attachments; and encrypted structured-result-only storage. Assert cancellation invokes no service, does not retain an automatic-confirm preference, and clears the selected path reference.

- [ ] **Step 4: Implement the confirmation gate to GREEN**

The controller must transition `idle → selected`, update the selected label to `已选择一个邮件文件` (optionally current safe basename), process Qt paint events so the selected state is visible behind the dialog, call `confirm_mail_intake`, and only enqueue detection when it returns exactly `True`. Never pass the basename or path into result/error text.

- [ ] **Step 5: Add a RED→GREEN slice proving one confirmed selection invokes only the approved interface**

```python
self.assertEqual(intake.calls, [(str(mail_path), True)])
```

The UI source must contain no `MailObservation(`, `FeaturePipeline`, `EvidenceStore`, `PendingConfirmationStore`, `SafeEmlReader`, `email`, MIME parser, `open(`, `read_`, attachment file operation, subprocess, or networking call.

### Task 3: Controlled non-blocking worker seam and path lifecycle

**Files:**
- Modify: `endpoint_agent/src/shielddome_endpoint/desktop_mail_intake.py`
- Modify: `endpoint_agent/tests/test_desktop_mail_intake.py`

**Interfaces:**
- Produces: `MailIntakeWorker.run()` on a dedicated `QThread`; its implementation calls only `detect_file(path, confirmed_by_user=True)` and emits either the returned outcome or one stable code.
- Produces: one in-flight task maximum; controller signals `stateChanged`, `detectionSucceeded`, and `refreshRequested`.
- Produces: `shutdown()` that rejects future UI callbacks, never force-terminates parsing, and waits for the active thread.

- [ ] **Step 1: Write and run a RED test proving detection is not on the QApplication thread**

Use a blocking intake adapter that records `QThread.currentThread()` and releases from a `threading.Event`; assert it differs from `QApplication.instance().thread()` while the event loop remains responsive.

- [ ] **Step 2: Implement minimal `QObject` worker + `QThread` ownership and rerun to GREEN**

```python
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
```

Move the worker to a new `QThread`, connect `thread.started → worker.run`, `worker.finished → thread.quit`, and use `deleteLater` for both objects. Do not call `terminate`, create a subprocess, or add a thread pool.

- [ ] **Step 3: Add RED→GREEN slices for concurrency and stable busy UI**

While the blocking adapter is active: a second drop/selection is rejected; file-select is disabled; drop acceptance is disabled; the status reads `正在本地检测`; the fixed-height result/status region does not collapse or change page geometry. Re-enable interaction only after finished cleanup.

- [ ] **Step 4: Add RED→GREEN slices for path/result cleanup**

After success and each failure, assert controller `_selected_path is None`, worker `_path is None`, worker has no outcome/result attribute, safe basename is removed, and thread/worker references are released after `finished`. Use weak references where practical; do not inspect or retain `MailObservation`.

- [ ] **Step 5: Add RED→GREEN shutdown coverage**

Start a blocking detection, mark the window/controller shutting down, release the adapter, call `shutdown`, and process queued events. Assert the worker is allowed to finish, the thread is no longer running, and destroyed/disabled UI receivers are not updated. Connect `QApplication.aboutToQuit` to this shutdown path.

### Task 4: Compose the compact local-detection page

**Files:**
- Modify: `endpoint_agent/src/shielddome_endpoint/desktop_qt.py`
- Modify: `endpoint_agent/tests/test_desktop_qt.py`
- Create: `endpoint_agent/tests/capture_phase7c2_screenshots.py`

**Interfaces:**
- Consumes: injected `mail_intake_service` in `create_desktop_application`; production defaults lazily to `LocalMailIntakeService` only after PySide6 is available.
- Produces: navigation order `安全概览`, `本地检测`, `最近事件`, `已确认样本`, `本地数据`.
- Produces: a compact page containing `emlDropZone`, `selectEmlButton`, `mailIntakeStatus`, `mailIntakeResult`, and `openRecentEventsButton`.

- [ ] **Step 1: Write and run a RED real-window composition test**

At 1024x720, click `localIntakeNav`; assert the page index, compact drop zone height, visible selection button/status/result/actions, and no overlap using widget geometries. Assert the drop zone occupies less than half the page height.

- [ ] **Step 2: Implement the page and navigation to GREEN**

Use the existing graphite/paper/teal visual system. Keep the page as one quiet work surface with horizontal rules and a single dashed drop target—not a Hero and not nested cards. Use Segoe UI Variable Display for the restrained page heading, Segoe UI for body/actions, and Cascadia Mono only for event IDs/status keys.

Layout wireframe:

```text
┌ 本地检测 ─────────────────────────────────── 刷新 ┐
│ 将一个 EML 邮件文件拖到这里  [选择邮件文件]       │
│ 仅选择文件；确认前不会读取                       │
├──────────────────────────────────────────────────┤
│ 状态                结果                          │
│ 等待选择            风险 / 状态 / 建议 / 事件 ID │
├──────────────────────────────────────────────────┤
│ [返回最近事件]                                   │
└──────────────────────────────────────────────────┘
```

- [ ] **Step 3: Write and implement the minimal successful result projection**

Display exactly: risk level from `outcome.risk_level`, detection state from `outcome.execution_state`, generic advice from `outcome.generic_action`, and `outcome.local_event_id`. Do not display score, private evidence, rule codes, model version/reason, subject/body/address/URL/attachment, or path. After success call the existing Presenter refresh path once so Dashboard and recent events are refreshed; do not select an event or confirm a sample automatically.

- [ ] **Step 4: Add result/error state and navigation tests**

Assert success renders the four labels and returns to recent events only after the user clicks `返回最近事件`. Assert `file_too_large` and `unsupported_file` render restrained warning/error tones without leaking the synthetic path or injected exception. Assert loading/result/error transitions preserve geometry.

- [ ] **Step 5: Apply intentional Phase 7C.2 styling**

Tokens: `Graphite #202A2F`, `Paper #F4F5F2`, `Ink #172126`, `Signal Teal #2B7772`, `Rule #D4D9D7`, `Muted #647177`, `Warning #B46B2A`, `Critical #A23A36`. The signature element is a narrow dashed “inbox slot” drop target derived from secure document intake; remove any decorative container that does not communicate selection, state, result, or action.

### Task 5: Privacy, offline, and lifecycle constraint tests

**Files:**
- Modify: `endpoint_agent/tests/test_desktop_privacy.py`
- Modify: `endpoint_agent/tests/test_offline_constraints.py`
- Modify: `endpoint_agent/tests/test_package.py` only if a new GUI-independent public display contract is intentionally exported
- Modify: `endpoint_agent/tests/test_desktop_mail_intake.py`

**Interfaces:**
- Verifies the complete Phase 7C.2 production source set through AST/static guards and real Qt runtime seams.

- [ ] **Step 1: Write RED static tests for forbidden imports and capabilities**

Extend `DESKTOP_SOURCES` with `desktop_mail_intake.py`. Reject Python `email`/MIME parser imports, `FeaturePipeline`, `EvidenceStore`, `PendingConfirmationStore`, crypto/storage, `SafeEmlReader`, `MailObservation` construction, file `open`/read/write/copy/extract/execute/preview operations, `subprocess`, network imports, endpoint literals, and listener/connect calls. Permit only the lazy `LocalMailIntakeService` import at the desktop composition seam.

- [ ] **Step 2: Keep the production offline guard GREEN**

Run: `.\endpoint_agent\.venv-ui\Scripts\python.exe -m unittest discover -s endpoint_agent/tests -p "test_offline_constraints.py" -v`

- [ ] **Step 3: Add real-runtime zero-network and no-subprocess tests**

Patch `socket.socket` and `subprocess.Popen/run/call/check_call/check_output` to fail, create the real Qt app, select/confirm a synthetic mail through a local intake adapter, and assert none were called. Do not patch internal UI classes.

- [ ] **Step 4: Audit test temporary content**

Every synthetic `.eml` must be created under `TemporaryDirectory`; after the context closes, assert the directory no longer exists. Scan `endpoint_agent/tests` and the screenshot/build output for `.eml`, message bodies, attachments, path logs, unencrypted databases, and mail-content logs.

### Task 6: GUI capture, documentation, and acceptance gates

**Files:**
- Modify: `endpoint_agent/README.md`
- Modify: `endpoint_agent/DEVELOPMENT_PLAN.md`
- Modify: `endpoint_agent/docs/USAGE.md`
- Modify: `endpoint_agent/AGENTS.md`
- Modify: `endpoint_agent/tests/capture_phase7c2_screenshots.py`
- Verify: all Phase 7C.2 source/tests and generated ignored outputs

**Interfaces:**
- Documents the exact desktop interaction, safety statement, stable errors, worker lifecycle, privacy omissions, and phase status without implying Phase 8 or mail-client adapters exist.

- [ ] **Step 1: Generate five screenshot states with only synthetic adapters**

Run: `$env:QT_QPA_PLATFORM='offscreen'; .\endpoint_agent\.venv-ui\Scripts\python.exe endpoint_agent/tests/capture_phase7c2_screenshots.py`

Write only ignored PNGs under `endpoint_agent/dist/phase7c2/screenshots/`: `1366x768-initial.png`, `1024x720-selected-confirmation.png`, `1024x720-running.png`, `1024x720-complete.png`, and `1024x720-file-too-large.png`. The capture script must not leave an `.eml`, path record, database, key, or log.

- [ ] **Step 2: Inspect all five PNGs at original detail**

Check that the drop zone is not full-page; state/result/action hierarchy is clear; no text/button/status overlaps or clips; loading does not move layout; error color is restrained; and there are no gradients, Hero treatment, decorative large cards, or nested cards. Rework and recapture until both 1366x768 and 1024x720 satisfy the brief.

- [ ] **Step 3: Update documentation only after functional gates pass**

Set Phase 7C.2, Phase 7C, and Phase 7 to `complete`; keep Phase 7C.1 `complete` and Phase 8 `pending`; explicitly state desktop mail-client adapters remain Phase 9. Document that drag/drop only selects, confirmation is never remembered, the worker is single-flight/non-blocking, and the result contains only risk, status, generic advice, and local event ID. If real Qt drag, non-blocking execution, cleanup, screenshots, or full regression fails, keep Phase 7C.2 `in_progress` and do not complete Phase 7C/Phase 7.

- [ ] **Step 4: Run focused Phase 7C.2 and GUI tests**

```powershell
$env:QT_QPA_PLATFORM='offscreen'
.\endpoint_agent\.venv-ui\Scripts\python.exe -m unittest discover -s endpoint_agent/tests -p "test_desktop_mail_intake.py" -v
.\endpoint_agent\.venv-ui\Scripts\python.exe -m unittest discover -s endpoint_agent/tests -p "test_desktop_*.py" -v
```

- [ ] **Step 5: Run the complete Endpoint Agent regression and offline constraints**

```powershell
$env:QT_QPA_PLATFORM='offscreen'
.\endpoint_agent\.venv-ui\Scripts\python.exe -m unittest discover -s endpoint_agent/tests -v
.\endpoint_agent\.venv-ui\Scripts\python.exe -m unittest discover -s endpoint_agent/tests -p "test_offline_constraints.py" -v
```

- [ ] **Step 6: Build a fresh offline Wheel**

Run: `.\endpoint_agent\.venv-ui\Scripts\python.exe -m pip wheel --no-index --no-deps .\endpoint_agent --wheel-dir .\endpoint_agent\dist\phase7c2-wheel`

- [ ] **Step 7: Run final diff, scope, and contamination audits**

```powershell
git diff --check -- endpoint_agent
git status --short
git diff --stat
git diff --cached
git status --short -- app shielddome frontend extension web deploy scripts
```

Also enumerate `endpoint_agent/tests`, `endpoint_agent/dist/phase7c2`, and repository-visible untracked files for raw `.eml`, recognizable body text, attachment files, extraction directories, temporary path records, unencrypted databases, keys, or mail-content logs. Compare protected-directory status to the initial baseline and do not alter existing user files.

## Self-review

- Spec coverage: the tasks cover exact local-file drag acceptance/rejection, picker cancellation/filtering, explicit confirmation, single-flight non-UI-thread execution, safe shutdown, fixed error mapping, four-field results, Dashboard/event refresh, path cleanup, privacy/offline/static constraints, five screenshot states, documentation state, Wheel build, and Git/contamination audits.
- Placeholder scan: no `TBD`, deferred implementation instruction, generic “add error handling,” or unspecified test step remains.
- Type consistency: the worker consumes only `detect_file(path, confirmed_by_user=True)` and returns the existing `DetectionOutcome`; the UI display reads only `risk_level`, `execution_state`, `generic_action`, and `local_event_id`; stable failures are strings accepted by `safe_intake_error_text`.
- Scope check: Windows shell handling, directory scan/watch, desktop mail-client adapters, attachment-content work, Phase 8 packaging, networking, telemetry, and protected root directories are explicitly excluded.
