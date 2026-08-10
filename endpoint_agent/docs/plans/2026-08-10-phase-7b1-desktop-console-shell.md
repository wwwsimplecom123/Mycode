# Phase 7B.1 Desktop Console Shell Implementation Plan

> **Execution:** Implement task-by-task with the requested `executing-plans` workflow. Steps use checkbox syntax for evidence tracking; no subagent, branch, commit, or push is part of this scoped run.

**Goal:** Build and verify a compact PySide6 Windows tray application and read-only Personal Security Dashboard that consumes only Phase 7A `PersonalConsoleService` results.

**Architecture:** `PersonalConsolePresenter` is the GUI-independent deep module at the Phase 7A seam: it owns dashboard/event/detail mapping, pagination, fixed copy, empty/degraded/error states, and chart inputs behind a small state-returning interface. `DesktopLifecycle` is the testable application-lifecycle module; the production PySide6 adapter supplies the window, tray, custom-painted charts, navigation, and event wiring without importing storage or cryptography. PySide6 remains an optional import for the core package, while the desktop entry point fails with a stable dependency message when the pinned UI runtime is absent.

**Tech Stack:** Python 3.12, standard-library `dataclasses`/`enum`/`unittest`, `PySide6-Essentials==6.8.3` (QtCore/QtGui/QtWidgets, Python `>=3.9,<3.14`, LGPLv3/GPLv2/GPLv3/commercial), `tzdata==2026.3` (PSF-2.0; IANA data for Windows named time zones), custom `QPainter` charts, existing zero-dependency Wheel backend.

## Global Constraints

- Modify only `endpoint_agent/`; preserve every pre-existing tracked and untracked file.
- Implement Phase 7B.1 only. Do not implement Phase 7B.2 startup, Phase 7C `.eml` intake, sample mutation, diagnostics interaction, local-data deletion interaction, model delivery, release packaging, telemetry, update, or network services.
- UI and Presenter call only `PersonalConsoleService`; they never import or access SQLite, `EvidenceStore`, `ExampleStore`, DPAPI, AES-GCM, keys, nonces, tags, ciphertext, or local data paths.
- Production source creates no HTTP/WebSocket/RPC service, socket connection, listener, telemetry, upload, updater, or background download.
- Pin `PySide6-Essentials==6.8.3` and `tzdata==2026.3`; install them only in ignored `endpoint_agent/.venv-ui/` for development. Production installation must resolve pinned wheels from an approved offline cache and must never download at runtime.
- Use Qt Essentials and custom-painted lightweight charts; do not add Qt Charts, WebEngine, browser pages, Electron, local HTTP, or unnecessary Addons.
- Core `import shielddome_endpoint` must work without PySide6. Only the desktop entry/Qt adapter may import PySide6.
- Default desktop target is 1366x768; minimum verified viewport is 1024x720. No gradient, large pale-blue canvas, decorative large cards, nested cards, unstable chart/table sizing, overlap, clipping, or overflow.
- All displayed facts come from Phase 7A ViewModels. Production UI contains no static demonstration dataset.
- Empty, loading, damaged-store, unavailable, and rules-only degradation states use fixed non-sensitive copy and never expose exception text.
- Do not create a branch, commit, push, PR, Endpoint Release, Host executable, or installer.

## Confirmed Public Test Seams

- `PersonalConsolePresenter.refresh()`, `next_events()`, `previous_events()`, and `select_event(local_event_id)` returning immutable desktop state derived only from `PersonalConsoleService` results.
- `DesktopLifecycle.show_console()`, `hide_console()`, `handle_window_close()`, and `quit_application()` observed through injected UI lifecycle adapters.
- `create_desktop_application(service=None, *, show=True, enable_tray=True)` and `ShieldDomeMainWindow` under a real PySide6 `QApplication` with `QT_QPA_PLATFORM=offscreen`.
- Static production-source guards proving the desktop UI does not import storage/crypto modules and does not create network connections or listeners.

---

### Task 1: Pin the minimal UI runtime and preserve optional core import

**Files:**
- Create: `endpoint_agent/requirements-ui.txt`
- Modify: `endpoint_agent/pyproject.toml`
- Modify: `endpoint_agent/.gitignore`
- Modify: `endpoint_agent/tests/test_repository_hygiene.py`
- Modify: `endpoint_agent/tests/test_package.py`
- Modify: `endpoint_agent/tests/test_build.py`

**Interfaces:**
- Consumes: Python 3.12 and the existing local PEP 517 backend.
- Produces: exact runtime metadata `PySide6-Essentials==6.8.3`; ignored `.venv-ui/`; core package import that does not load or require `PySide6`.

- [x] **Step 1: Write a failing dependency/ignore/optional-import test**

```python
self.assert_endpoint_path_is_ignored("endpoint_agent/.venv-ui/Scripts/python.exe")
self.assertEqual(
    (ENDPOINT_ROOT / "requirements-ui.txt").read_text(encoding="utf-8"),
    "cryptography==49.0.0\nPySide6-Essentials==6.8.3\ntzdata==2026.3\n",
)
self.assertNotIn("PySide6", sys.modules)
```

- [x] **Step 2: Run focused tests and confirm red**

Run: `python -m unittest endpoint_agent.tests.test_repository_hygiene endpoint_agent.tests.test_package endpoint_agent.tests.test_build -v`

Expected: FAIL because `.venv-ui/`, the pinned requirements file, and Wheel metadata are absent.

- [x] **Step 3: Add the exact dependency and ignore rule**

Set `dependencies = ["cryptography==49.0.0", "PySide6-Essentials==6.8.3", "tzdata==2026.3"]`, create the UI requirements file with those exact three fixed runtime dependencies, add `/.venv-ui/`, and extend Wheel assertions for the exact `Requires-Dist` lines. Do not add PyInstaller or Qt Addons.

- [x] **Step 4: Run focused tests and confirm green**

Run: `python -m unittest endpoint_agent.tests.test_repository_hygiene endpoint_agent.tests.test_package endpoint_agent.tests.test_build -v`

Expected: PASS with no new skip.

### Task 2: Presenter state and dashboard mapping

**Files:**
- Create: `endpoint_agent/src/shielddome_endpoint/desktop_presenter.py`
- Create: `endpoint_agent/tests/test_desktop_presenter.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/__init__.py`

**Interfaces:**
- Consumes: `PersonalConsoleService.get_dashboard`, `list_recent_events`, `get_event_detail`, and Phase 7A immutable ViewModels only.
- Produces: immutable `DesktopConsoleState`; `PersonalConsolePresenter.refresh()`, `next_events()`, `previous_events()`, `select_event(local_event_id)`; exact 10-row desktop event pages.

- [x] **Step 1: Write a failing dashboard mapping test**

```python
state = PersonalConsolePresenter(StaticConsoleService(dashboard, events)).refresh()
self.assertEqual(state.today_count, "4")
self.assertEqual(tuple(point.value for point in state.trend), (0,) * 14 + (4,))
self.assertEqual(dict((item.key, item.value) for item in state.risk), {
    "low": 1, "medium": 1, "high": 1, "critical": 1,
})
self.assertEqual(dict((item.key, item.value) for item in state.sources), {
    "browser_native": 3, "manual_local": 1,
})
```

- [x] **Step 2: Run the presenter module and confirm red**

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_desktop_presenter.py" -v`

Expected: FAIL because `desktop_presenter` does not exist.

- [x] **Step 3: Implement the minimal immutable state mapper**

Map all fifteen trend buckets without re-aggregation; preserve all risk/source counts; map abstention, model failure, and rules-only degradation counts; translate fixed risk/source/status/action keys to concise Chinese labels; expose no original service exceptions or arbitrary text.

- [x] **Step 4: Add empty/corrupt/degraded red-green slices**

Assert `empty` when successful aggregates and events are zero, `degraded` when either store health is unavailable or rules-only is active, and `error` when no dashboard payload exists. Fixed error copy must contain recovery direction but not collaborator exception text.

- [x] **Step 5: Add pagination/detail red-green slices**

Assert offset changes by exactly 10, previous/next bounds are honored, page state remains stable on controlled service failure, selected detail contains only Phase 7A fields/rule codes, and not-found selection produces fixed safe copy.

### Task 3: Testable tray and window lifecycle

**Files:**
- Create: `endpoint_agent/src/shielddome_endpoint/desktop_lifecycle.py`
- Create: `endpoint_agent/tests/test_desktop_lifecycle.py`

**Interfaces:**
- Consumes: an injected adapter with `show_window()`, `hide_window()`, `hide_tray()`, and `quit_event_loop()`.
- Produces: `DesktopLifecycle.show_console()`, `hide_console()`, `handle_window_close() -> CloseDisposition.HIDE_TO_TRAY`, and idempotent `quit_application()`.

- [x] **Step 1: Write a failing tray open/hide/quit test**

```python
lifecycle.show_console()
lifecycle.hide_console()
lifecycle.quit_application()
self.assertEqual(adapter.events, ("show", "hide", "hide_tray", "quit"))
```

- [x] **Step 2: Run the lifecycle module and confirm red**

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_desktop_lifecycle.py" -v`

Expected: FAIL because `desktop_lifecycle` does not exist.

- [x] **Step 3: Implement the lifecycle module**

Keep lifecycle state in-process; close requests return `HIDE_TO_TRAY` and call `hide_window`; explicit quit hides the tray and terminates the Qt event loop exactly once.

- [x] **Step 4: Add close-to-tray and idempotency red-green slices**

Assert ordinary close never quits, opening after close shows/activates the window through the adapter, and repeated quit emits no extra events.

### Task 4: PySide6 window, navigation, custom charts, and tray adapter

**Files:**
- Create: `endpoint_agent/src/shielddome_endpoint/desktop_qt.py`
- Create: `endpoint_agent/src/shielddome_endpoint/desktop_app.py`
- Create: `endpoint_agent/tests/test_desktop_qt.py`

**Interfaces:**
- Consumes: `PersonalConsolePresenter` and `DesktopLifecycle`; imports only `PySide6.QtCore`, `PySide6.QtGui`, and `PySide6.QtWidgets` from Qt.
- Produces: `ShieldDomeMainWindow`, `QtDesktopAdapter`, `create_desktop_application(service=None, *, show=True, enable_tray=True)`, and `desktop_app.main()`.

- [x] **Step 1: Write a failing real-Qt offscreen smoke test**

```python
service = StaticConsoleService(dashboard_result=dashboard_result, event_result=event_result)
bundle = create_desktop_application(service=service, show=False, enable_tray=False)
bundle.window.resize(1024, 720)
bundle.window.show()
QApplication.processEvents()
self.assertEqual(bundle.window.minimumSize().width(), 1024)
self.assertEqual(bundle.window.minimumSize().height(), 720)
self.assertGreater(bundle.window.grab().width(), 0)
```

- [x] **Step 2: Run under the pinned UI Python and confirm red**

Run: `$env:QT_QPA_PLATFORM='offscreen'; .\endpoint_agent\.venv-ui\Scripts\python.exe -m unittest discover -s endpoint_agent/tests -p "test_desktop_qt.py" -v`

Expected: FAIL because the Qt adapter/window does not exist.

- [x] **Step 3: Implement the restrained desktop design**

Use the palette `Graphite #202A2F`, `Paper #F4F5F2`, `Ink #172126`, `Signal teal #2B7772`, `Warning #B46B2A`, `Critical #A23A36`; use `Segoe UI Variable Display` for restrained headings, `Segoe UI` for body, and `Cascadia Mono` for counts/IDs. Build one fixed 188 px navigation rail, a dashboard stack page, an events/detail page, stable dividers instead of decorative cards, visible keyboard focus, and no animation.

- [x] **Step 4: Implement custom lightweight chart widgets**

Draw the fifteen-day trend and horizontal distributions with `QPainter`; handle all-zero inputs with axes/labels plus a clear empty message; reserve label/value gutters so text never overlaps bars or plot geometry. Do not import QtCharts, QtNetwork, QML, WebEngine, or Addons.

- [x] **Step 5: Implement tray and close behavior**

Create a local painted shield icon, fixed status tooltip/menu, actions `打开控制台`, `隐藏控制台`, and `退出`; wire actions only to `DesktopLifecycle`; `closeEvent` ignores the close and hides the window unless explicit lifecycle quit has begun.

- [x] **Step 6: Implement loading and error boundaries**

Disable refresh/paging controls during synchronous bounded service reads, show fixed loading text, render empty/degraded/corrupt states in the stable content region, and catch only at the presenter/Qt entry edge without displaying exception text.

- [x] **Step 7: Run real-Qt tests and confirm green**

Run: `$env:QT_QPA_PLATFORM='offscreen'; .\endpoint_agent\.venv-ui\Scripts\python.exe -m unittest discover -s endpoint_agent/tests -p "test_desktop_qt.py" -v`

Expected: PASS with real PySide6 imports and pixels rendered.

### Task 5: Offline, privacy, packaging, and no-PySide guards

**Files:**
- Modify: `endpoint_agent/tests/test_offline_constraints.py`
- Modify: `endpoint_agent/tests/test_build.py`
- Modify: `endpoint_agent/tests/test_package.py`
- Create: `endpoint_agent/tests/test_desktop_privacy.py`

**Interfaces:**
- Consumes: Tasks 1–4 production source.
- Produces: static and runtime proof that the desktop shell has no direct storage/crypto access, network connection/listener, browser/HTTP replacement, mutation commands, or mandatory PySide import for core use.

- [x] **Step 1: Write the failing forbidden-import topology test**

Scan `desktop_presenter.py`, `desktop_lifecycle.py`, `desktop_qt.py`, and `desktop_app.py` AST imports and reject evidence/example stores, diagnostics exporter, key protection, crypto, SQLite, socket, HTTP clients/servers, browser modules, `.eml`, and mutation service method names.

- [x] **Step 2: Run focused guards and confirm red**

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_desktop_privacy.py" -v`

Expected: FAIL until the desktop source set and exact guards exist.

- [x] **Step 3: Add subprocess import and zero-network runtime proof**

Run a clean Python subprocess with an import blocker for `PySide6` and assert `import shielddome_endpoint` succeeds while `PySide6` remains absent. Patch `socket.socket` before a real offscreen application creation and assert it is never invoked; verify no listening ports are opened by the GUI process.

- [x] **Step 4: Extend Wheel content assertions**

Require the four desktop source modules and both exact dependencies in Wheel metadata. Confirm no tests, screenshot fixtures, `.venv-ui`, cached wheel, PyInstaller, or runtime data enters the Wheel.

- [x] **Step 5: Run focused guards and confirm green**

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_desktop_privacy.py" -v`

Expected: PASS with no PySide skip for pure core tests.

### Task 6: Real environment, visual verification, and conservative status docs

**Files:**
- Modify: `endpoint_agent/README.md`
- Modify: `endpoint_agent/DEVELOPMENT_PLAN.md`
- Modify: `endpoint_agent/docs/USAGE.md`
- Modify: `endpoint_agent/AGENTS.md`
- Modify: `endpoint_agent/docs/plans/2026-08-10-phase-7b1-desktop-console-shell.md`
- Generate ignored evidence: `endpoint_agent/dist/phase7b1/screenshots/1366x768.png`
- Generate ignored evidence: `endpoint_agent/dist/phase7b1/screenshots/1024x720.png`

**Interfaces:**
- Consumes: production desktop entry and a temporary real encrypted Phase 6 evidence store queried through real Phase 7A `PersonalConsoleService`.
- Produces: real PySide version evidence, two screenshots, docs/license/offline instructions, and Phase 7B.1 status updated only after acceptance.

- [x] **Step 1: Create the ignored UI development environment**

Run: `python -m venv endpoint_agent/.venv-ui`

Install for this development verification: `.\endpoint_agent\.venv-ui\Scripts\python.exe -m pip install -r endpoint_agent\requirements-ui.txt`

Record that Endpoint Release builders must instead pre-populate and install from an approved offline wheel cache with `--no-index`; the Agent never invokes pip.

- [x] **Step 2: Verify the exact runtime**

Run: `.\endpoint_agent\.venv-ui\Scripts\python.exe -c "import PySide6, sys; print(sys.version); print(PySide6.__version__)"`

Expected: Python 3.12 and PySide6 `6.8.3`.

- [x] **Step 3: Capture both required real-Qt screenshots**

Use a temporary current-user data root, real `EvidenceStore` encryption, real Phase 7A `PersonalConsoleService`, and production `ShieldDomeMainWindow`; write no static production demo data. Render at exactly 1366x768 and 1024x720, process the Qt event queue, and save both ignored PNGs.

- [x] **Step 4: Inspect screenshots and iterate**

Open both PNGs at original resolution. Check blank window, control overlap, clipped text, unrendered charts, table/action instability, empty/degraded visibility, and layout jump. Fix and recapture until both satisfy the brief.

- [x] **Step 5: Run all completion verification freshly**

```powershell
python -m unittest discover -s endpoint_agent/tests -p "test_desktop_*.py" -v
python -m unittest discover -s endpoint_agent/tests -v
$env:QT_QPA_PLATFORM='offscreen'; .\endpoint_agent\.venv-ui\Scripts\python.exe -m unittest discover -s endpoint_agent/tests -p "test_desktop_qt.py" -v
.\endpoint_agent\.venv-ui\Scripts\python.exe -c "import PySide6, tzdata; print(PySide6.__version__); print(tzdata.__version__)"
python -m pip wheel --no-index --no-deps .\endpoint_agent --wheel-dir .\endpoint_agent\dist\phase7b1
git diff --check -- endpoint_agent
git status --short
git diff --stat
git diff --cached
git status --short -- app shielddome frontend extension web deploy scripts
```

- [x] **Step 6: Update docs and phase state only from evidence**

Document the read-only UI/tray interface, version/license/reason, `.venv-ui` workflow, offline cache requirement, screenshot paths, exact verification counts, and exclusions. If real PySide6 startup and both screenshot inspections pass, set Phase 7B parent to `in_progress`, add Phase 7B.1 `complete`, keep Phase 7B.2 `pending`, keep Phase 7C `pending`, keep Phase 7 `in_progress`, and replace the stale final Phase 7 statement. Otherwise leave Phase 7B.1 `in_progress` and record the exact blocker.

## Frontend Design Direction

**Subject:** A per-user Windows phishing-defense instrument for employees who need a calm, trustworthy summary of what the local Endpoint Agent saw today.

**Single job:** Let the current user verify local protection health and inspect sanitized recent evidence without offering destructive controls.

**Palette:** Graphite `#202A2F` (navigation/tool chassis), Paper `#F4F5F2` (work surface), Ink `#172126` (primary text), Signal teal `#2B7772` (healthy/current activity), Warning `#B46B2A` (degraded/medium), Critical `#A23A36` (high/critical).

**Typography:** `Segoe UI Variable Display` for the product/title line; `Segoe UI` for UI copy and tables; `Cascadia Mono` for counts, timestamps, and opaque event IDs. Windows fallbacks are `Segoe UI` and `Consolas`.

**Layout:** A narrow graphite instrument rail anchors a paper work surface. Metrics use one ruled band rather than separate cards; the 15-day trace acts as the visual spine; events use a stable evidence ledger with a dedicated detail pane.

```text
┌──────────────┬──────────────────────────────────────────────────────────┐
│ SHIELDDOME   │  个人安全概览                         [刷新] [状态]      │
│ 本地防护     ├──────────────────────────────────────────────────────────┤
│              │  今日检测 │ 模型拒判 │ 模型故障 │ 纯规则降级          │
│ ● Agent 状态 ├──────────────────────────────────────────────────────────┤
│              │  15 天证据轨迹                    风险 / 来源条形分布   │
│ ▸ 安全概览   │                                                          │
│   最近事件   ├──────────────────────────────────────────────────────────┤
│              │  最近事件证据台账（稳定表格与分页）                      │
│              │                                                          │
│ 仅本机数据   │  状态与错误边界                                          │
└──────────────┴──────────────────────────────────────────────────────────┘
```

**Signature:** The “15-day evidence trace” is a restrained, custom-painted stepped line with fifteen fixed date notches that visibly encodes the exact retention window rather than decorating the page.

**Self-critique:** A generic security dashboard would use floating blue statistic cards and a large donut chart. This direction removes both: the ruled metric band communicates instrument density, and the retention trace is specific to Endpoint Evidence Records. The only expressive risk is the dark instrument rail; all other surfaces remain quiet and functional.

## Execution Evidence

- Baseline: 249 tests ran successfully with 1 existing packaged-Host skip before implementation.
- Phase 7B.1专项: 13 tests ran successfully in the pinned real PySide6 offscreen environment with no skips.
- Acceptance repair regression: 265 tests ran successfully with 1 existing unavailable packaged-Host skip in the pinned real PySide6 offscreen environment; the named `Asia/Shanghai` time-zone and local-calendar tests passed.
- Runtime: Python 3.12.10, PySide6 6.8.3, and tzdata 2026.3 imported from the ignored `.venv-ui` environment. The tzdata runtime pin supplies the Windows IANA database under PSF-2.0 and must come from the approved offline cache, never an Agent runtime download.
- Visuals: production Qt Widgets rendered from real Phase 7A service data at 1366x768 and 1024x720; an additional 1024x720 events/detail capture was inspected during layout iteration.
- Acceptance repair Wheel: `shielddome_endpoint-0.1.0-py3-none-any.whl`, 75,902 bytes, SHA-256 `07f0391ac6bcab8f8d281066edab8a68292cdf9e8c3fc81a4bcb159c844de8fe`; metadata declares all three exact runtime dependencies.
- Git: `git diff --check -- endpoint_agent` returned zero; the index remained empty and protected directories had no tracked differences.
