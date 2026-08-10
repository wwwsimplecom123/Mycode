# Phase 7B.2A Local Data Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This run is inline, does not create a worktree, branch, commit, or push, and preserves all user files.

**Goal:** Add safe current-user startup controls and explicit Confirmed Example Library, diagnostic export, and all-local-data deletion interactions to the existing ShieldDome desktop console, without implementing feedback confirmation or later phases.

**Architecture:** A deep `WindowsStartupManager` module owns executable validation, HKCU registry semantics, ownership checks, and idempotency behind a small status/install/uninstall interface; an injected registry adapter is the test seam, and the production adapter uses `winreg` without shells or administrator scope. `PersonalConsolePresenter` remains the GUI-independent desktop seam and exclusively calls `PersonalConsoleService` for sample and local-data operations; Qt owns only user intent, file selection, two-step confirmations, and rendering immutable safe display state.

**Tech Stack:** Python 3.12, standard-library `dataclasses`/`enum`/`pathlib`/`winreg`/`unittest`, `PySide6-Essentials==6.8.3`, `tzdata==2026.3`, existing Qt Widgets desktop shell and zero-dependency Wheel backend.

## Global Constraints

- Modify only `endpoint_agent/`; do not modify `app/`, `shielddome/`, `frontend/`, `extension/`, `web/`, `deploy/`, or `scripts/`.
- Implement Phase 7B.2A only. Phase 7B.2B and Phase 7C remain pending; do not implement `.eml` intake, formal EXE packaging, models, updates, telemetry, HTTP, WebSocket, RPC, network connections, or listeners.
- Do not implement `confirm_benign(...)` or `confirm_phishing(...)` UI actions. Endpoint Evidence Records and desktop ViewModels do not provide a safe `FeatureVector`; do not regenerate, persist, fabricate, or infer one. Record this as the Phase 7B.2B blocker.
- Startup registration uses only `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, never HKLM, scheduled tasks, elevation, shell, PowerShell, or untrusted command concatenation.
- Only an absolute, existing, frozen packaged `ShieldDomeEndpoint.exe` entry may be installed; ordinary `python.exe`, development module entry points, relative paths, and arbitrary executables are rejected.
- Uninstall removes only the exact owned value whose stored command matches the validated packaged executable. A same-name foreign value is preserved.
- UI and Presenter call local-data mutations only through `PersonalConsoleService`; they never import storage, encryption, key, diagnostic implementation, SQLite, or registry implementation modules.
- Sample displays are limited to opaque example ID, benign/phishing label, fixed source, UTC confirmation time, and conflict state. Never display `FeatureVector`, fingerprint, mail text, address, URL, attachment, path, key, ciphertext, exception, or stack.
- Diagnostic export is initiated only by a click and user-selected path. Default overwrite is false; an existing target requires a distinct second confirmation. Never preview, open, upload, or persist the chosen path.
- Delete-all requires an explanatory first confirmation and exact fixed text `删除全部本地数据` in a second dialog before calling `confirmed=True`; it does not remove application or extension files.
- Continue the Phase 7B.1 compact graphite/paper/teal desktop design. Use dividers and flat sections, no gradients, nested cards, or decorative backgrounds. Danger actions use the existing critical red and remain distinct from ordinary actions.
- Verify layouts at exactly 1366x768 and 1024x720; no table, filter, action, or confirmation text may overlap or clip.
- Do not reset, clean, checkout, rebase, overwrite user files, commit, or push.

## Confirmed Public Test Seams

- `WindowsStartupManager.status()`, `install()`, and `uninstall()` through an injected registry adapter, returning immutable stable status results.
- `PersonalConsoleService.list_confirmed_examples(...)`, `delete_confirmed_example(...)`, `clear_confirmed_examples(...)`, `export_diagnostics(...)`, and `delete_all_local_data(...)` as the only local-data command seam.
- `PersonalConsolePresenter` sample paging/filter/delete/clear/export/delete-all methods returning immutable desktop state with fixed safe notices.
- `create_desktop_application(...)` and `ShieldDomeMainWindow` under a real offscreen `QApplication`, with injected startup manager and dialog adapter/fakes.
- Static production-source guards for forbidden storage/crypto/registry imports in UI code, sensitive field names, network capabilities, and optional PySide import.

---

### Task 1: Safe HKCU Startup Manager

**Files:**
- Create: `endpoint_agent/src/shielddome_endpoint/startup_manager.py`
- Create: `endpoint_agent/tests/test_startup_manager.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/__init__.py`
- Modify: `endpoint_agent/tests/test_package.py`

**Interfaces:**
- Consumes: injected adapter methods `read_current_user_value(name)`, `write_current_user_value(name, value)`, and `delete_current_user_value(name)`; `sys.executable`; frozen-runtime evidence.
- Produces: `StartupStatusCode`, immutable `StartupStatus`, and `WindowsStartupManager.status()`, `install()`, `uninstall()`.

- [ ] **Step 1: Write and run the first failing startup validation test**

Assert relative paths, `python.exe`, non-frozen processes, wrong executable basenames, and arbitrary `.exe` files return stable unavailable/invalid results without adapter writes. Run `test_startup_manager.py` and record RED because the module does not exist.

- [ ] **Step 2: Implement minimal executable validation and status types**

Accept dependencies in the constructor, resolve without shell invocation, require absolute existing file path, frozen runtime, basename `ShieldDomeEndpoint.exe`, and command encoding as one safely quoted absolute executable path with no arguments.

- [ ] **Step 3: Add and run failing HKCU/idempotency/ownership tests**

Use a fake in-memory adapter that exposes only current-user operations. Assert status for absent, owned, and foreign same-name values; repeated install is unchanged; foreign values are never overwritten; repeated uninstall is unchanged; uninstall deletes only an exact owned value. Assert no HKLM/elevation/task/shell interface exists.

- [ ] **Step 4: Implement the production winreg adapter and manager behavior**

Keep `winreg` private to this module, open only `HKEY_CURRENT_USER` and the fixed Run subkey, use one fixed value name, and translate all implementation failures to stable status codes without returning paths or exception text.

- [ ] **Step 5: Run focused startup/package tests GREEN**

Run `test_startup_manager.py` plus package exports. Confirm fake tests never touch the real registry and core import still succeeds on platforms/import paths without eager Qt loading.

### Task 2: Sample and operation display state in the Presenter

**Files:**
- Modify: `endpoint_agent/src/shielddome_endpoint/desktop_presenter.py`
- Modify: `endpoint_agent/tests/test_desktop_presenter.py`

**Interfaces:**
- Consumes: only `PersonalConsoleService` result methods and sanitized console ViewModels.
- Produces: immutable sample rows/page state, startup display state, operation state, and presenter commands for filter/paging/delete/clear/export/delete-all.

- [ ] **Step 1: Write and run a failing sample list/filter/paging test**

Assert page size 10, all/benign/phishing filters, UTC display time, fixed source labels, visible conflict status, and no sensitive attributes. Confirm RED before implementation.

- [ ] **Step 2: Implement minimal immutable sample display mapping**

Extend desktop state with a flat `ConfirmedExamplePageDisplay`; reset offset on filter changes; retain only the opaque current-page IDs; map failures to fixed safe Chinese copy.

- [ ] **Step 3: Add vertical red-green slices for delete and clear**

Assert the presenter refuses unconfirmed calls, routes confirmed deletion/clear only through the service, refreshes the sample page and dashboard after success, and returns stable notices for not-found/failure without exception text.

- [ ] **Step 4: Add vertical red-green slices for diagnostic export**

Assert missing/cancelled path never calls the service, first call uses `confirmed=True, overwrite=False`, output-exists requires the UI's separate overwrite decision, confirmed overwrite uses `overwrite=True`, and success/cancel/failure states never retain or display the path.

- [ ] **Step 5: Add vertical red-green slices for all-data deletion**

Assert an unconfirmed or wrong confirmation text call is rejected locally; exact confirmed intent calls `delete_all_local_data(confirmed=True)` once; success refreshes dashboard and samples; repeated successful calls remain safe; partial failure uses fixed copy.

- [ ] **Step 6: Run focused presenter/service tests GREEN**

Run presenter and console service suites, including existing pagination, deletion, clearing, export confirmation/overwrite, and idempotent all-data deletion behavior.

### Task 3: Qt Sample Library and Local Data Settings Pages

**Files:**
- Modify: `endpoint_agent/src/shielddome_endpoint/desktop_qt.py`
- Modify: `endpoint_agent/tests/test_desktop_qt.py`
- Modify: `endpoint_agent/tests/test_desktop_privacy.py`

**Interfaces:**
- Consumes: Presenter state/commands, `WindowsStartupManager`, and a dialog adapter wrapping Qt file/confirmation/input dialogs.
- Produces: navigation pages `样本库` and `本地数据`, real startup status/toggle, sample table/filter/paging/destructive confirmations, diagnostics export flow, and delete-all two-step flow.

- [ ] **Step 1: Write and run a failing real-Qt sample page test**

Assert navigation, five safe columns (`确认时间`, `标签`, `来源`, `冲突`, `操作`), filter controls, paging, delete confirmation, clear confirmation, post-success refresh, and absence of sensitive field labels/content. Confirm RED.

- [ ] **Step 2: Build the flat sample library page**

Reuse Phase 7B.1 typography/palette/spacing, place filters and actions in one toolbar, keep row actions compact, show loading/empty/success/failure notices, and style clear as destructive without nested cards.

- [ ] **Step 3: Write and run failing startup/settings interaction tests**

Inject unavailable/disabled/enabled/foreign/failure startup states. Assert the UI text comes from manager results, unavailable development mode reads `安装版提供开机启动`, and toggles never claim success when the manager did not return success.

- [ ] **Step 4: Build the flat local-data settings page**

Add startup, diagnostics export, and destructive local-data sections separated by rules. Use a dialog adapter so tests choose/cancel paths and confirmations without native dialogs. Do not display or persist chosen paths.

- [ ] **Step 5: Add diagnostic overwrite and delete-all dialog tests**

Assert export requires file selection and confirmation, existing target creates a separate overwrite confirmation, cancel is visible, and delete-all requires an explanatory confirmation followed by exact text entry before any service call.

- [ ] **Step 6: Implement the dialog flows and stable copy**

Use `QFileDialog` only after the user clicks export; use separate `QMessageBox` prompts for export and overwrite; use a first destructive explanation and a second `QInputDialog` exact-text gate for delete-all. Never open, preview, upload, log, or auto-launch output.

- [ ] **Step 7: Strengthen privacy/offline/import topology guards**

Allow only `startup_manager` to import `winreg`; assert UI/presenter do not import registry, stores, crypto, diagnostic implementation, or sensitive field names; assert no socket/network/server literals or calls; block PySide6 and verify core package import.

- [ ] **Step 8: Run real offscreen Qt and privacy suites GREEN**

Run `test_desktop_qt.py`, presenter tests, privacy tests, and all new Phase 7B.2A tests under `.venv-ui` with `QT_QPA_PLATFORM=offscreen`.

### Task 4: Documentation, Phase State, and Visual Evidence

**Files:**
- Modify: `endpoint_agent/README.md`
- Modify: `endpoint_agent/DEVELOPMENT_PLAN.md`
- Modify: `endpoint_agent/docs/USAGE.md`
- Modify: `endpoint_agent/AGENTS.md`
- Modify: `endpoint_agent/docs/plans/2026-08-10-phase-7b2a-local-data-management.md`
- Generate ignored: `endpoint_agent/dist/phase7b2a/screenshots/1366x768-samples.png`
- Generate ignored: `endpoint_agent/dist/phase7b2a/screenshots/1024x720-local-data.png`
- Generate ignored: `endpoint_agent/dist/phase7b2a/screenshots/diagnostic-export-confirmation.png`
- Generate ignored: `endpoint_agent/dist/phase7b2a/screenshots/delete-all-double-confirmation.png`

**Interfaces:**
- Consumes: verified implementation and real Qt rendering.
- Produces: accurate usage/security documentation, four visually inspected captures, and truthful phase status.

- [ ] **Step 1: Update product and usage documentation**

Document HKCU-only packaged-entry constraints, unavailable development behavior, sample privacy fields, export confirmations/no-overwrite default, delete-all scope, offline behavior, and the fact that no `.eml`, networking, upload, updater, or executable packaging was added.

- [ ] **Step 2: Record the Phase 7B.2B blocker and exact states**

Keep Phase 7 and Phase 7B `in_progress`; keep Phase 7B.1 `complete`; add Phase 7B.2A `complete` only after all acceptance evidence; add Phase 7B.2B `pending`; keep Phase 7C `pending`. State that false-positive/false-negative confirmation is blocked because neither Endpoint Evidence Records nor desktop ViewModels safely provide the required `FeatureVector`.

- [ ] **Step 3: Capture the four required real-Qt screenshots**

Use injected safe test data through the public service/presenter seams, render the sample page at 1366x768 and settings at 1024x720, and capture the diagnostic and delete-all confirmation dialogs without real local-data deletion or registry mutation.

- [ ] **Step 4: Inspect every capture at original resolution and iterate**

Check table/filter/button/dialog overlap, clipping, minimum-size behavior, danger hierarchy, visible unavailable/cancel/failure states, and absence of paths or sensitive fields. Recapture after any correction.

### Task 5: Fresh Completion Verification

**Files:**
- Modify only when evidence reveals a defect: files already listed above.

**Interfaces:**
- Consumes: all Phase 7B.2A code/docs/tests and ignored visual artifacts.
- Produces: fresh evidence for each final claim, without commit or push.

- [ ] **Step 1: Run Phase 7B.2A focused tests**

Run startup, presenter, Qt, privacy, console service, and local-data command test modules and report exact run/skip/failure counts.

- [ ] **Step 2: Run the complete Endpoint Agent suite**

Set `QT_QPA_PLATFORM=offscreen` and run `unittest discover -s endpoint_agent/tests -v` with `.venv-ui`; report the exact actual count and skip.

- [ ] **Step 3: Verify GUI runtime and Wheel**

Print PySide6 and tzdata versions, rerun the real offscreen GUI suite, and build the Wheel with `pip wheel --no-index --no-deps` into `endpoint_agent/dist/phase7b2a`.

- [ ] **Step 4: Run diff, scope, and whitespace checks**

Run `git diff --check -- endpoint_agent`, `git status --short`, `git diff --stat`, `git diff --cached`, and protected-directory status/diff checks for `app shielddome frontend extension web deploy scripts`. Compare against the initial untracked-file baseline and do not alter it.

- [ ] **Step 5: Re-read this plan and report only evidenced results**

Confirm every Phase 7B.2A requirement maps to implementation/test/visual evidence, explicitly list anything not executed or not passing, and do not describe unexecuted validation as successful.

## Frontend Design Direction

**Subject:** The current Windows user's offline phishing-defense instrument; the added pages let that user curate sanitized local evidence and explicitly control local-data operations.

**Single job:** Make consequential local actions understandable, deliberate, and reversible where possible while keeping the everyday sample ledger compact.

**Palette:** Graphite `#202A2F`, Paper `#F4F5F2`, Ink `#172126`, Signal teal `#2B7772`, Warning `#B46B2A`, Critical `#A23A36`.

**Typography:** `Segoe UI Variable Display` for restrained page headings, `Segoe UI` for controls/table copy, and `Cascadia Mono` for timestamps and confirmation literals.

**Layout:** Extend the existing 188 px instrument rail with two entries. Samples use one ledger plus one toolbar; settings uses three ruled horizontal zones rather than cards.

```text
┌──────────────┬──────────────────────────────────────────────────────────┐
│ SHIELDDOME   │  已确认样本                         [筛选] [清空全部]    │
│              ├──────────────────────────────────────────────────────────┤
│ 安全概览     │  确认时间 │ 标签 │ 来源 │ 冲突 │ 操作                │
│ 最近事件     │  …                                               [删除] │
│ 已确认样本   ├──────────────────────────────────────────────────────────┤
│ 本地数据     │  第 1 / N 页                         [上一页] [下一页]  │
│              │                                                          │
│ 仅本机数据   │  状态 / 成功 / 失败固定文案                             │
└──────────────┴──────────────────────────────────────────────────────────┘

┌──────────────┬──────────────────────────────────────────────────────────┐
│ 本地数据     │  开机启动       真实状态          [启用 / 停用]         │
│              ├──────────────────────────────────────────────────────────┤
│              │  诊断包         用户选路          [导出诊断包]          │
│              ├──────────────────────────────────────────────────────────┤
│              │  危险操作       删除类别说明      [删除全部本地数据]    │
└──────────────┴──────────────────────────────────────────────────────────┘
```

**Signature:** The settings page uses a restrained three-zone “local custody ledger”: each row states what remains on the device, who initiates it, and whether it is reversible. The one expressive accent is the critical-red destructive zone, used nowhere else as a large action treatment.

**Self-critique:** A generic settings page would use nested cards and toggle switches that imply success optimistically. This design uses ruled rows and explicit state text from the startup module, preserving the instrument-like Phase 7B.1 identity and making destructive operations visibly different without creating a new visual system.

## Execution Evidence

- Baseline: 265 tests passed with 1 packaged-Host skip before implementation.
- TDD red evidence: Startup Manager first failed with 3 missing-module errors; local-data Presenter first failed with 2 missing-interface errors; the first Qt interaction run exposed and then fixed unavailable startup controls being re-enabled by refresh.
- Phase 7B.2A focused verification: 17 tests passed across startup, local-data Presenter/Qt, existing Presenter/Qt, privacy, optional-PySide, and zero-network modules.
- Full verification: 271 tests passed with 1 existing packaged-Host skip under `QT_QPA_PLATFORM=offscreen`.
- Runtime: PySide6 6.8.3 and tzdata 2026.3.
- Offline Wheel: `shielddome_endpoint-0.1.0-py3-none-any.whl`, 81,363 bytes, SHA-256 `bbb8ee57c065648ce58ec80706fe7d745a7bb7b950fd335aea4eec6b21872f33`.
- Visuals: four ignored PNG captures were generated and inspected for geometry. The offscreen capture rendered Chinese glyphs as square placeholders, so Chinese font appearance is not recorded as accepted.
- Git: `git diff --check -- endpoint_agent` exited zero; the index is empty; no tracked changes exist in protected directories. Pre-existing root/docs/scripts untracked user files remain untouched.
