# Phase 7A Personal Console Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the GUI-independent, per-Windows-user application service and immutable ViewModels needed by a future Personal Security Dashboard, including bounded dashboard/event/example queries and explicitly confirmed local-data commands.

**Architecture:** `console_models.py` defines the complete immutable and versioned UI boundary; it contains only sanitized scalar values and nested ViewModels. `PersonalConsoleService` is the sole deep module exposed to a future UI and owns bounded reads, local-time aggregation, health degradation, opaque in-process example command IDs, and exception sanitization. `LocalDataCommands` coordinates existing encrypted evidence/example stores and the existing diagnostic exporter, including best-effort all-data deletion and current-user diagnostic temporary cleanup, without exposing SQLite, DPAPI, AES-GCM, paths, fingerprints, or feature vectors through ViewModels.

**Tech Stack:** Python 3.12, standard-library `dataclasses`, `enum`, `datetime`/`zoneinfo`, `pathlib`, `unittest`, existing per-user SQLite/DPAPI/AES-256-GCM stores; no new dependency.

## Global Constraints

- Modify only `endpoint_agent/`; preserve all pre-existing tracked and untracked work, including Phase 6A, Phase 6B, and Phase 6C.
- Implement Phase 7A only. Do not implement Phase 7B tray/desktop UI, PySide6, charts, browser-based UI, Phase 7C `.eml` intake, mail parsing, shell integration, or later phases.
- Keep Phase 7 `in_progress`, mark Phase 7A `complete` only after fresh verification, and keep Phase 7B/7C `pending`.
- Keep Phase 3 `pending`, Phase 4B `pending`, Phase 5B `in_progress`, and their parent phase states unchanged.
- UI callers use only `PersonalConsoleService`; they never open SQLite, read keys, invoke DPAPI/AES-GCM, or traverse the current-user data directory.
- All persisted data comes from the current Windows user's existing encrypted stores under `%LOCALAPPDATA%\ShieldDome\EndpointAgent`; never introduce a shared or cross-user store.
- All reads are bounded to 4,096 evidence records, 512 example rows, event pages of at most 50, example pages of at most 50, event offsets of at most 4,096, and example offsets of at most 256.
- Inject an aware clock and local timezone; compare persisted UTC timestamps against local calendar-day boundaries for today's count and the fifteen-day trend.
- Never return subject/body, sender/recipient/address, URL/query, attachment name/content, `.eml`, `FeatureVector`, sample fingerprint, similarity/vector data, key/nonce/tag/ciphertext, username/SID/hostname, absolute data path, exception text, or traceback.
- Empty read-only queries must not create a database, key, WAL, SHM, journal, or temporary file.
- Store corruption and cross-user key failures produce fixed health/status codes and no partial data.
- Confirmation commands require `confirmed is True`; no detection, query, low-risk result, or background operation confirms a sample or exports diagnostics.
- Delete-all attempts evidence deletion, example deletion, and owned diagnostic-temporary cleanup even when one step fails; it returns a fixed complete or partial-failure code without sensitive details.
- Production source remains offline: no network client, HTTP/WebSocket/RPC, browser console, TCP/UDP listener, telemetry, upload, scheduler, or background thread.
- Do not commit, push, create a branch, or create a PR.

## Confirmed Public Test Seams

- Immutable ViewModel/result contracts exported from `shielddome_endpoint.console_models`.
- `PersonalConsoleService` public query and command methods; tests observe return values only.
- Existing encrypted `EvidenceStore`, `ExampleStore`, and `DiagnosticExporter` are system boundaries injected into the service/command layer; time, timezone, and opaque-ID generation are injected test boundaries.

---

### Task 1: Immutable versioned console result and ViewModel contracts

**Files:**
- Create: `endpoint_agent/src/shielddome_endpoint/console_models.py`
- Create: `endpoint_agent/tests/test_console_models.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/__init__.py`

**Interfaces:**
- Consumes: only sanitized enum/string/count/time values.
- Produces: `CONSOLE_VIEW_MODEL_SCHEMA_VERSION = "1.0"`; `ConsoleStatusCode`; `ConsoleHealthStatus`; `ModelRuntimeStatus`; immutable `ConsoleOperationResult`, `StoreHealthViewModel`, `AgentStatusSummary`, `DailyDetectionCount`, `DistributionCount`, `DashboardViewModel`, `EventListItemViewModel`, `EventDetailViewModel`, `EventPageViewModel`, `ConfirmedExampleListItemViewModel`, and `ConfirmedExamplePageViewModel`.

- [x] **Step 1: Write the failing immutability/version/privacy test**

```python
dashboard = DashboardViewModel(
    generated_at_utc=NOW,
    local_timezone="Asia/Shanghai",
    agent_status=AgentStatusSummary(
        agent_status=ConsoleHealthStatus.HEALTHY,
        model_status=ModelRuntimeStatus.DEGRADED,
        rules_only=True,
        evidence_store_health=StoreHealthViewModel(
            ConsoleHealthStatus.HEALTHY, 1, None
        ),
        example_library_health=StoreHealthViewModel(
            ConsoleHealthStatus.EMPTY, 0, None
        ),
    ),
    today_detection_count=1,
    daily_trend=(DailyDetectionCount("2026-08-05", 1),),
    risk_distribution=(DistributionCount("high", 1),),
    source_distribution=(DistributionCount("browser_native", 1),),
    model_abstention_count=0,
    model_failure_count=1,
    rules_only_degradation_count=1,
)
self.assertEqual(dashboard.schema_version, "1.0")
with self.assertRaises(FrozenInstanceError):
    dashboard.today_detection_count = 2
for forbidden in ("body", "address", "url", "feature_vector", "fingerprint", "ciphertext"):
    self.assertNotIn(forbidden, tuple(field.name for field in fields(type(dashboard))))
```

- [x] **Step 2: Run the focused module and confirm red**

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_console_models.py" -v`

Expected: FAIL because `shielddome_endpoint.console_models` does not exist.

- [x] **Step 3: Implement strict frozen/slotted contracts**

Use `@dataclass(frozen=True, slots=True)` for every ViewModel/result type. `StoreHealthViewModel` has `status`, `item_count`, `error_code`, and `schema_version`; `AgentStatusSummary` has `agent_status`, `model_status`, `rules_only`, both store-health values, and `schema_version`. Validate exact schema versions, aware UTC generation/detail times, non-negative integer counts, sorted unique category/date tuples, fixed status enums, page bounds, and safe opaque IDs matching `^example-[0-9a-f]{32}$`. `ConsoleOperationResult` has exactly `code`, `payload`, `affected_items`, and `schema_version`; it has no message/exception/traceback field.

- [x] **Step 4: Add red-green slices for invalid counts, duplicate/sorted categories, naive times, bad page bounds, and forbidden field topology**

Run the focused module after each slice. Expected literals must be independent fixed values, not recomputed with production helpers.

### Task 2: Local-time dashboard aggregation and controlled health

**Files:**
- Create: `endpoint_agent/src/shielddome_endpoint/console_service.py`
- Create: `endpoint_agent/tests/test_console_service.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/__init__.py`

**Interfaces:**
- Consumes: injected `EvidenceStore`, `ExampleStore`, aware `clock: Callable[[], datetime]`, `local_timezone: tzinfo`, and the ViewModels from Task 1.
- Produces: `CONSOLE_EVIDENCE_SCAN_MAX_RECORDS = 4096`; `CONSOLE_EVENT_PAGE_MAX_ITEMS = 50`; `CONSOLE_EVENT_PAGE_MAX_OFFSET = 4096`; `PersonalConsoleService.get_dashboard() -> ConsoleOperationResult`.

- [x] **Step 1: Write a failing local-midnight and zero-filled trend test**

```python
service = PersonalConsoleService(
    evidence_store=StaticEvidenceStore(records),
    example_store=StaticExampleStore(),
    clock=lambda: datetime(2026, 8, 5, 15, 30, tzinfo=timezone.utc),
    local_timezone=ZoneInfo("Asia/Shanghai"),
)
result = service.get_dashboard()
self.assertIs(result.code, ConsoleStatusCode.SUCCESS)
self.assertEqual(result.payload.today_detection_count, 1)
self.assertEqual(result.payload.daily_trend[0], DailyDetectionCount("2026-07-22", 0))
self.assertEqual(result.payload.daily_trend[-1], DailyDetectionCount("2026-08-05", 1))
```

- [x] **Step 2: Run the focused module and confirm red**

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_console_service.py" -v`

Expected: FAIL because `PersonalConsoleService` does not exist.

- [x] **Step 3: Implement one bounded all-or-nothing evidence scan and dashboard aggregation**

Read ordered evidence in pages of at most 100, stop at 4,096, issue one bounded overflow probe, and return `query_limit_exceeded` rather than truncating. Convert each UTC `detected_at` to the injected local timezone; include only local dates from today minus 14 days through today and never include a future timestamp. Emit exactly fifteen ascending date buckets, all four risk buckets, sorted source buckets, abstention count, model failure count (`timeout`, `error`, or invalid model output), and rules-only degradation count (`record.degraded`). Derive the recent model summary from the newest retained record and expose only fixed health/status enums.

- [x] **Step 4: Add red-green distribution/status and corruption slices**

Test exact risk/source/refusal/failure/degradation literals. A failing or partially failing store returns a dashboard with `evidence_store` health `unavailable`, fixed code `evidence_store_unavailable`, and zero event aggregates; exception type/text is absent. Example aggregate failures affect only example health. No partial counts survive either store failure.

- [x] **Step 5: Add red-green empty and cross-user slices**

Use real `EvidenceStore`/`ExampleStore` under a patched current-user root and prove `get_dashboard()` creates no DB/key/sidecar. Use injected current-user protectors for user A/user B and prove user B receives only controlled unavailable health and zero data.

### Task 3: Bounded recent-event list and sanitized detail

**Files:**
- Modify: `endpoint_agent/src/shielddome_endpoint/console_service.py`
- Modify: `endpoint_agent/tests/test_console_service.py`

**Interfaces:**
- Consumes: the same bounded recent evidence scan from Task 2.
- Produces: `PersonalConsoleService.list_recent_events(*, offset=0, limit=50) -> ConsoleOperationResult`; `PersonalConsoleService.get_event_detail(local_event_id) -> ConsoleOperationResult`.

- [x] **Step 1: Write a failing pagination and exact allowed-fields test**

```python
page = service.list_recent_events(offset=1, limit=1).payload
self.assertEqual(page.items[0].local_event_id, "event-second")
self.assertTrue(page.has_more)
self.assertEqual(
    tuple(field.name for field in fields(EventListItemViewModel)),
    ("local_event_id", "detected_at_utc", "risk_level", "detection_status", "generic_action", "source_kind", "abstained", "degraded", "model_execution_status", "error_code", "schema_version"),
)
```

- [x] **Step 2: Run the focused module and confirm red, then implement list mapping**

Filter to the same fifteen local dates, preserve newest-first ordering, slice only after the bounded scan, and calculate `has_more` without unbounded reads. Reject bool/non-int/negative/over-limit pagination with `invalid_request`.

- [x] **Step 3: Write a failing sanitized detail/not-found/empty-store test, then implement**

`EventDetailViewModel` may add only `rule_codes` to the list fields. Guard `database_path.exists()` before any direct lookup so an empty detail query cannot create a key or database. Return `not_found`, `evidence_store_unavailable`, or `success` only; do not return exception text or a record outside the current local fifteen-day window.

- [x] **Step 4: Add privacy and resource-bound red-green slices**

Seed synthetic forbidden mail values and assert none appears in `repr(page)`, `repr(detail)`, dataclass field names, or result objects. Verify the evidence page size/offset/scan maxima exactly and verify one corrupt encrypted row yields no partial page/detail.

### Task 4: Confirmed Example Library queries and explicit feedback commands

**Files:**
- Create: `endpoint_agent/src/shielddome_endpoint/local_data_commands.py`
- Create: `endpoint_agent/tests/test_local_data_commands.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/console_service.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/__init__.py`

**Interfaces:**
- Consumes: `ExampleStore`, strict `FeatureVector`, `ExampleSource.BROWSER_NATIVE`, injected clock, injected `example_id_factory: Callable[[], str]`, and existing confirmation enums.
- Produces: `CONSOLE_EXAMPLE_PAGE_MAX_ITEMS = 50`; `CONSOLE_EXAMPLE_PAGE_MAX_OFFSET = 256`; `LocalDataCommands.confirm_benign`; `confirm_phishing`; `delete_example`; `clear_examples`; plus service methods with the same names and `PersonalConsoleService.list_confirmed_examples(*, offset=0, limit=50, label=None)`.

- [x] **Step 1: Write a failing sanitized page/filter test**

```python
result = service.list_confirmed_examples(label=ExampleLabel.BENIGN)
self.assertEqual(result.payload.items[0].label, "benign")
self.assertRegex(result.payload.items[0].example_id, r"^example-[0-9a-f]{32}$")
self.assertFalse(hasattr(result.payload.items[0], "feature_vector"))
self.assertNotIn(example.keyed_fingerprint, repr(result))
```

- [x] **Step 2: Implement bounded sample mapping with opaque in-process command IDs**

Read at most the existing 512-row calibration bound, filter by strict `ExampleLabel | None`, apply offset/limit, calculate conflicts in memory, and create an injected opaque ID for each returned row. Keep a bounded map of at most 256 current IDs to `(keyed_fingerprint, label)` inside the service; never serialize or expose the mapped values. Refreshing a page may issue new IDs.

- [x] **Step 3: Write failing explicit benign/phishing confirmation tests, then implement**

```python
self.assertIs(service.confirm_benign(vector, confirmed=False).code, ConsoleStatusCode.CONFIRMATION_REQUIRED)
self.assertFalse(example_store.database_path.exists())
self.assertIs(service.confirm_phishing(vector, confirmed=True).code, ConsoleStatusCode.EXAMPLE_ADDED)
```

Require exact `confirmed is True`, call only the existing strict `ExampleStore.confirm`, and map `added`, `duplicate`, `conflict`, invalid input, capacity, unavailable, and unexpected failures to fixed console status codes. Never confirm during detection/query construction.

- [x] **Step 4: Write failing delete-one and clear tests, then implement**

Delete only an opaque ID previously returned by this service instance. Clear requires exact confirmation and clears the opaque map. Return `not_found`, `confirmation_required`, `success`, `example_store_unavailable`, or `command_failed` without exception details. Verify delete/clear remove the selected/all samples, database sidecars, and example key.

### Task 5: Explicit diagnostic export and coordinated all-local-data deletion

**Files:**
- Modify: `endpoint_agent/src/shielddome_endpoint/local_data_commands.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/console_service.py`
- Modify: `endpoint_agent/tests/test_local_data_commands.py`

**Interfaces:**
- Consumes: existing `DiagnosticExporter`, existing `EvidenceStore.delete_all`, existing `ExampleStore.clear`, current-user root from `default_user_data_directory`, and exact confirmation booleans.
- Produces: `PersonalConsoleService.export_diagnostics(output_path, *, confirmed, overwrite=False)`; `PersonalConsoleService.delete_all_local_data(*, confirmed)`; stable `ConsoleOperationResult` codes and affected counts only.

- [x] **Step 1: Write failing diagnostic confirmation/path/result mapping tests**

Verify `confirmed=False`, `1`, `"yes"`, and `None` never invoke the exporter. With `confirmed=True`, pass the caller-selected path and exact overwrite boolean to the existing exporter; return only fixed codes and a safe affected count, not the absolute output path/hash in a ViewModel. Map known exporter codes to fixed console codes and all other failures to `command_failed`.

- [x] **Step 2: Write a failing coordinated deletion test**

```python
result = service.delete_all_local_data(confirmed=True)
self.assertIs(result.code, ConsoleStatusCode.SUCCESS)
for path in (evidence_db, evidence_wal, evidence_shm, evidence_key, example_db, example_wal, example_shm, example_key, diagnostic_temp):
    self.assertFalse(path.exists())
```

- [x] **Step 3: Implement best-effort coordination and owned-temp cleanup**

If confirmation is not exactly `True`, perform no mutation. Otherwise attempt evidence deletion, example deletion, and cleanup of the exact current-user `diagnostic-temp` subtree independently. Never follow directory symlinks and never delete outside the resolved Endpoint Agent root. Return `success` only when all three steps succeed; otherwise return `local_data_delete_partial_failure` after all steps have been attempted. Clear cached example IDs in both outcomes.

- [x] **Step 4: Add failure-isolation and idempotency red-green slices**

Inject a failure in each deletion/export/confirmation collaborator and prove results contain only stable codes, no exception text/stack, and a subsequent call to `LocalDetectionService().detect(observation, local_event_id="event-command-failure", observed_now=NOW)` still returns its normal four-field projection. Repeated all-data deletion returns success and leaves every owned database/key/sidecar/temp path absent.

### Task 6: Package, offline guards, documentation, status, and fresh verification

**Files:**
- Modify: `endpoint_agent/tests/test_build.py`
- Modify: `endpoint_agent/tests/test_package.py`
- Modify: `endpoint_agent/tests/test_offline_constraints.py`
- Modify: `endpoint_agent/README.md`
- Modify: `endpoint_agent/DEVELOPMENT_PLAN.md`
- Modify: `endpoint_agent/docs/USAGE.md`
- Modify: `endpoint_agent/AGENTS.md`
- Modify: `endpoint_agent/docs/plans/2026-08-05-phase-7a-personal-console-service.md`

**Interfaces:**
- Consumes: the verified Task 1–5 public APIs and fresh command output.
- Produces: Wheel inclusion, offline/static proof, Phase 7A usage documentation, conservative phase states, and final evidence; no commit or push.

- [x] **Step 1: Add package/Wheel red-green coverage**

Require public import of the console schema/version, ViewModels, status enums, and `PersonalConsoleService`. Require `console_models.py`, `console_service.py`, and `local_data_commands.py` in the offline Wheel; add no dependency.

- [x] **Step 2: Add the Phase 7A offline/static guard**

Scan the three new production sources and reject `import socket`, network/client/server framework names, `.connect(`, `.bind(`, `.listen(`, URL literals, upload/telemetry, HTTP/WebSocket/RPC, browser launch, PySide6, `.eml` parsing, threading, scheduler, and subprocess code. Verify command failures cannot alter `LocalDetectionService`.

- [x] **Step 3: Update documentation and statuses only after focused/full tests pass**

Document the service-only Phase 7A API, local-time semantics, fifteen-day/4,096-record/50-item/512-row/256-offset bounds, exact privacy fields, controlled health, opaque example command IDs, explicit confirmation requirements, coordinated deletion, and zero network/listener behavior. Split Phase 7 into Phase 7A/7B/7C; set Phase 7 `in_progress`, Phase 7A `complete`, Phase 7B/7C `pending`, and leave Phase 3/4B/5B unchanged.

- [x] **Step 4: Run every required command freshly**

```powershell
python -m unittest discover -s endpoint_agent/tests -v
python -m unittest discover -s endpoint_agent/tests -p "test_console_models.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_console_service.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_local_data_commands.py" -v
node --check endpoint_agent/extension/background.js
node --check endpoint_agent/extension/content.js
python -m pip wheel --no-index --no-deps .\endpoint_agent --wheel-dir .\endpoint_agent\dist\phase7a
git status --short
git diff --stat
git diff -- endpoint_agent
git status --short -- app shielddome frontend extension web deploy scripts
```

- [ ] **Step 5: Audit requirements and record exact evidence**

Record total passed/failed/error/skipped counts, focused counts, JavaScript exits, Wheel result, local-user isolation, privacy topology, deletion paths, no-network proof, modified files, starting-versus-ending Git state, and the unchanged packaged-Host skip reason. Confirm no staged content and no forbidden directory changes.

## Execution Evidence

Observed on 2026-08-05 after the implementation and phase-status documentation changes:

- `python -m unittest discover -s endpoint_agent/tests -v`: exit 0; 249 run, 248 passed, 0 failed, 0 errors, 1 skipped. The skip is the pre-existing packaged Native Host check because no executable is available in this environment.
- `test_console_models.py`: exit 0; 5 passed, 0 failed/errors/skipped.
- `test_console_service.py`: exit 0; 13 passed, 0 failed/errors/skipped.
- `test_local_data_commands.py`: exit 0; 8 passed, 0 failed/errors/skipped.
- `node --check endpoint_agent/extension/background.js`: exit 0.
- `node --check endpoint_agent/extension/content.js`: exit 0.
- Offline no-dependency Wheel build: exit 0; `shielddome_endpoint-0.1.0-py3-none-any.whl`, 62,452 bytes, SHA-256 `ad99e058b3adaecdb485fed5f9bac8fe376286ac8b430c2a31aed234c5369f15`.
- `git diff --check`: exit 0. Final Git inspection reported only `endpoint_agent/` tracked/new Phase 7A files plus unrelated untracked files that were already present at the starting snapshot; no staged changes and no tracked changes under `app`, `shielddome`, `frontend`, `extension`, `web`, `deploy`, or root `scripts`.
