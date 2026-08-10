# Phase 7B.2B Pending Confirmation Context Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow the current Windows user to explicitly confirm a sanitized historical event as benign or phishing without exposing or reconstructing its `FeatureVector`.

**Architecture:** A deep `PendingConfirmationStore` module owns a separate encrypted SQLite store and exposes only put/consume/delete/clear operations keyed by `local_event_id`. `LocalDetectionService` publishes its pipeline-produced, privacy-scanned vector to a trusted callback; Native Host best-effort persists it, while `PersonalConsoleService` atomically orders sample confirmation before context deletion. Presenter and Qt cross only the event-confirmation interface and never receive vectors.

**Tech Stack:** Python 3.12, `unittest`, SQLite, current-user DPAPI, `cryptography==49.0.0` AES-256-GCM, PySide6 Widgets 6.8.3.

## Global Constraints

- Modify only `endpoint_agent/`; never modify protected application directories.
- Implement Phase 7B.2B only; no Phase 7C, Phase 8, `.eml`, model, installer, network, protocol, upload, update, or telemetry work.
- Preserve the Endpoint Evidence Record schema and the plugin's exact four-field projection.
- Persist only a Feature Pipeline-produced, PrivacyScanner-approved `FeatureVector`; never persist MailObservation, raw content, addresses, URLs, query parameters, or attachment names/content.
- Use a separate current-user DPAPI key, AES-256-GCM nonce per record, minimal plaintext index, and a maximum 15-day retention.
- Detection remains successful if pending-context persistence fails.
- Sample write precedes context deletion; failed writes retain context; duplicate confirmation does not duplicate samples.
- UI submits only event ID, target label, and explicit confirmation, and never exposes vector/fingerprint/model internals.
- Do not commit or push.

## Confirmed Public Test Seams

- `PendingConfirmationStore.put(...)`, `get(...)`, `delete(...)`, `cleanup_expired(...)`, and `clear()`.
- `LocalDetectionService.detect(...)` with an injected trusted feature callback.
- `NativeHostHandler(...)` with an injected pending-context store factory; native request/response protocol remains unchanged.
- `PersonalConsoleService.confirm_event_benign(local_event_id, *, confirmed)` and `confirm_event_phishing(...)`.
- `PersonalConsolePresenter.confirm_event_*` and `ShieldDomeMainWindow` event-detail actions.

---

### Task 1: Encrypted Pending Confirmation Context module

**Files:**
- Create: `endpoint_agent/src/shielddome_endpoint/pending_confirmation.py`
- Create: `endpoint_agent/src/shielddome_endpoint/pending_confirmation_store.py`
- Create: `endpoint_agent/tests/test_pending_confirmation_store.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/__init__.py`

**Interfaces:**
- Produces: immutable strict `PendingConfirmationContext`; store methods keyed only by event ID, with stable `PendingConfirmationStoreError.code`.

- [ ] Write one failing strict-schema/privacy/resource-limit test, run it RED, implement canonical serialization using existing FeatureVector validation plus `PrivacyScanner`, and run GREEN.
- [ ] Write failing current-user DPAPI/cross-user and random-nonce tests, run RED, implement a dedicated `UserDataKeyManager` configuration and AESGCM record encryption, then run GREEN.
- [ ] Write failing ciphertext/tag/index/key tamper and plaintext-search tests, run RED, bind event ID/version/expiry as associated data, validate exact SQLite columns, then run GREEN.
- [ ] Write failing 15-day boundary, deletion, sidecar/key clear tests, run RED, implement cleanup and secure clear using existing deletion/key modules without changing Evidence Record schema, then run GREEN.

### Task 2: Trusted detection capture and Native Host failure isolation

**Files:**
- Modify: `endpoint_agent/src/shielddome_endpoint/local_detection.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/native_host.py`
- Modify: `endpoint_agent/tests/test_local_detection.py`
- Modify: `endpoint_agent/tests/test_native_host.py`

**Interfaces:**
- Consumes: internal callback `(local_event_id, FeatureVector, detected_at) -> None`.
- Produces: best-effort pending context persistence without protocol changes.

- [ ] Write a failing Local Detection callback test proving the callback receives the exact pipeline vector and that callback failure does not alter the outcome; implement minimally and run GREEN.
- [ ] Write a failing Native Host test proving put/cleanup failure leaves the exact four-field response unchanged; inject a pending-store factory, implement best-effort persistence, and run GREEN.
- [ ] Add static assertions that no confirmation Native Messaging command or plugin field was added; run native/plugin suites GREEN.

### Task 3: Event confirmation orchestration and failure atomicity

**Files:**
- Modify: `endpoint_agent/src/shielddome_endpoint/console_models.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/console_service.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/local_data_commands.py`
- Modify: `endpoint_agent/tests/test_console_service.py`
- Modify: `endpoint_agent/tests/test_local_data_commands.py`

**Interfaces:**
- Produces: `confirm_event_benign(local_event_id, *, confirmed)` and phishing counterpart returning only stable operation codes.

- [ ] Write and run RED tests for missing explicit confirmation, invalid/missing/expired/corrupt/unavailable contexts and stable codes; implement lookup/error mapping and run GREEN.
- [ ] Write and run RED tests proving sample success then context deletion, sample failure retention, duplicate idempotency, and delete failure stability; implement ordered orchestration and run GREEN.
- [ ] Write and run RED test that delete-all destroys the new database, sidecars, and key; register the store in `LocalDataCommands`, implement, and run GREEN.

### Task 4: Presenter and explicit Qt event-detail interaction

**Files:**
- Modify: `endpoint_agent/src/shielddome_endpoint/desktop_presenter.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/desktop_qt.py`
- Modify: `endpoint_agent/tests/test_desktop_presenter.py`
- Modify: `endpoint_agent/tests/test_desktop_qt.py`
- Modify: `endpoint_agent/tests/test_desktop_privacy.py`

**Interfaces:**
- Consumes: event ID and explicit boolean only.
- Produces: two deliberate event-detail actions, fixed safe notices, and sample-page refresh.

- [ ] Write a failing presenter test proving only event ID/confirmation crosses the seam and no display state exposes FeatureVector/fingerprint; implement commands and stable copy, run GREEN.
- [ ] Write a failing real offscreen Qt test for two buttons, mandatory privacy confirmation dialog, success refresh, missing/expired message, and no auto-label/batch behavior; implement minimal flat actions and run GREEN.
- [ ] Add privacy/import/network/protocol guards and geometry assertions at 1366x768 and 1024x720; run GREEN.

### Task 5: Documentation, phase state, visuals, and fresh verification

**Files:**
- Modify: `CONTEXT.md`
- Modify: `endpoint_agent/AGENTS.md`
- Modify: `endpoint_agent/README.md`
- Modify: `endpoint_agent/DEVELOPMENT_PLAN.md`
- Modify: `endpoint_agent/docs/USAGE.md`
- Generate ignored: `endpoint_agent/dist/phase7b2b/screenshots/*.png`

**Interfaces:**
- Produces: accurate domain glossary, usage/security documentation, truthful phase state, and visual evidence.

- [ ] Add the implementation-free `Pending Confirmation Context` glossary term and document privacy, retention, stable failures, confirmation semantics, and deletion scope.
- [ ] Keep Phase 7 `in_progress`, Phase 7C `pending`, and only after all gates pass mark Phase 7B.2B and Phase 7B `complete` while retaining 7B.1/7B.2A `complete`.
- [ ] Generate and inspect original-resolution 1366x768 and 1024x720 event-confirmation screens plus success and expired states; iterate on overlap/clipping.
- [ ] Run focused Phase 7B.2B tests, full offscreen Endpoint Agent tests, real GUI suite, offline Wheel, `git diff --check -- endpoint_agent`, Git status/stat/index checks, and protected-directory checks; report exact evidence and any failure.

## Self-Review

- Spec coverage: storage schema/privacy/crypto/tamper/retention, trusted capture, atomic confirmation, deletion, UI interaction, offline/protocol invariants, documentation, visuals, and all completion gates are assigned.
- Placeholder scan: no deferred implementation placeholder is present.
- Type consistency: all callers use `local_event_id`; only trusted detection code handles `FeatureVector`; UI uses the two `confirm_event_*` interfaces.
