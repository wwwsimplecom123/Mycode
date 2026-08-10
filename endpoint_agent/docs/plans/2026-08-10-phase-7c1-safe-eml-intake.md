# Phase 7C.1 Safe EML Intake Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add explicit, bounded, read-only local `.eml` intake that feeds the existing local detection and encrypted persistence chain without adding UI or network capability.

**Architecture:** `SafeEmlReader` is a deep module whose small interface hides path validation, identity checks, bounded file reading, standard-library MIME parsing, safe body/link extraction, and attachment-metadata minimization. `LocalMailIntakeService` is the orchestration seam: it requires explicit confirmation, creates private local identity, invokes `LocalDetectionService`, and performs evidence and pending-context persistence on a best-effort basis.

**Tech Stack:** Python 3.12 standard library `email`, immutable existing domain contracts, `unittest`, existing encrypted stores, and the offline Wheel builder.

## Global Constraints

- Modify only `endpoint_agent/` plus the root domain glossary `CONTEXT.md`; do not modify protected application directories.
- Implement Phase 7C.1 only; no drag/drop UI, file picker, mail-client adapter, Phase 8, network, model, updater, telemetry, attachment-content inspection, or plugin protocol change.
- Treat every `.eml` and path as untrusted; never copy, mutate, move, delete, execute, preview, decompress, or externally resolve message content.
- Tests use synthetic messages without personal information and follow red → green vertical slices through the two public seams.
- Do not commit or push.

---

### Task 1: Safe explicit file and MIME intake seam

**Files:**
- Create: `endpoint_agent/src/shielddome_endpoint/safe_eml_intake.py`
- Create: `endpoint_agent/tests/test_safe_eml_intake.py`

**Interfaces:**
- Produces: `SafeEmlReader.read_explicit(path, *, observed_at) -> MailObservation`.
- Produces: `SafeEmlIntakeError.code` with only stable intake codes.

- [ ] Write one failing public-interface test for confirmation-independent safe reading of a normal synthetic `.eml`; run it and confirm RED because the module is absent.
- [ ] Implement centralized limits, stable errors, local-path/reparse/ADS checks, before/after file-identity comparison, and bounded byte reading; rerun the test to GREEN.
- [ ] Add one failing slice at a time for extension, missing/directory/unsafe paths, exact size boundary, headers, parts, depth, attachments, recipients, body, URLs, malformed encodings, HTML inertness, attachment non-decoding, nested-message skipping, and sanitized metadata; add only the implementation needed for each GREEN result.
- [ ] Assert the result uses `source_kind="manual_local"`, an opaque SHA-256-derived source message ID, declared authentication observations only, bounded strings, and no raw filename/path/content persistence side effect.

### Task 2: Detection and best-effort persistence orchestration seam

**Files:**
- Create: `endpoint_agent/src/shielddome_endpoint/local_mail_intake.py`
- Create: `endpoint_agent/tests/test_local_mail_intake.py`

**Interfaces:**
- Consumes: `SafeEmlReader.read_explicit(path, *, observed_at) -> MailObservation`.
- Produces: `LocalMailIntakeService.detect_file(path, *, confirmed_by_user) -> DetectionOutcome`.
- Produces: `LocalMailIntakeError.code`, reusing stable intake codes and never embedding exception text.

- [ ] Write and run a failing confirmation-required test; implement the minimal guard and confirm GREEN.
- [ ] Write and run a failing successful-orchestration test using reader/detection/store adapters; implement clock/event identity, local detection, encrypted evidence-record save, and pending-context capture through the existing feature sink.
- [ ] Add failing tests showing evidence and pending store construction/cleanup/write failures do not change or block the detection outcome; implement best-effort isolation and confirm GREEN.
- [ ] Add failure-path tests proving error representations contain no filename, absolute path, body, URL, attachment value, exception stack, or unstable code.

### Task 3: Public interface, offline guards, and phase documentation

**Files:**
- Modify: `endpoint_agent/src/shielddome_endpoint/__init__.py`
- Modify: `endpoint_agent/tests/test_offline_constraints.py`
- Modify: `endpoint_agent/README.md`
- Modify: `endpoint_agent/DEVELOPMENT_PLAN.md`
- Modify: `endpoint_agent/docs/USAGE.md`
- Modify: `endpoint_agent/AGENTS.md`

**Interfaces:**
- Produces public imports for both deep modules, their errors, and security limit constants needed by integrators/tests.

- [ ] Add failing export and offline-capability assertions; make the minimum export/guard changes and rerun to GREEN.
- [ ] Document explicit confirmation, stable errors, limits, inert MIME handling, observation-only authentication, best-effort encrypted persistence, privacy, and omitted 7C.2/UI capabilities.
- [ ] Only after all gates pass, split Phase 7C into 7C.1 `complete` and 7C.2 `pending`; keep Phase 7C and Phase 7 `in_progress`, and Phase 7B `complete`.

### Task 4: Acceptance and contamination audit

**Files:**
- Verify all files above and inspect generated temporary/build locations; do not add artifacts.

- [ ] Run focused 7C.1 tests, the complete offscreen Endpoint Agent suite, offline constraint tests, and a fresh offline Wheel build.
- [ ] Run `git diff --check -- endpoint_agent`, `git status --short`, `git diff --stat`, `git diff --cached`, and protected-directory checks for `app shielddome frontend extension web deploy scripts`.
- [ ] Inspect test/build temporary locations and repository status for raw `.eml`, attachment files, extraction directories, temporary bodies, unencrypted databases, logs containing mail content/path, network listeners, and protocol changes.
- [ ] Re-read every requirement and report exact commands, counts, exits, changed files, Git state, omissions, and whether 7C.2 may begin.

## Self-review

- Spec coverage: file/path identity, all MIME/resource limits, inert attachment/HTML behavior, privacy, detection/persistence isolation, offline/protocol invariants, documentation states, and all requested verification gates are assigned.
- Placeholder scan: no deferred implementation placeholders are present.
- Type consistency: both modules exchange the existing `MailObservation`; orchestration returns the existing `DetectionOutcome`; all failure interfaces expose stable `code` values.
