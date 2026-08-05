# Phase 6C Sanitized Diagnostics Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an explicit-confirmation-only, one-time sanitized diagnostic ZIP export that contains bounded aggregate health and compatibility data while excluding mail, samples, encryption material, local identity, paths, and network behavior.

**Architecture:** `DiagnosticsCollector` reads already-sanitized Endpoint Evidence Records through `EvidenceStore.list_page()` and aggregate-only Confirmed Example Library counts through a new `ExampleStore.diagnostic_aggregate()` seam. It converts those inputs into a strict immutable `SanitizedDiagnostics` contract with fixed versions, a fifteen-day window, bounded stable-code counts, and controlled health states. `DiagnosticExporter` serializes only fixed JSON payloads, writes a fixed-name ZIP in a current-user temporary directory, verifies its whitelist and SHA-256 manifest, and copies it to the caller-selected path only after explicit confirmation and overwrite checks.

**Tech Stack:** Python 3.12, standard-library `unittest`, `dataclasses`, `enum`, `json`, `hashlib`, `zipfile`, existing SQLite/DPAPI/AES-256-GCM stores, no new runtime dependency.

## Global Constraints

- Modify only `endpoint_agent/`; preserve all pre-existing tracked and untracked work, including Phase 6B.
- Implement Phase 6C only. Do not implement Phase 7 tray UI, dashboard, EML import, background jobs, scheduled export, upload, telemetry, HTTP, WebSocket, network clients, or listeners.
- Export only after `confirmed is True`; require the caller to provide the output path; reject an existing output by default and require a separate `overwrite=True` value to replace it.
- The ZIP whitelist is exactly `diagnostics.json`, `compatibility.json`, and `manifest.json`; archive names are constants and must be relative single-component POSIX names without `..`.
- Never serialize mail subject/body/address/recipient/sender, URL/query, attachment name/content, `.eml`, FeatureVector, similarity vector, sample fingerprint, SQLite/WAL/SHM content, key, nonce, authentication tag, ciphertext, username, SID, hostname, absolute path, environment value, token, API key, cookie, registry dump, rule weight, model reason, similar-example detail, exception traceback, or exception text.
- Read evidence only through the existing sanitized `EvidenceStore.list_page()` API. Read sample-library data only through aggregate-only `ExampleStore.diagnostic_aggregate()`; never copy a database or sidecar.
- Use exactly a fifteen-day UTC lookback, at most 4,096 evidence records, 512 example rows, 32 distinct error codes, and 32 source kinds. Exceeding a count or serialized/archive size limit fails with a stable code and leaves existing data/packages unchanged.
- Temporary directories live below `%LOCALAPPDATA%\ShieldDome\EndpointAgent\diagnostic-temp` and are removed on success and failure. A same-directory temporary output file may be used only to atomically replace a caller-approved existing output and must also be cleaned.
- Diagnostic export is not connected to Native Messaging or the extension, and neither package contents nor output paths appear in plugin responses.
- Do not commit, push, create a branch, or create a PR.

---

### Task 1: Aggregate-only Confirmed Example Library diagnostic seam

**Files:**
- Modify: `endpoint_agent/src/shielddome_endpoint/example_store.py`
- Test: `endpoint_agent/tests/test_diagnostics.py`

**Interfaces:**
- Consumes: authenticated `ConfirmedExample` rows already owned by `ExampleStore`.
- Produces: immutable `ExampleLibraryAggregate(total_rows: int, unique_examples: int, benign_labels: int, phishing_labels: int, conflicts: int)` and `ExampleStore.diagnostic_aggregate() -> ExampleLibraryAggregate`.

- [x] **Step 1: Write the failing aggregate-only seam test**

```python
aggregate = store.diagnostic_aggregate()
self.assertEqual(aggregate.total_rows, 3)
self.assertEqual(aggregate.unique_examples, 2)
self.assertEqual(aggregate.benign_labels, 2)
self.assertEqual(aggregate.phishing_labels, 1)
self.assertEqual(aggregate.conflicts, 1)
self.assertFalse(hasattr(aggregate, "feature_vector"))
self.assertFalse(hasattr(aggregate, "keyed_fingerprint"))
```

- [x] **Step 2: Run the focused module and confirm red**

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_diagnostics.py" -v`

Expected: FAIL because `ExampleStore.diagnostic_aggregate` and `ExampleLibraryAggregate` do not exist.

- [x] **Step 3: Implement the minimal authenticated aggregate query**

```python
@dataclass(frozen=True, slots=True)
class ExampleLibraryAggregate:
    total_rows: int
    unique_examples: int
    benign_labels: int
    phishing_labels: int
    conflicts: int

def diagnostic_aggregate(self) -> ExampleLibraryAggregate:
    if not self.database_path.exists():
        return ExampleLibraryAggregate(0, 0, 0, 0, 0)
    # Fetch at most EXAMPLE_CALIBRATION_SCAN_MAX_ROWS + 1, reject overflow,
    # authenticate/decrypt every selected row with _decode_row, group only in
    # memory, and return counts without returning fingerprints or vectors.
```

Map an overflow to `ExampleStoreError("example_diagnostic_limit_exceeded")`. A damaged key, schema, index, nonce, ciphertext, or tag must retain the existing stable store error and return no partial aggregate.

- [x] **Step 4: Add red-green slices for empty, overflow, corruption, and cross-user scope**

```python
self.assertEqual(empty_store.diagnostic_aggregate().total_rows, 0)
with self.assertRaisesRegex(ExampleStoreError, "^example_diagnostic_limit_exceeded$"):
    over_limit_store.diagnostic_aggregate()
with self.assertRaisesRegex(ExampleStoreError, "^example_key_unavailable$"):
    other_user_store.diagnostic_aggregate()
```

Run the focused module after each slice and keep `FeatureVector` and fingerprints outside the returned type.

### Task 2: Strict sanitized diagnostics collector

**Files:**
- Create: `endpoint_agent/src/shielddome_endpoint/diagnostics.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/__init__.py`
- Test: `endpoint_agent/tests/test_diagnostics.py`

**Interfaces:**
- Consumes: `EvidenceStore.list_page(offset, limit)`, `ExampleStore.diagnostic_aggregate()`, an injected aware UTC clock, package/protocol/schema version constants, and already-sanitized `EndpointEvidenceRecord` fields.
- Produces: `DIAGNOSTIC_SCHEMA_VERSION = "1.0"`; `DIAGNOSTIC_LOOKBACK_DAYS = 15`; `DIAGNOSTIC_MAX_EVIDENCE_RECORDS = 4096`; `DIAGNOSTIC_MAX_ERROR_CODE_KINDS = 32`; `DIAGNOSTIC_MAX_SOURCE_KINDS = 32`; `DiagnosticHealthStatus`; immutable `DiagnosticStoreHealth`; immutable `SanitizedDiagnostics`; `DiagnosticsCollector.collect() -> SanitizedDiagnostics`; stable `DiagnosticCollectionError`.

- [x] **Step 1: Write a failing fifteen-day aggregate and version test**

```python
snapshot = DiagnosticsCollector(
    evidence_store=evidence_store,
    example_store=example_store,
    clock=lambda: NOW,
).collect()
self.assertEqual(snapshot.schema_version, "1.0")
self.assertEqual(snapshot.lookback_days, 15)
self.assertEqual(snapshot.events_by_date, (("2026-08-04", 2),))
self.assertEqual(dict(snapshot.risk_level_counts)["high"], 1)
self.assertEqual(dict(snapshot.source_counts)["browser_native"], 2)
self.assertEqual(snapshot.rules_only_count, 1)
self.assertEqual(snapshot.model_abstained_count, 1)
self.assertEqual(snapshot.model_degraded_count, 1)
self.assertNotIn("2026-07-20", dict(snapshot.events_by_date))
```

- [x] **Step 2: Run the focused module and confirm red**

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_diagnostics.py" -v`

Expected: FAIL because `shielddome_endpoint.diagnostics` does not exist.

- [x] **Step 3: Implement strict immutable aggregates and canonical payload conversion**

`SanitizedDiagnostics.to_payload()` must emit only these top-level keys:

```python
{
    "schema_version",
    "generated_at_utc",
    "lookback_days",
    "versions",
    "evidence_store_health",
    "example_library_health",
    "event_count",
    "events_by_date",
    "risk_level_counts",
    "source_counts",
    "detection_state_counts",
    "model_execution_status_counts",
    "rules_only_count",
    "model_available_count",
    "model_abstained_count",
    "model_degraded_count",
    "stable_error_code_counts",
    "example_library_counts",
}
```

`versions` contains only Agent, Native Messaging protocol, MailObservation, FeatureVector, ModelAssessment, DetectionOutcome, EndpointEvidenceRecord, ConfirmedExample, and diagnostic schema versions. Risk, detection-state, model-status, label, and health keys are fixed enums; date/source/error entries are sorted tuples converted to JSON arrays/objects with integer counts.

- [x] **Step 4: Add red-green controlled-health and no-partial-data slices**

```python
snapshot = DiagnosticsCollector(
    evidence_store=FailingEvidenceStore(
        "SUBJECT user@example.test https://private.test/?token=secret"
    ),
    example_store=FailingExampleStore("C:\\Users\\private\\examples.sqlite3"),
    clock=lambda: NOW,
).collect()
serialized = snapshot.to_json_bytes()
self.assertEqual(snapshot.evidence_store_health.error_code, "evidence_store_unavailable")
self.assertEqual(snapshot.example_library_health.error_code, "example_library_unavailable")
self.assertNotIn(b"SUBJECT", serialized)
self.assertNotIn(b"example.test", serialized)
self.assertNotIn(b"C:\\\\Users", serialized)
```

Store failures produce `unavailable` health with zero counts and fixed diagnostic error codes; do not serialize `str(exception)`, exception type names, or a traceback. A missing database produces `empty`, not an error.

- [x] **Step 5: Add red-green limit and cross-user slices**

Patch the public limits downward in tests and require `DiagnosticCollectionError("diagnostic_record_limit_exceeded")`, `DiagnosticCollectionError("diagnostic_error_code_limit_exceeded")`, and `DiagnosticCollectionError("diagnostic_source_limit_exceeded")`. Use current-user-scope test protectors to write under user A and collect under user B; both stores must report unavailable with zero event/sample counts and no user A aggregate data.

- [x] **Step 6: Export and test the Phase 6C collector contracts**

Re-export only the strict constants, health/snapshot types, collector, and stable error from `shielddome_endpoint.__init__`; never export an API accepting a database/key/SID path from a diagnostic request.

### Task 3: Confirmed, bounded, atomic diagnostic ZIP export

**Files:**
- Create: `endpoint_agent/src/shielddome_endpoint/diagnostic_export.py`
- Create: `endpoint_agent/tests/test_diagnostic_export.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/__init__.py`
- Modify: `endpoint_agent/tests/test_build.py`

**Interfaces:**
- Consumes: `DiagnosticsCollector.collect()`, caller-selected output path, exact boolean confirmation, exact boolean overwrite choice, and an injected aware UTC clock.
- Produces: `DIAGNOSTIC_ARCHIVE_NAMES = ("diagnostics.json", "compatibility.json", "manifest.json")`; `DIAGNOSTIC_MANIFEST_SCHEMA_VERSION = "1.0"`; `DIAGNOSTIC_FILE_MAX_BYTES = 262144`; `DIAGNOSTIC_ARCHIVE_MAX_BYTES = 1048576`; immutable `DiagnosticExportResult`; `DiagnosticExporter.export(output_path, *, confirmed, overwrite=False)`; stable `DiagnosticExportError`.

- [x] **Step 1: Write and run a failing confirmation/overwrite test**

```python
with self.assertRaisesRegex(DiagnosticExportError, "^diagnostic_confirmation_required$"):
    exporter.export(output_path, confirmed=False)
self.assertFalse(output_path.exists())
output_path.write_bytes(b"existing-package")
with self.assertRaisesRegex(DiagnosticExportError, "^diagnostic_output_exists$"):
    exporter.export(output_path, confirmed=True)
self.assertEqual(output_path.read_bytes(), b"existing-package")
```

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_diagnostic_export.py" -v`

Expected: FAIL because `shielddome_endpoint.diagnostic_export` does not exist.

- [x] **Step 2: Implement fixed canonical JSON payloads and coarse compatibility data**

`compatibility.json` has exactly `schema_version`, `operating_system`, `windows_major_version`, `python_implementation`, `python_version`, `agent_package_version`, and `packaging_kind`. Values are coarse (`Windows`, Windows major only, Python major.minor, allowlisted implementation, source/frozen kind, package version); never call `getpass.getuser`, `platform.node`, `platform.platform`, path/environment dumping, registry APIs, or hostname APIs.

- [x] **Step 3: Implement manifest hashing and safe ZIP construction**

Serialize `diagnostics.json` and `compatibility.json` with `ensure_ascii=True`, sorted keys, compact separators, and a trailing newline. `manifest.json` lists those two payload files in fixed order with literal name, exact byte size, and lowercase SHA-256, plus the manifest schema and the exact archive whitelist. Use explicit `ZipInfo` names, fixed safe metadata, and `ZIP_DEFLATED`. Reopen the completed temporary ZIP and verify exact names, no absolute/drive path, no `..`, entry/file/archive limits, and every manifest size/hash before publishing it.

- [x] **Step 4: Implement current-user temporary cleanup and safe publication**

Create the build directory with `TemporaryDirectory(prefix="export-", dir=%LOCALAPPDATA%\ShieldDome\EndpointAgent\diagnostic-temp)` and close the ZIP before cleanup. For a new output, use exclusive creation and remove only the newly created partial file on failure. For approved overwrite, write/fsync a unique sibling temporary file and atomically `os.replace` it; remove that file on every failure. Map filesystem/ZIP/serialization failures to stable diagnostic export codes without exception text.

- [x] **Step 5: Add red-green archive whitelist, traversal, privacy, and integrity slices**

```python
with ZipFile(output_path) as archive:
    self.assertEqual(tuple(sorted(archive.namelist())), tuple(sorted(DIAGNOSTIC_ARCHIVE_NAMES)))
    for name in archive.namelist():
        self.assertFalse(PurePosixPath(name).is_absolute())
        self.assertNotIn("..", PurePosixPath(name).parts)
    manifest = json.loads(archive.read("manifest.json"))
    for item in manifest["files"]:
        payload = archive.read(item["name"])
        self.assertEqual(item["size_bytes"], len(payload))
        self.assertEqual(item["sha256"], hashlib.sha256(payload).hexdigest())
```

Seed real stores from a synthetic observation containing unique mail subject/body/address/URL/attachment/source ID plus test secret/key/ciphertext strings. Search every ZIP entry byte-for-byte and assert none appears. Assert archive names and JSON keys contain no database, WAL, SHM, key, nonce, authentication tag, ciphertext, FeatureVector, fingerprint, similarity, username, SID, hostname, absolute path, environment, cookie, token value, model reason, rule weight, exception, or traceback field.

- [x] **Step 6: Add red-green size, cleanup, network, determinism, and failure-isolation slices**

Patch file/archive limits below the known payload size and require a stable failure with no output. Inspect the current-user temporary parent after both a successful export and an injected write/ZIP failure; no `export-*` directory or sibling partial remains. Patch `socket.socket`, `socket.create_connection`, and listener-like operations to fail if called; export must still succeed without any call. Export the same injected snapshot twice and require identical archive entry names and JSON key topology, without requiring identical ZIP bytes. Cause export failure after a normal detection/evidence write and verify `EvidenceStore.get()` plus the four-field detection result remain unchanged.

- [x] **Step 7: Export and package the public Phase 6C seam**

Re-export `DiagnosticExporter`, `DiagnosticExportResult`, `DiagnosticExportError`, and fixed archive/schema/limit constants. Add `diagnostics.py` and `diagnostic_export.py` to the offline Wheel member assertion; do not add a dependency or any Native Messaging command.

### Task 4: Offline/static security regression

**Files:**
- Modify: `endpoint_agent/tests/test_offline_constraints.py`
- Modify: `endpoint_agent/tests/test_package.py`
- Test: `endpoint_agent/tests/test_diagnostic_export.py`

**Interfaces:**
- Consumes: all Phase 6C production sources and package exports.
- Produces: static and runtime proof that diagnostics have no network/listener/upload/background/plugin path.

- [x] **Step 1: Write a failing Phase 6C static guard test**

```python
sources = "\n".join(
    (SOURCE_ROOT / name).read_text(encoding="utf-8").casefold()
    for name in ("diagnostics.py", "diagnostic_export.py")
)
for forbidden in (
    "import socket", ".connect(", ".bind(", ".listen(",
    "requests.", "urllib.", "http://", "https://", "upload",
    "threading", "sched", "subprocess", "traceback",
):
    self.assertNotIn(forbidden, sources)
```

- [x] **Step 2: Run the focused offline test and confirm red**

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_offline_constraints.py" -v`

Expected: FAIL until the Phase 6C file scan is added and production source satisfies it.

- [x] **Step 3: Keep Native Messaging and extension surfaces unchanged**

Add package assertions for the new Python-only export API, then assert `native_host.py`, `native_payload.py`, `extension/background.js`, and `extension/content.js` contain no diagnostic export command, output path, archive name, or ZIP content bridge. Run the offline and package modules until they exit 0.

### Task 5: Phase status and usage documentation

**Files:**
- Modify: `endpoint_agent/README.md`
- Modify: `endpoint_agent/DEVELOPMENT_PLAN.md`
- Modify: `endpoint_agent/docs/USAGE.md`
- Modify: `endpoint_agent/AGENTS.md`
- Modify: `endpoint_agent/docs/plans/2026-08-05-phase-6c-sanitized-diagnostics.md`

**Interfaces:**
- Consumes: fresh red-green evidence from Tasks 1–4.
- Produces: exact Phase 6C API/whitelist/privacy/limit documentation and conservative phase states.

- [x] **Step 1: Document the explicit one-time export contract**

Add a usage example that passes a caller-chosen `.diag.zip` path, `confirmed=True`, and only uses `overwrite=True` after a second explicit decision. List the exact three ZIP files, payload fields, fifteen-day/4,096-record/512-sample/32-code/32-source/256-KiB-file/1-MiB-archive limits, manifest hash semantics, current-user temporary cleanup, no database copy, no FeatureVector/fingerprint, and no network/plugin integration.

- [x] **Step 2: Advance only the authorized statuses after fresh evidence**

Change Phase 6C from `pending` to `complete` and Phase 6 from `in_progress` to `complete` only after all required verification commands exit 0. Keep Phase 5B and Phase 3 statuses unchanged, keep Phase 4B `pending`, keep Phase 7 `pending`, and set the narrative next step to Phase 7 without implementing it.

- [x] **Step 3: Record exact execution evidence in this plan**

Append the fresh total/pass/failure/error/skip counts, focused-suite counts, JavaScript results, Wheel result, manifest/privacy/temp/network evidence, Git scope audit, and the unchanged Phase 5B skip reason. Do not claim a skipped Phase 5B browser/packaged-host check or any Phase 7 capability.

### Task 6: Fresh verification and scope audit

**Files:**
- Inspect only all modified files under `endpoint_agent/` and the Git state.

**Interfaces:**
- Consumes: completed Phase 6C implementation and documentation.
- Produces: evidence for the final report; no commit or push.

- [x] **Step 1: Run the complete Endpoint Agent regression**

Run: `python -m unittest discover -s endpoint_agent/tests -v`

- [x] **Step 2: Run the Phase 6C focused suites freshly**

```powershell
python -m unittest discover -s endpoint_agent/tests -p "test_diagnostics.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_diagnostic_export.py" -v
```

- [x] **Step 3: Run JavaScript syntax and offline Wheel checks**

```powershell
node --check endpoint_agent/extension/background.js
node --check endpoint_agent/extension/content.js
python -m pip wheel --no-index --no-deps .\endpoint_agent --wheel-dir .\endpoint_agent\dist\phase6c
```

- [x] **Step 4: Audit Git scope and generated artifacts**

## Execution Evidence

Fresh verification on 2026-08-05:

- Full Endpoint Agent regression: 221 tests run; 220 passed, 0 failures, 0 errors, and 1 skipped; exit code 0. The only skip remains the pre-existing Phase 5B packaged Host contract because no Host `.exe` exists in this environment.
- Phase 6C focused diagnostics suite: 9/9 passed with 0 failures, 0 errors, and 0 skips; exit code 0.
- Phase 6C focused export suite: 8/8 passed with 0 failures, 0 errors, and 0 skips; exit code 0.
- `node --check` passed for `extension/background.js` and `extension/content.js`; both exited 0.
- Offline `pip wheel --no-index --no-deps` succeeded and created `shielddome_endpoint-0.1.0-py3-none-any.whl`, 52,488 bytes, SHA-256 `b7fc8cb7afbea0c5e390328ba15319900e36e9d081a9473d69697cc7f7e05fba`.
- Tests verified exact confirmation and overwrite booleans, caller-selected output, the three-name archive whitelist, safe names without absolute/parent traversal, canonical payload topology, actual manifest sizes/hashes, current-user temporary cleanup after success/failure, and atomic preservation of an existing package.
- Privacy tests seeded real encrypted stores from mail containing unique subject/body/address/recipient/URL/attachment/source/secret values and verified that none, nor FeatureVector data, fingerprints, database material, keys, nonce/tag/ciphertext, paths, model reasons, rule weights, exception text, or tracebacks entered any ZIP member.
- Store tests verified fifteen-day aggregates, rule/model/error statistics, 4,096-record/512-row/32-source/32-error limits, damaged/partial database controlled health, no partial counts, and rejection of another Windows user scope.
- Runtime and static tests verified no network connection/listener, no scheduled/background/upload path, and no Native Messaging or browser-extension access to diagnostic contents or paths. Export failure left normal detection and encrypted evidence readable.
- Phase 6C and Phase 6 are complete. Phase 3, Phase 4B, and Phase 5B retain their prior states; Phase 7 is the next implementation phase and remains unimplemented.

```powershell
git status --short
git diff --stat
git diff -- endpoint_agent
git status --short -- app shielddome frontend extension web deploy scripts
```

Confirm no forbidden directory changed, no staged content exists, Phase 6B changes were not reverted or reformatted, generated diagnostic/Wheel/runtime files remain ignored, archive entries and manifest were freshly verified, and Phase 7 code is absent.
