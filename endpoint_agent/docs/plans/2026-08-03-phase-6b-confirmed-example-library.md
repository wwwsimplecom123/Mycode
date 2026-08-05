# Phase 6B Confirmed Example Library Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a per-Windows-user encrypted Confirmed Example Library and bounded similarity calibration that only consumes explicit user confirmations and can never override deterministic strong-rule risk floors.

**Architecture:** A strict immutable `ConfirmedExample` stores only a validated sanitized `FeatureVector`, schema versions, a human label, a fixed source enum, an aware confirmation time, and a per-user keyed fingerprint. `ExampleStore` owns explicit confirmation, HMAC-SHA-256 fingerprinting, a separate current-user DPAPI-protected random key, AES-256-GCM encryption, bounded SQLite queries, deduplication, conflict preservation, deletion, and clearing. `ExampleCalibrator` applies one exact unconflicted label or at least three mutually consistent high-similarity fingerprints; `LocalDetectionService` treats all calibration failures as no adjustment, while Risk Fusion applies bounded directional adjustments after model evidence and never below a strong-rule floor or into `critical` from example evidence alone.

**Tech Stack:** Python 3.12, standard-library `unittest`, SQLite 3, HMAC-SHA-256, Windows current-user DPAPI, `cryptography==49.0.0` AESGCM, existing Feature Schema 2.0 and Detection Kernel.

## Global Constraints

- Modify only `endpoint_agent/`; preserve all pre-existing tracked and untracked work.
- Implement Phase 6B only. Do not implement Phase 6C, Phase 7, model training, model-weight changes, upload, diagnostics export, desktop UI, new Native Messaging confirmation commands, network clients, HTTP/WebSocket, or listeners.
- A sample enters the library only through `ExampleStore.confirm(...)` with a matching `UserConfirmationAction`; detection, low risk, mailbox contents, and evidence persistence never call `confirm`.
- Persist only sanitized `FeatureVector` values, feature/example schema versions, `benign` or `phishing` human label, fixed source enum, aware UTC confirmation time, and a keyed fingerprint. Never persist subject, body, addresses, complete URLs, attachment names/content, `.eml`, source message IDs, credentials, or tokens.
- Use a separate random 32-byte example-library key protected by current-user DPAPI under `%LOCALAPPDATA%\ShieldDome\EndpointAgent\examples`; use domain-separated HMAC-SHA-256 fingerprints and AES-256-GCM with fresh 12-byte nonces.
- Fingerprints are meaningful only inside one user's library and must differ for independent user keys.
- Limit the library to 256 distinct keyed fingerprints, at most two label rows per fingerprint, page size to 50, page offset to 256, and one calibration scan to 512 encrypted rows.
- Exact matches require one unconflicted label. Approximate matches require at least three distinct consistent fingerprints at similarity `>= 0.94` and no opposite or internally conflicted label in the qualifying set.
- Benign calibration is bounded to `-8`; phishing calibration is bounded to `+18`. Example adjustment cannot lower a strong-rule floor and cannot by itself create `critical`.
- Calibration exceptions, damaged storage, incompatible records, and authentication failures must preserve the rule/model detection result and minimal plugin projection.
- The plugin projection remains exactly `local_event_id`, `risk_level`, `execution_state`, and `generic_action`; it never contains example content, fingerprint, similarity, supporting count, rule detail, or internal reason.
- Do not commit, push, create a branch, or create a PR.

---

### Task 1: Strict confirmed-example contract and explicit confirmation vocabulary

**Files:**
- Create: `endpoint_agent/src/shielddome_endpoint/confirmed_examples.py`
- Create: `endpoint_agent/tests/test_confirmed_examples.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/__init__.py`

**Interfaces:**
- Consumes: `FeatureVector`, `FEATURE_SCHEMA_VERSION`, Feature Pipeline name/order constants, and `TEXT_HASH_DIMENSION`.
- Produces: `CONFIRMED_EXAMPLE_SCHEMA_VERSION = "1.0"`; `EXAMPLE_FINGERPRINT_VERSION = "hmac-sha256-v1"`; `ExampleLabel`; `ExampleSource`; `UserConfirmationAction`; immutable `ConfirmedExample`; `validate_example_feature_vector`; `canonical_feature_vector_bytes`; `keyed_feature_fingerprint`; stable `ConfirmedExampleValidationError`.

- [x] **Step 1: Write a failing immutable public-contract and canonical round-trip test**

```python
record = ConfirmedExample.create(
    vector,
    label=ExampleLabel.BENIGN,
    source=ExampleSource.BROWSER_NATIVE,
    confirmed_at=CONFIRMED_AT,
    keyed_fingerprint="a" * 64,
)
self.assertEqual(record.feature_vector, vector)
self.assertEqual(record.schema_version, "1.0")
self.assertEqual(ConfirmedExample.from_json_bytes(record.to_json_bytes()), record)
with self.assertRaises(FrozenInstanceError):
    record.label = ExampleLabel.PHISHING
```

- [x] **Step 2: Run the module and confirm red**

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_confirmed_examples.py" -v`

Expected: FAIL because `shielddome_endpoint.confirmed_examples` does not exist.

- [x] **Step 3: Implement the minimal strict record**

```python
@dataclass(frozen=True, slots=True)
class ConfirmedExample:
    feature_vector: FeatureVector
    label: ExampleLabel
    source: ExampleSource
    confirmed_at: datetime
    keyed_fingerprint: str
    feature_schema_version: str = FEATURE_SCHEMA_VERSION
    fingerprint_version: str = EXAMPLE_FINGERPRINT_VERSION
    schema_version: str = CONFIRMED_EXAMPLE_SCHEMA_VERSION
```

Require exact numeric/categorical feature names and order, `text_input is None`, exactly 64 finite text-vector values in `[-1, 1]`, an empty or unit-length vector within tolerance, bounded categorical values, ordered/unique approved missing-mask names, current schema versions, aware times, and a lowercase 64-hex fingerprint. Canonical JSON decoding must use exact keys, reject duplicate keys and non-object/trailing/oversized input, and map every failure to `ConfirmedExampleValidationError("invalid_confirmed_example")`.

- [x] **Step 4: Add red-green slices for illegal labels, sources, schema, unknown fields, overlong categorical data, raw text, malformed vectors, and naive time**

```python
for mutation in (
    {**payload, "label": "unknown"},
    {**payload, "source": "mailbox_auto"},
    {**payload, "schema_version": "future"},
    {**payload, "subject": "private subject"},
):
    with self.assertRaisesRegex(ConfirmedExampleValidationError, "^invalid_confirmed_example$"):
        ConfirmedExample.from_json_bytes(json.dumps(mutation).encode("utf-8"))
```

Run the single module after each vertical slice until it exits 0.

- [x] **Step 5: Add independent per-key HMAC fingerprint tests**

```python
first = keyed_feature_fingerprint(vector, b"a" * 32)
second = keyed_feature_fingerprint(vector, b"b" * 32)
self.assertNotEqual(first, second)
self.assertEqual(first, keyed_feature_fingerprint(vector, b"a" * 32))
```

The HMAC input must be `b"ShieldDome Confirmed Example Fingerprint v1\0" + canonical_feature_vector_bytes(vector)` and must never use an unkeyed content hash.

### Task 2: Per-user encrypted Example Store and explicit confirmation-only admission

**Files:**
- Create: `endpoint_agent/src/shielddome_endpoint/example_store.py`
- Create: `endpoint_agent/tests/test_example_store.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/__init__.py`
- Modify: `endpoint_agent/tests/test_build.py`

**Interfaces:**
- Consumes: `UserDataKeyManager`, current-user DPAPI, `AESGCM`, `ConfirmedExample`, and the confirmation enums from Task 1.
- Produces: `EXAMPLE_LIBRARY_MAX_FINGERPRINTS = 256`; `EXAMPLE_PAGE_MAX_ITEMS = 50`; `EXAMPLE_PAGE_MAX_OFFSET = 256`; `EXAMPLE_CALIBRATION_SCAN_MAX_ROWS = 512`; `ExampleConfirmationStatus`; `ExampleStore.confirm`; `find_exact`; `list_for_calibration`; `list_page`; `delete`; `clear`; stable `ExampleStoreError`.

- [x] **Step 1: Write a failing explicit-confirmation admission test**

```python
with self.assertRaisesRegex(ExampleStoreError, "^invalid_confirmation$"):
    store.confirm(
        vector,
        action=None,
        source=ExampleSource.BROWSER_NATIVE,
        confirmed_at=CONFIRMED_AT,
    )
self.assertEqual(store.list_page(), ())
```

Also assert there is no `put`, `save_detection`, `import_mailbox`, or other public admission method.

- [x] **Step 2: Run the store module and confirm red**

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_example_store.py" -v`

Expected: FAIL because `shielddome_endpoint.example_store` does not exist.

- [x] **Step 3: Implement minimal explicit confirmation, encrypted put/read, and deterministic pagination**

Use `%LOCALAPPDATA%\ShieldDome\EndpointAgent\examples` by default and `UserDataKeyManager(example_root, database_filename="confirmed_examples.sqlite3")`, producing a separate DPAPI-protected key at `examples\keys\evidence.key`. Use one table:

```sql
CREATE TABLE confirmed_examples (
    keyed_fingerprint TEXT NOT NULL,
    label TEXT NOT NULL,
    confirmed_at_utc TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    authentication_tag BLOB NOT NULL,
    PRIMARY KEY (keyed_fingerprint, label)
) WITHOUT ROWID
```

Bind all four plaintext indexes as canonical AES-GCM associated data. The encrypted JSON contains the complete approved `ConfirmedExample` and nothing else. Use `journal_mode=WAL`, `secure_delete=ON`, `temp_store=MEMORY`, exact table-shape verification, user version `1`, a fresh nonce for every inserted row, and all-or-nothing authenticated page reads.

- [x] **Step 4: Add red-green deduplication and conflict-preservation slices**

```python
self.assertIs(
    store.confirm(
        vector,
        action=UserConfirmationAction.CONFIRM_BENIGN,
        source=ExampleSource.BROWSER_NATIVE,
        confirmed_at=CONFIRMED_AT,
    ),
    ExampleConfirmationStatus.ADDED,
)
self.assertIs(
    store.confirm(
        vector,
        action=UserConfirmationAction.CONFIRM_BENIGN,
        source=ExampleSource.BROWSER_NATIVE,
        confirmed_at=CONFIRMED_AT,
    ),
    ExampleConfirmationStatus.DUPLICATE,
)
self.assertIs(
    store.confirm(
        vector,
        action=UserConfirmationAction.CONFIRM_PHISHING,
        source=ExampleSource.BROWSER_NATIVE,
        confirmed_at=CONFIRMED_AT,
    ),
    ExampleConfirmationStatus.CONFLICT,
)
self.assertEqual({item.label for item in store.find_exact(vector)}, {BENIGN, PHISHING})
```

Capacity counts distinct fingerprints, so an opposite label for an existing fingerprint can still be retained without exceeding 256 unique examples. Reject a new unique fingerprint at capacity with `ExampleStoreError("example_capacity_exceeded")`; duplicate confirmation at capacity remains idempotent.

- [x] **Step 5: Add red-green label filtering, bounded queries, delete-one, and clear slices**

Reject page limits outside `1..50`, offsets outside `0..256`, non-enum filters, and calibration scans above the fixed internal bound. `delete(fingerprint, label)` deletes exactly one row, uses secure deletion and WAL checkpoint/truncate, and is idempotent. `clear()` counts rows, securely deletes/vacuums, closes the database, overwrites/removes the example database and owned WAL/SHM/journal/temp files, and deletes only the separate example-library protected key; repeated clear returns `0`.

- [x] **Step 6: Add red-green privacy, isolation, tamper, and capacity tests**

Create a `MailObservation` containing unique subject, body, address, full URL, attachment name, and source ID; persist only its Feature Pipeline output. Search every database, WAL, SHM, journal, temp, and key byte sequence and assert none contains the raw values. Reopen the same database with a different injected SID scope and require `example_key_unavailable`; flip nonce/ciphertext/tag/index bits and require `example_decryption_failed` with no partial page. Confirm two independent keys produce different fingerprints for the same vector.

- [x] **Step 7: Include the new production modules in the offline Wheel assertion**

Add `confirmed_examples.py`, `example_store.py`, and later `example_calibration.py` to `test_build.py`'s expected Wheel members. Do not add a runtime dependency beyond the existing fixed `cryptography==49.0.0`.

### Task 3: Conservative exact and approximate calibration

**Files:**
- Create: `endpoint_agent/src/shielddome_endpoint/example_calibration.py`
- Create: `endpoint_agent/tests/test_example_calibration.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/__init__.py`

**Interfaces:**
- Consumes: `FeatureVector`, `ExampleStore.find_exact`, `ExampleStore.list_for_calibration`, and validated `ConfirmedExample` rows.
- Produces: `EXAMPLE_APPROXIMATE_MIN_MATCHES = 3`; `EXAMPLE_APPROXIMATE_SIMILARITY_THRESHOLD = 0.94`; `EXAMPLE_BENIGN_ADJUSTMENT = -8`; `EXAMPLE_PHISHING_ADJUSTMENT = 18`; `ExampleCalibrationStatus`; immutable `ExampleCalibration`; `ExampleCalibrator.calibrate(feature_vector)`.

- [x] **Step 1: Write and run a failing exact-match test**

```python
calibration = ExampleCalibrator(store).calibrate(vector)
self.assertIs(calibration.status, ExampleCalibrationStatus.EXACT_APPLIED)
self.assertEqual(calibration.adjustment, -8)
self.assertEqual(calibration.supporting_examples, 1)
```

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_example_calibration.py" -v`

Expected: FAIL because the calibrator module does not exist.

- [x] **Step 2: Implement exact matching with conflict rejection**

One exact fingerprint row applies the label's bounded adjustment. Two labels for the exact fingerprint return `REJECTED_CONFLICT`, adjustment `0`, and support `0`; they are never silently ordered or overwritten.

- [x] **Step 3: Add red-green approximate-consensus slices**

Compute deterministic similarity only between fully validated compatible Feature Schema 2.0 vectors:

```text
0.75 * max(0, text-vector cosine)
+ 0.15 * mean(1 - abs(a-b) / max(1, abs(a), abs(b)))
+ 0.10 * categorical exact-match fraction
```

Group qualifying rows by keyed fingerprint. A fingerprint carrying both labels is a conflict, not two votes. Require at least three distinct qualifying fingerprints, one shared label, and no qualifying opposite/conflicted label. Return `SIMILAR_APPLIED` with `-8` or `+18`; never return similarity values or fingerprints in `ExampleCalibration`.

- [x] **Step 4: Add red-green rejection slices**

Cover `NO_EXAMPLES`, `REJECTED_LOW_SIMILARITY`, `REJECTED_INSUFFICIENT`, and `REJECTED_CONFLICT`; every rejection has adjustment `0`. Invalid feature vectors fail with stable `invalid_calibration_input`. Store errors propagate to the orchestration boundary so non-blocking behavior is tested separately.

### Task 4: Bounded Risk Fusion and non-blocking detection integration

**Files:**
- Modify: `endpoint_agent/src/shielddome_endpoint/domain.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/risk_fusion.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/detection_kernel.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/local_detection.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/native_host.py`
- Modify: `endpoint_agent/tests/test_domain.py`
- Modify: `endpoint_agent/tests/test_risk_fusion.py`
- Modify: `endpoint_agent/tests/test_detection_kernel.py`
- Modify: `endpoint_agent/tests/test_local_detection.py`
- Modify: `endpoint_agent/tests/test_native_host.py`
- Modify: `endpoint_agent/tests/test_privacy.py`

**Interfaces:**
- Consumes: optional `ExampleCalibration` supplied to `DetectionKernel.detect` and an optional calibrator supplied to `LocalDetectionService`.
- Produces: `DETECTION_OUTCOME_SCHEMA_VERSION = "3.0"`; private evidence fields `example_adjustment`, `example_calibration_status`, and `example_supporting_count`; unchanged four-field plugin projection; a default Native Host composition using the per-user store without exposing confirmation through Native Messaging.

- [x] **Step 1: Write failing Risk Fusion bound tests**

```python
benign = fuse_risk(
    rules,
    model_assessment=None,
    execution_state=DetectionExecutionState.RULES_ONLY,
    example_calibration=exact_benign,
)
self.assertGreaterEqual(benign.final_risk_score, benign.risk_floor)
phishing_only = fuse_risk(
    (),
    model_assessment=None,
    execution_state=DetectionExecutionState.RULES_ONLY,
    example_calibration=exact_phishing,
)
self.assertLess(phishing_only.final_risk_score, 80)
```

Cover strong authentication, dangerous URL, blacklist/policy, and dangerous attachment categories through strong-rule fixtures; benign calibration cannot lower any established floor. Positive example adjustment is applied after model adjustment, clamped to `0..100`, and when rules+model are below 80 it cannot be the step that crosses to 80.

- [x] **Step 2: Implement the minimal Risk Fusion extension**

Add optional `example_calibration`; only `EXACT_APPLIED` and `SIMILAR_APPLIED` may contribute, and the accepted value must equal the fixed directional constant. Store the applied adjustment separately from `model_adjustment`. A positive applied adjustment upgrades `continue` to `verify_sender`; a benign adjustment never weakens a rule-selected action.

- [x] **Step 3: Add failing Kernel/private-evidence/plugin-boundary tests, then implement**

Add the three example summary fields to `StructuredPrivateEvidence`, bump Detection Outcome schema to `3.0`, pass calibration into Risk Fusion, and keep `minimal_plugin_projection` byte-for-byte at four fields. Privacy tests must prove no fingerprint, similarity, sample vector, label source, supporting record content, or internal rule detail reaches the plugin projection.

- [x] **Step 4: Add failing Local Detection calibration-exception test, then implement best-effort orchestration**

`LocalDetectionService.detect` transforms and evaluates rules first, then calls the injected calibrator in `try/except`. On any exception it passes `ExampleCalibration.failed()` with zero adjustment to the Kernel and returns the otherwise identical rule/model result. It never confirms or writes a sample.

- [x] **Step 5: Wire the Native Host default to a lazy per-user calibrator without adding a confirmation message**

Keep all sample admission and similarity logic outside `native_host.py`. The Host may call a local factory that composes `ExampleStore` + `ExampleCalibrator` + `LocalDetectionService`; tests inject empty/failing calibrators for deterministic behavior. Native payload parsing continues to reject unknown confirmation, label, similarity, rule, and score fields, and the response remains the existing four-field projection.

### Task 5: Phase status, usage, package, and security documentation

**Files:**
- Modify: `endpoint_agent/README.md`
- Modify: `endpoint_agent/DEVELOPMENT_PLAN.md`
- Modify: `endpoint_agent/docs/USAGE.md`
- Modify: `endpoint_agent/AGENTS.md`
- Modify: `endpoint_agent/docs/plans/2026-08-03-phase-6b-confirmed-example-library.md`
- Modify: `endpoint_agent/tests/test_package.py`

**Interfaces:**
- Consumes: fresh red-green and verification evidence from Tasks 1–4.
- Produces: public Phase 6B API documentation, exact storage/query/calibration bounds, correct phase states, and package exports.

- [x] **Step 1: Export and test the Phase 6B public contracts**

Re-export the strict enums/record, `ExampleStore`, `ExampleCalibrator`, result/status types, and limit/schema constants from `shielddome_endpoint.__init__`. Keep package version unchanged unless the existing project policy requires a release version bump; this phase does not create an Endpoint Release.

- [x] **Step 2: Document privacy, poisoning resistance, and bounded calibration**

Document the explicit confirmation-only admission path, separate current-user DPAPI key, AES-GCM, keyed HMAC fingerprint, 256-fingerprint capacity, 50-item pages, two-label conflict retention, exact/three-example approximate gates, threshold `0.94`, adjustments `-8/+18`, strong-rule floor protection, no critical from sample evidence alone, zero upload/training, and clear/delete behavior.

- [x] **Step 3: Update phase states conservatively**

Only after every required command exits 0, mark Phase 6B `complete`; keep Phase 6 `in_progress` and Phase 6C `pending`. Preserve Phase 3 `pending`, Phase 4 `in_progress`, Phase 4B `pending`, Phase 5 `in_progress`, Phase 5B `in_progress`, and Phase 7+ `pending`.

- [x] **Step 4: Record execution evidence in this plan**

Check each completed box only after its matching red-green evidence exists. Append exact fresh test totals, failures, errors, skips, JavaScript checks, Wheel result, encryption/isolation checks, and Git scope audit without claiming skipped real-browser or Phase 6C/7 work.

### Task 6: Fresh verification and scope audit

**Files:**
- Inspect all modified files under `endpoint_agent/` and the full Git state only.

**Interfaces:**
- Consumes: the complete Phase 6B implementation and docs.
- Produces: completion evidence; no commit or push.

- [x] **Step 1: Run the complete Endpoint Agent regression**

Run: `python -m unittest discover -s endpoint_agent/tests -v`

- [x] **Step 2: Run every Phase 6B focused suite freshly**

```powershell
python -m unittest discover -s endpoint_agent/tests -p "test_confirmed_examples.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_example_store.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_example_calibration.py" -v
```

- [x] **Step 3: Run JavaScript syntax and offline Wheel checks**

```powershell
node --check endpoint_agent/extension/background.js
node --check endpoint_agent/extension/content.js
python -m pip wheel --no-index --no-deps .\endpoint_agent --wheel-dir .\endpoint_agent\dist\phase6b
```

- [x] **Step 4: Audit scope and generated artifacts**

```powershell
git status --short
git diff --stat
git diff -- endpoint_agent
git status --short -- app shielddome frontend extension web deploy scripts
```

Confirm no forbidden directory changed, no staged content exists, no raw mail/key/database/build artifact is tracked, all generated runtime categories remain ignored, and Phase 6C/7+ capabilities are absent.

## Execution Evidence

Fresh verification on 2026-08-03:

- Full Endpoint Agent regression: 201 tests run; 200 passed, 0 failures, 0 errors, and 1 skipped. The only skip is the pre-existing packaged Host contract because no Host `.exe` exists in this environment; it is Phase 5B work and does not waive any Phase 6B test.
- Focused Phase 6B suites: confirmed-example contracts 3/3 passed; encrypted store 9/9 passed; calibration 6/6 passed; no failures, errors, or skips.
- `node --check` passed for `extension/background.js` and `extension/content.js`.
- Offline `pip wheel --no-index --no-deps` succeeded. The generated 45,266-byte Wheel has SHA-256 `91707ce50f81748e51d582d945a2da8ab161c2eb19df60ab8090fecee20e619d` and is ignored by `/dist/`.
- Storage tests verified explicit-confirmation-only admission, current-user scope rejection, per-key fingerprints, same-user deduplication, conflict retention, encrypted retrieval, plaintext absence from SQLite/WAL/SHM and owned sidecars, authenticated tamper failure, capacity/query bounds, delete-one, and clear.
- Calibration and fusion tests verified exact/three-example consensus gates, low-similarity/insufficient/conflict rejection, bounded `-8/+18` adjustments, authentication/dangerous-URL/blacklist/dangerous-attachment strong floors, no sample-only `critical`, and non-blocking calibration failure.
- Offline guards and source-process tests verified no network client, listener, upload, model training, or model-weight mutation path.
- Git audit found no staged content. All Phase 6B changes are under `endpoint_agent/`; the two untracked `scripts/*.py` entries shown by the forbidden-directory status command were present in the initial user worktree and remain untouched. The generated Wheel is ignored, and no database, WAL, SHM, key, mail, or other runtime artifact is tracked.
- Phase 6B is `complete`; Phase 6 remains `in_progress` and Phase 6C remains `pending`. Phase 3, Phase 4B, Phase 5B, Phase 7, and later states were not advanced.
