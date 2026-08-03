# Phase 6A Encrypted Evidence Store Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a per-Windows-user encrypted Endpoint Evidence Record store with current-user DPAPI key protection, AES-256-GCM record encryption, a testable fifteen-day retention boundary, and explicit deletion of all local evidence data.

**Architecture:** A strict immutable evidence contract projects only approved fields from `DetectionOutcome`. `CurrentUserKeyProtector` wraps one random 256-bit data key with Windows DPAPI, `EvidenceCipher` encrypts every record independently with AES-GCM, and `EvidenceStore` owns SQLite indexing, retention, WAL cleanup, and cryptographic erasure. `NativeHostHandler` attempts persistence after detection and always returns the existing minimal detection projection when storage fails.

**Tech Stack:** Python 3.12, standard-library `unittest`, Windows CryptProtectData/CryptUnprotectData via `ctypes`, `cryptography==49.0.0` AESGCM, SQLite 3, Native Messaging.

## Global Constraints

- Modify only `endpoint_agent/`; preserve all pre-existing tracked and untracked work.
- Implement Phase 6A only. Do not implement Confirmed Example Library, calibration, diagnostics export, tray UI, dashboard, model training, ONNX, model download, attachment content handling, network clients, HTTP/WebSocket, or listeners.
- Production data defaults to `%LOCALAPPDATA%\ShieldDome\EndpointAgent`; never use a system-shared directory or cross-user database.
- Protect a random 32-byte data key with Windows DPAPI current-user scope; never set `CRYPTPROTECT_LOCAL_MACHINE`.
- Encrypt each record with AES-256-GCM and a fresh 12-byte nonce from the mature `cryptography` library.
- Persist only necessary SQLite index fields plus nonce, ciphertext, and authentication tag. Never persist subject, body, complete addresses, URLs, attachment content, or raw email.
- Default retention is exactly fifteen days; deletion occurs when `expires_at <= injected_now`.
- Decryption, key, schema, and authentication failures return no partial or half-trusted evidence.
- Storage failure must not block or alter the Native Host detection result.
- Native Messaging stdout must never contain mail content, keys, nonces, ciphertext, tags, or tracebacks.
- Do not download dependencies. `cryptography==49.0.0` is already available offline in the development environment; document that the matching runtime wheel and transitive wheels must be included in an approved offline Endpoint Release build cache.
- Do not commit, push, create a branch, or create a PR.

---

### Task 1: Strict Endpoint Evidence Record contract

**Files:**
- Create: `endpoint_agent/src/shielddome_endpoint/evidence_record.py`
- Create: `endpoint_agent/tests/test_evidence_record.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/__init__.py`

**Interfaces:**
- Consumes: `DetectionOutcome`, `RiskLevel`, `GenericAction`, `DetectionExecutionState`, and `ModelExecutionStatus` from `domain.py`.
- Produces: `EVIDENCE_RECORD_SCHEMA_VERSION = "1.0"`; immutable `EndpointEvidenceRecord`; `EndpointEvidenceRecord.from_detection_outcome(outcome, *, detected_at, source_kind)`; `to_json_bytes()`; `from_json_bytes(payload)`; stable `EvidenceRecordValidationError`.

- [x] **Step 1: Write one failing public-contract test**

```python
record = EndpointEvidenceRecord.from_detection_outcome(
    outcome,
    detected_at=DETECTED_AT,
    source_kind="browser_native",
)
self.assertEqual(record.local_event_id, outcome.local_event_id)
self.assertEqual(record.rule_codes, ("sender_reply_domain_mismatch",))
self.assertTrue(record.degraded)
self.assertEqual(record.retention_until, DETECTED_AT + timedelta(days=15))
```

- [x] **Step 2: Run the single module and confirm red**

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_evidence_record.py" -v`

Expected: FAIL because `shielddome_endpoint.evidence_record` does not exist.

- [x] **Step 3: Implement the minimal immutable projection and canonical JSON round trip**

```python
@dataclass(frozen=True, slots=True)
class EndpointEvidenceRecord:
    local_event_id: str
    detected_at: datetime
    retention_until: datetime
    risk_level: RiskLevel
    detection_status: DetectionExecutionState
    generic_action: GenericAction
    source_kind: str
    rule_codes: tuple[str, ...]
    abstained: bool
    degraded: bool
    model_execution_status: ModelExecutionStatus | None
    error_code: str | None
    schema_version: str = EVIDENCE_RECORD_SCHEMA_VERSION
```

Use exact-key JSON decoding, stable-code validation, aware UTC datetimes, maximum 128-character event IDs, maximum 32-character source kinds, maximum 64 rule codes, and maximum 64 characters for every stable rule/error code. Reject unknown/missing fields, incompatible schema, booleans in typed positions, invalid enum values, naive times, retention windows other than exactly fifteen days, and trailing/non-object JSON with `EvidenceRecordValidationError("invalid_evidence_record")`.

- [x] **Step 4: Add red-green slices for illegal schema, unknown fields, overlong fields, and sensitive source fields**

```python
for mutation in (
    {**payload, "schema_version": "future"},
    {**payload, "subject": "private subject"},
    {**payload, "source_kind": "x" * 33},
):
    with self.assertRaisesRegex(EvidenceRecordValidationError, "^invalid_evidence_record$"):
        EndpointEvidenceRecord.from_json_bytes(json.dumps(mutation).encode())
```

Run the module after each test/implementation slice until it exits 0.

### Task 2: Current-user DPAPI data-key protection

**Files:**
- Create: `endpoint_agent/src/shielddome_endpoint/key_protection.py`
- Create: `endpoint_agent/tests/test_key_protection.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/__init__.py`

**Interfaces:**
- Consumes: `%LOCALAPPDATA%`, Windows `crypt32!CryptProtectData`, `crypt32!CryptUnprotectData`, and current-user SID lookup.
- Produces: `default_user_data_directory()`; `CurrentUserKeyProtector.protect(bytes) -> bytes`; `CurrentUserKeyProtector.unprotect(bytes) -> bytes`; `UserDataKeyManager.load_or_create() -> bytes`; `UserDataKeyManager.delete()`; stable `KeyProtectionError`.

- [x] **Step 1: Write and run a failing real-Windows DPAPI round-trip test**

```python
@unittest.skipUnless(sys.platform == "win32", "Windows DPAPI integration")
def test_real_dpapi_round_trip_uses_current_user_scope(self):
    protector = CurrentUserKeyProtector()
    protected = protector.protect(b"k" * 32)
    self.assertNotEqual(protected, b"k" * 32)
    self.assertEqual(protector.unprotect(protected), b"k" * 32)
```

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_key_protection.py" -v`

Expected: FAIL before implementation.

- [x] **Step 2: Implement DPAPI with current-user flags only**

Call DPAPI with `CRYPTPROTECT_UI_FORBIDDEN = 0x1`, assert the flags do not contain `CRYPTPROTECT_LOCAL_MACHINE = 0x4`, free all DPAPI output buffers with `LocalFree`, and convert every Windows error into `KeyProtectionError("key_protection_failed")` or `KeyProtectionError("key_unprotection_failed")` without including input, output, SID, or exception text.

- [x] **Step 3: Add red-green tests for scope isolation and flag safety**

```python
self.assertEqual(call.flags & CRYPTPROTECT_LOCAL_MACHINE, 0)
with self.assertRaisesRegex(KeyProtectionError, "^user_scope_mismatch$"):
    other_scope_protector.unprotect(protected_by_current_scope)
```

The protected envelope carries a SHA-256 digest of the current SID and the DPAPI blob. The real DPAPI round trip proves OS integration; an injected SID provider tests rejection of a copied blob in a different user scope without creating or modifying Windows accounts.

- [x] **Step 4: Add red-green tests for random key creation, corruption, and per-user path selection**

Create the 32-byte key only when both the key and evidence database are absent; write it atomically as DPAPI ciphertext under `%LOCALAPPDATA%\ShieldDome\EndpointAgent\keys`; never regenerate over a corrupt/missing key for an existing database. Verify two independent LOCALAPPDATA roots use different key files and random keys.

### Task 3: AES-256-GCM evidence encryption

**Files:**
- Create: `endpoint_agent/src/shielddome_endpoint/evidence_crypto.py`
- Create: `endpoint_agent/tests/test_evidence_crypto.py`
- Modify: `endpoint_agent/pyproject.toml`
- Modify: `endpoint_agent/_build_backend.py`
- Modify: `endpoint_agent/tests/test_build.py`

**Interfaces:**
- Consumes: a validated 32-byte data key, `EndpointEvidenceRecord`, and caller-provided associated data.
- Produces: immutable `EncryptedEvidence(nonce, ciphertext, authentication_tag)`; `EvidenceCipher.encrypt(record, *, associated_data)`; `EvidenceCipher.decrypt(encrypted, *, associated_data)`; stable `EvidenceCryptoError`.

- [x] **Step 1: Write and run a failing randomized-encryption test**

```python
first = cipher.encrypt(record, associated_data=b"event-001")
second = cipher.encrypt(record, associated_data=b"event-001")
self.assertNotEqual(first.nonce, second.nonce)
self.assertNotEqual(first.ciphertext, second.ciphertext)
self.assertEqual(cipher.decrypt(first, associated_data=b"event-001"), record)
```

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_evidence_crypto.py" -v`

Expected: FAIL because the cipher module does not exist.

- [x] **Step 2: Implement minimal AESGCM encryption**

Use `AESGCM(key).encrypt(secrets.token_bytes(12), plaintext, associated_data)` and split the final 16 bytes as the authentication tag. Reject all non-32-byte keys, non-12-byte nonces, non-16-byte tags, empty ciphertext, and oversized encrypted values with stable errors.

- [x] **Step 3: Add red-green tamper and wrong-key slices**

Flip one bit separately in nonce, ciphertext, tag, and associated data; each decrypt must raise `EvidenceCryptoError("evidence_decryption_failed")` and return no record. A second random key must also fail with the same stable code.

- [x] **Step 4: Declare and emit the offline runtime dependency**

Set `dependencies = ["cryptography==49.0.0"]`. Extend `_build_backend.py` to emit one `Requires-Dist: cryptography==49.0.0` line from the project dependency list. Update `test_build.py` to require the new evidence modules and exact metadata while retaining the `--no-index --no-deps` build.

### Task 4: SQLite evidence store, retention, and safe deletion

**Files:**
- Create: `endpoint_agent/src/shielddome_endpoint/evidence_store.py`
- Create: `endpoint_agent/tests/test_evidence_store.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/__init__.py`
- Modify: `endpoint_agent/tests/test_repository_hygiene.py`

**Interfaces:**
- Consumes: `UserDataKeyManager`, `EvidenceCipher`, `EndpointEvidenceRecord`, and an injected aware-UTC clock.
- Produces: `EvidenceStore.put(record)`; `get(local_event_id)`; `list_page(*, offset=0, limit=50)`; `cleanup_expired(now=None)`; `delete_all()`; stable `EvidenceStoreError`.

- [x] **Step 1: Write and run a failing put/get/page test**

```python
store.put(first)
store.put(second)
self.assertEqual(store.get(first.local_event_id), first)
self.assertEqual(store.list_page(offset=0, limit=1), (second,))
self.assertEqual(store.list_page(offset=1, limit=1), (first,))
```

Run: `python -m unittest discover -s endpoint_agent/tests -p "test_evidence_store.py" -v`

Expected: FAIL because the store module does not exist.

- [x] **Step 2: Implement the minimal per-user SQLite schema and CRUD**

Use one `endpoint_evidence` table with only `local_event_id`, `detected_at_utc`, `expires_at_utc`, `schema_version`, `nonce`, `ciphertext`, and `authentication_tag`; use `WITHOUT ROWID`, `journal_mode=WAL`, `secure_delete=ON`, and `temp_store=MEMORY`. Associated data must canonically bind every plaintext index field. `get` and `list_page` decrypt, validate, and compare all index fields before returning any record.

- [x] **Step 3: Add red-green privacy and event-isolation slices**

Persist records derived from observations containing a unique subject, body, address, URL, and attachment name. Search the database, WAL, SHM, journal, and key file bytes; none may contain those UTF-8 values. Repeated puts and reads for different event IDs must never mix records. Tamper with SQLite nonce/ciphertext/tag in a test fixture and require a stable error with no partial page.

- [x] **Step 4: Add red-green fifteen-day boundary cleanup**

```python
self.assertEqual(store.cleanup_expired(now=expiry - timedelta(microseconds=1)), 0)
self.assertEqual(store.cleanup_expired(now=expiry), 1)
self.assertIsNone(store.get("event-expired"))
```

Reject naive clocks and use the injected clock when `now` is omitted.

- [x] **Step 5: Add red-green full-deletion cleanup**

Delete all rows with SQLite secure deletion, checkpoint/truncate WAL, vacuum, close connections, overwrite owned database/key/journal/WAL/SHM/temp files before unlinking where supported, and remove only known ShieldDome-owned paths. Verify records, protected key, `-wal`, `-shm`, `-journal`, and owned `.tmp` files no longer exist. Repeated deletion must be idempotent.

### Task 5: Native Host non-blocking persistence

**Files:**
- Modify: `endpoint_agent/src/shielddome_endpoint/native_host.py`
- Modify: `endpoint_agent/tests/test_native_host.py`
- Modify: `endpoint_agent/tests/test_native_host_process.py`

**Interfaces:**
- Consumes: lazy `Callable[[], EvidenceStore]`, `EndpointEvidenceRecord.from_detection_outcome`, and the existing detection outcome.
- Produces: unchanged four-field Native Messaging response plus best-effort local evidence persistence.

- [x] **Step 1: Write and run a failing storage-failure response test**

```python
handler = NativeHostHandler(
    DEVELOPMENT_EXTENSION_ORIGIN,
    evidence_store_factory=lambda: FailingEvidenceStore(),
    clock=lambda: OBSERVED_AT,
    event_id_factory=lambda: "event-storage-failure",
)
self.assertEqual(set(handler(detect_message())), ALLOWED_PLUGIN_FIELDS)
```

The fake store raises an exception containing subject/body/key/ciphertext-shaped values; assert none appears in framed stdout.

- [x] **Step 2: Implement lazy best-effort persistence after detection**

Create the store only after a successful detection, project the record, call `put`, catch storage/projection exceptions without printing or changing the detection response, and retain no record or mail content on the handler between calls beyond the store object itself.

- [x] **Step 3: Add red-green success and consecutive-request isolation tests**

Inject a recording store and assert each event produces exactly one matching record with its own ID/source/status. Update subprocess tests to set a unique temporary `LOCALAPPDATA` per host run so production defaults are exercised without touching the developer's actual profile data.

### Task 6: Phase status, usage, dependency, and privacy documentation

**Files:**
- Modify: `endpoint_agent/README.md`
- Modify: `endpoint_agent/DEVELOPMENT_PLAN.md`
- Modify: `endpoint_agent/docs/USAGE.md`
- Modify: `endpoint_agent/AGENTS.md`
- Modify: `endpoint_agent/docs/plans/2026-08-03-phase-6a-encrypted-evidence-store.md`

**Interfaces:**
- Consumes: fresh test results from Tasks 1–5.
- Produces: conservative Phase 6A/6B/6C status and exact offline deployment instructions.

- [x] **Step 1: Split Phase 6 conservatively**

Document Phase 6 as `in_progress`, Phase 6A as `complete` only if all required fresh Windows/crypto/privacy/retention/regression checks pass, Phase 6B as `pending`, and Phase 6C as `pending`. Keep Phase 5B `in_progress` and Phase 7 `pending`.

- [x] **Step 2: Document the public store contract and privacy boundary**

List approved evidence fields, `%LOCALAPPDATA%` paths, current-user DPAPI, AES-256-GCM, 15-day `expires_at <= now` semantics, safe decryption failure, page ordering, full deletion, and non-blocking Native Host behavior. State that cryptography runtime wheels must come from an approved offline build cache and no download occurs at runtime.

- [x] **Step 3: Record execution evidence in this plan**

Check each completed box only after its red-green evidence exists. If real DPAPI or AESGCM cannot run, leave Phase 6A and the corresponding boxes `in_progress` and record the exact blocker without substituting a fake.

**Execution evidence through Task 6:**

- Evidence Record, DPAPI, AES-GCM, retention, all-delete, Native Host storage-failure, package export, unknown database schema, empty cleanup, and directory-boundary slices each produced the expected failing test before their minimal implementation.
- The real Windows DPAPI test invokes `CryptProtectData` and `CryptUnprotectData` under the current logged-in user; the separate scope/flag test confirms no `CRYPTPROTECT_LOCAL_MACHINE` flag and rejects a copied protected envelope under a different SID scope.
- The development integration run after Tasks 1–5 executed 176 Endpoint Agent tests with exit code 0 and one pre-existing packaged-Host skip. Task 7 repeats all required commands freshly before completion.

### Task 7: Fresh verification and scope audit

**Files:**
- Inspect only all modified files under `endpoint_agent/` and the Git state.

**Interfaces:**
- Consumes: completed implementation and docs.
- Produces: evidence for the final report; no commit or push.

- [x] **Step 1: Run focused suites**

```powershell
python -m unittest discover -s endpoint_agent/tests -p "test_key_protection.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_evidence_crypto.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_evidence_store.py" -v
```

- [x] **Step 2: Run the complete Endpoint Agent regression**

```powershell
python -m unittest discover -s endpoint_agent/tests -v
```

- [x] **Step 3: Run syntax, offline Wheel, and privacy checks**

```powershell
node --check endpoint_agent/extension/background.js
node --check endpoint_agent/extension/content.js
python -m pip wheel --no-index --no-deps .\endpoint_agent --wheel-dir .\endpoint_agent\dist\phase6a
```

- [x] **Step 4: Audit Git scope and generated artifacts**

```powershell
git status --short
git diff --stat
git diff -- endpoint_agent
git status --short -- app shielddome frontend extension web deploy scripts
```

Confirm no forbidden directory changed, no sensitive runtime file is tracked, build output is ignored, no staged diff exists, and Phase 6B/6C/7 capabilities are absent.

**Fresh verification evidence:**

- Full Endpoint Agent regression: 176 tests run; 175 passed; 0 failures; 0 errors; 1 existing packaged-Host skip; exit code 0.
- `test_key_protection.py`: 6 tests passed, including real current-user Windows DPAPI; exit code 0.
- `test_evidence_crypto.py`: 2 tests passed; exit code 0.
- `test_evidence_store.py`: 7 tests passed; exit code 0.
- `node --check` passed for `background.js` and `content.js`; exit code 0.
- Offline Wheel build passed with `--no-index --no-deps`; produced a 35,504-byte Wheel with SHA-256 `9faf0af252067b756f29bd3a07ec3e0337a4e722f1e03c2c74ab28e7795b3e05`.
- Git audit found no tracked or staged diff in `app/`, `shielddome/`, `frontend/`, `extension/`, `web/`, `deploy/`, or `scripts/`; the two untracked `scripts/build_*.py` files were present in the starting baseline and remain untouched. Phase 6A changes are confined to `endpoint_agent/`, and the built Wheel/database/key categories are ignored.
