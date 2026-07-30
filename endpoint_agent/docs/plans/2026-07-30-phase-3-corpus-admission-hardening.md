# Phase 3 Corpus Admission Hardening Implementation Plan

> **For Codex:** Follow `$executing-plans` and `$tdd`. Complete each public-behavior slice with a witnessed failing test before the minimum implementation. This plan hardens Phase 3 prerequisites only; it does not start Phase 3 model development.

**Goal:** Make `CorpusGovernance.prepare(candidates, split_policy) -> CorpusSnapshot` the single fail-closed admission seam for human labeling, provenance, authorization, privacy, and redistribution rights while keeping manifests deterministic and non-sensitive.

**Architecture:** Extend the immutable corpus domain facts, keep all admission policy inside `CorpusGovernance`, and project only audit-safe facts into a versioned manifest. `PrivacyScanner` remains a structural boundary checker that returns only a boolean and stable violation codes. No intake adapter, model code, service, storage, or network capability is added.

**Tech Stack:** Python 3.12 standard library, frozen slotted dataclasses, `StrEnum`, SHA-256, `unittest`, offline setuptools wheel build.

---

## Public interfaces and invariants

- The only corpus admission interface remains `CorpusGovernance.prepare(candidates, split_policy) -> CorpusSnapshot`.
- `CorpusCandidate` contains immutable, non-sensitive facts only. New required fields have no permissive defaults.
- New enums are `AuthorizationStatus` and `PrivacyReviewStatus`; both are re-exported by `shielddome_endpoint`.
- `CorpusManifestEntry` contains governance facts and digests, never `sanitized_training_representation` or evidence payloads.
- `CorpusManifest.digest` is a canonical SHA-256 over the schema version and ordered entry projection. Input order cannot change it; any projected authorization, review, or privacy fact must change it.
- Authorization expiry is evaluated deterministically against the candidate's `ingested_at` admission timestamp. A perpetual grant must be explicit; expiry and perpetual status are mutually exclusive.
- `PrivacyScanner` returns only `PrivacyScanResult(safe, violations)` with sorted, deduplicated codes.
- `CORPUS_SCHEMA_VERSION` changes from `2.0` to `3.0` because the public manifest contract changes. Historical Phase 2 artifacts remain untouched.

## Stable rejection codes

| Category | Stable code |
| --- | --- |
| Label governance | `missing_label_guideline_version`, `invalid_label_guideline_version`, `missing_label_evidence_id`, `invalid_label_evidence_id`, `missing_reviewer_id`, `invalid_reviewer_id`, `invalid_review_time`, `missing_review_policy_version`, `invalid_review_policy_version` |
| Source provenance | `missing_source_dataset_id`, `invalid_source_dataset_id`, `missing_source_version`, `invalid_source_version`, `invalid_source_evidence_digest` |
| Authorization | `missing_authorization_basis_id`, `invalid_authorization_basis_id`, `authorization_not_active`, `internal_training_not_allowed`, `endpoint_weight_distribution_not_allowed`, `invalid_authorization_approval_time`, `missing_authorization_expiry`, `conflicting_authorization_expiry`, `invalid_authorization_expiry`, `authorization_expired` |
| Privacy | `privacy_not_approved`, `missing_sanitization_policy_version`, `invalid_sanitization_policy_version`, `invalid_privacy_review_time`, `invalid_privacy_evidence_digest`, `invalid_sanitized_representation_digest`, `sanitized_representation_digest_mismatch` |
| Existing policy | Existing duplicate, label-conflict, source/time holdout, split isolation, schema, hash, and safe-identifier codes remain unchanged. |

Rejections contain only `item_id` and one stable code. They never echo the rejected value.

### Task 1: Human-review governance gate

**Files:**
- Modify: `endpoint_agent/tests/test_corpus_governance.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/corpus.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/__init__.py`

1. Extend the fictional candidate helper with valid label guideline, label evidence, reviewer, review time, and review policy facts.
2. Add one public test that varies each missing or invalid fact and asserts the exact stable rejection projection.
3. Run the corpus test and witness failure because `CorpusCandidate` lacks the fields or `prepare` admits the candidate.
4. Add the required immutable fields and fail-closed checks using safe identifier and aware-time helpers.
5. Run:

```powershell
python -m unittest discover -s endpoint_agent/tests -p "test_corpus_governance.py" -v
```

### Task 2: Source provenance and authorization evidence gates

**Files:**
- Modify: `endpoint_agent/tests/test_corpus_governance.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/corpus.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/__init__.py`

1. Add public tests for dataset ID/version, canonical source evidence digest, authorization basis, and allowed authorization states.
2. Witness the targeted failures.
3. Add `AuthorizationStatus` and the required provenance/authorization fields and checks.
4. Add tests proving `internal_training_allowed` and `endpoint_weight_distribution_allowed` must each be exactly `True`.
5. Witness failures, implement the two distinct gates, and rerun the corpus test after each behavior.

### Task 3: Authorization time and expiry gate

**Files:**
- Modify: `endpoint_agent/tests/test_corpus_governance.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/corpus.py`

1. Add tests for missing/naive authorization approval time, missing expiry disposition, simultaneous expiry and perpetual status, naive expiry, and expiry at or before `ingested_at`.
2. Witness targeted failures.
3. Implement deterministic, aware-time validation without a wall-clock or network dependency.
4. Rerun the corpus test.

### Task 4: Privacy approval and digest gates

**Files:**
- Modify: `endpoint_agent/tests/test_corpus_governance.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/corpus.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/__init__.py`

1. Add tests for privacy approval, sanitization policy, privacy review time, canonical privacy evidence digest, canonical sanitized representation digest, and digest/content mismatch.
2. Witness failures.
3. Add `PrivacyReviewStatus`, immutable privacy facts, and fail-closed checks.
4. Rerun the corpus test.

### Task 5: Manifest hardening and deterministic digest

**Files:**
- Modify: `endpoint_agent/tests/test_corpus_governance.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/corpus.py`
- Modify: `endpoint_agent/tests/test_package.py`
- Modify: `endpoint_agent/training_tests/test_onnx_validation.py`

1. Add tests that enumerate the manifest entry schema, assert the sanitized representation is absent, compare repeated/reordered inputs, and prove every new governance category changes `CorpusManifest.digest`.
2. Witness failures.
3. Project only stable identifiers, digests, statuses, booleans, UTC timestamps, groups, and split into `CorpusManifestEntry`.
4. Compute the manifest digest with canonical JSON and SHA-256; bump `CORPUS_SCHEMA_VERSION` to `3.0` and update contract assertions only.
5. Rerun corpus and package tests. Do not alter Phase 2 model or evaluation artifacts.

### Task 6: PrivacyScanner structural boundary

**Files:**
- Modify: `endpoint_agent/tests/test_privacy.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/privacy.py`

1. Update helpers to use fully fictional valid governance facts.
2. Add tests that inject fictional unsafe values into new candidate/manifest fields and assert only sorted, unique violation codes are returned.
3. Add assertions that results do not contain the source string, URL query, credential, path, or identity-like value.
4. Witness targeted failures if the scanner leaks or misses a category.
5. Make the minimum structural scanning change needed; do not add mail redaction behavior.
6. Run:

```powershell
python -m unittest discover -s endpoint_agent/tests -p "test_privacy.py" -v
```

### Task 7: Regression behavior and documentation

**Files:**
- Modify: `endpoint_agent/tests/test_corpus_governance.py`
- Modify: `endpoint_agent/docs/USAGE.md`
- Modify: `endpoint_agent/docs/TRAINING.md`
- Modify: `endpoint_agent/README.md`
- Optionally append only: `endpoint_agent/docs/plans/2026-07-30-phase-3-readiness-audit.md`

1. Run the existing exact/normalized duplicate, label conflict, source/time holdout, and split isolation tests.
2. Preserve the readiness audit's `NO-GO` conclusion and Phase 3 `pending` state.
3. Document the new required facts, rejection behavior, manifest digest, offline/non-sensitive boundary, and `CORPUS_SCHEMA_VERSION = "3.0"`.
4. Do not document any model selection, training, export, or approved corpus that does not exist.

### Task 8: Verification before completion

**Files:**
- Verify only; build output: `endpoint_agent/dist/corpus-hardening/`

Run exactly:

```powershell
python -m unittest discover -s endpoint_agent/tests -p "test_corpus_governance.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_privacy.py" -v
python -m unittest discover -s endpoint_agent/tests -v
.\endpoint_agent\.venv-training\Scripts\python.exe -m unittest discover -s endpoint_agent/training_tests -v
python -c "import sys; sys.path.insert(0, r'endpoint_agent/src'); import shielddome_endpoint as s; print(s.__version__, s.FEATURE_SCHEMA_VERSION, s.CORPUS_SCHEMA_VERSION)"
python -m pip wheel --no-index --no-deps .\endpoint_agent --wheel-dir .\endpoint_agent\dist\corpus-hardening
git status --short
git diff --stat
git diff -- endpoint_agent
git status --short -- app shielddome frontend extension web deploy scripts phishingDP-main
```

Also verify `DEVELOPMENT_PLAN.md` still says Phase 3 is `pending`, no protected directory changed, and no model, corpus, email, or training artifact was newly tracked. The offline wheel is a packaging output only and must remain untracked. Do not commit or push.

## Completion conditions

- Every required label, source, authorization, rights, expiry, and privacy fact is represented immutably and enforced with stable rejection codes.
- Both internal-training permission and endpoint-weight-distribution permission require separate explicit approval.
- Expired or invalid authorization is not admitted.
- Manifest content and digest are deterministic, order-independent, sensitive-content-free, and governance-fact-complete.
- Privacy scanning exposes only stable codes.
- Existing duplicate/conflict/holdout/split behavior remains green.
- Endpoint Agent and affected training contract tests pass; offline wheel build succeeds.
- Phase 3 remains `pending` and the readiness conclusion remains `NO-GO`.
- Only `endpoint_agent/` is modified; there is no commit or push.
