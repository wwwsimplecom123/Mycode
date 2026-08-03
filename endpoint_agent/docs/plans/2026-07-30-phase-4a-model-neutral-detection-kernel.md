# Phase 4A Model-Neutral Detection Kernel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `$executing-plans` and `$tdd` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. The user forbids commits, pushes, branches, and PRs for this work.

**Goal:** Deliver a deterministic, fully offline Detection Kernel that remains useful in rules-only mode and can later accept a release-approved Local Mail Risk Model through a stable interface.

**Architecture:** `DetectionKernel.detect(...)` is the top-level deep-module interface. It receives an immutable `FeatureVector`, already-formed immutable `RuleAssessment` values, an injected local event ID/time, and an optional `LocalInference` adapter; it hides assessment validation, exception degradation, risk fusion, and private/plugin projections. `LocalInference.infer(feature_vector, context)` is the only model seam; Phase 4A supplies a side-effect-free `UnavailableModelAdapter`, while deterministic fake adapters remain test-only.

**Tech Stack:** Python 3.12 standard library, `typing.Protocol`, frozen slotted dataclasses, `StrEnum`, `unittest`, and the existing zero-dependency offline PEP 517 wheel builder.

## Global Constraints

- Modify only `endpoint_agent/`; preserve every pre-existing tracked and untracked file outside it.
- Phase 3 remains `pending`; Phase 4 becomes `in_progress` only after all Phase 4A acceptance checks pass.
- Phase 4A must not train, download, load, or publish a model and must not add an ONNX Runtime adapter or placeholder.
- Production code must remain fully offline and have zero third-party runtime dependencies.
- Do not add Native Messaging, HTTP/WebSocket/TCP/UDP, storage, encryption, UI, `.eml` intake, attachment access, or later-phase placeholders.
- Keep `FEATURE_SCHEMA_VERSION = "2.0"` and `CORPUS_SCHEMA_VERSION = "3.0"` unchanged.
- Model faults and invalid output must return a rule-derived `DetectionOutcome`; they must not leak adapter exceptions or private values.
- Each listed public behavior gets an observed red test before its minimum green implementation; no bulk test-first horizontal slice.
- Do not commit, push, create a branch, or open a PR.

---

## Domain model and fixed interfaces

Canonical distinctions:

- `ModelAssessment` is untrusted output from one Local Mail Risk Model invocation. It is never the final verdict.
- `RuleAssessment` is an already-formed, non-sensitive deterministic rule fact. The Kernel does not parse mail or recreate server rules.
- `DetectionExecutionState.RULES_ONLY` means the caller deliberately supplied no model adapter. `MODEL_UNAVAILABLE`, `MODEL_TIMEOUT`, `MODEL_ERROR`, and `MODEL_INVALID_OUTPUT` describe attempted model execution that degraded to rules.
- `StructuredPrivateEvidence` is an in-memory, non-sensitive projection, not an Endpoint Evidence Record and not permission to persist anything.

The implementation must keep these exact seams:

```python
class LocalInference(Protocol):
    def infer(
        self,
        feature_vector: FeatureVector,
        context: InferenceContext,
    ) -> ModelAssessment: ...


class DetectionKernel:
    def __init__(self, inference: LocalInference | None = None) -> None: ...

    def detect(
        self,
        feature_vector: FeatureVector,
        rule_assessments: tuple[RuleAssessment, ...],
        *,
        local_event_id: str,
        detected_at: datetime,
        inference_context: InferenceContext,
    ) -> DetectionOutcome: ...
```

`InferenceContext.max_duration_ms` is an integer from 1 through 60,000. The default acceptance examples use 3,000 ms. `DetectionKernel.detect` accepts timezone-aware `detected_at` and derives the retention deadline as exactly 15 days later; it never reads the wall clock.

`ModelAssessment` changes to an explicitly optional success payload:

```python
@dataclass(frozen=True, slots=True)
class ModelAssessment:
    probability: float | None
    confidence_state: ModelConfidenceState | None
    execution_status: ModelExecutionStatus
    model_version: str | None
    feature_schema_version: str | None
    duration_ms: int
    error_code: str | None = None
    schema_version: str = MODEL_ASSESSMENT_SCHEMA_VERSION
```

Success requires a finite probability in `[0, 1]`, an allowed confidence state, a safe model version, compatible Feature Schema 2.0, a non-negative bounded duration within the invocation budget, no error code, and the current Model Assessment schema. Failure statuses carry no probability, confidence state, or model version. Invalid output becomes `model_invalid_output`; budget overrun becomes `model_timeout`. Stable codes use lower snake case and never include exception text or paths.

The immutable deterministic rule contract is:

```python
@dataclass(frozen=True, slots=True)
class RuleAssessment:
    rule_id: str
    category: RuleCategory
    severity: RuleSeverity
    score_contribution: int
    strong_evidence: bool
    evidence_code: str
    generic_action: GenericAction
```

`rule_id` and `evidence_code` are lower-snake stable codes; score contribution is 0–100. Duplicate rule IDs contribute once, choosing the most conservative value by a documented deterministic ordering independent of input order.

Risk mapping and strong floors are centralized in `risk_fusion.py`:

| Risk level | Score |
| --- | --- |
| `low` | 0–24 |
| `medium` | 25–49 |
| `high` | 50–79 |
| `critical` | 80–100 |

Strong `low`, `medium`, `high`, and `critical` evidence establish floors of 20, 40, 70, and 90. Confident phishing adds at most 25 points; model evidence alone cannot create a critical result, and a positive model adjustment cannot push a sub-critical rule score above 79. Confident benign removes at most 5 points and never crosses a strong floor. Uncertain and every degraded state add no model adjustment. The final score is clamped to 0–100.

### Task 1: Local Inference seam and unavailable behavior

**Files:**
- Create: `endpoint_agent/tests/test_inference.py`
- Create: `endpoint_agent/src/shielddome_endpoint/inference.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/domain.py`

**Interfaces:**
- Consumes: existing `FeatureVector`.
- Produces: `InferenceContext`, `LocalInference`, `ModelConfidenceState`, `ModelExecutionStatus`, versioned `ModelAssessment`, and `UnavailableModelAdapter`.

- [ ] Add one test that calls `UnavailableModelAdapter().infer(vector, InferenceContext(3000))` only through a variable typed `LocalInference` and expects `UNAVAILABLE`, `probability is None`, `confidence_state is None`, `model_version is None`, zero duration, and `model_not_configured`.
- [ ] Patch `pathlib.Path.open`, `Path.read_bytes`, `Path.write_bytes`, and `socket.socket` in that test to fail if called, then run the required inference test command and observe import failure because `inference.py` does not exist.
- [ ] Add the enums, frozen `InferenceContext`, `LocalInference` protocol, optional-success `ModelAssessment`, and the side-effect-free adapter with the exact return value asserted above.
- [ ] Rerun `python -m unittest discover -s endpoint_agent/tests -p "test_inference.py" -v` and require exit 0 before the next behavior.

### Task 2: Model Assessment validation

**Files:**
- Modify: `endpoint_agent/tests/test_inference.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/inference.py`

**Interfaces:**
- Consumes: `ModelAssessment`, expected Feature Schema version, and `InferenceContext`.
- Produces: immutable `ValidatedModelAssessment` with sanitized `assessment`, `execution_state`, `degraded`, and stable `error_code`.

- [ ] Add a passing-success test for a compatible 0.72 assessment and observe failure because `validate_model_assessment` is absent; implement the minimum normalizer and rerun.
- [ ] Add one table-driven test for `NaN`, positive/negative infinity, values below zero and above one; observe red, then map each to `MODEL_INVALID_OUTPUT` with `invalid_model_assessment` and no retained assessment.
- [ ] Add one table-driven test for illegal confidence/execution values, incompatible Feature Schema 2.0, negative/non-integer/over-60,000 duration, bad assessment schema, unsafe/missing success model version, unsafe error code, success with error code, and failure carrying probability/confidence/model version; observe red, implement fail-closed validation, and rerun.
- [ ] Add a budget test where a syntactically valid 3,001 ms success under a 3,000 ms context becomes `MODEL_TIMEOUT` with `inference_budget_exceeded`; observe red, implement, and rerun the inference module.

### Task 3: Pure-rule risk fusion

**Files:**
- Create: `endpoint_agent/tests/test_risk_fusion.py`
- Create: `endpoint_agent/src/shielddome_endpoint/risk_fusion.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/domain.py`

**Interfaces:**
- Consumes: tuple of `RuleAssessment`, optional validated successful `ModelAssessment`, and `DetectionExecutionState`.
- Produces: immutable `RiskFusionResult` containing final score/level/action, rule score, model adjustment, risk floor, strong-evidence flag, and deduplicated rule assessments.

- [ ] Add a zero-evidence rules-only test expecting score 0, `low`, `continue`, and no strong evidence; run the risk-fusion command and observe missing interface.
- [ ] Add the rule enums/dataclass plus `fuse_risk(...)` with centralized thresholds and clamping; rerun green.
- [ ] Add separate red-green behaviors for one weak contribution, multiple contributions, strong severity floors, 0–100 clamping, input-order invariance, and duplicate rule-ID single counting.
- [ ] Keep rule validation at the immutable contract constructor with stable `invalid_rule_assessment`; never retain or echo rejected values.

### Task 4: Model and rule fusion

**Files:**
- Modify: `endpoint_agent/tests/test_risk_fusion.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/risk_fusion.py`

**Interfaces:**
- Consumes the validated assessment/state produced by Task 2.
- Produces deterministic bounded model adjustments without changing the Task 3 interface.

- [ ] Add a confident-phishing test with no strong rules; observe red, then add the bounded positive adjustment and no-strong critical cap.
- [ ] Add a confident-benign test; observe red, then add the maximum five-point protective adjustment.
- [ ] Add one table-driven uncertain/unavailable/timeout/error/invalid-output test expecting zero model adjustment; observe red and implement.
- [ ] Add a strong-evidence plus 0.0 confident-benign test expecting its risk floor and action to remain; observe red and enforce floors after model adjustment.

### Task 5: Detection Kernel outcome and degradation

**Files:**
- Create: `endpoint_agent/tests/_detection_fakes.py`
- Create: `endpoint_agent/tests/test_detection_kernel.py`
- Create: `endpoint_agent/src/shielddome_endpoint/detection_kernel.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/domain.py`

**Interfaces:**
- Consumes the exact `DetectionKernel` interface fixed above.
- Produces `DetectionOutcome` schema 2.0 with immutable `StructuredPrivateEvidence` and exact tuple-pair plugin projection.

- [ ] Put `FakeModelAdapter` only in `_detection_fakes.py`; it implements `LocalInference.infer` and can return one configured assessment or raise one configured exception.
- [ ] Add a success test asserting caller-supplied event ID, `detected_at + 15 days`, model-success execution state, and a deterministic outcome; run the detection-kernel command and observe missing interface.
- [ ] Implement `DetectionKernel.detect` to call the adapter, validate output, fuse risk, and create the outcome. Rerun green.
- [ ] Add one red-green uncertain test and one red-green no-adapter rules-only test.
- [ ] Add separate red-green tests for unavailable, returned timeout, returned error, invalid assessment, duration-over-budget, and raised adapter exception; each must return a rules-derived outcome and stable state. Exception messages must never enter the result.
- [ ] Add red-green validation for timezone-aware `detected_at` and safe local event ID using stable `invalid_detection_context` without reflecting rejected values.

### Task 6: Exact minimal plugin projection

**Files:**
- Modify: `endpoint_agent/tests/test_detection_kernel.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/detection_kernel.py`

**Interfaces:**
- Produces exactly four ordered fields: `local_event_id`, `risk_level`, `execution_state`, and `generic_action`.

- [ ] Add an exact field-set and order assertion for `minimal_plugin_projection`; include internal model/rule fields in the fake input and assert none appear in the projection serialization.
- [ ] Run the detection-kernel test and observe red if the projection is absent or broader.
- [ ] Implement the four-field projection in one private helper and rerun green. Do not expose probability, model/version/reason, rule ID/weight/evidence code, similarity data, body, URL, or identity fields.

### Task 7: Structured private evidence privacy boundary

**Files:**
- Modify: `endpoint_agent/tests/test_detection_kernel.py`
- Modify: `endpoint_agent/tests/test_privacy.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/domain.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/detection_kernel.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/privacy.py`

**Interfaces:**
- `StructuredPrivateEvidence` contains only deduplicated stable rule evidence, score composition, execution/degradation state, and assessment/model/feature/outcome version summaries.
- `PrivacyScanner.scan_detection_outcome(outcome, forbidden_values=()) -> PrivacyScanResult` checks the full immutable outcome and returns stable codes only.

- [ ] Add an exact dataclass-field test for private evidence and a safe outcome scan; observe red because the scanner method and structure are absent.
- [ ] Implement the immutable evidence projection and scanner entry, then rerun the privacy and detection-kernel modules.
- [ ] Add a malicious manually constructed outcome containing fictional body, address, URL query, credential, and private path values; observe red if any category is missed, then reuse the existing structural string scanner so only stable violation codes are returned.
- [ ] Assert normal Kernel output contains no source `FeatureVector.text_input`, model error text, full addresses, query strings, tokens, passwords, or paths.

### Task 8: Public exports, offline packaging, and stage documentation

**Files:**
- Modify: `endpoint_agent/tests/test_domain.py`
- Modify: `endpoint_agent/tests/test_package.py`
- Modify: `endpoint_agent/tests/test_offline_constraints.py`
- Modify: `endpoint_agent/tests/test_build.py`
- Modify: `endpoint_agent/src/shielddome_endpoint/__init__.py`
- Modify: `endpoint_agent/AGENTS.md`
- Modify: `endpoint_agent/README.md`
- Modify: `endpoint_agent/docs/USAGE.md`
- Modify: `endpoint_agent/DEVELOPMENT_PLAN.md`

**Interfaces:**
- Public package exports the model/rule/outcome enums and immutable contracts, `InferenceContext`, `LocalInference`, `UnavailableModelAdapter`, and `DetectionKernel`.
- `FEATURE_SCHEMA_VERSION` remains 2.0, `CORPUS_SCHEMA_VERSION` remains 3.0, and `DETECTION_OUTCOME_SCHEMA_VERSION` becomes 2.0 because private evidence and execution semantics change.

- [ ] Add package import assertions and exact domain field/version assertions; run targeted package/domain tests and observe red for absent exports/version changes.
- [ ] Export the Phase 4A contracts without exporting the test fake or any ONNX adapter; rerun green.
- [ ] Extend the wheel content assertion with `inference.py`, `risk_fusion.py`, and `detection_kernel.py` and retain the no-`Requires-Dist` assertion.
- [ ] Extend offline assertions to reject production HTTP/WebSocket server modules, listener calls, and third-party dependencies while continuing to scan all production sources; observe red only if a required guard is absent, make the minimum guard/test change, and rerun.
- [ ] Update documentation to state Phase 3 is intentionally deferred and still `pending`; split Phase 4 into complete Phase 4A and pending Phase 4B; keep Phase 4 overall `in_progress`; permit Phases 5–7 to depend on 4A; keep Endpoint Release gated by Phase 3, Phase 4B, and release gates.
- [ ] Document exact inference, fusion, degradation, projection, version, and offline behavior without claiming real three-second hardware validation or a production model.

### Task 9: Verification before completion

**Files:**
- Verify only; ignored build output goes to `endpoint_agent/dist/phase4a/`.

- [ ] Run each required targeted test command and record test/pass/failure/skip counts plus exit codes.
- [ ] Run the full Endpoint Agent suite and the complete training-contract suite; do not infer success from targeted tests.
- [ ] Print package, Feature Schema, Corpus Schema, and Detection Outcome Schema versions from a fresh process with `endpoint_agent/src` on `sys.path`.
- [ ] Build the wheel with `--no-index --no-deps`, inspect its file list and metadata, and record exit code.
- [ ] Scan production source imports/calls and `pyproject.toml` to confirm no network, server, listener, ONNX Runtime, or third-party production dependency was added.
- [ ] Run the exact final Git status/diff commands, confirm only `endpoint_agent/` changed relative to the starting baseline, Phase 3 is `pending`, Phase 4 is not `complete`, and no model/data/mail artifacts were added.
- [ ] Do not commit or push.

## Required verification commands

```powershell
python -m unittest discover -s endpoint_agent/tests -p "test_inference.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_risk_fusion.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_detection_kernel.py" -v
python -m unittest discover -s endpoint_agent/tests -v
.\endpoint_agent\.venv-training\Scripts\python.exe -m unittest discover -s endpoint_agent/training_tests -v
$env:PYTHONPATH = (Resolve-Path endpoint_agent\src).Path
python -c "import shielddome_endpoint as s; print(s.__version__, s.FEATURE_SCHEMA_VERSION, s.CORPUS_SCHEMA_VERSION, s.DETECTION_OUTCOME_SCHEMA_VERSION)"
python -m pip wheel --no-index --no-deps .\endpoint_agent --wheel-dir .\endpoint_agent\dist\phase4a
git status --short
git diff --stat
git diff -- endpoint_agent
git diff --cached
git status --short -- app shielddome frontend extension web deploy scripts phishingDP-main
```

## Plan self-review

- Spec coverage: Tasks 1–8 map one-for-one to the eight required TDD slices and include every requested failure, privacy, packaging, documentation, stage-state, and prohibited-capability constraint.
- Placeholder scan: the plan contains no empty production adapter, ONNX placeholder, unspecified exception behavior, or deferred implementation step inside Phase 4A.
- Type consistency: `InferenceContext`, `LocalInference`, `ModelAssessment`, `ValidatedModelAssessment`, `RuleAssessment`, `RiskFusionResult`, `DetectionKernel`, and `DetectionOutcome` names and directions are consistent across all tasks.
- Deep-module review: callers learn one model method and one detection method; validation, model degradation, duplicate handling, score floors, action selection, and projections remain local to their owning modules.
- Domain review: Phase 4A does not imply an Approved Training Corpus, Unified Model Release, Endpoint Evidence Record, or complete Endpoint Release.
