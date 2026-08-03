# Phase 4A.1 Local Rule Evaluation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a fully offline, deterministic chain from `MailObservation` through local feature and rule evaluation to `DetectionOutcome`, without trusting browser-supplied risk judgments.

**Architecture:** `LocalRuleEvaluator` is a deep module whose single interface validates a complete Feature Schema 2.0 vector and returns stable immutable `RuleAssessment` values from a centralized policy table. `LocalDetectionService` is the future Native Messaging detection seam; it validates observation facts, runs `FeaturePipeline`, invokes the evaluator, and delegates fusion and projection to the existing `DetectionKernel`. The only injectable production dependency is a `LocalInference` adapter, defaulting to `UnavailableModelAdapter`.

**Tech Stack:** Python 3.12 standard library, frozen domain dataclasses, `unittest`, the existing zero-dependency PEP 517 Wheel backend.

## Global Constraints

- Modify only `endpoint_agent/`; preserve all existing Phase 4A and unrelated working-tree changes.
- Keep Feature Schema `2.0`, Corpus Schema `3.0`, Model Assessment Schema `1.0`, and Detection Outcome Schema `2.0` unchanged.
- Do not implement Native Messaging, a browser extension, persistence, UI, training, ONNX Runtime, attachment-content access, or any network listener/client.
- Browser-originated data is observation fact only; it cannot supply `RuleAssessment`, model state, risk scores, actions, retention, identity ownership, roles, or permissions.
- Production code remains fully offline and adds no third-party runtime dependency.
- Every public behavior follows a red → green TDD cycle; no commit, push, branch, or PR is created.

---

### Task 1: Validate Feature Schema 2.0 at the rule seam

**Files:**
- Create: `endpoint_agent/src/shielddome_endpoint/rule_evaluator.py`
- Create: `endpoint_agent/tests/test_rule_evaluator.py`

**Interfaces:**
- Consumes: `FeatureVector` and the canonical `NUMERIC_FEATURE_NAMES` / `CATEGORICAL_FEATURE_NAMES` from `feature_pipeline.py`.
- Produces: `FeatureVectorValidationError(ValueError)` and `LocalRuleEvaluator.evaluate(features: FeatureVector) -> tuple[RuleAssessment, ...]`.

- [ ] **Step 1: Write a failing public-interface test for a valid pipeline-produced vector.**

  Assert `LocalRuleEvaluator().evaluate(FeaturePipeline().transform(observation))` returns a tuple and does not mutate the vector.

- [ ] **Step 2: Run the focused test and confirm RED.**

  Run `python -m unittest discover -s endpoint_agent/tests -p "test_rule_evaluator.py" -v`; expect an import failure because `rule_evaluator` does not exist.

- [ ] **Step 3: Implement the minimal validated reader and empty evaluation.**

  Validate `FeatureVector` type, exact schema version, tuple pair structure, exact complete unique numeric and categorical names, finite non-boolean numeric values, non-negative numeric values, and string categorical values. Raise only stable codes such as `incompatible_feature_schema`, `invalid_numeric_features`, and `invalid_categorical_features`.

- [ ] **Step 4: Run the focused test and confirm GREEN.**

- [ ] **Step 5: Add one failing test at a time for incompatible schema, duplicate numeric name, duplicate categorical name, missing fields, unknown fields, NaN, Infinity, boolean numeric values, and negative numeric values; minimally implement each before proceeding.**

### Task 2: Evaluate structured authentication, sender, link, and attachment rules

**Files:**
- Modify: `endpoint_agent/src/shielddome_endpoint/rule_evaluator.py`
- Modify: `endpoint_agent/tests/test_rule_evaluator.py`

**Interfaces:**
- Consumes: validated numeric and categorical feature mappings created inside `LocalRuleEvaluator`.
- Produces: stable `RuleAssessment` tuples ordered by a centralized immutable rule-policy table.

- [ ] **Step 1: Add and run a failing authentication-rule test.**

  Cover DMARC fail, SPF fail/softfail, DKIM fail, multiple failures, and verify missing authentication alone is neither emitted nor strong.

- [ ] **Step 2: Implement only the centralized authentication policies and predicates; rerun to GREEN.**

- [ ] **Step 3: Add and run a failing sender/reply-to mismatch test, then implement it as a non-strong signal.**

- [ ] **Step 4: Add and run failing link tests for IP literals, suspicious ports, punycode, Unicode domains, and more than 20 bounded URLs; implement the minimal policies.**

- [ ] **Step 5: Add and run failing attachment-metadata tests for dangerous extensions and double extensions; make dangerous extensions strong without inspecting attachment content.**

### Task 3: Evaluate intent combinations and cross-category strong evidence

**Files:**
- Modify: `endpoint_agent/src/shielddome_endpoint/rule_evaluator.py`
- Modify: `endpoint_agent/tests/test_rule_evaluator.py`

**Interfaces:**
- Consumes: only bounded intent counts and other validated Feature Schema 2.0 values.
- Produces: stable intent-combination and cross-category assessments.

- [ ] **Step 1: Add a failing test proving individual credential, payment, urgency, or impersonation counts do not create intent rules or strong evidence; implement no single-word rules.**

- [ ] **Step 2: Add a failing test for credential + urgency, implement its non-strong combination policy, and rerun to GREEN.**

- [ ] **Step 3: Repeat red → green for payment + urgency, impersonation + credential, and impersonation + payment.**

- [ ] **Step 4: Add failing tests for IP literal + credential and at least two authentication failures + impersonation; implement these as strong high-severity policies.**

### Task 4: Prove evaluator determinism, deduplication, privacy, and bounded work

**Files:**
- Modify: `endpoint_agent/tests/test_rule_evaluator.py`
- Modify: `endpoint_agent/tests/test_privacy.py`

**Interfaces:**
- Tests only `LocalRuleEvaluator.evaluate`; no private helper tests.

- [ ] **Step 1: Add a failing stability test asserting identical inputs produce identical tuples, rule order is fixed, and rule IDs/evidence codes are unique.**

- [ ] **Step 2: Adjust centralized policy evaluation minimally until the stability test is GREEN.**

- [ ] **Step 3: Add a privacy test using a body, address, queried URL, attachment filename, token, password, and private path; assert none appears in rules or the final outcome.**

- [ ] **Step 4: Add a bounded-input test comparing an observation capped at pipeline limits with one containing additional malicious facts beyond each limit; assert identical vectors and assessments.**

### Task 5: Build the Local Detection Service seam

**Files:**
- Create: `endpoint_agent/src/shielddome_endpoint/local_detection.py`
- Create: `endpoint_agent/tests/test_local_detection.py`

**Interfaces:**
- Consumes: `MailObservation`, constructor-only optional `LocalInference`, `local_event_id`, and timezone-aware `observed_now`.
- Produces: `LocalDetectionService.detect(observation, *, local_event_id, observed_now) -> DetectionOutcome`.

- [ ] **Step 1: Write a failing test that calls the exact public detect interface and proves observation facts become local rule evidence; run and confirm RED.**

- [ ] **Step 2: Implement observation contract validation plus the fixed `FeaturePipeline → LocalRuleEvaluator → DetectionKernel` chain with a 3,000 ms inference context; rerun to GREEN.**

- [ ] **Step 3: Add a failing signature/trust test proving callers cannot pass rules, scores, model assessments, execution states, actions, retention, or ownership judgments; keep the narrow interface.**

- [ ] **Step 4: Add failing tests for the default unavailable adapter, adapter exception degradation, strong-rule floors, and deterministic results for injected ID/time; implement only constructor-time adapter selection.**

### Task 6: Publish interfaces, constraints, and phase documentation

**Files:**
- Modify: `endpoint_agent/src/shielddome_endpoint/__init__.py`
- Modify: `endpoint_agent/tests/test_package.py`
- Modify: `endpoint_agent/tests/test_offline_constraints.py`
- Modify: `endpoint_agent/README.md`
- Modify: `endpoint_agent/docs/USAGE.md`
- Modify: `endpoint_agent/DEVELOPMENT_PLAN.md`
- Modify: `endpoint_agent/AGENTS.md`
- Modify: `endpoint_agent/docs/plans/2026-07-31-phase-4a1-local-rule-evaluation.md`

**Interfaces:**
- Produces public imports for `FeatureVectorValidationError`, `LocalRuleEvaluator`, and `LocalDetectionService`.

- [ ] **Step 1: Add failing package-export and offline-constraint assertions, then add the minimal exports and confirm GREEN.**

- [ ] **Step 2: Document the plugin trust boundary, rules-only degradation, no Native Messaging/extension implementation, and Phase 4A.1 as Phase 5's safety prerequisite.**

- [ ] **Step 3: Mark Phase 4A.1 complete only after fresh acceptance evidence; retain Phase 3 pending, Phase 4 in progress, Phase 4B pending, and Phase 5 pending, with Phase 5 as next step.**

### Task 7: Fresh acceptance verification and scope audit

**Files:**
- Verify all modified and new files under `endpoint_agent/`.

**Interfaces:**
- Verifies the two public seams and the existing package/build interface.

- [ ] **Step 1: Run focused evaluator tests.**

  `python -m unittest discover -s endpoint_agent/tests -p "test_rule_evaluator.py" -v`

- [ ] **Step 2: Run focused local-service tests.**

  `python -m unittest discover -s endpoint_agent/tests -p "test_local_detection.py" -v`

- [ ] **Step 3: Run the complete Endpoint Agent suite and record pass/fail/error/skip counts and exit code.**

  `python -m unittest discover -s endpoint_agent/tests -v`

- [ ] **Step 4: Run package import verification and record the actual Python executable.**

  `python -c "import sys; sys.path.insert(0, r'endpoint_agent/src'); import shielddome_endpoint as s; print(sys.executable); print(s.__version__, s.FEATURE_SCHEMA_VERSION, s.CORPUS_SCHEMA_VERSION, s.DETECTION_OUTCOME_SCHEMA_VERSION)"`

- [ ] **Step 5: Build the Wheel offline.**

  `python -m pip wheel --no-index --no-deps .\endpoint_agent --wheel-dir .\endpoint_agent\dist\phase4a1`

- [ ] **Step 6: Inspect `git status`, tracked/staged diffs, all untracked endpoint files, and protected-directory status; confirm no model, training data, real email, commit, push, branch, or later-phase implementation was added.**

## Plan Self-Review

- Spec coverage: all six requested TDD slices, trust/privacy/offline/resource constraints, documentation, statuses, and verification commands are assigned above.
- Placeholder scan: no deferred implementation placeholders remain.
- Type consistency: both public interfaces and all schema/version names match the current Phase 4A code.
