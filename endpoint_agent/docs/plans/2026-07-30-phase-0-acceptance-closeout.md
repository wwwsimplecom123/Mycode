# ShieldDome Endpoint Agent Phase 0 Acceptance Closeout Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `executing-plans` for inline execution, apply `tdd` to the wheel-build seam, and use `verification-before-completion` for the final acceptance gate. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the existing Phase 0 package build reproducibly in an offline Python 3.12 environment without preinstalled third-party build backends, then align Phase 0 documentation with the verified state.

**Architecture:** Keep production code unchanged. Replace the external setuptools build backend with a project-local PEP 517 backend implemented only with the Python standard library; exercise it through the real `pip wheel --no-index` interface and keep all build outputs in ignored temporary locations. Update only Phase 0 build documentation and the next-stage handoff sentence after the full acceptance gate succeeds.

**Tech Stack:** Python 3.12 standard library, PEP 517, Wheel archive format, `pip wheel`, `unittest`, and Git `check-ignore`.

## Global Constraints

- Modify or create files only under `endpoint_agent/`.
- Preserve all existing user changes; do not reformat unrelated content.
- Do not modify `app/`, `shielddome/`, `frontend/`, `extension/`, `web/`, `deploy/`, or `scripts/`.
- Do not implement Feature Pipeline, corpus governance, mail parsing, model loading/inference/training, ONNX, Native Messaging, browser changes, database, encryption, tray, console, HTTP, WebSocket, or any other runtime capability.
- Use standard-library `unittest`; do not introduce pytest.
- Do not download build dependencies. The accepted wheel command must include `--no-index` and work without setuptools, wheel, flit, hatchling, or another third-party PEP 517 backend.
- Do not create a worktree or branch, commit, push, or open a pull request.
- Keep Phase 1 status `pending`; mentioning Phase 1 is limited to the required next-step documentation correction.
- If the final isolated wheel build cannot be verified, change Phase 0 to `in_progress` and record the exact blocker instead of claiming completion.

---

## File Map

- Create `endpoint_agent/_build_backend.py`: project-local, zero-dependency PEP 517 wheel backend; packages only `src/shielddome_endpoint/**/*.py` and emits valid metadata and RECORD entries.
- Modify `endpoint_agent/pyproject.toml`: declare `requires = []`, `build-backend = "_build_backend"`, and `backend-path = ["."]`; retain standard project metadata and remove the now-unused setuptools-specific table.
- Create `endpoint_agent/tests/test_build.py`: end-to-end offline wheel build test using the real `python -m pip wheel` interface and a self-cleaning temporary directory.
- Modify `endpoint_agent/docs/USAGE.md`: publish the verified offline command, zero-external-backend behavior, and the new total Phase 0 test count.
- Modify `endpoint_agent/AGENTS.md`: make the standard offline build command authoritative and forbid reintroducing external build-backend requirements without explicit approval.
- Modify `endpoint_agent/docs/plans/2026-07-29-phase-0.md`: correct the historical Phase 0 file map, backend declaration, and wheel verification command so it no longer instructs `--no-build-isolation`.
- Modify `endpoint_agent/DEVELOPMENT_PLAN.md`: only after acceptance succeeds, retain `Status: complete`, change the final next-step sentence to Phase 1, and leave every later status unchanged.

## Public Build Interface

From the repository root:

```powershell
python -m pip wheel --no-index --no-deps .\endpoint_agent --wheel-dir <ignored-or-temporary-directory>
```

Expected artifact:

```text
shielddome_endpoint-0.1.0-py3-none-any.whl
```

The wheel must contain:

```text
shielddome_endpoint/__init__.py
shielddome_endpoint/domain.py
shielddome_endpoint-0.1.0.dist-info/METADATA
shielddome_endpoint-0.1.0.dist-info/WHEEL
shielddome_endpoint-0.1.0.dist-info/RECORD
```

The PEP 517 backend exports:

```python
get_requires_for_build_wheel(config_settings=None) -> list[str]
prepare_metadata_for_build_wheel(metadata_directory, config_settings=None) -> str
build_wheel(wheel_directory, config_settings=None, metadata_directory=None) -> str
```

No runtime API is added or changed.

---

### Task 1: Offline wheel build seam

**Files:**
- Create: `endpoint_agent/tests/test_build.py`
- Create: `endpoint_agent/_build_backend.py`
- Modify: `endpoint_agent/pyproject.toml`

**Interfaces:**
- Consumes: the public `python -m pip wheel --no-index --no-deps <project>` command and Python standard library.
- Produces: a valid pure-Python `shielddome_endpoint-0.1.0-py3-none-any.whl` without acquiring external build dependencies.

- [ ] **Step 1: Write one failing end-to-end build test**

Create a `unittest.TestCase` that uses `TemporaryDirectory`, runs the exact public build command with `sys.executable`, captures output, and asserts exit code 0. It must assert exactly one expected wheel exists, open it with `zipfile.ZipFile`, verify the five required package/metadata paths, and confirm `METADATA` contains `Name: shielddome-endpoint`, `Version: 0.1.0`, and `Requires-Python: >=3.12`.

- [ ] **Step 2: Run the focused test and verify red**

Run:

```powershell
python -m unittest discover -s endpoint_agent/tests -p "test_build.py" -v
```

Expected: exit code nonzero because the isolated `--no-index` build cannot obtain `setuptools>=69`; the failure output names the unavailable setuptools build requirement.

- [ ] **Step 3: Implement the minimum zero-dependency PEP 517 backend**

Change `pyproject.toml` to:

```toml
[build-system]
requires = []
build-backend = "_build_backend"
backend-path = ["."]
```

Keep the existing `[project]` metadata unchanged and remove `[tool.setuptools]` plus `[tool.setuptools.packages.find]`, because the local backend owns the conventional `src/` package collection. In `_build_backend.py`, use `tomllib` to read the canonical name/version/Python floor, collect only `.py` files below `src/shielddome_endpoint`, and use `zipfile`, `hashlib`, `base64`, and `csv` to write a pure-Python wheel. Generate standards-shaped `METADATA`, `WHEEL`, and `RECORD`; return no build requirements. Do not import production modules or third-party packages.

- [ ] **Step 4: Rerun the focused test and verify green**

Run the same focused command. Expected: one test passes, zero failures/errors/skips, exit code 0, and the test temporary directory is removed.

- [ ] **Step 5: Check the vertical slice**

Run `git status --short` and inspect `_build_backend.py`, `pyproject.toml`, and `test_build.py`. Confirm no generated wheel, build tree, or `.egg-info` appears as an unignored path.

---

### Task 2: Build documentation and Phase 0 handoff consistency

**Files:**
- Modify: `endpoint_agent/docs/USAGE.md`
- Modify: `endpoint_agent/AGENTS.md`
- Modify: `endpoint_agent/docs/plans/2026-07-29-phase-0.md`
- Modify after successful verification: `endpoint_agent/DEVELOPMENT_PLAN.md`

**Interfaces:**
- Consumes: the green wheel command and the final Phase 0 test count.
- Produces: one reproducible documented command and a development plan whose completed Phase 0 points to Phase 1 without changing Phase 1 status.

- [ ] **Step 1: Correct build instructions**

In `USAGE.md`, `AGENTS.md`, and the original Phase 0 plan, replace the setuptools/`--no-build-isolation` assumption with the exact public build command above. State that the project-local PEP 517 backend has zero external build requirements and that `pip` itself is still required to invoke the build. Update the expected complete test count from 17 to 18.

- [ ] **Step 2: Run documentation consistency checks**

Search the three documents for `--no-build-isolation`, `setuptools>=69`, and `setuptools.build_meta`; expect zero stale matches outside explicitly quoted failure evidence in the new closeout plan. Confirm all published wheel commands include `--no-index`, `--no-deps`, and the local path `.\endpoint_agent`.

- [ ] **Step 3: Defer the next-step edit until the final pre-status gate**

Leave `DEVELOPMENT_PLAN.md` untouched until Task 3 proves package import, all tests, wheel build, ignore rules, and directory isolation. If they pass, replace only the final sentence’s `Phase 0：脚手架与约束测试` with `Phase 1：Feature Pipeline 与数据集治理`, keep Phase 0 `complete`, and keep Phase 1 `pending`.

---

### Task 3: Full Phase 0 acceptance and status gate

**Files:**
- Inspect all files under `endpoint_agent/`.
- Modify `endpoint_agent/DEVELOPMENT_PLAN.md` only as permitted by Task 2 Step 3.

**Interfaces:**
- Consumes: package source, tests, build configuration, ignore rules, documentation, and the captured Git baseline.
- Produces: evidence deciding whether Phase 0 remains `complete` or must become `in_progress` with a blocker.

- [ ] **Step 1: Run the complete Phase 0 suite**

```powershell
python -m unittest discover -s endpoint_agent/tests -v
```

Read all output and record total tests, passes, failures, errors, skips, and exit code.

- [ ] **Step 2: Verify package import and public versions**

```powershell
$env:PYTHONPATH = (Resolve-Path endpoint_agent\src).Path
python -c "import shielddome_endpoint as s; print(s.__version__); print(s.MAIL_OBSERVATION_SCHEMA_VERSION, s.FEATURE_SCHEMA_VERSION, s.DETECTION_OUTCOME_SCHEMA_VERSION)"
```

Expected output contains `0.1.0` and `1.0 1.0 1.0`; exit code 0.

- [ ] **Step 3: Run a fresh standalone offline wheel build**

Use the public build command with a unique temporary directory, confirm exactly one expected wheel and exit code 0, then delete only that verified temporary directory. Do not install the wheel into the development interpreter.

- [ ] **Step 4: Verify every ignore category**

Run `git check-ignore --no-index -v` for representative model/model-package, training-data, key, log, SQLite/WAL/SHM/journal, diagnostic, cache, and build paths. Every representative path must resolve to `endpoint_agent/.gitignore`.

- [ ] **Step 5: Apply the next-step documentation edit only if Steps 1-4 pass**

Retain `Status: complete`, keep Phase 1 `Status: pending`, and change only the final next-step phase name to Phase 1. If any build acceptance remains unresolved, set Phase 0 to `in_progress`, leave the next step at Phase 0, and add the exact build blocker beneath the Phase 0 completion criteria.

- [ ] **Step 6: Rerun tests after the documentation decision**

Run the complete Phase 0 suite again and record fresh counts and exit code.

- [ ] **Step 7: Perform the required final Git checks**

```powershell
git status --short
git diff --stat
git diff -- endpoint_agent
git status --short -- app shielddome frontend extension web deploy scripts
```

Because `endpoint_agent/` is untracked, also enumerate and inspect every Endpoint Agent file. Compare paths outside `endpoint_agent/` with the start-of-task baseline, confirm protected-directory status output is empty, confirm staged diff is empty, and confirm no generated wheel or runtime artifact appears unignored.

---

## Plan Self-Review

- Scope coverage: the plan addresses only the known Phase 0 build and documentation acceptance gaps.
- TDD coverage: the sole new behavior is protected by one red/green end-to-end wheel-build test.
- Build consistency: `pyproject.toml`, tests, usage docs, agent instructions, and historical Phase 0 plan use the same command and backend assumptions.
- Status safety: Phase 0 remains complete only after a fresh build; Phase 1 remains pending and receives no implementation.
- Boundary safety: every planned write is under `endpoint_agent/`; protected directories and scripts are read-only.
- Placeholder scan: no deferred code, service stub, adapter stub, model stub, or later-stage implementation appears in this plan.
- Git workflow: no worktree, branch, commit, push, or pull request step is included.
