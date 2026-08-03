# Phase 5B Native Host Packaging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `$executing-plans`, `$tdd`, and `$verification-before-completion` in that order. Steps use checkbox (`- [ ]`) syntax for tracking. The user forbids commits, pushes, branches, and PRs.

**Goal:** Prepare a reproducible Windows Native Messaging Host build, stable development extension identity, safe per-user Chrome/Edge registration lifecycle, subprocess protocol acceptance, and an executable real-browser acceptance runbook without claiming completion when the packaged Host or manual browser evidence is unavailable.

**Architecture:** The existing Python stdio Host remains the only protocol and detection implementation. A PyInstaller one-file console build wraps a minimal entry point, writes ignored output plus integrity metadata, and stays a development-only packaging dependency outside the production Wheel. A public extension key fixes the unpacked development extension ID; a PowerShell module derives that ID, validates build metadata and hashes, generates browser-specific manifests with absolute paths, and limits registry writes/deletes to the two current-user Native Messaging Host keys.

**Tech Stack:** Python 3.12 standard library, `unittest`, PyInstaller as a pinned development-only build tool, PowerShell 5.1-compatible scripts, Windows HKCU registry, Chrome/Edge Manifest V3 Native Messaging, SHA-256, and existing JavaScript assets.

## Global Constraints

- Modify only `endpoint_agent/`; never modify root `extension/` or `app/`, `shielddome/`, `frontend/`, `web/`, `deploy/`, or `scripts/`.
- Preserve Phase 3 `pending`, Phase 4 `in_progress`, Phase 4B `pending`, Phase 5 `in_progress`, Phase 5A `complete`, Phase 6 and later `pending`.
- Phase 5B remains `in_progress` unless the Host executable build, automated acceptance, and real Chrome and Edge chinaccs acceptance all obtain fresh evidence.
- Native Host stdin/stdout remains exact Native Messaging framing; stdout contains no diagnostic text, payload fragments, secrets, or traceback.
- No HTTP, WebSocket, TCP/UDP listener, network client, external model, server address, Token, account, database, persistence, DPAPI, AES-GCM, `.eml`, desktop UI, or model work.
- The repository stores only the extension public key and derived ID; no private key, `.pem`, `.key`, `.pfx`, `.crx`, Host `.exe`, or other binary build output is committed.
- PyInstaller is a development-only requirement and must not enter `pyproject.toml`, Wheel metadata, or production runtime dependencies.
- Installation defaults to HKCU and requires no administrator rights. Uninstall deletes only exact ShieldDome keys and manifests that pass ownership checks.
- Do not install packages from the network. If PyInstaller is not already available offline, run and record the build failure, retain reproducible configuration, skip packaged-host-only tests, and report the blocker.
- Do not commit or push.

---

## File map and interfaces

**Create**

- `endpoint_agent/requirements-packaging.txt`: exact development-only PyInstaller version.
- `endpoint_agent/packaging/native_host_entry.py`: import and invoke `shielddome_endpoint.native_host.main()` without writing diagnostics to stdout.
- `endpoint_agent/native_host/identity.json`: public host name, stable development extension ID/origin, and identity kind.
- `endpoint_agent/native_host/NativeHostRegistration.psm1`: identity derivation, build-integrity validation, manifest generation, HKCU registration/status/uninstall primitives.
- `endpoint_agent/native_host/build-host.ps1`: reproducible one-file PyInstaller build into ignored `dist/native-host/`, followed by SHA-256 build metadata generation.
- `endpoint_agent/native_host/install-host.ps1`: validate inputs, generate Chrome/Edge manifests with the absolute Host path, and register both browsers for the current user.
- `endpoint_agent/native_host/check-host.ps1`: return nonzero unless both registered manifests, origin, Host path, and build hash agree.
- `endpoint_agent/native_host/uninstall-host.ps1`: remove only owned registration values/manifests and leave unrelated browser settings untouched.
- `endpoint_agent/tests/test_native_packaging.py`: identity, development-dependency, ignored-output, generated-manifest, registry lifecycle, path, and ownership tests.
- `endpoint_agent/tests/test_native_host_process.py`: real subprocess framing, isolation, malformed input, stdout privacy, and listener tests; packaged-executable cases skip only when the ignored `.exe` is absent.
- `endpoint_agent/docs/BROWSER_ACCEPTANCE.md`: exact Chrome and Edge manual acceptance and uninstall checklist.

**Modify**

- `endpoint_agent/extension/manifest.json`: add the public Manifest V3 `key` that deterministically derives the stable development ID.
- `endpoint_agent/src/shielddome_endpoint/native_host.py`: replace the placeholder origin with the derived stable development identity while retaining strict equality.
- `endpoint_agent/native_host/com.shielddome.endpoint_agent.development.json`: align the checked-in development example with the public identity; generated installed manifests still use the actual absolute Host path.
- `endpoint_agent/.gitignore`: explicitly cover Host executable/build metadata output if the existing `/dist/` and `/build/` rules are not sufficient for the tested paths.
- `endpoint_agent/tests/test_extension_static.py`: assert public-key-derived ID, Python constant, identity document, and allowed origin are identical and non-wildcard.
- `endpoint_agent/tests/test_build.py`: assert PyInstaller and packaging scripts are absent from the production Wheel and Wheel metadata has no runtime dependency.
- `endpoint_agent/tests/test_offline_constraints.py`: include entry point, build/registration scripts, manifests, and extension assets in offline/listener guards without flagging documented browser registry names.
- `endpoint_agent/tests/test_repository_hygiene.py`: prove Host `.exe`, build metadata, PyInstaller work/spec output, and generated manifests under ignored output directories are ignored.
- `endpoint_agent/AGENTS.md`, `endpoint_agent/README.md`, `endpoint_agent/DEVELOPMENT_PLAN.md`, `endpoint_agent/docs/USAGE.md`, `endpoint_agent/extension/README.md`, `endpoint_agent/native_host/README.md`: document automated evidence, commands, development versus future production identity, registry boundaries, and remaining manual blocker.

**Produced interfaces**

- `Get-ShieldDomeExtensionId -PublicKey <base64>` returns the 32-character Chrome ID by SHA-256 hashing decoded public-key bytes and mapping the first 16 bytes' nibbles to `a`–`p`.
- `Test-ShieldDomeBuild -HostPath <absolute.exe> -BuildMetadataPath <absolute.json>` verifies the `MZ` file shape, SHA-256, host name, extension ID/origin, and absolute path before any write.
- `New-ShieldDomeBrowserManifest -Browser Chrome|Edge ...` writes exact `{name, description, path, type, allowed_origins}` JSON with `type="stdio"` and one literal origin.
- `Install-ShieldDomeNativeHost`, `Get-ShieldDomeNativeHostStatus`, and `Uninstall-ShieldDomeNativeHost` accept default production HKCU paths plus explicit test-only registry paths used under `HKCU:\Software\ShieldDome\EndpointAgentTests\<guid>`.
- Build metadata contains exact fields `schema_version`, `host_name`, `extension_id`, `extension_origin`, `executable_path`, `executable_sha256`, `build_tool`, and `build_tool_version`; it contains no machine account, mail, Token, server, or private-key material.

## Task 1: Stable public development extension identity

- [ ] Add failing tests in `test_extension_static.py` that require `manifest.json.key`, derive its ID, compare it with `identity.json`, `native_host.py`, and the checked-in manifest, reject wildcard/HTTP(S) origins, and assert no private-key files exist.
- [ ] Run `python -m unittest discover -s endpoint_agent/tests -p "test_extension_static.py" -v`; expect failure because the extension key and identity document do not exist and the placeholder ID is still in use.
- [ ] Generate one RSA public SubjectPublicKeyInfo value using an ephemeral in-memory key, commit only its Base64 public bytes in `manifest.json`, calculate the derived ID, create `identity.json`, and update Python/example-manifest constants.
- [ ] Rerun the focused test and require all identity assertions to pass.

## Task 2: Reproducible ignored Host build configuration

- [ ] Add failing tests in `test_native_packaging.py`, `test_build.py`, and `test_repository_hygiene.py` requiring the entry point, pinned packaging requirement, build script, ignored `.exe`/work/metadata output, and absence of PyInstaller from the Wheel.
- [ ] Run the three focused modules; expect failure only for missing Phase 5B files/ignore guarantees.
- [ ] Add `requirements-packaging.txt`, `packaging/native_host_entry.py`, and `build-host.ps1`. The build command is:

  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File endpoint_agent\native_host\build-host.ps1
  ```

  It invokes `python -m PyInstaller --noconfirm --clean --onefile --console --noupx --name ShieldDomeEndpointHost`, sets `--paths endpoint_agent\src`, writes all work/output beneath ignored `endpoint_agent\build\native-host` and `endpoint_agent\dist\native-host`, then hashes the `.exe` into build metadata.
- [ ] Rerun focused tests green.
- [ ] Execute the real build command. If `python -m PyInstaller --version` is unavailable, require a nonzero exit with a concise installation/offline-cache instruction, do not download it, and record the packaged-host blocker.

## Task 3: Host subprocess protocol and offline behavior

- [ ] Add a failing `test_native_host_process.py` harness that starts `python endpoint_agent/packaging/native_host_entry.py <origin>` with `PYTHONPATH=endpoint_agent/src`, writes binary frames, and decodes stdout strictly as frames.
- [ ] Add red tests for ping, minimum `detect_mail`, two distinct requests with no prior subject/body/address leakage, invalid length, invalid JSON, unknown field, oversized payload, and clean exit. Error stdout must contain only `{error_code}` frames and no payload, Token, exception text, or traceback.
- [ ] Add a Windows test that keeps the Host process alive on stdin, checks `Get-NetTCPConnection`/`netstat` for zero listening sockets owned by the Host PID, then closes stdin and requires a clean exit. The test does not make a network request.
- [ ] Add the same protocol suite for `endpoint_agent/dist/native-host/ShieldDomeEndpointHost.exe`; skip those cases only when the ignored executable is absent, with the reason `packaged Host unavailable`.
- [ ] Implement only entry-point/runtime fixes required by observed failures, keeping `native_host.py` as the sole protocol loop.
- [ ] Run `python -m unittest discover -s endpoint_agent/tests -p "test_native_host_process.py" -v` and record pass/fail/skip counts separately for source and packaged Host paths.

## Task 4: Chrome/Edge manifest generation and current-user registry lifecycle

- [ ] Add failing `test_native_packaging.py` cases that use a temporary directory containing spaces and Chinese characters plus isolated `HKCU:\Software\ShieldDome\EndpointAgentTests\<guid>` registry keys.
- [ ] Require generated Chrome/Edge manifests to share exact host name, `stdio` type, one allowed origin, and the resolved absolute `.exe` path; require the origin to match the extension key-derived ID.
- [ ] Require two idempotent installs, successful status, uninstall, second idempotent uninstall, and absent test keys/files afterward.
- [ ] Add adversarial ownership tests: change a registry default to an unrelated path and change a manifest host name; uninstall must refuse to delete those items and return nonzero instead of broad deletion.
- [ ] Implement `NativeHostRegistration.psm1` plus the install/check/uninstall wrappers. Defaults are exactly:

  ```text
  HKCU\Software\Google\Chrome\NativeMessagingHosts\cn.shielddome.endpoint_agent
  HKCU\Software\Microsoft\Edge\NativeMessagingHosts\cn.shielddome.endpoint_agent
  ```

  Generated manifests live below `%LOCALAPPDATA%\ShieldDome\EndpointAgent\NativeMessagingHosts\{Chrome,Edge}`; tests override both registry and manifest roots with isolated ShieldDome test paths.
- [ ] Rerun `test_native_packaging.py`; after the test, independently query the test registry prefix and require no leftover keys.
- [ ] If a valid built Host exists, execute install → check → uninstall → install against the default HKCU locations and leave the final valid registration in place for manual acceptance. If no built Host exists, do not create default browser registrations and report the blocker.

## Task 5: Offline/static security guards

- [ ] Add failing offline-guard assertions for the entry point, PowerShell build/registration sources, generated manifest schema, and extension identity. Explicitly reject listener calls, network client commands/imports, HTTP(S)/WS endpoint literals, remote downloads, server/Token/account configuration, and stdout diagnostics.
- [ ] Run `test_offline_constraints.py`; confirm failures identify unscanned Phase 5B assets rather than existing production code.
- [ ] Extend the guard or focused static checks minimally. Registry product paths and `chrome-extension://` origins are protocol identifiers, not network endpoints, and must be validated structurally rather than hidden from the scan.
- [ ] Rerun the focused offline and packaging tests green.

## Task 6: Real Chrome and Edge acceptance preparation

- [ ] Create `docs/BROWSER_ACCEPTANCE.md` with commands to build, install, check, load the unpacked extension, copy the displayed extension ID, compare it with `identity.json`/manifest origin, test a real chinaccs message, repeat offline, inspect DevTools Network, verify the exact four visible result fields, uninstall, and inspect both registry keys.
- [ ] Include separate Chrome `chrome://extensions` and Edge `edge://extensions` steps and clearly label the current public key/ID as development acceptance identity, not a future store/enterprise production identity.
- [ ] Where interactive browser control and an authenticated chinaccs session are available, execute the checklist separately in Chrome and Edge and record observable evidence. Do not treat unit/static tests as browser evidence.
- [ ] If the packaged Host, browser session, or authenticated mail detail is unavailable, leave Phase 5B and Phase 5 `in_progress`; document exactly which manual steps remain.

## Task 7: Documentation and phase-state synchronization

- [ ] Update `AGENTS.md`, `README.md`, `DEVELOPMENT_PLAN.md`, `docs/USAGE.md`, extension README, and Native Host README only after automated verification results are known.
- [ ] Record the exact public development identity, build command/dependency boundary, output paths, HKCU registry keys, status/uninstall commands, and real-browser checklist link.
- [ ] Keep Phase 5B and Phase 5 `in_progress` unless both browsers were manually accepted with a packaged Host; never advance Phase 3, Phase 4B, Phase 6, Phase 7, or Phase 8.

## Task 8: Fresh acceptance and scope audit

- [ ] Run the full Endpoint Agent suite and all three JavaScript syntax checks.
- [ ] Run the Host build command and record success or the actual offline-tool failure.
- [ ] Run source and, if present, packaged Host subprocess protocol tests.
- [ ] Run Chrome/Edge manifest generation plus isolated install/status/uninstall tests.
- [ ] Run the required offline Wheel build into `endpoint_agent/dist/phase5b`.
- [ ] Run all Git scope commands, compare with the starting baseline, and confirm protected directories are unchanged.
- [ ] Do not commit or push.

## Required verification commands

```powershell
python -m unittest discover -s endpoint_agent/tests -v
node --check endpoint_agent/extension/background.js
node --check endpoint_agent/extension/content.js
node --check endpoint_agent/extension/adapters/chinaccs.js
powershell -NoProfile -ExecutionPolicy Bypass -File endpoint_agent\native_host\build-host.ps1
python -m unittest discover -s endpoint_agent/tests -p "test_native_host_process.py" -v
python -m unittest discover -s endpoint_agent/tests -p "test_native_packaging.py" -v
powershell -NoProfile -ExecutionPolicy Bypass -File endpoint_agent\native_host\install-host.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File endpoint_agent\native_host\check-host.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File endpoint_agent\native_host\uninstall-host.ps1
python -m pip wheel --no-index --no-deps .\endpoint_agent --wheel-dir .\endpoint_agent\dist\phase5b
git status --short
git diff --stat
git diff -- endpoint_agent
git diff --cached
git status --short -- app shielddome frontend extension web deploy scripts
```

Default install/check/uninstall commands are executed only when the real built Host and build metadata exist. The automated isolated-registry test always exercises install/status/uninstall mechanics without touching browser settings outside the ShieldDome test prefix.

## Completion conditions

Phase 5B may become `complete` only when all are true:

1. The PyInstaller command succeeds and produces the ignored Host `.exe` plus matching SHA-256 metadata.
2. The packaged Host subprocess suite passes ping, detection, isolation, malformed-input, privacy, and no-listener checks with zero packaged-host skips.
3. Default HKCU Chrome and Edge install/check/uninstall/upgrade behavior succeeds with the built Host.
4. Real Chrome and real Edge each load the stable-ID extension, detect an authenticated chinaccs message online and offline, show only risk/status/generic advice/event ID, and show no ShieldDome external request in browser Network tools.
5. Uninstall removes both owned registrations/manifests and no unrelated browser setting.

If any item lacks fresh evidence, Phase 5B and Phase 5 remain `in_progress` and the final report separates completed automation from the blocker.

## Plan self-review

- **Spec coverage:** Tasks 1–8 cover executable configuration, development-only identity, Chrome/Edge HKCU registry boundaries, absolute/Unicode paths, idempotency and owned cleanup, subprocess framing/error/isolation/privacy/listener checks, manual browser acceptance, docs, Wheel, and final Git audit.
- **Placeholder scan:** Every deliverable has an exact path, command, interface, registry location, error/skip branch, and completion rule; later-phase work is explicitly excluded.
- **Type/name consistency:** `identity.json` feeds the derived manifest origin and build metadata; build metadata validates the executable before the same identity drives both browser manifests; the Host still consumes the browser-supplied launch origin and returns the existing four-field projection.
- **Safety review:** No private extension key is persisted, build output is ignored, no package download is attempted, tests use an isolated ShieldDome registry prefix, and default registry mutation is gated on a real verified build.
