# Native Host Phase 5B packaging and registration

`identity.json` and the extension's committed public manifest key define the fixed development ID `hchaloelgnennaojaiikeebhajcoccih`. `com.shielddome.endpoint_agent.development.json` documents the matching protocol name, fixed origin, and absolute-path shape required by Chromium. This public development identity is not a future store or enterprise release identity; no private key is stored.

Build the stdio Host with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File endpoint_agent\native_host\build-host.ps1
```

The build requires the pinned development-only PyInstaller dependency in `requirements-packaging.txt`; it never enters the production Wheel. Output and SHA-256 metadata are written beneath ignored `endpoint_agent/dist/native-host/`. If PyInstaller is unavailable offline, do not download it implicitly or claim the Host was built.

After a successful build, use `install-host.ps1`, `check-host.ps1`, and `uninstall-host.ps1`. They default to current-user Chrome and Edge Native Messaging keys, generate separate manifests with the real absolute Host path, support repeated installation, and refuse to delete registration values that do not point to ShieldDome-owned manifests. They do not modify other browser settings or require administrator rights.

Real Chrome and Edge acceptance steps are in `docs/BROWSER_ACCEPTANCE.md`. In the current environment no Host `.exe` exists, so the checked-in development example is not registered and Phase 5B remains `in_progress`.

The browser supplies the extension origin as a Host process argument. Request JSON never supplies or overrides the origin allowlist.
