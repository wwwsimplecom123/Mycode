# Native Host development manifest

`com.shielddome.endpoint_agent.development.json` documents the Phase 5A protocol name, a fixed development-only extension origin, and the absolute-path shape required by Chromium.

It is not registered and its executable path does not exist in Phase 5A. Do not write the Windows registry or copy this manifest into browser registration directories. Phase 5B will build the Host executable, replace the development identity/path, register it per browser, and run real Edge/Chrome acceptance.

The browser supplies the extension origin as a Host process argument. Request JSON never supplies or overrides the origin allowlist.
