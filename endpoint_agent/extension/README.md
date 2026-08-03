# ShieldDome Endpoint Agent MV3 Extension (Phase 5A / 5B Development Identity)

This standalone development extension observes only the open message at `https://webmail.chinaccs.cn/*` and sends bounded mail facts to `cn.shielddome.endpoint_agent` through Chrome/Edge Native Messaging. It has no server setting, credential, browser storage, or network request capability.

The committed public manifest key deterministically fixes the development acceptance ID `hchaloelgnennaojaiikeebhajcoccih` and origin `chrome-extension://hchaloelgnennaojaiikeebhajcoccih/`. The repository contains no private signing key. This development identity supports reproducible unpacked Chrome/Edge acceptance; a future store or enterprise production identity must be handled as a separate release decision and synchronized with the production Native Host allowlist.

Phase 5B provides reproducible Host build configuration and current-user Chrome/Edge registration scripts under `endpoint_agent/native_host/`. Real browser acceptance remains required; follow `endpoint_agent/docs/BROWSER_ACCEPTANCE.md` and do not infer browser success from unit tests.

The status bar is warning-only. It never deletes, moves, isolates, downloads, opens, previews, extracts, or executes a message or attachment.
