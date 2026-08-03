# ShieldDome Endpoint Agent MV3 Extension (Phase 5A)

This standalone development extension observes only the open message at `https://webmail.chinaccs.cn/*` and sends bounded mail facts to `cn.shielddome.endpoint_agent` through Chrome/Edge Native Messaging. It has no server setting, credential, browser storage, or network request capability.

Phase 5A provides source and static validation only. The fixed development origin `chrome-extension://abcdefghijklmnopabcdefghijklmnop/` is not a production extension identity and the repository contains no private signing key. Phase 5B must assign the enterprise extension identity, package the Host executable, install the browser-specific Native Host manifest, and perform real Chrome/Edge acceptance.

The status bar is warning-only. It never deletes, moves, isolates, downloads, opens, previews, extracts, or executes a message or attachment.
