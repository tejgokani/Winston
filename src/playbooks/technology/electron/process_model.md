---
id: technology.electron.process_model
title: "Electron: Process Model & Renderer Isolation"
category: technology
vulnerabilityClass: broken_isolation
appliesToStack: electron
requiresAnyTag: ["electron"]
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A05:2021 Security Misconfiguration"
  - "A03:2021 Injection"
cweRefs:
  - "CWE-829"
  - "CWE-16"
  - "CWE-79"
realWorldReferences:
  - title: "Electron — official Security checklist (contextIsolation, sandbox, nodeIntegration, remote content)"
    url: "https://www.electronjs.org/docs/latest/tutorial/security"
    type: security_blog
  - title: "Discord/Signal/VS Code-class Electron RCE via XSS reaching Node when isolation is off (disclosed research)"
    url: "https://benjamin-altpeter.de/shell-injection/"
    type: research_paper
  - title: "CVE-2018-1000006 — Electron protocol-handler RCE and the push to secure defaults"
    url: "https://github.com/electron/electron/security/advisories"
    type: vendor_security_advisory
quickModeSummary: >
  In Electron, an XSS in the renderer becomes remote code execution on the user's
  machine unless the process model is locked down. Check every BrowserWindow/
  webPreferences for the secure configuration: contextIsolation must be true
  (default in modern Electron — flag it being disabled), nodeIntegration must be
  false, sandbox should be true, and enableRemoteModule/the deprecated remote
  module must be off. The single most dangerous combo is nodeIntegration:true (or
  contextIsolation:false) on a window that loads any web content — it exposes
  Node (require, child_process, fs) to page JavaScript, so any injected script
  runs native code. Also flag windows that load remote/untrusted URLs or allow
  arbitrary navigation/new-window, and webviews without these protections. Treat
  renderer content as untrusted and keep Node out of it.
fileSelectionHint:
  roles: ["config", "main", "service", "view"]
  matchImports: ["electron"]
  matchAuthMapTags: ["electron"]
  maxFiles: 12
  priorityOrder: ["main", "config", "view"]
severityHeuristics:
  critical:
    - "A BrowserWindow/webview has nodeIntegration:true (or contextIsolation:false) AND loads web/remote/user-influenceable content, so an XSS in the renderer reaches Node (require/child_process/fs) — renderer XSS to native RCE"
  high:
    - "contextIsolation is disabled or sandbox is off on a window rendering non-trivial content, weakening the boundary between page JS and the preload/Node context even if nodeIntegration is false"
    - "The app loads remote/untrusted URLs into a main-window renderer (not an isolated view), or allows arbitrary navigation / window.open to attacker-controlled origins, giving injected/malicious pages the renderer's capabilities"
  medium:
    - "enableRemoteModule / the remote module is enabled, or webviews are used without explicit secure webPreferences, expanding the attack surface"
    - "Secure defaults are relied upon but individual windows override them inconsistently, so some renderers are hardened and others are not"
  low:
    - "A window with secure settings (contextIsolation:true, nodeIntegration:false, sandbox:true) loading only bundled local content — the target state; confirm no override before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:renderer_isolation"
  relatedNodeIds: ["component:remote_code_execution", "component:input_validation"]
graphEdgeMapping:
  - relation: causes
    from: "component:renderer_isolation"
    to: "component:remote_code_execution"
commonAiCodingMistakes:
  - "AI sets `nodeIntegration: true` (or `contextIsolation: false`) to make `require`/Node APIs work directly in the renderer, not realizing this hands Node to page JavaScript — so any XSS (including from a dependency or injected content) becomes native code execution."
  - "AI loads a remote URL or user-influenceable content into the main renderer instead of an isolated, sandboxed view, exposing the app's renderer capabilities to that content."
  - "AI disables the sandbox for convenience, weakening OS-level containment of the renderer."
  - "AI enables the remote module (or uses `@electron/remote`) broadly, exposing main-process objects to the renderer."
  - "AI adds a `<webview>` without setting secure `webpreferences`, inheriting insecure behavior."
  - "AI allows unrestricted `will-navigate` / `new-window` so the renderer can be steered to attacker origins."
falsePositiveGuardrails:
  - "Do not flag windows that use the secure configuration — contextIsolation:true, nodeIntegration:false, sandbox:true — loading only bundled local content. That is the target; confirm no per-window override re-enables Node."
  - "A window that legitimately needs Node access but loads ONLY trusted, bundled, non-web content with contextIsolation still on and a minimal preload bridge is lower risk than one rendering web content — assess what the renderer loads."
  - "Navigation/window-open handlers that restrict to an allow-list of trusted origins are correct — only unrestricted navigation to arbitrary origins is the finding."
  - "Modern Electron defaults (contextIsolation on, nodeIntegration off) mean the absence of explicit settings is often secure — verify the effective config/version rather than flagging silence."
---

## Root Cause Explanation

Electron runs web content (a Chromium renderer) next to Node.js, and its entire
security model is about keeping those two apart. When the boundary is intact, an
XSS in the renderer is "just" an XSS — annoying, contained. When the boundary is
removed — `nodeIntegration: true`, or `contextIsolation: false` — page JavaScript
can reach Node's `require`, `child_process`, and `fs`, so the *same* XSS becomes
arbitrary native code execution on the user's machine. This is why the Electron
security checklist treats these settings as load-bearing, and why several
well-known desktop apps have shipped renderer-XSS-to-RCE bugs.

The secure configuration is now the default in modern Electron
(`contextIsolation: true`, `nodeIntegration: false`), plus `sandbox: true` and no
remote module. The review is therefore about finding where the app *overrides*
those defaults, where it loads remote/untrusted content into a capable renderer,
and where webviews or navigation handlers open the door. Keep Node out of any
renderer that touches web content; expose only a minimal, audited preload bridge
(see electron.ipc_preload).

## Vulnerable Patterns

```js
// Node handed to the renderer — XSS becomes RCE
new BrowserWindow({
  webPreferences: { nodeIntegration: true, contextIsolation: false, sandbox: false },
});
win.loadURL("https://third-party.example.com");    // remote content in a capable renderer
```

Correct: secure webPreferences, local content, restricted navigation.

```js
new BrowserWindow({
  webPreferences: {
    contextIsolation: true,
    nodeIntegration: false,
    sandbox: true,
    preload: path.join(__dirname, "preload.js"),   // minimal, audited bridge only
  },
});
win.webContents.on("will-navigate", (e, url) => { if (!isTrusted(url)) e.preventDefault(); });
```

## Data Flow Tracing Guide

1. Enumerate every `BrowserWindow`, `BrowserView`, and `<webview>` and read its
   `webPreferences`.
2. Flag `nodeIntegration: true`, `contextIsolation: false`, `sandbox: false`, and
   remote-module enablement.
3. Determine what each renderer loads (bundled local vs. remote/untrusted) and
   whether navigation/new-window is restricted.
4. The highest severity is a Node-enabled/isolation-off renderer that loads or
   can navigate to web/untrusted content (XSS→RCE).
5. Cross-reference electron.ipc_preload for what the preload bridge exposes.

## Evidence Checklist

- [ ] The window/webview `webPreferences`, quoted.
- [ ] What the renderer loads and its navigation restrictions.
- [ ] The effective Electron defaults/version if settings are implicit.
- [ ] The XSS→Node path if isolation is off.

## Attack Scenario Template

> An attacker achieves XSS in the renderer (via injected content, a compromised
> dependency, or a loaded remote page). Because [file:line] configures the window
> with [nodeIntegration:true / contextIsolation:false / sandbox:false], the
> injected script reaches Node (`require('child_process')`), executing native code
> on the user's machine — renderer XSS to full RCE.

## Graph Mapping Instructions

- Ensure a `component:renderer_isolation` node with a `causes` edge to
  `component:remote_code_execution`.
- Note the XSS→RCE elevation in `reasoning`.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:renderer_isolation`; cross-link to electron.ipc_preload.
