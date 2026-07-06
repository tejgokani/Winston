---
id: technology.electron.ipc_preload
title: "Electron: IPC & Preload Bridge Security"
category: technology
vulnerabilityClass: broken_access_control
appliesToStack: electron
requiresAnyTag: ["electron"]
deepOnly: false
reviewPass: 2
owaspRefs:
  - "A03:2021 Injection"
  - "A01:2021 Broken Access Control"
cweRefs:
  - "CWE-749"
  - "CWE-78"
  - "CWE-829"
realWorldReferences:
  - title: "Electron — contextBridge and secure IPC patterns; the danger of exposing ipcRenderer or Node APIs to the page"
    url: "https://www.electronjs.org/docs/latest/tutorial/context-isolation"
    type: security_blog
  - title: "Preload/contextBridge over-exposure leading to renderer-to-main privilege escalation (research writeups)"
    url: "https://benjamin-altpeter.de/shell-injection/"
    type: research_paper
  - title: "Electron IPC main handlers acting on renderer input without validation (command injection / path traversal class)"
    url: "https://www.electronjs.org/docs/latest/tutorial/security"
    type: security_blog
quickModeSummary: >
  With contextIsolation on, the preload script's contextBridge is the ONLY door
  between untrusted page JavaScript and the privileged main process — so what it
  exposes is the attack surface. Flag preloads that expose too much: the whole
  `ipcRenderer` (letting the page send any channel), Node modules (fs,
  child_process), or generic "invoke any channel / run this" functions. Then
  review the main-process IPC handlers (ipcMain.handle/on): they receive input
  from a potentially-compromised renderer, so treat every argument as untrusted —
  flag handlers that pass renderer input into shell/exec, file paths (traversal),
  SQL, or arbitrary URLs (SSRF) without validation. Expose a minimal,
  purpose-specific API surface (not raw IPC), validate every argument in the main
  process, and never hand the page a generic escape hatch.
fileSelectionHint:
  roles: ["preload", "main", "config", "service"]
  matchImports: ["electron"]
  matchAuthMapTags: ["electron"]
  maxFiles: 12
  priorityOrder: ["preload", "main", "service"]
severityHeuristics:
  critical:
    - "A main-process IPC handler passes renderer-supplied input into a dangerous sink — shell/exec, a file path, SQL, or an outbound request — without validation, so a compromised/XSS'd renderer achieves command injection / path traversal / SSRF in the privileged process"
    - "The preload exposes raw Node APIs (fs/child_process) or the full ipcRenderer / a generic 'invoke any channel'/'eval' function to the page, giving page JavaScript direct privileged capability"
  high:
    - "The contextBridge exposes an overly broad API (more channels/operations than needed, or pass-through of arbitrary arguments) that a compromised renderer can abuse to reach sensitive main-process functionality"
    - "IPC handlers perform sensitive/privileged actions with no authorization or origin/sender check, trusting that the renderer is legitimate"
  medium:
    - "IPC arguments are partially validated, or the exposed API is purpose-specific but one operation forwards unvalidated input to a moderately sensitive sink"
    - "Preload leaks main-process objects/prototypes to the page in a way that could be leveraged, or channels lack a clear allow-list"
  low:
    - "A minimal contextBridge exposing specific, validated operations with main-side argument validation — the correct pattern; confirm no raw IPC/Node exposure before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:ipc_bridge"
  relatedNodeIds: ["component:remote_code_execution", "component:input_validation"]
graphEdgeMapping:
  - relation: causes
    from: "component:ipc_bridge"
    to: "component:remote_code_execution"
  - relation: depends_on
    from: "component:ipc_bridge"
    to: "component:input_validation"
commonAiCodingMistakes:
  - "AI exposes `ipcRenderer` directly via contextBridge (`contextBridge.exposeInMainWorld('ipc', ipcRenderer)`) so the page can send ANY channel, collapsing the isolation boundary the preload was supposed to protect."
  - "AI writes an IPC handler like `ipcMain.handle('run', (e, cmd) => exec(cmd))` or `readFile(path)` that runs renderer-supplied commands/paths, so a compromised renderer gets command injection / arbitrary file read in the main process."
  - "AI exposes Node modules (fs, child_process) or a generic `invoke(channel, ...args)` through the preload, handing the page privileged primitives."
  - "AI trusts that IPC messages come from its own legitimate renderer and does no argument validation or sender/origin check, even though an XSS'd or malicious renderer is the threat."
  - "AI builds file/shell/DB operations in handlers without path allow-listing or parameterization, reintroducing classic injection in the privileged process."
falsePositiveGuardrails:
  - "Do not flag a preload that exposes a minimal, purpose-specific API (named operations, not raw ipcRenderer/Node) AND whose main-process handlers validate/parameterize every argument — that is the correct contextBridge pattern."
  - "Handlers that allow-list file paths, parameterize SQL, restrict outbound URLs, and validate enums before any sink are safe — the concern is unvalidated renderer input reaching a dangerous sink."
  - "Exposing specific, non-sensitive read operations with validated inputs is fine — severity scales with the sink's danger and the sensitivity of the operation."
  - "Cross-reference electron.process_model (isolation) — if isolation is off, the bridge is moot (the page already has Node); report the process-model issue there and the bridge over-exposure here without double-counting."
---

## Root Cause Explanation

Once `contextIsolation` is on (as it should be), page JavaScript can no longer
touch Node directly — it can only call whatever the **preload** exposes through
`contextBridge`, and it can only talk to the main process over the **IPC
channels** the app defines. Those two things are therefore the entire
renderer-to-privilege attack surface, and both are routinely over-built. On the
preload side, exposing `ipcRenderer` wholesale, Node modules, or a generic
"invoke any channel / run anything" helper hands the page back the very
capabilities isolation removed. On the main side, IPC handlers receive arguments
from a renderer that may be XSS'd or malicious, so an unvalidated handler that
shells out, reads a renderer-supplied path, builds SQL, or fetches a
renderer-supplied URL is command injection / path traversal / SSRF *in the
privileged process*.

The discipline is the same as any trust boundary: expose the **minimum**,
purpose-specific API (named operations, not raw IPC/Node), and **validate every
argument** on the main side as untrusted input — allow-list paths, parameterize
queries, restrict URLs, check enums, and where relevant verify the sender. The
preload is a security-critical allow-list, not a convenience shim.

## Vulnerable Patterns

```js
// preload — hands the page raw IPC / Node (boundary collapse)
contextBridge.exposeInMainWorld("ipc", ipcRenderer);           // any channel
contextBridge.exposeInMainWorld("node", { exec: require("child_process").exec });

// main — renderer input into a dangerous sink, no validation
ipcMain.handle("run", (e, cmd) => exec(cmd));                  // command injection
ipcMain.handle("read", (e, p) => fs.readFileSync(p));          // path traversal
```

Correct: minimal named API + main-side validation.

```js
// preload — specific operations only
contextBridge.exposeInMainWorld("api", {
  openProject: (id) => ipcRenderer.invoke("project:open", id),
});
// main — validate every argument
ipcMain.handle("project:open", (e, id) => {
  if (!/^[a-f0-9-]{36}$/.test(id)) throw new Error("bad id");   // allow-list
  return openProjectById(id);
});
```

## Data Flow Tracing Guide

1. Read the preload: what does contextBridge expose? Flag raw ipcRenderer, Node
   modules, or generic invoke/eval helpers; note the exposed API's breadth.
2. For each exposed operation, find its main-process IPC handler.
3. In each handler, trace renderer-supplied arguments into sinks (shell, file
   path, SQL, URL) and check for validation/parameterization/allow-listing.
4. Check for authorization/sender checks on sensitive handlers.
5. Cross-reference electron.process_model — isolation must be on for the bridge to
   matter.

## Evidence Checklist

- [ ] The contextBridge exposure, quoted (what the page can call).
- [ ] The main-process handler and the sink its arguments reach.
- [ ] The validation/allow-listing present or absent.
- [ ] A concrete renderer-to-sink payload.

## Attack Scenario Template

> An attacker with a foothold in the renderer (XSS / malicious content) calls
> [exposed API / IPC channel]. Because [file:line] [exposes raw ipcRenderer/Node /
> passes the argument into exec/readFile/SQL/fetch unvalidated], the call executes
> [command injection / arbitrary file read / SSRF] in the privileged main process,
> resulting in [native compromise / data theft].

## Graph Mapping Instructions

- Ensure a `component:ipc_bridge` node with a `depends_on` edge to
  `component:input_validation` and, for exec sinks, a `causes` edge to
  `component:remote_code_execution`.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:ipc_bridge`; cross-link to electron.process_model.
