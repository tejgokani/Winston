---
id: technology.tauri.security
title: "Tauri: Capabilities, Commands & Config"
category: technology
vulnerabilityClass: broken_access_control
appliesToStack: tauri
requiresAnyTag: ["tauri"]
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A05:2021 Security Misconfiguration"
  - "A03:2021 Injection"
cweRefs:
  - "CWE-749"
  - "CWE-78"
  - "CWE-16"
realWorldReferences:
  - title: "Tauri — Security model, capabilities/permissions, and the allowlist/scopes system"
    url: "https://tauri.app/security/"
    type: security_blog
  - title: "Tauri — command (IPC) design and the danger of exposing broad filesystem/shell scopes to the webview"
    url: "https://tauri.app/develop/calling-rust/"
    type: security_blog
  - title: "Tauri security advisories (CSP, asset protocol, scope bypass classes)"
    url: "https://github.com/tauri-apps/tauri/security/advisories"
    type: vendor_security_advisory
quickModeSummary: >
  Tauri runs a web frontend over a Rust backend, and its security rests on
  capabilities/permissions (what the frontend is allowed to call) and command
  scopes (what those calls can touch). Review tauri.conf.json and the capability
  files: flag broad allowlist/permissions (fs, shell, http enabled widely),
  overly permissive scopes (fs access to `$HOME/**` or `**`, shell allowing
  arbitrary commands, http to `*`), and a weak/absent CSP (which is your XSS-to-
  capability firebreak — a frontend XSS can invoke whatever the capabilities
  allow). Then review the #[tauri::command] functions: they receive input from
  the webview, so validate every argument (path traversal, shell/SQL injection)
  as untrusted. Grant least-privilege capabilities scoped to exactly what the app
  needs, keep the CSP strict, and validate command inputs in Rust.
fileSelectionHint:
  roles: ["config", "main", "command", "service"]
  matchImports: ["@tauri-apps/api", "tauri"]
  matchAuthMapTags: ["tauri"]
  maxFiles: 12
  priorityOrder: ["config", "command", "main"]
severityHeuristics:
  critical:
    - "A capability/allowlist grants the frontend broad shell execution or filesystem access with a wide scope (e.g. shell allowing arbitrary commands, fs scope of `**`/`$HOME/**`), so a frontend XSS can run arbitrary commands or read/write arbitrary files via the capability"
    - "A #[tauri::command] passes webview-supplied input into a shell/exec, a filesystem path, or SQL without validation — command injection / path traversal reachable from the webview"
  high:
    - "The CSP is disabled/weak, removing the XSS firebreak so any injected frontend script can freely invoke the app's capabilities; or http/network capability is scoped to `*` enabling SSRF-like reach"
    - "Capabilities are broader than the app needs (excessive functionality), enlarging what a compromised frontend can do"
  medium:
    - "Command inputs are partially validated, or scopes are bounded but wider than necessary; the asset protocol or custom protocols expose more than required"
    - "Capabilities are assigned per-window inconsistently so some windows are over-privileged"
  low:
    - "Least-privilege capabilities with narrow fs/shell/http scopes, a strict CSP, and validated command inputs — the target state; confirm scopes and CSP before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:capability_config"
  relatedNodeIds: ["component:remote_code_execution", "component:input_validation"]
graphEdgeMapping:
  - relation: causes
    from: "component:capability_config"
    to: "component:remote_code_execution"
  - relation: depends_on
    from: "component:capability_config"
    to: "component:input_validation"
commonAiCodingMistakes:
  - "AI enables the shell capability with an open scope (allowing arbitrary commands) so the frontend can 'run things', not registering that a frontend XSS then runs arbitrary commands on the host via that capability."
  - "AI grants a broad fs scope (`$HOME/**` or `**`) instead of the specific directories the app needs, giving a compromised frontend arbitrary file access."
  - "AI weakens or disables the CSP, removing the firebreak that limits what an injected script can do — with capabilities enabled, XSS becomes host access."
  - "AI writes a #[tauri::command] that shells out or reads a path from a webview-supplied argument without validating it (command injection / path traversal in Rust)."
  - "AI sets the http capability scope to `*`, letting the frontend make arbitrary outbound requests through the backend (SSRF-like)."
  - "AI grants every capability 'to be safe/flexible' rather than the minimum the features require."
falsePositiveGuardrails:
  - "Do not flag capabilities that are narrowly scoped to exactly what the app needs (specific fs directories, a fixed shell command allow-list, specific http hosts) with a strict CSP — that is least privilege. Read the actual scopes."
  - "Commands that validate/allow-list their arguments before any sink are safe — the concern is unvalidated webview input reaching shell/path/SQL."
  - "A strict CSP materially limits XSS-to-capability escalation — factor it in when rating capability breadth."
  - "The mere use of fs/shell/http capabilities is not a finding — excessive SCOPE or missing input validation is. Establish the scope/validation gap."
---

## Root Cause Explanation

Tauri, like Electron, puts a web frontend in front of native power — but its
security model is explicit: **capabilities/permissions** declare what the
frontend may call, and **scopes** declare what those calls may touch, with a
**CSP** limiting what injected scripts can do in the first place. Security is
therefore a configuration exercise plus input validation. The failure mode is
over-granting: enabling the shell capability with an open command scope, giving
the filesystem capability a `**`/`$HOME/**` scope, opening http to `*`, or
weakening the CSP. Any of these means a frontend XSS — always possible — can
invoke real host capability: run commands, read/write arbitrary files, or make
arbitrary requests. The CSP is the firebreak; the scopes are the blast radius.

The second surface is the Rust `#[tauri::command]` functions: they take arguments
from the webview, which is untrusted, so a command that passes those arguments
into a shell, a filesystem path, or a query without validation is classic
injection in the native backend. The controls: grant least-privilege
capabilities with the narrowest scopes the features require, keep a strict CSP,
and validate every command argument in Rust as untrusted input.

## Vulnerable Patterns

```jsonc
// tauri.conf.json / capabilities — over-broad scopes + weak CSP
{ "permissions": [
    { "identifier": "shell:allow-execute", "allow": [{ "cmd": "*" }] },   // arbitrary commands
    { "identifier": "fs:allow-read", "allow": [{ "path": "$HOME/**" }] }   // arbitrary files
  ],
  "security": { "csp": null } }                                            // no firebreak
```

```rust
#[tauri::command]
fn run(cmd: String) -> String { Command::new("sh").arg("-c").arg(cmd).output()... } // injection
```

Correct: narrow scopes, strict CSP, validated commands.

```jsonc
{ "permissions": [
    { "identifier": "fs:allow-read", "allow": [{ "path": "$APPDATA/projects/**" }] }
  ],
  "security": { "csp": "default-src 'self'" } }
```

## Data Flow Tracing Guide

1. Read tauri.conf.json and capability files: list every granted capability and
   its scope (fs paths, shell commands, http hosts). Flag broad scopes.
2. Check the CSP — strict, weak, or disabled.
3. Enumerate `#[tauri::command]` functions and trace webview-supplied arguments
   into sinks (shell/path/SQL/URL); check validation.
4. Assess least privilege: are capabilities broader than the features need?
5. Check per-window capability assignment for over-privileged windows.

## Evidence Checklist

- [ ] The granted capabilities and their scopes, quoted.
- [ ] The CSP setting.
- [ ] The command function and the sink its arguments reach.
- [ ] The validation/allow-listing present or absent.

## Attack Scenario Template

> An attacker achieves XSS in the Tauri frontend. Because [file:line] grants
> [shell with an open scope / fs `**` / http `*`] and [the CSP is weak], the
> injected script invokes the capability to [run arbitrary commands / read
> arbitrary files / make arbitrary requests] on the host — or a #[tauri::command]
> forwards the input into a shell/path unvalidated — resulting in [host
> compromise / data theft].

## Graph Mapping Instructions

- Ensure a `component:capability_config` node with a `causes` edge to
  `component:remote_code_execution` for shell/fs-broad findings and a `depends_on`
  edge to `component:input_validation` for command-injection findings.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:capability_config`.
