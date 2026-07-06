---
id: technology.desktop.deep_link_hijacking
title: "Desktop: Custom Protocol / Deep-Link Handling"
category: technology
vulnerabilityClass: improper_input_handling
appliesToStack: desktop apps registering custom URL schemes (Electron/Tauri)
requiresAnyTag: ["electron", "tauri"]
deepOnly: false
reviewPass: 2
owaspRefs:
  - "A03:2021 Injection"
  - "A01:2021 Broken Access Control"
cweRefs:
  - "CWE-20"
  - "CWE-88"
  - "CWE-78"
realWorldReferences:
  - title: "Electron custom protocol handler argument injection (CVE-2018-1000006) — deep link reaching command execution"
    url: "https://github.com/electron/electron/security/advisories"
    type: vendor_security_advisory
  - title: "Deep-link / custom-scheme abuse to trigger privileged actions in desktop apps"
    url: "https://positive.security/blog/url-open-rce"
    type: research_paper
  - title: "OWASP — validating deep-link/URL input before acting on it"
    url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"
    type: security_blog
quickModeSummary: >
  Apps that register a custom URL scheme (myapp://) can be launched by any web
  page or other app with an attacker-controlled URL, so the deep-link handler is
  an untrusted input entry point — and on some platforms the URL becomes command-
  line arguments (argument injection, CVE-2018-1000006). Review the protocol/
  open-url handler: treat the incoming URL as fully untrusted. Flag handlers that
  pass deep-link parameters into shell/exec, navigate the webview to a URL from
  the link (open redirect / loading attacker content into a privileged renderer),
  perform sensitive actions (auth, purchases, file operations) triggered solely by
  the link with no confirmation, or reflect link data into the app unsanitized.
  Parse and validate the URL strictly, allow-list actions/targets, and require
  confirmation for anything sensitive a link can trigger.
fileSelectionHint:
  roles: ["main", "config", "service", "controller"]
  matchImports: ["electron", "@tauri-apps/api"]
  matchAuthMapTags: ["electron", "tauri"]
  maxFiles: 10
  priorityOrder: ["main", "controller", "config", "service"]
severityHeuristics:
  critical:
    - "A deep-link/custom-protocol handler passes URL-derived input into a shell/exec or command-line arguments (argument injection), so a crafted myapp:// link from a web page executes commands on the host"
  high:
    - "The handler navigates a privileged renderer to a URL taken from the deep link, loading attacker-controlled content into the app's (capable) webview, or performs a sensitive action (auth token exchange, purchase, file write) triggered solely by the link with no verification"
    - "Deep-link parameters are used to select actions/targets with no allow-list, letting a link invoke unintended app functionality"
  medium:
    - "Deep-link input is reflected into the app or used in a moderately sensitive operation with partial validation, or the scheme handler lacks single-instance/argument-parsing hardening that prevents injection"
    - "Sensitive actions require the app to be focused/foregrounded but not explicit user confirmation"
  low:
    - "The handler strictly parses and validates the URL, allow-lists actions/targets, and confirms sensitive operations — the target state; confirm the validation before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:deep_link_handler"
  relatedNodeIds: ["component:input_validation", "component:remote_code_execution"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:deep_link_handler"
    to: "component:input_validation"
  - relation: causes
    from: "component:deep_link_handler"
    to: "component:remote_code_execution"
commonAiCodingMistakes:
  - "AI registers a custom scheme and passes the launch URL/arguments into a shell or uses them to build a command, not accounting for argument injection (CVE-2018-1000006) — a web page's `myapp://...` link runs commands on the host."
  - "AI navigates the app's webview to a URL taken from the deep link, so an attacker's link loads their page into the privileged renderer (compounding with the process-model/capability issues)."
  - "AI performs a sensitive action (complete auth, apply a setting, open/delete a file) directly from deep-link parameters with no confirmation, so any page that opens the link triggers it."
  - "AI uses a link parameter to choose which internal action to run with no allow-list, exposing unintended functionality."
  - "AI trusts the deep-link URL because 'it's our scheme', forgetting any app or web page can invoke it with arbitrary content."
falsePositiveGuardrails:
  - "Do not flag handlers that strictly parse the URL, validate/allow-list the action and parameters, and require confirmation for sensitive operations — that is correct handling of an untrusted entry point."
  - "A handler that only navigates to allow-listed internal routes (not arbitrary URLs) and never reaches a shell/command sink is safe — confirm the allow-list and the absence of command sinks."
  - "Single-instance + proper argument parsing (not passing the raw URL to a shell) mitigates argument injection — factor it in."
  - "Cross-reference electron.process_model / tauri.security (renderer capability) — the deep link is the vector; report the handler's input-validation gap here without double-counting the renderer issue."
---

## Root Cause Explanation

Registering a custom URL scheme (`myapp://`) is convenient — it lets links and
other apps launch yours with context — but it also means *any web page or app can
invoke your handler with an attacker-controlled URL*. The deep-link handler is
therefore an untrusted input entry point that arrives from outside the app's own
UI, and it is easy to forget that "our scheme" doesn't mean "our input." Two
consequences make it dangerous. On some platforms the launch URL is passed as
**command-line arguments**, so a handler that forwards them to a shell yields
argument injection and command execution from a mere link (CVE-2018-1000006). And
because the handler runs inside the privileged desktop app, using link data to
navigate the webview, complete authentication, or perform file/settings
operations lets a crafted link drive sensitive behavior — often with no user
interaction beyond clicking a link.

The controls are ordinary untrusted-input handling applied to the deep-link
boundary: parse and strictly validate the URL, allow-list the actions and targets
it may select, never pass link data to a shell or use it to load arbitrary
content into a capable renderer, and require explicit confirmation for anything
sensitive a link can trigger.

## Vulnerable Patterns

```js
// Deep-link argument reaches a shell → command execution from a link
app.on("open-url", (e, url) => exec(`process ${new URL(url).searchParams.get("file")}`));

// Link navigates the privileged renderer to attacker content
app.on("open-url", (e, url) => win.loadURL(new URL(url).searchParams.get("next")));

// Sensitive action straight from the link, no confirmation
app.on("open-url", (e, url) => completeLogin(new URL(url).searchParams.get("token")));
```

Correct: parse, validate, allow-list, confirm.

```js
app.on("open-url", (e, url) => {
  const u = new URL(url);
  const action = u.hostname;                      // e.g. myapp://open-project
  if (action === "open-project" && /^[a-f0-9-]{36}$/.test(u.searchParams.get("id") ?? "")) {
    openProjectById(u.searchParams.get("id"));    // allow-listed, validated
  }
});
```

## Data Flow Tracing Guide

1. Find custom scheme registration and the handler(s) (`open-url`, second-instance
   argv, Tauri deep-link/plugin handlers).
2. Trace link-derived input into sinks: shell/command, webview navigation,
   sensitive actions (auth/file/settings), internal action selection.
3. Check parsing/validation and action/target allow-listing.
4. Check whether the platform passes the URL as argv (argument-injection risk) and
   whether the app mitigates it.
5. Check for confirmation on sensitive link-triggered operations.

## Evidence Checklist

- [ ] The scheme registration and handler, quoted.
- [ ] The sink the link data reaches (shell / navigation / sensitive action).
- [ ] Validation / allow-listing / confirmation present or absent.
- [ ] A concrete malicious `myapp://` URL and its effect.

## Attack Scenario Template

> A web page the victim visits triggers `myapp://...` with attacker-controlled
> parameters. Because [file:line] [passes the parameter into a shell / navigates
> the renderer to the link's URL / completes a sensitive action] without
> validation or confirmation, the link results in [command execution / attacker
> content in the privileged renderer / an unauthorized sensitive action].

## Graph Mapping Instructions

- Ensure a `component:deep_link_handler` node with a `depends_on` edge to
  `component:input_validation`; command-sink findings add a `causes` edge to
  `component:remote_code_execution`.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:deep_link_handler`; cross-link to the renderer-capability
  playbook where relevant.
