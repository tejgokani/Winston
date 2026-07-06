---
id: technology.browser_ext.messaging
title: "Browser Extension: Messaging & Isolation"
category: technology
vulnerabilityClass: broken_access_control
appliesToStack: browser extensions with message passing / native hosts
requiresAnyTag: ["browser-ext"]
deepOnly: false
reviewPass: 2
owaspRefs:
  - "A01:2021 Broken Access Control"
  - "A03:2021 Injection"
cweRefs:
  - "CWE-346"
  - "CWE-940"
  - "CWE-749"
realWorldReferences:
  - title: "Chrome — message passing, externally_connectable, and validating message senders"
    url: "https://developer.chrome.com/docs/extensions/develop/concepts/messaging"
    type: vendor_security_advisory
  - title: "Extension privilege escalation: web page → content script → background reaching privileged APIs without sender validation"
    url: "https://portswigger.net/research/exploiting-browser-extensions"
    type: research_paper
  - title: "nativeMessaging host abuse — a web page reaching native code through an over-permissive extension bridge"
    url: "https://www.tenable.com/blog/browser-extension-native-messaging"
    type: security_blog
quickModeSummary: >
  The privilege gradient in an extension runs web page (untrusted) → content script
  (semi-privileged) → background/service worker (full extension APIs) → native host
  (native code). Message passing crosses these boundaries, so each hop must validate
  what it receives. Flag: background message handlers (onMessage / onMessageExternal)
  that act on messages without validating the sender (origin/id) and the message
  contents, so a web page (via externally_connectable or a compromised content
  script) can invoke privileged APIs (the classic page→background escalation);
  externally_connectable set to broad matches (or "<all_urls>") letting arbitrary
  sites message the extension; content scripts forwarding page-controlled data to the
  background which then acts on it; and nativeMessaging hosts that trust extension
  messages and pass them to native sinks (shell/exec). Validate sender and content at
  every hop, scope externally_connectable narrowly, and never let page data reach a
  privileged/native sink unchecked.
fileSelectionHint:
  roles: ["background", "content_script", "service", "config", "native_host"]
  matchImports: ["webextension-polyfill", "chrome", "browser"]
  matchAuthMapTags: ["browser-ext"]
  maxFiles: 10
  priorityOrder: ["background", "native_host", "content_script", "config"]
severityHeuristics:
  critical:
    - "A background/native-host message handler passes message data into a dangerous sink (nativeMessaging → shell/exec, privileged API calls, script injection) without validating the sender AND the content, so a web page or compromised content script reaches native code / powerful APIs (privilege escalation to RCE-class)"
  high:
    - "Background onMessage handlers invoke privileged extension APIs based on messages with no sender validation, so a page (via externally_connectable or a content script relay) drives those APIs; or externally_connectable is broadly scoped (<all_urls> / broad matches) allowing arbitrary sites to message the extension"
    - "A content script forwards page-controlled data to the background which acts on it (fetch to page-supplied URL, storage/cookie ops) without validation"
  medium:
    - "Sender is checked but message content isn't validated before use, or externally_connectable is scoped but wider than needed; message channels lack an action allow-list"
    - "postMessage between content script and page is used without origin/target checks"
  low:
    - "Handlers validate both sender (id/origin) and content, externally_connectable is narrowly scoped (or absent), and page data never reaches a privileged sink unchecked — the target state; confirm sender+content validation before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:extension_messaging"
  relatedNodeIds: ["component:authorization", "component:remote_code_execution"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:extension_messaging"
    to: "component:authorization"
  - relation: causes
    from: "component:extension_messaging"
    to: "component:remote_code_execution"
commonAiCodingMistakes:
  - "AI writes a background `onMessage`/`onMessageExternal` handler that performs a privileged action based on the message, without validating `sender` (id/origin) — so a web page (via externally_connectable) or a compromised content script escalates to the extension's APIs."
  - "AI sets `externally_connectable.matches` to `<all_urls>` or a broad pattern, letting any website send messages to the extension."
  - "AI has a content script relay page-controlled data (a URL, a command, DOM content) to the background, which acts on it (fetch, cookies, storage) with no validation — page→privileged data flow."
  - "AI builds a nativeMessaging host that trusts messages from the extension and passes them into a shell/exec, so a page→content-script→background→native chain reaches command execution."
  - "AI uses `window.postMessage` between content script and page without checking `event.origin` / target origin, mixing trust boundaries."
  - "AI validates the sender OR the content but not both, leaving a gap."
falsePositiveGuardrails:
  - "Do not flag message handlers that validate BOTH the sender (sender.id for internal, sender.origin/url against an allow-list for external) AND the message content/action (allow-listed action, validated arguments) before acting — that is correct cross-boundary handling."
  - "externally_connectable that is absent (no external messaging) or narrowly scoped to specific trusted origins is correct — only broad matches are the finding."
  - "A nativeMessaging host that validates/allow-lists the operations it will perform (no raw shell from message data) is correct — the concern is message data reaching a native sink unchecked."
  - "postMessage with strict origin/target checks is correct — only unchecked cross-context postMessage is a finding."
  - "Cross-reference browser_ext.permissions (the API surface) — report the messaging/sender-validation gap here without double-counting the permission breadth."
---

## Root Cause Explanation

A browser extension spans a privilege gradient — an untrusted web **page**, a
content **script** that runs in that page but can talk to the extension, a
**background/service worker** with the extension's full API access, and optionally a
**native messaging host** running native code. Message passing is how data crosses
those boundaries, and every crossing is a trust-boundary transition that must be
validated. The canonical vulnerability is **privilege escalation via unvalidated
messages**: a background handler that acts on a message without checking *who sent it*
lets a web page (through `externally_connectable`) or a compromised content script
invoke the extension's privileged APIs. Broaden `externally_connectable` to
`<all_urls>` and any site on the web can send those messages. Extend the chain to a
`nativeMessaging` host that forwards message data to a shell, and a web page reaches
**native code execution** through the extension.

The controls mirror any IPC boundary: at each hop, validate **both** the sender
(`sender.id` for internal messages; `sender.origin`/`url` against an allow-list for
external) **and** the message content (allow-listed action, validated arguments)
before acting; scope `externally_connectable` to specific trusted origins (or omit
it); never forward page-controlled data to a privileged/native sink unchecked; and
use origin/target checks on any `postMessage` between the content script and the page.

## Vulnerable Patterns

```js
// Background acts on any message, no sender validation → page/content-script escalation
chrome.runtime.onMessageExternal.addListener((msg, sender, send) => {
  if (msg.action === "getCookies") send(chrome.cookies.getAll(msg.filter));   // any sender
});
```

```jsonc
{ "externally_connectable": { "matches": ["<all_urls>"] } }   // any site can message
```

```js
// nativeMessaging host trusting message data into a shell → RCE chain
port.onMessage.addListener((m) => exec(m.command));
```

Correct: validate sender + content, scope externally_connectable, allow-list
actions.

```js
chrome.runtime.onMessageExternal.addListener((msg, sender, send) => {
  if (sender.origin !== "https://app.example.com") return;          // sender check
  if (msg.action === "ping") send({ ok: true });                    // allow-listed action
});
```

## Data Flow Tracing Guide

1. Find all message handlers: onMessage, onMessageExternal, native host onMessage,
   window.postMessage between content script and page.
2. For each, check sender validation (id/origin against an allow-list) and content/
   action validation before any privileged/native action.
3. Read externally_connectable scope (broad vs. specific vs. absent).
4. Trace page-controlled data through content script → background → sinks (APIs,
   fetch, native host → shell).
5. Rank: page→native/shell is critical; page→privileged-API is high.

## Evidence Checklist

- [ ] The message handler and its sender/content validation (or absence), quoted.
- [ ] externally_connectable scope.
- [ ] The privileged/native sink the message data reaches.
- [ ] A concrete page→handler→sink escalation path.

## Attack Scenario Template

> An attacker's web page [messages the extension via externally_connectable / drives
> a compromised content script to relay to the background]. Because [file:line] acts
> on the message without validating [the sender / the content], the page invokes
> [a privileged extension API / the native host's shell], resulting in [cookie/data
> theft / native code execution] — escalating from an untrusted page to the
> extension's (or native) privileges.

## Graph Mapping Instructions

- Ensure a `component:extension_messaging` node with a `depends_on` edge to
  `component:authorization`; native-sink findings add a `causes` edge to
  `component:remote_code_execution`.
- Note the page→background→native escalation path in `reasoning`.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:extension_messaging`; cross-link to browser_ext.permissions.
