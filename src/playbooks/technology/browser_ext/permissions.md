---
id: technology.browser_ext.permissions
title: "Browser Extension: Permissions & Content Scripts"
category: technology
vulnerabilityClass: excessive_permissions
appliesToStack: browser extensions (Chrome/Firefox/Edge, MV3)
requiresAnyTag: ["browser-ext"]
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A01:2021 Broken Access Control"
  - "A05:2021 Security Misconfiguration"
cweRefs:
  - "CWE-250"
  - "CWE-272"
  - "CWE-79"
realWorldReferences:
  - title: "Chrome — extension security best practices, least-privilege permissions, host_permissions"
    url: "https://developer.chrome.com/docs/extensions/develop/security-privacy/stay-secure"
    type: vendor_security_advisory
  - title: "Malicious/compromised extensions abusing broad host permissions to steal data across all sites (repeated incidents)"
    url: "https://arstechnica.com/information-technology/2024/12/malicious-chrome-extensions-compromise-users-in-16-companies/"
    type: incident_postmortem
  - title: "Content-script XSS/DOM injection and the danger of injecting page-controlled data into the extension context"
    url: "https://developer.chrome.com/docs/extensions/develop/security-privacy/stay-secure#content_scripts"
    type: security_blog
quickModeSummary: >
  An extension's power — and its blast radius if compromised — is set by its
  manifest permissions. Review manifest.json: flag broad host_permissions
  (<all_urls>, *://*/*) and powerful APIs (tabs, webRequest, cookies, scripting,
  debugger, nativeMessaging) requested beyond what the features need — an extension
  with all-sites access that gets compromised (supply-chain, sold, or malicious
  update) can read/modify every page and steal cookies/credentials (a repeated
  real-world incident class). Then review content scripts: they run in web pages,
  so treat page/DOM data as untrusted — flag injecting page-controlled data into the
  extension's DOM/eval (extension XSS), and over-broad content_scripts matches. Use
  least-privilege permissions (activeTab and specific hosts over <all_urls>),
  request optional permissions on demand, and never trust page data in the extension
  context.
fileSelectionHint:
  roles: ["config", "content_script", "service", "background"]
  matchImports: ["webextension-polyfill", "chrome", "browser"]
  matchAuthMapTags: ["browser-ext"]
  maxFiles: 10
  priorityOrder: ["config", "content_script", "background"]
severityHeuristics:
  critical:
    - "The extension requests broad host access (<all_urls> / *://*/*) plus powerful APIs (cookies/webRequest/scripting/debugger) it doesn't strictly need, so a compromise (malicious update, supply-chain, ownership transfer) grants read/modify of every site and theft of cookies/credentials across the web"
  high:
    - "A content script injects page-controlled/DOM data into the extension's own DOM or an eval/innerHTML sink, enabling XSS in the privileged extension context (which can reach the extension's APIs)"
    - "nativeMessaging or debugger permission is requested, bridging the extension to native code or full devtools without a strong justification"
  medium:
    - "Permissions are broader than needed but not maximally dangerous (e.g. host access to more sites than the features touch), or content_scripts match patterns are over-broad"
    - "The extension requests all permissions up front instead of using optional_permissions / activeTab on demand"
  low:
    - "Least-privilege manifest (activeTab or specific hosts, minimal APIs), content scripts that treat page data as untrusted, and on-demand optional permissions — the target state; confirm the permission set matches the features before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:extension_permissions"
  relatedNodeIds: ["component:authorization", "component:secrets"]
graphEdgeMapping:
  - relation: exposes
    from: "component:extension_permissions"
    to: "component:secrets"
commonAiCodingMistakes:
  - "AI requests `host_permissions: ['<all_urls>']` and `cookies`/`webRequest` 'to be flexible', giving the extension read/modify access to every site — so if it's ever compromised or sold, the attacker harvests data and cookies across the entire web (the repeated malicious-extension incident class)."
  - "AI writes a content script that inserts page-derived data via `innerHTML` or `eval` into the extension's UI, creating XSS in the privileged extension context."
  - "AI requests powerful APIs (debugger, nativeMessaging, scripting on all sites) that the features don't need."
  - "AI uses over-broad `content_scripts.matches` (e.g. `<all_urls>`) when the extension only needs to run on one site."
  - "AI requests all permissions at install instead of using `activeTab` / `optional_permissions` requested on demand."
  - "AI trusts messages/data from the web page in the content script and forwards them to the background with the extension's privileges (see browser_ext.messaging)."
falsePositiveGuardrails:
  - "Do not flag an extension whose permissions match its features — a password manager legitimately needs broad access; a single-site tool should not. Judge permissions against the stated functionality, and prefer least privilege (activeTab/specific hosts) as the bar."
  - "Content scripts that treat page/DOM data as untrusted (textContent not innerHTML, no eval, sanitized before use) are correct — only injecting page-controlled data into a sink is the XSS finding."
  - "activeTab + on-demand optional_permissions is the least-privilege pattern and is correct even if the extension can access a page when invoked."
  - "nativeMessaging/debugger with a clear, necessary justification (and a locked-down native host) may be acceptable — flag the breadth/justification, and cross-reference browser_ext.messaging for the native host security."
---

## Root Cause Explanation

A browser extension runs with privileges ordinary web pages never get — reading and
modifying page content, intercepting requests, accessing cookies — and the manifest's
**permissions** decide exactly how much. That permission set is also the **blast
radius if the extension is ever compromised**, and extensions get compromised
routinely: supply-chain attacks on their dependencies, malicious updates, and
outright sale of popular extensions to bad actors. An extension with `<all_urls>`
host access plus `cookies`/`webRequest` that turns malicious can harvest credentials
and data from *every site the user visits* — a real, repeated incident class. So
least privilege isn't hygiene here; it's the cap on catastrophe.

The second surface is **content scripts**, which execute inside web pages and thus
sit next to untrusted, attacker-influenceable DOM. Injecting page-controlled data
into the extension's own DOM (`innerHTML`) or `eval` yields XSS in the *privileged
extension context*, which can reach the extension's APIs. The controls: request the
**minimum** permissions the features need (prefer `activeTab` and specific hosts over
`<all_urls>`, request powerful APIs only when justified, use `optional_permissions`
on demand), and treat all page/DOM data in content scripts as untrusted.

## Vulnerable Patterns

```jsonc
// Over-broad permissions — huge blast radius if compromised
{ "host_permissions": ["<all_urls>"],
  "permissions": ["cookies", "webRequest", "scripting", "tabs"] }   // more than needed
```

```js
// Content script injecting page data into the extension DOM → extension XSS
panel.innerHTML = document.querySelector(".title").textContent + document.location.hash;
```

Correct: least privilege + untrusted page data.

```jsonc
{ "permissions": ["activeTab"], "optional_permissions": ["cookies"],
  "host_permissions": ["https://app.example.com/*"] }
```

## Data Flow Tracing Guide

1. Read manifest.json: list host_permissions and permissions; compare against the
   extension's actual features (least privilege?).
2. Flag `<all_urls>`/`*://*/*`, and powerful APIs (cookies, webRequest, scripting on
   all sites, debugger, nativeMessaging) beyond need.
3. Review content scripts: trace page/DOM data into innerHTML/eval/extension-DOM
   sinks.
4. Check content_scripts.matches breadth and whether activeTab/optional_permissions
   are used.
5. Rank by compromise blast radius (all-sites + cookies/webRequest highest).

## Evidence Checklist

- [ ] The requested host_permissions and permissions, quoted, vs. the features.
- [ ] Any content-script injection of page data into a sink.
- [ ] Powerful-API requests and their justification.
- [ ] Whether least-privilege patterns (activeTab/optional) are used.

## Attack Scenario Template

> The extension (with [<all_urls> + cookies/webRequest]) is [compromised via a
> malicious update / supply-chain / sold]. Because [file:line] grants access to
> every site, the now-malicious extension reads and exfiltrates [cookies /
> credentials / page data] across all the user's sites — or a content script's
> injection of page data yields XSS in the extension context — resulting in
> [web-wide data theft].

## Graph Mapping Instructions

- Ensure a `component:extension_permissions` node with an `exposes` edge to
  `component:secrets` for broad cookie/host findings.
- Content-script XSS findings cross-link to xss and note the privileged-context
  elevation.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:extension_permissions`.
