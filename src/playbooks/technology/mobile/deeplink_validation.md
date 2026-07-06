---
id: technology.mobile.deeplink_validation
title: "Mobile: Deep Link & App Link Validation"
category: technology
vulnerabilityClass: improper_input_handling
appliesToStack: mobile apps handling deep links / app links / universal links
requiresAnyTag: ["android", "ios", "flutter", "expo"]
deepOnly: false
reviewPass: 2
owaspRefs:
  - "OWASP MASVS-PLATFORM"
  - "A01:2021 Broken Access Control"
cweRefs:
  - "CWE-20"
  - "CWE-939"
  - "CWE-601"
realWorldReferences:
  - title: "OWASP MASTG — deep link handling and validation across platforms"
    url: "https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/"
    type: security_blog
  - title: "Android App Links / iOS Universal Links — domain verification vs. unverified custom schemes"
    url: "https://developer.android.com/training/app-links/verify-android-applinks"
    type: vendor_security_advisory
  - title: "Deep-link parameter injection driving WebView navigation, open redirect, and sensitive actions"
    url: "https://evanconnelly.github.io/post/ios-url-scheme-hijacking/"
    type: research_paper
quickModeSummary: >
  A deep link is untrusted input from outside the app — any app or web page can open
  it with attacker-controlled parameters. This cross-platform playbook covers the
  shared handler logic (see android.exported_components, ios.url_scheme,
  desktop.deep_link_hijacking for platform specifics). Flag deep-link handlers that:
  perform sensitive/irreversible actions from link parameters with no validation or
  confirmation (complete auth, purchase, change settings, delete/share data);
  navigate a WebView or make a request to a link-supplied URL (open redirect / SSRF /
  loading attacker content); select internal actions/screens by an unvalidated
  parameter (no allow-list); or reflect link data into the UI unsanitized. Prefer
  verified App Links / Universal Links over unverified schemes for sensitive flows,
  strictly parse and allow-list every parameter and action, and require confirmation
  for sensitive operations a link can trigger.
fileSelectionHint:
  roles: ["controller", "service", "config", "view"]
  matchImports: ["expo-linking", "react-navigation", "uni_links", "go_router", "Linking"]
  matchAuthMapTags: ["android", "ios", "flutter", "expo"]
  maxFiles: 10
  priorityOrder: ["controller", "service", "view", "config"]
severityHeuristics:
  critical:
    - "A deep-link handler performs a privileged/irreversible action (auth completion, payment, data deletion/sharing, security-setting change) from link parameters with no validation or confirmation, so any app/page that opens the link triggers it"
  high:
    - "Link parameters drive WebView navigation or an outbound request to a link-supplied URL (loading attacker content into the app / open redirect / SSRF), or select internal actions/screens with no allow-list"
    - "A sensitive flow relies on an unverified custom scheme (hijackable) rather than a domain-verified App Link / Universal Link"
  medium:
    - "Link input is partially validated, or reflected into the UI without sanitization, or the App Link / Universal Link domain verification (assetlinks.json / apple-app-site-association) is misconfigured so it falls back to an unverified scheme"
    - "Sensitive actions require the app foregrounded but not explicit confirmation"
  low:
    - "Verified App/Universal Links for sensitive flows, strict parameter parsing/allow-listing, action allow-lists, and confirmation for sensitive operations — the target state; confirm the validation before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:deep_link_handler"
  relatedNodeIds: ["component:input_validation", "component:authorization"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:deep_link_handler"
    to: "component:input_validation"
commonAiCodingMistakes:
  - "AI routes deep links to screens/actions using an unvalidated parameter (`Linking` → navigate(params.screen)) with no allow-list, letting a link reach unintended internal functionality."
  - "AI performs a sensitive action straight from link parameters (apply a referral/credit, complete a flow, change a setting) with no confirmation, so any page that opens the link triggers it."
  - "AI opens a WebView or fetches a URL taken from the deep link, enabling open redirect / loading attacker content / SSRF."
  - "AI uses an unverified custom scheme for a sensitive flow (auth/payment) instead of a domain-verified App/Universal Link, making it hijackable/spoofable."
  - "AI reflects deep-link data into the UI without sanitizing it."
  - "AI misconfigures assetlinks.json / apple-app-site-association so App/Universal Link verification fails and the app falls back to the unverified scheme."
falsePositiveGuardrails:
  - "Do not flag handlers that strictly parse the link, validate and allow-list the action and parameters, and confirm sensitive operations — that is correct handling of an untrusted entry point."
  - "Navigation restricted to an allow-list of internal routes (not arbitrary screens/URLs) is safe — only unvalidated action/target selection is the finding."
  - "Verified App Links / Universal Links (domain-verified) for sensitive flows are the correct, non-spoofable choice — do not flag them."
  - "Non-sensitive deep links (open a public screen) with validated params are fine — severity scales with the sensitivity of what the link can reach."
  - "Cross-reference the platform-specific playbooks (android.exported_components, ios.url_scheme, desktop.deep_link_hijacking) — report the shared handler-validation gap here without double-counting the platform config issue."
---

## Root Cause Explanation

A deep link is an entry point into the app that originates *outside* the app's own UI:
any other app or any web page the user visits can open `myapp://...` (or an App/
Universal Link) with parameters the attacker chose. So the deep-link handler receives
untrusted input, and the recurring failure is forgetting that — treating link
parameters as if the app itself supplied them. When those parameters drive a sensitive
action (completing authentication, a purchase, a settings change, data deletion or
sharing) with no validation or confirmation, a crafted link becomes a one-click (or
zero-click) trigger for that action. When they drive WebView navigation or an outbound
request, they become open redirect, attacker-content loading, or SSRF. When they select
an internal screen/action without an allow-list, they reach unintended functionality.

This playbook is the cross-platform core; the platform specifics — Android exported
components and App Links, iOS URL schemes vs. Universal Links, desktop custom-protocol
handling — are covered in their own playbooks. The shared controls: prefer
**domain-verified** App/Universal Links over unverified schemes for anything sensitive;
**strictly parse and allow-list** every parameter and action; never pass link data to a
WebView/request/command sink unchecked; and **require confirmation** for sensitive
operations a link can trigger.

## Vulnerable Patterns

```js
// Unvalidated action selection + sensitive action from link params
Linking.addEventListener('url', ({ url }) => {
  const p = new URL(url).searchParams;
  navigation.navigate(p.get('screen'));            // no allow-list
  if (p.get('action') === 'applyCredit') applyCredit(p.get('amount'));  // no confirmation
});

// WebView / request to a link-supplied URL
webview.loadUrl(new URL(url).searchParams.get('next'));   // open redirect / attacker content
```

Correct: verified links, allow-list, validate, confirm.

```js
Linking.addEventListener('url', ({ url }) => {
  const p = new URL(url).searchParams;
  const screen = ALLOWED_SCREENS[p.get('screen') ?? ''];   // allow-list
  if (screen) navigation.navigate(screen);
  // sensitive actions require an in-app confirmation step
});
```

## Data Flow Tracing Guide

1. Find deep-link handlers (Linking, router deep-link config, uni_links, expo-linking,
   platform open-URL/intent handlers).
2. Trace link parameters into sinks: sensitive actions, WebView navigation / requests,
   internal action/screen selection, UI reflection.
3. Check validation, allow-listing, and confirmation on sensitive operations.
4. For sensitive flows, check whether a verified App/Universal Link is used vs. an
   unverified scheme, and whether domain verification (assetlinks.json / AASA) is
   configured.
5. Cross-reference the platform playbooks for config specifics.

## Evidence Checklist

- [ ] The deep-link handler and the sink link params reach, quoted.
- [ ] Validation / allow-listing / confirmation present or absent.
- [ ] For sensitive flows, verified link vs. unverified scheme.
- [ ] A concrete malicious link and its effect.

## Attack Scenario Template

> A web page the victim visits (or a malicious app) opens [the app's deep link] with
> attacker-controlled parameters. Because [file:line] [performs a sensitive action /
> navigates a WebView / selects an action] from the link with no validation or
> confirmation, the link results in [an unauthorized action / open redirect / attacker
> content loaded / reaching unintended functionality].

## Graph Mapping Instructions

- Ensure a `component:deep_link_handler` node with a `depends_on` edge to
  `component:input_validation`.
- Sensitive-action findings add a `depends_on`/`enables` edge to
  `component:authorization` where relevant.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:deep_link_handler`; cross-link to the platform-specific playbook.
