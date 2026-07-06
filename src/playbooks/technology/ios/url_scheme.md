---
id: technology.ios.url_scheme
title: "iOS: URL Schemes & Universal Links"
category: technology
vulnerabilityClass: improper_input_handling
appliesToStack: ios
requiresAnyTag: ["ios"]
deepOnly: false
reviewPass: 2
owaspRefs:
  - "OWASP MASVS-PLATFORM"
  - "A01:2021 Broken Access Control"
cweRefs:
  - "CWE-20"
  - "CWE-939"
  - "CWE-441"
realWorldReferences:
  - title: "OWASP MASTG — iOS custom URL schemes and universal links (deep-link input handling)"
    url: "https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0075/"
    type: security_blog
  - title: "Apple — Universal Links vs. custom URL schemes and the scheme-hijacking risk"
    url: "https://developer.apple.com/documentation/xcode/allowing-apps-and-websites-to-link-to-your-content"
    type: vendor_security_advisory
  - title: "URL scheme hijacking — multiple apps registering the same scheme; and deep-link parameters driving sensitive actions"
    url: "https://evanconnelly.github.io/post/ios-url-scheme-hijacking/"
    type: research_paper
quickModeSummary: >
  Custom URL schemes (myapp://) can be invoked by any app or web page with attacker-
  controlled parameters, and — unlike Universal Links — schemes can be HIJACKED
  (another app can register the same scheme to intercept your links, including OAuth
  redirects/tokens). Review openURL/scene handlers: treat the incoming URL as fully
  untrusted. Flag handlers that perform sensitive actions from deep-link params with
  no validation/confirmation (auth completion, purchases, settings, file ops), that
  navigate a WebView to a link-supplied URL, or that reflect link data unsanitized;
  and flag using custom schemes (instead of Universal Links) for sensitive flows
  like OAuth callbacks (hijackable). Prefer Universal Links (domain-verified) for
  sensitive deep links, validate/allow-list every parameter and action, and confirm
  sensitive operations.
fileSelectionHint:
  roles: ["controller", "service", "config", "view"]
  matchImports: ["UIKit", "SwiftUI", "Foundation"]
  matchAuthMapTags: ["ios"]
  maxFiles: 10
  priorityOrder: ["controller", "service", "config", "view"]
severityHeuristics:
  critical:
    - "A sensitive flow (OAuth/auth callback, token exchange) uses a hijackable custom URL scheme, so a malicious app registering the same scheme can intercept the redirect/token (account takeover)"
    - "A deep-link handler performs a privileged/irreversible action or passes link parameters into a dangerous sink (WebView navigation to attacker content, a command/file operation) with no validation"
  high:
    - "Deep-link parameters drive a sensitive action (purchase, settings change, data access) triggered solely by the link with no user confirmation or validation"
    - "Link parameters are used to select actions/targets with no allow-list, or reflected into the app/WebView unsanitized"
  medium:
    - "Deep-link input is partially validated, or a custom scheme is used for a moderately sensitive flow where Universal Links (domain-verified) would be appropriate"
    - "Universal Links are used but the associated-domains / apple-app-site-association validation is misconfigured"
  low:
    - "Universal Links (domain-verified) for sensitive flows, with strict parameter validation, action allow-listing, and confirmation for sensitive operations — the target state; confirm before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:deep_link_handler"
  relatedNodeIds: ["component:input_validation", "component:authentication"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:deep_link_handler"
    to: "component:input_validation"
  - relation: enables
    from: "component:deep_link_handler"
    to: "component:authentication"
commonAiCodingMistakes:
  - "AI uses a custom URL scheme (myapp://oauth-callback) for the OAuth redirect, not realizing another app can register the same scheme and intercept the authorization code/token — account takeover. Sensitive callbacks should use domain-verified Universal Links (or PKCE + a claimed https redirect)."
  - "AI performs a sensitive action directly from deep-link parameters (complete login, make a purchase, change a setting) with no confirmation, so any app/page that opens the link triggers it."
  - "AI navigates a WebView to a URL taken from the deep link, loading attacker content into the app."
  - "AI uses a link parameter to choose an internal action with no allow-list, exposing unintended functionality."
  - "AI trusts the deep-link URL because it's 'their scheme', ignoring that any caller can supply arbitrary parameters."
  - "AI misconfigures the apple-app-site-association / associated-domains so Universal Links silently fall back to the hijackable scheme."
falsePositiveGuardrails:
  - "Do not flag Universal Links (domain-verified via apple-app-site-association) used for sensitive flows with validated parameters — that is the correct, non-hijackable pattern. Confirm associated-domains is configured."
  - "Handlers that strictly parse and allow-list the action/parameters and confirm sensitive operations are correct handling of an untrusted entry point."
  - "A custom scheme used only for non-sensitive navigation (open a specific screen) with validated, allow-listed parameters is acceptable — severity scales with sensitivity and hijackability of the flow."
  - "OAuth using PKCE plus a claimed HTTPS (Universal Link) redirect is the secure mobile pattern — do not flag it as scheme hijacking."
  - "Cross-reference the general deep-link validation and webview playbooks; report the iOS scheme-hijacking/handler angle here."
---

## Root Cause Explanation

iOS offers two deep-link mechanisms with very different security properties. A
**custom URL scheme** (`myapp://`) is just a string any app can claim — so multiple
apps can register the *same* scheme, and iOS's resolution is not guaranteed to favor
yours. That makes schemes **hijackable**: a malicious app can register your scheme
and intercept links meant for you, which is catastrophic for anything carrying
secrets — most notoriously OAuth callbacks, where the intercepted redirect leaks the
authorization code or token, yielding account takeover. **Universal Links**, by
contrast, are tied to a domain you prove you own (via `apple-app-site-association`),
so they can't be hijacked; they are the correct choice for sensitive flows.

Beyond hijacking, every deep-link handler is an untrusted input entry point: any app
or web page can invoke it with arbitrary parameters. So handlers that perform
sensitive or irreversible actions straight from link parameters (completing auth,
purchases, settings changes), navigate a WebView to a link-supplied URL, or select
internal actions without an allow-list let a crafted link drive the app. The
controls: use **Universal Links** (domain-verified) for sensitive deep links and
OAuth (with PKCE); treat every incoming URL as untrusted — strictly parse, validate,
and allow-list parameters and actions; and require confirmation for sensitive
operations a link can trigger.

## Vulnerable Patterns

```swift
// Hijackable custom scheme for OAuth callback — token interception
// Info.plist registers CFBundleURLSchemes: ["myapp"]; redirect_uri = myapp://oauth
func application(_ app: UIApplication, open url: URL, ...) -> Bool {
  completeLogin(token: url.queryParam("token"))          // sensitive action, no validation
}

// Deep link navigates a WebView / selects an action with no allow-list
webView.load(URLRequest(url: URL(string: url.queryParam("next")!)!))
```

Correct: Universal Links + PKCE for sensitive flows; validate + allow-list +
confirm.

```swift
func scene(_ s: UIScene, continue userActivity: NSUserActivity) {   // Universal Link
  guard let url = userActivity.webpageURL, isTrustedHost(url) else { return }
  switch url.pathComponents { /* allow-listed actions, validated params */ }
}
```

## Data Flow Tracing Guide

1. Identify deep-link mechanisms: custom URL schemes (CFBundleURLSchemes) vs.
   Universal Links (associated-domains + apple-app-site-association).
2. For sensitive flows (OAuth, auth, payments), check whether a hijackable custom
   scheme is used instead of a Universal Link (+ PKCE).
3. In open-URL/scene handlers, trace link parameters into sensitive actions,
   WebView navigation, or action selection; check validation/allow-listing/
   confirmation.
4. Check Universal Link configuration (associated-domains, AASA) for misconfig that
   falls back to schemes.
5. Rank: hijackable sensitive flow and unvalidated sensitive action are highest.

## Evidence Checklist

- [ ] The deep-link mechanism (scheme vs. Universal Link), quoted from config.
- [ ] For sensitive flows, whether a hijackable scheme is used.
- [ ] The handler's sink (sensitive action / WebView / action select) and its
      validation.
- [ ] Confirmation on sensitive link-triggered operations.

## Attack Scenario Template

> A malicious app registers the same custom scheme (or a web page opens the link).
> Because [file:line] [uses a hijackable scheme for the OAuth callback / performs a
> sensitive action from link params without validation], the attacker [intercepts
> the auth token / triggers the sensitive action], resulting in [account takeover /
> unauthorized action].

## Graph Mapping Instructions

- Ensure a `component:deep_link_handler` node with a `depends_on` edge to
  `component:input_validation`; OAuth-hijack findings add an `enables` edge to
  `component:authentication` (account-takeover class).
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:deep_link_handler`.
