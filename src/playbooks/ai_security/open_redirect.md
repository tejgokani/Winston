---
id: ai_security.open_redirect
title: Open Redirect
category: ai_security
vulnerabilityClass: open_redirect
appliesToStack: technology-agnostic
deepOnly: false
reviewPass: 3
owaspRefs:
  - "A01:2021 Broken Access Control"
cweRefs:
  - "CWE-601"
realWorldReferences:
  - title: "GSA (login.fr.cloud.gov) — Stealing users' OAuth tokens through the redirect_uri parameter (HackerOne #665651)"
    url: "https://hackerone.com/reports/665651"
    type: bug_bounty_disclosure
  - title: "pixiv — Stealing users' OAuth authorization code via redirect_uri (HackerOne #1861974)"
    url: "https://hackerone.com/reports/1861974"
    type: bug_bounty_disclosure
  - title: "cs.money — Open redirect (`https://cs.money///google.com`) chained to OAuth login for full account takeover (HackerOne #905607)"
    url: "https://hackerone.com/reports/905607"
    type: bug_bounty_disclosure
  - title: "Better Auth — Open redirect via scheme-less callbackURL bypassing fully-qualified-URL blocklist (GHSA-8jhw-6pjj-8723)"
    url: "https://github.com/better-auth/better-auth/security/advisories/GHSA-8jhw-6pjj-8723"
    type: vendor_security_advisory
  - title: "Directus — Open redirect on OAuth login endpoint via redirect parameter enabling phishing (GHSA-fr3w-2p22-6w7p)"
    url: "https://github.com/directus/directus/security/advisories/GHSA-fr3w-2p22-6w7p"
    type: vendor_security_advisory
  - title: "OWASP — Unvalidated Redirects and Forwards (Open Redirect)"
    url: "https://owasp.org/www-community/attacks/open_redirect"
    type: security_blog
quickModeSummary: >
  Find every redirect (HTTP 3xx, `Location` header, client-side
  `window.location`/router push driven by a URL param) where the destination
  comes from user-controlled input: a `?url=`/`?next=`/`?returnTo=`/`?redirect_uri=`
  query param, a form field, or an OAuth/SSO `state`/`return_to` value
  round-tripped through an identity provider. Check whether the destination
  is validated against an allowlist of same-origin/known-safe targets before
  the redirect fires, and specifically whether that validation can be
  bypassed by protocol-relative URLs (`//evil.com`), scheme-less URLs,
  backslash tricks (`/\evil.com`), or userinfo/path tricks
  (`https://trusted.com@evil.com`).
fileSelectionHint:
  roles: ["route_handler", "auth", "oauth_handler", "sso_callback", "middleware", "login_controller"]
  matchImports: ["passport", "next-auth", "oauth2", "authlib", "express", "urllib.parse", "URL"]
  matchAuthMapTags: ["oauth", "sso", "redirect"]
  maxFiles: 8
  priorityOrder: ["oauth_handler", "sso_callback", "auth", "route_handler"]
severityHeuristics:
  critical:
    - "Redirect destination is derived from an OAuth/SSO parameter (redirect_uri, state-encoded return_to) that is round-tripped through the identity provider without server-side allowlist validation, enabling authorization-code or access-token theft"
    - "Redirect destination directly forwards user input with no validation at all, and the flow sits immediately after a login/authorization step (post-login redirect, magic-link redirect) so the exposed context includes a live session or token"
  high:
    - "Redirect destination is validated by a same-origin/domain check that is bypassable via protocol-relative URL (`//evil.com`), scheme-less URL, or a permissive `startsWith`/substring check (e.g. `url.startsWith('/')` allows `//evil.com`, or `url.includes('trusted.com')` allows `evil.com?trusted.com`)"
  medium:
    - "Redirect destination is user-controlled and unvalidated but the flow carries no sensitive token/session context (a plain marketing 'continue to' link with no auth material) — genuine phishing risk but not credential/token theft"
  low:
    - "Redirect target is user-controlled but confirmed to only ever be interpolated into a client-side link users must consciously click, with clear destination shown, and no auto-follow — reduced but nonzero risk"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:redirect_handling"
  relatedNodeIds: ["component:authentication", "component:oauth", "component:api_security"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:redirect_handling"
    to: "component:authentication"
  - relation: protects
    from: "component:redirect_handling"
    to: "component:oauth"
commonAiCodingMistakes:
  - "AI implements a same-origin check with `url.startsWith('/')` intending to only allow relative paths, missing that `//evil.com` and `/\\evil.com` are both protocol-relative/browser-normalized absolute URLs that satisfy `startsWith('/')` while leaving the site entirely — this exact bypass class is the root cause of the Better Auth advisory (GHSA-8jhw-6pjj-8723) above."
  - "AI validates the redirect target with `url.includes(allowedDomain)` or a regex without anchoring, which passes attacker URLs like `https://evil.com/trusted.com` or `https://trusted.com.evil.com` that merely contain the allowed domain as a substring."
  - "AI wires the post-login 'return to' URL straight from a query param into a redirect with no validation at all during initial scaffolding (it works in every manual test because the developer only ever tests with legitimate same-site URLs), and the validation step never gets added before shipping."
  - "AI treats the OAuth `redirect_uri` or `state` parameter as opaque/trusted because it's 'part of the OAuth flow', not realizing these are attacker-controlled inputs that must be validated against a server-side allowlist of registered redirect URIs — exactly the pattern behind the GSA and pixiv OAuth-token-theft disclosures above."
  - "AI copies a redirect allowlist check into one auth flow (e.g. standard login) but a structurally identical SSO/magic-link/password-reset flow added later doesn't get the same check, because it doesn't look like 'the same code' at a glance even though it has the same vulnerability shape."
  - "AI decodes a URL once for validation but the runtime/browser decodes it again downstream (double-encoding bypass), or validates before following an additional client-side redirect chain that re-reads the original unvalidated param."
falsePositiveGuardrails:
  - "Do not flag a redirect whose destination is chosen from a small fixed set of server-defined constants (e.g. `redirect(SUCCESS_PAGE)` where `SUCCESS_PAGE` is never influenced by request data) — confirm the destination string actually originates from user input before flagging."
  - "Do not flag a redirect target validated by resolving to a full URL object and checking `.hostname`/`.origin` against an exact allowlist (not a substring/startsWith check) — that is the correct pattern; verify the validation is anchored/exact before concluding it's a false positive versus a bypassable check."
  - "A redirect to a third-party URL that is the entire point of the feature (e.g. an outbound link tracker, an 'external link' warning page) is not automatically a vulnerability — the concern is specifically unauthenticated/unvalidated redirects that occur in or immediately after an authentication/authorization flow, or that could be mistaken by a user for staying on the trusted site. State which of these applies before flagging."
  - "Client-side-only redirects gated behind a user click with the destination domain visibly displayed are lower severity than silent, automatic server-side 3xx redirects — don't apply the same severity heuristics to both without noting the distinction in the finding."
  - "If the codebase uses a well-known auth library (next-auth, Passport, authlib) for the OAuth/SSO flow itself, check whether the library enforces `redirect_uri` allowlisting internally before flagging the library's own callback handling — focus the review on any custom post-authentication redirect logic layered on top by the application."
---

## Root Cause Explanation

Open redirect is a validation gap at a single point: the app takes a
destination URL from user-controlled input and hands it to a redirect
mechanism (`Location` header, `res.redirect()`, `window.location = ...`,
router navigation) without confirming the destination is one the app
actually intends to send users to. On its own this looks low-severity — "so
what, the user clicks a link and ends up somewhere else" — which is exactly
why it gets under-prioritized in both human and AI-assisted review. But two
things make it a serious primitive in practice:

1. **Phishing with a trusted domain in the address bar.** A link to
   `https://real-app.com/redirect?url=evil.com` shows the real, trusted
   domain right up until the bounce. Users (and automated link scanners) that
   check the domain before clicking are defeated by design.
2. **OAuth/SSO token and code theft.** When the vulnerable redirect sits
   inside or immediately after an OAuth/SSO flow — a `redirect_uri`,
   a `return_to`/`state`-encoded path used after the identity provider
   redirects back — the attacker doesn't need the user to notice anything
   wrong. The identity provider itself performs the redirect carrying a live
   authorization code or access token, straight to the attacker's endpoint,
   as documented in the GSA, pixiv, and cs.money disclosures cited above.
   This turns a "low severity" bug into full account takeover.

The most common implementation failure is a same-origin check with the wrong
shape: `startsWith('/')`, `includes(trustedDomain)`, or a regex that isn't
anchored to the start/end of the hostname. Browsers normalize
protocol-relative (`//evil.com`) and backslash (`/\evil.com`) forms into
absolute URLs pointing off-site, so any check written against the raw string
rather than a parsed URL's `hostname`/`origin` is a likely bypass — this is
precisely the class of bug fixed in the Better Auth advisory referenced
above.

## Vulnerable Patterns

```js
// Naive: attacker fully controls destination
app.get('/redirect', (req, res) => {
  res.redirect(req.query.url); // ?url=https://evil.com
});
```

```js
// Looks validated, isn't: startsWith('/') admits protocol-relative URLs
function isSafeRedirect(url) {
  return url.startsWith('/'); // '//evil.com' and '/\\evil.com' both pass
}
```

```js
// Substring check bypassed by domain that merely contains the allowed one
function isSafeRedirect(url) {
  return url.includes('myapp.com'); // 'https://myapp.com.evil.com' passes
}
```

```
# OAuth callback trusting redirect_uri/state without allowlist validation
GET /oauth/callback?code=AUTH_CODE&state=<attacker-controlled-return_to>
-> server redirects to state's return_to carrying the auth code
```

Correct shape parses to a URL object and compares the *parsed* origin/host,
not the raw string, against an exact allowlist:

```js
function isSafeRedirect(target, allowedOrigin) {
  try {
    const url = new URL(target, allowedOrigin); // resolves relative safely
    return url.origin === allowedOrigin;
  } catch {
    return false;
  }
}
```

## Data Flow Tracing Guide

1. Find every redirect call site: server-side (`res.redirect`,
   `Response.redirect`, framework-specific `redirect()` helpers, manual
   `Location` header sets) and client-side (`window.location`,
   `window.location.href =`, router `.push`/`.replace` fed by a URL param
   read from `location.search`).
2. For each, trace the destination argument back to its source. Is it a
   hardcoded/constant string, a value looked up from a server-side allowlist
   by key, or does it flow — directly or through one or more
   functions/components — from `req.query`, `req.body`, a header, or a
   URL fragment/param read client-side?
3. If user-controlled, find the validation function (if any) applied before
   the redirect fires. Read it precisely: does it parse the URL into a
   structured object and compare `.hostname`/`.origin` exactly, or does it
   operate on the raw string with `startsWith`/`includes`/regex?
4. If a validation function exists but operates on the raw string, construct
   a concrete bypass payload for the exact check shown (protocol-relative,
   scheme-less, backslash, userinfo-prefix, or double-encoded) and confirm it
   would pass.
5. Determine whether this redirect sits inside or immediately downstream of
   an authentication/authorization flow (OAuth `redirect_uri`, SSO
   `RelayState`, post-login `return_to`, email verification/magic-link
   redirect, password-reset redirect). If so, check whether any token,
   authorization code, or session identifier is present in the URL, a
   fragment, or would be sent via `Referer` header to the attacker-controlled
   destination — this is what elevates severity from phishing to
   account/token compromise.
6. For OAuth-specific flows: is `redirect_uri` validated against a
   server-side allowlist of URIs registered for that OAuth client, or merely
   checked for a matching substring/prefix?

## Evidence Checklist

- [ ] Exact file + line range of the redirect call site is cited.
- [ ] Exact file + line range showing the destination value's user-controlled
      origin is cited (query param, body field, OAuth state/redirect_uri).
- [ ] The validation logic (if any) is quoted verbatim, with an explicit
      statement of whether it operates on a parsed URL object or a raw
      string.
- [ ] If claiming a bypass of an existing check: a concrete payload string
      that passes the shown validation and still redirects off-origin is
      given (e.g. `//evil.com`, `https://trusted.com.evil.com`,
      `/\evil.com`, `https://trusted.com@evil.com`).
- [ ] Whether the redirect occurs within/after an auth flow (elevating
      severity toward token/code theft) or is a standalone navigation
      (phishing-only) is stated explicitly, with the specific token/session
      material at risk named if applicable.

A finding without the redirect sink, the origin of the destination value, and
the validation logic (or explicit absence) quoted must not be submitted.

## Attack Scenario Template

> An attacker sends a victim a link to [specific endpoint] with
> [parameter]=[malicious destination]. Because [specific code location]
> [does not validate the destination / validates it with a check bypassable
> by (payload)], the victim's browser is redirected to
> [attacker-controlled domain]. [If OAuth/SSO-adjacent: this redirect carries
> (authorization code / access token / session identifier) because
> (specific reason, e.g. "the flow completes the OAuth exchange before
> redirecting")], resulting in [concrete impact: attacker obtains a valid
> session for the victim's account / harvests credentials via a phishing
> page that impersonates the trusted domain].

Fill every bracket from evidence gathered in this repo. If it can't be
confirmed whether sensitive material accompanies the redirect, cap severity
at `medium` (phishing risk) rather than assuming token theft.

## Graph Mapping Instructions

- Ensure a `component:redirect_handling` node exists on the first
  open-redirect finding in a scan, with a `depends_on` edge to
  `component:authentication`.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from `component:redirect_handling` to
  the finding node.
- If the finding involves an OAuth/SSO flow, add an `enables` edge from the
  finding node to `component:oauth` (create that node if it doesn't exist,
  with a `depends_on` edge from `component:authentication`) to make the
  token-theft chain visible in the graph.
- If a finding is caused by another finding already identified in this scan
  (e.g. a missing origin-allowlist configuration finding is the root cause
  behind multiple redirect endpoints being individually vulnerable), state
  that explicitly in the finding's `reasoning` field so the graph mapper
  wires a `causes` edge between them instead of treating them as unrelated
  duplicates.
