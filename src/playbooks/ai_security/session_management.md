---
id: ai_security.session_management
title: Session Management
category: ai_security
vulnerabilityClass: session_management
appliesToStack: technology-agnostic
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A07:2021 Identification and Authentication Failures"
  - "A05:2021 Security Misconfiguration"
cweRefs:
  - "CWE-384"
  - "CWE-613"
  - "CWE-1004"
  - "CWE-614"
  - "CWE-598"
realWorldReferences:
  - title: "Acronis disclosed on HackerOne: Session Fixation on Acronis"
    url: "https://hackerone.com/reports/1486341"
    type: bug_bounty_disclosure
  - title: "Shopify disclosed on HackerOne: H1-514 Session Fixation on multiple endpoints"
    url: "https://hackerone.com/reports/423136"
    type: bug_bounty_disclosure
  - title: "Gratipay disclosed on HackerOne: Session Fixation at Logout"
    url: "https://hackerone.com/reports/193556"
    type: bug_bounty_disclosure
  - title: "Coinbase disclosed on HackerOne: Cookie missing HttpOnly flag"
    url: "https://hackerone.com/reports/5204"
    type: bug_bounty_disclosure
  - title: "IRCCloud disclosed on HackerOne: \"SESSION\" Cookie without HttpOnly flag"
    url: "https://hackerone.com/reports/7033"
    type: bug_bounty_disclosure
  - title: "OWASP Cheat Sheet Series — Session Management Cheat Sheet"
    url: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
    type: security_blog
  - title: "MITRE CWE-384: Session Fixation"
    url: "https://cwe.mitre.org/data/definitions/384.html"
    type: research_paper
quickModeSummary: >
  This is the general session-cookie playbook, distinct from JWT-specific
  concerns (see ai_security.jwt_authentication). Check: are session cookies
  set with httpOnly, secure, and sameSite flags (framework middleware like
  express-session does NOT default to secure-by-default)? Is the session ID
  regenerated on login/privilege change, or does a pre-auth session ID
  survive into an authenticated session (fixation)? Does logout actually
  destroy the session server-side (session store), or only clear the
  client-side cookie? Does any code path put a session/auth token in a URL
  (query string, redirect target), where it can leak via referrer headers,
  browser history, or server access logs?
fileSelectionHint:
  roles: ["auth", "middleware", "session", "route_handler"]
  matchImports: ["express-session", "cookie-session", "flask-session", "django.contrib.sessions", "iron-session", "connect-redis"]
  matchAuthMapTags: ["session"]
  maxFiles: 8
  priorityOrder: ["session", "auth", "middleware", "route_handler"]
severityHeuristics:
  critical:
    - "Session ID is not regenerated after login/privilege escalation, and a pre-authentication session ID (e.g. one an attacker can set or predict, such as via a session-id-in-URL flow) is accepted as valid post-authentication — classic session fixation, full account takeover."
    - "Session/auth token transmitted in a URL (query string or path) on a flow that also redirects to or embeds third-party content, maximizing referrer-leak exposure of a live, authenticated token."
  high:
    - "Session cookie missing `secure` flag on an application served over HTTPS — cookie can be forced over plaintext HTTP via protocol downgrade/MITM."
    - "Logout only clears the client-side cookie and does not invalidate the session server-side (e.g. no `req.session.destroy()` / store deletion) — a captured cookie remains valid indefinitely after 'logout'."
    - "Session cookie missing `httpOnly` flag on an application that also has any XSS exposure (even low-severity) — turns XSS into session hijacking."
  medium:
    - "Session cookie missing `sameSite` attribute (or set to `None` without `secure`) with no equivalent CSRF-token defense elsewhere in the flow."
    - "No idle/absolute session timeout configured, so a stolen or abandoned session cookie remains valid indefinitely."
  low:
    - "Session ID entropy/generation relies on the framework default without an explicit weak override — only flag if a custom/weak generator is found; do not flag framework defaults as low-entropy without evidence."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:session_management"
  relatedNodeIds: ["component:authentication", "component:jwt", "component:api_security"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:authentication"
    to: "component:session_management"
  - relation: protects
    from: "component:session_management"
    to: "component:api_security"
commonAiCodingMistakes:
  - "AI scaffolds `express-session` (or an equivalent framework session middleware) with only the minimal required options (`secret`, `resave`, `saveUninitialized`) and never sets `cookie: { httpOnly: true, secure: true, sameSite: 'lax' }` — the library does not default these to secure values, so the scaffold ships an insecure cookie unless the developer knows to add them explicitly."
  - "AI implements a login handler that authenticates the user and writes user data into `req.session`, but reuses the session object/ID that existed before login (from the anonymous pre-auth request) instead of calling a session-regeneration step — this is textbook session fixation (CWE-384), and it is easy to miss because the login 'works' correctly in manual testing."
  - "AI implements logout by clearing the cookie client-side (`res.clearCookie(...)`) or removing client state, without also calling the session store's destroy method server-side — the session record remains valid in the store/DB, so a previously-captured cookie value still authenticates after the user believes they've logged out."
  - "AI passes a session or auth token as a URL parameter (e.g. `?session=...` or `/reset?token=...` used as a bearer credential rather than a one-time-use code) for convenience during scaffolding — these values leak via `Referer` headers to any third-party resource loaded on the page, browser history, and server access logs."
  - "AI copies session config from a tutorial/example that sets `secure: false` for local HTTP development and this literal value survives into the production config, because there is no environment-conditional override (`secure: process.env.NODE_ENV === 'production'`) actually wired up."
falsePositiveGuardrails:
  - "Do not flag a missing `secure` cookie flag if the application is genuinely only ever served over plaintext HTTP in its deployed environment (e.g. an internal tool behind a VPN with TLS terminated at a layer outside the reviewed code) — confirm the actual deployment/TLS-termination context before flagging, and note the assumption if it can't be confirmed from the repo alone."
  - "Do not flag JWT-based stateless auth (e.g. `next-auth`, hand-rolled bearer-token auth with no server-side session store) using session-fixation or server-side-invalidation heuristics from this playbook — that failure mode belongs to ai_security.jwt_authentication. This playbook applies to stateful, cookie-backed sessions (session ID + server-side store)."
  - "Do not flag session-ID-not-regenerated as fixation if the framework's session middleware regenerates the ID internally on every request or on privilege change by default (verify the actual library behavior/version, don't assume) — cite the specific login code path where regeneration is absent."
  - "A session token appearing in a URL is not automatically a leak risk if it is a single-use, short-lived token scoped to a non-sensitive action (e.g. an unsubscribe link) — assess whether the token is a live authentication credential (can be replayed to gain a session) before assigning high/critical severity."
---

## Root Cause Explanation

This playbook covers stateful, cookie-backed session security — distinct from
`ai_security.jwt_authentication`, which covers stateless bearer-token
concerns (signature/algorithm verification, claim trust). If the codebase's
"session" is really a JWT held client-side with no server-side session store,
route findings about that token's verification and claims there instead; this
playbook is about the session *cookie* itself and the server-side session
*lifecycle* — issuance, regeneration, and destruction.

The recurring failure modes:

1. **Missing cookie security attributes.** `httpOnly`, `secure`, and
   `sameSite` are not defaults in most session middleware — they must be set
   explicitly. Missing `httpOnly` turns any XSS finding (even a minor one)
   into full session hijacking. Missing `secure` allows the cookie to be sent
   over plaintext HTTP if an attacker can force a downgrade. Missing/loose
   `sameSite` removes a baseline CSRF defense.
2. **Session fixation.** The session identifier issued *before*
   authentication is reused *after* authentication, instead of being
   regenerated. If an attacker can set or predict a victim's pre-auth session
   ID (e.g. by sending them a link containing one, or because the ID is
   accepted from a URL/cookie the attacker controls), and the victim then
   logs in without the ID changing, the attacker's copy of that same ID is
   now a valid authenticated session.
3. **No server-side invalidation on logout.** Logout that only clears the
   cookie client-side leaves the session record alive in the server-side
   store. Any previously-captured copy of that cookie (via XSS, a shared
   device, a proxy log, network capture) remains a valid credential
   indefinitely, defeating the user's expectation that logging out ends
   access.
4. **Session tokens in URLs.** A session or authentication token placed in a
   query string or path segment is exposed through channels the developer
   usually isn't thinking about: the `Referer` header sent to any third-party
   resource the page loads, browser history, server access logs, and any
   proxy/CDN logging layer in between — all of which persist and are
   readable by parties who were never meant to see a live credential.

## Vulnerable Patterns

Look for shapes like these (illustrative, not exhaustive — reason about
equivalents in the actual stack you're reviewing, don't string-match):

```js
// Missing secure cookie attributes — library does not default these on
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  // cookie: { httpOnly: true, secure: true, sameSite: 'lax' }  <- missing entirely
}));

// Session fixation — pre-auth session ID reused after login, never regenerated
app.post('/login', async (req, res) => {
  const user = await authenticate(req.body);
  req.session.userId = user.id; // same session ID as before login
  res.redirect('/dashboard');
});
// Correct: req.session.regenerate(err => { req.session.userId = user.id; ... })

// Logout that never invalidates server-side
app.post('/logout', (req, res) => {
  res.clearCookie('connect.sid'); // client-side only
  res.redirect('/login');
  // req.session.destroy(...) never called — session record still valid in the store
});

// Session/auth token in a URL
app.get('/dashboard', (req, res) => {
  res.redirect(`/api/data?session=${req.session.id}`); // leaks via Referer, logs, history
});
```

## Data Flow Tracing Guide

To evaluate this playbook responsibly, trace the following before writing any
Finding:

1. Find the session middleware configuration (`session_map`/config file where
   the session library is initialized). Read the `cookie` options object
   verbatim — is `httpOnly` present and `true`? Is `secure` present and
   `true` (or conditionally true in production)? Is `sameSite` set?
2. Find every login/authentication success handler. Does it call a
   regeneration step (`req.session.regenerate(...)`, an equivalent
   "rotate session ID" call, or a fresh session object) before writing
   authenticated user data into the session — or does it write into the
   session object that already existed for the pre-auth request?
3. Find every logout handler. Does it call the session store's destroy/delete
   method (server-side), or only clear the cookie on the response
   (client-side)? If a session store (Redis, DB-backed store, etc.) is in
   use, confirm whether the record is actually removed/invalidated there.
4. Search for session/token identifiers appearing in `req.query`, URL
   template strings, `res.redirect` targets, or logging statements — trace
   whether the value used is a live, replayable authentication credential
   (high severity) versus a scoped, single-use, non-sensitive token (lower
   severity).

## Evidence Checklist

Before submitting a Finding for this playbook, confirm:

- [ ] At least one concrete code snippet with an exact file + line range is
      attached as evidence — do not paraphrase, quote the actual line(s).
- [ ] If claiming missing cookie flags: the exact session/cookie
      configuration object is cited, showing the flags that are absent.
- [ ] If claiming session fixation: the login handler is cited, and it is
      confirmed (not assumed) that no regeneration call exists on that path.
- [ ] If claiming missing server-side invalidation on logout: the logout
      handler is cited, and it is confirmed the session store is never
      called to delete/invalidate the record (not just that the cookie is
      cleared).
- [ ] If claiming a session-token-in-URL leak: the exact line constructing
      the URL is cited, and the token's nature (live vs. single-use/scoped)
      is stated.
- [ ] Confirmation the flow in question is a stateful cookie-backed session,
      not a stateless JWT/bearer-token flow that belongs to
      `ai_security.jwt_authentication` instead.

A finding without at least one concrete code-snippet evidence entry must not
be submitted.

## Attack Scenario Template

> An attacker [obtains/sets/predicts] a session identifier via [specific
> mechanism — pre-auth link, XSS given missing httpOnly, captured cookie via
> missing secure flag over HTTP, referrer leak from a URL-embedded token].
> Because [specific code location] does not [missing check — regenerate on
> login / invalidate on logout / restrict cookie transmission], the attacker's
> copy of the session remains valid, resulting in [concrete impact specific
> to this repo, e.g. "persistent access to the victim's account after they
> believe they've logged out" — not a generic description].

Fill every bracket concretely from evidence gathered in this repo. If a
bracket can't be filled from real evidence, the scenario is speculative and
severity must be capped at `medium`, with a note that exploitability is
unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:session_management` node exists (create it on
  the first session-related finding in a scan) with a `depends_on` edge from
  `component:authentication`.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from `component:session_management`.
- If a missing-`httpOnly`-cookie finding co-occurs in the same scan with any
  XSS finding, note the relationship explicitly in both findings' `reasoning`
  fields (missing httpOnly is what turns the XSS into session hijacking) so
  the graph mapper can wire an `enables` edge from the XSS finding node to
  this one.
- If session cookie handling is delegated entirely to a well-known,
  independently-audited library/framework default (and the repo does not
  override its secure defaults), do not create a component-level finding —
  note the delegation in the scan summary instead, per the false-positive
  guardrails above.
