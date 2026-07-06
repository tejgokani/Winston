---
id: ai_security.csrf
title: Cross-Site Request Forgery (CSRF)
category: ai_security
vulnerabilityClass: csrf
appliesToStack: cookie/session-authenticated web applications
requiresAnyTag:
  - frontend
  - templating
  - nextjs
  - nuxt
  - sveltekit
  - remix
  - astro
  - django
  - flask
  - rails
  - laravel
  - php
  - java
  - dotnet
  - express
  - fastify
  - nestjs
deepOnly: false
reviewPass: 2
owaspRefs:
  - "A01:2021 Broken Access Control"
  - "A05:2021 Security Misconfiguration"
cweRefs:
  - "CWE-352"
realWorldReferences:
  - title: "OWASP — Cross-Site Request Forgery Prevention Cheat Sheet (synchronizer token, double-submit, SameSite)"
    url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
    type: security_blog
  - title: "django-rest-framework SessionAuthentication CSRF exemption pitfalls and disclosed CSRF bug-bounty reports"
    url: "https://hackerone.com/reports/44146"
    type: bug_bounty_disclosure
  - title: "PortSwigger Web Security Academy — CSRF, SameSite bypasses, and when tokens are still required"
    url: "https://portswigger.net/web-security/csrf"
    type: security_blog
  - title: "MDN — SameSite cookies (Lax/Strict/None) and their role and limits in CSRF defense"
    url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"
    type: security_blog
quickModeSummary: >
  CSRF applies when the application authenticates requests using something the
  browser attaches automatically — session cookies (or HTTP Basic) — because a
  malicious site can then cause the victim's browser to send authenticated
  state-changing requests. Check that every state-changing endpoint (POST/PUT/
  PATCH/DELETE, or GET that mutates) on a cookie/session-authenticated app is
  protected by an anti-CSRF measure: a synchronizer/double-submit token
  validated server-side, and/or SameSite=Lax|Strict on the session cookie plus
  origin/referer checks. Flag framework CSRF protection that has been globally
  disabled (`csrf: false`, `@csrf_exempt`, `csrfProtection` removed), cookies
  set with SameSite=None without a token, and state-changing actions exposed
  over GET. Note the important exception: a pure API authenticated ONLY by a
  bearer token/Authorization header (no cookies) is not CSRF-susceptible —
  don't flag those.
fileSelectionHint:
  roles: ["route_handler", "controller", "middleware", "config", "form", "view"]
  matchImports: ["csurf", "csrf", "@fastify/csrf-protection", "django.middleware.csrf", "flask_wtf", "express-session"]
  matchAuthMapTags: ["session", "cookie"]
  maxFiles: 12
  priorityOrder: ["config", "middleware", "route_handler", "controller"]
severityHeuristics:
  critical:
    - "A cookie/session-authenticated, state-changing endpoint that performs a sensitive action (change email/password, transfer funds, change roles/permissions, delete account, admin operations) has no CSRF protection (no token validated AND cookie is not SameSite-restricted), so a malicious page can trigger it in the victim's authenticated session"
  high:
    - "Framework CSRF protection is globally disabled or broadly exempted (csrf disabled, @csrf_exempt on state-changing views, middleware removed) on a cookie-authenticated app, leaving state-changing endpoints unprotected"
    - "The session cookie is set with SameSite=None (or SameSite not set on a legacy stack that defaults to None) with no synchronizer/double-submit token, exposing state-changing requests to cross-site forgery"
  medium:
    - "State-changing operations are reachable via GET (so a simple <img>/link triggers them) on a cookie-authenticated app, or CSRF tokens exist but aren't validated on some state-changing routes (inconsistent coverage)"
    - "Reliance on SameSite=Lax alone as the sole defense for top-level-navigation-triggerable state changes (Lax still permits top-level GET navigations), without a token for sensitive actions"
  low:
    - "A non-sensitive state change lacks explicit CSRF defense but is low-impact, or CSRF token rotation/scoping is weaker than ideal though present — confirm impact before flagging higher"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:csrf_protection"
  relatedNodeIds: ["component:authentication", "component:api_layer"]
graphEdgeMapping:
  - relation: protects
    from: "component:csrf_protection"
    to: "component:api_layer"
  - relation: depends_on
    from: "component:csrf_protection"
    to: "component:authentication"
commonAiCodingMistakes:
  - "AI disables the framework's built-in CSRF protection to 'fix' a 403/failing request during development (`app.config['WTF_CSRF_ENABLED'] = False`, `@csrf_exempt`, removing `csurf`, Rails `skip_before_action :verify_authenticity_token`) and never re-enables it, leaving all cookie-authenticated state-changing endpoints forgeable."
  - "AI builds a cookie/session-authenticated app and simply never adds CSRF protection, because the happy path works without it — the vulnerability only manifests from a cross-origin attacker page, which no functional test exercises."
  - "AI sets the session cookie `SameSite=None` (often while enabling cross-site embedding or a third-party context) without adding a CSRF token, removing the browser-level defense with nothing replacing it."
  - "AI exposes a state-changing action over GET (a `/delete?id=`, `/logout`, `/transfer?to=`) so it can be triggered by a link/image, which is inherently CSRF-triggerable and also bypasses many token schemes tied to POST bodies."
  - "AI adds CSRF tokens to some forms/routes but not to a newly added state-changing endpoint (an API route beside the protected ones), producing inconsistent coverage."
  - "AI over-applies CSRF protection to a pure bearer-token API (no cookies), or conversely assumes 'it's an API so CSRF doesn't apply' while the API actually authenticates via session cookies — the deciding factor is whether auth rides on an automatically-attached credential, not whether it's called an API."
falsePositiveGuardrails:
  - "Do not flag CSRF on an endpoint whose authentication is SOLELY a bearer token / Authorization header / custom header that the browser does NOT attach automatically and that a cross-site page cannot set on a cross-origin request — such endpoints are not CSRF-susceptible. Confirm the app does not ALSO accept a session cookie for the same endpoint."
  - "An endpoint protected by a synchronizer or double-submit CSRF token that is validated server-side is correct — confirm the token is actually checked (not just issued) on the state-changing route before concluding it's unprotected."
  - "SameSite=Strict (or Lax for non-navigation-triggerable actions) on the session cookie provides real CSRF defense for the covered cases — assess whether the specific action is reachable via a method SameSite still permits before flagging, rather than treating SameSite as worthless."
  - "GET endpoints that are genuinely safe/idempotent (read-only) do not need CSRF protection — only state-changing GETs are the finding."
  - "Framework CSRF that is enabled by default and not disabled (Django/Rails/Laravel enable it globally) means individual forms/routes are covered unless explicitly exempted — do not flag missing tokens when the global protection is active and the route isn't exempted."
---

## Root Cause Explanation

CSRF is a consequence of how browsers handle ambient credentials. When an
application authenticates a request using something the browser attaches
*automatically* — a session cookie, HTTP Basic auth — then any web page the
victim visits can cause the victim's browser to send an authenticated request
to that application, because the browser includes the cookie regardless of
which site initiated the request. The attacker never sees the response; they
don't need to. If the request *changes state* (transfers money, changes the
account email, grants a role), causing it to fire is the whole attack.

This is why the deciding question is never "is it an API?" but "does
authentication ride on an automatically-attached credential?" A session-cookie
app is CSRF-susceptible; a pure bearer-token API (where the client must
explicitly set an `Authorization` header a cross-site page cannot forge) is
not. AI-generated code gets this wrong in both directions: it builds
cookie-session apps with no CSRF defense (the happy path works, and only a
cross-origin attacker page reveals the gap, which no functional test
simulates), and it sometimes bolts CSRF tokens onto bearer-token APIs where
they add nothing.

The defenses are a synchronizer or double-submit token that the server
validates on every state-changing request (a value a cross-site page cannot
read or guess), reinforced by `SameSite=Lax|Strict` cookies and origin/referer
checks. The recurring failures are: framework CSRF protection globally
disabled to silence a 403 during development and never restored;
`SameSite=None` set for cross-site embedding with no token to replace the lost
browser defense; and state-changing actions exposed over GET, which are
trivially triggerable and slip past body-bound token schemes.

## Vulnerable Patterns

```python
# Framework CSRF disabled / exempted on a cookie-auth app
@csrf_exempt
def change_email(request):        # state change, forgeable
    request.user.email = request.POST["email"]; request.user.save()
```

```js
// Cookie-session app with no CSRF protection and SameSite=None
app.use(session({ cookie: { sameSite: "none", secure: true } }));
app.post("/account/email", requireLogin, (req, res) => { /* no token check */ });
```

```
GET /account/delete?confirm=1     # state change over GET → <img src> triggers it
```

Correct shapes validate a token and restrict the cookie:

```js
app.use(session({ cookie: { sameSite: "lax", secure: true } }));
app.use(csrfProtection);                          // token issued + validated
app.post("/account/email", requireLogin, (req, res) => { /* token verified by middleware */ });
```

## Data Flow Tracing Guide

1. Determine the authentication mechanism for each state-changing endpoint.
   If auth is solely a bearer/custom header the browser doesn't auto-attach,
   CSRF does not apply — stop. If a session cookie (or Basic) authenticates
   it, continue.
2. For each cookie-authenticated state-changing endpoint (POST/PUT/PATCH/
   DELETE, and any mutating GET), check for a CSRF token that is *validated*
   server-side (not merely rendered into the form).
3. Check the session cookie's SameSite attribute and whether it's set at all.
4. Look for globally disabled/exempted framework CSRF protection.
5. Look for state-changing operations reachable via GET.
6. Weight severity by the sensitivity of the action (funds/roles/credentials
   = critical).

## Evidence Checklist

- [ ] The endpoint, its HTTP method, and the state change it performs.
- [ ] The authentication mechanism (cookie/session vs. bearer header),
      established from code, to justify that CSRF applies.
- [ ] The CSRF defense present or absent (token validation, SameSite,
      exemption/disable), quoted.
- [ ] For disabled protection: the exact disable/exempt directive.

A finding must establish that the endpoint is cookie/session-authenticated
(or otherwise ambient-credential-authenticated) before asserting CSRF.

## Attack Scenario Template

> The victim, logged into [app] with a session cookie, visits an attacker's
> page. That page auto-submits [method] [endpoint] (via a hidden form / an
> <img> for a GET). Because [file:line] [has no CSRF token validation / has
> CSRF protection disabled/exempted / sets SameSite=None with no token / the
> action is a state-changing GET], the victim's browser sends the request
> with the session cookie attached and the server performs [sensitive state
> change] as the victim, resulting in [impact].

## Graph Mapping Instructions

- Ensure a `component:csrf_protection` node exists, with a `protects` edge to
  `component:api_layer` and a `depends_on` edge to
  `component:authentication`.
- Each unprotected state-changing endpoint is a `finding:<uuid>` vulnerability
  node with a `causes` edge from `component:csrf_protection` (the missing/
  disabled defense is the root cause).
- If one root cause (globally disabled CSRF middleware) leaves many endpoints
  exposed, state it in `reasoning` so the mapper links them rather than
  duplicating.
