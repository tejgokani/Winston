---
id: technology.nextjs.auth_and_middleware
title: Next.js Middleware Route Protection Bypass
category: technology
vulnerabilityClass: broken_access_control
appliesToStack: nextjs
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A01:2021 Broken Access Control"
cweRefs:
  - "CWE-863"
  - "CWE-284"
  - "CWE-346"
realWorldReferences:
  - title: "Authorization Bypass in Next.js Middleware (GHSA-f82v-jwr5-mffw / CVE-2025-29927)"
    url: "https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw"
    type: vendor_security_advisory
  - title: "Postmortem on Next.js Middleware bypass"
    url: "https://vercel.com/blog/postmortem-on-next-js-middleware-bypass"
    type: incident_postmortem
  - title: "Understanding CVE-2025-29927: The Next.js Middleware Authorization Bypass Vulnerability"
    url: "https://securitylabs.datadoghq.com/articles/nextjs-middleware-auth-bypass/"
    type: security_blog
  - title: "CVE-2025-29927: Next.js Middleware Authorization Bypass - Technical Analysis"
    url: "https://projectdiscovery.io/blog/nextjs-middleware-authorization-bypass"
    type: security_blog
  - title: "Next.js middleware bypasses: how to tell if you were affected"
    url: "https://blog.arcjet.com/next-js-middleware-bypasses-how-to-tell-if-you-were-affected/"
    type: security_blog
  - title: "Clerk: Next.js CVE-2025-29927"
    url: "https://clerk.com/blog/cve-2025-29927"
    type: vendor_security_advisory
quickModeSummary: >
  Check whether route protection lives only in middleware.ts. If so: (1) is
  Next.js pinned to a version patched against CVE-2025-29927
  (>=15.2.3/14.2.25/13.5.9/12.3.5), and if self-hosted (not Vercel/Netlify),
  is the x-middleware-subrequest header stripped at the edge/proxy? (2) does
  the middleware `matcher` config actually cover every sensitive path, or
  does a negative-lookahead/exclusion pattern unintentionally let a protected
  route slip through? (3) is there ANY per-route/server-side re-check, or is
  middleware the sole enforcement point for auth/authz?
fileSelectionHint:
  roles: ["middleware", "auth", "route_handler", "config"]
  matchImports: ["next/server", "next-auth/middleware", "@clerk/nextjs/server", "next/navigation"]
  matchAuthMapTags: ["nextjs_middleware"]
  maxFiles: 8
  priorityOrder: ["middleware", "config", "route_handler", "auth"]
severityHeuristics:
  critical:
    - "Next.js version is unpatched against CVE-2025-29927 (< 12.3.5/13.5.9/14.2.25/15.2.3), self-hosted (not auto-protected by Vercel/Netlify), and middleware is the sole enforcement point for an authenticated/admin area — the x-middleware-subrequest header, or the modern 'middleware:middleware:middleware:middleware:middleware' recursion-depth variant, lets an unauthenticated attacker skip the check entirely."
    - "The middleware `matcher` (or an internal `if (pathname.startsWith(...))` early-return) excludes a path pattern that actually contains a sensitive route, e.g. matcher excludes `/api` broadly but a sensitive mutation lives under `/api/admin`."
  high:
    - "Middleware performs the ONLY auth/authz check for a set of routes with no server-side re-verification in the page/layout/route handler itself (defense-in-depth gap — a single misconfiguration or future Next.js bug fully disables protection)."
    - "Middleware checks authentication (is there a session?) but not authorization (does this session's role/tenant permit this specific route?), while the route itself performs no additional per-resource check."
  medium:
    - "Matcher config uses a broad catch-all (`matcher: '/((?!_next/static|_next/image|favicon.ico).*)'`) making it hard to verify which routes are actually covered — increases risk of silent gaps as new routes are added."
  low:
    - "Middleware redirects unauthenticated users client-side (e.g. via a flag checked in a client component) rather than returning a server-side redirect/403, allowing a flash of protected content or a race an attacker could script around."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:nextjs_middleware"
  relatedNodeIds: ["component:authentication", "component:authorization", "component:route_protection"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:route_protection"
    to: "component:nextjs_middleware"
  - relation: protects
    from: "component:nextjs_middleware"
    to: "component:api_security"
commonAiCodingMistakes:
  - "AI scaffolds a single middleware.ts as 'the' auth layer for the whole app because it's the idiomatic Next.js pattern shown in tutorials, and never adds a second, server-side check inside the protected route/layout/server action — so the app has exactly one point of failure, which is precisely the assumption CVE-2025-29927 broke industry-wide."
  - "AI writes a matcher config using a negative-lookahead pattern (`/((?!_next|api/public).*)`), gets the regex subtly wrong (e.g. forgets a leading path or a trailing route added later), and the exclusion silently swallows a route that should have been protected — this drifts further as new routes are added without matcher being revisited."
  - "AI copies a Next.js version pin from an older tutorial/template (pre-2025) into a new project, leaving it vulnerable to CVE-2025-29927 by default with no awareness the version matters for security, not just features."
  - "AI treats `middleware.ts` returning `NextResponse.next()` vs a redirect as equivalent to 'authorization happened,' without distinguishing an authentication check (is there a session) from an authorization check (is this session allowed to do X to resource Y) — most gaps show up in the latter, one layer AI-generated middleware rarely attempts."
falsePositiveGuardrails:
  - "If the app is exclusively deployed on Vercel or Netlify, the CVE-2025-29927 header-spoofing bypass itself is auto-mitigated at the platform layer per the vendor advisory — do not raise it as a live finding for that deployment target, but DO still flag reliance on middleware as the sole enforcement layer as a defense-in-depth gap, since a future/different bypass class is not ruled out."
  - "A middleware matcher that excludes purely static/public assets (`_next/static`, `favicon.ico`, public marketing pages) is correct behavior, not a finding — only flag exclusions that plausibly cover an authenticated or sensitive path."
  - "Do not flag every use of middleware for auth as a critical finding by default — severity depends on whether a second, server-side check exists downstream (route handler, layout, Server Action, or data-access layer). Trace this before assigning severity; middleware + redundant server-side check is a low/informational note at most."
---

## Root Cause Explanation

Next.js `middleware.ts` runs before a request reaches a route, which makes it
an attractive single place to bolt on "authentication." Two related but
distinct failure modes recur:

1. **Middleware as sole enforcement point (architectural).** Next.js's own
   documentation historically presented middleware as sufficient for route
   protection. In March 2025, CVE-2025-29927 (GHSA-f82v-jwr5-mffw, CVSS 9.1)
   showed why that's fragile: an internal header, `x-middleware-subrequest`,
   used by Next.js itself to prevent middleware from recursively invoking
   itself, could be spoofed by an external attacker. Setting it to the right
   value (a colon-joined repetition of the word `middleware`, or
   `src/middleware`, depending on version/layout) tricked the framework into
   believing the middleware had already run, and it skipped execution
   entirely — silently forwarding the request to the protected route with
   zero auth/authz checks applied. Any app that treated middleware as the
   *entire* access-control layer was fully bypassable, unauthenticated, with
   a single crafted header. Vercel and Netlify deployments were automatically
   protected (their edge layer strips/validates the header); self-hosted
   deployments were not, unless patched or the header was stripped upstream.
2. **Matcher / path-exclusion misconfiguration (per-repo bug).** Even with a
   patched framework, middleware only runs on paths matched by its `matcher`
   config (or an internal path check at the top of the middleware function).
   A `matcher` regex/glob that's slightly wrong — an exclusion pattern that's
   broader than intended, a route added after the matcher was written and
   never added to it, or an early `return NextResponse.next()` for a path
   prefix that turns out to also contain a sensitive sub-route — creates a
   silent, repo-specific bypass with the exact same impact as the CVE, just
   without a spoofed header.

Both failure modes share the same underlying lesson the Vercel postmortem
draws explicitly: **middleware should supplement authorization, not replace
it.** Route/controller-level checks are what keeps an app safe when the
middleware layer is bypassed, misconfigured, or simply forgotten for a new
route.

## Vulnerable Patterns

```ts
// middleware.ts — sole enforcement point, no redundant server-side check
export function middleware(request: NextRequest) {
  const session = getSessionFromCookie(request);
  if (!session && request.nextUrl.pathname.startsWith('/dashboard')) {
    return NextResponse.redirect(new URL('/login', request.url));
  }
  return NextResponse.next();
}
// ...and nowhere else in app/dashboard/**/page.tsx or its server actions is
// the session re-verified. If middleware is skipped for any reason
// (spoofed header on an unpatched/self-hosted Next.js, matcher bug, future
// framework bug), every page under /dashboard is fully open.

// matcher config that looks protective but has a gap
export const config = {
  matcher: ['/dashboard/:path*'],
};
// New route /admin/users is added later. It is NOT under /dashboard, so
// this matcher never runs on it — silent, unreviewed bypass.

// authentication-only check, no authorization
export function middleware(request: NextRequest) {
  const session = getSessionFromCookie(request);
  if (!session) return NextResponse.redirect(new URL('/login', request.url));
  // any authenticated user, regardless of role/tenant, passes — the route
  // itself must still check role/ownership, and often doesn't.
  return NextResponse.next();
}
```

## Data Flow Tracing Guide

1. Locate `middleware.ts`/`middleware.js` at the project root (or `src/`).
   Read its `matcher` export (or the internal path-prefix checks) and
   enumerate exactly which paths it runs on.
2. Cross-reference that path list against `route_map`: for every route that
   handles sensitive data or state changes, confirm it is actually matched.
   Flag any sensitive route that a matcher exclusion or narrow inclusion
   pattern would skip.
3. Check the Next.js version pinned in `package.json` against the patched
   ranges for CVE-2025-29927 (>=12.3.5, >=13.5.9, >=14.2.25, >=15.2.3). If
   below the patched range, check the deployment target: is it Vercel or
   Netlify (auto-mitigated) or self-hosted/other (needs the
   `x-middleware-subrequest` header stripped upstream or the framework
   patched)?
4. For each route middleware is relied on to protect, check the route
   handler / Server Component / layout / Server Action itself: is there an
   independent, server-side re-verification of session AND
   role/ownership — or does the route trust that "if I was reached, I must
   be authorized"? A route with zero independent checks depends entirely on
   middleware never being bypassed.
5. Distinguish authentication ("is there a valid session") from
   authorization ("is this session allowed to do this specific thing to this
   specific resource"). Middleware commonly does the former only; trace
   whether the latter happens anywhere.

## Evidence Checklist

- [ ] The exact `middleware.ts` matcher/path-check logic is quoted, with file
      and line range.
- [ ] The specific sensitive route(s) it does or does not cover are named
      concretely (not "some routes may be missed").
- [ ] The Next.js version from `package.json` is cited, plus whether it falls
      inside the CVE-2025-29927 vulnerable range, plus the deployment target
      (Vercel/Netlify vs self-hosted) that determines real exploitability.
- [ ] If claiming "middleware is the sole enforcement point," the specific
      route handler/Server Component/Server Action file is cited showing the
      absence of a redundant server-side check — not just its absence
      inferred without reading the file.
- [ ] Confirmation this isn't a matcher exclusion for genuinely public/static
      content before flagging it as a bypass.

## Attack Scenario Template

> [If self-hosted + unpatched] An unauthenticated attacker sends a request to
> [specific protected path] with header `x-middleware-subrequest:
> middleware:middleware:middleware:middleware:middleware`, causing Next.js
> to skip middleware execution entirely (CVE-2025-29927). Because
> [route/handler file] performs no independent server-side authorization
> check, the request reaches [specific action/data], resulting in
> [concrete impact — e.g. "unauthenticated read of another tenant's
> dashboard data"].
>
> [If matcher-gap, framework-version-independent] A route at [specific path]
> is not covered by the middleware `matcher` at [file:line] because
> [specific exclusion/pattern reason]. An attacker who simply requests that
> path directly bypasses the auth check that visually appears to protect
> the surrounding route tree, reaching [specific action/data].

Fill every bracket from concrete evidence. If the deployment target can't be
confirmed, note that Vercel/Netlify auto-mitigation may apply and cap
severity accordingly rather than asserting unauthenticated RCE-equivalent
impact.

## Graph Mapping Instructions

- Ensure a `component:nextjs_middleware` node exists on first
  middleware-related finding, with a `depends_on` edge from
  `component:route_protection`.
- Each concrete gap (matcher exclusion, unpatched CVE-2025-29927 exposure,
  sole-enforcement-point architecture) becomes its own `finding:<uuid>`
  vulnerability node with a `causes` edge from `component:nextjs_middleware`.
- If a finding traces to a specific downstream route/handler lacking its own
  check, add an `enables` edge from the finding node to that route's node
  (e.g. `route:/dashboard/admin`) to make the blast radius explicit in the
  graph.
- If both a middleware gap AND a missing per-route check are found together,
  note the causal relationship explicitly in the finding's `reasoning` field
  (the middleware gap is the trigger; the missing route-level check is why
  the trigger has unauthenticated impact) so the graph mapper wires a
  `causes` edge between the two findings rather than treating them as
  unrelated.
