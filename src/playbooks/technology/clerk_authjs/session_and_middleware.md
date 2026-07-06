---
id: technology.clerk_authjs.session_and_middleware
title: Clerk / Auth.js / better-auth Session and Middleware Misconfiguration
category: technology
vulnerabilityClass: broken_authentication
appliesToStack: clerk, next-auth, better-auth
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A07:2021 Identification and Authentication Failures"
  - "A01:2021 Broken Access Control"
cweRefs:
  - "CWE-287"
  - "CWE-863"
  - "CWE-613"
realWorldReferences:
  - title: "Brief Summary: CVE-2026-41248 Clerk JavaScript SDK Middleware Route Protection Bypass (CVSS 9.1)"
    url: "https://zeropath.com/blog/cve-2026-41248-clerk-middleware-bypass"
    type: security_blog
  - title: "Investigating a major security vulnerability with Clerk's Next.js integration"
    url: "https://pilcrowonpaper.com/blog/clerk-nextjs-vulnerability/"
    type: security_blog
  - title: "Clerk: Next.js CVE-2025-29927"
    url: "https://clerk.com/blog/cve-2025-29927"
    type: vendor_security_advisory
  - title: "Possible user mocking that bypasses basic authentication (NextAuth.js — GHSA-v64w-49xw-qq89)"
    url: "https://github.com/nextauthjs/next-auth/security/advisories/GHSA-v64w-49xw-qq89"
    type: vendor_security_advisory
  - title: "Critical Account Takeover via Unauthenticated API Key Creation in better-auth (CVE-2025-61928)"
    url: "https://github.com/better-auth/better-auth/security/advisories/GHSA-99h5-pjcv-gr6v"
    type: vendor_security_advisory
  - title: "ZeroPath: Breaking Authentication — Unauthenticated API Key Creation in better-auth (CVE-2025-61928)"
    url: "https://zeropath.com/blog/breaking-authentication-unauthenticated-api-key-creation-in-better-auth-cve-2025-61928"
    type: security_blog
quickModeSummary: >
  Identify which library (Clerk, Auth.js/NextAuth, better-auth) is in use,
  then check: (1) is `clerkMiddleware()`/`auth.protect()` (Clerk),
  `withAuth`/middleware `authorized` callback (Auth.js), or the better-auth
  session handler actually wired to every sensitive route, with a matching
  library version patched against known bypass CVEs? (2) is session/claim
  data re-verified server-side before sensitive actions, or is a
  client-passed/cookie-decoded value trusted directly (as in the Clerk
  header/cookie-precedence bug and the better-auth request-body userId
  fallback)? (3) do custom API-key or session-derivation code paths ever
  fall back to trusting attacker-controlled input when no session is
  present?
fileSelectionHint:
  roles: ["auth", "middleware", "session", "route_handler"]
  matchImports: ["@clerk/nextjs", "@clerk/nextjs/server", "next-auth", "@auth/core", "better-auth", "better-auth/next-js"]
  matchAuthMapTags: ["clerk", "next_auth", "better_auth"]
  maxFiles: 8
  priorityOrder: ["middleware", "auth", "route_handler", "session"]
severityHeuristics:
  critical:
    - "Clerk SDK version falls in a known vulnerable range for a middleware route-protection bypass (e.g. CVE-2026-41248-class issue) and `auth.protect()`/`clerkMiddleware()` is the sole enforcement layer for sensitive routes with no server-side re-check."
    - "better-auth API-key (or equivalent) handler derives the acting user from request-body-supplied data (e.g. a `userId` field) whenever no session is present, instead of rejecting the request outright — mirrors CVE-2025-61928's unauthenticated account-takeover pattern."
    - "Auth.js/NextAuth session/JWT verification trusts a value from the wrong source with attacker-influenced precedence (e.g. checking a spoofable header/cookie before validating against the true session store), analogous to the CVE-2024-22206-class header/cookie mismatch."
  high:
    - "Session claims (role, plan, org membership) issued by Clerk/Auth.js/better-auth are trusted directly in a sensitive branch without a server-side re-fetch from the provider/DB — a stale or forged claim bypasses authorization even though the session itself is validly signed."
    - "Library version is pinned below the patched release for a disclosed CVE relevant to this stack (Clerk SDK bypass, NextAuth GHSA-v64w-49xw-qq89, better-auth CVE-2025-61928) with no other mitigating control."
  medium:
    - "Session cookie is configured without `httpOnly`/`secure`/appropriate `sameSite`, or `NEXTAUTH_SECRET`/equivalent signing secret sourced from a weak fallback rather than a required env var."
    - "Middleware-based protection (any of the three libraries) is the only enforcement point for a route tree, with no redundant per-route/server-side check — same defense-in-depth gap as the Next.js middleware playbook, specific to how each library's middleware helper is wired."
  low:
    - "Session/JWT expiry is very long with no revocation mechanism exposed/used, or `useSession`/client-side session state is trusted for a UI-only decision with no bearing on an actual access-control check (informational)."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:session_management"
  relatedNodeIds: ["component:authentication", "component:nextjs_middleware", "component:authorization"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:authentication"
    to: "component:session_management"
  - relation: protects
    from: "component:session_management"
    to: "component:api_security"
commonAiCodingMistakes:
  - "AI wires `clerkMiddleware()` (or the Auth.js/better-auth equivalent) once at the project root and treats that as complete route protection for the app's lifetime, never adding a second server-side check in new routes added later — the same single-point-of-failure pattern that made CVE-2025-29927 and Clerk's own middleware-bypass advisory (CVE-2026-41248-class) high-impact rather than cosmetic."
  - "AI pins whichever version of Clerk/next-auth/better-auth was current in its training data or a copied tutorial, without checking for since-disclosed CVEs (e.g. better-auth < 1.3.26, vulnerable NextAuth ranges) — dependency versions are treated as a functionality choice, not a security-relevant one."
  - "AI implements a custom 'get current user' helper for better-auth/Auth.js that falls back to trusting a request-body or query-param supplied user id 'for convenience during testing,' mirroring exactly the flaw in CVE-2025-61928 — this fallback path is easy to leave in because it works fine in every manual/happy-path test."
  - "AI uses `auth()`/`getServerSession()`/Clerk's `currentUser()` results directly in a sensitive branch (role check, plan check) without re-fetching from the source of truth, trusting the session payload as if it were freshly re-verified on every read."
falsePositiveGuardrails:
  - "Do not flag standard, unmodified use of Clerk's `clerkMiddleware()`/`auth.protect()`, Auth.js's `withAuth`, or better-auth's session middleware as inherently insecure — these libraries handle signature verification and session validation internally; focus the review on (a) version/CVE exposure, (b) whether it's the sole enforcement layer, and (c) how claims are used downstream, not on re-deriving crypto correctness of the library itself."
  - "Before flagging a version as vulnerable, confirm the actual resolved version in the lockfile (not just the package.json range) against the specific patched version for the CVE in question — many ranges (e.g. `^5.0.0`) may already resolve to a patched patch/minor release."
  - "A route with no explicit per-route auth check is not automatically a finding if it demonstrably sits behind a properly configured, version-patched middleware AND the app's threat model accepts middleware as sufficient for that specific low-sensitivity route (e.g. a marketing page behind a soft gate) — reserve high/critical severity for state-changing or data-exposing routes."
---

## Root Cause Explanation

Clerk, Auth.js (NextAuth), and better-auth all solve the same problem —
issuing and verifying a session for a Next.js app — but the failure modes
that show up in AI-assisted code cluster around the same handful of root
causes regardless of which library is chosen:

1. **Middleware treated as the entire access-control layer.** All three
   libraries ship a middleware helper (`clerkMiddleware()`, Auth.js's
   `withAuth`/`authorized` callback, better-auth's session middleware) that
   makes "protect this route" look like one line of config. That
   simplicity is exactly what makes it easy to treat as sufficient on its
   own. It isn't structurally different from the generic Next.js middleware
   risk (see the `technology.nextjs.auth_and_middleware` playbook) — but
   each library also carries library-specific bypass risk on top of the
   framework-level one. A documented example: a Clerk JavaScript SDK
   middleware route-protection bypass (tracked publicly, CVSS 9.1) affected
   the exact mechanism `auth.protect()` relies on to gate routes across
   `@clerk/nextjs`, `@clerk/nuxt`, and `@clerk/astro`. Separately,
   independent security research (pilcrowonpaper's investigation into
   Clerk's Next.js integration) found a mismatch between where the SDK
   looked for the session JWT across middleware vs. endpoint handlers — a
   refactor caused the endpoint handler to check a spoofable cookie before
   the authoritative header, letting an attacker who knew a target's user ID
   impersonate them and escalate role, without ever forging a signature.
2. **Fallback-to-untrusted-input when no session exists.** better-auth's
   CVE-2025-61928 (CVSS 9.3, GHSA-99h5-pjcv-gr6v) is the clearest example:
   the API-key creation/update handlers determined whether auth was required
   by checking for a session *and* whether a `userId` field was present in
   the request body — when no session existed but a `userId` was supplied,
   the handler used the attacker-controlled body value as the acting user
   instead of rejecting the request. This is a "convenience fallback that
   became a backdoor" pattern: reasonable-looking code for a case that
   should never legitimately occur (no session, but we have a user id
   anyway) becomes a full authentication bypass.
3. **Claims trusted without re-verification.** As with hand-rolled JWT (see
   `ai_security.jwt_authentication`), session claims issued by any of these
   libraries can still be used unsafely downstream — trusting `role` or
   `orgId` from a decoded session without re-checking against the current
   source of truth reintroduces the same trust-boundary problem these
   libraries were adopted specifically to avoid.
4. **Stale/unpatched library versions.** NextAuth.js has its own disclosed
   history (e.g. GHSA-v64w-49xw-qq89, "possible user mocking that bypasses
   basic authentication," plus older information-disclosure and open-redirect
   advisories). AI-scaffolded projects frequently pin whatever version
   appeared in training data or a copied tutorial, with no mechanism to
   revisit that pin as CVEs are disclosed later.

## Vulnerable Patterns

```ts
// middleware.ts — Clerk, sole enforcement point, no route-level re-check
export default clerkMiddleware((auth, req) => {
  if (isProtectedRoute(req)) auth().protect();
});
// If nothing inside app/dashboard/**/*.tsx or its Server Actions
// independently re-verifies the session, an SDK-level middleware bypass
// (as in the Clerk CVSS-9.1 route-protection advisory) has zero fallback.

// better-auth style handler — fallback to attacker-controlled input
async function getActingUser(req: Request, body: any) {
  const session = await getSession(req);
  if (session) return session.user;
  if (body.userId) return { id: body.userId }; // CVE-2025-61928 pattern:
  // no session AND a body-supplied id is accepted as if authenticated.
  throw new Error('Unauthorized');
}

// Auth.js — trusting decoded claims without re-fetch
const session = await getServerSession(authOptions);
if (session?.user?.role === 'admin') {
  // role claim baked into the token at sign-in time; if role was revoked
  // since, this branch still executes on the stale claim.
  await performAdminAction();
}

// Version pin exposed to a disclosed CVE
// package.json
"better-auth": "^1.3.20"   // vulnerable range for CVE-2025-61928 (< 1.3.26)
```

## Data Flow Tracing Guide

1. Identify which of the three libraries (or a combination) is in use by
   scanning imports (`@clerk/nextjs`, `next-auth`/`@auth/core`,
   `better-auth`) and locate the middleware/config file(s) wiring it up.
2. Check the resolved version in the lockfile against known disclosed CVEs
   for that library and confirm whether the project is inside or outside the
   vulnerable range.
3. For Clerk/Auth.js: does `clerkMiddleware()`/`withAuth` sit alone as the
   enforcement layer, or is there a redundant server-side check
   (`auth.protect()` again, or `getServerSession`/`currentUser()` call)
   inside the route/Server Action itself?
4. For better-auth or any custom session/user-derivation helper: trace every
   branch of the "get current user" logic. Does any branch return a
   user/session object built from request-supplied data (body, query,
   header) without an accompanying validated session? That's the
   CVE-2025-61928 shape — flag it regardless of whether it's literally
   better-auth's code or a custom equivalent inspired by a similar pattern.
5. Wherever a session's claims (role, org, plan) are read, trace forward to
   where they're used. Is there a re-fetch from the provider/DB before a
   sensitive action, or is the claim trusted as-is?
6. Cross-reference with `technology.nextjs.auth_and_middleware` for the
   framework-level middleware bypass risk (CVE-2025-29927) — the two
   playbooks compound when a library-level middleware bypass and a
   framework-level one are both present and unmitigated.

## Evidence Checklist

- [ ] The exact middleware/config wiring for the auth library in use is
      quoted with file and line range.
- [ ] The resolved (lockfile) version of the library is cited alongside the
      specific CVE/advisory and its patched-version threshold, if a
      version-based finding is claimed.
- [ ] If claiming a fallback-to-untrusted-input authentication bypass: the
      exact branch where request-supplied data is used as if it were a
      validated session is cited, along with confirmation no session check
      guards that branch.
- [ ] If claiming a stale-claim/trust-boundary issue: both the line where
      the claim is read and the line where it's used in a sensitive branch
      are cited.
- [ ] Confirmation of deployment target (Vercel/Netlify auto-mitigation vs.
      self-hosted) when relevant to a framework-level middleware bypass
      compounding this finding.

## Attack Scenario Template

> An attacker [without any session / with a low-privilege session] sends a
> request to [specific endpoint] with [specific attacker-controlled value —
> e.g. a `userId` in the request body, or a spoofed header/cookie]. Because
> [specific file:line] derives the acting-user/authorization decision from
> that value instead of a validated session — matching the pattern in
> [cited CVE] — the request is processed as if it came from
> [impersonated/escalated identity], resulting in [concrete impact specific
> to this repo].

Fill every bracket from evidence gathered in this repo, including the
specific library/version and cited advisory. If a bracket can't be filled
concretely, cap severity at `medium` and note exploitability is unconfirmed.

## Graph Mapping Instructions

- Ensure a `component:session_management` node exists on first finding for
  this playbook, with a `depends_on` edge from `component:authentication`.
- Each concrete finding (middleware-bypass exposure, fallback-to-untrusted
  authentication, stale-claim trust issue, unpatched CVE-exposed version)
  becomes its own `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:session_management`.
- If the finding also implicates framework-level Next.js middleware
  (CVE-2025-29927-class exposure), add a `depends_on` edge from this
  finding's node to the `component:nextjs_middleware` node so the graph
  shows the compounding risk rather than two isolated findings.
- If a finding enables reaching a specific sensitive downstream system
  (billing, admin panel, another tenant's data), add an `enables` edge from
  the finding node to that component's node id.
