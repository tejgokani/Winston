---
id: technology.express.middleware_and_routing
title: "Express: Middleware & Routing"
category: technology
vulnerabilityClass: broken_authentication
appliesToStack: express
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A01:2021 Broken Access Control"
cweRefs:
  - "CWE-284"
realWorldReferences:
  - title: "Authorization bypass in express-jwt (CVE-2020-15084 / GHSA-6g6m-m6h5-w9gf)"
    url: "https://github.com/advisories/GHSA-6g6m-m6h5-w9gf"
    type: vendor_security_advisory
  - title: "path-to-regexp ReDoS via unbounded parameter regex (CVE-2024-45296 / GHSA-9wv6-86v2-598j) — affects Express's default router"
    url: "https://github.com/advisories/GHSA-9wv6-86v2-598j"
    type: vendor_security_advisory
  - title: "Unpatched path-to-regexp ReDoS in Express's bundled 0.1.x range (CVE-2024-52798)"
    url: "https://github.com/expressjs/express/issues/6216"
    type: vendor_security_advisory
  - title: "Express.js Production Best Practices: Security — official middleware-ordering and error-handler placement guidance"
    url: "https://expressjs.com/en/advanced/best-practice-security.html"
    type: vendor_security_advisory
  - title: "March 2026 Security Releases — Express.js team's own postmortem-style advisory on the path-to-regexp ReDoS patch rollout across supported branches"
    url: "https://expressjs.com/en/blog/2026-03-30-security-releases/"
    type: incident_postmortem
quickModeSummary: >
  Check that auth/authorization middleware is applied consistently across
  routers (not just some), that middleware order is correct (auth before
  the handler, error-handling middleware last), and that router-level
  `app.use()` mounting doesn't accidentally exclude routes added later in a
  file.
fileSelectionHint:
  roles: ["route_handler", "middleware"]
  matchImports: ["express"]
  matchAuthMapTags: []
  maxFiles: 10
  priorityOrder: ["middleware", "route_handler"]
severityHeuristics:
  critical:
    - "A router or route group meant to be fully protected has one or more routes added after the protecting middleware was wired, bypassing it entirely"
  high:
    - "Middleware order places the auth check after a handler that already performs a side effect (e.g. logging middleware runs fine, but an early route defined before app.use(requireAuth) executes unprotected)"
  medium:
    - "Error-handling middleware is defined before route handlers (Express requires it last), risking unhandled errors leaking stack traces instead of being caught"
  low:
    - "CORS middleware is configured with a permissive origin (`*`) alongside credentialed requests — defense-in-depth gap, confirm before treating as active exposure"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:api_security"
  relatedNodeIds: ["component:authentication", "component:authorization"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:api_security"
    to: "component:authentication"
commonAiCodingMistakes:
  - "AI mounts an auth middleware with app.use(requireAuth) partway through app.js, but a route defined earlier in the same file (or in a router required before the middleware is applied) is unintentionally left unprotected, since Express applies middleware in registration order, not file order intuitively expected."
  - "AI adds a new route to an existing router file by appending it at the end, after a `module.exports = router` statement was assumed to be the end of the file — the route is dead code, or worse, gets added to the wrong router object entirely due to a copy-paste mistake."
  - "AI copies a protected router's structure for a new router but forgets to re-apply the auth middleware at the new router's mount point in app.js, since middleware application happens at the mounting call site, not inside the router file itself."
  - "AI wires up a JWT auth middleware (e.g. express-jwt or a hand-rolled equivalent) without pinning the accepted `algorithms` list, mirroring the real-world CVE-2020-15084 authorization bypass — a token verified against a public/JWKS key can be forged if `alg: none` or a mismatched algorithm is accepted, silently defeating the auth middleware every route depends on."
  - "AI defines a route parameter pattern with two params in one path segment (e.g. `/flights/:from-:to`) without a bounding regex, reproducing the path-to-regexp ReDoS class (CVE-2024-45296/CVE-2024-52798) — this isn't an authorization bypass but can be chained with a middleware-ordering finding since a stalled event loop also stalls every auth check behind it."
  - "AI treats the presence of an auth middleware in the require/import list as proof it's active — but never checks whether it's actually passed into app.use()/router.use() versus just imported and left unused, a copy-paste artifact common when scaffolding from a template router."
falsePositiveGuardrails:
  - "Do not flag routes mounted under a path that's clearly public in intent (e.g. /api/public/*, /health, /webhooks/*) as missing auth — these are often intentionally open."
  - "Middleware applied via router.use() inside a router file protects all routes defined after that call in the same file/router — trace the actual registration order before concluding a route is unprotected; don't assume file-level middleware only from app.js is the only valid protection point."
  - "The Express-official pattern of registering a catch-all 404 handler and a 4-argument error handler as the very last `app.use()` calls is correct and expected — do not flag error-handling middleware appearing after all routes as a defect; flag it only when it appears before routes (which breaks Express's error-propagation model)."
  - "An auth middleware that is imported but relies on route-level `algorithms`/`audience`/`issuer` options (e.g. express-jwt style config) being correct is a config-verification finding, not automatically an unprotected-route finding — distinguish 'middleware is missing' from 'middleware is present but misconfigured' (see CVE-2020-15084) since they need different evidence and different severity framing."
---

## Root Cause Explanation

Express's middleware model is registration-order-dependent: a route defined
or a router mounted *before* a protective middleware is registered will not
have that middleware applied to it, even if the middleware appears
immediately below in the same file. This is a common AI-scaffolding gap
because the natural mental model ("this middleware protects the app") doesn't
match Express's actual execution model ("this middleware protects everything
registered after it").

## Vulnerable Patterns

```js
const app = express();

// Route defined BEFORE the auth middleware is registered — unprotected
app.get('/api/account', (req, res) => { res.json(currentUser(req)); });

app.use(requireAuth); // only protects routes registered after this line

app.get('/api/billing', (req, res) => { res.json(billingInfo(req)); });
```

```js
// New router added but auth middleware not re-applied at its mount point
app.use('/api/users', requireAuth, usersRouter);
app.use('/api/reports', reportsRouter); // missing requireAuth here
```

## Data Flow Tracing Guide

1. Reconstruct the actual middleware registration order for the app by
   reading `app.js`/`server.js` top to bottom (or the equivalent entry
   file), noting the exact line each `app.use()` and route/router
   registration occurs.
2. For each router mount (`app.use('/path', router)`), check whether an auth
   middleware is passed as an argument at the mount call, or whether the
   router itself applies `router.use(requireAuth)` internally before its
   routes.
3. Cross-reference against `route_map`'s `middlewareChain` — any route with
   an empty chain that isn't an intentionally public path is worth tracing
   back to confirm no app-level middleware covers it.

## Evidence Checklist

- [ ] The exact registration order (file + line numbers) showing the route
      in question is registered before the relevant protective middleware.
- [ ] Confirmation the route is not an intentionally public path.

## Attack Scenario Template

> Because [route] is registered at [file:line], before [middleware] is
> applied at [file:line], an unauthenticated request to [route] reaches the
> handler directly, resulting in [concrete impact].

## Graph Mapping Instructions

- Ensure `component:api_security` exists with a `depends_on` edge to
  `component:authentication`.
- A finding here that shows a specific route is unprotected should also
  reference the specific downstream data/component it exposes (e.g. add an
  `enables` edge to `component:database` if it exposes direct data access).
