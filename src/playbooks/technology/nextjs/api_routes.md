---
id: technology.nextjs.api_routes
title: "Next.js: API Routes & Route Handlers"
category: technology
vulnerabilityClass: broken_access_control
appliesToStack: nextjs
requiresAnyTag: ["nextjs"]
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A01:2021 Broken Access Control"
  - "A05:2021 Security Misconfiguration"
cweRefs:
  - "CWE-285"
  - "CWE-639"
  - "CWE-16"
realWorldReferences:
  - title: "Next.js middleware authorization bypass via the x-middleware-subrequest header (CVE-2025-29927)"
    url: "https://github.com/advisories/GHSA-f82v-jwr5-mffw"
    type: vendor_security_advisory
  - title: "Next.js — cache poisoning / response leakage in App Router route handlers (CVE-2024-46982)"
    url: "https://github.com/advisories/GHSA-gp8f-8m3g-qvj9"
    type: vendor_security_advisory
  - title: "Vercel engineering — postmortem and guidance on the CVE-2025-29927 middleware bypass"
    url: "https://vercel.com/blog/postmortem-on-next-js-middleware-bypass"
    type: incident_postmortem
  - title: "OWASP — Broken Object Level Authorization (BOLA/IDOR) reference"
    url: "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
    type: security_blog
quickModeSummary: >
  Review every App Router route handler (`app/**/route.ts`, exported GET/POST/
  etc.) and Pages Router API route (`pages/api/**`). The dominant risk is that
  authorization is enforced only in middleware or only in the UI, not in the
  handler itself — so a direct request to the API endpoint bypasses it (the
  CVE-2025-29927 class). Confirm each handler that returns or mutates
  protected data re-checks the session AND checks that the authenticated user
  owns/may access the specific object id in the request (IDOR/BOLA), rather
  than trusting a userId from the body/query. Also check: secrets or
  server-only env vars leaking into responses or to `NEXT_PUBLIC_` vars,
  missing input validation on the parsed body, and over-permissive CORS set
  manually in the handler.
fileSelectionHint:
  roles: ["route_handler", "api_route", "middleware", "controller"]
  matchImports: ["next/server", "next-auth", "next", "@clerk/nextjs"]
  matchAuthMapTags: ["nextjs", "next-auth", "clerk"]
  maxFiles: 12
  priorityOrder: ["route_handler", "api_route", "middleware"]
severityHeuristics:
  critical:
    - "A route handler returning or mutating sensitive/protected data performs no server-side authorization of its own and relies solely on middleware that is bypassable (or on client-side gating), so a direct request to the endpoint reaches the data unauthenticated"
    - "A handler reads an object id from the request and returns/modifies that object without verifying the authenticated user owns or may access it (IDOR/BOLA), enabling access to arbitrary users' records by changing the id"
  high:
    - "A handler trusts a user/tenant/role identifier taken from the request body or query (rather than from the verified session) to decide what data to return or what action to take"
    - "A server-only secret, service-role key, or internal env var is exposed to the client — assigned to a NEXT_PUBLIC_ variable, returned in a response body, or embedded in props/serialized state"
  medium:
    - "A handler parses the request body without schema validation before using fields in a query or side effect, or sets permissive CORS (Access-Control-Allow-Origin: * with credentials, or a reflected origin) directly in the handler"
    - "Authorization is enforced but duplicated inconsistently across handlers such that some methods (e.g. GET is checked, DELETE is not) on the same resource are unprotected"
  low:
    - "A public endpoint (health check, webhook, public content) is intentionally unauthenticated but lacks a comment/marker distinguishing it from an accidentally-open one — confirm intent before flagging higher"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:authorization"
  relatedNodeIds: ["component:authentication", "component:api_layer"]
graphEdgeMapping:
  - relation: protects
    from: "component:authorization"
    to: "component:api_layer"
  - relation: depends_on
    from: "component:api_layer"
    to: "component:authentication"
commonAiCodingMistakes:
  - "AI puts the auth check in `middleware.ts` and treats the route handlers as implicitly protected, not accounting for the fact that middleware can be bypassed (CVE-2025-29927) and that defense-in-depth requires the handler itself to verify the session — middleware is a convenience layer, not the authorization boundary."
  - "AI writes a handler like `GET /api/orders/[id]` that fetches the order by id and returns it, checking that the user is logged in but never that the order belongs to them — the textbook IDOR/BOLA, and the most common access-control bug AI produces because ownership checks require domain knowledge the model doesn't infer from the schema."
  - "AI trusts `userId` from `req.body`/`searchParams` to scope a query (`where: { userId: body.userId }`) instead of deriving it from the authenticated session, letting any user read/write another user's data by supplying a different id."
  - "AI exposes a server secret by naming it `NEXT_PUBLIC_...` so it's 'available on the client,' not realizing that inlines it into the browser bundle, or returns internal config/service-role keys in a debug field of a JSON response."
  - "AI sets `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true` (an invalid, and when reflected instead of `*`, dangerous combination) in a route handler to 'fix CORS,' opening authenticated endpoints to any origin."
  - "AI parses `await req.json()` and immediately spreads it into a database update, allowing mass-assignment of fields the user shouldn't control (role, isAdmin, ownerId) — validate and pick allowed fields explicitly."
falsePositiveGuardrails:
  - "Do not flag a handler that re-verifies the session server-side (`auth()`/`getServerSession()`/Clerk `auth()`) and checks object ownership before returning/mutating data — that is the correct pattern even if middleware also checks. Confirm the ownership check ties the object to the session user, not to a request-supplied id."
  - "A route intentionally public (marked as such, a webhook with its own signature verification, static public content) is not an access-control bug — confirm whether signature/verification or public-by-design intent applies before flagging."
  - "`NEXT_PUBLIC_` variables that hold genuinely public values (publishable/anon keys explicitly designed for client exposure, public URLs) are not secret leakage — distinguish publishable keys from secret/service-role keys before flagging."
  - "Do not flag ownership as missing without tracing the query: if the query filters by a session-derived user/tenant id (`where: { userId: session.user.id }`), the object is already scoped and no separate ownership check is needed."
  - "Server Actions and route handlers that validate the body with zod/valibot and pick explicit fields are not mass-assignment — confirm the parsed object is not spread wholesale into a mutation before flagging."
---

## Root Cause Explanation

Next.js gives you several places to enforce authorization — middleware, the
route handler, the data layer — and the framework's ergonomics nudge
developers (and AI) toward doing it in middleware once and considering the
job done. CVE-2025-29927 made the danger of that concrete: a crafted
`x-middleware-subrequest` header caused Next.js to skip middleware entirely,
so every app that relied on middleware as its *only* authorization boundary
was instantly bypassable. The durable lesson isn't "patch that CVE"; it's
that the route handler is the real trust boundary and must enforce
authorization itself, with middleware as an optimization on top.

The second dominant class is object-level authorization (IDOR/BOLA). App
Router handlers and Pages API routes routinely take an id from the URL or
body, fetch that object, and return it — checking only that *someone* is
logged in, not that *this* user may see *this* object. Because AI generates
handlers from the schema shape without the domain knowledge of who-owns-what,
it produces authenticated-but-unauthorized endpoints constantly. The fix is
to scope every query by a session-derived identifier or to explicitly verify
ownership after fetching.

Two supporting issues round out the review: server/client boundary leaks
(secrets promoted to `NEXT_PUBLIC_` or returned in responses, since anything
reaching the client bundle is public), and request-trust issues (deciding
authorization from a body/query-supplied userId/role, mass-assignment from an
un-validated parsed body, and hand-set permissive CORS on authenticated
endpoints).

## Vulnerable Patterns

```ts
// Ownership never checked — IDOR
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const order = await db.order.findUnique({ where: { id: params.id } }); // any id!
  return Response.json(order);
}
```

```ts
// Trusts a request-supplied userId to scope data
const body = await req.json();
const data = await db.post.findMany({ where: { userId: body.userId } });
```

```ts
// Secret promoted to the client bundle
// .env: NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_...  ← inlined into browser JS
```

Correct shapes derive identity from the verified session and scope every
query by it, validating the body first:

```ts
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const order = await db.order.findFirst({
    where: { id: params.id, userId: session.user.id }, // scoped to the caller
  });
  if (!order) return new Response("Not found", { status: 404 });
  return Response.json(order);
}
```

## Data Flow Tracing Guide

1. Enumerate all `app/**/route.ts` exports (GET/POST/PUT/PATCH/DELETE) and
   `pages/api/**` handlers.
2. For each, find where authorization is enforced: in the handler, in
   middleware, or nowhere. Treat middleware-only as unprotected for
   sensitive handlers.
3. For handlers taking an object id, confirm the query is scoped by a
   session-derived id or that ownership is checked after fetch. If the query
   filters only by the request id, it's IDOR.
4. Check every identifier used for authorization (userId, tenantId, role):
   does it come from the session or from the request?
5. Grep for `NEXT_PUBLIC_` on secret-looking names and scan response bodies
   for secret/service-role keys or internal config.
6. Check manually-set CORS headers and whether `req.json()`/body is spread
   into a mutation without field allow-listing.

## Evidence Checklist

- [ ] File + line of the handler and the exact authorization check present
      (or its absence), quoted.
- [ ] For IDOR: the query and the origin of every identifier it filters by,
      showing whether it's session-derived or request-supplied.
- [ ] For secret leakage: the variable name/response field and why it holds
      a secret rather than a publishable value.
- [ ] The HTTP method(s) affected and whether other methods on the same
      resource differ in protection.

## Attack Scenario Template

> An attacker authenticated as an ordinary user sends [method] [route] with
> [id/field] set to [another user's id / an elevated value]. Because
> [file:line] [relies only on bypassable middleware / checks login but not
> ownership / trusts a request-supplied identifier], the handler returns or
> modifies [object] belonging to [another user/tenant], resulting in
> [cross-user data disclosure / unauthorized modification / privilege
> escalation].

## Graph Mapping Instructions

- Ensure a `component:authorization` node exists, with a `protects` edge to
  `component:api_layer`.
- Each vulnerable handler becomes a `finding:<uuid>` vulnerability node with
  a `causes` edge from `component:authorization` (the missing/insufficient
  check is the root cause).
- For IDOR findings, add an `exposes` edge from the finding node to the data
  store/component the object lives in.
- If several handlers share one missing-guard root cause (e.g. all rely on
  the same bypassable middleware), state it in `reasoning` so the mapper
  links them.
