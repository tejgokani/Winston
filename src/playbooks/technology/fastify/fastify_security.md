---
id: technology.fastify.security
title: "Fastify: Hooks, Schemas & Route Security"
category: technology
vulnerabilityClass: broken_access_control
appliesToStack: fastify
requiresAnyTag: ["fastify"]
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A01:2021 Broken Access Control"
  - "A03:2021 Injection"
  - "A05:2021 Security Misconfiguration"
cweRefs:
  - "CWE-285"
  - "CWE-16"
  - "CWE-20"
realWorldReferences:
  - title: "Fastify — CORS plugin origin reflection with credentials misconfiguration guidance (@fastify/cors docs)"
    url: "https://github.com/fastify/fastify-cors"
    type: security_blog
  - title: "@fastify/jwt — verifying tokens and the importance of algorithm and audience/issuer checks (docs)"
    url: "https://github.com/fastify/fastify-jwt"
    type: security_blog
  - title: "Fastify — find-my-way router and the security implications of route ordering / wildcard routes"
    url: "https://fastify.dev/docs/latest/Reference/Routes/"
    type: security_blog
  - title: "OWASP — Broken Object Level Authorization (BOLA/IDOR) reference"
    url: "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
    type: security_blog
quickModeSummary: >
  Fastify's security hinges on hooks and schema validation being attached to
  the right routes. Check that authentication/authorization is enforced via a
  `preHandler`/`onRequest` hook on every protected route (and that
  route-level hooks aren't silently skipped by registering routes on a
  different instance/plugin scope than the hook). Confirm every route with a
  body/params/querystring has a JSON `schema` so unvalidated input can't reach
  handlers, that `@fastify/jwt` verification pins the algorithm and checks
  audience/issuer, and that `@fastify/cors` isn't reflecting arbitrary origins
  with credentials. Watch for IDOR (object id used without ownership check)
  and for handlers trusting a userId/role from the request instead of the
  authenticated token.
fileSelectionHint:
  roles: ["route_handler", "controller", "plugin", "hook", "auth", "middleware"]
  matchImports: ["fastify", "@fastify/jwt", "@fastify/cors", "@fastify/auth", "@fastify/helmet", "fastify-plugin"]
  matchAuthMapTags: ["fastify", "jwt"]
  maxFiles: 12
  priorityOrder: ["hook", "auth", "plugin", "route_handler"]
severityHeuristics:
  critical:
    - "A protected route has no authentication/authorization hook attached (onRequest/preHandler), or the hook is registered on a different plugin scope than the route so it never runs, leaving the endpoint open"
    - "A route reads an object id and returns/mutates it without verifying the authenticated principal owns it (IDOR/BOLA)"
  high:
    - "@fastify/jwt verification does not pin the algorithm and/or does not validate audience/issuer/expiry, or the secret/public key is weak or hardcoded"
    - "A handler trusts a userId/tenantId/role from the request body/query rather than from the verified JWT/session"
  medium:
    - "A route accepts a body/querystring/params with no JSON schema, so malformed or unexpected-shape input reaches the handler and downstream queries unvalidated"
    - "@fastify/cors reflects the request origin (origin: true or a permissive function) while credentials are enabled, exposing authenticated endpoints cross-origin"
  low:
    - "Security headers plugin (@fastify/helmet) is absent on an HTML-serving app, or error handlers leak stack traces / internal details in responses"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:authorization"
  relatedNodeIds: ["component:authentication", "component:api_layer", "component:input_validation"]
graphEdgeMapping:
  - relation: protects
    from: "component:authorization"
    to: "component:api_layer"
  - relation: depends_on
    from: "component:api_layer"
    to: "component:input_validation"
commonAiCodingMistakes:
  - "AI defines an `authenticate` decorator/hook but forgets to attach it to some routes (or attaches it only to a parent that a child plugin doesn't inherit), because Fastify's encapsulation means hooks registered in one scope don't apply to routes registered in a sibling scope — producing endpoints that look protected next to protected ones but aren't."
  - "AI writes routes without a `schema`, relying on manual `if (!req.body.x)` checks, missing Fastify's built-in schema validation that would reject malformed input before the handler and also enable safe serialization — leaving type-confusion and injection surface open."
  - "AI calls `fastify.jwt.verify`/`request.jwtVerify()` without configuring `algorithms`, `audience`, or `issuer`, accepting any algorithm the token declares and tokens minted for other audiences."
  - "AI configures `@fastify/cors` with `origin: true` (reflect any origin) alongside `credentials: true`, effectively allowing any website to make authenticated cross-origin requests."
  - "AI takes `request.body.userId` to scope a query instead of `request.user.sub` from the verified token, enabling cross-user access."
  - "AI returns raw errors (`reply.send(err)`) or leaves the default error serializer exposing stack traces and internal messages to clients."
falsePositiveGuardrails:
  - "Do not flag a route as unprotected if an `onRequest`/`preHandler` auth hook is attached at the route or at an enclosing plugin scope the route actually inherits — verify the encapsulation relationship (same or ancestor `register` scope) before concluding the hook doesn't run."
  - "A route legitimately public (login, health, public content, signed webhook) does not need an auth hook — confirm intent before flagging."
  - "@fastify/cors with a fixed allow-list of trusted origins (not reflection) is correct even with credentials — only reflection/wildcard-with-credentials is the issue."
  - "Routes with a JSON `schema` covering body/params/querystring are validated by Fastify automatically — do not flag missing validation when a schema is present and covers the fields used."
  - "Do not flag JWT config as weak if `algorithms` is pinned and audience/issuer are validated (or documented as intentionally omitted for a symmetric single-audience internal service) — quote the actual config."
---

## Root Cause Explanation

Fastify is secure by construction *if* two mechanisms are used correctly:
lifecycle hooks and JSON schema validation. Both are undermined by Fastify's
encapsulation model, which is exactly what trips up AI-generated code. Hooks
and decorators registered inside a plugin apply only to that plugin's
encapsulated context and its children — not to sibling plugins. So an
`authenticate` hook registered in one `register()` scope silently does not
protect routes registered in another, and the resulting unprotected endpoint
sits visually beside protected ones with no syntactic difference. Reviewing
Fastify authorization therefore means reasoning about *scope inheritance*,
not just "is there an auth hook somewhere."

Schema validation is Fastify's other pillar: attaching a JSON `schema` to a
route makes Fastify validate body/params/querystring before the handler and
serialize responses safely. AI often omits schemas and hand-rolls partial
`if` checks, losing both the input-validation guarantee (type confusion,
unexpected-shape objects reaching queries) and safe serialization. The
remaining issues mirror general API security in Fastify-specific clothing:
`@fastify/jwt` used without algorithm/audience pinning, `@fastify/cors`
reflecting origins with credentials, IDOR from unowned object ids, and
authorization decisions made from request-supplied identifiers instead of the
verified token.

## Vulnerable Patterns

```ts
// Auth hook registered in a different scope than the routes it should guard
fastify.register(async (secured) => {
  secured.addHook("onRequest", secured.authenticate);
  secured.get("/me", meHandler);
});
fastify.register(async (other) => {
  other.get("/admin/users", listUsersHandler); // NOT guarded — sibling scope
});
```

```ts
// JWT verify with no algorithm/audience pinning
const payload = await request.jwtVerify(); // accepts token's declared alg, any aud
```

```ts
// CORS reflecting origin with credentials
fastify.register(cors, { origin: true, credentials: true });
```

Correct shapes attach the guard where it's inherited, pin JWT verification,
and validate with schemas:

```ts
fastify.register(cors, { origin: ["https://app.example.com"], credentials: true });

fastify.get("/orders/:id", {
  onRequest: [fastify.authenticate],
  schema: { params: { type: "object", properties: { id: { type: "string" } }, required: ["id"] } },
}, async (req, reply) => {
  const order = await db.order.findFirst({ where: { id: req.params.id, userId: req.user.sub } });
  if (!order) return reply.code(404).send();
  return order;
});
```

## Data Flow Tracing Guide

1. Map plugin/`register` scopes and which routes live in which scope. For
   each protected route, find the auth hook and confirm it's in the route's
   scope or an ancestor.
2. For each route, check for a `schema` covering the inputs the handler uses.
3. Inspect `@fastify/jwt` setup: `algorithms`, `audience`, `issuer`, secret
   source. Inspect `@fastify/cors`: origin allow-list vs. reflection, and
   credentials.
4. For handlers using object ids, confirm ownership scoping by a
   token-derived id.
5. Check error handling for stack-trace/internal leakage.

## Evidence Checklist

- [ ] File + line of the route and its attached hooks/schema (or their
      absence), plus the scope relationship to any auth hook.
- [ ] JWT verification config and CORS config quoted where relevant.
- [ ] For IDOR: the query and the origin of its scoping identifier.
- [ ] The concrete request that reaches protected data/action.

## Attack Scenario Template

> An attacker sends [method] [route] [with token for another audience / with
> another user's object id / from an arbitrary origin]. Because [file:line]
> [registers the auth hook in a sibling scope / verifies JWT without
> algorithm+audience pinning / reflects the origin with credentials / omits
> the ownership check], the request [reaches the handler unauthenticated /
> is accepted with a forged-or-foreign token / succeeds cross-origin with
> the victim's cookies], resulting in [impact].

## Graph Mapping Instructions

- Ensure `component:authorization` exists with a `protects` edge to
  `component:api_layer`.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from the relevant component (authorization for missing hooks,
  input_validation for missing schemas, authentication for JWT config).
- Link findings sharing a scope/config root cause via `reasoning`.
