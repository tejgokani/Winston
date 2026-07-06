---
id: technology.trpc.procedure_authorization
title: tRPC Procedure-Level Authorization
category: technology
vulnerabilityClass: broken_access_control
appliesToStack: trpc
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A01:2021 Broken Access Control"
cweRefs:
  - "CWE-862"
  - "CWE-863"
  - "CWE-284"
realWorldReferences:
  - title: "tRPC Docs — Authorization"
    url: "https://trpc.io/docs/server/authorization"
    type: vendor_security_advisory
  - title: "tRPC Docs — Middlewares"
    url: "https://trpc.io/docs/server/middlewares"
    type: vendor_security_advisory
  - title: "How a GraphQL Bug Resulted in Authentication Bypass (HackerOne)"
    url: "https://www.hackerone.com/blog/how-graphql-bug-resulted-authentication-bypass"
    type: bug_bounty_disclosure
  - title: "Implementing Authorization with Clerk in a tRPC app running on a Cloudflare Worker"
    url: "https://dev.to/yinks/implementing-authorization-with-clerk-in-a-trpc-app-running-on-a-cloudflare-worker-4li5"
    type: security_blog
quickModeSummary: >
  For every tRPC procedure in the router tree, determine whether it is built
  from `publicProcedure` or `protectedProcedure` (or an RBAC-wrapped variant)
  and whether that matches the sensitivity of what it does. `protectedProcedure`
  only proves a middleware chain confirmed *authentication* (a valid session
  exists) — it does NOT prove the caller is *authorized* to touch the specific
  resource (record/tenant/org) the input references. Flag procedures copy-pasted
  from a protected sibling that still default to `publicProcedure`, and flag
  `protectedProcedure` mutations/queries that take an id/ownerId-like input but
  never re-check that the resource belongs to `ctx.session.user`.
fileSelectionHint:
  roles: ["route_handler", "middleware", "auth"]
  matchImports: ["@trpc/server", "initTRPC", "trpc"]
  matchAuthMapTags: ["trpc"]
  maxFiles: 10
  priorityOrder: ["route_handler", "middleware", "auth"]
severityHeuristics:
  critical:
    - "A mutation that creates/updates/deletes state-changing or financial data is built from publicProcedure with no auth middleware at all"
    - "A protectedProcedure fetches or mutates a resource by id from input without any ownership/tenant check against ctx.session.user, allowing any authenticated user to read or modify another user's data (IDOR)"
  high:
    - "A router-level .use() middleware intended to apply auth to an entire router is bypassed because one procedure in the router was built directly from t.procedure instead of the router's protected base"
    - "Role/permission checks (e.g. isAdminProcedure) exist for some admin mutations but a newly added admin mutation was copy-pasted from a protectedProcedure example and only checks authentication, not the admin role"
  medium:
    - "Authorization logic re-implemented ad hoc inside a resolver body instead of centralized middleware, creating drift risk as more procedures are added"
    - "ctx type only weakly narrows the authenticated user (e.g. optional session) such that TypeScript doesn't force downstream code to handle the unauthenticated case, masking missing checks"
  low:
    - "publicProcedure used for a genuinely public, read-only, non-sensitive endpoint (informational only, verify intent before flagging even at low severity)"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:trpc_router"
  relatedNodeIds: ["component:authentication", "component:authorization", "component:api_security"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:trpc_router"
    to: "component:authentication"
  - relation: depends_on
    from: "component:trpc_router"
    to: "component:authorization"
  - relation: protects
    from: "component:authorization"
    to: "component:api_security"
commonAiCodingMistakes:
  - "AI scaffolds a new procedure by copying a sibling in the same router file, but the sibling happened to be publicProcedure (e.g. a `list` query) and the new one is a mutation that should have been protectedProcedure — the copy carries the wrong base forward."
  - "AI correctly uses protectedProcedure for a new mutation and treats that as sufficient, without adding the ownership check (e.g. `where: { id: input.id, userId: ctx.session.user.id }`) that the operation actually needs — conflating 'is logged in' with 'owns this resource'."
  - "AI adds a new router to the app router tree but forgets to nest it under a parent router that applies a global auth middleware via `.use()`, so the new router's procedures fall back to being independently (and incorrectly) public."
  - "AI implements role-based procedures (adminProcedure, orgOwnerProcedure) for the first few sensitive routes, then later reverts to plain protectedProcedure for a new admin-only mutation because the pattern wasn't centralized or documented, silently downgrading enforcement."
  - "AI trusts a role or tenantId passed in the tRPC input payload from the client instead of reading it from ctx (derived server-side from the verified session), letting a client simply claim a different role or tenant in the request body."
falsePositiveGuardrails:
  - "Do not flag a procedure as vulnerable purely for being publicProcedure — first confirm it isn't an intentionally public operation (e.g. public content listing, health check, sign-up/sign-in mutation, public search). Public-by-design procedures are correct, not a finding."
  - "Do not treat protectedProcedure as fully authorizing an operation — check whether the procedure's business logic re-verifies resource ownership/tenant scoping for any input containing an id. protectedProcedure alone only proves authentication."
  - "Before flagging a router as unprotected, check whether auth is applied once at a parent router or at the tRPC context/middleware level (e.g. a top-level `.use(isAuthed)` in the router tree or an all-procedures context middleware) rather than per-procedure — trace the actual middleware chain, don't assume based on procedure naming alone."
  - "Do not flag role checks implemented via a documented meta-based pattern (e.g. NestJS-tRPC style `meta: { roles: [...] }` read by a shared middleware) as missing authorization just because there's no inline `if (role !== 'admin')` — confirm whether the shared middleware actually enforces the declared meta before concluding it's decorative."
---

## Root Cause Explanation

tRPC's core selling point — end-to-end type safety with minimal boilerplate —
is also what makes procedure-level authorization easy to get subtly wrong:

1. **Authentication vs. authorization conflation.** tRPC's idiomatic pattern
   (documented at `trpc.io/docs/server/authorization`) is to build a
   `protectedProcedure` from `t.procedure.use(isAuthed)`, where `isAuthed`
   only checks that `ctx.session`/`ctx.user` exists. That answers "is this
   caller logged in?" — it says nothing about whether the caller is allowed
   to touch the *specific resource* referenced by the procedure's input
   (a record id, another user's profile, another tenant's data). Because the
   procedure "feels" protected (the name says so, the middleware runs), it's
   easy to stop reasoning about authorization at that point and never add
   the ownership/tenant check the operation actually needs. This is the
   same authentication-vs-authorization gap covered in
   `ai_security/authorization.md`, but tRPC's naming convention
   (`protectedProcedure`) actively encourages developers and AI agents to
   believe the check is complete when it is only half done.
2. **Copy-paste procedure scaffolding.** Routers are typically built
   procedure-by-procedure, and both humans and AI coding agents commonly
   create a new procedure by duplicating a nearby one and editing the input
   schema and resolver body. If the nearby example was `publicProcedure`
   (e.g., a public listing query) and the new procedure is a mutation that
   should require auth, the wrong base survives the copy unless someone
   deliberately swaps it — there is no compiler error or runtime warning for
   using the "wrong" procedure builder, since both are valid, well-typed
   `t.procedure`-derived objects.
3. **Middleware chaining and router composition gaps.** tRPC supports
   applying `.use()` at the router level so every procedure in a router
   inherits a middleware chain. When auth is centralized this way, adding a
   new sub-router without nesting it under the protected parent router
   silently drops it out of the enforced chain — the new router's procedures
   type-check fine and look identical in shape to protected ones, but never
   actually run the auth middleware.
4. **Client-supplied identity fields.** Because tRPC inputs are just
   Zod-validated JSON payloads, it's tempting (and easy for an AI agent
   working from a "make the input match what the frontend sends" mental
   model) to accept a `role` or `tenantId`/`orgId` field directly in the
   procedure input rather than deriving it from `ctx.session` on the server.
   This lets a client simply claim elevated privileges or a different
   tenant in the request body, bypassing the intended access boundary
   entirely.

## Vulnerable Patterns

```ts
// 1. Sensitive mutation left on publicProcedure — likely copy-paste from a public query
export const userRouter = router({
  listPublicProfiles: publicProcedure.query(() => db.profile.findMany({ where: { public: true } })),
  // should be protectedProcedure — mutates account data, no auth check at all
  deleteAccount: publicProcedure
    .input(z.object({ userId: z.string() }))
    .mutation(({ input }) => db.user.delete({ where: { id: input.userId } })),
});

// 2. protectedProcedure that checks authentication but not ownership (IDOR)
export const invoiceRouter = router({
  getInvoice: protectedProcedure
    .input(z.object({ invoiceId: z.string() }))
    .query(async ({ input }) => {
      // any logged-in user can read any invoice by id — no ownerId/tenant check
      return db.invoice.findUnique({ where: { id: input.invoiceId } });
    }),
});

// 3. Trusting a client-supplied role/tenant instead of ctx
export const adminRouter = router({
  banUser: protectedProcedure
    .input(z.object({ targetUserId: z.string(), callerRole: z.string() }))
    .mutation(({ input }) => {
      if (input.callerRole !== 'admin') throw new TRPCError({ code: 'FORBIDDEN' });
      // callerRole came from the request body, not ctx.session.user.role
      return db.user.update({ where: { id: input.targetUserId }, data: { banned: true } });
    }),
});

// 4. New sub-router not nested under the parent router's auth middleware
const protectedRouter = router({ /* has auth middleware applied via .use() upstream */ });
export const appRouter = router({
  protected: protectedRouter,
  // added later, forgotten to nest under the auth-checked composition
  reports: reportsRouter, // reportsRouter's procedures use t.procedure directly, no isAuthed
});
```

## Data Flow Tracing Guide

1. Find where `initTRPC` is set up and locate the `isAuthed` (or equivalent)
   middleware and the exported procedure builders (`publicProcedure`,
   `protectedProcedure`, and any role/tenant-scoped variants like
   `adminProcedure`). Confirm exactly what each middleware checks — session
   existence only, or also a role/permission claim.
2. For every router file, enumerate every procedure and record which builder
   it's constructed from. Cross-reference against the HTTP verb / mutation
   type: does a state-changing procedure (create/update/delete, or any
   query returning another user's private data) use at least
   `protectedProcedure`?
3. For every `protectedProcedure` (or stronger) that accepts an id-like input
   field (anything resembling `id`, `userId`, `orgId`, `resourceId` in the
   Zod schema), trace the resolver body: does it scope the DB query by
   `ctx.session.user.id` / `ctx.session.user.orgId`, or does it fetch/mutate
   purely by the client-supplied id with no ownership filter?
4. Check router composition: does every router that should be protected get
   merged into the app router under a parent that applies the auth
   middleware via `.use()`, or does each router independently import
   `protectedProcedure`? If independently imported, confirm every router
   file actually imports the protected variant and not `t.procedure`
   directly.
5. For any role/permission field used in an authorization check inside a
   resolver, trace its origin back to `ctx` (server-derived from the
   verified session/JWT) — never to `input` (client-supplied). If a role or
   tenant identifier is read from `input`, that's a critical finding
   regardless of what procedure builder wraps it.

## Evidence Checklist

- [ ] The exact procedure builder used (`publicProcedure`, `protectedProcedure`,
      or custom) is cited with file + line for the flagged procedure.
- [ ] For a missing-authorization (not just missing-authentication) finding:
      both the resolver's DB query (showing no ownership/tenant filter) and
      the input schema (showing the id field is client-controlled) are cited.
- [ ] For a client-trusted-role finding: the exact line where the role/tenant
      value is read from `input` rather than `ctx` is cited.
- [ ] For a router-composition gap: the app router's composition tree is
      cited showing the router in question sits outside the protected
      parent's middleware chain.
- [ ] Confirmation that the flagged procedure is not an intentionally public
      operation (public listing, health check, sign-up/sign-in) before
      concluding severity.

## Attack Scenario Template

> An authenticated attacker with an ordinary account calls
> [procedure name] with [input, e.g. `invoiceId` belonging to another user].
> Because [specific file:line] only verifies that a session exists
> (`protectedProcedure`/`isAuthed`) and never scopes the query by
> [ownership field], the resolver returns/mutates [specific resource type]
> belonging to a different [user/tenant], resulting in [concrete impact,
> e.g. "reading another customer's invoice PDF" or "deleting another
> org's project"].

Fill every bracket from evidence gathered in this repo. If the ownership
check exists elsewhere (e.g. enforced at the database layer via row-level
security) verify that before claiming this finding — cite where you checked.

## Graph Mapping Instructions

- Ensure a `component:trpc_router` node exists on the first tRPC-related
  finding in a scan, with `depends_on` edges to `component:authentication`
  and `component:authorization`.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`. Use a `causes` edge from `component:authorization` when
  the root cause is a missing ownership/resource check on an otherwise
  authenticated procedure, versus a `causes` edge from
  `component:authentication` when the procedure has no auth middleware at
  all — these are different root causes and should not be merged.
- If a finding allows reaching another tenant's or user's data, add an
  `enables` edge from the finding node to the relevant data-store component
  node (e.g. `component:database`).
- If multiple procedures share the same missing-ownership-check root cause
  (a systemic pattern across a router), note this in each finding's
  `reasoning` field so the graph mapper can group them under a single
  root-cause component rather than treating each as isolated.
