---
id: technology.nestjs.security
title: "NestJS: Guards, Pipes & Dependency Injection Security"
category: technology
vulnerabilityClass: broken_access_control
appliesToStack: nestjs
requiresAnyTag: ["nestjs"]
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A01:2021 Broken Access Control"
  - "A03:2021 Injection"
  - "A08:2021 Software and Data Integrity Failures"
cweRefs:
  - "CWE-285"
  - "CWE-639"
  - "CWE-915"
realWorldReferences:
  - title: "NestJS — official Security recipes: authentication, authorization guards, CSRF, helmet, rate limiting"
    url: "https://docs.nestjs.com/security/authentication"
    type: security_blog
  - title: "class-validator — bypassing validation via missing whitelist/forbidNonWhitelisted (mass-assignment), and the @nestjs/common ValidationPipe options"
    url: "https://docs.nestjs.com/techniques/validation"
    type: security_blog
  - title: "TypeORM — SQL injection through QueryBuilder string interpolation and raw where() (advisory discussions)"
    url: "https://github.com/typeorm/typeorm/issues/3267"
    type: vendor_security_advisory
  - title: "OWASP — Broken Object Level Authorization (BOLA/IDOR) reference"
    url: "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
    type: security_blog
quickModeSummary: >
  NestJS enforces auth via Guards and input safety via the ValidationPipe.
  Check that protected controllers/handlers actually have an auth Guard
  applied (@UseGuards at controller or handler level, or a global guard) and
  that role/permission guards check the specific action — a global JwtGuard
  authenticates but does not authorize. Confirm a global (or per-route)
  ValidationPipe is configured with `whitelist: true` and
  `forbidNonWhitelisted: true` so DTOs strip unknown fields (mass-assignment
  defense), and that DTOs actually annotate every field with class-validator
  decorators. Watch for IDOR (entity id used without ownership check),
  TypeORM QueryBuilder string interpolation (SQL injection), and secrets read
  from ConfigService but then logged or returned.
fileSelectionHint:
  roles: ["controller", "guard", "pipe", "service", "interceptor", "middleware", "dto"]
  matchImports: ["@nestjs/common", "@nestjs/core", "@nestjs/passport", "@nestjs/jwt", "class-validator", "typeorm", "@nestjs/typeorm"]
  matchAuthMapTags: ["nestjs", "jwt"]
  maxFiles: 14
  priorityOrder: ["guard", "controller", "pipe", "service"]
severityHeuristics:
  critical:
    - "A controller/handler exposing sensitive data or actions has no auth guard applied at any level (handler, controller, or global), leaving it publicly reachable"
    - "A resolver/handler reads an entity id and returns/mutates it without verifying the authenticated user owns it (IDOR/BOLA)"
    - "A TypeORM QueryBuilder or repository raw query interpolates user input into the SQL/where string instead of using parameter binding (:param)"
  high:
    - "A role/permission guard exists but authenticates only (verifies a valid JWT) without checking the caller has the specific role/permission for the action, so any logged-in user can perform privileged operations"
    - "The ValidationPipe is missing or configured without whitelist/forbidNonWhitelisted, so request bodies with extra fields flow into entities (mass-assignment of role/ownerId/isAdmin)"
  medium:
    - "DTOs lack class-validator decorators on some fields so those fields are unvalidated even with a ValidationPipe, or transform options allow unsafe coercion"
    - "A handler trusts a userId/tenant/role from the request body/params rather than from the authenticated principal (req.user)"
  low:
    - "Security middleware (helmet, CSRF for cookie-auth, throttler/rate limiting) is absent, or errors leak internal details via the default exception filter"
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
  - "AI applies a global `JwtAuthGuard` and considers everything protected, conflating authentication with authorization — every authenticated user can then hit admin-only endpoints because no RolesGuard/permission check gates the specific action."
  - "AI writes DTOs but configures the ValidationPipe without `whitelist: true`/`forbidNonWhitelisted: true` (or omits the pipe), so extra request fields survive into `create(dto)` / `repo.save({ ...dto })`, enabling mass-assignment of fields like `role` or `isAdmin` the user should never set."
  - "AI builds a TypeORM query with `createQueryBuilder().where(`name = '${name}'`)` string interpolation instead of `.where('name = :name', { name })`, reintroducing SQL injection under an ORM that would otherwise bind parameters."
  - "AI forgets `@UseGuards` on a newly added controller/handler that sits beside guarded ones, since NestJS guards are opt-in per-scope and there's no compile-time signal that a route is unguarded."
  - "AI fetches an entity by id from params and returns it, checking only that a JWT is valid, never that the entity belongs to `req.user` — the standard IDOR."
  - "AI marks fields in a DTO without decorators (a plain typed property), which class-validator ignores entirely, so those fields pass validation unchecked even with a strict pipe."
falsePositiveGuardrails:
  - "Do not flag a handler as unprotected if a guard applies at any effective level — global (`app.useGlobalGuards`/APP_GUARD provider), controller `@UseGuards`, or handler `@UseGuards`. Check for a global guard provider before concluding a controller is open."
  - "A route explicitly marked public (a `@Public()` decorator with a corresponding guard skip, login, health) is intentionally unauthenticated — confirm the public-marker mechanism before flagging."
  - "TypeORM QueryBuilder using named/positional parameters (`:id`, `?`) with a params object is correctly bound — only string interpolation into the query fragment is injection."
  - "A ValidationPipe configured globally with whitelist and forbidNonWhitelisted protects all routes with DTOs — do not flag per-route missing validation when the global pipe and a decorated DTO are both present."
  - "Do not flag authorization as missing when a RolesGuard/CASL/permission check gates the specific action and reads roles from the verified principal — quote the guard logic."
---

## Root Cause Explanation

NestJS provides strong, composable security primitives — Guards for
authorization, the ValidationPipe + class-validator for input, Interceptors
for cross-cutting concerns — but every one of them is opt-in per scope, and
that opt-in nature is exactly where AI-generated code fails. The two dominant
failures are (1) conflating authentication with authorization and (2)
mis-wiring the ValidationPipe so mass-assignment slips through.

For authorization: a global `JwtAuthGuard` verifies that a request carries a
valid token, which feels like "the app is protected." But authentication only
establishes *who* the caller is; authorization decides *whether they may do
this specific thing*. Without a RolesGuard / permission check on privileged
handlers, every authenticated user can invoke admin operations. Because
guards are decorators the developer must remember to add, a newly scaffolded
controller can silently ship with no guard at all, visually indistinguishable
from its guarded neighbors.

For input: NestJS's ValidationPipe strips and rejects unknown properties
*only* when configured with `whitelist: true` and `forbidNonWhitelisted:
true`, and it validates *only* fields that carry class-validator decorators.
AI frequently omits those options or writes undecorated DTO fields, so a
request body with an extra `role: "admin"` flows through `repo.save({
...dto })` and mass-assigns a privileged field. The remaining review surface
is standard-but-NestJS-flavored: IDOR from unowned entity ids, TypeORM
QueryBuilder string interpolation (SQL injection), request-trusted
identifiers, and missing hardening middleware.

## Vulnerable Patterns

```ts
// Authentication without authorization
@UseGuards(JwtAuthGuard) // authenticates only
@Controller("admin")
export class AdminController {
  @Delete("users/:id")
  remove(@Param("id") id: string) { return this.users.remove(id); } // any logged-in user
}
```

```ts
// ValidationPipe without whitelist → mass-assignment
app.useGlobalPipes(new ValidationPipe()); // extra fields survive
// ...
this.repo.save({ ...createUserDto }); // role/isAdmin from body persist
```

```ts
// TypeORM QueryBuilder string interpolation → SQL injection
this.repo.createQueryBuilder("u").where(`u.email = '${email}'`).getOne();
```

Correct shapes gate the action, strip unknown fields, and bind parameters:

```ts
app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }));

@UseGuards(JwtAuthGuard, RolesGuard)
@Roles("admin")
@Delete("users/:id")
remove(@Param("id") id: string) { /* ... */ }

this.repo.createQueryBuilder("u").where("u.email = :email", { email }).getOne();
```

## Data Flow Tracing Guide

1. Locate global guards (APP_GUARD providers, `useGlobalGuards`) and
   per-controller/handler `@UseGuards`. For each sensitive handler, confirm
   both authentication and an action-specific authorization check exist.
2. Find the ValidationPipe configuration and confirm `whitelist` +
   `forbidNonWhitelisted`. Inspect DTOs for decorators on every field used
   downstream.
3. For handlers taking entity ids, confirm ownership scoping by `req.user`.
4. Grep TypeORM QueryBuilder/`.query(` for string interpolation vs. bound
   params.
5. Check that identifiers used for authorization come from `req.user`, not
   the request body/params.

## Evidence Checklist

- [ ] File + line of the handler and the guards/pipe effectively applied (or
      their absence), including any global providers.
- [ ] ValidationPipe config and the relevant DTO decorators quoted.
- [ ] For IDOR/SQLi: the query and the origin of its inputs.
- [ ] The concrete request that reaches the protected action/data.

## Attack Scenario Template

> An attacker authenticated as an ordinary user sends [method] [route] [with
> another user's id / an extra privileged field / a SQL payload]. Because
> [file:line] [applies only an authentication guard with no role check /
> configures ValidationPipe without whitelist / interpolates input into a
> QueryBuilder string], the request [performs a privileged action / persists
> an elevated role / injects SQL], resulting in [impact].

## Graph Mapping Instructions

- Ensure `component:authorization` exists with a `protects` edge to
  `component:api_layer`.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from the relevant root-cause component (authorization, input_validation,
  or database_access for QueryBuilder SQLi).
- Note shared root causes (a missing global pipe affecting many DTOs) in
  `reasoning` so the mapper links related findings.
