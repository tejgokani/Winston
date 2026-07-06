---
id: technology.dotnet.aspnet_core_security
title: "ASP.NET Core: Authorization, EF Core & Model Binding"
category: technology
vulnerabilityClass: broken_access_control
appliesToStack: dotnet
requiresAnyTag: ["dotnet"]
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A01:2021 Broken Access Control"
  - "A03:2021 Injection"
  - "A08:2021 Software and Data Integrity Failures"
cweRefs:
  - "CWE-285"
  - "CWE-89"
  - "CWE-915"
realWorldReferences:
  - title: "ASP.NET Core — authorization bypass / security advisories (Microsoft Security Advisory for .NET, e.g. CVE-2024-38095 and the .NET authz series)"
    url: "https://github.com/dotnet/announcements/labels/Security"
    type: vendor_security_advisory
  - title: "Newtonsoft.Json / BinaryFormatter — insecure deserialization with TypeNameHandling.All enabling RCE (Microsoft guidance to stop using BinaryFormatter)"
    url: "https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide"
    type: vendor_security_advisory
  - title: "Entity Framework Core — raw SQL and FromSqlRaw injection vs. FromSqlInterpolated safe parameterization (Microsoft docs)"
    url: "https://learn.microsoft.com/en-us/ef/core/querying/sql-queries"
    type: security_blog
  - title: "OWASP — Mass Assignment / over-posting in ASP.NET model binding"
    url: "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"
    type: security_blog
quickModeSummary: >
  Review ASP.NET Core authorization and EF Core data access. Confirm that
  controllers/actions or minimal-API endpoints handling protected resources
  carry `[Authorize]` (with the right policy/role) rather than relying on a
  fallback that may not be configured — and that `[AllowAnonymous]` isn't
  accidentally opening sensitive endpoints. Check for IDOR (loading an entity
  by id without an ownership/policy check), EF Core `FromSqlRaw`/
  `ExecuteSqlRaw` with string concatenation (use `FromSqlInterpolated`/
  parameters instead), over-posting/mass-assignment where request data binds
  directly onto EF entities (use DTOs / `[Bind]` allow-lists), insecure
  deserialization (`BinaryFormatter`, `TypeNameHandling.All` in
  Newtonsoft.Json), and CORS configured with `AllowAnyOrigin` +
  `AllowCredentials`.
fileSelectionHint:
  roles: ["controller", "endpoint", "service", "repository", "config", "startup", "middleware"]
  matchImports:
    ["Microsoft.AspNetCore", "Microsoft.EntityFrameworkCore", "System.Text.Json", "Newtonsoft.Json", "Microsoft.AspNetCore.Authorization"]
  matchAuthMapTags: ["dotnet", "jwt"]
  maxFiles: 14
  priorityOrder: ["config", "startup", "controller", "repository"]
severityHeuristics:
  critical:
    - "Insecure deserialization reachable from user input — BinaryFormatter, or Newtonsoft.Json with TypeNameHandling.All/Auto on untrusted data — enabling gadget-chain RCE"
    - "A protected controller/action/minimal-API endpoint lacks [Authorize] (and no global fallback policy enforces auth), or [AllowAnonymous] exposes a sensitive endpoint, leaving it publicly reachable"
    - "EF Core FromSqlRaw/ExecuteSqlRaw or ADO.NET command text concatenates user input instead of parameterizing, enabling SQL injection"
  high:
    - "An action loads an entity by id and returns/mutates it without an ownership/resource-based authorization check (IDOR/BOLA)"
    - "Model binding maps request data directly onto an EF entity with no DTO or [Bind]/allow-list, enabling over-posting of fields like Role/IsAdmin/OwnerId (mass assignment)"
  medium:
    - "[Authorize] is present but authenticates only (no policy/role for the specific action), or authorization decisions use a request-supplied id/role rather than claims from the authenticated principal (User.FindFirst)"
    - "CORS policy uses AllowAnyOrigin together with AllowCredentials, or SetIsOriginAllowed(_ => true), exposing authenticated endpoints cross-origin"
  low:
    - "Antiforgery/CSRF protection missing on cookie-authenticated form posts, security headers absent, or developer exception page / detailed errors enabled in production"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:authorization"
  relatedNodeIds: ["component:authentication", "component:api_layer", "component:database_access"]
graphEdgeMapping:
  - relation: protects
    from: "component:authorization"
    to: "component:api_layer"
  - relation: depends_on
    from: "component:api_layer"
    to: "component:database_access"
commonAiCodingMistakes:
  - "AI puts `[Authorize]` on some controllers and forgets it on others, with no global fallback authorization policy configured, so newly added endpoints default to anonymous — ASP.NET Core does not require auth unless you opt in per endpoint or set a FallbackPolicy."
  - "AI uses `FromSqlRaw($\"SELECT * FROM Users WHERE Email = '{email}'\")` (string interpolation into FromSqlRaw is NOT parameterized) instead of `FromSqlInterpolated` or explicit `SqlParameter`s — a subtle trap because the interpolated-string version looks identical to the safe FromSqlInterpolated call."
  - "AI binds request bodies straight onto EF entities (`public IActionResult Update(User user)`) enabling over-posting: an attacker adds `Role` or `IsAdmin` to the payload and it persists — the classic ASP.NET mass-assignment bug."
  - "AI enables `TypeNameHandling.All`/`Auto` in Newtonsoft.Json 'to preserve types' or uses BinaryFormatter, opening gadget-chain RCE on untrusted input."
  - "AI loads an entity by id and returns it after only checking the user is authenticated, never that the entity belongs to them — IDOR — because resource-based authorization (IAuthorizationService) requires deliberate wiring."
  - "AI configures CORS with `AllowAnyOrigin().AllowCredentials()` (which ASP.NET actually rejects) and 'fixes' it with `SetIsOriginAllowed(_ => true).AllowCredentials()`, reflecting any origin with credentials."
falsePositiveGuardrails:
  - "Do not flag missing [Authorize] if a global FallbackPolicy requiring authenticated users is configured (AddAuthorization with FallbackPolicy, or app.MapXxx().RequireAuthorization()) — verify the global policy before concluding an endpoint is open."
  - "`FromSqlInterpolated($\"... {email}\")` and `FromSqlRaw` with explicit SqlParameter arguments ARE parameterized and safe — only `FromSqlRaw`/`ExecuteSqlRaw` with a concatenated or interpolated string (no parameters) is injection. Distinguish the two carefully."
  - "An action using a DTO/ViewModel (not the EF entity) for binding, or an explicit `[Bind(nameof(...))]` allow-list, is not over-posting — confirm the bound type before flagging."
  - "System.Text.Json without custom polymorphic type resolvers, and Newtonsoft.Json without TypeNameHandling, are not the unsafe-deserialization case — confirm TypeNameHandling.All/Auto or BinaryFormatter on untrusted data before flagging RCE."
  - "Resource-based authorization via IAuthorizationService/AuthorizeAsync with a policy that checks ownership is the correct IDOR defense — do not flag when present and enforced."
---

## Root Cause Explanation

ASP.NET Core is secure-by-configuration, and the configuration burden is
where AI-generated code slips. Authorization is opt-in per endpoint:
`[Authorize]` must be applied, or a global `FallbackPolicy` set, or the
endpoint defaults to anonymous. AI scatters `[Authorize]` inconsistently and
rarely configures a fallback, so a freshly added controller ships public.
Worse, `[AllowAnonymous]` overrides everything, so a copy-pasted anonymous
attribute can silently open a sensitive action.

Two .NET-specific traps compound this. First, EF Core's `FromSqlRaw` accepts
a C# interpolated string that *looks* exactly like the safe
`FromSqlInterpolated` call but does *not* parameterize — the difference is
the method name, not the syntax, so AI routinely writes the injectable form.
Second, model binding maps posted fields onto whatever type the action
accepts; bind directly onto an EF entity and an attacker "over-posts" extra
fields like `Role` or `IsAdmin` that then persist (mass assignment). The DTO/
allow-list defense requires deliberate discipline the model often skips.

Insecure deserialization rounds out the critical surface: `BinaryFormatter`
(which Microsoft has deprecated precisely because it's unsafe) and
Newtonsoft.Json `TypeNameHandling.All/Auto` both enable gadget-chain RCE on
untrusted input. The rest is standard: IDOR from unowned entity ids,
request-trusted authorization identifiers, permissive CORS, and missing
antiforgery on cookie-authenticated posts.

## Vulnerable Patterns

```csharp
// FromSqlRaw with interpolation — NOT parameterized (looks like the safe call!)
var users = ctx.Users.FromSqlRaw($"SELECT * FROM Users WHERE Email = '{email}'");

// Over-posting: binding request data onto the EF entity
[HttpPost] public IActionResult Update(User user) { ctx.Update(user); ctx.SaveChanges(); }

// Insecure deserialization
JsonConvert.DeserializeObject<object>(input, new JsonSerializerSettings {
  TypeNameHandling = TypeNameHandling.All });
```

Correct shapes parameterize, bind to DTOs, and require authorization:

```csharp
var users = ctx.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Email = {email}"); // parameterized

[Authorize]
[HttpPost] public async Task<IActionResult> Update(UpdateUserDto dto) {
  var user = await ctx.Users.FirstOrDefaultAsync(u => u.Id == dto.Id && u.OwnerId == User.GetUserId());
  if (user is null) return NotFound();
  user.Name = dto.Name; // explicit fields only
  await ctx.SaveChangesAsync();
  return Ok();
}
```

## Data Flow Tracing Guide

1. Check the authorization setup: is there a global FallbackPolicy? For each
   sensitive controller/action/minimal-API endpoint, confirm `[Authorize]`
   with the right policy/role, and check for stray `[AllowAnonymous]`.
2. Grep EF Core for `FromSqlRaw`/`ExecuteSqlRaw`/`ExecuteSqlInterpolated` and
   ADO.NET `CommandText`; classify each as parameterized or concatenated.
3. Inspect action parameter types: DTO/ViewModel vs. EF entity, and any
   `[Bind]` allow-list, to find over-posting.
4. Search for `BinaryFormatter`, `TypeNameHandling.All/Auto`, and
   `SoapFormatter` on untrusted input.
5. Check CORS policy and antiforgery configuration against the auth model.

## Evidence Checklist

- [ ] The endpoint and its authorization attributes / fallback policy status.
- [ ] For injection: the exact EF/ADO call and whether parameters are used.
- [ ] For over-posting: the bound type and any allow-list.
- [ ] For deserialization: the settings/formatter and the untrusted source.

## Attack Scenario Template

> An attacker sends [method] [endpoint] [with a SQL payload / extra
> privileged fields / a malicious typed payload / another user's id]. Because
> [file:line] [lacks [Authorize] with no fallback policy / uses FromSqlRaw
> with interpolation / binds onto the EF entity / enables TypeNameHandling.All
> / omits the ownership check], the request [reaches the endpoint anonymously
> / injects SQL / persists an elevated field / triggers deserialization RCE /
> accesses another user's data], resulting in [impact].

## Graph Mapping Instructions

- Ensure `component:authorization` exists with a `protects` edge to
  `component:api_layer`.
- Deserialization findings add a `causes` edge toward a code-execution
  component if supported.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from its root-cause component. Link shared root causes (a missing fallback
  policy) in `reasoning`.
