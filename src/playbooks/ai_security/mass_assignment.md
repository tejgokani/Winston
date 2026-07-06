---
id: ai_security.mass_assignment
title: Mass Assignment / Over-Posting
category: ai_security
vulnerabilityClass: mass_assignment
appliesToStack: ORM/ODM-backed apps with request-to-model binding
requiresAnyTag:
  - sql
  - postgres
  - prisma
  - drizzle
  - mongodb
  - rails
  - laravel
  - django
  - nestjs
  - java
  - dotnet
  - express
  - fastify
deepOnly: false
reviewPass: 2
owaspRefs:
  - "A01:2021 Broken Access Control"
  - "A08:2021 Software and Data Integrity Failures"
cweRefs:
  - "CWE-915"
  - "CWE-639"
realWorldReferences:
  - title: "GitHub 2012 mass-assignment incident — a researcher added his key to the rails/rails repo by over-posting a protected attribute"
    url: "https://blog.github.com/2012-03-04-public-key-security-vulnerability-and-mitigation/"
    type: incident_postmortem
  - title: "OWASP API Security Top 10 — API6:2019 Mass Assignment"
    url: "https://owasp.org/API-Security/editions/2019/en/0xa6-mass-assignment/"
    type: security_blog
  - title: "Ruby on Rails — strong parameters, introduced directly in response to the mass-assignment class"
    url: "https://guides.rubyonrails.org/action_controller_overview.html#strong-parameters"
    type: security_blog
  - title: "HackerOne disclosed reports — privilege escalation via mass assignment of role/isAdmin fields"
    url: "https://hackerone.com/reports/53858"
    type: bug_bounty_disclosure
quickModeSummary: >
  Find every place a request body/object is bound wholesale into a database
  model or entity: `Model.create(req.body)`, `Object.assign(user, req.body)`,
  `{ ...dto }` spread into an ORM write, `repo.save(req.body)`, Rails
  `Model.new(params[:x])` without strong params, Django `ModelForm` with no
  field allow-list, `.update(**request.data)`. The risk is over-posting:
  the model has sensitive attributes the user should not control (`role`,
  `isAdmin`, `is_staff`, `ownerId`, `accountBalance`, `emailVerified`,
  `plan`, `price`), and by adding those keys to the request the attacker sets
  them directly — the classic being privilege escalation via `role: "admin"`.
  The fix is an explicit allow-list: bind only named, user-settable fields
  (a DTO/serializer with a fixed field set, strong parameters, `pick()`),
  never the raw request object. Flag any raw-object bind into a model that has
  privileged/server-owned fields.
fileSelectionHint:
  roles: ["route_handler", "controller", "service", "model", "repository", "serializer", "dto"]
  matchImports: ["prisma", "drizzle-orm", "sequelize", "typeorm", "mongoose", "@nestjs/typeorm"]
  matchAuthMapTags: ["orm", "database"]
  maxFiles: 12
  priorityOrder: ["controller", "route_handler", "service", "model"]
severityHeuristics:
  critical:
    - "A raw request object is bound into a model that has a privilege/authorization field (role, isAdmin, is_staff, permissions, scopes, ownerId/userId used for tenancy), so an attacker can over-post that field to escalate privileges or take ownership of another entity"
  high:
    - "A raw request object is bound into a model with a security- or value-sensitive field the user shouldn't control (emailVerified, accountBalance, price, plan/tier, credits, status, approved), enabling financial or trust-state tampering"
  medium:
    - "A raw request object is bound into a model with no currently-sensitive fields, but the pattern has no allow-list, so any sensitive field added to the model later becomes silently over-postable (latent escalation); or the allow-list exists but is a deny-list (block-list) that must enumerate every sensitive field and is easy to leave incomplete"
  low:
    - "Raw-object binding on a model whose fields are all genuinely user-owned and non-sensitive, flagged as a hardening/consistency issue — confirm no sensitive field exists on the model (now) before downgrading"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:input_validation"
  relatedNodeIds: ["component:authorization", "component:database_access"]
graphEdgeMapping:
  - relation: protects
    from: "component:input_validation"
    to: "component:database_access"
  - relation: depends_on
    from: "component:authorization"
    to: "component:input_validation"
commonAiCodingMistakes:
  - "AI writes `User.create(req.body)` / `prisma.user.update({ data: req.body })` / `Object.assign(user, req.body)` because binding the whole body is the shortest way to a working CRUD endpoint, not registering that the model also has a `role`/`isAdmin` column the attacker can now set by adding that key — the textbook privilege escalation (the GitHub 2012 incident)."
  - "AI spreads a validated DTO into the write (`repo.save({ ...dto })`) believing validation makes it safe, but schema validation checks the TYPES of fields, not whether a field is ALLOWED to be user-set — an attacker adds `role` and if the DTO/validator doesn't strip unknown keys, it persists."
  - "AI uses a block-list ('everything except password') instead of an allow-list, which silently fails to protect any sensitive field added to the model afterward."
  - "AI relies on the field simply 'not being in the form UI', not accounting for the attacker sending a raw request with extra keys the UI never renders."
  - "AI binds `req.body` into a nested/related model (a create with nested writes) where the nested object carries the sensitive field, over-posting one level down where it's easy to miss."
  - "AI omits framework protections that exist for exactly this — Rails strong parameters, Django form/serializer `fields`, NestJS ValidationPipe `whitelist`/`forbidNonWhitelisted`, Mongoose `strict` — assuming the raw bind is fine."
falsePositiveGuardrails:
  - "Do not flag a write that binds only an explicit allow-list of user-settable fields — a DTO/serializer with a fixed `fields` set, Rails strong params (`params.require(:x).permit(:a, :b)`), an explicit `pick(body, ['name','email'])`, or field-by-field assignment. That is the correct pattern regardless of how verbose it looks."
  - "A validation layer that STRIPS unknown properties (NestJS ValidationPipe with whitelist+forbidNonWhitelisted, a zod schema with `.strict()`/`.strip()` that removes extras) makes a subsequent bind safe for the fields it covers — confirm it actually strips (not merely type-checks) before treating a spread as vulnerable."
  - "A model with no sensitive/server-owned fields at all (every column is legitimately user-editable) is low risk even with raw binding — enumerate the model's fields and confirm none are privilege/value/trust-bearing before downgrading, and note it's latent if the model could gain such a field."
  - "Server-side assignment that overwrites the sensitive field AFTER the bind (e.g. `user.role = 'user'` set explicitly after `Object.assign`) neutralizes the over-post for that field — confirm the overwrite covers every sensitive field and runs unconditionally."
  - "Do not treat every use of `req.body` as mass assignment — the vulnerability requires the raw object reaching a MODEL WRITE that includes sensitive fields. A body used only to read individual values, or passed to non-persistence logic, is not this bug."
---

## Root Cause Explanation

Mass assignment (a.k.a. over-posting, or "autobinding") is what happens when
an application takes a request object and binds all of its keys onto a
database model in one step, trusting that the request will only contain the
fields the UI meant to expose. But an attacker doesn't use the UI — they send
the raw request, and they can add any key the *model* accepts, not just the
ones the form renders. If the model has a field the user shouldn't control —
`role`, `isAdmin`, `is_staff`, `ownerId`, `accountBalance`, `emailVerified`,
`price`, `plan` — the attacker sets it directly by including it in the body.

The canonical outcome is privilege escalation: `role: "admin"` posted to a
profile-update endpoint that binds `req.body` wholesale. This is not a
theoretical concern — it's the bug that let a researcher commit to the Rails
repository in 2012 by over-posting a protected attribute, which is *why* Rails
introduced strong parameters. It's also OWASP API6, a top API risk, precisely
because API endpoints so often bind JSON bodies straight to ORM models.

AI-generated code produces this constantly because whole-object binding is the
shortest path to a working CRUD endpoint, and because the failure is invisible
on the happy path — the extra key only appears in a hand-crafted request. A
subtle trap compounds it: developers (and models) assume that *validating* the
body makes the bind safe, but validation checks field *types*, not field
*permission*. Unless the validation layer explicitly strips unknown properties
or the code binds a fixed allow-list, the sensitive field flows through. The
only robust fix is an allow-list: bind exactly the named fields the user may
set, via a DTO/serializer, strong parameters, or explicit assignment — never
the raw request object, and never a block-list that must anticipate every
sensitive field.

## Vulnerable Patterns

```js
// Whole body bound into the model — attacker adds "role":"admin"
await prisma.user.update({ where: { id }, data: req.body });
const user = await User.create(req.body);
Object.assign(user, req.body); await user.save();
```

```ruby
# Rails without strong parameters
User.new(params[:user])          # params[:user][:admin] = true → over-posted
```

```python
# Django / DRF with no field allow-list
User.objects.filter(id=id).update(**request.data)   # request.data['is_staff']=True
```

Correct shapes bind an explicit allow-list:

```js
const { name, email } = req.body;                 // only user-settable fields
await prisma.user.update({ where: { id }, data: { name, email } });
```

```ruby
params.require(:user).permit(:name, :email)       # strong parameters
```

## Data Flow Tracing Guide

1. Find every model/entity write (`create`, `update`, `save`, `insert`,
   `.new(...)`, `Object.assign` onto a model, spreads into `data:`).
2. For each, determine whether the data argument is a raw request object
   (`req.body`, `params[:x]`, `request.data`, a spread DTO that wasn't
   stripped) or an explicit allow-list of named fields.
3. For raw-object binds, enumerate the target model's fields and identify any
   privilege (`role`/`isAdmin`/`permissions`), tenancy (`ownerId`/`userId`),
   value (`balance`/`price`/`plan`/`credits`), or trust (`emailVerified`/
   `approved`/`status`) fields. Their presence sets severity.
4. Check for a stripping validation layer (whitelist/forbidNonWhitelisted,
   zod `.strict`, serializer `fields`) that runs before the bind and actually
   removes unknown keys.
5. Check for a post-bind server-side overwrite of sensitive fields.

## Evidence Checklist

- [ ] The model write call site and its data argument quoted, showing the
      raw-object bind.
- [ ] The origin of the bound object (request body/params).
- [ ] The specific sensitive field(s) on the target model that the user
      shouldn't control, named — this is what makes it exploitable.
- [ ] The absence (or incompleteness) of an allow-list / stripping validation
      / post-bind overwrite.
- [ ] A concrete over-post payload (e.g. `{ "role": "admin" }`) the path admits.

A finding must name at least one sensitive field on the model; a raw bind
into a model with no sensitive fields is at most a latent/hardening note.

## Attack Scenario Template

> An attacker sends [method] [endpoint] with the normal fields plus
> [sensitive field, e.g. "role":"admin" / "isVerified":true /
> "accountBalance":100000]. Because [file:line] binds [req.body/params]
> directly into [model] with no allow-list (and no stripping validation),
> the [sensitive field] is written to the database, resulting in [privilege
> escalation to admin / bypassing verification / financial tampering /
> taking ownership of another entity].

## Graph Mapping Instructions

- Ensure a `component:input_validation` node exists, with a `protects` edge to
  `component:database_access`.
- Privilege-escalation mass-assignment findings add an `enables` edge from the
  finding node to `component:authorization` and must be flagged as
  escalation-class in `reasoning`.
- Each over-posting sink is a `finding:<uuid>` vulnerability node with a
  `causes` edge from `component:input_validation`.
- If one shared helper/pattern causes over-posting across several endpoints,
  note it in `reasoning` so the mapper links them.
