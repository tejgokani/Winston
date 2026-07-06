---
id: technology.prisma.query_safety
title: Prisma Query Safety
category: technology
vulnerabilityClass: injection_and_mass_assignment
appliesToStack: prisma
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A03:2021 Injection"
  - "A08:2021 Software and Data Integrity Failures"
cweRefs:
  - "CWE-89"
  - "CWE-915"
  - "CWE-20"
realWorldReferences:
  - title: "Raw queries — $queryRawUnsafe / $executeRawUnsafe warnings (official Prisma docs)"
    url: "https://www.prisma.io/docs/orm/prisma-client/using-raw-sql/raw-queries"
    type: vendor_security_advisory
  - title: "sql injection in queryRaw function (prisma/prisma GitHub Discussion #26013)"
    url: "https://github.com/prisma/prisma/discussions/26013"
    type: security_blog
  - title: "When the 'safe' is worse than you thought — bypassing Prisma's $queryRaw via Prisma.raw() (Bounce Security)"
    url: "https://www.bouncesecurity.com/blog/2024/03/28/when-the-safe-is-worse-than-you-thought.html"
    type: security_blog
  - title: "Prisma Raw Query Leads to SQL Injection? Yes and No (nodejs-security.com)"
    url: "https://www.nodejs-security.com/blog/prisma-raw-query-sql-injection"
    type: security_blog
  - title: "How Homakov hacked GitHub/Rails via mass assignment on public_key user_id (2012 incident)"
    url: "https://homakov.blogspot.com/2012/03/how-to.html"
    type: incident_postmortem
  - title: "API Security 101: Mass Assignment & Exploitation in the Wild (Cobalt.io)"
    url: "https://www.cobalt.io/blog/mass-assignment-apis-exploitation-in-the-wild"
    type: security_blog
  - title: "Mass assignment vulnerability (OWASP API Top 10 background)"
    url: "https://en.wikipedia.org/wiki/Mass_assignment_vulnerability"
    type: security_blog
quickModeSummary: >
  Check every `$queryRawUnsafe`/`$executeRawUnsafe` call for string
  concatenation or template-literal interpolation of request-derived input
  (should use the parameterized form instead). Check every `$queryRaw`/
  `Prisma.sql` call for use of `Prisma.raw()` wrapping user input inside a
  tagged template (defeats parameterization even in the "safe" API). Check
  every `.create({ data: ... })` / `.update({ data: ... })` for the entire
  request body (or an unpicked object) being spread directly into `data:`,
  which lets a client set fields like `role`, `isAdmin`, `verified`,
  `balance` that exist on the model but were never meant to be
  client-settable.
fileSelectionHint:
  roles: ["route_handler", "service", "repository", "database"]
  matchImports: ["@prisma/client", "prisma"]
  matchAuthMapTags: ["prisma"]
  maxFiles: 8
  priorityOrder: ["repository", "service", "route_handler"]
severityHeuristics:
  critical:
    - "`$queryRawUnsafe`/`$executeRawUnsafe` is called with a string built via concatenation or template-literal interpolation (`` `...${req.query.x}...` ``) of request-derived input — full SQL injection, equivalent to raw string-built SQL in any other stack."
    - "A `create`/`update`/`upsert` call spreads the raw request body (`data: req.body`, `data: { ...req.body }`, `data: JSON.parse(body)`) directly into Prisma's `data:` argument on a model that has privilege/trust fields (`role`, `isAdmin`, `verified`, `balance`, `plan`, `permissions`, `ownerId`), with no allowlist/pick step — a client can set those fields directly."
  high:
    - "`$queryRaw`/`$executeRaw` tagged-template call wraps a request-derived value in `Prisma.raw(...)` (or manually constructs a `Prisma.Sql`-shaped object) instead of interpolating it directly into the template — this defeats Prisma's built-in parameterization while looking like the 'safe' API, so reviewers and static tools both tend to miss it."
    - "Table or column names used in a raw query are built from request-derived input (even via the parameterized `$queryRaw`), since Prisma cannot parameterize identifiers — must be allowlisted, not validated as 'looks like a column name.'"
  medium:
    - "A `data:` object is built by destructuring and re-spreading most of the request body with only one or two dangerous fields deleted (`delete body.role; data: { ...body }`) rather than positively allowlisting permitted fields — fragile if the model gains a new sensitive field later."
    - "Request-derived input reaches a raw query only for read-only reporting/analytics purposes with no auth-sensitive branch depending on the result — still real injection risk (data exfiltration), but lower blast radius than a write path or auth-bypass path."
  low:
    - "Raw SQL is used for a query Prisma's query builder could express natively, increasing the surface area for future injection even where current parameterization is correct — flag as hardening guidance, not an active vulnerability, unless input is actually unparameterized."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:prisma_data_layer"
  relatedNodeIds: ["component:database", "component:api_input_handling"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:api_input_handling"
    to: "component:prisma_data_layer"
  - relation: depends_on
    from: "component:prisma_data_layer"
    to: "component:database"
commonAiCodingMistakes:
  - "AI assistants reach for `$queryRawUnsafe`/`$executeRawUnsafe` specifically because the name sounds like a normal escape hatch for 'complex' queries (dynamic sort columns, dynamic WHERE clauses, search filters), and then build the SQL string with template literals or `+` concatenation using values straight from `req.query`/`req.body` — the parameterized sibling API (`$queryRawUnsafe(sql, ...params)`) exists but is easy to skip when the AI is optimizing for 'make the dynamic query work' rather than for safety."
  - "AI assistants sometimes 'fix' a SQL injection finding by switching from `$queryRawUnsafe` to `$queryRaw` with a tagged template, which is correct — but then reintroduce the same bug by wrapping the dynamic portion in `Prisma.raw()` because that's the only way to interpolate something like a dynamic `ORDER BY` column, not realizing `Prisma.raw()` inside `$queryRaw` opts back out of parameterization entirely (this exact bypass was independently discovered and disclosed by Bounce Security's Prisma research)."
  - "AI assistants generate `create`/`update` handlers by directly wiring `req.body` (or a lightly-typed `dto`) into Prisma's `data:` field for speed — e.g. `prisma.user.update({ where: { id }, data: req.body })` — without noticing that the User model also has `role`/`isAdmin`/`verified` fields, so any authenticated (or sometimes unauthenticated) client can include those keys in their JSON body and have Prisma write them, because Prisma's `data:` accepts any subset of model fields with no automatic allowlisting."
  - "AI-generated 'profile update' or 'settings update' endpoints frequently use a Zod/TypeScript type for validation that mirrors the full Prisma model (auto-generated from `prisma generate` types) rather than a narrower 'UpdateProfileInput' type that excludes privileged fields — validation passes because the payload is well-typed, but the type itself doesn't encode which fields are client-settable."
  - "When asked to add a 'search' or 'filter' feature, AI assistants often generate raw SQL for dynamic column/table selection (since Prisma's query builder can't parameterize identifiers) and validate the column name with a regex or an inline check that's easy to get wrong, instead of a hardcoded allowlist array checked with `includes()`."
falsePositiveGuardrails:
  - "Prisma's standard query builder methods (`findMany`, `findUnique`, `create`, `update`, `where: { field: userInput }`, etc.) are parameterized and safe by default per Prisma's own documentation — do not flag ordinary query-builder usage as injection-prone just because it incorporates user input; the injection risk is specific to `$queryRawUnsafe`/`$executeRawUnsafe` and to `Prisma.raw()` misuse inside `$queryRaw`/`$executeRaw`."
  - "`$queryRawUnsafe`/`$executeRawUnsafe` used with its parameterized-call form (`$queryRawUnsafe('SELECT * FROM x WHERE id = $1', id)`) is NOT injectable — Prisma still escapes the substituted values in this form. Only flag it when the SQL string itself is built via concatenation/interpolation of request-derived values before being passed in."
  - "A `data:` object built from a request body IS safe if the code explicitly picks/destructures only allowed fields before constructing it (e.g. `const { name, email } = req.body; data: { name, email }` or a Zod schema with `.pick()`/`.omit()` that strips privileged fields) — confirm by reading the actual object literal or destructuring passed to `data:`, not just that `req.body` appears somewhere in the function."
  - "Do not flag mass assignment on models/fields that have no privilege, ownership, or trust implications (e.g. a `bio` or `displayName` field) — cite the specific sensitive field (role/isAdmin/verified/balance/ownerId/plan) that is reachable through the unguarded `data:` object before rating severity `critical` or `high`."
  - "Middleware-level protections count as mitigation if actually present and actually wired to the route in question — e.g. a global Prisma Client extension/middleware that strips privileged fields from `data:` on writes, or an authorization layer that rejects the request before it reaches the Prisma call for non-admin callers. Trace whether such a layer is genuinely active on this route before downgrading or dismissing a finding, not just present somewhere in the codebase."
  - "Raw queries built entirely from hardcoded strings or from server-controlled constants (feature flags, config, enum values not derived from request input) are not injectable regardless of `Unsafe` naming — confirm the dynamic portion actually traces back to client-controlled input before flagging."
---

## Root Cause Explanation

Prisma is designed to make SQL injection structurally hard by default: the
standard query builder (`findMany`, `where`, `create`, etc.) always
parameterizes values, and Prisma's own documentation is explicit that this
protection holds even when user input flows into `where` clauses. The
vulnerabilities in this playbook exist specifically where code steps *outside*
that safe default, in two independent ways that both show up disproportionately
in AI-assisted code because they look like reasonable, minimal-effort ways to
solve a real problem (dynamic queries, fast CRUD endpoints).

1. **Raw SQL injection via the "Unsafe" escape hatch.** Prisma exposes
   `$queryRawUnsafe`/`$executeRawUnsafe` for cases the query builder can't
   express (dynamic column/table names, complex dynamic filters). Prisma's
   docs describe these methods as accepting a raw string with "no
   parameterization" when used with string building, and warn they carry
   "significant risk" of SQL injection. The moment request-derived input is
   concatenated or template-literal-interpolated into that string, it's
   classic SQL injection — no different in kind from raw string-built SQL in
   any other language/ORM.
2. **A subtler bypass of the "safe" API.** Independent security research
   (Bounce Security's "Fun with SQL injection in Prisma ORM" series, and a
   corroborating prisma/prisma GitHub discussion) disclosed that even the
   tagged-template `$queryRaw`/`$executeRaw` — the API developers reach for
   specifically *because* it's marketed as safe — can be defeated by wrapping
   a value in `Prisma.raw()` inside the template, or by manually constructing
   an object shaped like Prisma's internal `Sql` type. Both techniques opt a
   specific interpolated value back out of parameterization while the
   surrounding call still looks like "the safe function." This matters for
   review because grep-for-`Unsafe` heuristics will miss it entirely — the
   vulnerable call site literally has "Raw" not "RawUnsafe" in its name.
3. **Mass assignment via unguarded `data:` objects.** Prisma's `create`/
   `update`/`upsert` methods accept a `data:` object that may contain any
   subset of the model's fields — Prisma applies no automatic allowlisting.
   If application code spreads an entire request body (or a loosely-typed DTO
   that mirrors the full model) into `data:`, a client can set *any* field
   that exists on that model, including ones the API was never designed to
   expose — `role`, `isAdmin`, `verified`, `balance`, `ownerId`. This is not a
   Prisma-specific novelty; it is the same class of bug that produced one of
   the most cited web security incidents in history (Egor Homakov's 2012
   GitHub/Rails hack, where an unguarded mass-assignment path let him attach
   his own SSH public key to another user's account by adding a `user_id`
   field to a form). Prisma's ORM ergonomics — "just spread the body into
   `data:`" being the fastest way to make an update endpoint work — make it
   easy for both AI assistants and humans to recreate that exact pattern
   today, model by model.

## Vulnerable Patterns

Look for shapes like these (illustrative — reason about equivalents in the
actual codebase, don't string-match):

```ts
// 1. Classic raw string-built SQL injection
const rows = await prisma.$queryRawUnsafe(
  `SELECT * FROM "User" WHERE email = '${req.query.email}'`
);

// 2. $queryRawUnsafe used correctly (parameterized) — NOT vulnerable
const rows = await prisma.$queryRawUnsafe(
  `SELECT * FROM "User" WHERE email = $1`, req.query.email
);

// 3. The "safe" API defeated via Prisma.raw() — still injectable
const sortCol = req.query.sort; // client-controlled
const rows = await prisma.$queryRaw`
  SELECT * FROM "User" ORDER BY ${Prisma.raw(sortCol)}
`;

// 4. Mass assignment — entire body written straight into data:
app.patch('/api/users/:id', async (req, res) => {
  const user = await prisma.user.update({
    where: { id: req.params.id },
    data: req.body, // client can send { role: 'admin', verified: true }
  });
  res.json(user);
});

// 5. Mass assignment via naive spread — still vulnerable
const user = await prisma.user.create({
  data: { ...req.body, id: undefined }, // only id is stripped
});
```

## Data Flow Tracing Guide

Trace the following before writing any Finding:

1. Grep for `$queryRawUnsafe`, `$executeRawUnsafe`, `$queryRaw`, `$executeRaw`,
   and `Prisma.raw(` across the codebase. For each call site, determine
   whether the SQL text (or any fragment passed via `Prisma.raw()`) is built
   from a literal string, a server-side constant/allowlisted value, or
   request-derived input (`req.query`, `req.body`, `req.params`, a decoded
   token claim, anything ultimately client-controlled).
2. For `$queryRawUnsafe`/`$executeRawUnsafe` specifically: is the call using
   the parameterized form (`sql, param1, param2, ...`) or is the entire query
   already a single interpolated/concatenated string by the time it's passed
   in? The parameterized form is safe even though the function name contains
   "Unsafe."
3. For `$queryRaw`/`$executeRaw` tagged templates: does any `${...}`
   interpolation wrap its value in `Prisma.raw()`, or construct an object
   with a `.sql`/`.values` shape manually? If so, trace that value back to
   its source the same way as step 1.
4. Grep for `.create({`, `.update({`, `.upsert({` across route
   handlers/services using this Prisma model. For each, inspect the literal
   object (or variable) passed to `data:`. Is it built by explicit field
   selection (destructuring named fields, a DTO type with only intended
   fields, `.pick()`/`.omit()` on a validation schema) or does it spread an
   object that originates from request input (`req.body`, `{ ...body }`, a
   parsed-but-unfiltered JSON payload)?
5. If `data:` does originate from request input, open the corresponding
   Prisma model definition (`schema.prisma`) and check which fields exist
   beyond the ones the endpoint is supposed to let clients set. Flag only the
   fields that carry real privilege/trust/financial meaning — call them out
   by name in the finding.
6. Check whether validation (Zod/Yup/class-validator/manual checks) runs
   before the Prisma call, and if so, whether that validation schema
   positively allowlists fields or merely checks types on whatever keys are
   present (a type check on `req.body.role` still allows `role` through if
   the schema doesn't explicitly exclude it).

## Evidence Checklist

Before submitting a Finding for this playbook, confirm:

- [ ] At least one concrete code snippet with exact file + line range is
      attached as evidence — do not paraphrase, quote the line(s).
- [ ] If claiming raw-SQL injection: the exact `$queryRawUnsafe`/
      `$executeRawUnsafe`/`$queryRaw`+`Prisma.raw()` call site is cited, and
      the trace from client input to that call site is shown (both
      endpoints).
- [ ] If claiming mass assignment: the exact `data:` object/spread is cited,
      AND the specific sensitive field(s) on the model (from `schema.prisma`
      or the generated client types) that are reachable through it are named
      explicitly — not a generic "spreads req.body" claim.
- [ ] Confirmed whether a validation/allowlisting layer exists upstream of
      the Prisma call and, if so, why it does not actually block the
      dangerous field(s) (e.g. schema uses `.passthrough()`, or the sensitive
      field happens to pass the declared type check).
- [ ] For raw-query findings, confirmed the interpolated/concatenated portion
      is genuinely request-derived and not a hardcoded/allowlisted value that
      merely resembles user input.

A finding without at least one concrete code-snippet evidence entry must not
be submitted.

## Attack Scenario Template

An attacker sends a request to [exact endpoint] with [field/parameter] set to
[malicious SQL fragment / privileged field-value pair, e.g.
`{"role": "admin"}`]. Because [specific code location] passes this value
[unparameterized into a raw SQL string / unfiltered into Prisma's `data:`
argument] without [missing check — parameterization / field allowlisting],
the resulting query executes with [concrete impact specific to this repo,
e.g. "the requesting user's own row updated to `role = 'admin'`, granting
access to `/admin/*` routes gated on that field" — not a generic
description].

Fill every bracket concretely with evidence gathered in the repo. If a
bracket can't be filled with real evidence, the scenario is speculative and
severity must be capped at `medium`, with a note that exploitability is
unconfirmed.

## Graph Mapping Instructions

- Always ensure `component:prisma_data_layer` exists (create it on any
  Prisma-related finding in this scan) with a `depends_on` edge to
  `component:database` and a `depends_on` edge from
  `component:api_input_handling`.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from `component:prisma_data_layer` (or
  a more specific component, e.g. `component:authorization` if the root
  cause is a missing allowlist that should have lived in an authorization
  layer) to the finding node.
- If a finding enables reaching a specific sensitive downstream capability
  (e.g. an admin panel gated on the `role` field that mass assignment can
  now set, or the underlying database itself for raw SQL injection), add an
  `enables` edge from the finding node to that component's node id.
- Root cause vs. symptom: if a finding is *caused by* another finding already
  identified in the scan (e.g. a missing-input-validation finding causes both
  the mass-assignment finding and a separate business-logic finding), say so
  explicitly in the finding's `reasoning` field so the graph mapper wires a
  `causes` edge between the finding nodes rather than treating them as
  unrelated.
