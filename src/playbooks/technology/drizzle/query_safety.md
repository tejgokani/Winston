---
id: technology.drizzle.query_safety
title: Drizzle ORM Query Safety
category: technology
vulnerabilityClass: sql_injection_and_mass_assignment
appliesToStack: drizzle
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A03:2021 Injection"
  - "A08:2021 Software and Data Integrity Failures"
cweRefs:
  - "CWE-89"
  - "CWE-915"
realWorldReferences:
  - title: "Drizzle ORM has SQL injection via improperly escaped SQL identifiers (GHSA-gpj5-g38j-94v9, CVE-2026-39356)"
    url: "https://github.com/drizzle-team/drizzle-orm/security/advisories/GHSA-gpj5-g38j-94v9"
    type: vendor_security_advisory
  - title: "Drizzle ORM — Magic sql`` operator (official docs on parameter binding vs. sql.raw())"
    url: "https://orm.drizzle.team/docs/sql"
    type: vendor_security_advisory
  - title: "Drizzle ORM — Insert (official docs)"
    url: "https://orm.drizzle.team/docs/insert"
    type: vendor_security_advisory
  - title: "Does Drizzle guard against SQL injections? (drizzle-orm Discussion #446)"
    url: "https://github.com/drizzle-team/drizzle-orm/discussions/446"
    type: security_blog
quickModeSummary: >
  Check every use of the `sql` template tag: are dynamic values interpolated
  as normal `${value}` template placeholders (safely parameterized by
  Drizzle) or passed through `sql.raw(...)`/`.inlineParams()`/string
  concatenation before reaching `sql` (bypasses parameterization entirely —
  real SQL injection)? Also check `sql.identifier()`/`.as()`/dynamic
  column-or-table-name construction for attacker-controlled input, since
  identifier escaping is a separate, weaker guarantee than value
  parameterization (see CVE-2026-39356). Separately, check every
  `.insert(table).values(...)` and `.update(table).set(...)` call: is the
  argument an explicitly constructed object with a fixed, known field list,
  or is it (or does it spread) a request body / user-controlled object
  directly? The latter is mass assignment — it lets a client set fields
  (role, isAdmin, ownerId, price, verified) the endpoint never intended to
  expose.
fileSelectionHint:
  roles: ["database", "repository", "route_handler", "model"]
  matchImports: ["drizzle-orm", "drizzle-orm/sql", "drizzle-orm/pg-core", "drizzle-orm/mysql-core", "drizzle-orm/sqlite-core"]
  matchAuthMapTags: ["drizzle"]
  maxFiles: 8
  priorityOrder: ["repository", "route_handler", "database"]
severityHeuristics:
  critical:
    - "Untrusted input (request body/query/param, header, or any value originating from an HTTP request) reaches `sql.raw(...)`, `.inlineParams()`, or is string-concatenated/template-literal-built into a query string before being passed to `sql`/`db.execute` — full SQL injection, equivalent to raw string-built SQL."
    - "`.insert(table).values(req.body)` or `.update(table).set(req.body)` (or a shallow spread of it, e.g. `{...req.body}` or `{...req.body, updatedAt: new Date()}`) is used directly on a table that has privileged/sensitive columns (role, isAdmin, permissions, ownerId, verified, balance, price) reachable by a non-privileged caller — mass assignment lets the client set those columns."
  high:
    - "Untrusted input reaches `sql.identifier()`, `.as()`, or any dynamic column/table-name construction (e.g. building an `ORDER BY` clause from a user-supplied sort field name) without an allowlist check against known column/table names — identifier escaping has weaker guarantees than value parameterization and was the subject of a disclosed Drizzle CVE (GHSA-gpj5-g38j-94v9)."
    - "`.values()`/`.set()` is built from a request body with a denylist (removing a few known-dangerous fields) rather than an allowlist (picking only known-safe fields) — any new sensitive column added to the schema later is unprotected by default."
  medium:
    - "A helper function wraps `.insert()`/`.update()` and accepts a loosely-typed object (e.g. `Record<string, unknown>` or `any`) as its values argument, making it easy for a future caller to pass an unvalidated object through even if current call sites are safe — a latent mass-assignment risk."
    - "Normal `${value}` interpolation inside `sql` template tag is used correctly, but the surrounding TypeScript types are widened with `as any`/`as unknown`, silently permitting a caller to pass a raw SQL fragment object where a plain value was expected."
  low:
    - "Dynamic sort/filter field names are validated against an allowlist but the allowlist is maintained separately from the schema and could drift out of sync — defense-in-depth gap, not itself exploitable today."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:drizzle_orm"
  relatedNodeIds: ["component:database", "component:data_access_layer", "component:authorization"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:data_access_layer"
    to: "component:drizzle_orm"
  - relation: protects
    from: "component:drizzle_orm"
    to: "component:database"
  - relation: depends_on
    from: "component:drizzle_orm"
    to: "component:authorization"
commonAiCodingMistakes:
  - "AI reaches for `sql.raw(...)` or plain string interpolation (backtick template literals, not the `sql` tag) to build a dynamic `WHERE`/`ORDER BY` clause when the field name itself is variable, because it doesn't realize `sql` tag placeholders (`${value}`) only parameterize *values*, not identifiers — and grabs the nearest-looking escape hatch instead of `sql.identifier()` plus an allowlist."
  - "AI writes a generic 'create' or 'update' handler that does `.values(req.body)` or `.set({ ...req.body, updatedAt: new Date() })` for convenience/brevity during scaffolding, intending to 'add validation later,' and the allowlist/pick step never gets added once the endpoint works in manual testing."
  - "AI generates a PATCH endpoint that spreads the parsed body directly into `.set()` reasoning 'the schema types will catch bad fields' — but Drizzle's `.set()` typing only enforces that provided keys exist on the table and have the right *type*, it does not restrict which of the table's columns a given endpoint is allowed to write, so role/ownerId/price fields typed correctly by an attacker pass straight through."
  - "AI copies a working sql-tagged template pattern (e.g. sql`...${value}...`) for a new dynamic-sort feature but changes it to interpolate the column name itself as a plain value (sql`ORDER BY ${sortColumn}`), not recognizing that column/table names need `sql.identifier()` treatment, not value parameterization, and that user-controlled sort keys need an allowlist regardless."
falsePositiveGuardrails:
  - "Standard `${value}` interpolation inside the `sql` template tag (e.g. sql`SELECT * FROM users WHERE id = ${userId}`) is Drizzle's intended, parameterized, SQL-injection-safe usage — do not flag this pattern on its own. Only flag when `sql.raw()`, `.inlineParams()`, or string concatenation/template literals outside the `sql` tag are used to build the query text, or when identifier-construction helpers (`sql.identifier()`, `.as()`) receive unsanitized user input."
  - "`.insert()`/`.update()` calls built from an explicitly constructed object literal with a fixed field list (e.g. `.values({ title: input.title, body: input.body })`) are safe even if `input` itself originated from a request body — the allowlisting already happened at the object-literal boundary. Only flag when the request-derived object (or a broad spread of it) is passed as the values/set argument wholesale."
  - "A spread of a request body is not automatically mass assignment if it's spread into an object that's then explicitly overwritten/narrowed for every sensitive field before being passed to `.values()`/`.set()` (e.g. `{...req.body, role: 'user', ownerId: session.userId}` where every privileged field is force-set after the spread) — trace whether the sensitive columns are actually reachable by the attacker-controlled portion, not just whether a spread syntax appears."
  - "If the table being written to has no privileged/sensitive columns at all (e.g. a purely user-owned scratch/preferences table with no role, ownership, or financial fields), a spread-based `.values()`/`.set()` is lower severity — check the actual schema definition for the target table before assuming critical severity, and downgrade to medium if no sensitive column exists."
  - "`sql.raw()` used with a compile-time-constant string (not runtime user input) — e.g. building a migration helper or a fixed DDL fragment — is not injectable. Trace the actual origin of the value passed to `sql.raw()`/`.inlineParams()` back to confirm it is runtime, request-derived data before flagging."
---

## Root Cause Explanation

Drizzle ORM's core safety guarantee — and the place that guarantee is easiest
to accidentally step outside of — comes down to a single distinction: the
`sql` template tag parameterizes **values**, not arbitrary SQL text. Query
safety failures in Drizzle codebases cluster around two root causes:

1. **Bypassing parameterization for dynamic SQL text.** When you write
   `` sql`SELECT * FROM users WHERE id = ${userId}` ``, Drizzle rewrites the
   `${userId}` placeholder into a driver-level bind parameter (`$1`, `?`,
   etc.) and sends the value separately from the query text — this is what
   actually prevents SQL injection, the same mechanism as a parameterized
   query in any other stack. But Drizzle also exposes escape hatches for
   cases the tag can't express: `sql.raw(...)` inserts a string directly into
   the query with **no** escaping at all, and `.inlineParams()` explicitly
   opts out of parameter binding by inlining values into the string. Both
   are legitimate for genuinely trusted, non-runtime-derived input (a fixed
   table name known at code-authoring time, a literal SQL fragment). The
   vulnerability appears the moment request-derived data flows into either
   of those escape hatches, or into hand-built string concatenation used to
   assemble a query before it's ever passed to `sql`/`db.execute` — at that
   point Drizzle provides no protection whatsoever, identical to
   string-building raw SQL in any language.
2. **Identifier construction is a weaker, separate guarantee from value
   parameterization.** Column names, table names, and aliases can't be bind
   parameters in SQL (a placeholder can't stand in for `ORDER BY <col>`) so
   Drizzle instead escapes identifiers by quoting them via
   `sql.identifier()`/`.as()`-style helpers. This is real protection, but it
   is a different, narrower mechanism than parameter binding, and it has
   had real bugs: Drizzle disclosed CVE-2026-39356 (GHSA-gpj5-g38j-94v9)
   after finding that its dialect-specific identifier-escaping logic didn't
   correctly escape embedded quote/delimiter characters, letting an attacker
   who controlled an identifier-position value (a dynamic sort column, a
   report-builder alias) break out of the quoted identifier and inject SQL.
   The lesson generalizes beyond the specific patched bug: any codebase that
   passes user-controlled strings into identifier position — most commonly a
   "sort by `<field>`" or "group by `<field>`" feature built from a query
   param — needs an explicit allowlist against known column names, because
   identifier-escaping alone is a thinner safety margin than value binding
   and has a documented history of edge-case failures.
3. **Mass assignment via `.values()`/`.set()`.** Separately from SQL
   injection, Drizzle's insert/update API takes a plain object:
   `.insert(table).values({...})` and `.update(table).set({...})`. Drizzle's
   TypeScript types constrain which *keys* are valid columns and what *type*
   each value must be, but they say nothing about which columns a given API
   endpoint should be allowed to write. If application code passes a
   request body (or a shallow spread of it) directly as that object, any
   field the schema defines becomes settable by the client — including
   columns the endpoint's author never intended to expose, like `role`,
   `isAdmin`, `ownerId`, `verified`, or `price`. This is the same
   mass-assignment class that has caused real-world privilege-escalation and
   IDOR-adjacent bugs across many ORMs and web frameworks for over a decade;
   Drizzle does not have a first-class "permitted fields" concept the way
   some frameworks do, so the allowlisting responsibility sits entirely with
   application code, and it's easy to omit under time pressure or during
   AI-assisted scaffolding where the "happy path" object shape is written
   first and field restriction is meant to be a follow-up.

## Vulnerable Patterns

Look for shapes like these (illustrative, not exhaustive — reason about
equivalents in the actual codebase you're reviewing, don't string-match):

```ts
// Pattern 1: sql.raw() / string concatenation with runtime user input — real SQL injection
const rows = await db.execute(
  sql.raw(`SELECT * FROM users WHERE email = '${req.query.email}'`)
);
// or building the query text before it ever reaches `sql`:
const clause = `id = ${req.params.id}`;
await db.execute(sql`SELECT * FROM orders WHERE ${sql.raw(clause)}`);

// Pattern 2: unsanitized identifier construction (dynamic sort/order-by)
const sortField = req.query.sort; // client-controlled, e.g. "id; DROP TABLE users;--"
await db.execute(sql`SELECT * FROM products ORDER BY ${sql.identifier(sortField)}`);
// safe version: validate `sortField` against an allowlist of real column names first

// Pattern 3: mass assignment via unrestricted .values()/.set()
app.post("/api/users/:id", async (req, res) => {
  await db.update(users).set(req.body).where(eq(users.id, req.params.id));
  // req.body could include { role: "admin", verified: true } and both get written
});

app.post("/api/posts", async (req, res) => {
  await db.insert(posts).values({ ...req.body, authorId: session.userId });
  // spreading req.body first still lets it set e.g. `published`, `featured`, `id`
  // unless every sensitive field is force-overwritten AFTER the spread
});
```

The safe equivalents: use plain `${value}` interpolation inside `sql` for all
runtime values; validate any user-controlled identifier against a known
allowlist before passing it to `sql.identifier()`; and build `.values()`/
`.set()` from an explicit object literal that only includes the fields the
endpoint intends to accept (optionally validated by a schema library like
Zod/`drizzle-zod` first).

## Data Flow Tracing Guide

To evaluate this playbook responsibly, trace the following before writing any
Finding:

1. Find every call site of `sql.raw(...)` and `.inlineParams()` in the
   codebase. For each, trace the argument backward: is it a compile-time
   string literal / constant, or does it incorporate a variable? If a
   variable, trace that variable back to its origin — does it ultimately
   derive from `req.body`/`req.query`/`req.params`, a header, or any other
   request-controlled source? Cite the full chain from request input to the
   `sql.raw()` call.
2. Find every use of `sql.identifier()`, `.as(...)`, or any manually
   constructed identifier/column-name string used in a query. Trace its
   source the same way — is it a fixed set of known columns, or does it
   accept an arbitrary string from the request? If arbitrary, check whether
   an allowlist/switch/whitelist validation happens before it reaches the
   query — cite the validation code if present, or its absence if not.
3. Find every `.insert(table).values(arg)` and `.update(table).set(arg)`
   call. For each, determine whether `arg` is: (a) an object literal with an
   explicit, fixed field list — safe; (b) a variable that is itself an
   explicit object literal built elsewhere from named fields — safe, trace
   to confirm; (c) `req.body` (or equivalent parsed request payload) used
   directly, or a spread of it — mass-assignment candidate.
4. For any mass-assignment candidate from step 3, open the schema definition
   for the target table (`pgTable`/`mysqlTable`/`sqliteTable` definition)
   and list its columns. Identify which columns are privileged/sensitive in
   this application's context (role, permission, ownership, financial,
   verification-status fields) — this determines severity, since a spread
   into a table with no sensitive columns is a much smaller issue than one
   with an `isAdmin` column.
5. For any mass-assignment candidate, check whether the surrounding handler
   force-overwrites the sensitive fields after the spread (e.g. `{...req.
   body, role: 'user'}`) — if every sensitive column identified in step 4 is
   explicitly pinned after the spread, the finding does not hold; if any
   sensitive column is left unpinned, it does.

## Evidence Checklist

Before submitting a Finding for this playbook, confirm:

- [ ] At least one concrete code snippet with an exact file + line range is
      attached as evidence — do not paraphrase, quote the actual line(s).
- [ ] If claiming SQL injection via `sql.raw()`/`.inlineParams()`/string
      concatenation: the exact call site is cited, AND the backward trace to
      a request-derived source is shown (file + line where the value
      originates from `req.*` or equivalent).
- [ ] If claiming an identifier-injection issue: the exact `sql.identifier()`/
      `.as()`/raw-identifier call is cited, along with confirmation that no
      allowlist check occurs between the request-derived value and that
      call.
- [ ] If claiming mass assignment: the exact `.values()`/`.set()` call is
      cited, the target table's schema columns are listed, and the specific
      sensitive column(s) reachable through the unrestricted object are
      named explicitly (not "could include sensitive fields" — name them).
- [ ] For a mass-assignment finding, confirmation that no post-spread
      overwrite of the named sensitive column(s) exists in the same handler.

A finding without at least one concrete code-snippet evidence entry must not
be submitted.

## Attack Scenario Template

> An attacker sends a request to [specific endpoint/route] with [a crafted
> value in `sql.raw()`-reachable input / a crafted identifier string / an
> extra field in the request body, named concretely — e.g. `"role": "admin"`].
> Because [specific file:line] passes this value into [`sql.raw()` without
> escaping / `sql.identifier()` without an allowlist / `.values()`/`.set()`
> without field restriction], the resulting query [executes attacker-supplied
> SQL against the database / writes to the `[column name]` column the
> endpoint never intended to expose], resulting in [concrete impact specific
> to this repo — e.g. "an unauthenticated user can set their own `role`
> column to `admin` via `PATCH /api/users/:id`" or "arbitrary read of the
> `users` table via UNION-based injection in the search endpoint" — not a
> generic description].

Fill every bracket concretely from evidence gathered in this repo. If a
bracket can't be filled from real evidence, the scenario is speculative and
severity must be capped at `medium`, with a note that exploitability is
unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:drizzle_orm` node exists (create it on the first
  Drizzle-related finding in a scan) with a `depends_on` edge from
  `component:data_access_layer`.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from `component:drizzle_orm` (or
  `component:authorization` if the root cause is a missing field-allowlist
  rather than a raw-SQL escape hatch) to the finding node.
- If a SQL-injection finding allows reading or writing data outside the
  authorized scope, add an `enables` edge from the finding node to
  `component:database`. If a mass-assignment finding allows privilege
  escalation (writing a role/permission column), add an `enables` edge to
  `component:authorization`.
- Root cause vs. symptom: if a mass-assignment finding exists because a
  request-validation/schema layer (e.g. a missing Zod schema) never
  constrained the incoming payload before it reached `.values()`/`.set()`,
  say so explicitly in the finding's `reasoning` field so the graph mapper
  can wire a `causes` edge from the validation gap to this finding rather
  than treating the Drizzle call site as the sole root cause.
