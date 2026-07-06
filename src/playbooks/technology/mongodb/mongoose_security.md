---
id: technology.mongodb.mongoose_security
title: Mongoose / MongoDB Security Beyond Operator Injection
category: technology
vulnerabilityClass: broken_access_control_and_data_layer_trust
appliesToStack: mongoose
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A01:2021 Broken Access Control"
  - "A03:2021 Injection"
  - "A08:2021 Software and Data Integrity Failures"
cweRefs:
  - "CWE-284"
  - "CWE-639"
  - "CWE-95"
  - "CWE-915"
realWorldReferences:
  - title: "Mongoose — Improper use of $where in match leads to search injection (CVE-2024-53900)"
    url: "https://github.com/advisories/GHSA-m7xq-9374-9rvx"
    type: vendor_security_advisory
  - title: "Mongoose — NoSQL injection via nested $where under $or in populate() match, bypassing the CVE-2024-53900 fix (CVE-2025-23061)"
    url: "https://github.com/advisories/GHSA-vg7j-7cwx-8wgw"
    type: vendor_security_advisory
  - title: "Two critical vulns in Mongoose could lead to stolen MongoDB data, RCE (The Register)"
    url: "https://www.theregister.com/2025/02/20/mongoose_flaws_mongodb/"
    type: security_blog
  - title: "Rocket.Chat — Post-Auth Blind NoSQL Injection in users.list leaking password reset tokens and 2FA secrets (HackerOne #1130874)"
    url: "https://hackerone.com/reports/1130874"
    type: bug_bounty_disclosure
quickModeSummary: >
  Beyond operator injection ($ne/$gt/$regex — covered by the NoSQL injection
  playbook), check three Mongoose-specific gaps: (1) does every query that
  returns or mutates a document scope it to the requesting user/tenant (e.g.
  `{ _id, ownerId: req.user.id }`), or does the app rely on the client
  supplying a correct document ID with no ownership check — Mongoose has no
  row-level-security equivalent, so any query without an explicit scope
  filter has full-collection reach; (2) does any code path let request input
  reach a `$where` clause or a `$function`/`$expr` with `$where`-like raw JS
  evaluation, which executes arbitrary server-side JavaScript; (3) is
  `strict` mode disabled (`strict: false`) on any schema, or bypassed via
  `Model.collection.insertOne`/raw driver calls, allowing clients to write
  unexpected fields onto documents.
fileSelectionHint:
  roles: ["route_handler", "controller", "model", "repository", "data_access", "middleware"]
  matchImports: ["mongoose"]
  matchAuthMapTags: ["mongodb"]
  maxFiles: 8
  priorityOrder: ["model", "repository", "route_handler", "controller"]
severityHeuristics:
  critical:
    - "User-controlled input reaches a `$where` clause, `$function` body, or `$accumulator` with raw JavaScript — arbitrary server-side code execution against the database process."
    - "A query/mutation that returns or modifies another user's data has no ownership/tenant scoping filter at all (e.g. `Model.findById(req.params.id)` used for a private resource with no `ownerId`/`tenantId` check anywhere in the handler), and the ID is guessable or enumerable."
  high:
    - "`strict: false` is set on a schema whose documents include privilege/trust fields (role, isAdmin, verified, balance, tenantId, planId), allowing a client-supplied field to be persisted even though it isn't declared in the schema."
    - "Authorization is checked via a global middleware but a specific route/service function bypasses it by calling the model directly (e.g. an internal service function reused by both an admin job and a public route, with no per-call scope re-check)."
  medium:
    - "Ownership scoping exists but is applied inconsistently — e.g. present on `findOne`/`updateOne` but missing on the corresponding `deleteOne`/aggregate variant for the same resource."
    - "`select: false` / field projection is relied on as the only mechanism hiding sensitive fields (password hash, internal flags) from API responses, with no test or code path verifying it's applied on every read path (including `.lean()` queries and aggregation pipelines, which can silently include excluded fields)."
  low:
    - "Schema uses `strict: 'throw'` inconsistently across nested subdocuments without `useNestedStrict`, creating a hardening gap without a demonstrated exploitable path yet."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:mongoose_data_layer"
  relatedNodeIds: ["component:database", "component:authorization"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:mongoose_data_layer"
    to: "component:database"
  - relation: depends_on
    from: "component:authorization"
    to: "component:mongoose_data_layer"
commonAiCodingMistakes:
  - "AI scaffolds a CRUD resource handler with `Model.findById(req.params.id)` (or `findOneAndUpdate`/`deleteOne` by ID alone) because that's the simplest working query, and never adds an `ownerId`/`tenantId` filter — MongoDB has no concept of row-level security, so unlike a Postgres table with RLS policies, every Mongoose query has full-collection reach unless the application code adds the scope itself. This pattern is the single most common access-control gap in AI-generated MongoDB code."
  - "AI 'fixes' a validation error caused by an unexpected field by setting `strict: false` on the schema (or removing `strict: true`) instead of adding the field to the schema or stripping it from the input — this silently converts a validation failure into a mass-assignment hole, since any field the client sends now persists to the document even though it was never declared."
  - "AI implements a dynamic filter/sort/search feature and builds part of the query as a template string evaluated via `$where` (or constructs a `$expr`/`$function` body from user input) because it's the most direct way to express 'match records where some computed condition on user input holds' — not recognizing that `$where` and `$function` evaluate arbitrary JavaScript server-side, unlike every other Mongo query operator."
  - "AI writes an authorization check once in a shared middleware for the primary CRUD routes generated in one prompt, then in a later prompt adds a new route or a background job / webhook handler that calls the same Mongoose model directly, forgetting the equivalent scope check because the model itself enforces nothing — the access-control logic lives entirely in application code that AI assistants tend to duplicate per-route rather than centralize."
  - "AI relies on `select: false` in the schema definition to hide sensitive fields (password hashes, internal tokens) from API responses, then later adds a `.lean()` query or an `$aggregate`/`$project` pipeline for a new feature that bypasses the schema-level projection default, re-exposing the field without anyone noticing because the original protection worked in the routes it was originally added to."
falsePositiveGuardrails:
  - "Do not flag every ID-based query as an access-control gap — first confirm the resource is actually private/scoped to a user or tenant (not a globally-readable resource like a public product catalog) before treating a missing ownership filter as a Finding."
  - "`$where` usage with a hardcoded, non-user-influenced JavaScript string (e.g. a fixed comparison the codebase always uses, containing no interpolation of request-derived values) is not RCE-capable — confirm the exact string is built with request-derived interpolation/concatenation before citing this as critical; this mirrors the NoSQL injection playbook's data-flow requirement, don't flag `$where` presence alone."
  - "`strict: false` is not automatically a Finding on schemas with no privilege/trust fields (e.g. a free-form metadata/settings collection intentionally designed to accept arbitrary keys) — name the specific sensitive field that becomes writable before assigning high/critical severity, the same standard applied to Prisma mass-assignment findings."
  - "If authorization is enforced by a `pre('find')`/`pre('findOne')`/`pre('updateOne')` Mongoose query middleware (a `.pre()` hook that injects the ownership filter automatically for every query on the model) do not flag individual route handlers that omit an explicit filter — verify whether such a global hook exists and is actually registered on the schema before concluding scoping is missing."
  - "Do not conflate this playbook's access-control findings with operator-injection findings covered by the NoSQL injection playbook (`ai_security/nosql_injection.md`) — if the missing scoping and an unsanitized filter object both exist on the same query, cite both playbooks' evidence separately rather than merging them into one finding, since they have different root causes and different fixes (add a scope filter vs. type-check/validate input)."
---

## Root Cause Explanation

Most Mongoose/MongoDB security guidance (including this project's own
`ai_security/nosql_injection.md` playbook) focuses on operator injection —
attacker-controlled query operators like `$ne`/`$gt`/`$regex` reaching a
filter object. That's a real and common bug class, but it is not the only
way Mongoose-backed applications end up broken. This playbook covers three
different, non-overlapping root causes that show up just as often in
AI-assisted code and are easy to miss because they don't look like
"injection" at all:

1. **No row-level-security equivalent.** Relational databases with RLS
   (Postgres, and platforms like Supabase built on it) can enforce
   "a user may only see rows where `owner_id = current_user`" *at the
   database layer*, independent of application code. MongoDB and Mongoose
   have no such mechanism — every query issued through a Mongoose model has
   full read/write access to the entire collection by default. Any scoping
   ("only this user's documents") has to be added explicitly, on every
   single query, by application code. This makes the failure mode
   structural rather than incidental: a developer (or an AI assistant) who
   writes `Order.findById(req.params.id)` has written a query that is
   *correct* in the sense that it runs and returns the right shape of data,
   but has silently granted every authenticated (or even unauthenticated)
   caller access to every order in the collection, not just their own. There
   is no schema-level flag to catch this, no exception thrown, and no
   framework warning — it looks identical to a correctly-scoped query until
   someone tries an ID that isn't theirs.
2. **`$where` and raw-JS evaluation operators.** MongoDB's query language
   includes `$where` (and, in aggregation pipelines, `$function`/
   `$accumulator` with a JS body), which accept a JavaScript expression or
   function evaluated server-side against each document. This is
   fundamentally different from every other query operator — it's not
   pattern matching or comparison, it's code execution. If any part of that
   JavaScript string or function body is built from user input, the
   application has a server-side JavaScript execution vulnerability, not
   just an authorization or filtering bug. This is the exact mechanism
   behind Mongoose's real disclosed CVE-2024-53900, where `$where` reached
   the query engine through `populate()`'s `match` option, and its bypass
   CVE-2025-23061, where the initial patch blocked only the top-level case
   and was defeated by nesting `$where` inside `$or`.
3. **Missing `strict` mode (mass-assignment-adjacent).** Mongoose schemas
   default to `strict: true`, meaning fields not declared in the schema are
   silently dropped rather than persisted — this is Mongoose's closest
   analog to an allowlist. When `strict` is turned off (often to work around
   a validation error during scaffolding, or to support "flexible" documents)
   or bypassed by dropping to the raw MongoDB driver (`Model.collection.
   insertOne(req.body)`), any field the client includes in a request body
   gets written to the document, whether or not the application intended to
   expose it. This is structurally the same bug as Prisma's unguarded
   `data:` mass assignment (see `technology/prisma/query_safety.md`) and the
   same class of bug behind the 2012 GitHub/Rails mass-assignment incident —
   just reached through a different ORM's escape hatch.

## Vulnerable Patterns

```js
// 1. No ownership/tenant scoping — any authenticated user can read/edit
//    any order by guessing or enumerating IDs
app.get('/api/orders/:id', requireAuth, async (req, res) => {
  const order = await Order.findById(req.params.id); // no ownerId check
  res.json(order);
});

// Same bug on a mutation — full account takeover of arbitrary resource state
app.patch('/api/orders/:id', requireAuth, async (req, res) => {
  const order = await Order.findByIdAndUpdate(req.params.id, req.body);
  res.json(order);
});

// Correct shape — scope every query to the authenticated principal
const order = await Order.findOne({ _id: req.params.id, ownerId: req.user.id });
if (!order) return res.status(404).end(); // 404, not 403 — don't leak existence

// 2. $where reachable with request-derived input — server-side JS execution
const results = await Model.find({
  $where: `this.name.indexOf('${req.query.search}') >= 0`,
});

// 3. strict mode disabled — any field in req.body persists
const FlexibleSchema = new mongoose.Schema({ name: String }, { strict: false });
await FlexibleModel.create(req.body); // client can set role, isAdmin, etc.

// Bypassing schema validation entirely via the raw driver
await Model.collection.insertOne(req.body); // no Mongoose validation/strict applies at all
```

## Data Flow Tracing Guide

Trace the following before writing any Finding:

1. **Scoping.** For every route/service that reads, updates, or deletes a
   single document by ID (`findById`, `findOne({ _id })`,
   `findByIdAndUpdate`, `findByIdAndDelete`, and their non-`ById` filter
   equivalents), check whether the filter object includes an
   ownership/tenant field (`ownerId`, `userId`, `tenantId`, `orgId`, or
   equivalent) tied to the authenticated principal (`req.user.id` or
   similar) — not just the resource's own `_id`. If the filter is `_id`
   alone, confirm the resource is actually meant to be globally readable
   before flagging (see guardrails) — a private resource (order, message,
   document, profile) with `_id`-only scoping is the finding.
2. Check whether a global scoping mechanism exists instead of a per-route
   filter: a Mongoose `pre('find')`/`pre('findOne')`/`pre('updateOne')`/
   `pre('deleteOne')` query middleware hook that injects the tenant/owner
   filter automatically. If present and registered on the schema in use,
   individual routes don't need their own explicit filter — verify the hook
   is actually attached (`schema.pre(...)` call site) and actually runs for
   the query methods used by the route under review (Mongoose query
   middleware only fires for the specific method names it's registered on).
3. **`$where`/raw-JS operators.** Grep for `$where`, `$function`,
   `$accumulator` across query and aggregation-pipeline code (including
   inside `populate()`'s `match` option, which is where CVE-2024-53900 and
   CVE-2025-23061 both hid). For each hit, trace whether the JS
   string/function body is a hardcoded literal or is built via
   concatenation/interpolation of request-derived input.
4. **`strict` mode.** Grep schema definitions (`new mongoose.Schema(...)`)
   for `strict: false` or `strict: 'throw'` absence combined with sensitive
   fields on the model. Also grep for direct raw-driver usage
   (`Model.collection.insertOne`/`updateOne`/`bulkWrite`) which bypasses
   Mongoose schema validation and `strict` entirely regardless of the
   schema's own setting.
5. For any mass-assignment-shaped finding (`strict: false` or raw-driver
   write), open the schema definition and name the specific sensitive
   field(s) (role, isAdmin, verified, balance, tenantId, planId) that become
   client-writable — the same evidentiary bar as the Prisma playbook's
   mass-assignment findings.
6. Cross-check field-hiding assumptions: if the code relies on
   `select: false` in the schema to keep a field (password hash, token) out
   of API responses, check every read path for that model — plain queries,
   `.lean()` queries, and `$project`/aggregation pipelines each apply (or
   fail to apply) that default independently.

## Evidence Checklist

Before submitting a Finding for this playbook, confirm:

- [ ] At least one concrete code snippet with exact file + line range is
      attached as evidence — do not paraphrase, quote the line(s).
- [ ] If claiming missing ownership/tenant scoping: the exact query call
      site is cited, AND confirmation is given that no global scoping
      middleware (`pre()` hook) covers this query method on this schema.
- [ ] If claiming missing scoping: confirmation that the resource is
      genuinely private (not an intentionally public/global collection) is
      stated explicitly.
- [ ] If claiming `$where`/`$function` code execution: the exact call site
      is cited, AND the trace from request-derived input to the JS
      string/function body is shown.
- [ ] If claiming a mass-assignment/`strict` issue: the schema's `strict`
      setting (or raw-driver bypass) is cited, AND the specific
      privilege/trust field(s) on the model that become client-writable are
      named explicitly.

A finding without at least one concrete code-snippet evidence entry must not
be submitted.

## Attack Scenario Template

> An attacker who is authenticated as [any low-privilege user] requests
> [specific endpoint] with [resource ID belonging to another user/tenant].
> Because [specific code location] queries the collection using [filter
> shown, e.g. `findById(req.params.id)`] without a matching
> [ownerId/tenantId] scope check, the query returns/modifies
> [specific resource type] belonging to a different [user/tenant], resulting
> in [concrete impact: cross-tenant data disclosure / unauthorized
> modification of another user's data / arbitrary server-side JS execution
> via $where, specific to this repo — not a generic description].

Fill every bracket concretely from evidence gathered in this repo. If a
bracket can't be filled from real evidence (e.g. IDs aren't sequential or
guessable and no enumeration path is evident), the scenario is speculative
and severity must be capped at `medium`, with a note that exploitability
depends on ID predictability/leakage elsewhere in the app.

## Graph Mapping Instructions

- Always ensure a `component:mongoose_data_layer` node exists (create it on
  the first Mongoose-related finding in a scan) with a `depends_on` edge to
  `component:database`, and a `depends_on` edge from
  `component:authorization` to `component:mongoose_data_layer`.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from `component:mongoose_data_layer`
  (or `component:authorization` specifically, if the root cause is a missing
  scope filter rather than a data-layer bug) to the finding node.
- If a finding involves `$where`/`$function` reachable from user input, add a
  `causes` edge from the finding node toward a
  `component:remote_code_execution`-equivalent node if the graph schema in
  use supports one.
- If a finding involves cross-tenant/cross-user data exposure, add an
  `enables` edge from the finding node to `component:authorization` to
  reflect that the access-control boundary itself is compromised, not just a
  single data point.
- Do not merge this playbook's findings with `ai_security/nosql_injection.md`
  findings on the same query — if both a missing-scope issue and an
  operator-injection issue exist on the same call site, create two distinct
  finding nodes and note the shared call site in each finding's `reasoning`
  field rather than collapsing them into one finding (they have different
  root causes and different remediations).
