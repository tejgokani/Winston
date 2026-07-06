---
id: ai_security.nosql_injection
title: NoSQL Injection
category: ai_security
vulnerabilityClass: nosql_injection
appliesToStack: document/NoSQL data stores (MongoDB, Firestore, DynamoDB)
requiresAnyTag: ["mongodb", "dynamodb", "firebase"]
deepOnly: false
reviewPass: 3
owaspRefs:
  - "A03:2021 Injection"
cweRefs:
  - "CWE-943"
  - "CWE-89"
realWorldReferences:
  - title: "Rocket.Chat — Post-Auth Blind NoSQL Injection in users.list leaking password reset tokens and 2FA secrets (HackerOne #1130874)"
    url: "https://hackerone.com/reports/1130874"
    type: bug_bounty_disclosure
  - title: "Mongoose — NoSQL injection via nested $where under $or in populate() match, bypassing the CVE-2024-53900 fix (CVE-2025-23061)"
    url: "https://github.com/advisories/GHSA-vg7j-7cwx-8wgw"
    type: vendor_security_advisory
  - title: "Mongoose — Improper use of $where in match leads to search injection (CVE-2024-53900)"
    url: "https://github.com/advisories/GHSA-m7xq-9374-9rvx"
    type: vendor_security_advisory
  - title: "PortSwigger Web Security Academy — Exploiting NoSQL operator injection to bypass authentication"
    url: "https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-bypass-authentication"
    type: security_blog
  - title: "OWASP Testing Guide — Testing for NoSQL Injection"
    url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"
    type: security_blog
quickModeSummary: >
  Find every database query (MongoDB/Mongoose most common, but the same shape
  applies to any document/NoSQL store with operator-style query languages)
  where a filter/selector object is built directly from user input — e.g.
  `Model.findOne(req.body)` or `Model.find({ username: req.body.username,
  password: req.body.password })` — instead of extracting and type-checking
  individual scalar fields first. Because JSON request bodies let an attacker
  send `{"password": {"$ne": null}}` instead of a string, an unvalidated
  filter object lets query operators ($ne, $gt, $regex, $where, $or) reach
  the database engine, most dangerously in authentication checks where it
  produces a full login bypass.
fileSelectionHint:
  roles: ["route_handler", "controller", "auth", "model", "repository", "data_access"]
  matchImports: ["mongoose", "mongodb", "monk", "mongojs", "@nestjs/mongoose", "express-mongo-sanitize"]
  matchAuthMapTags: ["nosql", "mongodb"]
  maxFiles: 8
  priorityOrder: ["auth", "route_handler", "model", "repository"]
severityHeuristics:
  critical:
    - "A raw user-controlled object (whole `req.body`/`req.query`, or an unvalidated field taken from it) is passed directly into a `findOne`/`find`/`update`/`deleteOne` filter used for authentication or authorization (login, password check, session/token lookup, password reset token validation)"
  high:
    - "A raw user-controlled object reaches a query filter on non-auth but sensitive data (another user's records, admin-only resources), enabling data exfiltration or unauthorized access/modification via operator injection even though it's not a login bypass"
  medium:
    - "User input reaches a `$where` clause, a dynamically constructed `$regex`, or a query-building helper that evaluates expressions, but only after partial sanitization whose completeness is unclear (e.g. a global sanitizer is applied upstream but not confirmed to cover this specific route/middleware chain)"
  low:
    - "Operator injection is theoretically reachable but the field in question is independently constrained (e.g. cast to a specific type by an ORM schema, such as a strict Mongoose schema type that rejects non-scalar input) such that the operator-object payload would fail validation before reaching the query — confirm the cast/validation is enforced before downgrading, don't assume it"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:database_access"
  relatedNodeIds: ["component:authentication", "component:input_validation"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:database_access"
    to: "component:input_validation"
  - relation: protects
    from: "component:authentication"
    to: "component:database_access"
commonAiCodingMistakes:
  - "AI scaffolds a login handler as `User.findOne({ username: req.body.username, password: req.body.password })` (or the hashed-password equivalent, checking a hash comparison only after the findOne already ran an attacker-controlled operator) — this is the single most common NoSQL injection shape and produces a direct authentication bypass via `{\"$ne\": null}` or `{\"$gt\": \"\"}`, mirroring the exact pattern documented in PortSwigger's NoSQL injection lab and the Rocket.Chat disclosure above."
  - "AI passes an entire parsed request body into a query with `Model.find(req.body)` or `Model.updateOne(req.query, ...)` as a shortcut for 'flexible filtering,' without extracting and type-validating the specific fields the query is meant to accept — any key in the JSON body becomes a query operator or field selector at the attacker's discretion."
  - "AI adds input validation for SQL injection (parameterized queries, escaping quotes) out of habit, but doesn't recognize that MongoDB/NoSQL stores need a structurally different defense (rejecting non-scalar/operator-shaped input), since there's no query string to escape — the query IS a JavaScript/JSON object, so the injection surface is the object's shape, not its string content."
  - "AI uses a `$where` clause or constructs a dynamic `$regex` from user input for a 'search' feature, not recognizing that `$where` executes arbitrary JavaScript server-side (a much more severe primitive than operator injection alone) and that unescaped regex input enables ReDoS in addition to injection — this is the exact bug class behind CVE-2024-53900/CVE-2025-23061 in Mongoose's `populate()` handling."
  - "AI relies on a middleware sanitizer (e.g. `express-mongo-sanitize`) added early in scaffolding, but a later route added outside that middleware's chain (a new router, a different app instance, a GraphQL resolver, a WebSocket handler) bypasses it entirely while looking structurally identical to protected routes."
  - "AI assumes client-side form validation (an `<input type=\"text\">` that only submits strings) protects the server, not accounting for the fact that an attacker bypasses the browser entirely and sends a raw JSON body with `{\"$ne\": null}` directly to the API."
falsePositiveGuardrails:
  - "Do not flag a query filter built from individually-extracted, type-checked scalar values (e.g. `String(req.body.username)` or a schema-validated/typed field via Zod/Joi/Mongoose schema casting that rejects object values before the query executes) — this is the correct pattern; confirm the cast/validation actually runs before the value reaches the query, and that it rejects (not merely stringifies-and-passes-through) non-scalar input."
  - "Do not flag ORMs/ODMs that enforce a strict schema type on the field in question (e.g. a Mongoose schema declares `password: { type: String }`) without first confirming whether that cast actually strips or rejects operator objects for this library/version — some casting behaviors coerce rather than reject, which can still leave a bypass; state which behavior was confirmed."
  - "A query filter built entirely from server-side/trusted values (session-derived user ID, values looked up from another table, hardcoded constants) is not attacker-controlled input, even if it superficially resembles a vulnerable pattern — trace the actual origin before flagging."
  - "If `express-mongo-sanitize` (or equivalent) is present, confirm it is actually mounted on the specific route/middleware chain under review (not just imported/present elsewhere in the codebase) before treating that route as protected — a global sanitizer that isn't applied to a given router instance provides no protection for that router."
  - "Do not equate every use of `$` operators in application code with a vulnerability — operators supplied by the application's own code (not from user input) as part of legitimate query logic are normal and expected; the concern is specifically operators or object-shaped values that originate from request data."
---

## Root Cause Explanation

NoSQL injection in document databases like MongoDB is structurally different
from SQL injection, and that difference is exactly why AI-generated code
(and human code influenced by SQL-injection training) tends to miss it.
There's no query string to escape — a MongoDB query filter is a JSON/BSON
object, and the object's *shape* is the attack surface, not its string
content. Because HTTP frameworks parse JSON request bodies into arbitrary
nested objects by default, a client can send `{"password": {"$ne": null}}`
just as easily as `{"password": "hunter2"}`, and if that object is passed
into a query filter unmodified, MongoDB interprets `$ne` as the "not equal"
query operator rather than a literal password string.

The canonical exploit is authentication bypass:

```
POST /login
{"username": {"$ne": null}, "password": {"$ne": null}}
```

If the handler does `User.findOne({ username: req.body.username, password:
req.body.password })`, this query becomes "find a user whose username is not
null and whose password is not null" — true for essentially every real user
record — and the attacker is logged in as whichever document the database
returns first, with no valid credentials.

Beyond `$ne`, the broader operator surface includes `$gt`/`$lt` (range
bypass), `$regex` (pattern-based data extraction, and a ReDoS vector),
`$or`/`$and` (query restructuring), and most dangerously `$where`, which in
MongoDB accepts a raw JavaScript expression evaluated server-side — turning
an injection bug into de facto server-side code execution. This is the exact
mechanism behind Mongoose's CVE-2024-53900 and its bypass CVE-2025-23061,
where `$where` reached the query engine through nested operators inside
`populate()` even after an initial fix attempted to block the top-level
case — illustrating that partial/first-pass sanitization is easy to
bypass with a different nesting shape.

## Vulnerable Patterns

```js
// Classic authentication bypass — entire body used as the filter's values
app.post('/login', async (req, res) => {
  const user = await User.findOne({
    username: req.body.username,
    password: req.body.password,
  });
  if (user) return res.json({ token: issueToken(user) });
  res.status(401).end();
});
// Attacker sends: {"username":{"$ne":null},"password":{"$ne":null}}
```

```js
// Even more direct — the whole request body becomes the filter
app.post('/search', async (req, res) => {
  const results = await Product.find(req.body); // any key can be an operator
  res.json(results);
});
```

```js
// $where executes attacker-influenced JavaScript server-side
Model.find({ $where: `this.name == '${req.query.name}'` });
```

Correct shape extracts and type-checks each field before it reaches the
query, rejecting anything that isn't the expected primitive type:

```js
const username = String(req.body.username ?? '');
const password = String(req.body.password ?? '');
if (!username || !password) return res.status(400).end();
const user = await User.findOne({ username }); // then compare password hash separately, never in the filter
```

## Data Flow Tracing Guide

1. Find every call into the data layer that builds a filter/selector/update
   document: `find`, `findOne`, `findOneAndUpdate`, `updateOne`,
   `updateMany`, `deleteOne`, `count`, `aggregate` (via `$match`), and any
   custom repository/DAO wrapper around them.
2. For each, trace the filter object's construction back to its source.
   Is the entire object (or a nested sub-object) taken directly from
   `req.body`/`req.query`/`req.params`/parsed WebSocket or GraphQL input, or
   is each field individually extracted and cast to a specific primitive
   type (`String(...)`, `Number(...)`, a schema validator that rejects
   object-shaped input) before being placed into the filter?
3. If a field is extracted individually, confirm the extraction actually
   *rejects* non-scalar values rather than merely passing them through
   (e.g. `String({$ne: null})` produces the string `"[object Object]"` in
   JS — safe — but a validator that only checks `typeof x === 'string' ||
   typeof x === 'object'` or that stringifies without type-checking upstream
   may not).
4. Check for and validate the actual coverage of any sanitization middleware
   (`express-mongo-sanitize`, a custom recursive `$`-key stripper): is it
   mounted globally (`app.use(...)` before all routers) or only on specific
   routers? Does the route under review sit downstream of it?
5. Flag any use of `$where` or dynamically-built `$regex` fed by user input
   as a priority — these carry the highest severity ceiling (code execution
   / ReDoS) regardless of whether the immediate context is authentication.
6. Determine what the query is used for: authentication/authorization checks
   are critical severity by default (full bypass), general data queries are
   high (unauthorized data access/exfiltration), and internal/admin-only
   tooling not reachable pre-auth is comparatively lower priority — but
   still cite the concrete reachability.

## Evidence Checklist

- [ ] Exact file + line range of the query call (`findOne`/`find`/etc.) with
      the filter argument shown is cited.
- [ ] Exact file + line range showing the filter's user-controlled origin
      (request body/query/param) is cited, tracing through any intermediate
      functions if the origin and the query call are in different files.
- [ ] Any type-checking/casting/sanitization applied to the relevant field(s)
      before the query is quoted verbatim, with an explicit statement of
      whether it rejects or merely coerces non-scalar/operator-shaped input.
- [ ] A concrete payload (e.g. `{"password": {"$ne": null}}`) that would
      reach the query filter unmodified given the traced code path is
      provided.
- [ ] What the query is used for (authentication, data lookup, admin action)
      is stated, to justify the assigned severity.

A finding without the query call site, the user-controlled origin, and the
validation status (present-and-effective / present-but-bypassable / absent)
explicitly quoted must not be submitted.

## Attack Scenario Template

> An attacker sends a request to [specific endpoint] with
> [field]=[operator payload, e.g. `{"$ne": null}` or `{"$gt": ""}`] instead
> of the expected scalar value. Because [specific code location] passes
> [user-controlled object/field] directly into [query method] without
> [type-checking/casting that's missing], the resulting MongoDB query
> becomes [describe the effective query semantics, e.g. "match any document
> where password is not null"], which [matches every user record / matches
> the first document / bypasses the intended filter], resulting in
> [concrete impact: authentication bypass logging in as an arbitrary user /
> disclosure of records belonging to other users / a ReDoS via unescaped
> $regex].

Fill every bracket from evidence gathered in this repo. If the exact impact
depends on database contents you can't inspect (e.g. which document would be
returned first), describe the mechanism concretely and note that exact blast
radius is environment-dependent, without downgrading severity for an
authentication-bypass-shaped finding — the bypass mechanism itself is the
critical fact, not which specific account gets reached first.

## Graph Mapping Instructions

- Ensure a `component:database_access` node exists on the first NoSQL
  injection finding in a scan, with a `depends_on` edge to
  `component:input_validation`.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from `component:database_access` to
  the finding node.
- If the finding is in an authentication/login flow, add an `enables` edge
  from the finding node to `component:authentication`, and flag in the
  finding's `reasoning` field that this is an authentication-bypass-class
  finding so downstream severity aggregation weighs it correctly (a
  bypassable login check should not be diluted by being graphed identically
  to a low-impact data query injection).
- If the finding involves `$where` or dynamic `$regex` construction, add a
  `causes` edge from the finding node toward a
  `component:remote_code_execution`-equivalent node if the graph schema in
  use supports one, since `$where` executes server-side JavaScript.
- If a finding is caused by another finding already identified in this scan
  (e.g. a missing global-sanitizer-mounting finding is the root cause behind
  several individually-vulnerable routes), state that explicitly in the
  finding's `reasoning` field so the graph mapper wires a `causes` edge
  between them rather than treating them as unrelated duplicates.
