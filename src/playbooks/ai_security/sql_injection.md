---
id: ai_security.sql_injection
title: SQL Injection
category: ai_security
vulnerabilityClass: sql_injection
appliesToStack: any relational database access (raw drivers, query builders, ORM escape hatches)
requiresAnyTag: ["sql", "postgres", "prisma", "drizzle"]
deepOnly: false
reviewPass: 3
owaspRefs:
  - "A03:2021 Injection"
cweRefs:
  - "CWE-89"
  - "CWE-943"
realWorldReferences:
  - title: "MOVEit Transfer SQL injection (CVE-2023-34362) — the Cl0p mass-exploitation campaign that breached 2,700+ organizations and ~95M individuals"
    url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a"
    type: vendor_security_advisory
  - title: "Sequelize — SQL injection through JSON path keys / operator injection (CVE-2023-22578, GHSA-8h3w-2vmv-58wg)"
    url: "https://github.com/advisories/GHSA-8h3w-2vmv-58wg"
    type: vendor_security_advisory
  - title: "Prisma — raw query template helpers and the $queryRawUnsafe / $executeRawUnsafe interpolation footgun (docs on raw queries and SQL injection)"
    url: "https://www.prisma.io/docs/orm/prisma-client/using-raw-sql/raw-queries"
    type: security_blog
  - title: "GitLab disclosed on HackerOne: SQL injection in the DAST / project import path"
    url: "https://hackerone.com/reports/1626277"
    type: bug_bounty_disclosure
  - title: "PortSwigger Web Security Academy — SQL injection cheat sheet and authentication bypass labs"
    url: "https://portswigger.net/web-security/sql-injection"
    type: security_blog
quickModeSummary: >
  Find every place a SQL statement is assembled from a string that includes
  user input — template literals, `+` concatenation, f-strings, `.format()`,
  `%` formatting, or an ORM's "unsafe/raw" escape hatch (`$queryRawUnsafe`,
  `sequelize.query(str)`, `knex.raw("... " + x)`, `cursor.execute(f"...")`,
  Django `.extra()`/`RawSQL`, `EntityManager.createNativeQuery(str)`). The
  fix is always parameterized queries / bound placeholders — passing user
  values as parameters (`$1`, `?`, `:name`) separate from the query text, so
  the driver never parses them as SQL. Flag any query where a value reaches
  the SQL string itself rather than the parameter list, and treat
  identifiers (table/column names, `ORDER BY`, `LIMIT` direction) specially
  since those cannot be parameterized and must be validated against an
  allow-list instead.
fileSelectionHint:
  roles: ["route_handler", "controller", "model", "repository", "data_access", "service"]
  matchImports:
    ["pg", "mysql", "mysql2", "sqlite3", "better-sqlite3", "knex", "sequelize", "typeorm", "kysely", "psycopg2", "psycopg", "pymysql", "sqlalchemy", "prisma", "drizzle-orm"]
  matchAuthMapTags: ["sql", "database"]
  maxFiles: 10
  priorityOrder: ["repository", "data_access", "model", "route_handler", "controller"]
severityHeuristics:
  critical:
    - "User input is concatenated/interpolated into a SQL string used in an authentication, authorization, or account-lookup query (login, password/token check, tenant/ownership filter), enabling authentication bypass or cross-tenant data access"
    - "User input is concatenated/interpolated into a SQL string that reaches a raw execution path with no parameterization anywhere on the write side (INSERT/UPDATE/DELETE) or a stacked-query-capable driver, enabling data modification/destruction or (driver-dependent) stacked queries"
  high:
    - "User input is concatenated/interpolated into a SELECT over sensitive data with no parameterization, enabling reading of other users' or admin-only records via UNION/boolean/blind extraction"
    - "User-controlled value flows into a non-parameterizable clause (table/column identifier, ORDER BY column/direction, dynamic LIMIT/OFFSET) without an allow-list, enabling injection where placeholders can't help"
  medium:
    - "User input reaches a raw/query-builder escape hatch that is partially parameterized but interpolates at least one fragment (e.g. a WHERE built with placeholders but an ORDER BY built by concatenation), or where the parameterization is applied inconsistently across branches of the same handler"
    - "An ORM operator/JSON-path injection surface is reachable (e.g. Sequelize operator injection from a raw request object) where the ORM would otherwise parameterize scalar values"
  low:
    - "A raw query interpolates only server-side/trusted constants (no user-reachable path) but is written in a concatenation style that will become vulnerable the moment a maintainer wires user input into it — flag as a latent/hardening issue, and confirm no current user path before downgrading"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:database_access"
  relatedNodeIds: ["component:input_validation", "component:authentication"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:database_access"
    to: "component:input_validation"
  - relation: protects
    from: "component:input_validation"
    to: "component:database_access"
commonAiCodingMistakes:
  - "AI writes a query with a template literal because it reads more naturally than placeholders — `db.query(`SELECT * FROM users WHERE email = '${email}'`)` — not registering that the driver's parameterized form (`db.query('SELECT * FROM users WHERE email = $1', [email])`) is the whole point of the driver. This is the single most common shape and is a direct injection."
  - "AI reaches for an ORM's raw escape hatch (`$queryRawUnsafe`, `sequelize.query`, `knex.raw`, Django `.extra()`/`RawSQL`, SQLAlchemy `text()` with `.format()`) to express a query it couldn't figure out in the ORM's typed API, and interpolates user input into the raw string — bypassing exactly the parameterization the ORM would otherwise have provided. The `Unsafe` suffix / raw helper is the tell."
  - "AI parameterizes the WHERE clause correctly but builds `ORDER BY ${sortColumn}` or `LIMIT ${n}` by concatenation because those can't take placeholders — not recognizing that identifiers and keywords must instead be validated against a fixed allow-list of permitted column names / directions before interpolation."
  - "AI uses a tagged-template SQL library (Prisma `$queryRaw`, `sql` from postgres.js/slonik) correctly in one place, then in another place builds the same query with `$queryRawUnsafe` + string building for a 'dynamic' case, silently losing the safety the tagged template provided."
  - "AI passes a whole request object into an ORM `where` clause (Sequelize/TypeORM), letting an attacker inject operators or JSON-path keys the ORM interprets structurally — the SQL-world analogue of NoSQL operator injection (see the Sequelize CVE above)."
  - "AI adds escaping by hand (`value.replace(\"'\", \"''\")`) instead of parameterizing, missing numeric contexts, backslash/encoding edge cases, and identifier contexts — hand-rolled escaping is not a substitute for bound parameters and should itself be flagged."
falsePositiveGuardrails:
  - "Do not flag a query that uses bound parameters/placeholders for every user-controlled value (`$1`/`?`/`:name` with a separate values array, a tagged-template `sql` helper, or an ORM's typed query methods with scalar arguments) — that is the correct pattern. Confirm the value is actually in the parameter list, not interpolated into the string that precedes it."
  - "Do not flag a raw query whose interpolated parts are exclusively hardcoded constants or values derived entirely from server-side trusted state (a validated enum, a session-derived id already parameterized) — trace each interpolated fragment to its origin before flagging."
  - "For identifier/ORDER BY cases, if the user-controlled value is checked against a hardcoded allow-list (a `switch`/map from an input token to a fixed column name, or membership in a constant array) before being placed in the query, that is the correct non-parameterizable-clause pattern — confirm the allow-list is exhaustive and that the default branch rejects rather than falls through to raw input."
  - "An ORM's high-level methods (`findMany({ where: { email } })`, `.filter(email=...)`) parameterize scalar values by default — do not flag these as injection unless a raw/unsafe escape hatch or a whole-object operator-injection surface is actually involved."
  - "Do not treat the mere presence of the word `query` or a raw driver import as a finding — the vulnerability requires a user-controlled value reaching the SQL text itself; establish that data path with quoted evidence before flagging."
---

## Root Cause Explanation

SQL injection happens when user-controlled data is combined with SQL command
text in a way that lets the data change the *structure* of the statement
rather than only supplying *values*. Every mainstream database driver
supports parameterized queries (also called prepared statements or bound
parameters): the query text with placeholders (`$1`, `?`, `:name`) is sent to
the database separately from the parameter values, so the database plans the
statement first and then binds the values as pure data that can never be
re-parsed as SQL. Injection is, almost without exception, the result of
*not* using that mechanism — of building the statement as a string with the
values already baked in.

AI-generated code is especially prone to this because string interpolation
reads more naturally than placeholder syntax. A model asked to "look up a
user by email" will very often produce:

```js
const user = await db.query(`SELECT * FROM users WHERE email = '${email}'`);
```

which looks correct and passes a happy-path test, but lets an attacker who
submits `' OR '1'='1` (or `'; DROP TABLE ...`, or a `UNION SELECT` to
exfiltrate other tables) rewrite the query. The same failure recurs one
level up in ORMs: the ORM parameterizes by default, but every ORM ships an
"unsafe"/raw escape hatch for queries the typed API can't express, and AI
reaches for that escape hatch precisely when it's improvising — then
interpolates user input into it, discarding the ORM's protection. Prisma's
`$queryRawUnsafe`, Sequelize's `sequelize.query(string)`, Knex's `.raw()`
with concatenation, Django's `.extra()`/`RawSQL`, and SQLAlchemy's `text()`
combined with `str.format()` are the canonical footguns.

A second, subtler class involves query fragments that *cannot* be
parameterized: table and column identifiers, `ORDER BY` targets and
direction, and sometimes `LIMIT`/`OFFSET`. Placeholders only bind values,
not identifiers or keywords, so a "sort by user-chosen column" feature can't
be fixed by adding a `?`. These must be validated against a fixed allow-list
of permitted identifiers, mapping the untrusted input token to a known-safe
column name. AI frequently parameterizes the value clauses correctly and
then concatenates the `ORDER BY` column, leaving a real injection point in
otherwise-clean code.

## Vulnerable Patterns

```js
// Concatenation / template literal — classic injection
db.query("SELECT * FROM users WHERE email = '" + req.body.email + "'");
db.query(`SELECT * FROM orders WHERE id = ${req.params.id}`);
```

```ts
// ORM raw escape hatch defeating the ORM's own parameterization
await prisma.$queryRawUnsafe(`SELECT * FROM "User" WHERE email = '${email}'`);
await sequelize.query(`SELECT * FROM products WHERE name = '${name}'`);
knex.raw("SELECT * FROM t WHERE a = " + userValue);
```

```python
# f-strings / % / .format() into a cursor
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)  # % is string formatting here, NOT a placeholder
```

```ts
// Non-parameterizable clause built by concatenation
const rows = await db.query(
  `SELECT * FROM items ORDER BY ${req.query.sort} ${req.query.dir}`
);
```

Correct shapes:

```js
// Bound parameters — values travel separately from the SQL text
db.query("SELECT * FROM users WHERE email = $1", [email]);            // node-postgres
db.query("SELECT * FROM users WHERE email = ?", [email]);             // mysql2
```

```python
cursor.execute("SELECT * FROM users WHERE name = %s", (name,))        # %s is a placeholder here, tuple param
```

```ts
// Identifier allow-list for the non-parameterizable clause
const SORT_COLUMNS = { created: "created_at", name: "display_name" } as const;
const col = SORT_COLUMNS[req.query.sort as keyof typeof SORT_COLUMNS] ?? "created_at";
const dir = req.query.dir === "asc" ? "ASC" : "DESC";
await db.query(`SELECT * FROM items ORDER BY ${col} ${dir}`); // col/dir are from fixed sets, not user text
```

## Data Flow Tracing Guide

1. Enumerate every call that sends SQL to the database: raw driver calls
   (`.query`, `.execute`, `cursor.execute`), query-builder raw escapes
   (`.raw`, `sequelize.query`, `$queryRawUnsafe`/`$executeRawUnsafe`), and
   ORM raw-SQL helpers (Django `.extra`/`RawSQL`/`.raw`, SQLAlchemy `text`).
2. For each, determine how the SQL string is constructed. Is it a constant
   with placeholders and a separate values array/tuple, or is it built with
   `+`, template literals, f-strings, `%`, or `.format()`?
3. If the string is built by concatenation/interpolation, trace each
   interpolated fragment back to its origin. Does any fragment derive from
   `req`/request body/query/params, headers, a webhook payload, a message
   body, or any other attacker-reachable source?
4. Distinguish value contexts from identifier/keyword contexts. A
   user-controlled *value* must be parameterized; a user-controlled
   *identifier* (table/column/ORDER BY/direction) must be allow-listed.
   Confirm which one applies and whether the appropriate defense is present.
5. For ORMs, check whether a whole request object is passed into a `where`
   clause or JSON-path operation, which can allow operator/path injection
   even when scalar values would have been parameterized.
6. Establish reachability and purpose: authentication/authorization/ownership
   queries are critical (bypass / cross-tenant access); general data reads
   are high; writes without parameterization are critical. Cite the concrete
   route and the payload that reaches the query.

## Evidence Checklist

- [ ] Exact file + line range of the query execution call, with the SQL
      string argument shown.
- [ ] Exact file + line range showing the user-controlled origin of the
      interpolated fragment, traced through intermediate functions if needed.
- [ ] A statement of the context (value vs. identifier/keyword) and whether
      the correct defense (bound parameter vs. allow-list) is present,
      quoting any escaping/validation actually applied.
- [ ] A concrete injection payload (e.g. `' OR '1'='1`, a `UNION SELECT`, or
      an `ORDER BY (CASE WHEN ...)` blind probe) that the traced path would
      let reach the SQL text.
- [ ] What the query does (auth check, data read, write) to justify severity.

A finding without the execution call site, the user-controlled origin, and
the parameterization/allow-list status explicitly quoted must not be
submitted.

## Attack Scenario Template

> An attacker sends a request to [endpoint] with [parameter] set to
> [injection payload]. Because [file:line] builds the SQL string by
> [concatenation/interpolation/raw escape hatch] instead of using bound
> parameters, the payload is parsed as SQL, changing the query from
> [intended semantics] to [attacker-controlled semantics], resulting in
> [concrete impact: authentication bypass / disclosure of other tenants'
> rows via UNION / modification or deletion of data / blind extraction of
> the schema]. [If identifier context: because the ORDER BY column is taken
> from user input with no allow-list, the attacker injects a subquery/CASE
> expression to perform blind boolean extraction.]

Fill every bracket from evidence in this repo. If exact blast radius depends
on data you can't inspect, describe the injection mechanism concretely
without downgrading an auth-bypass- or write-capable finding.

## Graph Mapping Instructions

- Ensure a `component:database_access` node exists on the first SQL injection
  finding in a scan, with a `depends_on` edge to `component:input_validation`.
- Each concrete injection point becomes a `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from `component:database_access`.
- If the vulnerable query is part of an authentication/authorization flow,
  add an `enables` edge from the finding node to `component:authentication`
  and note the auth-bypass class in the finding's `reasoning` so severity
  aggregation weighs it as a bypass, not a generic data read.
- If several injection points share a single root cause (e.g. a shared raw
  query helper that concatenates), state that in `reasoning` so the mapper
  wires `causes` edges between them rather than treating them as unrelated.
