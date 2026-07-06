---
id: technology.graphql.query_safety
title: GraphQL Query Safety (Introspection, Field Authorization, Query DoS)
category: technology
vulnerabilityClass: security_misconfiguration
appliesToStack: graphql
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A05:2021 Security Misconfiguration"
  - "A01:2021 Broken Access Control"
  - "A04:2021 Insecure Design"
cweRefs:
  - "CWE-200"
  - "CWE-862"
  - "CWE-400"
  - "CWE-770"
realWorldReferences:
  - title: "GraphQL.org — Security"
    url: "https://graphql.org/learn/security/"
    type: vendor_security_advisory
  - title: "Apollo GraphOS Docs — Graph Security Overview"
    url: "https://www.apollographql.com/docs/graphos/platform/security/overview"
    type: vendor_security_advisory
  - title: "Apollo Blog — 9 Ways To Secure your GraphQL API"
    url: "https://www.apollographql.com/blog/9-ways-to-secure-your-graphql-api-security-checklist"
    type: security_blog
  - title: "HackerOne Report #1132803 — GraphQL introspection is enabled"
    url: "https://hackerone.com/reports/1132803"
    type: bug_bounty_disclosure
  - title: "HackerOne Report #291531 — Introspection query leaks sensitive information"
    url: "https://hackerone.com/reports/291531"
    type: bug_bounty_disclosure
  - title: "How a GraphQL Bug Resulted in Authentication Bypass (HackerOne, 2023 Ambassador World Cup)"
    url: "https://www.hackerone.com/blog/how-graphql-bug-resulted-authentication-bypass"
    type: bug_bounty_disclosure
  - title: "How a GraphQL Misconfiguration Exposed Sensitive Information: A $25,000 Bug Bounty Report"
    url: "https://osintteam.blog/how-a-graphql-misconfiguration-exposed-sensitive-information-a-25-000-bug-bounty-report-a8207bc7ff11"
    type: bug_bounty_disclosure
  - title: "Bug Bounty Insights: 10 Key Findings — Broken Access Control in GraphQL"
    url: "https://medium.com/@maakthon/bug-bounty-findings-10-major-vulnerabilities-exposed-in-cloverleafs-application-bac-in-graphql-0ae1ee0eb4d5"
    type: bug_bounty_disclosure
  - title: "PortSwigger Web Security Academy — GraphQL API vulnerabilities"
    url: "https://portswigger.net/web-security/graphql"
    type: security_blog
quickModeSummary: >
  Three independent checks, don't conflate them: (1) Is introspection
  reachable in the production/non-staging environment for an API that isn't
  intentionally public? (2) Does every resolver that returns sensitive fields
  re-check authorization at the field/node level, or does the codebase only
  gate access at the top-level query/mutation and assume nested resolvers
  inherit that check? (3) Is there any enforced limit on query depth, breadth
  (aliasing/batching), or computed cost — or can a single request fan out into
  an unbounded number of resolver calls / DB queries? Each is a distinct,
  independently-fixable finding; do not merge them into one vague "GraphQL is
  insecure" finding.
fileSelectionHint:
  roles: ["route_handler", "middleware", "config", "resolver"]
  matchImports: ["graphql", "apollo-server", "@apollo/server", "graphql-yoga", "express-graphql", "graphql-depth-limit", "graphql-validation-complexity", "type-graphql", "nexus"]
  matchAuthMapTags: ["graphql"]
  maxFiles: 10
  priorityOrder: ["config", "route_handler", "resolver", "middleware"]
severityHeuristics:
  critical:
    - "A field resolver returns another user's or tenant's private data (PII, credentials, tokens, financial records) with no re-check of the caller's authorization for that specific node, reachable even when the parent/top-level query was itself gated"
    - "No query depth, complexity, or batch/alias limit is configured anywhere in the server setup, and at least one resolver performs an unbounded or recursive-relationship traversal (e.g. self-referential type like author->posts->author) reachable by an unauthenticated or low-privilege caller"
  high:
    - "Introspection is enabled with no environment gating on an API that is not intended to be a public developer-facing API, exposing the full schema (types, mutations, deprecated/internal fields) to any caller"
    - "Depth/complexity limiting exists for some resolvers/routers but a newly added resolver or subgraph is not covered by the shared validation rule"
  medium:
    - "Introspection is enabled in a genuinely public API but the schema itself exposes internal/debug fields or mutations not meant for external consumers"
    - "Rate limiting or timeout protections exist at the infra layer but no GraphQL-aware cost control exists, so a single cheap-looking request can still fan out into many backend calls (e.g. N+1 without DataLoader batching combined with nested list fields)"
  low:
    - "Introspection enabled in a non-production/staging environment that is properly network-isolated (informational only, verify isolation before concluding this is fine)"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:graphql_api"
  relatedNodeIds: ["component:authorization", "component:api_security", "component:rate_limiting"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:graphql_api"
    to: "component:authorization"
  - relation: protects
    from: "component:rate_limiting"
    to: "component:graphql_api"
  - relation: exposes
    from: "component:graphql_api"
    to: "component:api_security"
commonAiCodingMistakes:
  - "AI scaffolds a GraphQL server (Apollo Server / graphql-yoga / express-graphql) with introspection left at its framework default (often enabled) and no environment check, because the scaffolding prompt was about getting the API working, not about production hardening — introspection never gets revisited before deploy."
  - "AI adds authorization middleware/directives on top-level Query and Mutation fields (e.g. a `@auth` directive on `getUser`) but does not propagate the same check into nested field resolvers that return related sensitive objects (e.g. `getUser { organization { billingInfo } }`), assuming the parent check covers the whole response tree — it does not, because GraphQL resolves each field independently."
  - "AI wires up resolvers for a relationship field (e.g. `author { posts { author { posts ... } } }`) without adding `graphql-depth-limit` / `graphql-validation-complexity` (or the framework's native cost-limiting feature) because nothing in a typical scaffolding prompt asks for DoS protection explicitly — the schema is left with unbounded traversal depth by default."
  - "AI implements pagination for list fields but doesn't cap `first`/`limit` arguments, letting a client request an enormous page size that, combined with nested list fields, produces a combinatorial explosion of resolver calls despite pagination being 'present'."
  - "AI copies a security config from a tutorial that hardcodes `introspection: process.env.NODE_ENV !== 'production'` but the environment variable is never actually set to `production` in the deploy config, so introspection stays enabled in the real production environment despite the code looking correct."
falsePositiveGuardrails:
  - "Do not flag introspection as a vulnerability by default — first determine whether the API is intentionally public/self-service (e.g. a public developer API, GitHub's public GraphQL API pattern) where introspection is expected and documented; the finding is about *unintended* exposure of an internal/authenticated-only API's schema, not introspection categorically."
  - "Do not flag missing field-level authorization on fields that return genuinely public data (e.g. a public username or avatar on a `User` type) — confirm the specific field being returned is sensitive before citing this as a finding, and cite the exact field name and type, not the whole schema."
  - "Do not flag 'no depth limit configured' as critical severity in isolation — check whether the schema's actual type graph has cyclic/recursive relationships that make deep nesting exploitable. A flat schema with no circular relations has much lower real DoS exposure even without an explicit depth-limit package installed."
  - "Do not conflate authentication (a valid session/token) with field-level authorization (this specific field, for this specific node, for this caller) — a resolver behind an auth-required top-level query is not automatically safe for every nested field it returns; verify explicitly whether each sensitive nested resolver re-checks ownership/permissions."
  - "If depth/complexity limiting is implemented at the gateway or router layer (e.g. Apollo Router's max_depth config, an API gateway in front of the GraphQL endpoint) rather than in the GraphQL server code itself, check for that configuration before concluding it's missing — it may live outside the files initially selected for review."
---

## Root Cause Explanation

GraphQL's flexibility — a single endpoint, client-specified shape of the
response, arbitrary nesting of related types — is precisely what makes three
distinct misconfiguration classes recur across real deployments:

1. **Introspection left enabled in production.** GraphQL servers ship with
   introspection (the `__schema`/`__type` meta-fields that let a client ask
   the API to describe itself) enabled by default in most frameworks. This
   is invaluable during development and for genuinely public APIs, but for
   an internal or authenticated-only API it hands an attacker the complete
   map of the attack surface for free: every type, every field (including
   fields not exposed in the app's own UI), every mutation, and often
   deprecated or internal-only fields left in the schema. Multiple disclosed
   HackerOne reports (e.g. reports #1132803 and #291531) show introspection
   being the first step that led to discovery of a more serious
   vulnerability — including a full authentication bypass discovered during
   HackerOne's 2023 Ambassador World Cup, where the root cause HackerOne
   itself identified was not introspection itself but the broken access
   control it made trivial to find.
2. **Missing field-level / resolver-level authorization.** GraphQL resolves
   a query field-by-field, each field backed by its own resolver function.
   A common mental model mistake — for both human developers and AI coding
   agents — is to authorize at the top-level Query/Mutation field only
   (e.g. "you must be logged in to call `getOrganization`") and assume that
   authorization covers the entire nested response tree the query returns.
   It does not: a nested resolver for `organization.billingInfo` or
   `user.privateNotes` runs independently and, unless it explicitly
   re-checks the caller's permission for that specific node/field, will
   happily return sensitive data reachable via a different, less-obviously-
   sensitive top-level query that happens to traverse through it. OWASP's
   GraphQL Cheat Sheet frames this directly: authorization must be enforced
   "on both edges and nodes," not just at the query root.
3. **Denial of service via unbounded query shape.** Because GraphQL lets the
   client choose arbitrary nesting depth, field aliases, and (in batched
   setups) multiple operations per request, a single HTTP request can
   generate an enormous number of resolver invocations and backend calls if
   the schema has any cyclic or list-of-list relationships (a very common
   shape: `author -> posts -> author -> posts -> ...`, or a list field
   nested inside another list field). Unlike REST, where each endpoint has a
   roughly fixed cost, a GraphQL endpoint's cost is a function of the
   *query the client sends*, not the endpoint itself — so without explicit
   depth limiting, complexity/cost analysis, or breadth limiting, "make a
   request" and "make the server do exponential work" are the same
   operation from the API's point of view. Apollo's and graphql.org's own
   security guidance both describe this as requiring deliberate "demand
   control" (depth limits, complexity limits, pagination caps, persisted
   queries) precisely because GraphQL does not provide this by default.

## Vulnerable Patterns

```js
// 1. Introspection enabled unconditionally (or gated by an env var that's never actually set)
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true, // or defaulted, or `process.env.NODE_ENV !== 'production'`
                        // when NODE_ENV is never actually set to 'production' in deploy config
});

// 2. Top-level query authorized, nested resolver is not
const resolvers = {
  Query: {
    getUser: requireAuth((_, { id }) => db.user.findById(id)), // caller must be logged in
  },
  User: {
    // no permission re-check here — any authenticated caller reaching a
    // User node via ANY query path gets billingInfo, including via
    // getUser(id: someoneElsesId) or a search endpoint that returns User objects
    billingInfo: (parent) => db.billing.findByUserId(parent.id),
  },
};

// 3. No depth/complexity limiting, recursive relationship in the schema
type Author {
  name: String
  posts: [Post]
}
type Post {
  title: String
  author: Author   // cyclic: author -> posts -> author -> posts ...
}
// server config has no validationRules: [depthLimit(n), createComplexityLimitRule(n)]
// a single crafted query can nest this relationship dozens of levels deep

// 4. Pagination present but unbounded page size
type Query {
  posts(first: Int): [Post]   // no max enforced on `first` server-side
}
```

## Data Flow Tracing Guide

1. Locate the GraphQL server construction (Apollo Server, graphql-yoga,
   express-graphql, or framework-native setup). Find the `introspection`
   option (or equivalent) and trace exactly what determines its value —
   a literal boolean, an env var comparison, or the framework default (check
   what that default actually is for the specific library/version in use).
   If gated by an env var, verify the deploy config actually sets that var
   in production — a correct-looking code line with an unset env var is
   still a finding.
2. Enumerate resolvers for types that carry sensitive fields (financial,
   PII, credentials, internal-only data). For each, check whether the
   resolver itself performs a permission check against the caller (from
   context, not from client input) for that specific field/node, or whether
   it silently inherits from a parent's check. Trace at least one full query
   path from a top-level Query field, through intermediate types, to the
   sensitive field to confirm whether authorization is enforced at every
   hop or only the first.
3. Check the server config (or gateway/router config, which may live outside
   the initially selected files — check config directories and
   infra-as-code too) for `graphql-depth-limit`, `graphql-validation-complexity`,
   a framework-native cost limiter (e.g. Apollo Router `max_depth`/
   `max_root_fields`, graphql-java `MaxQueryDepthInstrumentation`), a
   persisted-query/trusted-document allowlist, or query batching limits.
   If none exist, inspect the schema's type graph for cyclic relationships
   or list-of-list nesting that would make the missing limit exploitable
   rather than theoretical.
4. Check list/connection fields for a server-enforced maximum on
   pagination arguments (`first`, `limit`, `last`) — a client-supplied
   unbounded page size combined with nested list fields multiplies request
   cost.

## Evidence Checklist

- [ ] For an introspection finding: the exact config line and file setting
      (or defaulting) introspection is cited, plus confirmation of the
      actual runtime environment value if it's env-gated.
- [ ] For a field-authorization finding: the specific sensitive field name,
      its resolver's file + line, and a full query path (top-level field ->
      ... -> sensitive field) showing how it's reachable without a
      field-level check are all cited.
- [ ] For a query-DoS finding: the schema fragment showing the
      cyclic/nested-list relationship AND the absence of any depth/
      complexity/batch limit in the server or gateway config are both cited.
- [ ] Confirmation that the API is not an intentionally public/self-service
      GraphQL API (which would make introspection expected) before flagging
      that specific finding.
- [ ] Confirmation that depth/complexity limiting isn't enforced at a
      gateway/router layer outside the reviewed files before claiming it's
      entirely absent.

## Attack Scenario Template

> An attacker [authenticated as a low-privilege user / unauthenticated,
> per findings] sends a query that [uses introspection to enumerate the
> schema / traverses from top-level field X into nested field Y without
> triggering a permission check / nests relationship Z to depth N via
> aliasing]. Because [specific file:line] does not [missing check —
> introspection gating / field-level authorization / depth or complexity
> limiting], the request [returns sensitive data belonging to another
> user or tenant / causes the server to perform an unbounded number of
> resolver or database calls], resulting in [concrete impact specific to
> this repo, e.g. "full schema disclosure including internal admin
> mutations" or "single-request resource exhaustion capable of degrading
> the API for all tenants"].

Fill every bracket from evidence gathered in this repo. If exploitability
depends on infrastructure not visible in the reviewed files (e.g. whether a
gateway enforces limits), state that explicitly and cap severity at
`medium` pending confirmation.

## Graph Mapping Instructions

- Ensure a `component:graphql_api` node exists on the first GraphQL-related
  finding in a scan, with a `depends_on` edge to `component:authorization`
  and an `exposes` edge to `component:api_security`.
- Treat introspection exposure, missing field-level authorization, and
  missing query-cost limiting as three independently-rooted finding types —
  do not merge them into a single finding node even if found in the same
  scan. Each gets its own `finding:<uuid>` vulnerability node.
- For a field-level authorization finding, add a `causes` edge from
  `component:authorization` to the finding node, and if the exposed field
  belongs to a specific sensitive data domain (billing, PII, credentials),
  add an `enables` edge from the finding node to that domain's component
  node if one exists in the graph (e.g. `component:billing`).
- For a query-DoS finding, add a `causes` edge from `component:graphql_api`
  (or `component:rate_limiting` if the root cause is specifically the
  absence of rate/cost limiting) to the finding node.
- If an introspection finding was the discovery mechanism that led directly
  to another finding in the same scan (e.g. introspection revealed a
  sensitive mutation later found to lack authorization), record that in the
  reasoning field of the downstream finding so the graph mapper can add a
  `causes` edge from the introspection finding to it, rather than treating
  them as unrelated.
