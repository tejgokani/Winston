---
id: ai_security.authorization
title: Authorization / Broken Access Control
category: ai_security
vulnerabilityClass: broken_access_control
appliesToStack: technology-agnostic
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A01:2021 Broken Access Control"
cweRefs:
  - "CWE-862"
  - "CWE-863"
  - "CWE-639"
realWorldReferences:
  - title: "Autodesk: IDOR Vulnerability Allowing Attacker to Edit Another User's Profile"
    url: "https://hackerone.com/reports/2962056"
    type: bug_bounty_disclosure
  - title: "Veris: Critical - Insecure Direct Object Reference Leading to Privilege Escalation via Org-Member DELETE Endpoint"
    url: "https://hackerone.com/reports/120115"
    type: bug_bounty_disclosure
  - title: "Uber IDOR via phone number substituted for userID ($10,000 bounty)"
    url: "https://hackerone.com/reports/143717"
    type: bug_bounty_disclosure
  - title: "Vibe Coding Security Risks: Why AI-Generated Code Keeps Shipping Broken Access Control"
    url: "https://getautonoma.com/blog/vibe-coding-security-risks"
    type: security_blog
  - title: "Top 25 IDOR Bug Bounty Reports"
    url: "https://corneacristian.medium.com/top-25-idor-bug-bounty-reports-ba8cd59ad331"
    type: security_blog
quickModeSummary: >
  For every route that takes a resource id (userId, orderId, documentId,
  etc.), check whether the handler verifies the authenticated caller actually
  owns or is permitted to access that specific resource — not just that they
  are logged in. Authentication (who are you) is not authorization (are you
  allowed to touch this specific row). Look especially at routes that were
  clearly extended from a working single-user example (copy-pasted CRUD).
fileSelectionHint:
  roles: ["route_handler", "middleware", "auth"]
  matchImports: []
  matchAuthMapTags: []
  maxFiles: 10
  priorityOrder: ["route_handler", "middleware"]
severityHeuristics:
  critical:
    - "Any authenticated user can read, modify, or delete another user's data by changing an id in the request (IDOR) with no ownership check anywhere in the call path"
    - "An endpoint intended for admins only is reachable by any authenticated (or unauthenticated) user"
  high:
    - "Ownership check exists but is performed inconsistently across otherwise-identical routes (e.g. GET checks ownership, DELETE on the same resource doesn't)"
    - "Authorization decision is made client-side only (hidden UI element) with no server-side enforcement"
  medium:
    - "Ownership check exists but relies on a client-supplied field (e.g. trusting a userId in the request body instead of the authenticated session) rather than the authenticated identity"
  low:
    - "Verbose error messages leak whether a resource exists for ids the caller doesn't own (information disclosure, not access itself)"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:authorization"
  relatedNodeIds: ["component:authentication", "component:business_logic"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:authorization"
    to: "component:authentication"
  - relation: protects
    from: "component:authorization"
    to: "component:api_security"
commonAiCodingMistakes:
  - "AI scaffolds a CRUD resource by cloning a working example route; the clone gets authentication middleware (easy to copy) but the ownership check inside the handler — which was specific to the original resource's shape — doesn't get adapted, so it's silently dropped."
  - "AI implements the 'list my items' endpoint correctly (filters by authenticated user id in the query) but the 'get single item by id' endpoint fetches by id alone without also filtering by owner, because it looks like a simpler case that 'obviously' only returns the right data."
  - "AI adds an admin-only route and protects it with 'requireAuth' (any logged-in user) instead of a role/permission check, because the two concepts get conflated when scaffolding quickly."
  - "Ownership checks get added to the read path but forgotten on write/delete paths added in a later iteration, since they were written as separate follow-up prompts without re-deriving the full CRUD surface each time."
  - "AI implements the authorization check correctly in code that looks right on inspection, but never gets exercised by a second-user test — the model (and the developer reviewing its output) verifies the happy path with a single test account, so a check that silently no-ops (e.g. compares a value to itself, or checks the wrong field) ships undetected. Static review of the code shape is not sufficient evidence the check works; industry data attributes over 60% of security issues in AI-scaffolded apps to this class of missing/broken data-access control (IDOR, missing row-level security, client-side-only auth checks)."
  - "AI relies on ORM/framework 'convenience' relations (e.g. `user.orders`) for the authenticated user's own data, but when a related resource is fetched through a different relation or a raw query added later (e.g. `Order.find(id)` for a support/admin feature), the ownership scoping baked into the convenience relation doesn't carry over, and nothing flags the raw query as needing the same filter."
falsePositiveGuardrails:
  - "Do not flag routes that are intentionally public or shared (e.g. public profile pages, publicly listed products) — check whether the resource is described as user-scoped anywhere (schema, other routes' filtering behavior) before assuming it should be owner-restricted."
  - "Do not flag admin routes if a role/permission check is present, even if it looks different from the ownership-check pattern used elsewhere — role-based and ownership-based authorization are both valid, don't require them to look identical."
  - "If a resource is fetched via a query already scoped by the authenticated user's id (e.g. `WHERE user_id = session.userId`), that satisfies the ownership check even if there's no separate explicit `if (resource.userId !== session.userId)` line — look at the actual data access, not just for a specific code shape."
  - "If the datastore itself enforces row-level scoping (e.g. Postgres/Supabase Row-Level Security policies, a multi-tenant ORM default scope applied globally), the application-layer handler doesn't need its own redundant ownership check — verify the policy actually exists and covers this table/operation before treating the missing in-handler check as a finding."
  - "A code shape that looks correct (an `if` comparing ids) is not itself sufficient evidence — where feasible, prefer citing evidence that the check is actually reachable and correctly wired (e.g. it isn't dead code, doesn't compare a value to itself, and the compared identity is the session's, not a value the caller also controls) over merely noting the check's presence."
---

## Root Cause Explanation

Broken access control is consistently the most common real-world web
vulnerability class (OWASP's #1 category), and it fails in a narrow set of
recurring shapes:

1. **Missing ownership check (IDOR).** A route accepts a resource id from the
   caller and fetches/mutates that resource without confirming the
   authenticated identity actually owns it or has been granted access to it.
   The route "works" for the developer testing with their own data and
   silently allows cross-user access for anyone who changes the id.
2. **Authentication mistaken for authorization.** A route correctly requires
   *a* logged-in user (authentication) but never checks *which* user is
   allowed to do *this specific thing* (authorization). This is the single
   most common AI-scaffolding gap: `requireAuth` gets attached everywhere,
   and that feels like "it's protected" even when nothing checks ownership
   or role.
3. **Inconsistent enforcement across a resource's CRUD surface.** Because
   REST/CRUD routes for one resource are usually written incrementally
   (list, then get, then update, then delete — often across separate prompts
   or commits), the ownership check that was correctly reasoned through for
   the first route doesn't automatically propagate to the others.
4. **Client-side authorization.** A permission check exists only in the
   frontend (hiding a button, disabling a menu item) with no corresponding
   server-side enforcement — trivially bypassed by calling the API directly.

## Vulnerable Patterns

```js
// IDOR: fetches by id with no ownership filter or check
app.get('/api/orders/:orderId', requireAuth, async (req, res) => {
  const order = await db.orders.findById(req.params.orderId);
  res.json(order); // any authenticated user can read any order
});

// Authentication without authorization: role never checked
app.post('/api/admin/refund', requireAuth, async (req, res) => {
  await processRefund(req.body.orderId); // any logged-in user can trigger this
});

// Client-supplied identity trusted instead of the session's
app.put('/api/profile', requireAuth, async (req, res) => {
  await db.users.update(req.body.userId, req.body.changes); // trusts body, not session
});
```

## Data Flow Tracing Guide

1. For every route in `route_map` that takes an id-like path parameter
   (`:userId`, `:orderId`, `:id`, etc.), find where that id is used to fetch
   or mutate data. Is the query/lookup scoped by the authenticated identity
   (e.g. `WHERE owner_id = session.userId`), or is the id used alone?
2. For routes that appear admin/privileged (path contains `/admin/`,
   handler name suggests elevated action, or it performs a destructive
   cross-user operation like refunds/bans/deletions), confirm the
   authorization check is role/permission-based, not just `requireAuth`.
3. Compare routes operating on the *same* resource (list vs. get vs. update
   vs. delete) — do they all apply the same ownership logic? A mismatch
   between sibling routes is strong evidence of an inconsistent scaffold.
4. Check whether identity used in an authorization decision comes from the
   verified session/token (trustworthy) or from the request body/query
   string (attacker-controlled, untrustworthy) — trace exactly which
   variable feeds the check.

## Evidence Checklist

- [ ] The exact route (method + path) and handler file/line are cited.
- [ ] The exact line where the resource is fetched/mutated is cited, showing
      whether an ownership filter is present or absent.
- [ ] If claiming inconsistent enforcement across sibling routes: both routes
      are cited side by side.
- [ ] If claiming trust of a client-supplied identity: the exact line where
      that value is read is cited, showing it's not derived from the
      verified session.
- [ ] Confirmation the resource is not intentionally public/shared (checked
      against how it's queried elsewhere in the codebase).

## Attack Scenario Template

> An authenticated attacker (their own valid session, not a privileged one)
> changes [id parameter] in a request to [route] from their own resource id
> to another user's. Because [specific code location] does not verify
> ownership before [fetching/mutating] the resource, the attacker gains
> [concrete impact — read/modify/delete another user's specific data type].

## Graph Mapping Instructions

- Always ensure a `component:authorization` node exists with a `depends_on`
  edge to `component:authentication` — authorization only makes sense once
  identity is established.
- Each concrete finding becomes a `finding:<uuid>` vulnerability node with a
  `causes` edge from `component:authorization` (or `component:business_logic`
  if the root cause is really a missing business rule rather than a missing
  check per se).
- If the finding exposes a specific external resource type (e.g. a payments
  or billing component), add an `enables` edge from the finding node to that
  component, reflecting what the broken check actually exposes.
