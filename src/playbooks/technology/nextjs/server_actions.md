---
id: technology.nextjs.server_actions
title: Next.js Server Actions Treated as Trusted Function Calls
category: technology
vulnerabilityClass: broken_access_control
appliesToStack: nextjs
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A01:2021 Broken Access Control"
  - "A04:2021 Insecure Design"
cweRefs:
  - "CWE-862"
  - "CWE-863"
  - "CWE-639"
realWorldReferences:
  - title: "Next.js Server Actions Security: 5 Vulnerabilities You Must Fix"
    url: "https://makerkit.dev/blog/tutorials/secure-nextjs-server-actions"
    type: security_blog
  - title: "Next.js 16 Server Actions Security: The Auth Check Most Developers Miss"
    url: "https://dev.to/shubhradev/nextjs-16-server-actions-security-the-auth-check-most-developers-miss-1ei1"
    type: security_blog
  - title: "Critical RCE Vulnerability in React & Next.js Exposed (Server Actions deserialization)"
    url: "https://www.ox.security/blog/rce-in-react-server-components/"
    type: security_blog
  - title: "Server Actions and Security · vercel/next.js Discussion #68155"
    url: "https://github.com/vercel/next.js/discussions/68155"
    type: security_blog
  - title: "Next.js Server Actions and Mutations (official docs — Security section)"
    url: "https://nextjs.org/docs/app/building-your-application/data-fetching/server-actions-and-mutations#authentication-and-authorization"
    type: vendor_security_advisory
  - title: "Vibe Coding Security Checklist: Audit AI Apps"
    url: "https://securestartkit.com/blog/the-vibe-coding-security-checklist-how-to-audit-your-ai-generated-app"
    type: security_blog
quickModeSummary: >
  Every `'use server'` function is a public HTTP endpoint reachable directly
  (curl, no UI, no auth by default), regardless of how "private" it looks in
  the component tree. For each Server Action: is there an explicit
  server-side session/auth check inside the action itself (not just on the
  page that renders the trigger)? For any resource id/owner id passed as an
  argument, is ownership/tenant re-verified against the session server-side,
  or is the caller-supplied id trusted directly in the query/mutation?
fileSelectionHint:
  roles: ["server_action", "route_handler", "data_access", "form"]
  matchImports: ["next/server", "server-only", "react/server"]
  matchAuthMapTags: ["nextjs_server_action"]
  maxFiles: 8
  priorityOrder: ["server_action", "data_access", "route_handler"]
severityHeuristics:
  critical:
    - "A Server Action performs a state-changing operation (delete, payment, role change, password/email change) with no server-side authentication check at all — reachable by anyone who can construct the action's POST request, authenticated or not."
    - "A Server Action accepts a resource/user/tenant id as an argument and uses it directly in a query or mutation without verifying it belongs to the authenticated caller (IDOR) — e.g. `deletePost(postId)` with no `where: { authorId: session.user.id }` equivalent."
  high:
    - "A Server Action checks 'is there a session' but not 'does this session's role/tenant permit this specific action,' allowing any authenticated user to perform an admin/privileged operation."
    - "Auth/ownership checks are duplicated ad hoc across many Server Action files rather than centralized in a shared data-access layer, making it easy for one file to have been updated and others missed (verify by diffing check logic across similar actions)."
  medium:
    - "Server Action performs authorization only implicitly by relying on the calling page having been access-controlled (e.g. by middleware or a layout check), rather than re-verifying inside the action itself — safe only as long as no other caller can ever reach the action, which is not a guarantee Server Actions provide."
  low:
    - "Server Action lacks server-side input validation (e.g. no schema/zod check on argument shape/type) even though it does perform an auth check — a defense-in-depth gap, not a direct access-control bypass."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:nextjs_server_actions"
  relatedNodeIds: ["component:authorization", "component:data_access_layer", "component:api_security"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:nextjs_server_actions"
    to: "component:authorization"
  - relation: protects
    from: "component:data_access_layer"
    to: "component:nextjs_server_actions"
commonAiCodingMistakes:
  - "AI generates a Server Action as if it were an internal helper function called only from one specific button/form, and — reasoning by that narrow call site rather than by 'this compiles to a public POST endpoint' — omits any auth/ownership check, matching the exact failure mode multiple 2025-2026 writeups describe: 'the page that renders the button is protected, but the action behind the button accepts whatever the caller sends.'"
  - "AI adds an auth check (`const session = await auth()`) but stops at authentication, never adding the ownership/authorization check that the resource id argument actually belongs to that session — producing a working-looking but IDOR-vulnerable action, e.g. `updateInvoice(invoiceId, data)` with no check that `invoiceId` belongs to the caller."
  - "AI copy-pastes an existing Server Action to create a new one (e.g. duplicating `updatePost` to make `deletePost`) and carries over the auth check inconsistently or drops it, especially when the new action is added in a later session/turn without the original context in view."
  - "AI treats client-side validation/disabled UI (a button that's hidden unless the user is an admin) as equivalent to server-side authorization, leaving the underlying Server Action fully callable by anyone who inspects the client bundle for the action's reference and calls it directly."
falsePositiveGuardrails:
  - "Do not flag a Server Action for missing auth if it is read-only, returns only public data, and takes no caller-supplied identifiers that could pivot to another user's data (e.g. fetching a public product catalog) — confirm what data/mutation the action actually touches before flagging."
  - "If auth/ownership checks are centralized in a shared 'data access layer' or repository module (a pattern explicitly recommended by Next.js security guides) and every Server Action routes through it, do not flag each individual action as missing a check — verify the centralized layer performs the check correctly instead, and only flag actions that bypass that layer directly (e.g. calling the ORM/DB client directly rather than through the DAL)."
  - "A Server Action guarded by middleware-based route protection is not automatically safe — Server Actions are invoked via POST to the page route hosting them and can, depending on version/config, be reachable in ways middleware matchers don't anticipate; do not treat middleware coverage alone as sufficient evidence of authorization without a server-side check inside the action itself."
---

## Root Cause Explanation

Next.js Server Actions (`'use server'`) are designed to read like a normal,
private, same-process function call from the developer's point of view — you
`import` it and call it like any other async function from a form or event
handler. Under the hood, the framework compiles each Server Action into a
public HTTP POST endpoint with a stable reference, invocable by anyone who
can send that request, independent of which React component happened to call
it in your source.

This is exactly the gap the Next.js docs' own "Authentication and
Authorization" section for Server Actions warns about: *treat Server Actions
as you would public-facing API endpoints, and ensure the user is authorized
to perform the action.* Multiple independent write-ups converge on the same
description: `'use server'` doesn't add authentication — it exposes an
endpoint that anyone with a valid session cookie (or, for actions with no
check at all, anyone period) and a cURL command can call directly, no UI
required. TypeScript types, client-side prop validation, and "this button is
only rendered for admins" component logic constrain what the *UI* can do —
none of it constrains what an attacker sending a raw request to the action
can do.

Two independent checks are required per action, and AI-assisted code
routinely gets only the first:

1. **Authentication** — is there a valid, server-verified session at all?
2. **Authorization / ownership** — does *this* session's user/role/tenant
   have permission to perform *this* action on *this specific resource*,
   where the resource is identified by an argument the caller controls?

The second check is the one that's missing most often in practice, because
it requires reasoning about the specific argument (e.g. `postId`,
`invoiceId`, `userId`) rather than just "is anyone logged in" — and because
duplicating that check by hand across many action files (rather than
centralizing it) makes it easy for one file to fall out of sync when logic
changes elsewhere.

## Vulnerable Patterns

```ts
'use server'

// No auth check at all — a public endpoint that deletes any post by id.
export async function deletePost(postId: string) {
  await db.post.delete({ where: { id: postId } });
}

// Authentication only, no ownership/authorization check — IDOR.
export async function updateInvoice(invoiceId: string, data: InvoiceInput) {
  const session = await auth();
  if (!session) throw new Error('Unauthorized');
  // Any authenticated user can update ANY invoice by guessing/enumerating
  // invoiceId — the query never scopes to session.user.id or their tenant.
  await db.invoice.update({ where: { id: invoiceId }, data });
}

// Client-side gating mistaken for security.
function AdminPanel({ isAdmin }: { isAdmin: boolean }) {
  // isAdmin only hides the button in the UI — banUser is still a public
  // endpoint callable directly regardless of what isAdmin was on render.
  return isAdmin ? <button onClick={() => banUser(userId)}>Ban</button> : null;
}
```

Correct shape for comparison (what the fix should look like):

```ts
'use server'

export async function updateInvoice(invoiceId: string, data: InvoiceInput) {
  const session = await auth();
  if (!session) throw new Error('Unauthorized');

  // Authorization: scope the mutation to a resource the caller actually owns.
  const invoice = await db.invoice.findUnique({ where: { id: invoiceId } });
  if (!invoice || invoice.ownerId !== session.user.id) {
    throw new Error('Forbidden');
  }
  await db.invoice.update({ where: { id: invoiceId }, data });
}
```

## Data Flow Tracing Guide

1. Enumerate every file/function marked `'use server'` (file-level directive
   or inline `async function` with the directive as its first line inside a
   Server Component/action file).
2. For each one, check the first lines of the function body: is there a
   server-side session lookup (`auth()`, `getServerSession()`,
   `currentUser()`, or the project's equivalent)? If absent, this is a
   critical finding candidate — confirm the action is not read-only/public
   data before concluding.
3. For each argument that looks like a resource identifier (an `id`,
   `userId`, `orgId`, `tenantId`, etc.), trace whether it is used directly in
   a query/mutation's `where` clause without being cross-checked against
   `session.user.id` (or the equivalent ownership/tenant field). If the
   query is scoped only by the caller-supplied id and not also by something
   derived from the session, that's an IDOR candidate.
4. Check whether auth/ownership logic is centralized (a shared data-access
   layer / repository module that every action routes through) or
   duplicated per-action. If duplicated, diff the check logic across
   similarly-shaped actions (e.g. all actions touching the same resource
   type) — inconsistency between them is strong evidence of a forgotten
   check in at least one.
5. Confirm the action isn't relying solely on the calling page/layout having
   been protected by middleware — that protects navigation to the page, not
   direct invocation of the action's endpoint.

## Evidence Checklist

- [ ] The exact Server Action function is quoted with file and line range,
      including its full body (not paraphrased) so the absence/presence of a
      check is directly verifiable.
- [ ] If claiming a missing authentication check: confirm no session lookup
      exists anywhere in the function body, including any helper it calls
      (trace one level into helpers before concluding).
- [ ] If claiming an IDOR/missing-ownership issue: cite the specific
      caller-supplied identifier argument and the specific query/mutation
      line where it's used unscoped by session-derived data.
- [ ] If claiming reliance on client-side gating only: cite the specific
      component that hides the trigger, and confirm no equivalent check
      exists server-side in the action itself.
- [ ] Confirmation the action is not exclusively read-only public data (no
      access-control issue to report if so).

## Attack Scenario Template

> An attacker with [no session / any authenticated session] sends a direct
> POST request to the Server Action endpoint for [action name] at
> [file:line], supplying [specific argument, e.g. `invoiceId` belonging to
> another user] as its argument. Because [file:line] does not
> [missing check — verify session / verify ownership of the resource],
> the mutation executes against [specific resource/table], resulting in
> [concrete impact — e.g. "attacker deletes or reads another tenant's
> invoice by id enumeration"].

Fill every bracket from evidence gathered in this repo. If exploitability
requires guessing/enumerating IDs and the ID space is a non-sequential UUID
with no other disclosure vector, note this in the scenario — it affects
practical exploitability (still a valid finding, but note the constraint)
rather than the underlying finding itself.

## Graph Mapping Instructions

- Ensure a `component:nextjs_server_actions` node exists on first
  Server-Action-related finding, with a `depends_on` edge to
  `component:authorization`.
- Each concrete missing-check finding becomes its own `finding:<uuid>`
  vulnerability node, with a `causes` edge from
  `component:nextjs_server_actions` (or `component:data_access_layer` if the
  root cause is a shared DAL gap affecting multiple actions) to the finding.
- If a single missing-check root cause (e.g. no centralized DAL,
  inconsistent per-action checks) produces multiple concrete findings across
  different action files, note this explicitly in each finding's `reasoning`
  field so the graph mapper can link them as symptoms of one systemic
  root-cause node rather than N unrelated findings.
- If a finding's resource ultimately reaches a specific sensitive downstream
  system (billing, PII store, admin capability), add an `enables` edge from
  the finding node to that component's node id.
