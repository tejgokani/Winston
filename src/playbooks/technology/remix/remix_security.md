---
id: technology.remix.remix_security
title: Remix / React Router (Framework Mode) Security
category: technology
vulnerabilityClass: broken_access_control
appliesToStack: remix
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A01:2021 Broken Access Control"
  - "A04:2021 Insecure Design"
cweRefs:
  - "CWE-862"
  - "CWE-863"
  - "CWE-352"
  - "CWE-201"
realWorldReferences:
  - title: "React Router allows pre-render data spoofing on framework mode, enabling cache poisoning and stored XSS (CVE-2025-43865, GHSA-cpj6-fhp6-mr6j)"
    url: "https://github.com/remix-run/react-router/security/advisories/GHSA-cpj6-fhp6-mr6j"
    type: vendor_security_advisory
  - title: "React Router has a CSRF issue in Action/Server Action request processing (CVE-2026-22030, GHSA-h5cw-625j-3rxh)"
    url: "https://github.com/remix-run/react-router/security/advisories/GHSA-h5cw-625j-3rxh"
    type: vendor_security_advisory
  - title: "remix-run/react-router Discussion — Authenticated loaders (loaders are their own API route and must independently check auth)"
    url: "https://github.com/remix-run/react-router/discussions/9327"
    type: security_blog
  - title: "remix-run/react-router Discussion — Best practice around authentication checks in nested routes"
    url: "https://github.com/remix-run/react-router/discussions/12510"
    type: security_blog
quickModeSummary: >
  For every loader/action in route_map: does it independently verify the
  session/permission before returning data or performing a mutation, or does
  it rely on a parent layout / client-side redirect for protection? Does any
  loader return a field that a component only conditionally renders (data is
  serialized to the client either way, regardless of what JSX branches on
  it)? Do actions handling state-changing form submissions have CSRF
  protection (framework default, explicit token, or SameSite cookie
  strategy), especially any action reachable via a plain HTML form crossing
  origins?
fileSelectionHint:
  roles: ["route_handler", "loader", "action", "middleware"]
  matchImports: ["@remix-run/react", "@remix-run/node", "@remix-run/server-runtime", "react-router"]
  matchAuthMapTags: ["remix"]
  maxFiles: 8
  priorityOrder: ["loader", "action", "route_handler", "middleware"]
severityHeuristics:
  critical:
    - "An action performing a state-changing operation (delete, role change, payment, password reset) has no session/permission check and is reachable by an unauthenticated or under-privileged request"
    - "A loader returns another user's private data (PII, financial records, private documents) keyed only off a route param, with no ownership/tenant check against the authenticated session"
  high:
    - "A loader returns a superset of fields (e.g. full user object including internal flags, other users' summary data) that the component only conditionally renders based on a role check performed client-side"
    - "An action handling a traditional (non-fetcher) form submission has no CSRF defense and the app does not rely on framework-level SameSite=Strict/Lax cookie behavior as its only mitigation"
  medium:
    - "Auth check exists only in a parent/layout route's loader and a nested route assumes that protection without its own independent check (fragile if the route tree is later restructured or the child is rendered standalone)"
    - "Sensitive data is fetched in a loader used purely for optional/lazy UI (e.g. deferred data) without evaluating whether the response still ships it to unauthorized viewers before the deferred promise resolves"
  low:
    - "Missing explicit auth check on a loader whose data is already low-sensitivity/public but which would benefit from consistency with sibling protected routes"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:remix_data_layer"
  relatedNodeIds: ["component:authentication", "component:authorization", "component:api_security"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:remix_data_layer"
    to: "component:authentication"
  - relation: protects
    from: "component:authorization"
    to: "component:remix_data_layer"
commonAiCodingMistakes:
  - "AI scaffolds a new route with `loader`/`action` functions and, because the route 'feels' like a client-rendered React component (JSX return, useLoaderData hook), never adds a session check inside the loader itself — it treats the route as protected because a `<ProtectedLayout>` wrapper exists in the UI tree, forgetting that loaders execute server-side per-request and JSX-level wrapping does nothing to gate the loader's own network response."
  - "AI writes a loader that fetches the full user/order/document record from the database and returns it wholesale (`return json(user)`), then writes a component that conditionally renders only the fields the current viewer is allowed to see (`{isOwner && <SSN>{user.ssn}</SSN>}`) — the SSN is still present in the loader's JSON response and visible in browser devtools/network tab regardless of what the component chooses to render."
  - "AI copies an auth check from a parent/layout route's loader and assumes it protects all nested child routes, not realizing each route segment's loader runs independently and a nested route rendered outside that layout (or restructured later) loses the check entirely."
  - "AI implements a state-changing `action` for a plain `<Form method=\"post\">` without adding any CSRF token or origin check, assuming Remix/React Router provides CSRF protection out of the box the way some other frameworks bundle it by default — it does not; the framework processes whatever POST arrives at the action route."
  - "AI defers or streams loader data (`defer()`) for a 'nice to have' loading UX on a field that turns out to be sensitive (e.g. billing details streamed in after the initial page paint), not realizing the deferred promise's eventual resolution still serializes the data into the client response once resolved, with no additional access check applied at resolution time."
falsePositiveGuardrails:
  - "Do not flag every child route loader for lacking its own explicit auth check — if the app enforces auth centrally via React Router v7 middleware (a single middleware function on a parent route in `route_map`) rather than per-loader checks, this is a valid and common pattern; confirm the middleware actually runs for the specific nested route in question before flagging a gap."
  - "Do not flag `useFetcher`/JS-driven actions with the same CSRF severity as traditional `<Form>` POSTs — fetcher-initiated requests still cross-site-forgeable via a fetch() call from another origin unless CORS blocks it, so check whether the app's CORS config or SameSite cookie policy actually mitigates this before citing the same severity as a bare unprotected `<Form>` action."
  - "A loader returning a full object where the component conditionally hides fields is only a Finding if the hidden field is actually sensitive (PII, secrets, internal-only flags, cross-tenant data) — conditionally rendering a non-sensitive UI-only field (e.g. `isBetaUser` for a banner) is not a vulnerability worth flagging."
  - "SPA mode / `ssr: false` routes execute loaders in the browser, not on the server — do not apply the 'server-side auth check' framing to those routes; instead evaluate whether the underlying API the client-side loader calls independently enforces auth, since the loader itself has no privileged execution context to protect."
---

## Root Cause Explanation

Remix (and React Router v7 in framework mode) blurs a distinction that used to
be structurally obvious in older client/server-split apps: a `loader` or
`action` function is declared right next to the component it feeds, in the
same file, written in the same request/response-free style as the JSX below
it. That proximity is exactly what makes it easy to get wrong:

1. **Loaders/actions are server code, but they don't look like it.** A
   `loader` runs on the server for every navigation and revalidation, and an
   `action` runs on the server for every form submission — full access to
   cookies, headers, and the database. But because they're colocated with
   client-rendered JSX in the same route module, and because `useLoaderData()`
   feels like just another React hook, AI-assisted and human authors alike
   treat the route as "front-end" and forget the loader needs its *own*
   server-side auth check, independent of anything a parent layout or wrapper
   component does in the UI tree. The official React Router security guidance
   is blunt about this: **a loader is its own API route** and must be treated
   like one.
2. **"Security through UI hiding."** A loader that returns the full record
   (because that's simplest to code) and a component that conditionally
   renders only part of it is a UI decision, not a data boundary. The
   response body serialized to the client contains everything the loader
   returned, visible in the browser's network tab regardless of which JSX
   branch executes. This is the loader-analogue of the long-standing mistake
   of shipping a full API response and hiding fields with `display:none` or a
   conditional render.
3. **CSRF on actions.** Actions handling `<Form method="post">` submissions
   process whatever POST request arrives at that route — Remix/React Router
   does not add CSRF tokens automatically. Apps relying purely on cookie-based
   sessions for actions performing state changes need an explicit mitigation
   (token, origin/referer check, or a deliberate SameSite cookie strategy),
   the same class of gap formalized in the framework's own CVE-2026-22030
   CSRF advisory covering action/server-action request processing.
4. **Nested-route auth inheritance is a convention, not an enforced
   guarantee.** Placing an auth check in a parent route's loader protects
   child routes only as long as the route tree stays structured that way and
   the loaders are actually re-run — refactors, standalone rendering, or
   partial hydration paths can silently drop the inherited check.

## Vulnerable Patterns

```tsx
// Loader with no auth check at all — protected only by a UI wrapper
export async function loader({ params }: LoaderFunctionArgs) {
  const doc = await db.document.findUnique({ where: { id: params.id } });
  return json(doc); // any authenticated OR unauthenticated request gets this
}

export default function DocumentRoute() {
  const doc = useLoaderData<typeof loader>();
  return (
    <ProtectedLayout> {/* looks protected — but this is UI, not the loader */}
      <DocumentView doc={doc} />
    </ProtectedLayout>
  );
}

// "Security through UI hiding" — sensitive field shipped regardless of render
export async function loader({ request, params }: LoaderFunctionArgs) {
  const user = await getUser(params.id);
  return json(user); // includes ssn, internalNotes, billingDetails
}

function UserProfile({ user, viewer }) {
  return (
    <div>
      <h1>{user.name}</h1>
      {viewer.isAdmin && <p>SSN: {user.ssn}</p>} {/* still in the JSON payload for everyone */}
    </div>
  );
}

// Action with no CSRF defense on a state-changing form
export async function action({ request }: ActionFunctionArgs) {
  const session = await getSession(request.headers.get('Cookie'));
  const formData = await request.formData();
  await db.account.update({
    where: { id: session.userId },
    data: { email: formData.get('email') }, // no origin/token check
  });
  return redirect('/settings');
}
```

## Data Flow Tracing Guide

1. For every `loader`/`action` in `route_map`: does the function body itself
   call a session/auth utility (e.g. `requireUser`, `getSession`,
   `authenticator.isAuthenticated`) before touching the database, or does
   protection only exist in a parent route or a rendered layout component?
   Trace the parent chain in React Router v7 middleware config if present —
   confirm the middleware is actually registered on a route that covers this
   one.
2. For every field returned from a loader via `json()`/`return`/`defer()`:
   is every returned field actually needed and rendered unconditionally, or
   does the component gate some fields on a client-side role/ownership check?
   If gated, that field is exposed in the network response regardless.
3. For every `action` handling a traditional form POST: is there a CSRF
   token, origin/referer check, or explicit SameSite=Strict/Lax cookie
   configuration in place? Distinguish actions invoked only via
   `useFetcher`/programmatic JS (still forgeable cross-site via fetch unless
   CORS blocks it) from actions invoked via plain `<Form>` (directly
   forgeable via a hostile HTML page).
4. For nested routes: does the child route's own loader independently
   re-verify authorization for the specific resource it loads (e.g. ownership
   of a specific `params.id`), or does it just trust that reaching this route
   at all implies authorization? Object-level checks (this user can access
   *this specific* record) are commonly missing even when route-level auth is
   present.

## Evidence Checklist

- [ ] The exact loader/action file + line range is cited, not paraphrased.
- [ ] If claiming a missing-auth-check finding: confirm no covering
      middleware/parent-loader check exists by tracing the actual route tree
      in `route_map`, and cite why it doesn't apply (not present, not
      registered on this path, or contains no auth logic).
- [ ] If claiming a UI-hiding-only exposure: cite both the loader's return
      statement (showing the full field set) and the component's conditional
      render (showing the field is gated only in JSX).
- [ ] If claiming a CSRF gap: identify whether the action is reachable via a
      plain `<Form>` POST (higher severity) or only via `useFetcher`/JS call
      guarded by CORS (lower severity, cite the CORS config checked).
- [ ] Confirm the resource being loaded isn't intentionally public content
      before flagging a missing-check as unauthorized data exposure.

## Attack Scenario Template

> A request to [loader/action route] executes without an independent
> server-side check because [specific code location shows no auth call /
> parent-only protection]. As a result, [an unauthenticated user / a
> lower-privileged authenticated user] can [read another user's data /
> trigger a state-changing action] by [directly requesting the route /
> submitting a forged form], resulting in [concrete impact specific to this
> repo, e.g. "any authenticated user can view another tenant's invoices by
> changing the :id route param"].

Fill every bracket from evidence gathered in this repo. If a bracket can't be
filled from real evidence, cap severity at `medium` and note that
exploitability is unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:remix_data_layer` node exists (create on first
  finding in this playbook) with a `depends_on` edge to
  `component:authentication`.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from `component:remix_data_layer` (or
  a more specific node, e.g. `component:csrf_protection` for CSRF findings)
  to the finding node.
- If a missing-auth-check finding on one loader enables reaching a
  downstream sensitive component (e.g. a payments provider, a database
  containing cross-tenant data), add an `enables` edge from the finding node
  to that component's node id.
- If a UI-hiding-only exposure finding and a separately-identified
  missing-auth finding both trace back to the same loader, note the shared
  root cause explicitly in each finding's `reasoning` field so the graph
  mapper wires a `causes` edge between them instead of treating them as
  unrelated.
