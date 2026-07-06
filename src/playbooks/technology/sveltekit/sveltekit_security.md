---
id: technology.sveltekit.sveltekit_security
title: SvelteKit Security
category: technology
vulnerabilityClass: framework_specific_misconfiguration
appliesToStack: sveltekit
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A03:2021 Injection"
  - "A01:2021 Broken Access Control"
  - "A02:2021 Cryptographic Failures"
cweRefs:
  - "CWE-79"
  - "CWE-306"
  - "CWE-200"
realWorldReferences:
  - title: "Svelte Docs — {@html} (bypasses Svelte's automatic escaping)"
    url: "https://svelte.dev/docs/svelte/@html"
    type: security_blog
  - title: "SvelteKit Docs — $env/static/private (server-only, cannot be imported client-side)"
    url: "https://svelte.dev/docs/kit/$env-static-private"
    type: security_blog
  - title: "SvelteKit Docs — $env/static/public (PUBLIC_-prefixed, bundled into client code)"
    url: "https://svelte.dev/docs/kit/$env-static-public"
    type: security_blog
  - title: "@sveltejs/kit — Cross-site Scripting via tracked search_params (CVE-2025-32388, GHSA-6q87-84jw-cjhp)"
    url: "https://github.com/advisories/GHSA-6q87-84jw-cjhp"
    type: vendor_security_advisory
  - title: "CVEs affecting the Svelte ecosystem — official Svelte team writeup"
    url: "https://svelte.dev/blog/cves-affecting-the-svelte-ecosystem"
    type: vendor_security_advisory
quickModeSummary: >
  Check every `{@html ...}` for whether the value is user-controlled and
  unsanitized (Svelte auto-escapes everything except what's explicitly opted
  out via {@html}). Check every +page.server.ts/+layout.server.ts `load`
  function, every `actions` object in +page.server.ts, and every +server.ts
  handler for an auth/session check before it touches sensitive data or
  performs a mutation. Check every import from `$env/static/public` or
  `$env/dynamic/public` for a secret that should instead come from
  `$env/static/private` / `$env/dynamic/private` — anything in the public
  module (or PUBLIC_-prefixed) is bundled into client-shipped JS.
fileSelectionHint:
  roles: ["route_handler", "component", "config"]
  matchImports: ["$env/static/public", "$env/static/private", "$env/dynamic/public", "$env/dynamic/private", "@sveltejs/kit"]
  matchAuthMapTags: ["sveltekit"]
  maxFiles: 10
  priorityOrder: ["route_handler", "component", "config"]
severityHeuristics:
  critical:
    - "{@html} renders a value derived from user input (form field, query param, DB row populated from user input) with no sanitization step"
    - "A secret (API key, DB connection string, signing key, third-party service token) is imported from $env/static/public / $env/dynamic/public, or given a PUBLIC_ prefix, shipping it into the client bundle"
    - "A +server.ts handler or a form action in +page.server.ts performs a state-changing operation (POST/PUT/PATCH/DELETE, or a named action) with no session/locals check before executing"
  high:
    - "A +page.server.ts load function or +server.ts GET handler returns another user's data without verifying the requester owns/can access that resource (IDOR via missing ownership check, not just missing auth)"
    - "{@html} is used on content sanitized by a custom/ad-hoc filter (regex strip, naive replace) instead of a maintained sanitizer library"
    - "Auth is checked in a +layout.server.ts load function but a sibling +page.server.ts / +server.ts under the same route relies on that layout running, when SvelteKit's data-loading model means the deeper load/action can in some configurations still execute independently (e.g. standalone +server.ts endpoints are not covered by page layout load functions at all)"
  medium:
    - "A PUBLIC_-prefixed / $env/static/public variable holds non-secret but sensitive operational detail (internal hostname, feature-flag payload) that gives an attacker reconnaissance value without directly being a credential"
    - "{@html} renders trusted CMS/markdown content without any output-context review or CSP as defense-in-depth, even though the source itself is not directly user-controlled"
  low:
    - "No Content-Security-Policy configured in svelte.config.js as defense-in-depth, with no compensating output-encoding review evidenced elsewhere"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:sveltekit"
  relatedNodeIds: ["component:api_security", "component:secrets", "component:xss"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:sveltekit"
    to: "component:api_security"
  - relation: protects
    from: "component:api_security"
    to: "component:sveltekit"
  - relation: exposes
    from: "component:secrets"
    to: "component:sveltekit"
commonAiCodingMistakes:
  - "AI is asked to render markdown/CMS/rich-text content and reaches for `{@html content}` directly on a value that traces back to a user-submitted field (comment body, bio, profile field) instead of running it through a sanitizer (e.g. DOMPurify, sanitize-html) first — Svelte's escaping is bypassed entirely by design once {@html} is used."
  - "AI scaffolds a new +server.ts or a new named action inside `actions` in +page.server.ts by copying an existing authenticated route's shape but forgets to copy the actual `locals.user`/`locals.session` check, especially when the new endpoint is added in a separate turn from where hooks.server.ts originally set up auth."
  - "AI hits a 'Cannot find module $env/static/private' or 'not available in client-side code' error while wiring up a value needed in a `<script>` block on the client and 'fixes' it by moving the variable into `$env/static/public` (or renaming it with a PUBLIC_ prefix) rather than realizing the value must stay server-only and be passed down through a load function's return value instead."
  - "AI relies on a parent +layout.server.ts's `load` function to establish auth, then adds a sibling `+server.ts` API endpoint under the same route directory — SvelteKit does not run layout load functions before standalone +server.ts request handlers, so the endpoint ends up with no auth enforcement despite 'looking' like it's under a protected route."
  - "AI writes `hooks.server.ts` to set `event.locals.user` from a session cookie but a downstream load function or action reads `event.locals.user` without checking it's non-null, silently treating an unauthenticated request as if `user` were a valid (but empty/undefined-field) object instead of redirecting/erroring."
falsePositiveGuardrails:
  - "Do not flag {@html} when the rendered value is fully build-time/author-controlled (e.g. inlined from a local markdown file processed at build time, or a hardcoded string) — the risk is specifically about user-controlled data reaching {@html}, not the directive's mere presence."
  - "Do not flag {@html} when the value has already passed through a recognized sanitizer (DOMPurify, sanitize-html, rehype-sanitize) immediately upstream in the same data flow — verify the sanitizer call exists and covers the actual value being rendered."
  - "A variable is not automatically a finding just because it's imported from $env/static/public or $env/dynamic/public — confirm it actually holds sensitive material (a credential/secret) rather than a legitimately public value (analytics ID, public API base URL, feature flag meant for the client)."
  - "A +server.ts or form action with no explicit auth check is not automatically a vulnerability — verify it isn't an intentionally public endpoint (public search, static content API, webhook receiver with its own signature verification, health check, the login/signup action itself) before writing a Finding."
  - "Do not assume a parent +layout.server.ts's auth check automatically protects everything nested under it — verify the specific file in question (a sibling +server.ts, a load function, or a form action) actually receives/checks the auth state SvelteKit's routing model would realistically deliver to it, rather than assuming layout-level protection cascades everywhere."
---

## Root Cause Explanation

SvelteKit's security posture, like Astro's, starts from safe defaults —
Svelte auto-escapes all `{expression}` output, and SvelteKit's file-based
routing makes it straightforward to see where server logic lives. Most real
vulnerabilities come from three specific opt-outs/gaps:

1. **`{@html}` opt-out escaping.** Svelte escapes all mustache expression
   output by default; `{@html}` is the deliberate escape hatch for injecting
   raw markup, used whenever a component needs to render rich HTML (a CMS
   field, markdown-to-HTML output, a user bio). Because it's the only
   built-in way to render markup instead of text, it's easy to reach for
   reflexively on a value without checking whether that value is
   user-controlled or already sanitized.
2. **Auth is a convention, not an enforced structure.** SvelteKit gives you
   `hooks.server.ts` to populate `event.locals` and `+page.server.ts`/`+layout.server.ts`
   `load` functions and `actions` to read it, but nothing forces every
   route's `load`/`action`/`+server.ts` handler to actually check `locals`.
   Critically, **standalone `+server.ts` API endpoints are not covered by a
   sibling `+layout.server.ts`'s load function** — layout load functions run
   for page rendering, not for raw API requests hitting a `+server.ts` file
   in the same directory — so a very natural mental model ("this route is
   under a protected layout, so it's protected") is actually wrong for API
   endpoints, and this exact gap recurs across SvelteKit codebases.
3. **`$env/static/public` / `PUBLIC_` prefix is a bundling instruction, not a
   permissions system.** Any variable imported from the `public` env modules
   (or matching the configured `publicPrefix`, default `PUBLIC_`) gets
   statically inlined into client-shipped JavaScript at build time. There's
   no runtime gate — moving a variable from `$env/static/private` to
   `$env/static/public` (often done to silence a "cannot be imported
   client-side" build error) instantly and silently changes its trust
   boundary from server-only to world-readable.

## Vulnerable Patterns

```svelte
<!-- src/routes/profile/[id]/+page.svelte -->
<script>
  export let data; // data.bio is user-submitted, loaded server-side
</script>

<!-- Bypasses Svelte's default auto-escaping entirely -->
{@html data.bio}
```

```ts
// src/routes/api/users/[id]/promote/+server.ts
// No locals/session check before a privileged, state-changing action
export async function POST({ params, request }) {
  const { role } = await request.json();
  await db.user.update({ where: { id: params.id }, data: { role } });
  return new Response(null, { status: 204 });
}
```

```ts
// src/routes/settings/+layout.server.ts protects the *page*...
export async function load({ locals }) {
  if (!locals.user) throw redirect(303, '/login');
  return { user: locals.user };
}

// ...but a sibling +server.ts is NOT covered by that layout load function:
// src/routes/settings/export/+server.ts
export async function GET({ locals }) {
  // locals.user may be undefined here — this handler runs independently
  return json(await exportAllUserData(locals.user?.id)); // no check!
}
```

```ts
// A secret imported from the public module ships to the client bundle
import { PUBLIC_STRIPE_SECRET_KEY } from '$env/static/public';
```

## Data Flow Tracing Guide

1. Grep the codebase for every `{@html ...}` usage in `.svelte` files. For
   each, trace the value backward: is it a literal or build-time-only
   content, or does it originate from a `load` function's returned data
   (which itself may trace to a request/DB row populated by user input)? If
   user-controlled, is a sanitizer call (DOMPurify, sanitize-html,
   rehype-sanitize) applied upstream, in the `load` function or the
   component, before the value reaches `{@html}`?
2. Enumerate every `+server.ts` file and every `actions` entry inside
   `+page.server.ts` files. For each: does it read `event.locals` (or
   equivalent, set in `hooks.server.ts`) for a session/user, and does that
   check happen before any data access or mutation? Do not assume a parent
   `+layout.server.ts` load function protects a sibling `+server.ts` —
   confirm the handler itself performs the check.
3. Read `src/hooks.server.ts` and confirm how `event.locals` is populated —
   trace whether an invalid/missing session results in `locals.user` being
   `undefined`/`null` (safe, if downstream code checks it) versus a
   partially-populated object that downstream code might treat as valid.
4. Grep for every import from `$env/static/public`, `$env/dynamic/public`, or
   any identifier prefixed with the configured public prefix (default
   `PUBLIC_`). For each, check what the variable actually holds — is it a
   credential, connection string, or signing secret rather than a value
   legitimately meant for the browser? Cross-reference against the matching
   `$env/static/private` import to see if the same secret exists correctly
   scoped elsewhere (a sign it was moved/duplicated incorrectly).
5. For an endpoint added late in the project's history, confirm it received
   the same auth-wiring treatment as earlier, structurally similar
   `+server.ts`/`load`/`action` handlers — this is where inconsistent
   enforcement gaps concentrate.

## Evidence Checklist

- [ ] For an XSS finding: the exact `{@html ...}` call site is cited, plus
      the file/line where the rendered value originates from user input,
      with the data flow between them traced concretely.
- [ ] Confirmation that no sanitizer call sits between the user input and the
      `{@html}` sink in the traced flow.
- [ ] For a missing-auth finding: the exact `+server.ts`/`load`/`action`
      file:line is cited, plus confirmation that neither the handler itself
      nor a load function that SvelteKit's routing model would actually run
      before it performs an auth check.
- [ ] Confirmation the flagged route is not an intentionally public endpoint
      (login/signup action, public search, webhook receiver with its own
      signature check, health check).
- [ ] For a secret-exposure finding: the exact `$env/static/public` /
      `$env/dynamic/public` import or PUBLIC_-prefixed declaration is cited,
      plus a concrete reason the value is sensitive, not just that it's in
      the public module.

A finding without at least one concrete code-snippet evidence entry must not
be submitted.

## Attack Scenario Template

> An attacker submits [user-controlled field] containing `[payload]`. Because
> [specific file:line] renders it via `{@html}` without sanitization, the
> payload executes in the browser of any user who views [specific
> page/component], resulting in [concrete impact — session token theft,
> account takeover, stored XSS reaching an admin viewing user-submitted
> content].

> An attacker calls `[METHOD] [route path]` directly with no session cookie,
> targeting a `+server.ts` endpoint that sits under a route whose page layout
> is protected but whose API handler is not. Because [specific file:line]
> performs [privileged action] before any `event.locals` check, the request
> succeeds, resulting in [concrete impact].

Fill every bracket concretely from evidence gathered in this repo. If a
bracket can't be filled from real evidence, cap severity at `medium` and note
exploitability is unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:sveltekit` node exists (created on the first
  SvelteKit-related finding in a scan).
- An XSS finding via `{@html}` gets a `causes` edge from `component:xss` to
  the `finding:<uuid>` node; if the root cause is a missing sanitizer, note
  that explicitly in the finding's `reasoning` field.
- A missing-auth `+server.ts`/`load`/`action` finding gets a `causes` edge
  from `component:api_security` to the finding node, and a `depends_on` edge
  from `component:sveltekit` to `component:api_security`.
- A `$env/static/public`/`PUBLIC_`-prefixed secret-exposure finding gets a
  `causes` edge from `component:secrets` to the finding node, and an
  `exposes` edge from `component:secrets` to `component:sveltekit`.
- If a secret-exposure finding is what makes a subsequent finding possible
  (e.g. a leaked API key enables an attacker to call a third-party service
  directly, or a leaked session-signing secret enables session forgery), say
  so in the `reasoning` field so the graph mapper wires a `causes` edge
  between the two finding nodes rather than treating them as unrelated.
