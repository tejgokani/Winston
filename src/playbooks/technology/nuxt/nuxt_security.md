---
id: technology.nuxt.nuxt_security
title: Nuxt Security Mistakes — v-html XSS, Unguarded Server Routes, Leaked Runtime Config
category: technology
vulnerabilityClass: broken_access_control
appliesToStack: nuxt
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A03:2021 Injection"
  - "A01:2021 Broken Access Control"
  - "A02:2021 Cryptographic Failures"
cweRefs:
  - "CWE-79"
  - "CWE-862"
  - "CWE-798"
  - "CWE-200"
realWorldReferences:
  - title: "Runtime Config · Nuxt Advanced (official docs — public vs. private keys, client/server exposure)"
    url: "https://nuxt.com/docs/guide/going-further/runtime-config"
    type: vendor_security_advisory
  - title: "Server Directory · Nuxt Directory Structure (official docs — server/api routes, event handlers, middleware)"
    url: "https://nuxt.com/docs/directory-structure/server"
    type: vendor_security_advisory
  - title: "CVE-2026-47200: Nuxt route middleware not enforced when rendering .server.vue pages via /__nuxt_island/page_* (GitLab Advisory Database)"
    url: "https://advisories.gitlab.com/npm/nuxt/CVE-2026-47200/"
    type: vendor_security_advisory
  - title: "Security · Vue.js official guide (v-html, script gadgets, why Vue treats template-injection as out of scope)"
    url: "https://vuejs.org/guide/best-practices/security.html"
    type: vendor_security_advisory
  - title: "Evading defences using VueJS script gadgets — PortSwigger Research"
    url: "https://portswigger.net/research/evading-defences-using-vuejs-script-gadgets"
    type: research_paper
  - title: "Sessions and Authentication · Nuxt Recipes (official docs — requireUserSession, server route protection patterns)"
    url: "https://nuxt.com/docs/guide/recipes/sessions-and-authentication"
    type: vendor_security_advisory
quickModeSummary: >
  Three independent checks for Nuxt: (1) any `v-html="..."` binding —
  is the interpolated value ever derived from user input (route params,
  query strings, API responses reflecting user content, rich-text fields)
  without server-side sanitization (e.g. DOMPurify)? (2) every file under
  `server/api/*` and `server/routes/*` — does it call an auth check
  (`requireUserSession`, a custom `protectRoute`/session-verification
  utility, or global `server/middleware`) before touching data, or is
  reliance solely on client-side route guards which don't protect the
  underlying HTTP endpoint? (3) every key under `runtimeConfig` in
  `nuxt.config.ts` — is a secret (API key, DB credential, signing key)
  placed under `runtimeConfig.public` (or referenced via a `NUXT_PUBLIC_`
  env var) where it ships to every client bundle, instead of staying
  under the private (server-only) top-level key?
fileSelectionHint:
  roles: ["route_handler", "component", "config", "middleware", "server_action"]
  matchImports: ["nuxt", "#imports", "h3", "nitropack", "vue"]
  matchAuthMapTags: ["nuxt_server_route", "nuxt_runtime_config"]
  maxFiles: 10
  priorityOrder: ["config", "route_handler", "middleware", "component"]
severityHeuristics:
  critical:
    - "A secret with real privilege (API key granting write access, DB credential, JWT/session signing key, third-party payment key) is defined under `runtimeConfig.public` in `nuxt.config.ts` or sourced from a `NUXT_PUBLIC_*` env var — it is bundled into client-side JS and readable by anyone who loads the page."
    - "A `server/api/*` or `server/routes/*` handler performs a state-changing operation (delete, payment, role change, data write) with no session/auth check anywhere in its body or in applicable `server/middleware`, reachable by a direct unauthenticated HTTP request regardless of what the Vue UI shows."
  high:
    - "`v-html` renders a value that traces back to user-controlled input (query param, route param, form field, another user's profile/comment content) with no sanitization step (e.g. DOMPurify) between the source and the binding — stored or reflected XSS."
    - "A `server/api/*` route checks session presence but not resource ownership/tenant scope, allowing any authenticated user to read or mutate another user's/tenant's data by supplying a different id (IDOR)."
  medium:
    - "Auth/ownership logic in server routes is duplicated ad hoc per-handler (via manually repeated checks) rather than centralized in `server/middleware` or a shared utility, making it plausible that a newly added or copy-pasted route omits the check — verify by diffing check logic across similarly-shaped routes before flagging a specific one as missing."
    - "A non-secret but sensitive operational value (internal service URL, feature flag controlling access, internal id scheme) is placed under `runtimeConfig.public` — not directly exploitable on its own, but expands the client-visible attack surface and should be flagged as a config hygiene issue, not necessarily critical."
  low:
    - "`v-html` is used only on static, developer-authored content with no path from any user input source (e.g. hardcoded marketing copy) — defense-in-depth note only, not an active vulnerability."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:nuxt_framework"
  relatedNodeIds: ["component:xss_prevention", "component:api_security", "component:secrets", "component:authorization"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:nuxt_framework"
    to: "component:authorization"
  - relation: depends_on
    from: "component:nuxt_framework"
    to: "component:secrets"
  - relation: protects
    from: "component:xss_prevention"
    to: "component:nuxt_framework"
commonAiCodingMistakes:
  - "AI reaches for `v-html` to render rich text (a comment, a bio, a markdown-rendered field) because it 'just works' and looks correct in a manual test with benign content, without adding a sanitization step — Vue's auto-escaping via `{{ }}` interpolation is the safe default, and `v-html` is an explicit opt-out AI treats as equivalent to normal text rendering rather than as a raw-HTML injection point."
  - "AI scaffolds a `server/api/*.ts` route by copying the shape of an existing protected route but drops the `requireUserSession`/`protectRoute` call because the new route 'looks like' a simple read operation, or adds the route in a session where the auth pattern used elsewhere in `server/middleware` isn't in context."
  - "AI puts a value under `runtimeConfig.public` (or names an env var `NUXT_PUBLIC_*`) specifically because it needs the value in a client component, without registering that `public` is a deliberate client-exposure boundary rather than just a naming convention — the same class of mistake seen with `NEXT_PUBLIC_`/`VITE_`-prefixed env vars in other frameworks."
  - "AI relies on a client-side navigation guard (Vue Router `beforeEach`, a Nuxt route middleware defined with `defineNuxtRouteMiddleware`) as the only access control for a page whose data is fetched from a `server/api/*` route, not realizing route middleware only gates client-side navigation/SSR rendering of that specific route and does not, by itself, protect the underlying API endpoint from being called directly — the same failure class documented in CVE-2026-47200, where `.server.vue` pages reachable via `/__nuxt_island/page_*` bypassed route middleware entirely."
falsePositiveGuardrails:
  - "Do not flag `v-html` if the codebase pipes the value through a sanitizer (DOMPurify, `sanitize-html`, or equivalent) immediately before the binding, or if the sanitization happens server-side before the content is ever stored/returned — confirm by tracing the value back through its transform chain, not just by finding the `v-html` call site."
  - "Do not flag a `runtimeConfig.public.*` key as a leak just because it's under `public` — that's the framework's intended mechanism for shipping non-secret config (API base URLs, feature flags, public client ids like a Stripe publishable key) to the client. Only flag it if the specific value is actually sensitive (grants write/privileged access, is a private/secret credential, or is meant to be server-only) — check what the key controls, not just its namespace."
  - "Do not flag a `server/api/*` route as unauthenticated if protection is provided globally via `server/middleware/*.ts` (Nuxt/Nitro runs all server middleware before route handlers) — check the middleware directory and `event.context` for auth state set upstream before concluding a specific handler lacks a check."
  - "A route with no auth check is not automatically a vulnerability — cross-check whether it is an intentionally public endpoint (public content API, health check, webhook receiver with its own signature verification) before writing a Finding."
---

## Root Cause Explanation

Nuxt sits on top of two frameworks whose security defaults are easy to
undo with a single, innocuous-looking line: Vue on the client, and Nitro
(the `server/` directory) on the server. Three recurring failure classes
show up across both AI-assisted and human-written Nuxt code:

1. **`v-html` bypasses Vue's own XSS protection.** Vue's `{{ }}`
   interpolation auto-escapes everything by default — this is *the*
   reason Vue templates are safe against XSS out of the box. `v-html` is
   an explicit, named escape hatch that tells Vue "render this string as
   raw HTML, do not escape it." Vue's own security docs are blunt about
   this: rendering arbitrary user-provided content via `v-html` is
   "inherently dangerous," and Vue does not treat exploitation of an
   app's own `v-html` misuse as a framework vulnerability, because there
   is no way for the framework to protect a developer who explicitly
   asked it not to. AI-generated code reaches for `v-html` constantly for
   rich-text fields (bios, comments, markdown-rendered content) because
   it "looks correct" against benign test data, with no separate
   sanitization step in the chain.
2. **Nuxt server routes have no implicit auth.** Every file under
   `server/api/*` or `server/routes/*` becomes a live HTTP endpoint the
   moment it exists — Nitro does not know or care whether a Vue page
   "guards" access to it. A client-side `defineNuxtRouteMiddleware` or
   Vue Router guard controls whether a *page* renders/navigates; it says
   nothing about whether the *API route* that page's data comes from can
   be hit directly with curl. This exact class of bypass was serious
   enough to be assigned CVE-2026-47200: Nuxt's own route middleware was
   found not to be enforced when `.server.vue` pages were requested via
   the internal `/__nuxt_island/page_*` endpoint, letting an
   unauthenticated caller reach content that relied on middleware alone.
   Auth belongs *inside* the server route (or in `server/middleware`
   that runs for every request), never only on the client side.
3. **`runtimeConfig.public` is a client-shipping boundary, not a naming
   suggestion.** Nuxt's official docs are explicit: keys under the
   top-level `runtimeConfig` are server-only by default; only keys nested
   under `runtimeConfig.public` (plus `app`) are also available
   client-side, serialized into the page/client bundle. This is
   functionally identical to the `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_`
   prefix convention in other frameworks — a value placed in the wrong
   bucket, or an env var misnamed with the `NUXT_PUBLIC_` prefix, ships a
   secret to every visitor's browser.

## Vulnerable Patterns

```vue
<!-- Renders arbitrary attacker-controlled HTML with no sanitization -->
<template>
  <div v-html="comment.bodyHtml"></div>
</template>
<script setup>
const { comment } = defineProps(['comment'])
// comment.bodyHtml came straight from another user's submitted content
</script>
```

```ts
// server/api/orders/[id].ts — no auth check at all, reachable by anyone
export default defineEventHandler(async (event) => {
  const id = getRouterParam(event, 'id')
  return await db.order.findUnique({ where: { id } }) // no ownership scoping either
})
```

```ts
// nuxt.config.ts — secret placed in the client-exposed bucket
export default defineNuxtConfig({
  runtimeConfig: {
    public: {
      stripeSecretKey: process.env.NUXT_PUBLIC_STRIPE_SECRET_KEY, // ships to every browser
    },
  },
})
```

Correct shape for comparison:

```vue
<template>
  <div v-html="sanitizedBody"></div>
</template>
<script setup>
import DOMPurify from 'dompurify'
const { comment } = defineProps(['comment'])
const sanitizedBody = computed(() => DOMPurify.sanitize(comment.bodyHtml))
</script>
```

```ts
// server/api/orders/[id].ts — session + ownership check
export default defineEventHandler(async (event) => {
  const { user } = await requireUserSession(event)
  const id = getRouterParam(event, 'id')
  const order = await db.order.findUnique({ where: { id } })
  if (!order || order.userId !== user.id) {
    throw createError({ statusCode: 403, statusMessage: 'Forbidden' })
  }
  return order
})
```

```ts
// nuxt.config.ts — secret stays private, only non-secret config is public
export default defineNuxtConfig({
  runtimeConfig: {
    stripeSecretKey: process.env.STRIPE_SECRET_KEY, // server-only
    public: {
      stripePublishableKey: process.env.NUXT_PUBLIC_STRIPE_PUBLISHABLE_KEY, // fine, meant to be public
    },
  },
})
```

## Data Flow Tracing Guide

1. Grep for every `v-html` usage across `.vue` files. For each one, trace
   the bound expression backward to its source: a prop, a store value, an
   API response. If that source ultimately contains any user-submitted or
   third-party content (another user's profile/comment/bio, an uploaded
   file's parsed content, a CMS field editable by non-admins), determine
   whether a sanitizer (DOMPurify, `sanitize-html`, or a server-side
   markdown-to-safe-HTML pipeline) sits between the source and the
   binding. No sanitizer in the chain is the finding.
2. Enumerate every file under `server/api/**` and `server/routes/**`.
   For each, check: (a) does the handler body call a session-verification
   utility (`requireUserSession`, `getUserSession` + a manual check, or a
   project-specific `protectRoute`) before touching data or performing a
   mutation? (b) if not, does `server/middleware/*.ts` run first and set
   `event.context.user` (or similar) for this route path — check the
   middleware file(s) for any path-based exclusion logic that might skip
   this specific route.
3. For any route that does check auth, verify it also scopes the
   query/mutation to the authenticated user/tenant (ownership check), not
   just "is anyone logged in" — same IDOR reasoning as any other backend
   framework.
4. Read `nuxt.config.ts`'s `runtimeConfig` block in full. List every key
   under the private (top-level) section and every key under `public`.
   For each `public` key, ask: does this value grant access to anything
   (an API that can write/delete, a service credential, a signing key)?
   If yes, that's a leak — the value needs to move to the private section
   and be accessed only from `server/` code via `useRuntimeConfig(event)`.
5. Cross-check env var names: any `NUXT_PUBLIC_*`-prefixed variable is,
   by Nuxt's naming convention, intended to map to a `runtimeConfig.public.*`
   key — confirm nothing sensitive was named with that prefix out of habit
   copied from other frameworks' public-prefix conventions.

## Evidence Checklist

- [ ] For a `v-html` finding: the exact template binding is quoted with
      file + line, along with the full backward trace from binding to
      source, showing no sanitization step exists in between.
- [ ] For a missing-auth server route finding: the full handler body is
      quoted (file + line range), and `server/middleware/*` has been
      checked and confirmed not to cover this route path.
- [ ] For an IDOR-in-server-route finding: both the session check (if
      any) and the specific unscoped query/mutation line are cited.
- [ ] For a runtime config leak finding: the exact `nuxt.config.ts` line
      declaring the key under `runtimeConfig.public` (or the `NUXT_PUBLIC_*`
      env var) is cited, along with a concrete statement of what
      privilege/access that value grants.
- [ ] Confirmation the affected route/page is not an intentionally public
      exception (checked against `route_map`/`auth_map` context).

A finding without at least one concrete code-snippet evidence entry must
not be submitted.

## Attack Scenario Template

> An attacker [submits content containing a `<script>`/event-handler
> payload via <specific field> / sends a direct HTTP request to
> <specific server route> / inspects the client bundle for
> <specific runtimeConfig.public key>]. Because [specific file:line] does
> not [sanitize the v-html source / verify a session or ownership before
> the handler executes / keep the value under the private runtimeConfig
> section], the result is [concrete impact — e.g. "the payload executes
> in the browser of any user who views the comment," or "the attacker
> reads/mutates another tenant's order by id," or "the attacker obtains a
> credential capable of writing to the production database from the
> public JS bundle"].

Fill every bracket concretely from evidence gathered in this repo. If a
bracket can't be filled from real evidence, the scenario is speculative
and severity must be capped at `medium`, with a note that exploitability
is unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:nuxt_framework` node exists (create it on
  the first Nuxt-specific finding in a scan), with `depends_on` edges to
  `component:authorization` and `component:secrets`.
- A `v-html`/XSS finding gets a `causes` edge from `component:xss_prevention`
  (or `component:nuxt_framework` directly if no dedicated XSS component
  exists yet) to the finding node.
- A missing-auth server route finding gets a `causes` edge from
  `component:nuxt_framework` (or `component:api_security` if that
  component already exists in the graph) to the finding node.
- A `runtimeConfig.public` secret leak gets a `causes` edge from
  `component:secrets` to the finding node, and — if the leaked
  credential grants access to a specific downstream system (a database,
  a payments provider) — an additional `enables` edge from the finding
  node to that system's component node.
- If multiple server routes share the same missing-auth root cause (e.g.
  no centralized `server/middleware` auth, each route independently
  forgetting the check), note this explicitly in each finding's
  `reasoning` field so the graph mapper links them as symptoms of one
  systemic root cause rather than N unrelated findings.
