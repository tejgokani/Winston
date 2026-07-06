---
id: technology.astro.astro_security
title: Astro Security
category: technology
vulnerabilityClass: framework_specific_misconfiguration
appliesToStack: astro
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
  - title: "Astro Docs — set:html directive (escapes by default, opt-in to raw HTML)"
    url: "https://docs.astro.build/en/reference/directives-reference/#sethtml"
    type: security_blog
  - title: "Astro Docs — Environment Variables (PUBLIC_ prefix is bundled into client code)"
    url: "https://docs.astro.build/en/guides/environment-variables/"
    type: security_blog
  - title: "withastro/astro — DOM Clobbering Gadget found in Astro's client-side router leads to XSS (GHSA-m85w-3h95-hcf9)"
    url: "https://github.com/withastro/astro/security/advisories/GHSA-m85w-3h95-hcf9"
    type: vendor_security_advisory
  - title: "Cross-site Scripting (XSS) in astro — server-islands.ts insecure JSON.stringify usage (SNYK-JS-ASTRO-7547139)"
    url: "https://security.snyk.io/vuln/SNYK-JS-ASTRO-7547139"
    type: vendor_security_advisory
  - title: "Astro Cloudflare adapter — Stored XSS in /_image endpoint via unvalidated data: URLs (CVE-2025-65019)"
    url: "https://github.com/advisories/GHSA-fvmw-cj7j-j39q"
    type: vendor_security_advisory
quickModeSummary: >
  Check every `set:html={...}` for whether the value is user-controlled and
  unsanitized (Astro auto-escapes everything except what's explicitly opted
  out via set:html). Check every file under src/pages/api/**/*.ts (and any
  on-demand-rendered .astro page) for an auth check before it touches data or
  performs a mutation — Astro does not wire auth for you. Check every env var
  read via import.meta.env or astro:env for a PUBLIC_ prefix; anything
  PUBLIC_-prefixed is bundled into client-shipped JS, so a secret given that
  prefix (API key, DB URL, signing secret) is exposed to every visitor.
fileSelectionHint:
  roles: ["route_handler", "component", "config"]
  matchImports: ["astro:env", "astro/config"]
  matchAuthMapTags: ["astro"]
  maxFiles: 10
  priorityOrder: ["route_handler", "component", "config"]
severityHeuristics:
  critical:
    - "set:html renders a value derived from user input (query param, form field, DB row populated from user input, URL param) with no sanitization step"
    - "A secret (API key, DB connection string, signing key, third-party service token) is read via a PUBLIC_-prefixed env var or exported from astro:env/client, shipping it into the client bundle"
    - "An API route under src/pages/api/**/*.ts performs a state-changing action (POST/PUT/PATCH/DELETE) with no session/auth check before executing"
  high:
    - "An API route or on-demand-rendered page returns another user's data without verifying the requester owns/can access that resource (IDOR via missing ownership check, not just missing auth)"
    - "set:html is used on content sanitized by a custom/ad-hoc filter (regex strip, naive replace) instead of a maintained sanitizer library"
  medium:
    - "A PUBLIC_-prefixed variable holds non-secret but sensitive operational detail (internal hostname, feature-flag payload) that gives an attacker reconnaissance value without directly being a credential"
    - "set:html renders trusted CMS/markdown content that is rendered without any output-context awareness (e.g. no CSP configured as defense-in-depth) even though the source itself is not directly user-controlled"
  low:
    - "Astro's built-in CSP experimental flag is available but not enabled, with no compensating output encoding review evidenced elsewhere in the review"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:astro"
  relatedNodeIds: ["component:api_security", "component:secrets", "component:xss"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:astro"
    to: "component:api_security"
  - relation: protects
    from: "component:api_security"
    to: "component:astro"
  - relation: exposes
    from: "component:secrets"
    to: "component:astro"
commonAiCodingMistakes:
  - "AI is asked to render markdown/CMS/rich-text content and reaches for `<Fragment set:html={content} />` or `<div set:html={content} />` directly on a value that traces back to a user-submitted field (comment body, bio, profile field) instead of running it through a sanitizer (e.g. DOMPurify, sanitize-html) first — Astro's escaping is bypassed entirely by design once set:html is used, so there is no framework safety net left."
  - "AI scaffolds a new file under src/pages/api/ (e.g. api/users/[id].ts) by copying an existing authenticated route's shape but forgets to copy the actual `Astro.locals.session` / auth-check call, especially when the new route is added in a later, separate turn from where auth middleware was originally set up."
  - "AI prefixes an env var with PUBLIC_ to 'fix' a build error where `import.meta.env.SOME_KEY` was undefined in a client-side `<script>` block, not realizing that renaming it to PUBLIC_SOME_KEY doesn't fix a scoping bug — it ships the variable to every browser, and if that variable is actually a secret (API key, webhook secret) this converts a build-time inconvenience into a public credential leak."
  - "AI writes an Astro middleware.ts that checks auth for page routes but does not realize (or reviewer does not verify) that src/pages/api/*.ts endpoints are separate request targets that bypass that middleware if the middleware's `matcher`/path logic doesn't explicitly include /api/*."
  - "AI enables `output: 'server'` (or a hybrid/on-demand route) to add dynamic behavior to a previously fully-static site, without adding any authentication/session layer, because the original static site had no such surface — the new server-rendered routes silently become live attack surface with zero auth wired in."
falsePositiveGuardrails:
  - "Do not flag set:html when the rendered value is fully build-time/author-controlled (e.g. inlined from a local markdown/MDX file collection processed by Astro's content collections, or a hardcoded string) — the risk is specifically about user-controlled data reaching set:html, not the directive's mere presence."
  - "Do not flag set:html when the value has already passed through a recognized sanitizer (DOMPurify, sanitize-html, rehype-sanitize) immediately upstream in the same data flow — verify the sanitizer call exists and covers the actual value being rendered, don't assume its presence anywhere in the file is sufficient."
  - "A PUBLIC_-prefixed variable is not automatically a finding — confirm it actually holds sensitive material (a credential/secret) rather than a legitimately public value (analytics ID, public API base URL, feature flag meant for the client). Cross-check the variable's origin/naming against what it's used for."
  - "An API route with no explicit auth check is not automatically a vulnerability — verify it isn't an intentionally public endpoint (public search, static content API, webhook receiver with its own signature verification, health check) before writing a Finding, the same way you would for any other framework's route map."
  - "Astro's default static (`output: 'static'`) pages have no server-side request handling at request time — do not apply API-route-missing-auth heuristics to plain .astro pages unless the project is confirmed to use `output: 'server'`/`hybrid` or the specific page opts into on-demand rendering via `export const prerender = false`."
---

## Root Cause Explanation

Astro's security posture is unusual among frameworks in that its defaults are
genuinely safe — HTML expressions (`{value}`) are auto-escaped, static output
has no server request surface, and most vulnerabilities in Astro apps come
from a developer (or an AI agent) deliberately opting out of a safe default,
or from Astro's newer server-rendering capabilities being bolted onto code
that was written assuming a purely static site. Three recurring patterns:

1. **`set:html` opt-out escaping.** Astro escapes all expression output by
   default (`{userInput}` is always safe from XSS). `set:html` is the
   explicit, named escape hatch — its entire purpose is to inject raw HTML
   unescaped. Because it's the *only* way to render rich HTML content (from a
   CMS, markdown, user bios, comments), it gets reached for reflexively, and
   the sanitization step that should gate it is easy to skip, especially when
   an AI agent is optimizing for "render this markdown field" and treats
   `set:html` as the generic solution without distinguishing trusted
   build-time content from user-submitted content.
2. **API routes are just files — nothing wires auth automatically.**
   `src/pages/api/*.ts` endpoints are plain request handlers. Astro provides
   middleware (`src/middleware.ts`) as the idiomatic place to enforce auth,
   but nothing forces a given API route to be covered by it — a route added
   later, or added in a hurry, can simply not go through the auth check path,
   the same "inconsistent enforcement across routes" failure mode seen in
   hand-rolled Express/Next.js API routes.
3. **`PUBLIC_` is a bundling instruction, not a permissions system.** Astro
   (like Vite, which it builds on) treats any env var prefixed `PUBLIC_` as
   safe to inline into client-shipped JavaScript. There is no runtime check,
   no warning — the prefix is purely a naming convention that the build
   tooling trusts blindly. An AI agent chasing a "why is this undefined in
   the browser" bug will often rename a variable to add the prefix without
   registering that this changes its trust boundary from server-only to
   world-readable.

## Vulnerable Patterns

```astro
---
// src/pages/profile/[id].astro
const { bio } = await getUser(Astro.params.id); // bio is user-submitted
---
<!-- Bypasses Astro's default auto-escaping entirely; bio is rendered raw -->
<div set:html={bio} />
```

```ts
// src/pages/api/users/[id]/promote.ts
// No session/role check before a privileged, state-changing action
export async function POST({ params, request }) {
  const { role } = await request.json();
  await db.user.update({ where: { id: params.id }, data: { role } });
  return new Response(null, { status: 204 });
}
```

```ts
// astro.config.mjs / .env
// A secret given the PUBLIC_ prefix ships straight into the client bundle
PUBLIC_STRIPE_SECRET_KEY=sk_live_...
```

```astro
---
import { PUBLIC_STRIPE_SECRET_KEY } from 'astro:env/client';
// Now readable by anyone who opens devtools on any page that imports this
---
```

## Data Flow Tracing Guide

1. Grep the codebase for every `set:html` (and `Fragment set:html`,
   `is:raw`) usage. For each, trace the value backward to its source: is it a
   literal, build-time content-collection/MDX data, or does it originate from
   a request (`Astro.params`, `Astro.url.searchParams`, `await
   request.json()`, a DB row populated by a prior user submission)? If
   user-controlled, is there a sanitizer call (DOMPurify, sanitize-html,
   rehype-sanitize) directly upstream in the same flow?
2. Enumerate every file under `src/pages/api/**/*.ts` and every `.astro` page
   with `export const prerender = false` (or the project has `output:
   'server'`/`'hybrid'` globally). For each: does it read `Astro.locals` (or
   equivalent) for a session/user set by `src/middleware.ts`, and does that
   check happen before any data access or mutation, not after?
3. Read `src/middleware.ts` (if present) and confirm its matcher/path logic
   actually covers `/api/*` — middleware written for page-route auth doesn't
   automatically apply to API routes unless explicitly scoped to include
   them.
4. Grep for every `PUBLIC_` prefixed identifier (in `.env*`, `import.meta.env.PUBLIC_*`,
   `astro:env/client` imports) and check what each variable actually holds —
   is it a credential, connection string, or signing secret rather than a
   value legitimately meant for the browser?
5. For an on-demand route added late in the project's history (check git
   blame / file recency if available), confirm it received the same
   auth-wiring treatment as earlier, structurally similar routes — this is
   where "inconsistent enforcement" gaps concentrate.

## Evidence Checklist

- [ ] For an XSS finding: the exact `set:html={...}` call site is cited, plus
      the file/line where the rendered value originates from user input, with
      the data flow between them traced concretely (not asserted).
- [ ] Confirmation that no sanitizer call sits between the user input and the
      `set:html` sink in the traced flow.
- [ ] For a missing-auth finding: the exact API route file/line is cited,
      plus confirmation `src/middleware.ts` (if it exists) does not cover
      that route's path, or the route itself has no inline auth check.
- [ ] Confirmation the flagged route is not an intentionally public endpoint
      (checked against route naming/context, e.g. `/api/health`,
      `/api/webhooks/*`).
- [ ] For a secret-exposure finding: the exact `PUBLIC_`-prefixed
      declaration/import is cited, plus a concrete reason the value is
      sensitive (what it authenticates/accesses), not just that it's
      prefixed PUBLIC_.

A finding without at least one concrete code-snippet evidence entry must not
be submitted.

## Attack Scenario Template

> An attacker submits [user-controlled field] containing `[payload]`. Because
> [specific file:line] renders it via `set:html` without sanitization, the
> payload executes in the browser of any user who views [specific
> page/component], resulting in [concrete impact — session token theft,
> account takeover, stored XSS reaching an admin viewing user-submitted
> content].

> An attacker calls `[METHOD] [route path]` directly with no session cookie.
> Because [specific file:line] performs [privileged action] before any
> `Astro.locals`/session check, the request succeeds, resulting in [concrete
> impact — unauthorized data mutation, privilege escalation, data
> exfiltration].

Fill every bracket concretely from evidence gathered in this repo. If a
bracket can't be filled from real evidence, cap severity at `medium` and note
exploitability is unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:astro` node exists (created on the first
  Astro-related finding in a scan).
- An XSS finding via `set:html` gets a `causes` edge from `component:xss` to
  the `finding:<uuid>` node; if the root cause is a missing sanitizer, note
  that explicitly in the finding's `reasoning` so a related
  "add sanitization" remediation can be linked.
- A missing-auth API route finding gets a `causes` edge from
  `component:api_security` to the finding node, and a `depends_on` edge from
  `component:astro` to `component:api_security`.
- A `PUBLIC_`-prefixed secret-exposure finding gets a `causes` edge from
  `component:secrets` to the finding node, and an `exposes` edge from
  `component:secrets` to `component:astro`.
- If a secret-exposure finding is what makes a subsequent finding possible
  (e.g. a leaked API key enables an attacker to call a third-party service
  directly), say so in the `reasoning` field so the graph mapper wires a
  `causes` edge between the two finding nodes rather than treating them as
  unrelated.
