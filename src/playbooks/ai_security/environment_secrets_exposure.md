---
id: ai_security.environment_secrets_exposure
title: Environment Secrets Exposure via Build-Time Prefixes
category: ai_security
vulnerabilityClass: secrets_exposure
appliesToStack: technology-agnostic
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A02:2021 Cryptographic Failures"
  - "A05:2021 Security Misconfiguration"
cweRefs:
  - "CWE-200"
  - "CWE-798"
  - "CWE-540"
realWorldReferences:
  - title: "Hunting Secrets in JavaScript at Scale: How a Vite Misconfiguration Lead to Full CI/CD Compromise"
    url: "https://www.sprocketsecurity.com/blog/hunting-secrets-in-javascript-at-scale-how-a-vite-misconfiguration-lead-to-full-ci-cd-compromise"
    type: security_blog
  - title: "Hardcoded Secrets in AI-Generated Code: Catch Them Before Git Does"
    url: "https://www.toxsec.com/p/why-vibe-coding-leaks-your-secrets"
    type: security_blog
  - title: "Next.js Docs: Guides — Environment Variables"
    url: "https://nextjs.org/docs/pages/guides/environment-variables"
    type: vendor_security_advisory
  - title: "Vite Docs: Env Variables and Modes"
    url: "https://vite.dev/guide/env-and-mode"
    type: vendor_security_advisory
  - title: "The State of Secrets Sprawl 2026 (GitGuardian)"
    url: "https://www.gitguardian.com/state-of-secrets-sprawl-report-2026"
    type: research_paper
quickModeSummary: >
  Check every env var with a bundler-exposure prefix (NEXT_PUBLIC_, VITE_,
  EXPO_PUBLIC_, REACT_APP_, GATSBY_, PUBLIC_ for SvelteKit) for values that
  are actually secret — private API keys, database URLs, signing secrets,
  service-role keys — rather than values genuinely meant for the browser
  (publishable/anon keys, public config). Any such prefix ships the value
  into the client JS bundle verbatim at build time; there is no runtime
  gate, no auth check, and no way to revoke exposure short of rotating the
  credential.
fileSelectionHint:
  roles: ["config", "frontend", "build_config"]
  matchImports: ["next.config", "vite.config", "app.config", "webpack.config"]
  matchAuthMapTags: []
  maxFiles: 10
  priorityOrder: ["config", "frontend"]
severityHeuristics:
  critical:
    - "A private/secret-scoped API key (payment provider secret key, service-role/admin database key, signing key) is assigned to an env var using a bundler-exposure prefix (NEXT_PUBLIC_, VITE_, EXPO_PUBLIC_, REACT_APP_, GATSBY_, PUBLIC_) and that var is referenced anywhere in client-rendered code"
    - "A full database connection string (with embedded credentials) is assigned to a prefixed var"
  high:
    - "A third-party API key with meaningful cost/quota/data exposure (e.g. an unscoped LLM provider key, an email-sending API key) is exposed via a bundler prefix, even if the key is 'read-only' in intent but the provider offers no such scoping"
    - "A prefixed var's value is a JWT signing secret, webhook signing secret, or internal service-to-service auth token"
  medium:
    - "A prefixed var exposes an internal-only URL/hostname (staging admin panel, internal API gateway) that isn't itself a credential but expands the attack surface by revealing infrastructure"
    - "A key that is legitimately publishable (e.g. a Stripe publishable key, a Supabase anon key with RLS enforced) is exposed via the correct prefix, but there is no evidence server-side authorization (RLS policies, key restrictions) actually constrains what that key can do — the exposure is intentional but the backstop is unverified"
  low:
    - "A non-secret but internal build/version identifier is exposed via a prefix unnecessarily (no security impact, just unnecessary surface)"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:secrets"
  relatedNodeIds: ["component:frontend_build", "component:api_security"]
graphEdgeMapping:
  - relation: exposes
    from: "component:frontend_build"
    to: "component:secrets"
commonAiCodingMistakes:
  - "AI is asked to 'connect the frontend to Stripe/Supabase/an LLM provider' and, needing the value available in a client component, prefixes the secret-scoped key with NEXT_PUBLIC_/VITE_/REACT_APP_ to make `process.env`/`import.meta.env` resolve in the browser — the fastest way to make the code run, not the correct one. The model is optimizing for 'undefined error goes away,' not for the trust boundary the prefix crosses."
  - "AI copies an existing prefixed var's naming pattern for a new secret without re-deriving whether that specific value should be public — once one NEXT_PUBLIC_/VITE_ var pattern exists in a repo, the AI treats it as the established convention for 'how config gets read' and reuses it for genuinely sensitive values added later."
  - "AI scaffolds a `.env.local`/`.env` with both public and private keys, and when asked to 'fix an env var not showing up in the client,' the fix applied is to add the exposure prefix rather than to move the read to a server-only code path (API route, server action, edge function) — this is a very common one-line 'fix' that silently converts a private secret into a public one."
  - "AI-generated code reads the same conceptual value (e.g. a database key) through two different env vars in different files — one correctly server-only, one accidentally prefixed for a client component that doesn't actually need it — because the AI didn't trace that both originate from the same credential."
falsePositiveGuardrails:
  - "A prefixed var holding a value the provider explicitly designed to be public (Stripe *publishable* key `pk_...`, a Supabase *anon* key intended to be paired with Row Level Security, a Google Maps browser-restricted API key, a public Sentry DSN, a Firebase client config object) is not a finding by itself — these are meant to ship to the browser. Escalate only if there's evidence the corresponding server-side authorization (RLS policy, key HTTP-referrer restriction, Firebase security rules) is missing or misconfigured, which would make the intentionally-public key exploitable."
  - "Do not flag a prefixed var just because its name contains 'key' or 'token' — inspect the actual value/source or its documented purpose. A `NEXT_PUBLIC_ANALYTICS_KEY` for a client-side analytics SDK is routinely public by design."
  - "Do not flag secret-shaped values inside `.env.example`, `.env.template`, README code fences, or CI fixture files as live exposures — confirm the file is a real runtime config path, not documentation or a placeholder template."
  - "If the same secret is read in both a server-only file (correct) and a prefixed var (incorrect), report it as one exposure finding tied to the prefixed read site, not two separate secret-handling findings — the root cause is the exposure mechanism, not duplicate storage."
---

## Root Cause Explanation

Modern frontend build tools solve a real problem: client-side code needs some
configuration values (a public API base URL, a publishable payment key, a
feature-flag value) baked in at build time, since there's no server-side
request to inject them at runtime. Every major framework solves this the same
way — a naming convention that tells the bundler "inline this value into the
JS output verbatim":

- Next.js: `NEXT_PUBLIC_*`
- Vite (and Vite-based frameworks: SvelteKit's `PUBLIC_*`, Astro's `PUBLIC_*`): `VITE_*`
- Expo: `EXPO_PUBLIC_*`
- Create React App: `REACT_APP_*`
- Gatsby: `GATSBY_*`

The mechanism is not a runtime feature flag or an access-controlled endpoint
— it is literal string substitution performed by the bundler at build time.
Whatever value the env var holds at build time becomes a plaintext string
embedded directly in the shipped `.js` file, downloadable and readable by
anyone who loads the page, with no authentication, no expiry, and no way to
revoke it other than rotating the underlying credential and rebuilding.

The vulnerability class exists because the prefix is *opt-in by naming
convention only* — the tooling has no concept of "this specific value is too
sensitive to inline," it only checks whether the variable name matches a
string prefix. This creates a single-token failure mode: adding four
characters (`VITE_`) or twelve characters (`NEXT_PUBLIC_`) in front of a
variable name is the entire difference between "server-only, never leaves
the backend" and "burned into every page load, forever, for every visitor."

This is a distinct mechanism from generic hardcoded-secrets (see
`ai_security.secrets_management`) — the value here is often correctly sourced
from an environment variable (good practice for a *server* secret), but the
naming convention itself is the leak. A reviewer who only checks "is this
hardcoded in source" will miss it, because the code looks idiomatic.

## Vulnerable Patterns

```js
// Next.js — a payment provider's SECRET key, not the publishable key, exposed to every client bundle
// .env: NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_...
const stripe = new Stripe(process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY);

// Vite — a database connection string with embedded credentials, shipped to the browser
// .env: VITE_DATABASE_URL=postgres://user:pass@host:5432/db
const db = createClient(import.meta.env.VITE_DATABASE_URL);

// Expo — an LLM provider key meant for server-side calls, exposed via the client-safe prefix
// .env: EXPO_PUBLIC_OPENAI_API_KEY=sk-...
fetch('https://api.openai.com/v1/chat/completions', {
  headers: { Authorization: `Bearer ${process.env.EXPO_PUBLIC_OPENAI_API_KEY}` }
});

// Create React App — service-role/admin key intended to bypass row-level security, exposed
// .env: REACT_APP_SUPABASE_SERVICE_ROLE_KEY=eyJ...
const supabaseAdmin = createClient(url, process.env.REACT_APP_SUPABASE_SERVICE_ROLE_KEY);
```

Contrast with the correct pattern for the same intent — the value stays
server-only and the client calls a server-owned endpoint instead:

```js
// Next.js API route / server action — secret stays server-side, never prefixed
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY); // no NEXT_PUBLIC_
```

## Data Flow Tracing Guide

1. Enumerate every environment variable read in the codebase (`.env*` files,
   `process.env.*`, `import.meta.env.*`, `Constants.expoConfig.extra.*`) and
   sort them by whether their name matches a bundler-exposure prefix for the
   detected stack (`NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `REACT_APP_`,
   `GATSBY_`, `PUBLIC_`).
2. For each prefixed var, classify the *value's provider-intended
   sensitivity* — not its name. Check the value's shape/prefix against known
   patterns (`sk_live_`/`sk_test_` = Stripe secret key vs `pk_` = publishable;
   a Postgres/Mongo connection URI with inline credentials; a JWT-looking
   `service_role` key vs an `anon` key) and cross-reference against the
   provider's own documentation on what's meant to be public if uncertain.
3. Trace where each prefixed var is *read* — is it actually used in
   client-rendered code (a component, a hook, anything bundled for the
   browser), or is it defined with the prefix but only read in
   server-only files (still worth flagging as an unnecessary-exposure-risk,
   lower severity, since the prefix means it *will* ship if any client
   import path touches that module)?
4. Check whether the same conceptual credential also has a correctly
   server-only counterpart var elsewhere in the codebase — this indicates a
   copy/duplication mistake rather than an intentional design, and is strong
   evidence of AI-assisted incremental scaffolding (see
   `commonAiCodingMistakes`).
5. If a build config file (`next.config.js`'s legacy `env` key,
   `vite.config.js`'s `define`) manually inlines a var without going through
   the naming convention, treat it identically — the exposure mechanism is
   the same regardless of whether the prefix or a manual `define`/`env` block
   triggers it.

## Evidence Checklist

- [ ] The exact file + line where the prefixed variable is declared (`.env`,
      `.env.local`, `.env.production`, or a `next.config`/`vite.config`
      manual inline) is cited, with the variable name and enough of the
      value's shape shown to argue it's a genuine secret (never paste a full
      live credential into a finding — reference its shape/prefix, e.g.
      "value begins `sk_live_`").
  is cited.
- [ ] The exact file + line where the prefixed variable is *consumed* in
      client-bundled code is cited, establishing it does reach the browser
      (not just declared with the prefix and unused).
- [ ] A specific justification for why the value is provider-secret-scoped
      rather than provider-public-scoped (key prefix convention, API
      documentation, or the presence of a matching correctly-scoped
      public/publishable key elsewhere suggesting this one was meant to stay
      private).
- [ ] If claiming duplication (same secret also exists as a correctly
      server-only var), both locations are cited.

## Attack Scenario Template

> The environment variable `[VAR_NAME]`, declared at [file:line] with the
> [NEXT_PUBLIC_/VITE_/EXPO_PUBLIC_/REACT_APP_/GATSBY_] prefix, holds what
> appears to be a [provider] [secret/private-scoped] credential. Because the
> bundler inlines this value into the shipped client JavaScript at
> [file:line consuming it], any visitor to the deployed site can extract the
> literal value via browser devtools or by downloading the bundle directly
> (no authentication required). With this credential, an attacker can
> [concrete impact — e.g. "make authenticated calls to the payments API as
> the application, including refunds/payouts", "read or write any row in the
> database bypassing application-level authorization", "consume the LLM
> provider's quota/billing under the victim's account"].

Fill every bracket concretely. If the value's sensitivity can't be confirmed
(e.g. an ambiguous internal token whose scope is unclear from the code
alone), cap severity at `medium` and note the ambiguity explicitly rather
than asserting exploitability.

## Graph Mapping Instructions

- Always ensure a `component:secrets` node exists (reuse the one from
  `ai_security.secrets_management` if already created in this scan) and a
  `component:frontend_build` node representing the bundler/build pipeline.
- Add an `exposes` edge from `component:frontend_build` to
  `component:secrets` for each distinct finding.
- Each concrete exposure becomes its own `finding:<uuid>` vulnerability node.
  If the exposed credential is also used elsewhere in the codebase (e.g. the
  same Stripe secret key is used server-side for a payments component), add
  an `enables` edge from the finding to that downstream component's node —
  the exposure is the root cause that makes attacks on that component
  possible without needing to compromise the server at all.
- If a finding involves a database or admin/service-role key, add an
  `enables` edge from the finding node directly to `component:database` (or
  the most specific data-store node), since this is one of the few
  vulnerability classes that can grant complete, unauthenticated,
  unauthorized data access with zero additional chained steps.
