---
id: technology.vercel.deployment_security
title: Vercel Deployment Security
category: technology
vulnerabilityClass: insecure_deployment_configuration
appliesToStack: vercel
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A05:2021 Security Misconfiguration"
  - "A04:2021 Insecure Design"
cweRefs:
  - "CWE-284"
  - "CWE-522"
  - "CWE-799"
realWorldReferences:
  - title: "Vercel Knowledge Base — Vercel April 2026 security incident bulletin"
    url: "https://vercel.com/kb/bulletin/vercel-april-2026-security-incident"
    type: vendor_security_advisory
  - title: "Vercel Docs — Deployment Protection (Preview URLs public by default on Hobby; production only protected on Pro/Enterprise)"
    url: "https://vercel.com/docs/deployment-protection"
    type: vendor_security_advisory
  - title: "Vercel Docs — Environment variables (Production / Preview / Development scoping)"
    url: "https://vercel.com/docs/environment-variables"
    type: vendor_security_advisory
  - title: "Vercel Docs — Sensitive environment variables (write-only values)"
    url: "https://vercel.com/docs/environment-variables/sensitive-environment-variables"
    type: vendor_security_advisory
  - title: "Upstash — Rate Limiting Your Next.js App with Vercel Edge (why in-memory counters don't survive across serverless invocations/regions)"
    url: "https://upstash.com/blog/edge-rate-limiting"
    type: security_blog
quickModeSummary: >
  Check three Vercel-specific gaps: (1) is Deployment Protection configured,
  or are preview URLs (`*.vercel.app` branch/PR deployments) left at Vercel's
  default of being reachable by anyone with the link, while carrying the same
  env vars as production? (2) Are environment variables scoped per-target
  (Production / Preview / Development) or dumped into "all environments,"
  so a preview build — including ones triggered by external contributors'
  forked PRs — gets live production credentials? (3) Is rate limiting or
  other in-process state (counters, caches, locks) implemented with a plain
  in-memory object/Map, which does not work on Vercel's serverless model
  since each invocation can land on a different, ephemeral instance/region
  with no shared memory?
fileSelectionHint:
  roles: ["infra", "deployment", "middleware", "api_route"]
  matchImports: ["vercel.json", "@vercel/", "next.config.js", "next.config.ts"]
  matchAuthMapTags: ["vercel", "deployment_protection", "rate_limit"]
  maxFiles: 8
  priorityOrder: ["deployment", "infra", "middleware", "api_route"]
severityHeuristics:
  critical:
    - "A production-only secret (payment provider key, DB credential, signing key) is scoped to 'all environments' (or explicitly to Preview) in Vercel project settings, AND the project accepts preview deployments from external/forked pull requests — the secret is reachable by anyone who can open a PR."
  high:
    - "Deployment Protection is not enabled (or is left at Vercel's Hobby-plan default, which never protects the production domain) for a project handling authenticated user data or payments — preview URLs are guessable/discoverable and expose a full working copy of the app with production-equivalent env vars."
    - "Rate limiting on an auth, payment, or otherwise abuse-sensitive endpoint is implemented with a module-level in-memory counter/Map/array (`const attempts = new Map()`) with no external store — this provides no real protection on Vercel's serverless model, since concurrent/region-distributed invocations do not share memory."
  medium:
    - "Environment variables holding real secrets are not marked as 'Sensitive' in Vercel project settings, so their values remain readable in the dashboard/API by anyone with project access, rather than write-only."
    - "A `VERCEL_AUTOMATION_BYPASS_SECRET` (or similar deployment-protection bypass) is hardcoded in a committed file or client-exposed code path rather than injected as its own protected env var."
  low:
    - "Preview deployments are protected but the project relies on Vercel's default Standard Protection alone with no additional review of who has access to the team (protection is only as strong as team membership hygiene)."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:vercel_deployment"
  relatedNodeIds: ["component:secrets", "component:rate_limiting", "component:preview_environment"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:preview_environment"
    to: "component:secrets"
  - relation: protects
    from: "component:vercel_deployment"
    to: "component:production_data"
commonAiCodingMistakes:
  - "AI adds a new environment variable via the Vercel dashboard flow (or a `.env`-to-Vercel sync script) and, absent explicit instruction, defaults to checking 'all environments' since that's the path of least friction — production secrets end up available to every preview build, including ones built from external contributors' forked pull requests."
  - "AI scaffolds rate limiting for an API route using a simple `const requestCounts = new Map()` at module scope, because that's the textbook single-process rate-limiter pattern from countless tutorials — it works perfectly in local `next dev` (one persistent process) and silently does nothing in production, where each invocation may be a cold-started, geographically distributed, short-lived function instance with its own memory."
  - "AI treats a preview deployment as inherently non-sensitive ('it's just a preview') and doesn't flag that it shares the same env var set as production unless the developer has manually gone into project settings and re-scoped each variable — the assumption that preview == throwaway/safe is not backed by Vercel's actual default data-exposure model."
  - "AI copies a rate-limiting or caching snippet built for a traditional long-running server (Express with an in-memory LRU cache, a global Redis-less counter) directly into a Next.js API route or middleware file without adapting it for the serverless/edge execution model, because the code compiles and 'works' in a quick local test with a single invocation."
  - "AI wires up Deployment Protection bypass (`VERCEL_AUTOMATION_BYPASS_SECRET`) for CI/E2E testing but leaves the bypass secret in a checked-in CI config file or test script instead of Vercel/CI-native secret storage, defeating the purpose of having protection at all."
falsePositiveGuardrails:
  - "Do not flag 'all environments' scoping for genuinely non-sensitive config (feature flags, public API base URLs, `NEXT_PUBLIC_*` values already intended for client exposure) — this playbook targets credential-shaped values (API keys, DB URLs, signing secrets, payment provider keys) getting the same 'all environments' treatment as harmless config."
  - "Do not flag missing Deployment Protection on a project confirmed to be on Vercel's Hobby plan without first checking whether the app actually handles sensitive data — for a genuinely low-stakes demo/personal project, this is a low-severity note, not high; but for anything touching real user data, do flag it regardless of plan tier as an actionable gap (upgrade or restrict PR-preview triggering)."
  - "Do not flag in-memory rate limiting on routes that are not abuse-sensitive (e.g. a static content route, a route already behind Deployment Protection auth) with the same severity as auth/payment/write endpoints — confirm the endpoint's actual sensitivity before assigning high/critical."
  - "If the codebase demonstrably uses an external store for rate-limiting/shared state (Upstash Redis via `@upstash/ratelimit`, Vercel KV, a database-backed counter), do not flag it as the in-memory anti-pattern even if a local in-memory fallback exists for local dev only — verify which path actually executes in the deployed environment before concluding the protection is absent."
  - "A project using Vercel's custom/staging environments (Pro/Enterprise) with its own explicit variable scoping is not automatically vulnerable just because it has more than the standard three environments — evaluate whether each custom environment's variables match its actual sensitivity, not whether it deviates from the three-environment default."
---

## Root Cause Explanation

Vercel-specific deployment security failures come from three ways the
platform's actual default behavior diverges from what AI-scaffolded code
(and many developers) implicitly assume:

1. **Preview deployments are reachable and carry production-equivalent
   secrets by default.** Every push to a non-production branch, and every
   pull request, produces a live `*.vercel.app` deployment. Unless
   Deployment Protection is explicitly configured, that URL is reachable by
   anyone who has the link — and on the free Hobby plan, even *with*
   protection turned on, only preview URLs are protected; the production
   domain is never protected without a Pro/Enterprise plan. The deeper issue
   is that a preview deployment is not, by default, a stripped-down or
   sandboxed copy of the app — it runs the exact same code against whichever
   environment variables are scoped to "Preview" (or "All Environments"),
   which very often includes real, live credentials for convenience. Combine
   an externally-triggerable preview build (from a forked PR) with
   production secrets scoped into Preview, and you have a live credential
   exfiltration path that requires no authentication at all — the exact
   mechanism behind Vercel's own disclosed April 2026 incident, where a
   supply-chain-compromised third-party integration was used to trigger
   builds on preview environments and exfiltrate environment variables that
   were not marked "Sensitive."
2. **Environment variable scoping defaults toward over-sharing.** Vercel's
   env var UI lets a variable be scoped to Production, Preview, Development,
   or all three at once. Because scoping to "all environments" is the path
   of least friction (one click instead of three considered choices), and
   because most tutorials/scaffolds don't dwell on the distinction, secrets
   that should only ever exist in Production end up available to every
   Preview and Development build as well.
3. **The serverless execution model breaks naive stateful patterns.**
   Vercel Functions (and Edge Functions/Middleware) are not one long-running
   process holding shared memory the way a traditional Express server is.
   Each invocation can be served by a different instance, in a different
   region, with a cold start that wipes any module-level in-memory state.
   Code that implements rate limiting, caching, or locking with a plain
   in-memory `Map`/counter will appear to work in local development (a
   single persistent `next dev` process) and then provide effectively zero
   protection in production, because concurrent or subsequent requests very
   often do not hit the same instance/memory at all.

## Vulnerable Patterns

Look for shapes like these (illustrative, not exhaustive — reason about
equivalents in the actual stack you're reviewing, don't string-match):

```ts
// In-memory rate limiter — silently ineffective on Vercel's serverless model
const attempts = new Map<string, number>();

export async function POST(req: Request) {
  const ip = req.headers.get('x-forwarded-for') ?? 'unknown';
  const count = attempts.get(ip) ?? 0;
  if (count > 5) {
    return new Response('Too many requests', { status: 429 });
  }
  attempts.set(ip, count + 1);
  // ...
}
```

```jsonc
// vercel.json / project settings — no deployment protection configured,
// meaning preview URLs for every branch/PR are reachable by link alone
{
  "buildCommand": "next build"
  // no "deploymentProtection" / no equivalent project-level setting enabled
}
```

```
# Vercel dashboard env var configuration (conceptual, not code) —
# a production secret scoped to "All Environments" instead of
# Production-only, so it's injected into every Preview build too:
STRIPE_SECRET_KEY = sk_live_xxxxxxxxxxxxxxxx     [x] Production [x] Preview [x] Development
```

## Data Flow Tracing Guide

To evaluate this playbook responsibly, trace the following before writing any
Finding:

1. Check whether Deployment Protection is referenced anywhere in project
   config, CI setup, or documentation (`vercel.json`, README, CI YAML
   referencing `VERCEL_AUTOMATION_BYPASS_SECRET`). Absence of any reference
   is evidence, not proof — confirm by checking whether the project accepts
   PRs from forks (repo settings, CI trigger config) if that information is
   available in-repo.
2. For every environment variable referenced in code (`process.env.X`),
   check whether the corresponding value is expected to be a real secret
   (naming: `*_SECRET`, `*_KEY`, `*_TOKEN`, `DATABASE_URL`,
   `*_API_KEY`) versus general config. Where Vercel env var scoping is
   visible (a `.env.example`, a `vercel.json`, project docs, or an IaC/
   Terraform provider config for Vercel), check whether secret-shaped
   variables are scoped narrower than "all environments."
3. Search all API route handlers and middleware for rate limiting or
   abuse-prevention logic. For each one found, trace where its counter/state
   is stored: a module-level variable/`Map`/array (in-memory, broken on
   Vercel) versus an external call (Redis/Upstash, a database, Vercel KV,
   an edge config store).
4. Cross-check `middleware.ts`/`middleware.js` — logic there runs on the
   Edge Runtime, which has an even shorter-lived, more distributed execution
   model than standard serverless Functions, making in-memory state even
   less reliable there.
5. If a `VERCEL_AUTOMATION_BYPASS_SECRET` or similar protection-bypass value
   is referenced, trace where it's sourced from — an env var injected by
   the platform/CI secret store (correct) versus a literal string in a
   committed file (incorrect).

## Evidence Checklist

Before submitting a Finding for this playbook, confirm:

- [ ] At least one concrete code snippet with an exact file + line range is
      attached as evidence — do not paraphrase, quote the actual line(s).
- [ ] If claiming an over-scoped secret: the variable name and its inferred
      sensitivity (why it looks like a real secret, not generic config) are
      stated explicitly, along with where the scoping evidence came from
      (`.env.example`, `vercel.json`, IaC config, or explicit note that
      scoping isn't visible in-repo and Vercel's dashboard default is being
      cited as the reasoning).
- [ ] If claiming missing Deployment Protection: note the plan tier if
      knowable, since the practical fix differs (Hobby → restrict preview
      triggering / avoid sensitive data in preview; Pro/Enterprise → enable
      "All Deployments" protection scope).
- [ ] If claiming a broken in-memory rate limiter: the exact
      variable/Map declaration and its usage in the request-handling
      function are both cited, and confirmation that no external store call
      exists in the same code path.
- [ ] Confirmation that the endpoint/variable in question is genuinely
      sensitive (auth, payment, PII, or credential-shaped) rather than
      public-by-design config or a non-abuse-sensitive route.

A finding without at least one concrete code-snippet evidence entry must not
be submitted.

## Attack Scenario Template

> An attacker discovers a live preview deployment at [specific URL pattern,
> e.g. a `*.vercel.app` branch/PR deployment] via [link sharing, a forked
> PR they opened, guessable branch naming]. Because [specific env var /
> Deployment Protection gap] means the preview build carries [specific
> credential] scoped to Preview/all environments, the attacker extracts it
> via [specific mechanism: reading a client-exposed response, triggering a
> build log leak, direct env var access if they control the PR's CI
> context], resulting in [concrete impact specific to this repo — e.g. "the
> extracted key grants write access to the production database referenced
> in `<file>`," echoing the mechanism in Vercel's own April 2026 incident
> disclosure, where compromised preview-triggering access led to
> exfiltration of environment variables that were not marked Sensitive]."
>
> Separately, for a rate-limiting finding: an attacker sends [N] requests to
> [specific endpoint] in rapid succession. Because [specific in-memory
> counter] does not persist across [serverless invocations/regions/cold
> starts], each request is evaluated against a fresh/near-empty counter,
> allowing [concrete abuse outcome specific to this repo — e.g. unlimited
> password-guessing attempts against `<login route>`].

Fill every bracket concretely from evidence gathered in this repo. If a
bracket can't be filled from real evidence, the scenario is speculative and
severity must be capped at `medium`, with a note that exploitability is
unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:vercel_deployment` node exists (create it on
  the first Vercel-related finding in a scan), with a `depends_on` edge from
  `component:preview_environment` to `component:secrets` when an
  over-scoped secret finding is present.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from `component:vercel_deployment`
  (or a more specific root-cause component, e.g. `component:secrets` for
  env-var scoping issues, `component:rate_limiting` for in-memory state
  issues) to the finding node.
- If an over-scoped-secret finding involves a credential that grants access
  to another modeled component (a database, a payment provider, a
  third-party API), add an `enables` edge from the finding node to that
  component's node id, so the graph captures the blast radius beyond "a
  secret was exposed."
- Root cause vs. symptom: if a missing-Deployment-Protection finding and an
  over-scoped-secret finding co-occur, note in the finding's `reasoning`
  field that the protection gap is what makes the scoping issue exploitable
  without authentication — wire a `causes` edge from the protection finding
  to the secret-exposure finding rather than treating them as independent.
