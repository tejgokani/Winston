---
id: ai_security.rate_limiting
title: Missing or Misconfigured Rate Limiting
category: ai_security
vulnerabilityClass: missing_rate_limiting
appliesToStack: technology-agnostic
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A04:2021 Insecure Design"
  - "A07:2021 Identification and Authentication Failures"
cweRefs:
  - "CWE-307"
  - "CWE-770"
  - "CWE-799"
realWorldReferences:
  - title: "Infogram disclosed on HackerOne: No Rate limit on Password Reset"
    url: "https://hackerone.com/reports/280389"
    type: bug_bounty_disclosure
  - title: "Reddit — Missing rate limit in current password change settings leads to Account Takeover (Report #1170522)"
    url: "https://hackerone.com/reports/1170522"
    type: bug_bounty_disclosure
  - title: "Acronis disclosed on HackerOne: Missing rate limit for current password change/reset"
    url: "https://hackerone.com/reports/827484"
    type: bug_bounty_disclosure
  - title: "The $0 Bug That Cost Us $1,800 in API Calls"
    url: "https://dev.to/arpitstack/the-0-bug-that-cost-us-1800-in-api-calls-3add"
    type: incident_postmortem
  - title: "Echoes of AI Exposure: Thousands of Secrets Leaking Through Vibe Coded Sites — RedHunt Labs"
    url: "https://redhuntlabs.com/blog/echoes-of-ai-exposure-thousands-of-secrets-leaking-through-vibe-coded-sites-wave-15-project-resonance/"
    type: security_blog
  - title: "OpenAI API Docs — Rate limits"
    url: "https://developers.openai.com/api/docs/guides/rate-limits"
    type: vendor_security_advisory
  - title: "Rate Limiting Next.js API Routes using Upstash Redis — Upstash Blog"
    url: "https://upstash.com/blog/nextjs-ratelimiting"
    type: security_blog
quickModeSummary: >
  Check auth endpoints (login, signup, password-reset request/confirm, OTP
  verification) and any endpoint that calls a paid LLM API (chat, generate,
  summarize, embed) for a rate limiter. If one exists, what is it keyed on —
  a trustworthy value (authenticated user id, source IP) or a spoofable
  client-supplied header/cookie/body field? Is the limiter actually wired
  into the request path (imported and called with an early return on
  failure), or defined but unused? Is it global-only (misses per-user abuse)
  or per-identity-only (misses distributed/anonymous abuse)?
fileSelectionHint:
  roles: ["route_handler", "api_route", "middleware", "auth"]
  matchImports:
    - "@upstash/ratelimit"
    - "@upstash/redis"
    - "express-rate-limit"
    - "rate-limiter-flexible"
    - "next-rate-limit"
    - "hono/rate-limiter"
    - "openai"
    - "@anthropic-ai/sdk"
  matchAuthMapTags: ["rate_limit", "auth", "llm"]
  maxFiles: 8
  priorityOrder: ["route_handler", "api_route", "middleware"]
severityHeuristics:
  critical:
    - "Login, signup, or password-reset-confirm (token verification) endpoint has no rate limiting at all, allowing unlimited credential-stuffing or reset-token brute-force attempts."
    - "An LLM-calling endpoint (chat/completion/generation/embedding) that uses the developer's own API key is reachable with no rate limiting and no per-user/session cap, allowing an attacker to run unbounded paid API calls at the developer's expense (cost-abuse / financial DoS)."
  high:
    - "Rate limiter exists but is keyed on a client-controlled value (e.g. `X-Forwarded-For` read without trusting only the edge/proxy-set value, a client-supplied session/device id header, or a body field) that an attacker can rotate per-request to bypass the limit entirely."
    - "Password-reset *request* endpoint (the one that sends the email/SMS) has no rate limiting, enabling email/SMS bombing of a victim or enumeration of valid accounts via response-timing/content differences at high volume."
    - "Rate limiter is defined/imported in the codebase but not actually invoked on the request path it was clearly intended to protect (dead security control)."
  medium:
    - "Rate limit exists and is correctly keyed, but the threshold is high enough to still allow meaningful brute force or cost accumulation before detection (e.g. thousands of requests/minute on a login endpoint)."
    - "Rate limiting is applied only at a global/IP level with no additional per-authenticated-user limit, so a distributed attacker (rotating IPs/proxies) can still brute-force or abuse a single account or the LLM budget."
  low:
    - "No rate limiting on low-risk, non-state-changing, non-costly read endpoints — flag only as a hardening note, not a standalone finding, unless combined with another issue (e.g. an expensive query or enumeration risk)."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:rate_limiting"
  relatedNodeIds: ["component:authentication", "component:api_security", "component:llm_integration"]
graphEdgeMapping:
  - relation: protects
    from: "component:rate_limiting"
    to: "component:authentication"
  - relation: protects
    from: "component:rate_limiting"
    to: "component:llm_integration"
commonAiCodingMistakes:
  - "AI scaffolds login/signup/password-reset routes with full validation logic but no rate limiter, because rate limiting is an infrastructure/cross-cutting concern that isn't triggered by 'build a login form' as a prompt — it has to be asked for explicitly or caught in review."
  - "AI adds an LLM-calling API route (chat, summarize, generate-image) as the core feature of an app but never adds a per-user or per-IP cap on it, because the immediate goal ('call OpenAI and stream the response') doesn't naturally surface cost-abuse as a concern during scaffolding."
  - "AI wires up `@upstash/ratelimit` (or similar) correctly in one route as an example, then the pattern isn't propagated to other sensitive routes added later in the same session or in subsequent prompts — inconsistent coverage identical to the JWT-middleware-consistency failure mode."
  - "AI implements a rate limiter keyed on `req.headers['x-forwarded-for']` or a similar client-suppliable header without deferring to the platform's trusted-proxy-injected IP (e.g. Vercel's `request.ip` / `ipAddress()` helper, or a properly configured `trust proxy` setting), making the limiter trivially bypassable by an attacker who sets that header themselves."
  - "AI builds a rate limiter using in-memory state (a plain object/Map counting requests) in a serverless/edge function, which resets on every cold start and is not shared across concurrent instances — the limiter looks present in code review but provides near-zero real protection in a horizontally-scaled deployment."
  - "AI leaves the LLM provider API key directly reachable from a client-callable endpoint with no application-level limit, relying solely on the provider's own account-level rate limits/spend caps as the only backstop — which are usually far too high to prevent a meaningful bill spike before the developer notices."
falsePositiveGuardrails:
  - "Do not flag an endpoint as unprotected if rate limiting is enforced upstream at the platform/edge level (e.g. a Vercel Firewall / WAF rate-limiting rule, Cloudflare rate limiting rule, or API gateway throttling) and that configuration is visible in the repo (e.g. `vercel.json`, Cloudflare config, IaC) — cite that config before concluding the limit is absent, or explicitly note it wasn't found in-repo and may exist out-of-band."
  - "Do not treat NextAuth/Auth.js, Clerk, Supabase Auth, or similar managed-auth-provider login/signup flows as unprotected merely because no rate limiter is visible in application code — these providers typically implement their own throttling; verify the specific provider's documented behavior before flagging, and focus review on custom endpoints layered on top (e.g. a custom password-reset-confirm route)."
  - "A rate limiter keyed on authenticated user id for an endpoint that requires authentication is correct and sufficient on its own for authenticated abuse; do not additionally demand IP-based limiting unless the endpoint is also reachable pre-authentication or the identity itself is cheap to mint (e.g. free self-service signup)."
  - "Do not flag internal/service-to-service endpoints (e.g. a webhook receiver validated by signature, or an internal cron-triggered route not reachable from the public internet) using the same bar as public user-facing endpoints — confirm reachability from an untrusted client before treating missing rate limiting there as a finding."
---

## Root Cause Explanation

Missing rate limiting is an *absence* vulnerability — nothing in the code is
wrong, something that should exist simply doesn't — which makes it one of the
easiest classes for both human and AI-assisted development to skip
entirely, and one of the easiest for a reviewer to miss too if the review is
scanning for incorrect logic rather than for a missing cross-cutting
control. It shows up in two shapes that matter most in a modern stack:

1. **Auth endpoints without throttling enable brute force.** Login,
   signup, password-reset-request, password-reset-confirm (token/OTP
   verification), and MFA-code-verification endpoints are all,
   fundamentally, "guess a secret" surfaces. Without a limit on attempts per
   identity/IP, an attacker can credential-stuff a leaked password list
   against a login endpoint, brute-force a 6-digit OTP or reset token in a
   feasible number of requests, or account-takeover a specific victim by
   guessing their reset code — this is one of the single most commonly
   disclosed bug-bounty finding categories precisely because it's so easy to
   forget and so mechanical to test for.
2. **LLM-calling endpoints without throttling enable cost-abuse.** This is
   the AI-era addition to the classic rate-limiting story: an endpoint that
   proxies a request to OpenAI/Anthropic/etc. using the *developer's own* API
   key turns "missing rate limit" from an availability/brute-force problem
   into a direct, uncapped financial liability. Provider-side rate limits
   exist, but they're sized for legitimate usage tiers, not for preventing a
   single abusive client from running the bill up before anyone notices —
   the application itself is the only layer positioned to cap this per
   user/session/IP before the request reaches the provider.
3. **A rate limiter that exists but is keyed on the wrong value is
   functionally the same as no rate limiter.** The whole point of the limit
   is to tie request cost to something the attacker can't cheaply mint or
   rotate. IP address (trusted only when sourced from the platform/proxy,
   not an attacker-suppliable header) or authenticated user id are
   trustworthy identifiers; a client-supplied header, cookie, or body field
   is not — an attacker controls it and can simply send a new one per
   request to reset their quota.

## Vulnerable Patterns

Look for shapes like these (illustrative, not exhaustive — reason about
equivalents in the actual stack you're reviewing, don't string-match):

```ts
// No rate limiting at all on a credential-guessing surface
export async function POST(req: Request) {
  const { email, password } = await req.json()
  const user = await db.user.findUnique({ where: { email } })
  if (!user || !(await verifyPassword(password, user.passwordHash))) {
    return Response.json({ error: 'Invalid credentials' }, { status: 401 })
  }
  return Response.json({ token: signToken(user) })
}

// LLM proxy endpoint with the dev's own key, no per-user/IP cap
export async function POST(req: Request) {
  const { prompt } = await req.json()
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'user', content: prompt }],
  })
  return Response.json(completion)
}

// Rate limiter keyed on a spoofable, client-supplied value
const identifier = req.headers.get('x-client-id') ?? 'anonymous' // attacker sets any value
const { success } = await ratelimit.limit(identifier)
```

```ts
// Correct shape for comparison: server-trusted IP + authenticated user id,
// both via a platform helper rather than a raw client header
const identifier = userId ?? ipAddress(req) ?? 'anonymous'
const { success } = await ratelimit.limit(identifier)
if (!success) return Response.json({ error: 'Too many requests' }, { status: 429 })
```

## Data Flow Tracing Guide

To evaluate this playbook responsibly, trace the following before writing any
Finding:

1. Enumerate auth-adjacent endpoints (login, signup, password-reset
   request/confirm, OTP/MFA verification, email-change confirmation) and
   every endpoint that calls an LLM provider SDK or a paid third-party API
   using a server-held credential. For each, is a rate limiter's `.limit(...)`
   (or equivalent) call actually present in the handler's execution path —
   not just imported/defined elsewhere unused?
2. If a limiter is present, trace its key/identifier argument back to its
   source. Is it derived from a platform-trusted value (an edge-injected IP
   header validated by the platform, an authenticated session's user id) or
   from something the request itself supplies unchecked?
3. If a limiter is present, confirm its storage backend is shared/durable
   across instances (e.g. Upstash Redis) rather than in-process memory that
   resets per cold start or isn't shared across concurrent serverless
   instances — an in-memory counter in a horizontally-scaled deployment is
   close to a no-op.
4. For endpoints protected by a managed auth provider (NextAuth, Clerk,
   Supabase Auth), check whether the specific route in question (e.g. a
   *custom* password-reset-confirm handler built on top of the provider) is
   actually covered by the provider's built-in throttling, or whether it's
   custom code layered on top that needs its own limiter.
5. Check for platform/edge-level rate limiting configuration in the repo
   (`vercel.json` firewall rules, Cloudflare rules, API gateway config)
   before concluding an endpoint is fully unprotected — an app-code-only
   scan can miss protection enforced at the infrastructure layer.

## Evidence Checklist

Before submitting a Finding for this playbook, confirm:

- [ ] At least one concrete code snippet with an exact file + line range is
      attached as evidence — do not paraphrase, quote the actual line(s).
- [ ] The specific endpoint's full request path/method is cited, and its
      classification (auth-sensitive, LLM-cost-sensitive, or neither) is
      stated explicitly.
- [ ] If claiming a missing limiter: confirm (by reading the route handler
      end-to-end) that no limiter call exists in that path, and that no
      platform/edge-level config in the repo covers it.
- [ ] If claiming a spoofable-key limiter: cite the exact line where the
      identifier is derived and explain concretely why it's attacker-
      controllable in this codebase's deployment context.
- [ ] If claiming cost-abuse risk on an LLM endpoint: confirm the endpoint
      actually calls a paid provider using a server-held key (not a
      client-supplied key), and note the model/endpoint used if visible, to
      support the impact statement.

A finding without at least one concrete code-snippet evidence entry must not
be submitted.

## Attack Scenario Template

> An attacker sends repeated requests to [specific endpoint], varying
> [password guess / reset token / prompt payload] each time. Because
> [specific code location] does not enforce a rate limit tied to a
> trustworthy identifier, the attacker is able to [brute-force the
> credential/token within a feasible number of attempts / issue unlimited
> calls to the developer's LLM provider account], resulting in [concrete
> impact specific to this repo, e.g. "account takeover of any user whose
> email is known" or "unbounded OpenAI API spend on the developer's billing
> account, since the endpoint proxies requests using a server-held key with
> no per-user cap"].

Fill every bracket concretely from evidence gathered in this repo. If a
bracket can't be filled from real evidence, the scenario is speculative and
severity must be capped at `medium`, with a note that exploitability is
unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:rate_limiting` node exists (create it on the
  first rate-limiting-related finding in a scan) with `protects` edges to
  whichever of `component:authentication` and `component:llm_integration`
  are relevant to the finding.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from `component:rate_limiting` to
  the finding node.
- If a missing/bypassable rate limit finding enables reaching a specific
  downstream impact already modeled elsewhere in the graph (e.g. it enables
  brute-forcing into `component:authentication`, or enables unbounded spend
  against `component:llm_integration`), add an `enables` edge from the
  finding node to that component's node id.
- Root cause vs. symptom: if a spoofable-key finding is the reason a
  rate-limiting finding is exploitable (rather than the limiter being
  entirely absent), say so explicitly in the finding's `reasoning` field so
  the graph mapper distinguishes "no control" from "control present but
  bypassable" when wiring `causes` edges.
---
