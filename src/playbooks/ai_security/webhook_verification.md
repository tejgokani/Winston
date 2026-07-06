---
id: ai_security.webhook_verification
title: Webhook Signature Verification
category: ai_security
vulnerabilityClass: webhook_forgery
appliesToStack: technology-agnostic
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A08:2021 Software and Data Integrity Failures"
cweRefs:
  - "CWE-345"
  - "CWE-306"
realWorldReferences:
  - title: "New API: Stripe Webhook Signature Bypass via Empty Secret Enables Unlimited Quota Fraud (CVE-2026-41432)"
    url: "https://github.com/advisories/GHSA-xff3-5c9p-2mr4"
    type: vendor_security_advisory
  - title: "n8n: Missing Stripe-Signature Verification Allows Unauthenticated Forged Webhooks (GHSA-jf52-3f2h-h9j5)"
    url: "https://github.com/n8n-io/n8n/security/advisories/GHSA-jf52-3f2h-h9j5"
    type: vendor_security_advisory
  - title: "clerk/backend Webhook Verification Vulnerability (CVE-2025-53548, GHSA-9mp4-77wg-rwx9)"
    url: "https://github.com/clerk/javascript/security/advisories/GHSA-9mp4-77wg-rwx9"
    type: vendor_security_advisory
  - title: "Bypassing Payments Using Webhooks (Jack Cable)"
    url: "https://cablej.io/blog/bypassing-payments-using-webhooks/"
    type: security_blog
  - title: "Stripe Docs: Resolve webhook signature verification errors"
    url: "https://docs.stripe.com/webhooks/signature"
    type: vendor_security_advisory
  - title: "GitHub Docs: Validating webhook deliveries"
    url: "https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries"
    type: vendor_security_advisory
quickModeSummary: >
  Find every webhook receiver endpoint (Stripe, Clerk, Supabase, GitHub,
  PayPal, Shopify, Twilio, etc.) and confirm it verifies the provider's
  signature header (e.g. Stripe-Signature, X-Hub-Signature-256) using the
  provider's SDK/HMAC verification against a real, non-empty secret, and that
  this check runs and rejects the request BEFORE any side-effecting business
  logic executes. An endpoint that parses the JSON body and acts on it
  without verification accepts forged events from anyone who knows the URL.
fileSelectionHint:
  roles: ["route_handler", "webhook", "integration", "payments"]
  matchImports: ["stripe", "svix", "@clerk/backend", "@octokit/webhooks", "twilio"]
  matchAuthMapTags: ["webhook"]
  maxFiles: 8
  priorityOrder: ["webhook", "route_handler", "integration"]
severityHeuristics:
  critical:
    - "A webhook route triggers a financially or access-consequential side effect (marking an order/subscription paid, granting account access, issuing a refund, provisioning a resource) with no signature verification present at all"
    - "Signature verification is present but the secret used to verify is empty, a hardcoded placeholder, or sourced from a fallback default that could be unset in production (mirrors the empty-secret HMAC-forgery class: an empty/default secret computes a valid HMAC for any attacker-chosen payload)"
  high:
    - "Signature verification happens, but the side-effecting logic runs before or independent of the verification result (verification result is computed but not actually gating execution — e.g. logged/checked but not used in a conditional that halts processing)"
    - "Verification uses a non-constant-time string comparison for the computed vs provided signature, creating a timing side-channel that can leak the correct signature byte-by-byte"
  medium:
    - "Verification is present and correctly gates execution, but there's no replay protection (timestamp/nonce check) — a captured legitimate webhook payload can be re-sent indefinitely to re-trigger the same side effect"
    - "The webhook secret is sourced correctly but there's no evidence it's distinct per-environment (same secret conceivably shared between staging and production, increasing blast radius if one leaks)"
  low:
    - "A webhook endpoint for a low-consequence event (e.g. a logging/analytics webhook with no state-changing side effect) lacks verification — still a gap, but not immediately exploitable for material impact"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:webhook_integration"
  relatedNodeIds: ["component:api_security", "component:payments"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:webhook_integration"
    to: "component:authentication"
  - relation: protects
    from: "component:webhook_integration"
    to: "component:payments"
commonAiCodingMistakes:
  - "AI scaffolds a webhook route by directly parsing `req.body`/`request.json()` and acting on the event type/payload, mirroring the simplest example in a provider's quickstart docs — provider documentation frequently shows signature verification as a secondary/optional step or omits it from the first code sample entirely, and the AI reproduces the unverified quickstart version because it's the shortest path to 'the webhook works when I test it with curl.'"
  - "AI correctly implements verification for the first webhook handler in a codebase (e.g. Stripe), then scaffolds a second provider's webhook (e.g. Clerk or GitHub) by copying the route structure but not the verification step, because each provider's verification mechanism differs (different header name, different SDK call) and the AI treats route scaffolding and security verification as separable concerns rather than one atomic unit."
  - "AI wires up webhook signature verification but leaves the signing secret defaulted to an empty string or a placeholder (mirroring the exact real-world pattern behind CVE-2026-41432 in the 'New API' project) because the actual secret is meant to be configured post-deployment, and no startup check rejects an empty secret before accepting traffic."
  - "AI's verification code computes whether the signature is valid but the actual gating (`if (!valid) return 403`) is scaffolded as a TODO, a console.warn, or is present but structurally disconnected from the code path that executes the side effect (e.g. in a different function that isn't awaited/checked)."
falsePositiveGuardrails:
  - "Do not flag a webhook receiver that uses the provider's official verification helper/middleware (e.g. Stripe's constructEvent, GitHub's documented HMAC comparison, Svix's verify) correctly and gates execution on its result — confirm the actual gating control flow before concluding verification is 'present but ineffective.'"
  - "A webhook endpoint intentionally left public/unverified for a genuinely non-sensitive purpose (e.g. a health-check ping, a public status-page webhook with no side effects) is not a finding — check what the handler actually does before assuming verification is required."
  - "Do not conflate webhook signature verification with general API authentication (API keys, JWTs, session cookies) — a webhook endpoint correctly has no user session by design (the caller is the provider's server, not a logged-in user); the control that matters here is exclusively signature/HMAC verification against a shared secret."
  - "If verification is implemented via framework-level middleware or a well-known SDK not present in the scanned file set, check auth_map/route_map/import graph before concluding verification is missing — the route handler itself may legitimately look bare because verification happens upstream."
---

## Root Cause Explanation

Webhook endpoints invert the usual trust model: instead of the application
initiating a request to a trusted API, an external provider (Stripe, Clerk,
Supabase, GitHub, PayPal, Shopify, Twilio, and others) initiates an
unauthenticated-by-default HTTP POST to a URL the application exposes. There
is no session, no cookie, no user login involved — anyone who discovers or
guesses the URL can POST to it. The *only* thing distinguishing a genuine
event from a forged one is a cryptographic signature the provider attaches
to the request (commonly an HMAC computed over the raw request body using a
secret shared between the provider and the receiving application, sent in a
header like `Stripe-Signature` or `X-Hub-Signature-256`).

This vulnerability class follows a consistent shape across every disclosed
instance:

1. **No verification at all.** The handler trusts the JSON body directly.
   Provider quickstart documentation is partly responsible here — the
   simplest "hello world" webhook example in many providers' docs parses and
   acts on the payload first, with signature verification introduced as a
   security best-practice addendum rather than baked into the minimal
   example.
2. **Verification present but not enforced.** The signature is computed and
   compared, but a bug in the control flow means a failed check doesn't
   actually stop execution — the classic "verify-then-ignore-the-result"
   bug, functionally identical to having no check.
3. **Verification enforced but the secret is weak/empty.** HMAC verification
   with an empty or default secret computes a "valid" signature for
   literally any payload an attacker chooses, since the attacker can compute
   the same HMAC with the same known-empty key. This is not a hypothetical —
   it is the exact root cause behind a disclosed 2026 CVE in an open-source
   LLM gateway project, where an unset Stripe webhook secret allowed
   unlimited quota fraud.
4. **Insufficient verification depth.** Some SDKs/helpers verify signature
   *format* or perform an incomplete check (a documented real-world example:
   Clerk's `verifyWebhook()` helper had a disclosed vulnerability, CVE-2025-
   53548, where certain inputs could cause improperly signed events to be
   accepted as legitimate) — meaning "the code calls a verify function"
   isn't sufficient evidence by itself; the actual verification semantics
   matter, and using an outdated/vulnerable SDK version is itself part of
   this vulnerability class.

Because a user never directly interacts with a webhook endpoint, these
handlers escape the kind of manual testing that surfaces bugs in
user-facing flows — nobody clicks a button that hits `/api/webhooks/stripe`,
so an unverified handler can sit in production, apparently working
correctly, indefinitely.

## Vulnerable Patterns

```js
// No verification at all — trusts the JSON body directly
app.post('/api/webhooks/stripe', express.json(), (req, res) => {
  const event = req.body;
  if (event.type === 'checkout.session.completed') {
    markOrderPaid(event.data.object.metadata.orderId); // forgeable by anyone
  }
  res.sendStatus(200);
});

// Verification computed but not enforced — the bug hides in plain sight
app.post('/api/webhooks/github', (req, res) => {
  const valid = verifySignature(req); // computed...
  // ...but never checked before proceeding
  handleGithubEvent(req.body);
  res.sendStatus(200);
});

// Verification enforced, but the secret has an empty/placeholder fallback
const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET || '';
const event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
// an empty secret still "verifies" — HMAC with a known-empty key is forgeable
```

Correct pattern for comparison:

```js
app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), (req, res) => {
  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      req.headers['stripe-signature'],
      process.env.STRIPE_WEBHOOK_SECRET // must be non-empty, verified at startup
    );
  } catch (err) {
    return res.status(400).send(`Webhook signature verification failed: ${err.message}`);
  }
  // only reached if verification succeeded
  if (event.type === 'checkout.session.completed') markOrderPaid(/* ... */);
  res.sendStatus(200);
});
```

## Data Flow Tracing Guide

1. Identify every route that receives inbound webhooks — look for route
   paths containing `webhook`, imports of provider SDKs (`stripe`, `svix`,
   `@clerk/backend`, `@octokit/webhooks`), and any route explicitly excluded
   from normal auth middleware in `route_map`/`auth_map` (webhook routes are
   *correctly* excluded from session/JWT auth, which is a signal to check
   them against this playbook specifically, not a false-positive dismissal).
2. For each such route, trace whether a signature-verification call exists
   (provider SDK helper or manual HMAC comparison against a raw body).
3. If verification exists, trace its *result* forward — is there a
   conditional that halts execution (returns a 4xx, throws, early-returns)
   on failure, and does the side-effecting logic run strictly after that
   gate, not in parallel or before it?
4. Trace where the verification secret is sourced from — is it read from an
   environment variable with no fallback, or does it have a `||
   ''`/`|| 'placeholder'` fallback that would make verification trivially
   bypassable if unset? (Cross-reference with
   `ai_security.environment_secrets_exposure` and
   `ai_security.secrets_management` if a related finding already exists.)
5. Check whether the SDK/library version used for verification has any known
   advisories (e.g. Clerk's CVE-2025-53548) if version information is
   available in a lockfile/manifest.
6. Check for replay protection — does the handler validate the event
   timestamp/tolerance window or track processed event IDs to reject
   duplicates, or would a captured valid payload be replayable indefinitely?

## Evidence Checklist

- [ ] The exact file + line of the webhook route handler is cited.
- [ ] Either: (a) the exact line showing no verification call exists in the
      handler's code path, or (b) the exact line where verification is
      called AND the exact line(s) showing its result is not used to gate
      execution.
- [ ] If claiming a weak-secret issue: the exact line where the secret is
      sourced, showing the fallback/default.
- [ ] The exact side-effecting statement(s) reached without a passing
      verification gate (e.g. the database write, the access grant), cited
      by file + line.
- [ ] Confirmation this is a genuine external-provider webhook endpoint (not
      an internal-only callback already covered by network-level trust or a
      different auth mechanism this playbook doesn't apply to).

## Attack Scenario Template

> The endpoint at [file:line] receives webhook events from [provider] but
> [does not verify the provider's signature / verifies but does not enforce
> the result / verifies against a secret with a bypassable fallback:
> file:line]. An attacker who knows or discovers the endpoint URL can send a
> crafted POST request with a payload of their choosing — no valid signature
> is required to reach [specific side-effecting code, e.g. "markOrderPaid",
> "grantAccess"] at [file:line]. This results in [concrete impact — e.g. "an
> attacker marking any order as paid without payment, receiving the
> associated goods/access for free" or "an attacker granting themselves
> account access without completing the real onboarding flow"].

Fill every bracket concretely from evidence gathered in this repo. If the
exact side effect can't be confirmed as reachable from the forged payload
alone (e.g. it requires a valid-looking but hard-to-guess ID also present in
the payload), note that constraint and cap severity accordingly rather than
asserting unconditional exploitability.

## Graph Mapping Instructions

- Always ensure a `component:webhook_integration` node exists on the first
  webhook-related finding, tagged with the specific provider(s) involved
  (Stripe, Clerk, GitHub, etc. as relatedNodeIds or in the finding metadata).
- Each concrete missing/broken verification becomes its own `finding:<uuid>`
  vulnerability node with a `causes` edge from `component:webhook_integration`.
- If the webhook's side effect touches a specific component (payments,
  account provisioning, subscription state), add an `enables` edge from the
  finding node to that component's node — the webhook forgery is the entry
  point, the downstream component is what's actually compromised.
- If a weak/empty secret is the root cause (rather than a missing
  verification call entirely), note this in the finding's `reasoning` field
  and, if a `component:secrets` node/finding exists in the same scan from
  `ai_security.secrets_management` or
  `ai_security.environment_secrets_exposure`, wire a `causes` edge from that
  secrets finding to this webhook finding rather than treating them as
  unrelated.
