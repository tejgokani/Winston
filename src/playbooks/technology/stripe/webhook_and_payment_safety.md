---
id: technology.stripe.webhook_and_payment_safety
title: Stripe Webhook and Payment Safety
category: technology
vulnerabilityClass: broken_payment_trust_boundary
appliesToStack: stripe
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A08:2021 Software and Data Integrity Failures"
  - "A04:2021 Insecure Design"
cweRefs:
  - "CWE-345"
  - "CWE-290"
  - "CWE-841"
  - "CWE-807"
realWorldReferences:
  - title: "Receive Stripe events in your webhook endpoint (official docs)"
    url: "https://docs.stripe.com/webhooks"
    type: vendor_security_advisory
  - title: "Resolve webhook signature verification errors (official docs)"
    url: "https://docs.stripe.com/webhooks/signature"
    type: vendor_security_advisory
  - title: "Missing Stripe-Signature Verification Allows Unauthenticated Forged Webhooks (n8n, GHSA-jf52-3f2h-h9j5 / CVE-2026-21894)"
    url: "https://github.com/n8n-io/n8n/security/advisories/GHSA-jf52-3f2h-h9j5"
    type: vendor_security_advisory
  - title: "Stripe Webhook Signature Bypass via Empty Secret Enables Unlimited Quota Fraud (New API, GHSA-xff3-5c9p-2mr4)"
    url: "https://github.com/QuantumNous/new-api/security/advisories/GHSA-xff3-5c9p-2mr4"
    type: vendor_security_advisory
  - title: "Bypassing Payments Using Webhooks (Jack Cable)"
    url: "https://cablej.io/blog/bypassing-payments-using-webhooks/"
    type: bug_bounty_disclosure
  - title: "Upserve: Total price manipulation using price key in items array (HackerOne #364843)"
    url: "https://hackerone.com/reports/364843"
    type: bug_bounty_disclosure
  - title: "Uzbey: Price Manipulation via client-controlled amount field (HackerOne #17502)"
    url: "https://hackerone.com/reports/17502"
    type: bug_bounty_disclosure
  - title: "AI Generated Code Vulnerabilities: 7 Security Risks in 2026 (vibe-coded Stripe webhook handlers skipping signature checks)"
    url: "https://vibecoding.app/blog/ai-generated-code-security-risks"
    type: security_blog
quickModeSummary: >
  Check every Stripe webhook route: does it verify `Stripe-Signature` via
  `stripe.webhooks.constructEvent` using the *raw* request body (not
  JSON-parsed) before trusting the event? Is the checkout/payment-intent
  amount computed server-side from a Price/Product id, or does the handler
  accept a client-supplied `amount`/`price` field verbatim? Does webhook
  processing dedupe on `event.id` before performing fulfillment side effects
  (order creation, credit grant, entitlement flip), or can the same event
  double-fulfill on Stripe's automatic retries?
fileSelectionHint:
  roles: ["route_handler", "webhook_handler", "payment_service", "checkout"]
  matchImports: ["stripe"]
  matchAuthMapTags: ["stripe"]
  maxFiles: 8
  priorityOrder: ["webhook_handler", "route_handler", "payment_service"]
severityHeuristics:
  critical:
    - "Webhook route parses the event body and acts on it (grants access, marks paid, credits balance) without ever calling constructEvent / verifying Stripe-Signature — any internet client can forge a 'payment succeeded' event."
    - "Endpoint secret is empty, undefined, or falls back to a hardcoded/placeholder value, so signature verification silently passes or is skippable (mirrors CVE-2026-41432's empty-secret bypass)."
    - "Checkout/payment-creation endpoint charges an amount read directly from the request body (`req.body.amount`, `req.body.price`) instead of looking the price up server-side from a Stripe Price/Product id or internal catalog."
  high:
    - "Raw body is lost before signature verification (global `express.json()`/body-parser applied ahead of the webhook route, or a framework that auto-parses JSON), causing verification to fail-open, get disabled, or be worked around by re-serializing the body (which breaks HMAC integrity guarantees even if it 'happens to work')."
    - "Webhook handler performs fulfillment (order creation, entitlement grant, quota credit) without checking whether `event.id` has already been processed, so Stripe's documented at-least-once / possible-duplicate delivery can double-fulfill an order."
    - "Amount is client-supplied but only loosely validated (e.g. clamped to a range) rather than derived from a trusted server-side price source — still allows paying an unintended amount within the accepted range."
  medium:
    - "Signature timestamp tolerance is set to 0 or a very large value, weakening replay-attack protection Stripe's SDK provides by default."
    - "Webhook handler trusts `event.data.object` fields (e.g. metadata used for authorization decisions) without cross-checking against the corresponding object fetched fresh from the Stripe API when the decision is security-sensitive."
  low:
    - "Idempotency-Key header is not used on outbound Stripe API calls (create charge/subscription), risking duplicate charges on network retries — distinct from webhook dedup but related failure mode."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:stripe_webhooks"
  relatedNodeIds: ["component:payments", "component:checkout", "component:order_fulfillment"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:payments"
    to: "component:stripe_webhooks"
  - relation: depends_on
    from: "component:order_fulfillment"
    to: "component:stripe_webhooks"
commonAiCodingMistakes:
  - "AI assistants generate a webhook route that reads `req.body` as JSON and switches on `event.type` immediately — because Stripe's local CLI (`stripe listen --forward-to`) and test-mode events 'work' without verification, the missing `constructEvent` call is never surfaced in casual testing, only in production against a real forged request."
  - "AI scaffolds Express apps with a single global `app.use(express.json())` before all routes are defined, which silently breaks signature verification on the webhook route (or forces the author to remove verification entirely to make it 'work') — the fix requires mounting the webhook route with `express.raw({type: 'application/json'})' before the JSON body-parser, which AI-generated route ordering frequently gets wrong."
  - "AI-generated checkout flows built for speed pass the cart total computed in the frontend straight into `stripe.paymentIntents.create({ amount: req.body.amount })` or `stripe.checkout.sessions.create({ line_items: [{ price_data: { unit_amount: req.body.amount } }] })` instead of using a pre-created Stripe Price id or recomputing the total from a server-side product table."
  - "AI-generated webhook handlers treat `checkout.session.completed` / `payment_intent.succeeded` as a one-shot trigger and write fulfillment logic (insert order, decrement inventory, send confirmation email) directly in the handler with no dedup table or check, not accounting for Stripe's documented retry/duplicate-delivery behavior."
  - "AI assistants sometimes hardcode or read the webhook signing secret from a committed config/example file rather than `process.env.STRIPE_WEBHOOK_SECRET`, or leave a `|| ''` / `|| 'whsec_test'` fallback that silently disables verification if the env var is unset in a given deployment target."
falsePositiveGuardrails:
  - "Do not flag a webhook route as vulnerable purely because it appears simple — first confirm whether `constructEvent`, `constructEventAsync`, or an equivalent verified-parse call is genuinely absent from the handler's actual code path, not just missing from the specific snippet shown; some frameworks verify in middleware upstream of the handler function."
  - "If the endpoint only reads non-sensitive, non-financial event types (e.g. `customer.updated` used purely for cache invalidation) and never performs a fulfillment or entitlement-granting action, a missing-verification finding should be capped at `medium`/`high` rather than `critical` — cite the specific event types actually handled before rating severity."
  - "Do not conflate the Stripe API `Idempotency-Key` header (client-generated, used on outbound requests you send to Stripe) with webhook event deduplication (server-side, keyed on inbound `event.id`) — they are different mechanisms guarding different directions of the payment flow; check which one is actually missing before writing the finding."
  - "A checkout endpoint that accepts a client-supplied `priceId`/`lookup_key` referencing a pre-created, server-controlled Stripe Price object is NOT client-trusted pricing — the amount itself is still resolved server-side by Stripe from that Price object. Only flag amount-trust issues where a numeric amount, unit price, or quantity multiplier is taken directly from client input and used to compute the charge."
  - "If fulfillment logic is wrapped in a database transaction with a unique constraint on `stripe_event_id` (or an equivalent idempotency table/lock), the double-fulfillment risk is mitigated even without an explicit early-return check — verify the constraint/lock actually exists before flagging missing idempotency as a finding."
  - "Test/CLI-forwarded events (`stripe listen`, Stripe CLI `trigger`) working in local development is not evidence signature verification exists in the deployed code — confirm the actual verification call site, since local tunneling tools sometimes bypass or aren't affected by app-level verification bugs."
---

## Root Cause Explanation

Stripe integrations fail in three recurring ways, all stemming from the same
underlying mistake: treating data that crosses a trust boundary (the public
internet, or the browser) as if it were already authenticated and authoritative.

1. **Webhook forgery via missing/broken signature verification.** Stripe
   webhook endpoints are public HTTP(S) URLs — anyone who discovers or guesses
   one can POST a JSON body shaped like a Stripe event. Stripe's own
   documentation is explicit that the *only* thing distinguishing a real event
   from a forged one is the `Stripe-Signature` header, verified with the
   endpoint's signing secret via `constructEvent`/`constructEventAsync`. Two
   real, disclosed CVEs show exactly this failure in production software:
   n8n's Stripe Trigger node saved a signing secret but never checked incoming
   requests against it (GHSA-jf52-3f2h-h9j5, CVE-2026-21894), and a separate
   product (New API) failed to reject requests when the configured webhook
   secret was empty, letting attackers compute valid-looking signatures
   against an empty key entirely (GHSA-xff3-5c9p-2mr4). AI coding assistants
   reproduce this exact class of bug because Stripe's local test tooling
   (`stripe listen`, dashboard "send test webhook") "works" whether or not
   verification code exists — the missing check only becomes visible when
   someone (or something malicious) hits the endpoint directly in production.
2. **Trusting client-supplied price/amount.** The browser is not a trusted
   compute environment. When a checkout or payment-intent-creation endpoint
   reads a numeric amount (or a per-unit price multiplied by an
   attacker-controlled quantity) straight from the request body instead of
   deriving it from a Stripe Price/Product id or a server-side catalog, an
   attacker can simply change the number in the request. This is not
   theoretical: HackerOne report #364843 (Upserve) documents an order coming
   through with a line-item price of $0.01 because the price key in the
   request body was attacker-modifiable, and #17502 documents the same
   pattern in a PayPal-adjacent cart flow. The fix is structural, not a
   validation tweak: the server must compute the charge amount from data it
   controls (a Price object id, a database-stored SKU price), never from a
   number the client sent.
3. **Non-idempotent webhook processing.** Stripe's own documentation states
   plainly that webhook endpoints "might occasionally receive the same event
   more than once" and that events are not guaranteed to arrive in order.
   A handler that performs a side effect (create order row, grant credits,
   send a fulfillment email, decrement inventory) with no check against
   `event.id` will run that side effect twice on a retried delivery —
   double-crediting an account or double-shipping an order. This is a subtler
   bug than the other two because it doesn't fail during a single manual
   test; it only surfaces under Stripe's real retry behavior (temporary 5xx,
   timeout, network blip) or, per Stripe's docs, in rarer cases where two
   distinct Event objects are generated for what is logically one occurrence.

## Vulnerable Patterns

Look for shapes like these (illustrative — reason about equivalents in the
actual language/framework, don't string-match):

```js
// 1. No signature verification at all — anyone can POST this
app.post('/api/webhooks/stripe', express.json(), (req, res) => {
  const event = req.body; // trusted with zero verification
  if (event.type === 'checkout.session.completed') {
    fulfillOrder(event.data.object);
  }
  res.sendStatus(200);
});

// 2. Signature "verification" that's actually dead code — global JSON
// parser upstream has already re-serialized the body, so this either
// throws (and gets caught/ignored) or the raw body was never preserved.
app.use(express.json());
app.post('/api/webhooks/stripe', (req, res) => {
  const event = stripe.webhooks.constructEvent(
    JSON.stringify(req.body), // NOT the raw body Stripe signed
    req.headers['stripe-signature'],
    endpointSecret
  );
  ...
});

// 3. Client-trusted amount
app.post('/api/checkout', async (req, res) => {
  const { amount } = req.body; // attacker sends { amount: 1 }
  const intent = await stripe.paymentIntents.create({
    amount, currency: 'usd',
  });
  res.json({ clientSecret: intent.client_secret });
});

// 4. No idempotency / dedup on fulfillment
app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  const event = stripe.webhooks.constructEvent(req.body, sig, secret); // verified, good
  if (event.type === 'payment_intent.succeeded') {
    await db.orders.create({ ... }); // runs again on every retry of this event
    await grantEntitlement(event.data.object.metadata.userId);
  }
  res.sendStatus(200);
});
```

## Data Flow Tracing Guide

Trace the following before writing any Finding:

1. Locate every route registered for a Stripe webhook path (commonly
   `/api/webhooks/stripe`, `/webhooks/stripe`, `/stripe/webhook`). Confirm
   whether `stripe.webhooks.constructEvent` (or the async variant) is called
   in that exact handler's code path — not just present somewhere in the
   file.
2. Trace the request body from the framework's entry point to that
   `constructEvent` call. Is a global body-parsing middleware
   (`express.json()`, a framework's default JSON parsing) applied *before*
   this route, and if so, is the webhook route explicitly mounted with a raw
   body parser (`express.raw({ type: 'application/json' })`) ahead of it? If
   the raw bytes Stripe signed aren't what's passed to `constructEvent`,
   verification is either broken or was removed to make it "work."
3. Find where the endpoint secret comes from. Read it to its declaration —
   plain `process.env.STRIPE_WEBHOOK_SECRET` with no fallback, or a fallback
   literal/empty string that lets verification pass trivially when the env
   var is unset?
4. For every checkout/payment-intent-creation endpoint: trace the `amount`
   (or `unit_amount` / `quantity`) value passed into the Stripe API call back
   to its source. Is it read from `req.body`/query params, or looked up from
   a Stripe Price id / internal product table keyed by a client-supplied
   *identifier* (not a price)?
5. For each webhook event type actually handled (`event.type` branches),
   determine what side effect runs. Is there a check — a unique DB constraint
   on `event.id`/`event.data.object.id`, a Redis SETNX, an `already
   processed?` lookup — before that side effect executes? If the same event
   were delivered twice, would the side effect run twice?

## Evidence Checklist

Before submitting a Finding for this playbook, confirm:

- [ ] At least one concrete code snippet with exact file + line range is
      attached as evidence — do not paraphrase, quote the line(s).
- [ ] If claiming missing/broken signature verification: cite the exact
      route registration and the exact line (or absence) of the
      `constructEvent` call, plus the body-parsing middleware order if that's
      the root cause.
- [ ] If claiming client-trusted pricing: cite the exact line where the
      amount/price value is read from client input AND the exact line where
      it's passed into a Stripe API call, with no server-side price lookup in
      between.
- [ ] If claiming missing idempotency: cite the exact fulfillment side effect
      and confirm (by reading the surrounding code, schema, or migrations)
      that no dedup mechanism (unique constraint, existence check, lock) is
      present.
- [ ] Confirmed which Stripe event types are actually handled before rating
      severity — a `critical` missing-verification finding requires that a
      financial/entitlement-granting event type is in scope.

A finding without at least one concrete code-snippet evidence entry must not
be submitted.

## Attack Scenario Template

An attacker sends a crafted POST request to [exact webhook path], with a body
shaped as a `[event.type]` event and [claim/field] set to [attacker-chosen
value]. Because [specific code location] does not [verify Stripe-Signature /
recompute the amount server-side / check event.id before fulfillment], the
request is processed as if it were a genuine Stripe event, resulting in
[concrete impact specific to this repo, e.g. "the order at
`/api/orders/:id` being marked paid and the associated digital product
unlocked with zero payment" — not a generic description].

Fill every bracket concretely with evidence gathered in the repo. If a
bracket can't be filled with real evidence, the scenario is speculative and
severity must be capped at `medium`, with a note that exploitability is
unconfirmed.

## Graph Mapping Instructions

- Always ensure `component:stripe_webhooks` exists (create it on any
  Stripe-related finding in this scan) with a `depends_on` edge from
  `component:payments` and, when order/fulfillment logic is involved, from
  `component:order_fulfillment`.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from `component:stripe_webhooks` (or
  `component:checkout` if the root cause is client-trusted pricing rather
  than webhook verification) to the finding node.
- If a finding enables reaching a specific downstream system (e.g. an
  entitlement/credit-granting service, inventory system, email/notification
  service triggered by fulfillment), add an `enables` edge from the finding
  node to that component's node id.
- Root cause vs. symptom: if a finding is *caused by* another finding already
  identified in the scan (e.g. an empty/hardcoded webhook secret finding
  causes the signature-forgery finding), say so explicitly in the finding's
  `reasoning` field so the graph mapper wires a `causes` edge between the two
  finding nodes rather than treating them as unrelated.
