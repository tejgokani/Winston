---
id: technology.background_jobs.queue_security
title: Background Job & Queue Security
category: technology
vulnerabilityClass: broken_authorization
appliesToStack: background-jobs
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A01:2021 Broken Access Control"
  - "A02:2021 Cryptographic Failures"
  - "A08:2021 Software and Data Integrity Failures"
cweRefs:
  - "CWE-306"
  - "CWE-312"
  - "CWE-863"
  - "CWE-345"
realWorldReferences:
  - title: "BullMQ Docs — Going to Production (Bull Board exposure, Redis AUTH/TLS)"
    url: "https://docs.bullmq.io/guide/going-to-production"
    type: vendor_security_advisory
  - title: "Inngest Docs — Signing Keys: Secure Function Communication (replay-attack prevention, signed serve endpoints)"
    url: "https://www.inngest.com/docs/platform/signing-keys"
    type: vendor_security_advisory
  - title: "Inngest Docs — Build Reliable Webhooks (raw-body HMAC verification before trusting payload)"
    url: "https://www.inngest.com/docs/patterns/jobs/build-reliable-webhooks"
    type: security_blog
  - title: "PortSwigger — Webhook Signature Verification / Timing-Safe Comparison Guidance"
    url: "https://docs.port.io/actions-and-automations/setup-backend/webhook/signature-verification/"
    type: security_blog
quickModeSummary: >
  Check three things: (1) do enqueued job payloads contain plaintext secrets,
  tokens, or PII that will sit unencrypted in Redis/the queue's backing
  store, potentially for hours; (2) does every endpoint that enqueues or
  triggers a job (webhook receivers, admin dashboards like Bull Board,
  Inngest/Trigger.dev serve endpoints) verify a signature or auth token
  before accepting the trigger; (3) does the job handler re-check the
  actor's current authorization at execution time, or does it trust
  permissions/role snapshotted when the job was enqueued, which may be
  stale by the time a worker picks it up.
fileSelectionHint:
  roles: ["background_job", "queue_producer", "queue_consumer", "webhook_handler", "worker"]
  matchImports: ["bullmq", "bull", "inngest", "@trigger.dev/sdk", "ioredis", "bee-queue", "agenda"]
  matchAuthMapTags: ["queue", "webhook", "job"]
  maxFiles: 8
  priorityOrder: ["webhook_handler", "queue_producer", "queue_consumer", "worker"]
severityHeuristics:
  critical:
    - "Job payload contains raw secrets (API keys, session tokens, unhashed passwords, payment details) stored unencrypted in Redis/the queue backend, and Redis has no AUTH/TLS or is reachable without network restriction."
    - "A job-triggering webhook/HTTP endpoint (e.g. an Inngest serve endpoint, a custom '/enqueue' route, Bull Board) has no signature or authentication check, allowing an unauthenticated attacker to enqueue arbitrary jobs or read job state."
  high:
    - "Job handler performs a sensitive/destructive action (refund, role change, data export, delete) using an authorization snapshot taken at enqueue time, with no re-check of current permissions at execution time."
    - "Webhook signature is verified against a re-serialized/parsed body instead of the raw request bytes, making verification silently bypassable."
  medium:
    - "Sensitive but non-critical data (email address, internal user id, non-payment PII) is stored in plaintext job payloads with reasonable Redis network isolation already in place."
    - "Signature comparison uses a non-constant-time string equality check instead of a timing-safe comparison."
  low:
    - "Job payloads lack field-level encryption for sensitive data but the queue backend is on a private network with AUTH/TLS and no external exposure path identified."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:background_jobs"
  relatedNodeIds: ["component:queue_backend", "component:webhook_ingress", "component:authorization"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:background_jobs"
    to: "component:queue_backend"
  - relation: depends_on
    from: "component:webhook_ingress"
    to: "component:authentication"
  - relation: protects
    from: "component:authorization"
    to: "component:background_jobs"
commonAiCodingMistakes:
  - "AI scaffolds a BullMQ/Inngest job that receives `userId` and `role` as part of the payload at enqueue time, then trusts `role` inside the handler instead of re-fetching the user's current role from the database when the job executes."
  - "AI wires an Inngest `serve()` handler or a custom webhook route (e.g. a Stripe-triggered job enqueue) without pinning `INNGEST_SIGNING_KEY` or verifying the provider's HMAC signature, because the happy-path tutorial code omits it and the AI does not add it back."
  - "AI puts an entire request body — including auth tokens, full credit card objects, or password reset tokens — directly into a BullMQ job's `data` argument for a 'send email' or 'process payment' job, because it's the simplest way to pass data to a `Job` without designing a minimal payload."
  - "AI adds a Bull Board or Inngest dev-server UI for observability during scaffolding and it survives into a deployed environment without an `authMiddleware` in front of it."
  - "AI verifies a webhook signature by first calling `express.json()` (or a framework's default body parser) and then computing the HMAC over the parsed/re-stringified body, which silently breaks verification against byte-for-byte tampering while still 'passing' in local testing with well-formed requests."
falsePositiveGuardrails:
  - "Do not flag a job payload containing a user id or non-sensitive reference (order id, resource id) as a 'sensitive data in queue' finding — only flag payloads carrying secrets, tokens, full PII records, or payment data verbatim."
  - "Before flagging missing webhook signature verification, confirm the endpoint actually accepts external/untrusted input (a third-party webhook, a public-facing trigger route) — an internal-only enqueue call from your own authenticated API layer to your own job producer is not a webhook trust boundary and does not need HMAC verification, though it still needs standard app-level authz."
  - "Before flagging missing re-authorization at execution time, check whether the job is inherently idempotent/low-privilege (e.g. 'send a welcome email', 'regenerate a thumbnail') where a stale permission snapshot has no meaningful security impact — reserve high/critical severity for jobs that perform privileged or destructive actions."
  - "If Redis/the queue backend is confirmed to be on a private VPC/network with AUTH and TLS enabled (check infra config, not just app code) and no code path exposes it externally, do not escalate 'unencrypted payload' findings to critical — cap at medium and note the compensating network control."
---

## Root Cause Explanation

Background job and queue systems (BullMQ over Redis, Inngest, Trigger.dev, Agenda, and similar) introduce a second, often-overlooked trust boundary: the gap between when work is *triggered* and when it is *executed*. Three failure modes recur:

1. **The queue backend becomes an unintended data store.** Job payloads are serialized and written to Redis (or Inngest/Trigger.dev's managed store) so a worker — possibly running on a different machine, minutes or hours later — can pick them up. Developers treat this payload like an in-memory function argument, but it is actually data at rest, sitting in a keyspace that's frequently under-protected (default AUTH-less Redis, no TLS, broad IAM access to the backing store) and often outlives the request that created it (retry queues, delayed jobs, dead-letter queues can retain payloads for a long time).
2. **The job-triggering surface is itself an unauthenticated entry point.** Every webhook receiver that turns an external event into an enqueued job (a Stripe webhook enqueueing a "process payment" job, a GitHub webhook enqueueing a "sync repo" job) is a public HTTP endpoint. If it doesn't verify the sender's signature over the raw body, anyone who finds the URL can enqueue arbitrary jobs. This extends to internal admin surfaces like Bull Board/Inngest dashboards, which display and can often re-trigger job data and are dangerous if publicly reachable without auth.
3. **Time-of-check / time-of-use across the enqueue → execute gap.** Authorization is naturally checked at the moment a job is *created* (the user was an admin when they clicked "export all data"). But the job may not run until later, and by execution time the actor's role could have been revoked, their session invalidated, or the resource deleted. A handler that trusts payload fields like `role` or `isAdmin` instead of re-deriving authorization from the current state of the system silently reintroduces a privilege-escalation window — this is the queue-system analogue of a classic TOCTOU bug.

## Vulnerable Patterns

Illustrative shapes — reason about equivalents in the actual stack under review, don't string-match:

```js
// 1. Secrets/PII placed directly into an unencrypted job payload
await paymentQueue.add('process-refund', {
  cardNumber: req.body.cardNumber,       // raw PAN sitting in Redis
  stripeSecretKey: process.env.STRIPE_KEY, // secret duplicated into every job
  userEmail: user.email,
});

// 2. Webhook-triggered enqueue with no signature verification
app.post('/webhooks/stripe', express.json(), async (req, res) => {
  await jobQueue.add('handle-stripe-event', req.body); // no verifyStripeSignature()
  res.sendStatus(200);
});

// 3. Handler trusting a stale authorization snapshot instead of re-checking
jobQueue.process('delete-workspace', async (job) => {
  const { requestedByRole, workspaceId } = job.data;
  if (requestedByRole === 'owner') {   // role captured at enqueue time, not re-verified
    await deleteWorkspace(workspaceId);
  }
});

// 4. Admin dashboard mounted with no auth middleware
app.use('/admin/queues', bullBoardAdapter.getRouter()); // publicly reachable
```

## Data Flow Tracing Guide

To evaluate this playbook responsibly, trace the following before writing any Finding:

1. For every call to a job-producer API (`queue.add(...)`, `inngest.send(...)`, `trigger.dev` task trigger), inspect the payload object literal. List every field; classify each as identifier (safe), business data (context-dependent), or secret/PII/payment data (sensitive). Cite the exact enqueue call site.
2. For every route that enqueues a job in response to an inbound HTTP request (webhook receivers, `serve()` handlers for Inngest/Trigger.dev, any custom `/trigger` or `/enqueue` endpoint), check: is there a signature/HMAC verification call before the payload is trusted, and does that verification run against the *raw* request body (not a parsed-then-reserialized one)? Also check for an admin/dashboard route (Bull Board, Arena, Inngest dev server) and confirm it sits behind `auth_map`-registered middleware.
3. For every job handler/processor (`queue.process(...)`, an Inngest function body, a Trigger.dev `run` function), find every branch that gates a sensitive or destructive action. Determine whether the gating condition reads a field from `job.data` (enqueue-time snapshot) or performs a fresh lookup (database query, API call to the source of truth) at execution time.
4. Trace how long jobs can sit in the queue before executing (retry/backoff config, delayed job scheduling, dead-letter queue retention). Longer queue residency time widens the exposure window for both stale payload data (finding #1) and stale authorization (finding #3) — cite the relevant config (e.g. `attempts`, `backoff`, `removeOnComplete`) if present.

## Evidence Checklist

Before submitting a Finding for this playbook, confirm:

- [ ] At least one concrete code snippet with an exact file + line range is attached as evidence — do not paraphrase, quote the actual line(s).
- [ ] If claiming sensitive data in a job payload: the exact field name(s) and the enqueue call site are cited, and each field is shown to actually be a secret/PII/payment value (not just a suggestive name).
- [ ] If claiming missing webhook/trigger authentication: the exact route/handler is cited, along with confirmation (from `route_map`/`auth_map`) that no auth or signature-verification middleware wraps it.
- [ ] If claiming a stale-authorization issue: both the enqueue-time snapshot field and the execution-time usage of that field are cited, and the action performed is shown to be privileged/destructive (not a low-impact operation).
- [ ] Confirmation that the queue backend's network exposure was checked (infra config, not assumed) before escalating a plaintext-payload finding to critical severity.

A finding without at least one concrete code-snippet evidence entry must not be submitted.

## Attack Scenario Template

> An attacker [forges a webhook request without a valid signature / observes queue contents via an exposed Redis instance or dashboard / has their privileged role revoked after enqueueing a job but before it runs]. Because [specific code location] does not [missing signature check / payload encryption / execution-time re-authorization], the job at [specific queue/handler name] performs [concrete privileged action], resulting in [concrete impact specific to this repo — e.g. "arbitrary refunds issued to attacker-controlled accounts" or "another tenant's export data readable from a shared Redis keyspace"].

Fill every bracket concretely from evidence gathered in this repo. If a bracket can't be filled from real evidence, the scenario is speculative and severity must be capped at `medium`, with a note that exploitability is unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:background_jobs` node exists (create it on the first queue-related finding in a scan), with a `depends_on` edge to `component:queue_backend` (e.g. Redis, Inngest's managed platform).
- If a finding involves an inbound webhook/trigger endpoint, ensure a `component:webhook_ingress` node exists with a `depends_on` edge to `component:authentication`.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type `vulnerability`, with a `causes` edge from the most specific root-cause component (`component:queue_backend` for plaintext-payload issues, `component:webhook_ingress` for missing signature verification, `component:authorization` for stale-permission issues) to the finding node.
- If a stale-authorization finding is a downstream consequence of a missing re-fetch that also affects other flows, note the shared root cause explicitly in the finding's `reasoning` field so the graph mapper can link related findings via `causes` rather than treating them as isolated.
- If a finding enables reaching a specific external system (a payments provider, another tenant's data), add an `enables` edge from the finding node to that component's node id.
