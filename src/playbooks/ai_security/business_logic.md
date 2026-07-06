---
id: ai_security.business_logic
title: Business Logic / Ownership Validation
category: ai_security
vulnerabilityClass: business_logic_flaw
appliesToStack: technology-agnostic
deepOnly: true
reviewPass: 2
owaspRefs:
  - "A04:2021 Insecure Design"
cweRefs:
  - "CWE-841"
  - "CWE-840"
realWorldReferences:
  - title: "Reddit: Race Condition Leads to Inflation of Award/Coin Balance"
    url: "https://hackerone.com/reports/801743"
    type: bug_bounty_disclosure
  - title: "HackerOne CTF: Race Condition in Flag Submission"
    url: "https://hackerone.com/reports/454949"
    type: bug_bounty_disclosure
  - title: "Smashing the State Machine: The True Potential of Web Race Conditions (James Kettle, PortSwigger Research)"
    url: "https://portswigger.net/research/smashing-the-state-machine"
    type: research_paper
  - title: "Bug Bounty Race: Exploiting Race Conditions for Infinite Discounts"
    url: "https://infosecwriteups.com/bug-bounty-race-exploiting-race-conditions-for-infinite-discounts-a2cb2f233804"
    type: security_blog
  - title: "Business Logic Vulnerabilities (multi-step workflow / checkout step-skipping)"
    url: "https://portswigger.net/web-security/logic-flaws"
    type: security_blog
quickModeSummary: >
  Deep-mode only: trace multi-step workflows (checkout, transfers, approval
  chains, state machines) for missing state-validation, race conditions
  between check and use, or steps that can be skipped/reordered by a client
  that simply calls a later endpoint directly.
fileSelectionHint:
  roles: ["route_handler", "database", "payment"]
  matchImports: []
  matchAuthMapTags: []
  maxFiles: 12
  priorityOrder: ["route_handler", "payment", "database"]
severityHeuristics:
  critical:
    - "A financial or irreversible state transition (payment, transfer, deletion) can be triggered out of order or repeated (e.g. no idempotency check), causing direct financial or data-integrity loss"
  high:
    - "A workflow step's precondition is checked at read time but the state can change before the write (time-of-check to time-of-use), and the resource is contended (e.g. shared inventory/balance)"
  medium:
    - "A multi-step process can be entered at a later step directly, skipping validation that only happens in an earlier step, without necessarily causing direct loss but violating the intended business rule"
  low:
    - "A business rule is enforced client-side (UI prevents an invalid action) with server-side enforcement present but not obviously tested against direct API calls — flag for verification, not a confirmed bypass"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:business_logic"
  relatedNodeIds: ["component:authorization", "component:payments"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:business_logic"
    to: "component:authorization"
commonAiCodingMistakes:
  - "AI implements each step of a multi-step workflow (e.g. cart -> checkout -> payment -> fulfillment) as an independent endpoint scoped to its own prompt, without re-deriving what state must be true when that endpoint is entered — so nothing stops calling 'fulfillment' directly."
  - "AI adds a balance/inventory check immediately before a write in the same function, which looks correct in isolation but has no locking/transaction around the check-then-write, so concurrent requests can both pass the check before either write lands."
  - "AI implements a 'retry-safe' payment endpoint without an idempotency key, because idempotency wasn't part of the original prompt and there was no failing test to surface the gap."
  - "AI applies a discount/coupon by checking 'has this code been used' and then writing the redemption as two separate statements (a SELECT followed by an UPDATE) rather than a single atomic operation, mirroring the exact pattern behind real disclosed race-condition bounties (e.g. loyalty/coin-balance inflation, stacked-discount checkout exploits) — sending the request twice in quick succession passes the check both times before either write lands."
  - "AI builds a multi-step wizard (cart -> checkout -> payment -> confirm) where each later step trusts a status flag or query parameter set by the previous step's response instead of re-deriving server-side whether the prior step actually completed — so a client can synthesize the 'previous step succeeded' signal and jump straight to the high-value endpoint."
falsePositiveGuardrails:
  - "This playbook requires tracing an actual multi-step workflow across multiple files/routes — do not submit a finding from a single-file, single-step observation without showing the sequence of calls that constitutes the workflow."
  - "Do not flag a missing lock/transaction as critical unless the resource is plausibly contended (shared inventory, shared balance) — a per-user resource with no concurrent-request scenario is at most a low-severity theoretical gap."
  - "A check-then-write pattern backed by a database-level atomic guarantee (a single `UPDATE ... WHERE balance >= amount` with an affected-rows check, a unique constraint on a 'redemption' row, `SELECT ... FOR UPDATE`, or a compare-and-swap) is not vulnerable to TOCTOU even though it 'looks like' separate check and write in the surrounding code — read whether the database enforces atomicity, not just whether the check and write appear as two lines."
  - "Race-condition findings are strongest when tied to a concretely contended, valuable resource (balance, inventory, one-time coupon, loyalty points) as seen in real disclosed reports (e.g. Reddit coin-balance inflation, HackerOne flag-submission race) — a theoretical race on a low-value or effectively unlimited resource is lower severity even if the same code pattern is present."
---

## Root Cause Explanation

Business-logic flaws are the category static, pattern-based analyzers
structurally cannot catch, because there's no "bad pattern" to match — the
code is individually correct at each step; the flaw is in the *sequence* or
*concurrency* of steps not matching the intended business rule. This is
exactly where reasoning about the actual workflow (not just the code inside
one function) earns its keep.

Two recurring root causes:

1. **Skippable/reorderable steps.** A workflow is built as a sequence of
   independent API calls, and nothing server-side enforces that step N can
   only happen after step N-1 completed in the required state. Client-side
   sequencing (a wizard UI) is not enforcement.
2. **Time-of-check to time-of-use (TOCTOU) races.** A precondition (balance
   sufficient, inventory available, not-already-processed) is checked, then
   some time later the effect is applied — without a transaction, lock, or
   atomic operation tying the two together, allowing concurrent requests to
   both pass the check.

## Data Flow Tracing Guide

1. Identify multi-step workflows from the route map: routes that share a
   resource id or session concept and represent sequential stages (e.g.
   `/cart`, `/checkout`, `/pay`, `/confirm`).
2. For each stage, determine what state the resource must be in for that
   stage to be valid, and confirm the handler actually checks that state
   (not just that the user is authenticated).
3. For any check-then-write sequence touching a shared/contended value
   (balance, inventory count, "already used" flag), determine whether it's
   wrapped in a transaction/lock or is two independent operations.
4. For payment/refund/transfer endpoints, check for an idempotency key or
   equivalent duplicate-submission guard.

## Evidence Checklist

- [ ] The full sequence of routes/functions making up the workflow is cited,
      not just one file.
- [ ] The specific state check that's missing or misordered is identified
      with file/line references for each relevant step.
- [ ] For TOCTOU claims: both the check and the use are cited, showing the
      absence of a transaction/lock between them.

## Attack Scenario Template

> By calling [later-stage endpoint] directly instead of following
> [expected workflow sequence], or by sending [N] concurrent requests to
> [endpoint] before [state update] completes, [concrete impact — e.g.
> "checkout completes without payment", "the same discount is applied
> twice", "inventory goes negative"].

## Graph Mapping Instructions

- Ensure a `component:business_logic` node exists with a `depends_on` edge
  to `component:authorization` (a business-logic flaw often compounds an
  authorization gap, but is a distinct root cause).
- If the flaw involves a payments/financial workflow, add an `enables` edge
  from the finding to `component:payments`.
