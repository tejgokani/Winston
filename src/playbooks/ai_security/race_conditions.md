---
id: ai_security.race_conditions
title: Race Conditions & TOCTOU
category: ai_security
vulnerabilityClass: race_condition
appliesToStack: technology-agnostic
deepOnly: true
reviewPass: 3
owaspRefs:
  - "A04:2021 Insecure Design"
  - "A01:2021 Broken Access Control"
cweRefs:
  - "CWE-362"
  - "CWE-367"
  - "CWE-841"
realWorldReferences:
  - title: "Starbucks — race condition allowed unlimited gift-card balance transfer / money duplication (disclosed research)"
    url: "https://sakurity.com/blog/2015/05/21/starbucks.html"
    type: security_blog
  - title: "HackerOne disclosed reports — race conditions enabling coupon/gift-card/vote reuse and balance duplication via concurrent requests"
    url: "https://hackerone.com/reports/759247"
    type: bug_bounty_disclosure
  - title: "PortSwigger research — 'Smashing the state machine': the true potential of web race conditions (single-packet attack)"
    url: "https://portswigger.net/research/smashing-the-state-machine"
    type: research_paper
  - title: "OWASP — Testing for Race Conditions / limit-overrun and TOCTOU patterns"
    url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/"
    type: security_blog
quickModeSummary: >
  Find state-changing operations where a check and the dependent action are
  separate, non-atomic steps (check-then-act / TOCTOU), so that two concurrent
  requests can both pass the check before either commits. The high-value
  targets are anything with a limit or single-use invariant: redeeming a
  coupon/gift card once, "one vote per user", withdrawing only up to a balance,
  claiming limited inventory, applying a referral bonus once, or a
  check-balance-then-debit flow. When these read state, decide in application
  code, then write — without a database transaction, row lock, atomic
  conditional update, or unique constraint — an attacker firing many parallel
  requests can double-spend, redeem N times, or overdraw. Flag limit/uniqueness
  invariants enforced by a read-decide-write sequence rather than an atomic
  operation (a single UPDATE ... WHERE balance >= amount, an atomic decrement,
  a unique index, SELECT ... FOR UPDATE, or an idempotency key).
fileSelectionHint:
  roles: ["service", "controller", "route_handler", "repository", "payment", "model"]
  matchImports: []
  matchAuthMapTags: ["payments", "database"]
  maxFiles: 12
  priorityOrder: ["payment", "service", "repository", "route_handler"]
severityHeuristics:
  critical:
    - "A financial or value invariant (account balance, wallet/credit, gift-card, payout) is enforced by a non-atomic check-then-act with no transaction/lock/atomic conditional update, so concurrent requests can double-spend or overdraw — direct monetary loss"
    - "A security-critical single-use invariant (one-time token/coupon/invite redemption, single-use 2FA/OTP, one-time discount) is checked then consumed non-atomically, so concurrent requests redeem/use it multiple times"
  high:
    - "A limited-quantity or uniqueness invariant (inventory/seat/quota allocation, 'one vote/entry per user', unique username/handle claim) is enforced by read-decide-write without an atomic operation or unique constraint, enabling over-allocation or duplicate claims via concurrency"
    - "An authorization or state-machine transition depends on a value read separately from where it's acted upon (TOCTOU) such that a concurrent change between check and use bypasses the intended guard"
  medium:
    - "A check-then-act on non-financial, lower-impact state lacks atomicity/locking, enabling inconsistent state or a limited bypass under concurrency; or an idempotency mechanism exists but isn't enforced atomically"
    - "A file/resource TOCTOU (check existence/permissions then open/act) that could be won under concurrency but with constrained impact"
  low:
    - "A non-atomic sequence on state where concurrent conflict is possible but impact is negligible, or where a database default (e.g. an implicit unique constraint) likely mitigates — confirm whether an atomic guarantee already exists before finalizing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:business_logic"
  relatedNodeIds: ["component:database_access", "component:authorization"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:business_logic"
    to: "component:database_access"
  - relation: protects
    from: "component:business_logic"
    to: "component:authorization"
commonAiCodingMistakes:
  - "AI implements a balance debit as read-balance → check-sufficient-in-JS → write-new-balance in three separate statements, because that's the natural procedural expression, not recognizing that two concurrent requests both read the old balance, both pass the check, and both write — double-spending. The correct form is a single atomic conditional update (`UPDATE ... SET balance = balance - :amt WHERE id = :id AND balance >= :amt`) whose affected-row count confirms success."
  - "AI enforces 'redeem this coupon once' by SELECT-ing the coupon, checking `used == false` in application code, then UPDATE-ing `used = true` — a check-then-act window that lets parallel requests redeem it multiple times before any marks it used. The fix is an atomic conditional update or a unique redemption row with a constraint."
  - "AI enforces uniqueness ('one vote per user', 'claim this username') with an existence check followed by an insert, instead of a database UNIQUE constraint / upsert, so concurrent inserts both pass the check."
  - "AI wraps nothing in a transaction and uses no row locks (`SELECT ... FOR UPDATE`) for multi-step money/inventory operations, assuming request handlers run serially — they don't; the app is concurrent by default."
  - "AI adds an idempotency key concept but checks it non-atomically (look up key → if absent, process → store key), leaving the same TOCTOU window it was meant to close."
  - "AI relies on a preceding authorization/state check whose value can change before the guarded action executes (TOCTOU), e.g. re-checking a status that a concurrent request flips, without locking the row for the duration."
falsePositiveGuardrails:
  - "Do not flag an operation that enforces its invariant atomically: a single conditional UPDATE guarded by a WHERE clause on the invariant (and checking the affected-row count), an atomic increment/decrement, a database UNIQUE constraint / upsert, `SELECT ... FOR UPDATE` within a transaction, a compare-and-swap, or a distributed lock held across the critical section. These are the correct patterns even when the surrounding code also reads the value for display."
  - "A read that is purely informational (displaying a balance, showing availability) and is NOT the basis for a subsequent unguarded write is not a TOCTOU — the concern is specifically a check whose result gates an action that isn't performed atomically with the check."
  - "Operations that are naturally idempotent or commutative (setting a field to a fixed value, adding to a set) may not be exploitable via concurrency — reason about whether repeated/interleaved execution actually violates an invariant before flagging."
  - "A single-node in-process mutex/lock is adequate only if the app truly runs as one process; do not assume it's sufficient for a horizontally-scaled deployment, but equally do not flag a genuine atomic DB-level guarantee as insufficient. Match the mechanism to the deployment before judging."
  - "Do not flag every multi-statement sequence — many are not security invariants. The vulnerability requires a limit/uniqueness/authorization invariant that concurrency can violate for attacker gain; establish that invariant and the exploit before flagging."
---

## Root Cause Explanation

A race condition in application security is almost always a *check-then-act*
(TOCTOU: time-of-check to time-of-use) sequence applied to an invariant that
is supposed to hold exactly once or up to a limit. The application reads some
state, decides in code that the operation is allowed, and then performs the
write — as three separate steps. Because web applications are concurrent by
default (many workers, many requests, and with HTTP/2 an attacker can land
requests nearly simultaneously), two or more requests can each complete the
*read* and pass the *check* before any of them performs the *write*. Each then
acts as if it were the only one, and the invariant — "spend at most your
balance," "redeem this once," "one per user," "only N in stock" — is violated.

This is the mechanism behind a long line of real financial exploits:
duplicating gift-card balances by transferring from an account to itself in
parallel (the Starbucks case), redeeming one-time coupons N times, voting
repeatedly, and overdrawing wallets. It's high-value precisely because the
targets are the money/limit/uniqueness invariants at the heart of business
logic, and it's easy to introduce because the vulnerable form is the *natural*
procedural expression: read the balance, check it's enough, subtract and save.
AI-generated code produces exactly that sequence, since it mirrors how the
requirement is stated in prose, and no single-threaded test ever reveals the
flaw — you only see it under deliberate concurrency.

The fix is to make the check and the act a single atomic operation the
database (or another serializing authority) guarantees: a conditional
`UPDATE ... WHERE balance >= :amount` whose affected-row count tells you
whether it succeeded, an atomic decrement, a `UNIQUE` constraint or upsert for
"once per user," a `SELECT ... FOR UPDATE` row lock held across a transaction,
a compare-and-swap, or an atomically-enforced idempotency key. The invariant
must be enforced *where the write happens*, not in a preceding application-code
check the write doesn't depend on.

## Vulnerable Patterns

```js
// Non-atomic balance debit — two concurrent requests both pass the check
const { balance } = await db.account.findUnique({ where: { id } });
if (balance < amount) throw new Error("insufficient");     // time-of-check
await db.account.update({ where: { id }, data: { balance: balance - amount } }); // time-of-use
```

```js
// One-time coupon redeemed multiple times under concurrency
const coupon = await db.coupon.findUnique({ where: { code } });
if (coupon.used) throw new Error("already used");
await db.coupon.update({ where: { code }, data: { used: true } });
```

```js
// Uniqueness by check-then-insert instead of a constraint
if (await db.vote.findFirst({ where: { userId, pollId } })) throw new Error("voted");
await db.vote.create({ data: { userId, pollId } });        // concurrent inserts both pass
```

Correct shapes make the guard atomic:

```sql
-- affected-row count of 0 means the guard failed; no separate check needed
UPDATE account SET balance = balance - :amount WHERE id = :id AND balance >= :amount;
UPDATE coupon  SET used = true WHERE code = :code AND used = false;
```

```sql
-- uniqueness enforced by the database, not application code
CREATE UNIQUE INDEX one_vote_per_user ON vote (user_id, poll_id);
```

## Data Flow Tracing Guide

1. Identify the security/business invariants: balances, credits, one-time
   tokens/coupons/OTPs, per-user uniqueness, inventory/quota limits,
   state-machine transitions, authorization values.
2. For each, locate where it's enforced. Is it a read → decide-in-code → write
   sequence, or an atomic operation (conditional UPDATE with row-count check,
   atomic inc/dec, UNIQUE constraint/upsert, SELECT FOR UPDATE in a
   transaction, CAS, enforced idempotency key)?
3. For non-atomic sequences, confirm there's no surrounding transaction +
   row lock that actually serializes the critical section.
4. Construct the concurrency exploit: what do two+ interleaved requests
   achieve (double-spend, N-redeem, over-allocate, duplicate)?
5. Weight severity by impact: money/one-time-security = critical, limited
   resources/uniqueness = high.

## Evidence Checklist

- [ ] The invariant being protected, stated explicitly (e.g. "balance must
      not go negative", "coupon redeemable once").
- [ ] The check site and the act site quoted, showing they are separate and
      non-atomic (and not inside a serializing transaction/lock).
- [ ] The absence of an atomic guard (conditional update/row-count check,
      unique constraint, FOR UPDATE, atomic inc/dec, idempotency key).
- [ ] The concrete concurrent-request interleaving that violates the invariant
      and the attacker gain (double-spend amount, extra redemptions, etc.).

A finding must name the invariant and show the check/act are separable under
concurrency; a genuinely atomic guard is not a finding.

## Attack Scenario Template

> An attacker fires [N] concurrent [method] [endpoint] requests (e.g. via
> HTTP/2 single-packet timing). Because [file:line] enforces [invariant] with
> a non-atomic read-check-write (no transaction/row lock/atomic conditional
> update/unique constraint), all N requests read the same pre-state, all pass
> the [balance/used/exists] check before any commits, and each performs
> [debit/redeem/insert]. The result is [balance debited once but N withdrawals
> honored / a one-time coupon redeemed N times / N duplicate votes-or-claims],
> resulting in [monetary loss of X / bypass of the single-use control /
> over-allocation].

## Graph Mapping Instructions

- Ensure a `component:business_logic` node exists, with a `depends_on` edge to
  `component:database_access`.
- Financial/one-time-control race findings should be flagged in `reasoning` as
  double-spend / limit-overrun class so severity aggregation weights the
  monetary/security impact rather than treating it as a generic logic bug.
- Each race is a `finding:<uuid>` vulnerability node with a `causes` edge from
  `component:business_logic`; if it undermines an authorization/state guard,
  add an `enables` edge toward `component:authorization`.
