---
id: ai_mistakes.logic_duplication_and_drift
title: Logic Duplication & Security-Relevant Drift
category: ai_mistakes
vulnerabilityClass: ai_coding_defect
appliesToStack: technology-agnostic
deepOnly: true
reviewPass: 2
owaspRefs:
  - "A04:2021 Insecure Design"
cweRefs:
  - "CWE-1041"
quickModeSummary: >
  Check whether the same validation/authorization/sanitization logic is
  reimplemented in more than one place instead of calling a shared helper —
  and if so, whether the copies have already drifted (one checks something
  the other forgot).
fileSelectionHint:
  roles: ["route_handler", "middleware", "auth", "data_access"]
  matchImports: []
  matchAuthMapTags: []
  maxFiles: 12
  priorityOrder: ["route_handler", "middleware"]
severityHeuristics:
  critical:
    - "Duplicated authorization/permission logic has drifted such that one copy is missing a check the other has (e.g. one route checks resource ownership, a structurally similar route doesn't)"
  high:
    - "Duplicated input validation/sanitization has drifted such that one copy accepts input the other would reject"
  medium:
    - "Business logic (pricing, quota, rate calculation) is duplicated across files with no shared source of truth, risking future drift even if currently consistent"
  low:
    - "Non-security-relevant logic duplicated (formatting, display logic) — copy exists but drift has no security/correctness consequence yet"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:code_duplication"
  relatedNodeIds: ["component:authorization"]
graphEdgeMapping:
  - relation: causes
    from: "component:code_duplication"
    to: "component:authorization"
commonAiCodingMistakes:
  - "AI, working route-by-route or file-by-file without full-repo context, reimplements a validation/auth check it already wrote elsewhere in the same session, because it didn't search for or wasn't shown the existing helper."
  - "AI copy-pastes an existing route handler as the starting point for a new one (a common, otherwise-reasonable pattern) but then modifies the business logic without carrying forward a security-relevant check that was implicit in the original context (e.g. the original had an ownership check earlier in a shared middleware the new route doesn't use)."
  - "AI adds a second implementation of a helper under a slightly different name (e.g. `isAdmin` and `checkIsAdmin`) because it didn't find the original, and only one of the two gets updated when the admin-detection logic later changes."
falsePositiveGuardrails:
  - "Two pieces of logic that look similar but intentionally enforce different rules for different resource types are not drift — confirm the business requirement actually calls for identical behavior before flagging."
  - "Duplication alone (without an actual behavioral difference) is at most a low-severity maintainability note — only raise medium+ severity when the copies have measurably diverged in a way that changes what's allowed/validated."
---

## Root Cause Explanation

AI coding agents typically operate with a limited, task-scoped view of the
codebase rather than a full mental model of every existing helper function.
When asked to add a new route, endpoint, or feature, the natural completion
is to write the validation/authorization/sanitization logic inline again —
especially if the agent wasn't shown or didn't search for the existing
implementation. The result is functionally similar logic living in multiple
places. This becomes a real defect the moment someone (human or AI) updates
one copy — to fix a bug, tighten a rule, add a new required check — without
knowing the sibling copy exists, and the copies silently diverge.

## Vulnerable Patterns

```js
// routes/orders.js
function canAccessOrder(user, order) {
  return order.userId === user.id || user.role === 'admin'
}

// routes/invoices.js — reimplemented, and missing the admin bypass check
// that was *also* missing an ownership check that orders.js has
function canAccessInvoice(user, invoice) {
  return invoice.userId === user.id
  // no admin bypass — inconsistent with orders.js, may be intentional
  // or may be an accidental omission; needs confirmation either way
}
```

## Detection Guide

1. Identify functions/blocks across the included files that perform the same
   *kind* of check (ownership check, role check, input shape validation,
   sanitization) on structurally similar data.
2. Diff their actual logic line by line: same conditions, same operators,
   same edge-case handling? Note every place they diverge.
3. For each divergence, judge whether it's a deliberate difference in
   business rules (not a finding) or an omission/inconsistency with no
   apparent justification (a finding) — favor citing the specific missing
   condition over a vague "these look similar" claim.

## Evidence Checklist

- [ ] Both (or all) copies of the duplicated logic quoted with file + line.
- [ ] The specific line(s) where they diverge identified precisely — not
      just "these are different," but which check is present in one and
      absent in the other.
- [ ] A concrete reason the divergence is not an intentional business rule
      difference (or an explicit statement that this can't be confirmed from
      available context, capping severity at medium).

## Failure Scenario Template

> [file:lineA] and [file:lineB] both implement [kind of check], but
> [file:lineB] is missing the [specific condition] present in
> [file:lineA]. As a result, [concrete impact, e.g. "a user can access
> another user's invoice even though the equivalent order-access path
> correctly blocks this"].

## Graph Mapping Instructions

- Create `component:code_duplication` once per scan if any finding is filed
  here, with a `causes` edge to `component:authorization` when the drift is
  security-relevant.
- Each drifted pair becomes its own `finding:<uuid>` vulnerability node with
  a `causes` edge from `component:code_duplication`.
