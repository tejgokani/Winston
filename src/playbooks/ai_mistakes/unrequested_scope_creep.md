---
id: ai_mistakes.unrequested_scope_creep
title: Unrequested Scope Creep & Silent Behavior Changes
category: ai_mistakes
vulnerabilityClass: ai_coding_defect
appliesToStack: technology-agnostic
deepOnly: true
reviewPass: 3
owaspRefs: []
cweRefs: []
quickModeSummary: >
  Look for security-relevant configuration or behavior that was loosened or
  changed as an unrequested side effect of an unrelated task (e.g. CORS
  widened, an auth check removed, a permission relaxed, a debug/bypass flag
  left in) rather than a deliberate, scoped change to that specific area.
fileSelectionHint:
  roles: ["config", "middleware", "route_handler"]
  matchImports: []
  matchAuthMapTags: []
  maxFiles: 10
  priorityOrder: ["config", "middleware"]
severityHeuristics:
  critical:
    - "An authentication/authorization check was removed or bypassed as a side effect of an unrelated change, with no indication this was the intended task"
  high:
    - "A security-relevant config value was loosened (CORS origin widened to *, a permission scope broadened, TLS/cert verification disabled) outside the stated scope of the change"
  medium:
    - "A debug/test bypass (e.g. a hardcoded test user, a `if (process.env.NODE_ENV !== 'production')` gate around an auth check) was introduced and could plausibly ship if the environment check is wrong or missing on some deploy path"
  low:
    - "Unrelated files touched with no behavior change (pure scope creep, not a security issue by itself, but a signal to review the change more carefully)"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:configuration"
  relatedNodeIds: ["component:authorization"]
graphEdgeMapping:
  - relation: causes
    from: "component:configuration"
    to: "component:authorization"
commonAiCodingMistakes:
  - "AI, while debugging an unrelated CORS/network error blocking its own testing, widens the CORS policy to `*` or disables credential checks to get past the error, and the change is left in place after the actual task is done."
  - "AI, unable to get a test/manual verification to pass due to an auth check, comments out or bypasses that check 'temporarily' to confirm the rest of the change works, and the bypass survives into the final diff."
  - "AI adds a convenience flag (e.g. `?skipAuth=true`, a hardcoded backdoor test account) to make its own iterative testing faster, intending it as scaffolding, and it isn't removed before the change is considered complete."
  - "AI 'helpfully' refactors or reformats unrelated code while completing a narrow task, obscuring the actual intended change inside a much larger diff and making a real defect harder for a reviewer (human or AI) to spot."
falsePositiveGuardrails:
  - "If the task description/PR context explicitly calls for the security-relevant change (e.g. 'widen CORS to support the new partner domain'), this is not scope creep — it's the intended change; only flag if it's inconsistent with or absent from the stated task."
  - "Legitimate environment-gated test/dev-only behavior (e.g. seed data only loaded when `NODE_ENV === 'development'`) is standard practice, not a finding — only flag if the gate is missing, inverted, or bypassable."
  - "Don't flag reformatting/renaming with no behavior change as a security finding — note it only as a low-severity signal if it also obscures an actual behavioral change in the same diff."
---

## Root Cause Explanation

AI agents solve the problem directly in front of them, and while iterating
toward a working solution they sometimes hit an obstacle unrelated to the
actual task — a CORS error, a failing auth check, a permission denial — that
blocks them from verifying their own work. The fastest way past the obstacle
is often to loosen or bypass whatever's in the way, with the intent (stated
or implicit) of reverting it later. That reversion frequently doesn't happen,
because the agent's success signal was "the task now works," not "the
security posture is unchanged outside the requested scope."

## Vulnerable Patterns

```js
// Widened while debugging an unrelated feature, left in the diff
- app.use(cors({ origin: 'https://app.example.com' }))
+ app.use(cors({ origin: '*', credentials: true }))
```

```js
// Auth check commented out to unblock local testing of an unrelated change
async function handler(req, res) {
  // if (!req.user) return res.sendStatus(401)
  return res.json(await getSensitiveData(req.params.id))
}
```

```js
// Convenience bypass added for the agent's own iterative testing
if (req.query.skipAuth === 'true') return next()
```

## Detection Guide

1. If a task description, PR title, or commit message is available, compare
   the actual scope of security-relevant changes against what was asked for.
   Anything security-relevant outside that stated scope is a candidate.
2. Look specifically for commented-out checks, widened CORS/permission
   configs, and any new query param/env check that bypasses an
   authentication or authorization path.
3. Distinguish "this file was touched" (not itself a finding) from "this
   file's security-relevant behavior changed" (a finding candidate).

## Evidence Checklist

- [ ] Exact before/after (or current state) of the security-relevant
      change, with file + line.
- [ ] The stated task scope (if available) cited to show this change falls
      outside it — or, if no task context is available, an explicit note
      that this is inferred from the change looking like debug scaffolding
      (commented-out check, bypass query param) rather than confirmed scope
      creep.
- [ ] Confirmed the change isn't itself gated by a correct, non-bypassable
      environment check.

## Failure Scenario Template

> [file:line] contains [security-relevant change] which [falls outside the
> stated task scope | has the shape of debug scaffolding left behind]. If
> shipped, this results in [concrete impact, e.g. "any origin being able to
> make credentialed requests to the API" or "the sensitive-data endpoint
> being reachable without authentication"].

## Graph Mapping Instructions

- Create `component:configuration` once per scan if any finding is filed
  here, with a `causes` edge to `component:authorization` when the drift
  weakens access control.
- Each unrequested change becomes its own `finding:<uuid>` vulnerability
  node with a `causes` edge from `component:configuration`.
