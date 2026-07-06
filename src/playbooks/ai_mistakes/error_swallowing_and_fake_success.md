---
id: ai_mistakes.error_swallowing_and_fake_success
title: Error Swallowing & Fake Success
category: ai_mistakes
vulnerabilityClass: ai_coding_defect
appliesToStack: technology-agnostic
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A09:2021 Security Logging and Monitoring Failures"
cweRefs:
  - "CWE-390"
  - "CWE-252"
quickModeSummary: >
  Look for empty or near-empty catch blocks, caught exceptions that are only
  logged (or not even that) while execution continues as if nothing failed,
  and functions that return a success value/status 200 on a path that never
  confirms the underlying operation actually completed.
fileSelectionHint:
  roles: ["route_handler", "middleware", "data_access"]
  matchImports: []
  matchAuthMapTags: []
  maxFiles: 10
  priorityOrder: ["route_handler", "data_access"]
severityHeuristics:
  critical:
    - "A write/payment/auth-relevant operation's failure is swallowed and the caller is told it succeeded (e.g. HTTP 200 returned regardless of whether the DB write committed)"
  high:
    - "Catch block is empty or only re-throws a generic error, discarding the information needed to know what actually failed, on a path that handles user data or money"
  medium:
    - "Errors are caught and logged but execution continues into code that assumes the failed step succeeded"
  low:
    - "Non-critical background/telemetry call failures are swallowed without logging (acceptable if truly non-critical, but should be explicit)"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:error_handling"
  relatedNodeIds: ["component:logging"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:error_handling"
    to: "component:logging"
commonAiCodingMistakes:
  - "AI wraps a risky call in try/catch to make a demo run cleanly, catches the exception, and leaves the catch block empty or with only a comment, so the failure is invisible in production."
  - "AI writes a catch block that logs the error but then falls through into code written for the success path, because the model completed the 'happy path' structure and treated error handling as an afterthought bolted on to satisfy a linter."
  - "AI returns a generic success response (`res.status(200).json({ ok: true })`) from a handler where an awaited operation earlier in the function could have failed and was caught but not propagated into the response."
  - "AI catches a specific exception type from a low-level library and re-throws a generic `Error('something went wrong')`, discarding the original error's diagnostic detail (and stack) that would be needed to debug or alert on the real failure."
falsePositiveGuardrails:
  - "A catch block that re-throws the original error unmodified is fine — that's correct propagation, not swallowing."
  - "Framework-level global error handlers (e.g. Express error middleware, a top-level process handler) are an intentional last line of defense, not a swallowing bug, unless they also return a false-success response."
  - "Retry-with-backoff patterns that catch, log, and retry before eventually re-throwing are not swallowing — check whether the final attempt's failure is actually propagated."
---

## Root Cause Explanation

AI coding assistants are trained heavily on code samples where the "happy
path" is the point being demonstrated, and error handling is either omitted
or minimal boilerplate. When asked to add error handling to satisfy a task
description or linter, the model frequently produces a *syntactically*
complete try/catch that is *semantically* a no-op: the failure is caught,
optionally logged, and then execution proceeds as though the operation
succeeded. This is especially dangerous when it happens on the last write
in a multi-step operation, or right before a response is sent to the client.

## Vulnerable Patterns

```js
// Empty catch — failure is completely invisible
try {
  await db.orders.update(orderId, { status: 'paid' })
} catch (e) {}
return res.status(200).json({ ok: true })

// Logged but not propagated — caller still thinks it worked
try {
  await sendConfirmationEmail(user)
} catch (e) {
  console.error(e)
}
await markOnboardingComplete(user.id) // proceeds regardless

// Original error discarded, generic message loses diagnostic value
try {
  return await paymentProvider.charge(amount, token)
} catch (e) {
  throw new Error('Payment failed')
}
```

## Detection Guide

1. Find every try/catch (or language-equivalent: `except`, `rescue`,
   `.catch()`) in the included files. For each, check what the catch body
   actually does: nothing, log-only, or propagate/compensate.
2. For log-only or empty catches, trace forward from the catch block: does
   execution continue into code that assumes the try block succeeded (a
   response sent, a follow-up write performed, a flag set)?
3. Pay special attention to catches wrapping database writes, payment calls,
   and auth/session operations — these are the ones where fake success has
   real consequences (data loss, financial discrepancy, security bypass).

## Evidence Checklist

- [ ] Exact try/catch block quoted with file + line range.
- [ ] The line(s) after the catch that incorrectly assume success are also
      cited, if applicable.
- [ ] Confirmed this isn't a legitimate re-throw or an intentionally
      non-critical background operation.

## Failure Scenario Template

> The operation at [file:line] (e.g. "order status write") can fail and is
> caught at [line], but the catch block [does nothing | only logs], and
> execution proceeds to [consequence, e.g. "return a 200 success response to
> the client" or "mark onboarding complete"]. As a result, [concrete impact,
> e.g. "the customer is charged but the order never transitions to paid,
> silently losing the order"].

## Graph Mapping Instructions

- Create `component:error_handling` once per scan if any finding is filed
  here, with a `depends_on` edge to `component:logging`.
- Each swallowed-error site becomes its own `finding:<uuid>` vulnerability
  node with a `causes` edge from `component:error_handling`.
