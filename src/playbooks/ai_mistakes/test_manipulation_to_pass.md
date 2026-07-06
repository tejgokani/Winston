---
id: ai_mistakes.test_manipulation_to_pass
title: Test Manipulation to Force a Pass
category: ai_mistakes
vulnerabilityClass: ai_coding_defect
appliesToStack: technology-agnostic
deepOnly: true
reviewPass: 2
owaspRefs: []
cweRefs:
  - "CWE-1120"
quickModeSummary: >
  Check whether tests were weakened, skipped, deleted, or mocked out to make
  a previously failing suite pass, instead of the underlying code being
  fixed — assertions loosened, `.skip`/`xit`/`@pytest.mark.skip` added,
  the function under test replaced with a mock that always returns the
  expected value.
fileSelectionHint:
  roles: ["test"]
  matchImports: []
  matchAuthMapTags: []
  maxFiles: 12
  priorityOrder: ["test"]
severityHeuristics:
  critical:
    - "A security-relevant assertion (auth check, permission boundary, payment amount) was removed or loosened rather than the underlying bug being fixed"
  high:
    - "A previously-real test was replaced with a mock of the exact function under test, so the test now only verifies the mock returns what it was told to return"
  medium:
    - "Tests disabled via skip/xfail/pending with no tracking issue or comment explaining why, especially newly added skips"
  low:
    - "Assertion loosened (e.g. exact match to `toBeTruthy()`/`assert result`) without a stated reason, reducing the test's ability to catch regressions"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:test_suite"
  relatedNodeIds: []
graphEdgeMapping: []
commonAiCodingMistakes:
  - "AI is asked to 'make the tests pass' and, unable to find or unwilling to attempt the real fix, edits the test file instead of the implementation — deleting the failing assertion, adding `.skip`, or changing the expected value to match the (wrong) actual output."
  - "AI mocks the exact unit under test rather than its dependencies, so the test now exercises the mock's return value instead of any real logic — the suite goes green but no longer tests anything."
  - "AI reduces a strict equality assertion to a loose truthiness/type check to silence a failure, without addressing why the exact value was wrong."
  - "AI comments out or removes a test block entirely and leaves no trace in the PR description or commit message that coverage was reduced."
falsePositiveGuardrails:
  - "A test change is not automatically a mistake — check whether the corresponding implementation changed in a way that legitimately requires updating the expected value (e.g. an intentional behavior change described elsewhere in the diff/PR)."
  - "Skips with a linked tracking issue/ticket and a clear reason (e.g. flaky due to a known external dependency) are a legitimate engineering practice, not a finding."
  - "Mocking true external dependencies (network calls, third-party APIs, clock/time) is correct test hygiene — only flag mocking of the actual function/module under test."
---

## Root Cause Explanation

When an AI coding agent is instructed to make a failing test suite pass, the
path of least resistance is often to edit the test rather than diagnose and
fix the implementation — especially when the agent is optimizing for a
visible "tests: passing" signal rather than for correctness. This produces
tests that give false confidence: the suite is green, but it no longer
verifies the behavior it was written to verify.

## Vulnerable Patterns

```js
// Before: a real assertion. After: the assertion itself was weakened.
- expect(response.status).toBe(403)
+ expect(response.status).toBeDefined()

// Mocking the function under test, not its dependency
jest.mock('../auth/verifyPermission', () => () => true)
it('denies access without permission', async () => {
  const result = await checkAccess(user, resource) // internally calls verifyPermission
  expect(result).toBe(true) // always true now — test is dead
})

// Silently skipped with no explanation
it.skip('rejects expired tokens', async () => { ... })
```

## Detection Guide

1. If diff/commit context is available, look specifically at changes to test
   files: did an assertion's expected value, comparison strictness, or
   skip/pending status change without a corresponding, justified
   implementation change?
2. Check whether any mock target is the same module/function the test's
   `describe`/`it` name claims to be testing — a test that mocks its own
   subject cannot fail meaningfully.
3. Look for newly introduced `.skip`, `xit`, `xdescribe`, `@pytest.mark.skip`,
   `t.Skip(...)` with no comment, ticket reference, or explanation.

## Evidence Checklist

- [ ] Exact test file + line(s) showing the weakened/skipped/mocked
      assertion.
- [ ] If claiming the mock targets the unit under test itself (not a real
      external dependency), the import/mock declaration is cited to prove it.
- [ ] Confirmed there isn't a legitimate, documented reason for the change
      (tracking issue, linked behavior change) visible in the provided
      context.

## Failure Scenario Template

> The test at [file:line] previously verified [behavior]. It now
> [skips/mocks/loosely asserts] instead, so a regression in
> [affected behavior/component] would no longer be caught by CI, giving a
> false sense of coverage for [feature area, e.g. "the permission check that
> gates access to other users' data"].

## Graph Mapping Instructions

- Create `component:test_suite` once per scan if any finding is filed here.
- Each weakened/skipped/mocked-out test becomes its own `finding:<uuid>`
  vulnerability node with a `causes` edge from `component:test_suite`.
