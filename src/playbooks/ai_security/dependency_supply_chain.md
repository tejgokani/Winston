---
id: ai_security.dependency_supply_chain
title: Dependency Supply Chain Risk
category: ai_security
vulnerabilityClass: supply_chain_risk
appliesToStack: technology-agnostic
deepOnly: false
reviewPass: 3
owaspRefs:
  - "A08:2021 Software and Data Integrity Failures"
cweRefs:
  - "CWE-1104"
  - "CWE-494"
  - "CWE-829"
realWorldReferences:
  - title: "We Have a Package for You! A Comprehensive Analysis of Package Hallucinations by Code Generating LLMs (USENIX Security 2025)"
    url: "https://arxiv.org/html/2406.10279v3"
    type: research_paper
  - title: "Importing Phantoms: Measuring LLM Package Hallucination Vulnerabilities"
    url: "https://arxiv.org/pdf/2501.19012"
    type: research_paper
  - title: "Socket.dev — The Rise of Slopsquatting: How AI Hallucinations Are Fueling a New Class of Supply Chain Attacks"
    url: "https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks"
    type: security_blog
  - title: "Microsoft Security Blog — Typosquatted npm packages used to steal cloud and CI/CD secrets (14 packages published in 4 hours)"
    url: "https://www.microsoft.com/en-us/security/blog/2026/05/28/typosquatted-npm-packages-used-steal-cloud-ci-cd-secrets/"
    type: vendor_security_advisory
  - title: "Microsoft Security Blog — From package to postinstall payload: Inside the Mastra npm supply chain compromise by Sapphire Sleet"
    url: "https://www.microsoft.com/en-us/security/blog/2026/06/17/postinstall-payload-inside-mastra-npm-supply-chain-compromise/"
    type: incident_postmortem
  - title: "CERT/CC VU#534320 — Shai-Hulud npm self-propagating worm (500+ packages compromised via stolen CI/CD credentials)"
    url: "https://www.kb.cert.org/vuls/id/534320"
    type: incident_postmortem
quickModeSummary: >
  Check every newly added dependency: does the exact package name resolve on
  the registry (npm/PyPI/etc.), or could it be an AI-hallucinated name an
  attacker could register (slopsquatting)? Is it a plausible typosquat of a
  well-known package (one-character/transposition difference)? Does it (or a
  transitive dependency) ship a postinstall/preinstall script, and is that
  script's behavior known/auditable? Is there any lockfile/CI step that
  actually checks for known-vulnerable versions, or does nothing in the
  workflow ever revisit dependency freshness after initial scaffolding?
fileSelectionHint:
  roles: ["dependency_manifest", "lockfile", "ci_config"]
  matchImports: ["package.json", "package-lock.json", "requirements.txt", "pyproject.toml", "Pipfile", "go.mod", "Cargo.toml", "yarn.lock", "pnpm-lock.yaml"]
  matchAuthMapTags: []
  maxFiles: 8
  priorityOrder: ["dependency_manifest", "lockfile", "ci_config"]
severityHeuristics:
  critical:
    - "A dependency name in the manifest does not exist on the registry it's meant to come from (a hallucination candidate) and the package is imported and executed in a code path that will run — this is an unregistered name an attacker can claim today and turn into arbitrary code execution on every future `install`."
    - "A dependency (direct or transitive) ships a postinstall/preinstall script whose behavior cannot be explained by the review (obfuscated, minified, or fetches remote code at install time) and is actually present in the lockfile as installed."
  high:
    - "A dependency name is a plausible typosquat of a well-known, high-download package (single-character substitution, transposition, hyphen/underscore swap, common-prefix confusion like a scoped-vs-unscoped name) and was clearly intended to be the legitimate package."
    - "A direct dependency has a publicly known CVE with an available patched version, and nothing in the codebase's CI/tooling checks for it (no `npm audit`/`pip-audit`/Dependabot/Renovate/equivalent configured)."
  medium:
    - "A dependency ships a postinstall script that is benign and explainable (e.g. compiling a native binding via a well-known toolchain) but the codebase has no policy/tooling (`--ignore-scripts`, allowlist) governing which packages are permitted to run install-time code at all."
  low:
    - "Dependencies are pinned to exact versions with no automated update mechanism, creating gradual drift from patched versions over time (staleness risk, not an active vulnerability by itself)."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:dependency_supply_chain"
  relatedNodeIds: ["component:build_pipeline", "component:package_registry"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:build_pipeline"
    to: "component:dependency_supply_chain"
  - relation: enables
    from: "component:dependency_supply_chain"
    to: "component:code_execution"
commonAiCodingMistakes:
  - "AI coding agent generates an `import`/`require` for a package it inferred should exist (plausible-sounding name matching the task, e.g. `express-mongoose` conflating two real packages) but never actually verified against the registry — research on this pattern (USENIX Security 2025, 'We Have a Package for You!') found code-generating LLMs recommend nonexistent packages in roughly 5–20%+ of samples depending on model, and that hallucinated names are highly repeatable across runs of the same prompt, meaning an attacker can predict and pre-register them (slopsquatting)."
  - "AI runs `npm install <hallucinated-or-typo-name>` autonomously as part of a scaffolding task, and because the install succeeds (the attacker registered the name, or it resolves to an unrelated but installable package), the mistake is silently baked into the lockfile and never re-examined by a human."
  - "AI copies a dependency list from a tutorial/StackOverflow answer/older training-data snapshot without checking whether versions referenced are current, patched, or even still the canonical package for that functionality — introducing known-CVE versions from day one."
  - "AI adds a dependency to solve an immediate task without checking whether an existing, already-vetted dependency in the manifest already provides the same functionality, growing the attack surface (and postinstall-script surface) for no net capability gain."
  - "Nothing in the AI-scaffolded project setup wires up dependency vulnerability scanning (`npm audit`, `pip-audit`, Dependabot/Renovate config) as part of the initial scaffold, so the workflow has no mechanism to ever flag a dependency that was fine at scaffold-time but has since had a CVE disclosed."
falsePositiveGuardrails:
  - "Before flagging a package name as hallucinated, actually check registry existence and reasonable download/maintenance signals (age, maintainer, downloads) rather than asserting from name-plausibility alone — an unfamiliar name is not automatically hallucinated; a genuinely new or niche legitimate package looks the same from the outside."
  - "Do not flag every postinstall script as malicious — native module compilation (`node-gyp`, `prebuild-install`), font/binary asset fetching, and license-prompt scripts are common and benign. Only escalate when the script's behavior cannot be explained (obfuscated code, dynamic remote fetch-and-exec, unexplained network calls to non-package-related hosts) or when the package is unmaintained/newly published with no prior track record."
  - "Do not report a known-CVE dependency as a finding without checking whether the vulnerable code path is actually reachable from this application's usage of the package — cite the specific CVE and confirm (or explicitly flag as unconfirmed) whether the vulnerable function/feature is invoked."
  - "Do not treat a slightly unusual-looking but well-established, high-download, long-maintained package name as a typosquat candidate just because it resembles another package — check maintainer history and adoption before concluding intent to deceive."
  - "Version pinning/lockfiles by themselves are a best practice, not a vulnerability — only flag staleness as a finding when it's paired with an actual known CVE in the pinned version, not merely 'not on latest'."
---

## Root Cause Explanation

Supply chain risk in AI-assisted coding workflows has a genuinely new failure
mode layered on top of the classic ones, and reviewing this playbook means
covering both:

1. **Package hallucination / "slopsquatting" (the new angle).** LLMs
   generating code sometimes reference package names that sound plausible
   for the task but don't actually exist on the target registry — often by
   conflating two real package names, introducing a typo variant, or
   fabricating one outright. Academic research (USENIX Security 2025, "We
   Have a Package for You! A Comprehensive Analysis of Package Hallucinations
   by Code Generating LLMs") measured this directly: hallucination rates
   ranged roughly 5%–20%+ of generated code samples depending on the model,
   with open-source models hallucinating more than proprietary ones, and —
   critically — the same hallucinated name reappears consistently across
   repeated runs of the same prompt. That repeatability is what makes this
   exploitable: an attacker can run the same class of prompts an AI coding
   tool would see, harvest the hallucinated names that keep recurring, and
   register them on the real registry ahead of time. The next developer (or
   agent) that generates similar code and blindly `npm install`s or
   `pip install`s the hallucinated name pulls down the attacker's package
   instead of failing with a "not found" error.
2. **Typosquatting (classic, still very active).** A name one edit-distance
   away from a popular package, installed because neither the AI nor the
   developer double-checked the exact spelling/scope before running install.
   This remains one of the most consistently reported npm attack vectors
   because the entry barrier is trivial and detection tooling is inconsistent.
3. **Malicious postinstall/preinstall scripts.** npm (and other ecosystems)
   run install-time scripts by default. A compromised or malicious package
   doesn't need the application to `import` anything — code executes the
   moment `npm install` runs, before any of the application's own logic ever
   sees the package. This is the mechanism behind essentially every large
   npm supply-chain compromise disclosed in the last two years.
4. **Stale, never-revisited dependencies.** An AI-scaffolded project gets its
   initial dependency set right at creation time, but nothing in the
   resulting workflow (no `npm audit` in CI, no Dependabot/Renovate config)
   ever re-checks it. Known-CVE versions sit unpatched indefinitely because
   the scaffolding step that would normally prompt a human to think about
   ongoing maintenance never happened.

## Vulnerable Patterns

```json
// package.json — a name that sounds plausible for the task but was never
// verified against the npm registry (classic slopsquatting target)
{
  "dependencies": {
    "express-mongoose": "^1.0.0",      // conflates express + mongoose
    "requests-promise": "^4.0.0"       // plausible-sounding, not the real "request-promise"
  }
}
```

```bash
# AI agent autonomously installing whatever it generated, without
# confirming the name resolves to the intended, trusted package
npm install lodahs        # single-character typo of "lodash"
pip install python-dateutill   # typo of "python-dateutil"
```

```json
// A transitive/direct dependency with an install-time script whose
// behavior isn't visible in application code at all
{
  "scripts": {
    "postinstall": "node ./scripts/setup.js"
  }
}
// -> setup.js fetches and eval()s a remote payload; nothing in `app/` ever
//    calls this, so it's invisible to a review that only reads import sites
```

## Data Flow Tracing Guide

1. Diff the dependency manifest (`package.json`/`requirements.txt`/etc.)
   against the lockfile to see what's actually new versus long-established —
   focus scrutiny on recently added entries, especially ones added in the
   same change as AI-generated application code.
2. For each new/unfamiliar dependency name: does it exist on the registry,
   and does its metadata (age, maintainer history, download count) look like
   an established package rather than a just-registered placeholder? A
   package registered within days of being referenced in the codebase is a
   strong signal.
3. For near-miss names (one edit distance from a well-known package, or a
   scope/hyphenation variant): confirm whether the codebase's actual usage
   (imported symbols, API calls) matches the *real* package's API — a
   typosquat package that mimics the real API surface is harder to catch by
   behavior alone, so name-verification against the registry is the primary
   check, not "does it seem to work."
4. Check the lockfile for `postinstall`/`preinstall`/`install` script entries
   across all direct and transitive dependencies (not just direct — malicious
   packages are frequently pulled in transitively). Trace what each script
   actually does; flag any that are obfuscated, minified beyond what a
   legitimate small script would need, or reach out over the network.
5. Check for any dependency-vulnerability tooling wired into CI (`npm
   audit`, `pip-audit`, Snyk, Dependabot/Renovate config files). Its absence
   is evidence for the "never revisited" finding, not proof by itself of a
   vulnerable dependency — confirm at least one direct dependency actually
   has a known CVE with a reachable code path before elevating that specific
   finding above `low`.

## Evidence Checklist

- [ ] The exact package name and manifest/lockfile location is cited.
- [ ] If claiming hallucination: registry lookup result (or its absence) is
      described, plus why the name is plausible as an LLM-generated
      conflation/fabrication for this specific task.
- [ ] If claiming typosquatting: the specific well-known package it
      resembles and the exact character-level difference is named.
- [ ] If claiming a malicious/risky postinstall script: the exact script
      content or file path is cited, with a description of what it actually
      does (not just "has a postinstall script").
- [ ] If claiming a known-CVE dependency: the CVE id, installed version, and
      whether the vulnerable code path is reachable from this app's actual
      usage are all stated explicitly.
- [ ] Absence of CI vulnerability-scanning tooling is confirmed by checking
      CI config files, not assumed from the manifest alone.

## Attack Scenario Template

> A dependency named [package name] was added to [manifest location] as part
> of [feature/task]. [Because the name does not exist on the registry and is
> a plausible AI-hallucination target for this task / because it is a
> single-edit-distance typosquat of [real package] / because its postinstall
> script does [specific behavior]], an attacker who [registers the name /
> already controls the compromised package] gains [concrete impact — e.g.
> "arbitrary code execution in CI at build time, with access to whatever
> secrets are exposed to the build environment"] the next time `[install
> command]` runs in this repo or a CI pipeline that installs from this
> manifest.

If registry existence/ownership wasn't actually checked, say so and cap
severity accordingly rather than asserting hallucination or malicious intent
from name-shape alone.

## Graph Mapping Instructions

- Ensure a `component:dependency_supply_chain` node exists on first finding,
  with a `depends_on` edge from `component:build_pipeline`.
- Add an `enables` edge from `component:dependency_supply_chain` to
  `component:code_execution` to represent that a compromised/malicious
  dependency's blast radius is arbitrary code execution, not merely a data
  issue.
- Each concrete package (hallucinated name, typosquat, malicious postinstall,
  known-CVE version) becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from `component:dependency_supply_chain`.
- If a supply-chain finding is the root cause that would explain a secret
  exposure or CI compromise finding elsewhere in the scan (e.g. a postinstall
  script exfiltrating CI environment variables), add an `enables` edge from
  the supply-chain finding node to that other finding's node and state the
  causal link explicitly in `reasoning` so the graph mapper wires them
  together rather than reporting two disconnected findings.
