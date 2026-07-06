---
id: ai_mistakes.hallucinated_dependencies
title: Hallucinated Dependencies & APIs
category: ai_mistakes
vulnerabilityClass: ai_coding_defect
appliesToStack: technology-agnostic
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A06:2021 Vulnerable and Outdated Components"
cweRefs:
  - "CWE-1357"
realWorldReferences:
  - title: "We Have a Package for You! A Comprehensive Analysis of Package Hallucinations by Code Generating LLMs"
    url: "https://arxiv.org/abs/2406.10279"
    type: research_paper
quickModeSummary: >
  Does every imported package actually exist in the lockfile/registry, and
  does every called method actually exist on that library's real API surface
  (correct version)? AI models invent plausible-sounding package names and
  methods; attackers register the hallucinated package names ("slopsquatting")
  to hijack whatever gets auto-installed.
fileSelectionHint:
  roles: ["route_handler", "middleware", "auth", "config"]
  matchImports: []
  matchAuthMapTags: []
  maxFiles: 10
  priorityOrder: ["route_handler", "middleware", "auth"]
severityHeuristics:
  critical:
    - "An import resolves to a package name not present in the lockfile and not a standard-library module — code would fail to run, or (worse) a squatted package with that exact name exists on the public registry and would execute on install"
  high:
    - "Code calls a method/parameter on an official SDK that does not exist in the installed version (verified against package.json/requirements.txt pinned version), indicating the method was invented rather than looked up"
  medium:
    - "A dependency is imported but never declared in the manifest, relying on transitive resolution that could silently break"
  low:
    - "Deprecated or renamed API surface used in a way that still resolves today but is scheduled for removal upstream"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:dependencies"
  relatedNodeIds: ["component:build_pipeline"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:dependencies"
    to: "component:build_pipeline"
commonAiCodingMistakes:
  - "AI invents a plausible npm/pip package name that sounds like it should exist (e.g. a slight variation on a real popular package) instead of using the actual package, because the name pattern matches training data statistically rather than a verified registry lookup."
  - "AI calls a method that exists on a *different* library with a similar name/purpose, or that existed in a different major version of the same library, producing code that looks correct but throws at runtime."
  - "AI adds an import for a utility it assumes exists in the project (e.g. `from utils import slugify`) without checking whether that module or export actually exists in this repo."
falsePositiveGuardrails:
  - "Before flagging, check the actual lockfile (package-lock.json, requirements.txt with pinned versions, go.sum) — a package may be legitimately present even if unfamiliar."
  - "Do not flag internal monorepo imports (e.g. `@myorg/shared-utils`) as hallucinated without checking whether a local workspace package of that name exists in the repo."
  - "Version-specific API differences are only a finding if the installed/pinned version in the manifest is confirmed to lack the called member — don't guess based on general familiarity with the library."
---

## Root Cause Explanation

LLMs generate package names and API calls by pattern-completion over training
data, not by querying a real package registry or type-checking against an
installed SDK. This produces two recurring failure shapes:

1. **Hallucinated package names.** The model emits an import for a package
   that sounds right (matches naming conventions of the ecosystem) but does
   not exist, or exists as an abandoned/unrelated package. This is a known,
   measured phenomenon in LLM-generated code and creates a supply-chain attack
   surface: an attacker can register the hallucinated name on the real
   registry ("slopsquatting") so that the next AI-assisted install pulls in
   attacker-controlled code.
2. **Hallucinated API surface.** The model calls a method, parameter, or
   config key that doesn't exist on the actual library (or existed in a
   different major version), because the call pattern matches something
   common in the training corpus rather than the specific installed version.

## Vulnerable Patterns

```js
// Import doesn't match anything in package.json/package-lock.json
import { retryWithBackoff } from 'axios-retry-helper' // never installed, may not exist on npm at all

// Calling a method that doesn't exist on the pinned SDK version
const client = new StripeClient(key)
client.charges.createIdempotent(...) // Stripe SDK has no such method
```

## Detection Guide

1. For every top-level import/require in the included files, check whether
   the package name appears in the dependency manifest (package.json,
   requirements.txt, go.mod, Gemfile) or is a standard-library module for the
   detected language.
2. For calls into a well-known SDK (Stripe, AWS SDK, OpenAI, etc.), cross
   check the method/parameter name against what that SDK's pinned major
   version actually exposes — don't rely on general familiarity, note the
   pinned version from the manifest before judging.
3. For internal/local imports, check whether the referenced file or exported
   symbol actually exists in the repo's file tree/exports.

## Evidence Checklist

- [ ] Exact import statement or call site quoted, with file + line.
- [ ] The dependency manifest is cited to show the package is absent (or the
      pinned version is cited to show the method/param is absent).
- [ ] Not an internal workspace package — checked against the repo's actual
      module layout first.

## Failure Scenario Template

> Code at [file:line] imports/calls [name], which does not exist in
> [manifest file] / does not exist on [SDK]@[pinned version]. Running this
> path would [fail to build | throw at runtime | if the package name is later
> registered by an attacker on the public registry, execute
> attacker-controlled code on next install].

## Graph Mapping Instructions

- Create `component:dependencies` once per scan if any finding is filed here.
- Each hallucinated import/call becomes its own `finding:<uuid>` vulnerability
  node with a `causes` edge from `component:dependencies`.
