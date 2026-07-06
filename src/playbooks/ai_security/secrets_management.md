---
id: ai_security.secrets_management
title: Secrets Management
category: ai_security
vulnerabilityClass: secrets_exposure
appliesToStack: technology-agnostic
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A02:2021 Cryptographic Failures"
cweRefs:
  - "CWE-798"
  - "CWE-312"
  - "CWE-532"
realWorldReferences:
  - title: "GitGuardian — The State of Secrets Sprawl 2025 (23.8M secrets found on public GitHub, 70% of secrets leaked in 2022 still active in 2025)"
    url: "https://www.gitguardian.com/state-of-secrets-sprawl-report-2025"
    type: security_blog
  - title: "GitGuardian — The State of Secrets Sprawl 2026 (81% year-over-year surge in AI-service credential leaks; ~29M secrets on public GitHub)"
    url: "https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/"
    type: security_blog
  - title: "Rocket.Chat — API Keys Hardcoded in Github repository (HackerOne #766346)"
    url: "https://hackerone.com/reports/766346"
    type: bug_bounty_disclosure
  - title: "socfortress/CoPilot — Hardcoded JWT secret shipped as fallback in source and verbatim in .env.example, enabling full admin compromise (GHSA-4gxj-hw3c-3x2x)"
    url: "https://github.com/socfortress/CoPilot/security/advisories/GHSA-4gxj-hw3c-3x2x"
    type: vendor_security_advisory
  - title: "Cloud Security Alliance — Vibe Coding Security Crisis: Credential Sprawl and SDLC Debt"
    url: "https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-generated-code-security-vibe-coding-202/"
    type: research_paper
quickModeSummary: >
  Look for hardcoded API keys/secrets/passwords in source, weak fallback
  defaults for secrets read from environment variables (e.g. `|| 'default'`),
  secrets committed in config files, and secrets logged or returned in API
  responses/error messages.
fileSelectionHint:
  roles: ["config", "auth", "middleware", "docker", "ci_cd"]
  matchImports: []
  matchAuthMapTags: []
  maxFiles: 10
  priorityOrder: ["config", "auth"]
severityHeuristics:
  critical:
    - "A live-looking secret (API key, database credential, signing key) is hardcoded directly in a source file"
    - "A secret with a weak fallback default (e.g. `SECRET || 'changeme'`) is used for something security-critical (JWT signing, encryption) and there's no evidence the fallback is rejected at startup in production"
  high:
    - "A secret is logged (console.log, error handler, request logger) even if not hardcoded — it can leak through log aggregation"
    - "A secret is committed in a config file (.env checked into the repo, docker-compose with inline credentials) rather than injected at deploy time"
  medium:
    - "A secret is returned in an API response or error message under some condition (e.g. a debug/verbose mode left enabled)"
  low:
    - "A secret's name/comment suggests it's meant to be rotated but there's no rotation mechanism evident (defense-in-depth gap, not an active leak)"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:secrets"
  relatedNodeIds: ["component:authentication", "component:jwt"]
graphEdgeMapping:
  - relation: stores
    from: "component:secrets"
    to: "component:database"
commonAiCodingMistakes:
  - "AI writes a working fallback default during scaffolding (`process.env.API_KEY || 'sk-test-123'`) so the code runs immediately without requiring the developer to set up env vars first — this is meant to be temporary but nothing enforces its removal before deploy."
  - "AI adds verbose error logging that includes the full request/config object during debugging, which happens to include secrets, and the logging statement survives after the bug is fixed."
  - "AI generates a docker-compose.yml or CI config with inline example credentials for local development, and those literal values get committed and later reused unchanged in a staging/prod config."
  - "AI stores a third-party API key directly in a frontend-bundled file because the integration was scaffolded as if it were server-only, and the code got copied into a client component without noticing the secret would ship to the browser."
  - "AI coding assistants that ingest the full workspace for context (rather than respecting `.gitignore` the way a Git client would) can reproduce a real secret that already exists in a local `.env` file directly into newly generated source, sample code, or a committed config — bypassing the environment-variable abstraction that was supposed to keep it out of source in the first place."
  - "AI scaffolds an MCP server config (e.g. `mcp.json`, `claude_desktop_config.json`, a `.mcp` file) with a real API key or token hardcoded in the `env`/`args` block, copying the pattern from quickstart documentation that itself shows credentials inline for demo purposes — this is a documented mass pattern (GitGuardian found tens of thousands of unique secrets in public MCP config files, thousands still valid), and it is especially relevant to review here since this tool operates in the MCP ecosystem itself."
falsePositiveGuardrails:
  - "Do not flag values that are clearly placeholder/example text (e.g. 'your-api-key-here', 'xxx', values inside .env.example or README code blocks) as live secrets — distinguish documentation/template files from actual runtime config."
  - "Do not flag test fixtures using obviously fake credentials scoped to a test/mock environment, unless they're structured identically to how the real secret is sourced in production code (which would indicate the fake accidentally shadows real usage)."
  - "A secret read purely from `process.env.X` with no fallback and no default is not a finding by itself — that's the correct pattern. Only flag if there's a weak fallback, hardcoded value, or leakage path."
  - "When a credential-shaped literal appears in an MCP client config file (`mcp.json`, `claude_desktop_config.json`), don't assume it's automatically live — some MCP servers intentionally take short-lived or scope-limited tokens as config; do check whether the value matches a real provider's key format and whether the file is committed to version control before treating it as a finding, same as any other config file."
---

## Root Cause Explanation

Secret leakage in AI-assisted codebases follows a small number of shapes,
almost all traceable to the same underlying cause: a secret that was meant to
be temporary (for local development or a quick demo) survives into a path
that reaches production or version control.

1. **Hardcoded secrets.** The literal value appears directly in source —
   often introduced during scaffolding "to get it working" and never
   replaced with a real environment-variable read.
2. **Weak fallback defaults.** `process.env.SECRET || 'dev-secret'` runs
   fine locally and in CI, so nothing ever forces the developer to notice
   the fallback is still reachable in a real deployment.
3. **Leakage through logging or responses.** A secret isn't hardcoded but
   gets written to logs, error messages, or API responses under some
   condition (verbose/debug mode, unhandled exception including config
   state) — exposure without a "hardcoded" root cause.
4. **Committed config.** `.env` files, docker-compose files, or CI YAML with
   inline credentials get checked into version control, especially when a
   project is scaffolded quickly and `.gitignore` isn't set up first.

## Vulnerable Patterns

```js
// Hardcoded API key
const stripeClient = new Stripe('sk_live_51H8x...');

// Weak fallback survives into "production" if the env var is ever unset
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

// Secret leaked via logging
console.log('Config loaded:', config); // config includes apiKey, dbPassword

// Secret returned in an error response
res.status(500).json({ error: err.message, config: currentConfig });
```

## Data Flow Tracing Guide

1. Search config/auth/middleware files for string literals that look like
   credentials (long random-looking strings, `sk_`/`pk_`/`AKIA`-style
   prefixes common to well-known providers, anything assigned to a variable
   named `secret`, `key`, `password`, `token` with a literal value).
2. For every place a secret is read from `process.env`, check whether there's
   a `||` fallback or default parameter, and whether that fallback is
   distinguishable from a real secret (i.e., would a misconfigured
   production deploy silently "work" with the fallback?).
3. Trace logging statements and error handlers — does anything log a full
   config/request object that might include a secret field, rather than
   destructuring only the fields actually needed?
4. Check `.gitignore` for `.env`-style entries, and check whether any
   committed file (docker-compose.yml, CI config) contains what looks like a
   real (non-placeholder) value in a credential-shaped field.

## Evidence Checklist

- [ ] The exact file + line where the secret value or weak fallback appears
      is cited, with the literal snippet quoted.
- [ ] If claiming a leakage path (logging/response): the exact log/response
      statement is cited, and what secret-shaped field flows into it.
- [ ] Confirmation the value isn't a documented placeholder/example
      (checked filename and surrounding context — `.env.example`, README,
      test fixtures).

## Attack Scenario Template

> [Secret name/type] is [hardcoded in / logged from / committed in]
> [specific file/line]. An attacker with [read access to source / log
> access / repo access] obtains this value and can [concrete impact — e.g.
> "authenticate as the application to the payments provider", "forge JWTs
> for any user"].

## Graph Mapping Instructions

- Always ensure a `component:secrets` node exists on the first
  secrets-related finding.
- A secrets finding that would enable forging/bypassing another component
  (e.g. a hardcoded JWT secret enabling token forgery) should get a `causes`
  edge from the secrets finding node to the other finding's node, if that
  finding is present in the same scan — secrets issues are very often the
  true root cause behind an otherwise-separate-looking finding.
