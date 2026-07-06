<div align="center">

<img src="media/logo.png" alt="Winston" width="380" />



**An MCP server that turns any LLM into a security auditor — producing an
interactive, root-cause threat graph instead of a wall of text.**

![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178C6?logo=typescript&logoColor=white)
![Node](https://img.shields.io/badge/Node-%E2%89%A520-339933?logo=node.js&logoColor=white)
![MCP](https://img.shields.io/badge/Model%20Context%20Protocol-Server-8A2BE2)
![Playbooks](https://img.shields.io/badge/Security%20Playbooks-110-critical)
![Status](https://img.shields.io/badge/Status-Pre--1.0-yellow)

[Quick Start](#quick-start) ·
[How It Works](#how-it-works) ·
[Tools](#mcp-tools) ·
[Playbooks](#playbook-library) ·
[Extension](#vs-code-extension) ·
[CI/CD](#cicd--automation)

</div>

---

Winston is a [Model Context Protocol](https://modelcontextprotocol.io) server
that gives any MCP-capable agent (Claude Code, Cursor, VS Code Copilot Chat,
Claude Desktop) the ability to perform a **deep, structured, evidence-backed
security audit** of a repository — and to render the result as a live,
explorable **threat graph** rather than a static report. Winston does the
scanning, stack detection, playbook selection, evidence verification, and
graph construction; the LLM does the reasoning. It ships with **110
security playbooks** spanning web application security, cloud/infra, and —
uniquely — the modern AI/ML and native-app threat surface (prompt injection,
agent excessive agency, model supply chain, Electron/Android/iOS/Flutter),
each grounded in a real CVE, advisory, or disclosed incident rather than
generic OWASP boilerplate.

Winston is **free and credit-less** — no billing, licensing, or scan-quota
layer.

## Table of Contents

- [Why Winston](#why-winston)
- [How It Works](#how-it-works)
- [Quick Start](#quick-start)
- [MCP Tools](#mcp-tools)
- [Trust & Precision](#trust--precision)
- [Playbook Library](#playbook-library)
- [CI/CD & Automation](#cicd--automation)
- [Quality & Evaluation](#quality--evaluation)
- [VS Code Extension](#vs-code-extension)
- [Configuration](#configuration)
- [Using Winston with the Claude Family](#using-winston-with-the-claude-family)
- [Architecture](#architecture)
- [Development](#development)
- [Project Status](#project-status)
- [License](#license)

## Why Winston

| | |
|---|---|
| 🕸️ **Interactive threat graph, not a report** | Findings are mapped into nodes and edges — components, vulnerabilities, root causes — with a computed **crown** (the single highest-impact root cause) ranked above everything it causes. |
| 🎯 **Exact-match playbook targeting** | Stack detection gates every playbook. A pure JSON API never loads an XSS playbook; a Postgres app loads SQL injection, not NoSQL. The model never reasons about — or pays tokens for — a technology the repo doesn't use. |
| 🧩 **Piece-by-piece review, never the whole repo at once** | The audit is a phased loop: recon map → playbook plan → one pass at a time, each pulling only its own methodology and file slice. The model never holds the entire codebase in context. |
| 🛡️ **Built-in false-positive control** | Every submitted finding's evidence is deterministically verified against the actual file content. Suppressions (`.winston-ignore`) and per-playbook guardrails keep noise down without hiding what was filtered. |
| 🤖 **AI/ML-native threat coverage** | 20 playbooks mapped to the OWASP LLM Top 10 — prompt injection, RAG poisoning, agent excessive agency, model deserialization RCE, and more — because Winston is built for the era of AI-generated and AI-integrated code. |
| 📱 **Native app coverage** | 20 more playbooks for Electron, Tauri, Android, iOS, Flutter, and browser extensions, mapped to the OWASP MASVS. |
| 📚 **Real citations, not generic advice** | Every playbook cites a real CVE, GitHub/GitLab Security Advisory, disclosed bug-bounty report, or vendor postmortem — e.g. CVE-2025-29927 (Next.js middleware bypass), CVE-2025-32711 "EchoLeak" (the first confirmed zero-click prompt injection), the 2019 Capital One SSRF breach. |
| ✅ **Fixes get verified, not assumed** | `verify_fix` re-reads the repo and confirms the vulnerable code is actually gone before marking a finding resolved. |
| 📊 **Measurable, not just claimed** | A built-in evaluation harness scores real audit runs against seeded ground-truth vulnerabilities — precision, recall, F1 — so quality is a number, not a promise. |
| 🆓 **Free and credit-less** | No billing, no license keys, no scan quotas. |

## How It Works

Winston drives the calling agent through a deliberate, **phased flow** — the
model never loads the whole repository at once, and it works one playbook at
a time:

```
 audit_repository(repoPath, mode)
        │
        ▼
 ┌────────────────────────────────────────┐
 │ 1. RECON                                │  persona + doctrine, structural map
 │    stack detected, playbooks selected   │  (routes, auth surface, folder tree),
 │    — NO file bodies yet                 │  and a plan (ordered playbook passes)
 └────────────────────────────────────────┘
        │
        ▼
 ┌────────────────────────────────────────┐
 │ 2. PER-PASS REVIEW (repeats per pass)   │
 │    get_playbook(scanId, ids)  ────────▶ │  full methodology + exact file slice
 │    reason over ONLY those files         │  + severity rubric + false-positive
 │    verify against guardrails            │  guardrails + common mistakes
 │    submit_findings(scanId, findings)    │
 └────────────────────────────────────────┘
        │
        ▼
 ┌────────────────────────────────────────┐
 │ 3. GRAPH SYNTHESIS (deterministic)      │  findings → nodes/edges, root-cause
 │    no further LLM calls                 │  ranking, the "crown", risk score
 └────────────────────────────────────────┘
```

1. **`audit_repository`** scans the repo, detects its stack, and selects
   *only* the playbooks that match — then returns a persona ("you are
   Winston, a meticulous auditor working piece by piece"), a structural map,
   and an ordered plan of playbook summaries. **No file contents are
   included at this stage.**
2. The agent works one pass at a time. Each call to **`get_playbook`**
   returns that pass's playbooks in full — methodology, severity rubric,
   false-positive guardrails, common AI-coding mistakes — **and the exact
   file slice to review**, resolved from the playbook's own file-selection
   hints. The agent reads only those files, verifies each candidate finding
   against the guardrails, and calls **`submit_findings`** before moving on.
3. Winston deterministically maps accepted findings into a persistent threat
   graph — no further LLM calls — merging across repeat scans so re-auditing
   the same repo evolves one graph instead of producing disconnected results.

Stack decides the playbooks; each playbook decides its files; the model
reads only those — never the whole repo, never a playbook the stack doesn't
call for.

## Quick Start

> Winston is not yet published to npm — build and run it from source today.
> (`npx -y winston_sec_mcp` will work once published; the extension already
> defaults to that command.)

```bash
git clone https://github.com/tejgokani/Winston.git
cd Winston
npm install
npm run build
```

Point any MCP-capable client at the built server. For Claude Code, add to
`.mcp.json` in your project (or run `claude mcp add`):

```json
{
  "mcpServers": {
    "winston": {
      "command": "node",
      "args": ["/absolute/path/to/Winston/dist/server.js"]
    }
  }
}
```

The same shape works for Cursor, Windsurf, and Claude Desktop's MCP config —
only the config file's location differs.

Then, in your agent, just ask:

> *"Use the Winston MCP server to run a deep security audit of
> `/path/to/my/repo`, then generate a report."*

The agent will call `audit_repository`, work through the playbook passes via
`get_playbook`/`submit_findings`, and you can then call `generate_report` or
`launch_ui` to see the results.

## MCP Tools

| Tool | Purpose |
|---|---|
| `audit_repository` | Scan a repo, detect its stack, select matching playbooks, return the recon map + plan. Supports `diffBase` for PR-scoped audits. |
| `get_playbook` | Fetch one or more selected playbooks' full methodology, severity rubric, false-positive guardrails, and exact file slice for the current pass. |
| `submit_findings` | Submit structured findings for a scan; runs deterministic evidence verification and suppression checks before accepting. |
| `verify_fix` | Re-check whether a specific finding's vulnerable code is still present; marks it `fixed` with proof, or returns the fix prompt if not. |
| `scan_secrets` | Deterministic (no-LLM) scan for hardcoded credentials — API keys, tokens, private keys, high-entropy secrets. |
| `detect_ai_tooling` | Detect which AI coding tools were plausibly used in a repo, from git trailers and config artifacts — no LLM, no per-file authorship claims. |
| `coverage_report` | Report what was actually reviewed vs. selected for a scan — surfaces unreviewed areas instead of implying full coverage. |
| `generate_graph` | Return or refresh a repo's threat graph without re-running a review. |
| `generate_report` | Export the graph as Markdown, HTML, JSON, or SARIF (for GitHub Code Scanning). |
| `list_scans` | List scan history for a repo with risk-score deltas versus the previous scan. |
| `launch_ui` | Launch the local interactive threat-graph viewer. |
| `ping` | Health check. |

## Trust & Precision

A security tool's reputation is set by its *worst* finding. Winston filters
before anything reaches the graph, and reports what it filtered instead of
hiding it:

- **Deterministic evidence verification.** Every finding's quoted evidence
  must actually appear in the cited file — hallucinated or paraphrased
  evidence is rejected with no extra LLM call.
- **Per-playbook false-positive guardrails.** Each playbook ships an explicit
  "do not flag when…" exclusion list, delivered to the model alongside its
  methodology and enforced as an explicit verify-before-submit step.
- **Suppression & baselines.** A committable `.winston-ignore` file
  (`<playbook-id>`, a path glob, or both per line) plus inline
  `// winston:ignore [playbook-id] — reason` markers stop accepted-risk
  findings from re-surfacing every scan.
- **Root-cause ranking — the crown.** Winston follows `causes` edges between
  findings and computes, per node, the severity-weighted count of open
  vulnerabilities reachable downstream. The node with the largest blast
  radius is the **crown** — the one root cause to fix first — and every
  other root cause is ranked beneath it by impact.
- **Fix verification, not assumption.** `verify_fix` re-reads the repo and
  confirms the vulnerable code cited in a finding's evidence is actually
  gone before marking it resolved.
- **Diff-scoped audits.** Pass `diffBase` (e.g. `"main"`, `"HEAD~1"`) to
  scope a review to changed files only — fast, cheap PR-style audits instead
  of re-scanning the whole repo.
- **No-LLM secret pre-scan.** `scan_secrets` catches hardcoded credentials
  (AWS/GitHub/Stripe/OpenAI/Anthropic tokens, private keys, high-entropy
  assignments) deterministically, for free, before any model call.
- **Honest coverage reporting.** `coverage_report` shows which selected
  playbooks were actually executed vs. skipped — surfacing gaps instead of
  implying total coverage.

## Playbook Library

**110 playbooks**, each with a root-cause explanation, vulnerable/safe code
patterns, a data-flow tracing guide, an evidence checklist, false-positive
guardrails, and a real-world citation.

| Category | Count | Coverage |
|---|---|---|
| `ai_security/` | 28 | Universal fundamentals — Authorization, Secrets Management, JWT, SQL/NoSQL Injection, XSS, SSTI, CSRF, SSRF, Command Injection, Mass Assignment, XXE, Cryptographic Failures, Race Conditions, Rate Limiting, File Uploads, Supply Chain ("slopsquatting"), and more. Baseline items are always on; stack-conditional items (JWT, XSS, SQLi, NoSQLi, SSTI, CSRF, Mass Assignment, XXE) gate on `requiresAnyTag` so they only load when the stack actually has that surface. |
| `ai_mistakes/` | 6 | Failure patterns specific to AI-generated code — hallucinated dependencies, error swallowing / fake success, test manipulation to force a pass, destructive operations without safeguards, logic duplication/drift, unrequested scope creep. |
| `technology/` (web & infra) | 36 | Express, Next.js (Auth & Middleware, Server Actions, API Routes), NestJS, Fastify, Clerk/Auth.js/better-auth, Supabase RLS, Firebase, Stripe, Prisma, Drizzle, tRPC, GraphQL, Flask/FastAPI, Django, Rails, Laravel, Java/Spring, ASP.NET Core, Go, Astro, SvelteKit, Remix, Nuxt, MongoDB, WebSockets/realtime, background jobs, transactional email, Docker, Kubernetes, Terraform, Serverless/Lambda, Vercel, GitHub Actions. |
| `technology/ai_ml/` | 20 | Mapped to the **OWASP LLM Top 10** — Prompt Injection (direct & indirect/EchoLeak), Insecure Output Handling, Excessive Agency, Sensitive Information Disclosure, RAG & Vector Store Security, Prompt Template Injection, Unbounded Consumption, MCP Server Security, Model Supply Chain, Multimodal Injection, Agent Memory Poisoning, Overreliance, Jailbreak Resistance, Embedding Privacy, Unsafe Model Deserialization, MLOps Pipeline Security, Training Data Poisoning, Model Theft, LLM Authorization Boundaries. |
| `technology/{electron,tauri,desktop,browser_ext,android,ios,flutter,mobile}/` | 20 | Mapped to the **OWASP MASVS** — Electron process isolation & IPC/preload, Tauri capabilities, desktop auto-update integrity, deep-link hijacking, local embedded servers, browser-extension permissions/messaging, Android storage/exported-components/WebView/network, iOS storage/Keychain/ATS/URL schemes, Flutter, and cross-mobile biometric auth, permissions, deep links, and clipboard/screen-capture leakage. |

Stack detection covers `package.json` (including nested monorepo workspace
manifests), `requirements.txt`/`pyproject.toml`, `Gemfile`, `composer.json`,
`go.mod`, `pom.xml`/`build.gradle`, `Dockerfile`, Kubernetes/Helm manifests,
native mobile manifests (`AndroidManifest.xml`, `Info.plist`,
`pubspec.yaml`), and file extensions (`.tf`, `.csproj`, `.swift`, `.dart`) —
see `src/playbooks/technology/registry.yaml`.

## CI/CD & Automation

The `winston` CLI covers the deterministic, no-LLM checks and result export
for pipelines — no agent required:

```bash
winston secrets <path>              # deterministic secret scan; exits non-zero on high-confidence hits
winston detect <path>               # AI-tooling detection
winston coverage --scan <id>        # what was actually reviewed
winston report --scan <id> --format sarif   # export SARIF for GitHub Code Scanning
winston eval <fixture> --findings <json>    # score findings against ground truth
```

A composite **`action.yml`** GitHub Action runs the secret gate out of the
box; the full LLM-driven audit runs through an MCP-capable agent (e.g. the
Claude Code Action) with Winston registered as its MCP server, then exports
SARIF for upload to Code Scanning.

## Quality & Evaluation

Every playbook makes precision/recall claims implicitly — Winston measures
them explicitly. The evaluation harness scores real audit output against
hand-seeded ground-truth vulnerabilities in `tests/fixtures/sample-repos/`:

```bash
node dist/cli.js eval tests/fixtures/sample-repos/express-fixture --findings findings.json
```

A submitted finding matches a ground-truth entry when its evidence lands on
the same file with an overlapping line range (±3 lines) — the exact
playbook/vulnerability-class label doesn't need to match, since a correct
finding may reasonably classify the same real issue slightly differently.
Each ground-truth entry can only be claimed once; unmatched findings count
as false positives, unmatched ground truth as misses. The command prints
precision, recall, and F1, and exits non-zero on a real miss — so it can
gate CI on a minimum audit-quality bar. See
[`src/eval/scorer.ts`](src/eval/scorer.ts) for the exact matching rule.

## VS Code Extension

`extension/` is the Winston VS Code extension — the branded, one-click face
of the server. It builds clean (`npm run build` inside `extension/`, plain
`tsc`, zero external UI dependencies) and packages via
`npx @vscode/vsce package`. It contributes four commands and renders its own
graph view entirely inside VS Code — no browser tab, no external server.

- **`Winston: Enable in this workspace`** writes (or merges into) a
  `.vscode/mcp.json` pointing at the Winston MCP server, so any MCP-aware
  agent in the editor (Copilot Chat, Claude Code's extension, etc.) can call
  it immediately.
- **`Winston: Audit this repository`** registers the server if needed, then
  copies a ready-made audit prompt to your clipboard for you to paste into
  your agent.
- **`Winston: Open Threat Graph`** opens a native webview panel with a
  self-contained SVG renderer (no cytoscape/CDN dependency, so it works
  under VS Code's strict webview CSP and follows your light/dark theme). It
  reads the same `~/.winston/graphs/*.json` the MCP server writes and
  **live-updates via a filesystem watcher** as the agent submits findings —
  the crown sits at the top of the tree, severity-colored nodes branch
  beneath it, and clicking a node shows its evidence, reasoning, and fix
  prompt, with affected files opening directly in the editor.
- **`Winston: Detect AI Coding Tooling`** runs the same no-LLM detection
  logic as the `detect_ai_tooling` MCP tool (a parallel implementation in
  `extension/src/toolingDetector.ts`, since the extension doesn't depend on
  the server package) and prints results to an output channel.

The extension is not yet published to the Marketplace — install it locally
(`npx @vscode/vsce package` then "Install from VSIX…" in VS Code, or run it
via `F5` in an Extension Development Host from `extension/`). See
[`extension/README.md`](extension/README.md) for development details.

## Configuration

**`.winston-ignore`** (repo root) — suppress accepted-risk findings so they
stop re-surfacing every scan:

```
ai_security.xss
src/legacy/**
ai_security.jwt_authentication src/auth/*.js
```

**Inline suppression** — `// winston:ignore [playbook-id] — reason` on or
above the flagged line.

**`winston.config.json`** (repo root) — tune a scan without touching
suppressions or playbooks:

```json
{
  "minSeverity": "high",
  "disabledPlaybooks": ["ai_security.xss"]
}
```

- `minSeverity` — only include findings at or above this severity in
  generated reports.
- `disabledPlaybooks` — exclude specific playbook ids from this repo's
  scans entirely, even if the stack tag matches.

A missing or invalid config file is ignored; Winston falls back to scanning
as if none were present.

**`.winston/playbooks/`** (repo root) — drop your own `.md` playbooks (same
frontmatter schema as the built-ins) to extend Winston with org-specific
rules, or override a built-in by reusing its `id`.

## Using Winston with the Claude Family

Winston asks the model to find security vulnerabilities and describe their
impact. Safety-conscious models are trained to be cautious about anything
that *looks* like developing offensive capability, and a model such as
**Claude Fable 5** may occasionally hesitate or soften part of a review if
it reads the request out of context — a feature of good alignment, not a
bug, but one that can get in the way of a legitimate audit of your own code.

Winston addresses this two ways:

1. **Explicit authorization framing.** Every `audit_repository` response
   opens with an *Authorization & Intent* preamble establishing that this is
   an authorized defensive review of the developer's own repository, that
   all output is remediation guidance, and that attack scenarios exist to
   help prioritize risk — never as exploit code.
2. **Model guidance.** If Fable 5 seems to be deferring or truncating a
   review, point Winston at **Claude Opus** instead and re-run — the reason
   is throughput and consistency on a long, tool-heavy task, not that the
   work is illegitimate on any model. The server and playbooks are entirely
   model-agnostic.

## Architecture

```
src/
├── server.ts              MCP server entry point — registers all 12 tools
├── cli.ts                 winston CLI (secrets, detect, report/SARIF, coverage, eval)
├── pipeline/               framework-agnostic core, unit-tested independently of the MCP SDK
│   ├── scanner.ts          repo walk, role classification, import extraction
│   ├── techDetector.ts     stack detection against technology/registry.yaml
│   ├── contextEngine.ts    recon-summary + file-selection (role- and import-based)
│   ├── playbookLoader.ts   stack gating, requiresAnyTag filtering, custom playbooks
│   ├── promptBuilder.ts    the phased-flow prompt (persona, plan, protocol)
│   ├── graphBuilder.ts     findings → threat graph
│   └── reportGenerator.ts  Markdown / HTML / SARIF export
├── graph/                  canonical node/edge vocabulary + deterministic findings-to-graph mapper
├── detect/                 non-LLM detection — AI-tooling signals, secret scanning
├── verify/                 deterministic evidence verification (the false-positive gate)
├── suppress/                .winston-ignore + inline suppression handling
├── config/                  winston.config.json loader
├── eval/                    ground truth + precision/recall scorer
├── models/                  zod schemas — the contracts between pipeline stages
├── playbooks/                the differentiating asset — Markdown + YAML frontmatter, loaded as data
├── storage/                  scan/graph persistence (~/.winston)
└── ui/                       local Express app + static cytoscape.js graph viewer

extension/                  VS Code extension — native webview graph, MCP registration
tests/fixtures/sample-repos/ synthetic repos with seeded vulnerabilities, used by tests and eval
```

## Development

```bash
npm install
npm run dev                # run the MCP server via tsx (stdio transport)
npm run build               # compile + copy playbooks/static assets into dist/
npm test                     # vitest
npm run validate-playbooks
```

Inspect tools locally with the [MCP Inspector](https://github.com/modelcontextprotocol/inspector):

```bash
npm run build
npx @modelcontextprotocol/inspector --cli node dist/server.js \
  --method tools/call --tool-name audit_repository \
  --tool-arg repoPath=/absolute/path/to/repo --tool-arg mode=quick
```

## Project Status

Winston is pre-1.0 and under active development. Currently accurate,
worth knowing before you rely on it:

- Not yet published to npm — build from source (see [Quick Start](#quick-start)).
- Structural repo scanning covers JS/TS, Python, Go, Rust, Java, PHP, and
  Ruby; Kotlin/Swift/Dart repos use an extension-based file-selection
  fallback rather than full structural parsing.

## License

[MIT License, with one added condition](LICENSE): any product, service, or
sub-product — internal or public — that is built on or incorporates this
codebase must include a visible attribution stating that it uses or is
built upon Winston (this repository). Aside from that requirement, it's
standard MIT — use, modify, and distribute freely. See [`LICENSE`](LICENSE)
for the exact terms.
