---
id: ai_security.ai_llm_api_security
title: LLM API Integration Security
category: ai_security
vulnerabilityClass: llm_api_security
appliesToStack: technology-agnostic
deepOnly: false
reviewPass: 1
owaspRefs:
  - "LLM01:2025 Prompt Injection"
  - "LLM02:2025 Sensitive Information Disclosure"
  - "LLM05:2025 Improper Output Handling"
  - "LLM06:2025 Excessive Agency"
  - "LLM10:2025 Unbounded Consumption"
cweRefs:
  - "CWE-798"
  - "CWE-522"
  - "CWE-77"
  - "CWE-79"
  - "CWE-89"
  - "CWE-770"
  - "CWE-1426"
quickModeSummary: >
  Check every place the app calls OpenAI/Anthropic/other LLM APIs: is the API
  key ever reachable from client-side/bundled code (network tab, source maps,
  `NEXT_PUBLIC_*`/`VITE_*`/`REACT_APP_*` env prefixes, a direct fetch to
  api.openai.com or api.anthropic.com from a component)? Is user input
  concatenated into a system prompt or a prompt that drives tool/function
  calling without isolation or per-user scoping (prompt injection enabling
  cross-user tool calls)? Is the LLM-calling endpoint authenticated and rate
  limited, or can anyone spam it and run up the developer's API bill? Is raw
  LLM output ever interpolated into SQL, a shell command, or rendered as raw
  HTML without validation/escaping?
fileSelectionHint:
  roles: ["route_handler", "middleware", "component", "service", "api_client"]
  matchImports:
    - "openai"
    - "@anthropic-ai/sdk"
    - "anthropic"
    - "langchain"
    - "@ai-sdk/openai"
    - "@ai-sdk/anthropic"
    - "ai"
    - "google-generativeai"
    - "groq-sdk"
    - "cohere-ai"
  matchAuthMapTags: ["llm", "ai", "chatbot", "assistant"]
  maxFiles: 10
  priorityOrder: ["route_handler", "service", "api_client", "component", "middleware"]
severityHeuristics:
  critical:
    - "LLM API key (OpenAI/Anthropic/etc.) is read into client-bundled code (a frontend component, a `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_`-prefixed env var, or an inline string) such that it ships to every visitor's browser — trivially extractable from the network tab or bundle."
    - "Prompt injection lets a user-controlled message reach a function/tool-calling LLM with access to sensitive tools (order lookup, refunds, account modification, code execution) without per-request authorization scoping, allowing cross-tenant/cross-user data access or unintended privileged actions."
    - "Raw LLM output is interpolated directly into a SQL query, shell command, or `eval`-like sink with no parameterization/sanitization (indirect injection escalating to RCE or SQLi)."
  high:
    - "LLM-calling endpoint has no authentication and no rate limiting, allowing unbounded cost-abuse (denial-of-wallet) by anonymous callers."
    - "Raw, unescaped LLM output is rendered as HTML (`dangerouslySetInnerHTML`, `v-html`, unescaped template output) enabling stored/reflected XSS if the model can be steered to emit markup."
    - "System prompt embeds secrets, internal tool schemas, or other users' data, and there is no defense against prompt-leakage extraction via user input."
  medium:
    - "Rate limiting exists but is IP-based only (trivially bypassed) or has no per-user/per-API-key cost ceiling, so a single authenticated account can still run costs far beyond expected usage."
    - "User input is concatenated into the system prompt without any delimiter/structural separation from trusted instructions, increasing susceptibility to instruction override even where the blast radius of a successful injection is limited (e.g., no sensitive tools attached)."
    - "LLM output used to build a downstream artifact (e.g., a generated report, a filename, a redirect URL) without validation, but the sink is not immediately sensitive (defense-in-depth gap, not a direct exploit path)."
  low:
    - "API key correctly stays server-side but has no scoped/least-privilege project key or spend cap configured on the provider dashboard (defense-in-depth only)."
    - "Verbose LLM-related error messages (raw provider error bodies) returned to the client, potentially leaking prompt structure or backend implementation details."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:llm_integration"
  relatedNodeIds:
    - "component:api_security"
    - "component:secrets"
    - "component:rate_limiting"
    - "component:output_handling"
graphEdgeMapping:
  - relation: depends_on
    from: "component:llm_integration"
    to: "component:secrets"
  - relation: protects
    from: "component:rate_limiting"
    to: "component:llm_integration"
  - relation: depends_on
    from: "component:llm_integration"
    to: "component:output_handling"
commonAiCodingMistakes:
  - "AI scaffolds a quick working demo by calling `openai.chat.completions.create(...)` or `new Anthropic({...})` directly inside a React/Vue component or a client-side script, because that's the fastest path to 'it works' — the key ends up in the bundle. This mirrors documented tutorial-driven patterns (client-side OpenAI calls are common in quickstart guides written for simplicity, not production)."
  - "AI names the env var with a framework's public-exposure prefix out of habit — `NEXT_PUBLIC_OPENAI_API_KEY`, `VITE_ANTHROPIC_API_KEY`, `REACT_APP_OPENAI_KEY` — not realizing that prefix is precisely the mechanism that inlines the value into the client bundle at build time."
  - "AI builds a support/agent chatbot with function-calling tools (e.g. `lookup_order`, `issue_refund`) and passes the authenticated user's identity only in the initial system prompt text rather than binding it server-side to each tool invocation — so a crafted user message that gets the model to 'call lookup_order with id=12345' executes with no re-verification that 12345 belongs to the requesting user."
  - "AI wires up a `/api/chat` or `/api/generate` route with no auth middleware and no rate limiter because the demo/prototype had no users yet — this scaffolding survives unchanged into a deployed app with a real, billable API key behind it."
  - "AI treats the LLM response as trusted internal data once it comes back from the SDK, then interpolates it into a follow-up SQL query, a shell command (e.g., for a 'run this suggested command' feature), or renders it as raw HTML in a chat UI, because it was validated as 'coming from our own backend' rather than as attacker-influenced output."
  - "AI implements a system prompt as a single f-string/template literal with the user's raw message spliced directly in (`f\"You are a support agent... User says: {user_input}\"`), with no structural delimiter, no separate message role, and no instruction-hierarchy defense — the simplest possible implementation, and the most injectable one."
falsePositiveGuardrails:
  - "Do not flag a client-visible API key if it is a provider-issued publishable/restricted key explicitly designed for client-side use (rare for LLM providers, but verify — most OpenAI/Anthropic keys are NOT designed this way; check the key prefix and provider docs before assuming a client-exposed key is safe)."
  - "Do not flag prompt concatenation as injection-vulnerable by pattern-matching alone — confirm what the model can actually do with a successful override. A model with no tools and no sensitive output sink (e.g., a purely conversational FAQ bot) has materially lower severity than one with function-calling access to account/data-modifying tools, even though both technically lack input sanitization."
  - "Do not flag rate limiting as missing without checking for edge/infra-level protection (CDN/WAF rate limits, API gateway throttling, Vercel/Cloudflare edge middleware) that may not be visible in application code alone — note it as unconfirmed rather than asserting absence if the deployment platform isn't part of the reviewed file set."
  - "Do not treat every use of LLM output as an output-handling vulnerability — only flag when output reaches a genuinely sensitive sink (SQL, shell, raw HTML render, filesystem path, redirect target). Output that's only ever displayed as escaped text in a chat bubble via a framework's default (auto-escaping) rendering is not vulnerable to XSS via that path."
  - "A backend proxy route that forwards the API key server-side is not vulnerable merely for existing — the finding requires demonstrating the key or a bypassable secret actually reaches the client (check the actual response body/bundle, not just that a proxy pattern exists somewhere)."
realWorldReferences:
  - title: "LLM01:2025 Prompt Injection — OWASP Gen AI Security Project"
    url: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
    type: vendor_security_advisory
  - title: "OWASP Top 10 for LLM Applications 2025"
    url: "https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/"
    type: vendor_security_advisory
  - title: "Incident 622: Chevrolet Dealer Chatbot Agrees to Sell Tahoe for $1"
    url: "https://incidentdatabase.ai/cite/622/"
    type: incident_postmortem
  - title: "EchoLeak: First Real-World Zero-Click Prompt Injection Exploit in a Production LLM System"
    url: "https://arxiv.org/abs/2509.10540"
    type: research_paper
  - title: "How Microsoft Defends Against Indirect Prompt Injection Attacks"
    url: "https://www.microsoft.com/en-us/msrc/blog/2025/07/how-microsoft-defends-against-indirect-prompt-injection-attacks"
    type: vendor_security_advisory
  - title: "8,000+ ChatGPT API Keys Left Exposed Across GitHub Repos and Live Websites"
    url: "https://thecyberexpress.com/exposed-chatgpt-api-keys-github-websites/"
    type: security_blog
  - title: "Wiz Research: Common Security Risks in Vibe-Coded Apps"
    url: "https://www.wiz.io/blog/common-security-risks-in-vibe-coded-apps"
    type: security_blog
  - title: "Best Practices for API Key Safety — OpenAI Help Center"
    url: "https://help.openai.com/en/articles/5112595-best-practices-for-api-key-safety"
    type: vendor_security_advisory
  - title: "API Key Best Practices: Keeping Your Keys Safe and Secure — Claude Help Center"
    url: "https://support.claude.com/en/articles/9767949-api-key-best-practices-keeping-your-keys-safe-and-secure"
    type: vendor_security_advisory
  - title: "Denial of Wallet: Cost-Aware Rate Limiting for Generative AI Applications"
    url: "https://handsonarchitects.com/blog/2025/denial-of-wallet-cost-aware-rate-limiting-part-1/"
    type: security_blog
---

## Root Cause Explanation

Apps that integrate an LLM API (OpenAI, Anthropic, or similar) introduce a
class of failure that's distinct from classic web vulnerabilities in one key
way: the LLM itself is an untrusted-input-processing component sitting inside
the trust boundary, and its API key is a billable, high-value secret. Four
failure modes recur constantly, especially in AI-scaffolded ("vibe coded")
apps where tutorials and quickstarts optimize for "it works in five minutes,"
not production posture:

1. **Client-side key exposure.** The fastest way to get an LLM demo working
   is to call the provider's SDK directly from the frontend. Official
   quickstarts and countless tutorials show exactly this for pedagogical
   simplicity. The key then ships inside the JavaScript bundle (or is visible
   in the Network tab on every request) to every visitor. Unlike a leaked key
   in a git history — which can be rotated and the leak contained — a
   client-bundled key is a standing, silently-harvestable backdoor: bots
   scrape live sites and public repos for `sk-...`-shaped strings continuously,
   and abuse can begin within minutes of deployment. This is one of the
   fastest-growing categories of exposed secret on GitHub and is a
   specifically documented pattern in AI-scaffolded/"vibe coded" apps: 2025-era
   audits of apps built with tools like Lovable and Base44 found live API
   keys and unauthenticated endpoints exposed in shipped frontend bundles at
   meaningful scale.
2. **Prompt injection.** Because natural-language user input is passed into a
   prompt that also carries the system's trusted instructions, a
   sufficiently crafted message can override, extend, or redirect those
   instructions — especially dangerous when the LLM has function/tool-calling
   access to real backend actions (order lookup, refunds, account changes).
   This is not a theoretical risk: a Chevrolet dealership's ChatGPT-powered
   chatbot was manipulated into agreeing to sell a $76,000 SUV for $1 via a
   crafted prompt (AI Incident Database #622), and "indirect" prompt
   injection — where the malicious instructions arrive via *retrieved*
   content rather than the user's own message (a document, email, webpage,
   ticket) — has produced confirmed, high-severity production exploits, most
   notably EchoLeak (CVE-2025-32711, CVSS 9.3), a zero-click vulnerability in
   Microsoft 365 Copilot where a crafted email caused silent exfiltration of
   sensitive documents when a user merely asked Copilot to summarize their
   inbox.
3. **No rate limiting / cost controls.** LLM API calls are billed per token
   and provider-side rate limits are enforced at the organization/project
   level, not per end-user — meaning if the application itself doesn't add a
   per-user or per-IP throttle, there is no mechanism to stop one caller (or
   a script) from making unlimited calls against the developer's account.
   Because a leaked or abusable endpoint requires no further exploitation —
   an attacker just calls the API and the bill accrues — this is functionally
   a denial-of-wallet (DoW) attack, a cost-based cousin of denial-of-service.
4. **Missing output validation (indirect/insecure output handling).** Once a
   response comes back from the LLM SDK, it's easy to treat it as "our own"
   trusted data rather than as attacker-influenceable content, since the text
   that produced it may have come from a user or from retrieved external
   content. If that output is then interpolated into a SQL query, passed to
   a shell command, or rendered as raw HTML, the LLM becomes a confused
   deputy: an attacker who can influence the prompt (directly or indirectly)
   can influence the downstream sink through it. OWASP tracks this
   specifically as Improper Output Handling (LLM05:2025).

## Vulnerable Patterns

Look for shapes like these (illustrative, not exhaustive — reason about
equivalents in the actual stack you're reviewing, don't string-match):

```js
// 1. Client-side key exposure — key ships in the bundle
// components/Chat.jsx
const client = new OpenAI({
  apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY, // NEXT_PUBLIC_* is inlined at build time
  dangerouslyAllowBrowser: true,
});
const res = await client.chat.completions.create({ ... }); // called from the browser

// 2. Prompt injection into a tool-calling agent with no per-call authorization
const systemPrompt = `You are a support agent. You can call lookup_order(order_id).
The current user said: ${userMessage}`; // raw user text spliced into system role
// model decides which order_id to look up based on attacker-steerable text;
// lookup_order() itself doesn't re-check that order_id belongs to the caller

// 3. No rate limiting / cost controls
app.post('/api/chat', async (req, res) => {          // no auth middleware
  const completion = await openai.chat.completions.create({ // no rate limiter
    model: 'gpt-4', messages: req.body.messages,
  });
  res.json(completion);
});

// 4. Missing output validation — LLM output flows into a sensitive sink
const sql = `SELECT * FROM products WHERE category = '${llmSuggestedCategory}'`; // SQLi
db.query(sql);

<div dangerouslySetInnerHTML={{ __html: llmResponse }} /> // XSS if model emits markup

exec(`git ${llmSuggestedGitCommand}`); // command injection via model output
```

## Data Flow Tracing Guide

To evaluate this playbook responsibly, trace the following before writing any
Finding:

1. **Find every LLM SDK/API call site.** Grep for `openai`, `Anthropic`,
   `anthropic`, `chat.completions`, `messages.create`, `api.openai.com`,
   `api.anthropic.com`, and equivalents for other providers. For each call
   site, determine: does this file execute server-side (route handler, server
   action, edge function, backend service) or client-side (React/Vue/Svelte
   component, a script loaded in the browser, anything bundled by
   webpack/vite/esbuild for the frontend)? If client-side, trace where the
   `apiKey` value comes from — an env var, and if so, does its name carry a
   build-tool prefix that inlines it into the client bundle (`NEXT_PUBLIC_`,
   `VITE_`, `REACT_APP_`, `PUBLIC_` in Astro/SvelteKit, etc.)? Confirm by
   checking whether that same var is referenced anywhere in
   client-rendered code, not just declared in `.env`.
2. **Trace the prompt construction path for every LLM call.** Find where the
   final prompt (system message, user message, or a single concatenated
   string) is built. Identify every value spliced in that originates from
   user input, a database record populated by users, or externally-fetched
   content (a document, webpage, email, ticket, API response) — this is the
   indirect-injection surface. Is there any structural separation (distinct
   message roles, delimiters, an instruction hierarchy, an input
   classifier/guardrail) between trusted instructions and this
   untrusted content, or is it a single flat string?
3. **If the LLM call includes tools/functions,** enumerate each tool's
   capability and blast radius (read-only lookup vs. state-changing action
   like refunds, account edits, sending communications, code execution). For
   each sensitive tool, check whether the tool's *implementation* — not the
   prompt — enforces that the resource being acted on belongs to the
   authenticated caller. A model deciding "call `lookup_order(id=X)`" is not
   itself an authorization boundary; the handler behind that tool call must
   independently verify `X` belongs to the requesting user's session.
4. **Trace the route/handler that triggers each LLM call from the client.**
   Does it sit behind auth middleware (check against `auth_map`)? Is there a
   rate limiter (express-rate-limit, an edge/gateway rule, a token-bucket
   check, a per-user usage counter) in the request path before the LLM call
   executes? Is the limit per-IP only (weak — trivially defeated by rotating
   IPs or using a botnet) or tied to an authenticated identity/API key with a
   cost ceiling (stronger)?
5. **Trace where each LLM response is consumed after it returns.** Is it
   rendered directly (check for `dangerouslySetInnerHTML`, `v-html`,
   `{% autoescape false %}`, or equivalent raw-render mechanisms)? Is it
   interpolated into a query string, a shell command, a file path, or passed
   to any `eval`-like sink? Is it parsed as structured data (JSON/function
   call arguments) and trusted without schema validation before being used to
   drive further logic?

## Evidence Checklist

Before submitting a Finding for this playbook, confirm:

- [ ] At least one concrete code snippet with an exact file + line range is
      attached as evidence — do not paraphrase, quote the actual line(s).
- [ ] If claiming client-side key exposure: the exact import/instantiation
      line is cited AND confirmation that the containing file is part of the
      client bundle (not merely suspicion based on file location — check for
      `'use client'`, a components/ path actually rendered client-side, or a
      `<script>` tag, and check the env var's prefix against the framework's
      public-exposure convention).
- [ ] If claiming prompt injection: the exact line where user/external input
      is spliced into the prompt is cited, AND the specific downstream
      capability (tool, sensitive output) that a successful override could
      reach is identified concretely — not just "the model could be
      manipulated" in the abstract.
- [ ] If claiming missing authorization on a tool call: both the prompt
      construction site and the tool's implementation (showing the missing
      re-check) are cited.
- [ ] If claiming missing rate limiting / cost-abuse risk: confirmation that
      no rate limiter is present anywhere in the request path reviewed, with
      a note on whether edge/infra-level protection is out of scope for this
      review (don't claim total absence if the deployment platform's config
      wasn't part of the reviewed file set — flag as unconfirmed instead).
- [ ] If claiming missing output validation: both the LLM call site and the
      exact downstream sink (SQL query, shell exec, HTML render) receiving
      unvalidated output are cited.

A finding without at least one concrete code-snippet evidence entry must not
be submitted.

## Attack Scenario Template

> An attacker [obtains the client-exposed API key from the bundle / crafts a
> message containing embedded instructions / sends unauthenticated requests
> to the unthrottled endpoint / steers LLM output toward a sensitive sink].
> Because [specific code location] does not [missing check — key kept
> server-side / prompt isolation / rate limiting / output validation], the
> attacker is able to [concrete impact specific to this repo, e.g. "make
> unlimited billed completions against the developer's OpenAI account using
> the harvested key" or "cause the order-lookup tool to return another
> customer's order details by embedding an override instruction in the chat
> message"] — not a generic description.

Fill every bracket concretely from evidence gathered in this repo. If a
bracket can't be filled from real evidence, the scenario is speculative and
severity must be capped at `medium`, with a note that exploitability is
unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:llm_integration` node exists (create it on the
  first LLM-API-related finding in a scan) with a `depends_on` edge to
  `component:secrets` (for key handling) and to `component:output_handling`
  (for downstream sink findings).
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from `component:llm_integration` (or
  a more specific root-cause component, e.g. `component:secrets` if the root
  cause is client-side key exposure, or `component:rate_limiting` if the root
  cause is missing throttling) to the finding node.
- If a finding enables reaching a specific external system or sensitive
  component (e.g. a database via SQL injection through LLM output, a
  payments/refund system via an unguarded tool call), add an `enables` edge
  from the finding node to that component's node id.
- Root cause vs. symptom: if a finding is *caused by* another finding already
  identified in this scan (e.g. a missing-prompt-isolation finding causes a
  cross-user-data-access finding via an unguarded tool call), say so
  explicitly in the finding's `reasoning` field so the graph mapper can wire
  a `causes` edge between the two finding nodes rather than treating them as
  unrelated.
- If both a client-side key exposure finding and a missing-rate-limiting
  finding exist for the same LLM integration, note the compounding
  relationship explicitly (an exposed key with no server-side throttle at all
  means the attacker's abuse isn't even mediated by the app's own — likely
  absent — rate limiter) so severity assessment reflects the combined risk
  rather than each finding being scored in isolation.
