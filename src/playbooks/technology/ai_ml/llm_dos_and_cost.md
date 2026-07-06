---
id: technology.ai_ml.llm_dos_and_cost
title: "LLM: Unbounded Consumption, DoS & Cost Abuse"
category: technology
vulnerabilityClass: resource_exhaustion
appliesToStack: LLM applications exposed to user-controlled inference
requiresAnyTag: ["llm-api", "llm-app", "llm-agent"]
deepOnly: false
reviewPass: 2
owaspRefs:
  - "OWASP LLM10:2025 Unbounded Consumption"
  - "A04:2021 Insecure Design"
cweRefs:
  - "CWE-770"
  - "CWE-400"
  - "CWE-799"
realWorldReferences:
  - title: "OWASP Top 10 for LLM — Unbounded Consumption (denial of service and denial of wallet)"
    url: "https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/"
    type: security_blog
  - title: "'Denial of Wallet' — driving unbounded model/API spend against pay-per-token backends"
    url: "https://www.sans.org/blog/denial-of-wallet-attacks/"
    type: security_blog
  - title: "Recursive/looping agents and prompt-driven amplification causing runaway token and tool cost"
    url: "https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/"
    type: security_blog
quickModeSummary: >
  Every user-triggered inference costs money and compute; without limits, an
  attacker turns that into denial of service or "denial of wallet". Check for:
  missing per-user/per-key rate limits and quotas on LLM endpoints; no cap on
  input size (huge prompts), output length (max_tokens), or context assembled
  from user data (unbounded RAG/history); agent loops with no max-iteration/
  max-tool-call/timeout budget (a prompt can send an agent into an expensive
  loop); no per-request cost ceiling or spend alerting; and unauthenticated or
  cheaply-authenticated access to expensive models. The fixes are ordinary
  resource governance applied to inference: authenticate, rate-limit and quota
  per principal, bound input/output/context sizes, cap agent iterations and wall
  time, and enforce a spend budget with alerts.
fileSelectionHint:
  roles: ["service", "controller", "route_handler", "agent", "config"]
  matchImports: ["openai", "@anthropic-ai/sdk", "langchain", "@langchain/core", "llamaindex", "crewai", "autogen"]
  matchAuthMapTags: ["llm-api", "llm-app"]
  maxFiles: 10
  priorityOrder: ["controller", "agent", "service", "config"]
severityHeuristics:
  critical:
    - "An expensive LLM/agent endpoint is reachable with no authentication (or a trivially-obtainable key) and no rate limit, so anyone can drive unbounded pay-per-token spend or exhaust capacity (denial of wallet / DoS)"
  high:
    - "Authenticated LLM endpoints have no per-user rate limit/quota, or an agent can loop with no max-iteration/tool-call/timeout budget, so a single user (or a prompt injection) can amplify cost/compute far beyond intended"
    - "No cap on user-controlled input size, output max_tokens, or assembled context, allowing arbitrarily large (and slow/expensive) requests"
  medium:
    - "Rate limiting exists but is coarse (global, not per-principal) or easily bypassed, or spend is uncapped/unmonitored so abuse is possible but detectable late"
    - "Retry/backoff logic can amplify load (retry storms) under failure without a ceiling"
  low:
    - "Reasonable per-user limits and size/iteration caps are present but lack spend alerting or fine tuning — hardening only; confirm the core limits exist before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:rate_limiting"
  relatedNodeIds: ["component:llm_boundary", "component:authentication"]
graphEdgeMapping:
  - relation: protects
    from: "component:rate_limiting"
    to: "component:llm_boundary"
commonAiCodingMistakes:
  - "AI exposes a chat/completion endpoint with no rate limit or quota, so a script (or a leaked client key) runs up unbounded token spend — denial of wallet against the pay-per-token backend."
  - "AI builds an agent loop (`while not done: think(); act()`) with no max-iteration or timeout, so a prompt injection or a confused model can send it into an expensive, tool-calling loop."
  - "AI passes user input straight to the model with no length cap and no `max_tokens` on the output, letting a user submit huge prompts and demand huge completions."
  - "AI assembles context from unbounded sources (full chat history, all retrieved docs) with no token budget, so cost grows without limit as a conversation/corpus grows."
  - "AI ships the model API key to the client, so users call the expensive backend directly with no server-side throttle."
  - "AI adds retries without a ceiling/backoff, turning provider hiccups into a self-inflicted load amplifier."
falsePositiveGuardrails:
  - "Do not flag endpoints that enforce per-user/per-key rate limits and quotas AND bound input/output sizes — that is the correct governance. Confirm the limit is per-principal, not just a global cap that one user can consume entirely."
  - "Agents with a max-iteration/max-tool-call cap and a wall-clock timeout are bounded — only unbounded loops are the finding."
  - "A fixed, small `max_tokens` and an input length cap materially bound per-request cost — factor these in."
  - "Internal/trusted-only endpoints (not reachable by untrusted users, e.g. a batch job behind auth with its own budget) are lower risk — establish reachability before rating critical."
  - "The concern is user-driven unbounded consumption; a server-side scheduled task with fixed input is not this bug."
---

## Root Cause Explanation

Inference is expensive and metered, so an LLM endpoint is a resource the same way
a database or a compute cluster is — and it must be governed the same way. When
it isn't, two attacks follow. **Denial of service**: unbounded input sizes,
output lengths, context assembly, or agent loops let an attacker (or a
prompt-injected agent) consume compute and capacity until the service degrades.
**Denial of wallet**: because most backends bill per token or per call,
unbounded consumption converts directly into unbounded spend — an attacker
doesn't need to take you down, just to run up the bill. Agent loops make this
worse: a prompt can steer a tool-using agent into an expensive cycle, amplifying
one request into many.

The defenses are standard resource governance, applied to inference:
authenticate access, **rate-limit and quota per principal** (not just globally),
**bound** input length, output `max_tokens`, and assembled context, **cap** agent
iterations/tool-calls and wall-clock time, avoid unbounded retries, and enforce a
**spend budget with alerting** so abuse is capped and visible.

## Vulnerable Patterns

```ts
// No auth, no rate limit → denial of wallet
app.post("/chat", async (req, res) => {
  const out = await openai.chat.completions.create({ model: "gpt-4", messages: req.body.messages });
  res.json(out);                                  // any caller, any size, unlimited calls
});

// Unbounded agent loop
while (!done) { const step = await agent.think(); done = await agent.act(step); }  // no cap
```

Correct: auth + per-user limits + size/iteration caps + budget.

```ts
app.post("/chat", requireAuth, rateLimitPerUser, async (req, res) => {
  const messages = capContext(req.body.messages, MAX_INPUT_TOKENS);
  const out = await openai.chat.completions.create({ model, messages, max_tokens: 512 });
  res.json(out);
});
// agent: for (let i = 0; i < MAX_STEPS && !done && withinTimeout(); i++) { ... }
```

## Data Flow Tracing Guide

1. For each LLM/agent endpoint, check authentication and per-principal rate
   limiting/quota (not just a global cap).
2. Check input length caps, output `max_tokens`, and context-assembly bounds.
3. For agents, check max-iteration/tool-call caps and timeouts.
4. Check for a per-request/per-user spend ceiling and alerting.
5. Check whether the model key is exposed to clients (direct, unthrottled access)
   and whether retries have a ceiling/backoff.

## Evidence Checklist

- [ ] The endpoint/agent and its rate-limit/quota status, quoted.
- [ ] Input/output/context size bounds (or their absence).
- [ ] Agent iteration/timeout caps (or their absence).
- [ ] Reachability (auth) and any spend budget/alerting.

## Attack Scenario Template

> An attacker [scripts requests against the unauthenticated endpoint / crafts a
> prompt that loops the agent / submits huge prompts demanding huge outputs].
> Because [file:line] enforces no [per-user rate limit / iteration cap / size
> cap / spend budget], the attacker drives [service degradation / unbounded
> token spend], resulting in [denial of service / denial of wallet].

## Graph Mapping Instructions

- Ensure a `component:rate_limiting` node with a `protects` edge to
  `component:llm_boundary`.
- Note the denial-of-wallet vs. denial-of-service class in `reasoning`.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:rate_limiting` (the missing governance).
