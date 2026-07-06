---
id: technology.ai_ml.content_safety_and_jailbreak
title: "LLM: Content Safety & Jailbreak Resistance"
category: technology
vulnerabilityClass: content_safety
appliesToStack: apps exposing an LLM to end users / generating user-facing content
requiresAnyTag: ["llm-api", "llm-app"]
deepOnly: true
reviewPass: 3
owaspRefs:
  - "OWASP LLM01:2025 Prompt Injection"
  - "A04:2021 Insecure Design"
cweRefs:
  - "CWE-693"
  - "CWE-1173"
realWorldReferences:
  - title: "OWASP Top 10 for LLM — jailbreaks and guardrail bypass as a subclass of prompt injection"
    url: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
    type: security_blog
  - title: "DAN / 'Do Anything Now' and the ongoing jailbreak arms race against safety guardrails"
    url: "https://arxiv.org/abs/2308.03825"
    type: research_paper
  - title: "Brand and safety incidents from unbounded chatbots (e.g. dealership bots manipulated into absurd commitments)"
    url: "https://venturebeat.com/ai/a-chevy-dealership-added-an-ai-chatbot-then-all-hell-broke-loose/"
    type: incident_postmortem
quickModeSummary: >
  If your app exposes an LLM to end users (or publishes its output), guardrails
  are a control, and jailbreaks are the bypass. The security-relevant questions
  are not "can it be jailbroken" (guardrails are probabilistic and bypassable)
  but: what is the impact when it is? Check whether jailbreaking the model can
  reach anything consequential — tools/actions (then it's excessive agency),
  private data (disclosure), or brand/legal harm from published output — and
  whether defenses are layered (input/output moderation, not just a prompt
  instruction). Confirm the app doesn't rely solely on the model's own refusal
  for safety-critical behavior, applies independent output moderation before
  publishing/acting, and constrains what an unbounded model can do. Treat the
  guardrail as defense-in-depth, never the sole control.
fileSelectionHint:
  roles: ["service", "controller", "agent", "moderation"]
  matchImports: ["openai", "@anthropic-ai/sdk", "langchain", "@langchain/core"]
  matchAuthMapTags: ["llm-api", "llm-app"]
  maxFiles: 10
  priorityOrder: ["moderation", "controller", "agent", "service"]
severityHeuristics:
  critical:
    - "A jailbreak can reach a consequential capability — invoke tools/actions or access private data — because safety is enforced only by the model's own refusal with no independent authorization/moderation gate (this is excessive agency reached via jailbreak)"
  high:
    - "The app publishes/acts on model output externally (public content, transactions, brand-facing responses) relying solely on the model's guardrails, so a jailbreak produces harmful/liable output or actions with no independent moderation"
    - "Safety-critical behavior (refusing prohibited actions, enforcing usage policy) is implemented only as a prompt instruction, with no output/action-level control"
  medium:
    - "Output moderation exists but is incomplete (covers some categories/channels, not the consequential ones), or guardrails are single-layer where the impact of bypass is moderate"
    - "User-facing generation lacks rate/scope limits that would bound abuse of a jailbroken model"
  low:
    - "Jailbreaking yields only content shown back to the same user with no tools, no private data, and no publication/action — the impact is contained; confirm no consequential reach before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:content_moderation"
  relatedNodeIds: ["component:llm_boundary", "component:authorization"]
graphEdgeMapping:
  - relation: protects
    from: "component:content_moderation"
    to: "component:llm_boundary"
commonAiCodingMistakes:
  - "AI relies on the model's own refusal ('you must not do X') as the sole safety control for a consequential capability, so a jailbreak that talks the model past its refusal reaches tools/data — safety enforced in the prompt is bypassable."
  - "AI publishes chatbot output directly to users/public (or acts on it) with no independent output moderation, so a jailbroken response causes brand/legal harm (the dealership-bot class)."
  - "AI treats 'the model is aligned' as a guarantee, not defense-in-depth, and builds no output-level or action-level control behind it."
  - "AI applies input moderation only, missing that the harmful content is in the OUTPUT, or applies output moderation only to some channels."
  - "AI gives a user-facing, jailbreakable model access to private data or actions without an independent authorization gate — the jailbreak becomes disclosure/agency."
  - "AI has no rate/scope limits, so a jailbroken model can be driven to produce harmful content or actions at scale."
falsePositiveGuardrails:
  - "Do not rate a jailbreak critical/high when its impact is confined to content shown back to the same user with no tools, no private data, and no publication/action — guardrails being bypassable is expected; severity is about reachable impact. Establish the consequential reach first."
  - "Systems that enforce safety-critical behavior with independent controls (authorization gates on tools/data outside the model, output moderation before publishing/acting) are correct — the model's own refusal being bypassable doesn't matter when the real control is external. Confirm the external control."
  - "Layered moderation (input + output, covering the consequential categories/channels) is the right pattern — do not flag single points that a working layered defense already covers."
  - "Cross-reference agent_excessive_agency (tools) and sensitive_information_disclosure (data); when a jailbreak reaches those, report there with this as the vector, avoiding double-counting."
  - "A model that produces only advisory content with clear AI labeling and no consequential downstream is the acceptable case."
---

## Root Cause Explanation

Guardrails — a model's trained refusals and any safety prompting — are
probabilistic controls, and jailbreaks are the well-established, continuously
evolving bypass (DAN and its descendants). So for a security review the useful
question is never "can it be jailbroken" (assume yes) but "what does a jailbreak
*reach*." If safety-critical behavior is enforced only by the model's own
refusal, then bypassing that refusal reaches whatever the model can do: if it can
invoke tools or access private data, the jailbreak becomes excessive agency or
disclosure; if its output is published or acted upon, the jailbreak becomes brand
and legal harm — a car-dealership bot talked into absurd "binding" offers is the
memetic example.

The design principle is defense-in-depth: the guardrail is one layer, never the
sole control for anything consequential. Consequential capabilities (tools,
private data, actions) must be gated by **independent** authorization outside the
model, and externally-published or acted-upon output must pass **independent**
moderation — so that a bypassed refusal still can't cross into real impact. The
model's alignment is a helpful default, not a security boundary.

## Vulnerable Patterns

```ts
// Safety enforced only by the model's refusal, gating a real capability
const out = await llm.complete(`${safetyPrompt}\n${userMsg}`);   // "never reveal X / never do Y"
if (out.wantsToolCall) await runTool(out.tool);                  // jailbreak → tool reached

// Publishing model output with no independent moderation
publishToPublicPage(await llm.complete(userMsg));                // jailbreak → brand/legal harm
```

Correct: independent gates behind the guardrail.

```ts
const out = await llm.complete(`${safetyPrompt}\n${userMsg}`);
if (out.wantsToolCall && authorize(user, out.tool)) await runTool(out.tool);  // external gate
const safe = await moderateOutput(out.text);                                   // independent
if (safe.ok) publishToPublicPage(safe.text);
```

## Data Flow Tracing Guide

1. Determine whether the app exposes the model to end users or publishes/acts on
   its output.
2. Identify what a jailbroken model could reach: tools/actions, private data, or
   external publication.
3. For each, check for an independent control behind the guardrail: authorization
   outside the model, output moderation before publishing/acting.
4. Note whether safety-critical behavior is enforced only in the prompt.
5. Rank by reachable impact, not by whether a jailbreak is possible.

## Evidence Checklist

- [ ] Where the model is exposed / its output published or acted upon, quoted.
- [ ] What a jailbreak can reach (tools, data, publication).
- [ ] The independent control (or its absence) behind the guardrail.
- [ ] Whether safety is prompt-only.

## Attack Scenario Template

> An attacker jailbreaks the user-facing model. Because [file:line] enforces
> safety only via [the model's refusal / a prompt instruction] and the jailbroken
> model can reach [tools / private data / public publication] with no independent
> [authorization / moderation] gate, the bypass results in [unauthorized action /
> data disclosure / harmful or liable published content].

## Graph Mapping Instructions

- Ensure a `component:content_moderation` node with a `protects` edge to
  `component:llm_boundary`.
- When a jailbreak reaches tools/data, cross-link to agent_excessive_agency /
  sensitive_information_disclosure and note the vector in `reasoning`.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:content_moderation` (the missing independent control).
