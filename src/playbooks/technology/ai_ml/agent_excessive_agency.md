---
id: technology.ai_ml.agent_excessive_agency
title: "LLM: Excessive Agency & Unsafe Tool Use"
category: technology
vulnerabilityClass: excessive_agency
appliesToStack: LLM agents with tools / function calling
requiresAnyTag: ["llm-agent", "mcp", "llm-app"]
deepOnly: false
reviewPass: 1
owaspRefs:
  - "OWASP LLM06:2025 Excessive Agency"
  - "A01:2021 Broken Access Control"
cweRefs:
  - "CWE-269"
  - "CWE-862"
  - "CWE-441"
realWorldReferences:
  - title: "OWASP Top 10 for LLM — Excessive Agency (excessive functionality, permissions, or autonomy)"
    url: "https://genai.owasp.org/llmrisk/llm06-excessive-agency/"
    type: security_blog
  - title: "Confused-deputy risks in tool-using agents and MCP servers (Anthropic MCP security guidance)"
    url: "https://modelcontextprotocol.io/docs/concepts/security"
    type: security_blog
  - title: "Embrace the Red — agent hijacking: making a tool-using assistant take unintended actions via injection"
    url: "https://embracethered.com/blog/posts/2023/chatgpt-plugin-vulns-chat-with-code/"
    type: security_blog
quickModeSummary: >
  When an LLM can call tools/functions, the security question is what those
  tools can do and who authorized the call. Excessive agency = too much
  functionality (tools with broad/destructive capability), too many permissions
  (the agent's credentials/scopes exceed what the task needs), or too much
  autonomy (side-effecting actions execute without human approval or an
  independent authorization check). The danger compounds with prompt injection:
  an injected model becomes a confused deputy, invoking tools with the agent's
  privileges on the attacker's behalf. Check that each tool is least-privilege,
  that side-effecting/irreversible actions require an authorization check
  performed OUTSIDE the model (not the model deciding it's allowed) and ideally
  human confirmation, and that the agent's credentials are scoped per user/task,
  not a shared god-token.
fileSelectionHint:
  roles: ["agent", "tool", "service", "controller", "config"]
  matchImports: ["langchain", "@langchain/core", "llamaindex", "crewai", "autogen", "@openai/agents", "@modelcontextprotocol/sdk", "openai"]
  matchAuthMapTags: ["llm-agent", "mcp"]
  maxFiles: 12
  priorityOrder: ["tool", "agent", "config", "service"]
severityHeuristics:
  critical:
    - "An agent exposed to untrusted input can invoke a side-effecting or irreversible tool (send money/email, delete data, run code, modify infra, make external requests) where authorization is decided by the model itself or absent — a prompt injection becomes remote action with the agent's privileges"
    - "The agent runs with broad or shared credentials (an admin/service token, another user's scope) so any tool call it makes acts with more authority than the requesting user should have (privilege escalation / cross-tenant action)"
  high:
    - "Side-effecting tool calls execute with no human-in-the-loop confirmation and no independent (outside-the-model) authorization check, so the model's decision alone triggers real-world effects"
    - "The agent has more tools/functionality than the task requires (excessive functionality), enlarging the injection blast radius (e.g. a summarizer agent that can also delete files)"
  medium:
    - "Tools are side-effecting but scoped and authorized outside the model, yet lack rate/spend limits or an audit trail, so abuse is possible but bounded; or autonomy is high (multi-step, self-directed) without checkpoints"
    - "Tool inputs produced by the model are passed to the tool without validation, so injection can smuggle unexpected arguments even if the tool itself is authorized"
  low:
    - "The agent's tools are all read-only / non-sensitive and scoped to the requesting user, so excessive-agency impact is limited — confirm no tool has side effects or cross-user reach before downgrading"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:authorization"
  relatedNodeIds: ["component:llm_boundary", "component:external_system"]
graphEdgeMapping:
  - relation: protects
    from: "component:authorization"
    to: "component:external_system"
  - relation: enables
    from: "component:llm_boundary"
    to: "component:external_system"
commonAiCodingMistakes:
  - "AI registers powerful tools (run shell/SQL, send email, call payment APIs, delete records) on an agent that also ingests untrusted input, with the model deciding when to call them — so a prompt injection drives real actions (the confused deputy). The authorization must be enforced in the tool, outside the model."
  - "AI gives the agent a single shared, broadly-scoped credential (a service account, an admin API key) for all users, so every tool call acts with god privileges regardless of who asked — cross-user actions and privilege escalation."
  - "AI executes side-effecting tool calls immediately with no human confirmation for irreversible/high-impact actions (spend, delete, send), trusting the model's judgment as the only gate."
  - "AI over-provisions functionality: the agent is handed every available tool 'to be helpful,' when the task needs two — enlarging the attack surface for injection."
  - "AI passes the model-generated tool arguments straight into the tool without validating them against the caller's permissions (e.g. the model supplies a `userId`/`accountId` the requester shouldn't touch)."
  - "AI builds an MCP server whose tools trust the caller entirely and perform sensitive actions without per-call authorization, assuming the client/agent is trusted."
falsePositiveGuardrails:
  - "Do not flag an agent whose side-effecting tools each enforce an independent authorization check (against the requesting user's permissions, outside the model) before acting — that is the correct control even if the model 'decides' to call the tool. The gate is in the tool, not the prompt."
  - "Read-only tools scoped to the requesting user's own data, with no side effects and no cross-tenant reach, are low risk — confirm the tool cannot mutate state or read others' data."
  - "Human-in-the-loop confirmation for irreversible/high-impact actions is a valid control — do not flag autonomy when a confirmation step gates the consequential calls."
  - "Per-user/per-task scoped credentials (the agent acts with the requester's authority, not a shared god-token) are the correct pattern — only shared/over-broad credentials are the finding."
  - "The mere presence of tools/function-calling is not a vulnerability — excessive agency requires a consequential capability reachable from untrusted input without an outside-the-model authorization gate. Establish that gap before flagging."
---

## Root Cause Explanation

An LLM by itself only emits text; agency comes from the tools you give it. The
moment a model can call functions with side effects, the model's fallibility —
and its susceptibility to prompt injection — becomes the application's
fallibility. OWASP names three dimensions: excessive **functionality** (tools
more powerful or numerous than the task needs), excessive **permissions** (the
agent's credentials exceed what the requesting user should wield), and excessive
**autonomy** (consequential actions fire without human or independent checks).
Each enlarges what an injection can accomplish.

The central design error is letting the *model* be the authorization boundary.
"The agent will only delete a record if the user is allowed" is not a control,
because a prompt injection can convince the model the user is allowed. The
correct architecture treats every tool call as a request from an untrusted
source and authorizes it *outside* the model — in the tool implementation,
against the requesting user's real permissions, with the agent holding
per-user/per-task credentials rather than a shared god-token, and with
human-in-the-loop confirmation for irreversible or high-impact actions. Then an
injected model is contained: it can *ask* to do anything, but the privilege
boundary refuses what the user isn't entitled to.

## Vulnerable Patterns

```ts
// Powerful tools + untrusted input + model as the only gate = confused deputy
const agent = createAgent({
  tools: [runShell, deleteRecord, sendPayment, fetchUrl],   // excessive functionality
  credentials: ADMIN_TOKEN,                                  // excessive permissions (shared)
});
await agent.run(userMessage);   // side effects fire on the model's say-so alone
```

Correct: least-privilege tools, per-user scope, authz in the tool, confirm
high-impact.

```ts
async function deleteRecord(args, ctx) {
  if (!authorize(ctx.user, "delete", args.id)) throw new Error("denied"); // outside the model
  if (isHighImpact(args)) await requireHumanConfirmation(ctx);
  // ...
}
const agent = createAgent({ tools: [searchDocs, deleteRecord], credentials: ctx.userToken });
```

## Data Flow Tracing Guide

1. List every tool/function the agent can call; mark each as read-only vs.
   side-effecting/irreversible, and note its capability and data reach.
2. Determine the agent's credentials/scope — per-user/task or shared/broad?
3. For each side-effecting tool, find where authorization happens: inside the
   tool against the real user (correct), or implied by the model/prompt (broken/
   absent)?
4. Check whether untrusted input can reach the agent (it usually can) and whether
   consequential actions require human confirmation.
5. Validate model-supplied tool arguments against the caller's permissions.

## Evidence Checklist

- [ ] The tool registration and each tool's capability/data reach, quoted.
- [ ] The agent's credential scope (shared vs. per-user), quoted.
- [ ] For each consequential tool: where (if anywhere) authorization is enforced
      relative to the model.
- [ ] Whether untrusted input reaches the agent and whether high-impact actions
      are confirmed.
- [ ] A concrete injection-to-action path.

## Attack Scenario Template

> An attacker sends (or plants) input that the agent ingests. Because [file:line]
> exposes [tool] with [capability] and authorization is [decided by the model /
> absent], and the agent holds [a shared admin credential / the user's scope],
> the injected model invokes [tool] with the agent's privileges, resulting in
> [unauthorized action / cross-user effect / irreversible damage].

## Graph Mapping Instructions

- Ensure a `component:authorization` node with a `protects` edge to
  `component:external_system` (the tools/effects).
- Add an `enables` edge from `component:llm_boundary` to the tool/effect the
  injected model can reach; note the confused-deputy class in `reasoning`.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:authorization` (the missing outside-the-model gate).
