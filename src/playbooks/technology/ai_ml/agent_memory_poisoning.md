---
id: technology.ai_ml.agent_memory_poisoning
title: "LLM: Agent Memory & State Poisoning"
category: technology
vulnerabilityClass: memory_poisoning
appliesToStack: agents with persistent memory / conversation state across turns or sessions
requiresAnyTag: ["llm-agent", "mcp"]
deepOnly: true
reviewPass: 3
owaspRefs:
  - "OWASP LLM01:2025 Prompt Injection"
  - "OWASP LLM06:2025 Excessive Agency"
cweRefs:
  - "CWE-94"
  - "CWE-863"
  - "CWE-501"
realWorldReferences:
  - title: "ChatGPT long-term memory persistent prompt injection (Johann Rehberger — planting instructions that survive across sessions)"
    url: "https://embracethered.com/blog/posts/2024/chatgpt-persistent-memory-and-data-exfiltration/"
    type: security_blog
  - title: "OWASP Top 10 for LLM — prompt injection persisted into agent memory/state"
    url: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
    type: security_blog
  - title: "Memory/state poisoning in multi-agent and long-running agent systems"
    url: "https://genai.owasp.org/llmrisk/llm06-excessive-agency/"
    type: research_paper
quickModeSummary: >
  Agents that persist memory (long-term notes, conversation summaries, scratchpad
  state, shared multi-agent memory) create a durable injection surface: an
  attacker plants instructions once and they resurface in future turns or
  sessions, and — if memory is shared across users/agents — in other principals'
  contexts. Check that anything written to persistent memory is treated as
  untrusted when read back (delimited, not re-injected as trusted instructions),
  that memory is scoped per user/session (not a shared store that leaks or lets
  one user poison another's context), that what the agent chooses to persist is
  controlled (an injected agent shouldn't be able to write arbitrary durable
  instructions), and that persisted state can't carry exfiltration payloads that
  fire later. Persistent memory turns a one-shot injection into a durable one.
fileSelectionHint:
  roles: ["agent", "service", "memory", "controller", "config"]
  matchImports: ["langchain", "@langchain/core", "llamaindex", "crewai", "autogen", "@openai/agents"]
  matchAuthMapTags: ["llm-agent", "mcp"]
  maxFiles: 10
  priorityOrder: ["memory", "agent", "service", "config"]
severityHeuristics:
  critical:
    - "Persistent agent memory is shared across users/tenants (or across agents that serve different principals) such that one user can plant content that is read back into another user's context and drives actions/disclosure (cross-user persistent injection)"
  high:
    - "Content the agent writes to durable memory is re-read as trusted instructions in later turns/sessions, so a single injection persists and re-triggers (or carries a delayed exfiltration payload) beyond the originating interaction"
    - "An injected/compromised agent can write arbitrary durable instructions or state (no control over what is persisted), making the poisoning self-perpetuating"
  medium:
    - "Memory is per-user but re-injected without delimiting/provenance, so a same-user injection persists across that user's sessions (limited to their own context but durable)"
    - "Summarization/compression of history can smuggle injected instructions into the persisted summary undetected"
  low:
    - "Ephemeral, per-session memory that is not persisted across sessions and is handled as untrusted data on read-back — residual only; confirm no cross-user or durable path before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:agent_memory"
  relatedNodeIds: ["component:llm_boundary", "component:authorization"]
graphEdgeMapping:
  - relation: enables
    from: "component:agent_memory"
    to: "component:llm_boundary"
  - relation: depends_on
    from: "component:agent_memory"
    to: "component:authorization"
commonAiCodingMistakes:
  - "AI gives an assistant long-term memory and reads stored notes back into the prompt as trusted context, so an injection written once ('remember to always...') persists across sessions and re-fires — the ChatGPT persistent-memory injection class."
  - "AI shares an agent memory store across users (a global 'knowledge' or scratchpad) so one user can plant content that surfaces in another user's context (cross-user poisoning)."
  - "AI lets the agent decide what to persist and writes it verbatim, so an injected agent can write durable malicious instructions or a delayed exfiltration payload."
  - "AI summarizes conversation history into persisted memory without treating the source as untrusted, letting injected instructions ride into the summary and survive."
  - "AI stores exfiltration payloads (e.g. a markdown image URL) in memory that render later when the memory is displayed, firing the leak in a future session."
  - "AI keys memory too broadly (per-org instead of per-user) so state bleeds across principals."
falsePositiveGuardrails:
  - "Do not flag ephemeral, per-session context that is not persisted across sessions and is handled as untrusted data when re-read — that is not durable poisoning. Confirm there is no cross-session or cross-user persistence."
  - "Per-user memory that is delimited/marked as untrusted on read-back (not re-injected as trusted instructions) has the correct handling — the residual is limited to the same user, rank accordingly."
  - "Memory scoped strictly per user/session with server-verified identity is correct isolation — only shared/cross-user memory is the high/critical finding."
  - "Controlled persistence (the app decides what to store, validated, rather than the agent writing arbitrary durable instructions) is the correct pattern."
  - "Cross-reference prompt_injection (the injection itself) and sensitive_information_disclosure (cross-user leakage); report the persistence/durability angle here without double-counting."
---

## Root Cause Explanation

Persistent memory is what makes an agent useful across turns and sessions, and it
is exactly what turns a one-shot prompt injection into a durable one. When an
agent writes to long-term memory, a conversation summary, a shared scratchpad, or
a multi-agent store, and later reads that content back into its prompt as trusted
context, any injected instruction that made it into memory *re-fires* — in the
next turn, the next session, and (if memory is shared) in other users' contexts.
The ChatGPT persistent-memory injection demonstrated the durable version: plant
"always do X / always exfiltrate to Y" once, and it persists.

Two properties set the severity. **Scope**: per-user, per-session memory contains
the blast radius to that user; shared or over-broadly-keyed memory lets one user
poison another's context (cross-user, the serious case). **Trust on read-back**:
if persisted content is re-injected as trusted instructions rather than handled as
untrusted, delimited data, the injection keeps working. The controls: scope memory
per user/session to server-verified identity, treat everything read from memory as
untrusted data, control what the agent is allowed to persist (don't let an injected
agent write arbitrary durable instructions), and validate summaries so injected
text can't ride into them.

## Vulnerable Patterns

```python
# Persisted memory read back as trusted instructions → durable injection
memory.save(user_msg)                                   # may contain injected "always..."
context = memory.load()                                 # trusted context
answer = agent.run(system=policy + context, message=new_msg)

# Shared store across users → cross-user poisoning
GLOBAL_MEMORY.append(agent_note)                        # one user's note surfaces for all
```

Correct: per-user scope, untrusted on read-back, controlled persistence.

```python
context = memory.load(user_id=session.user.id)          # per-user, verified
answer = agent.run(
  system=policy,
  message=new_msg,
  context=f"<untrusted_memory>\n{context}\n</untrusted_memory>",   # data, not instructions
)
# persist only validated, app-controlled fields — not arbitrary agent-written instructions
```

## Data Flow Tracing Guide

1. Identify persistent memory/state: long-term memory, summaries, scratchpads,
   multi-agent shared stores.
2. Check scope: per-user/session keyed to verified identity, or shared/over-broad?
3. Check read-back handling: re-injected as trusted instructions, or delimited
   untrusted data?
4. Check what can be persisted: app-controlled/validated, or arbitrary
   agent-written content?
5. Look for exfiltration payloads or instructions that could be stored and fire
   later; check summarization for injection pass-through.

## Evidence Checklist

- [ ] The memory write and read-back code, quoted.
- [ ] Memory scope (per-user vs. shared) and identity keying.
- [ ] Whether read-back content is trusted or delimited.
- [ ] What the agent is allowed to persist.

## Attack Scenario Template

> An attacker plants an instruction (or exfiltration payload) that the agent
> writes to [persistent/shared] memory. Because [file:line] reads that memory back
> as trusted context [into the same user's future sessions / into other users'
> contexts], the injection re-fires later, resulting in [durable behavior override
> / delayed exfiltration / cross-user poisoning].

## Graph Mapping Instructions

- Ensure a `component:agent_memory` node with an `enables` edge to
  `component:llm_boundary` and a `depends_on` edge to `component:authorization`.
- Cross-user findings note the cross-tenant persistence class in `reasoning`.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:agent_memory`; cross-link to prompt_injection.
