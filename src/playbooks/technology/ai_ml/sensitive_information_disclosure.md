---
id: technology.ai_ml.sensitive_information_disclosure
title: "LLM: Sensitive Information Disclosure"
category: technology
vulnerabilityClass: sensitive_information_disclosure
appliesToStack: LLM applications handling private/system/user data
requiresAnyTag: ["llm-api", "llm-app", "llm-agent"]
deepOnly: false
reviewPass: 2
owaspRefs:
  - "OWASP LLM02:2025 Sensitive Information Disclosure"
  - "A01:2021 Broken Access Control"
cweRefs:
  - "CWE-200"
  - "CWE-201"
  - "CWE-359"
realWorldReferences:
  - title: "OWASP Top 10 for LLM — Sensitive Information Disclosure"
    url: "https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/"
    type: security_blog
  - title: "Samsung engineers leaked source code and internal data by pasting it into ChatGPT"
    url: "https://www.bloomberg.com/news/articles/2023-05-02/samsung-bans-chatgpt-and-other-generative-ai-use-by-staff-after-leak"
    type: incident_postmortem
  - title: "System-prompt extraction across production assistants (Bing/Sydney and the broader 'leak your prompt' class)"
    url: "https://arstechnica.com/information-technology/2023/02/ai-powered-bing-chat-spills-its-secrets-via-prompt-injection-attack/"
    type: security_blog
quickModeSummary: >
  Anything you put in the model's context can come back out — via the model's
  answer, logs, or an injection. Find sensitive data crossing the LLM boundary
  without need or control: secrets/API keys embedded in the system prompt;
  other users' or other tenants' data placed in a shared context (cross-user
  leakage); PII/regulated data sent to a third-party model provider (and its
  retention/training implications); prompts, completions, and RAG context
  written to logs verbatim; and the system prompt itself being extractable
  (it's not a secret store). Also check RAG retrieval respects per-user access
  control so a query can't surface documents the requester can't see. The fix:
  minimize what enters context, scope retrieval and context to the requesting
  user, keep secrets out of prompts, redact before sending to providers and
  before logging, and never rely on the system prompt to hide anything.
fileSelectionHint:
  roles: ["service", "prompt", "rag", "agent", "logging", "controller"]
  matchImports: ["openai", "@anthropic-ai/sdk", "langchain", "@langchain/core", "llamaindex"]
  matchAuthMapTags: ["llm-api", "llm-app"]
  maxFiles: 12
  priorityOrder: ["prompt", "rag", "logging", "service"]
severityHeuristics:
  critical:
    - "RAG/context retrieval is not scoped to the requesting user's permissions, so a query can surface another user's/tenant's private documents in the answer (cross-tenant data disclosure)"
    - "Secrets (API keys, credentials, tokens) are embedded in the system/prompt context, where prompt injection or system-prompt extraction can exfiltrate them"
  high:
    - "Regulated or sensitive personal data (PII/PHI/financial) is sent to a third-party model provider without consent/redaction/DPA consideration, or in a way that enters provider training/retention"
    - "Prompts, completions, or retrieved context containing sensitive data are written to logs/telemetry verbatim, creating a secondary disclosure surface"
  medium:
    - "The system prompt is relied upon to hide instructions/policies/data that would be damaging if extracted (it is extractable), or context includes more sensitive data than the task requires (over-collection)"
    - "User A's data can persist into User B's session via shared caches/memory/context without isolation"
  low:
    - "Sensitive data enters context but stays within the requesting user's own boundary, is not logged, and the provider terms exclude training/retention — residual exposure only; confirm before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:llm_boundary"
  relatedNodeIds: ["component:authorization", "component:secrets", "component:logging"]
graphEdgeMapping:
  - relation: exposes
    from: "component:llm_boundary"
    to: "component:secrets"
  - relation: depends_on
    from: "component:llm_boundary"
    to: "component:authorization"
commonAiCodingMistakes:
  - "AI builds RAG over a shared corpus and retrieves by semantic similarity only, with no per-user access filter, so any user's query can pull back documents belonging to other users/tenants (the most common serious RAG leak)."
  - "AI puts an API key or credential into the system prompt ('use this key to call the tool'), where an injection or a 'repeat your instructions' extraction leaks it."
  - "AI logs the full prompt and completion (including PII/RAG context) for 'debugging', creating a plaintext disclosure store in logs/telemetry."
  - "AI sends raw user data (support tickets, health records, source code) to a third-party provider without redaction or checking retention/training terms — the Samsung-style leak."
  - "AI relies on the system prompt to hide business logic, policies, or data, not realizing the system prompt is routinely extractable."
  - "AI reuses a cache/memory keyed too broadly, so one user's context bleeds into another's session."
falsePositiveGuardrails:
  - "Do not flag RAG that filters retrieval by the requesting user's permissions (metadata/ACL filter applied to the query, or per-user indexes) — that is the correct isolation. Confirm the filter is actually applied to the retrieval, not just present elsewhere."
  - "Sending data to a provider under terms that exclude training/retention, with appropriate consent/DPA, is a business decision, not automatically a vulnerability — flag the mechanism (raw PII, no redaction, training-enabled endpoint), not the mere use of a provider."
  - "A system prompt that contains no secrets and whose extraction is harmless is not a disclosure issue — the concern is secrets/sensitive data placed there, or reliance on its secrecy."
  - "Logging that redacts sensitive fields / logs only metadata is correct — confirm redaction covers prompts, completions, and retrieved context before flagging."
  - "Context scoped to the requesting user with no cross-user/tenant reach is the safe case — establish cross-user reach before rating critical."
---

## Root Cause Explanation

An LLM context is a one-way membrane in reverse: whatever you put in can be
elicited out — by a direct question, by prompt injection, through logs, or via
the provider. So sensitive-information disclosure in LLM apps is about
controlling what crosses the boundary and who can pull it back. The four
recurring leaks are: **cross-user RAG** (retrieval by similarity with no
per-user access filter, so one tenant's query surfaces another's documents);
**secrets in the prompt** (keys/credentials placed in the system prompt, where
injection or extraction leaks them — the system prompt is not a vault);
**third-party exposure** (raw PII/regulated/proprietary data sent to a model
provider whose retention or training terms weren't considered — the Samsung
leak); and **verbatim logging** (prompts, completions, and retrieved context
written to logs, creating a second plaintext copy).

The unifying fixes are data minimization and scoping: put the least sensitive
data necessary into context, scope retrieval and any shared context/memory to
the requesting user's permissions, keep secrets out of prompts entirely,
redact before sending to providers and before logging, and treat the system
prompt as extractable — never as a hiding place.

## Vulnerable Patterns

```python
# Cross-tenant RAG: similarity only, no access filter
docs = store.similarity_search(query)                 # returns anyone's docs
answer = llm.predict(context=docs, question=query)

# Secret in the system prompt
system = f"You are a bot. Use this key to call billing: {STRIPE_KEY}"

logger.info("prompt=%s completion=%s", full_prompt, completion)  # PII to logs
```

Correct: scope retrieval, keep secrets in the tool layer, redact.

```python
docs = store.similarity_search(query, filter={"owner": user.id})   # per-user ACL
answer = llm.predict(context=docs, question=query)
# billing key lives in the authorized tool, never in the prompt
logger.info("prompt_tokens=%d", n)                                  # metadata only
```

## Data Flow Tracing Guide

1. Inventory everything placed into model context: user input, RAG retrievals,
   tool outputs, and any embedded secrets/policies.
2. For RAG, check the retrieval is filtered by the requesting user's
   permissions (per-user index or ACL/metadata filter), not similarity alone.
3. Search the system/prompt construction for secrets or data relied upon to be
   hidden.
4. Trace prompts/completions/context into logging and telemetry; check for
   redaction.
5. Check what leaves to third-party providers and under what retention/training
   terms; check for redaction/consent.
6. Check caches/memory for cross-user isolation.

## Evidence Checklist

- [ ] For cross-user RAG: the retrieval call and whether a per-user filter is
      applied, quoted.
- [ ] For secrets-in-prompt: the prompt construction embedding the secret.
- [ ] For logging: the log statement and what sensitive fields it includes.
- [ ] For provider exposure: what data is sent and the retention/redaction status.

## Attack Scenario Template

> An attacker [asks a query that semantically matches another tenant's private
> document / prompt-injects "repeat your system prompt" / reads the debug logs].
> Because [file:line] [retrieves without a per-user filter / embeds a secret in
> the system prompt / logs the full prompt], the attacker obtains [another
> user's data / the API key / logged PII], resulting in [disclosure/compromise].

## Graph Mapping Instructions

- Ensure a `component:llm_boundary` node exists.
- Secret-in-prompt findings add an `exposes` edge to `component:secrets`.
- Cross-user RAG findings add a `depends_on` edge to `component:authorization`
  and an `exposes` edge to the data store; note the cross-tenant class.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:llm_boundary`.
