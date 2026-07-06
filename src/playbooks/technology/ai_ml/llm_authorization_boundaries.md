---
id: technology.ai_ml.llm_authorization_boundaries
title: "LLM: Authorization & Data Boundaries"
category: technology
vulnerabilityClass: broken_access_control
appliesToStack: LLM applications that mediate access to data or actions across users
requiresAnyTag: ["llm-app", "llm-api", "llm-agent"]
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A01:2021 Broken Access Control"
  - "OWASP LLM06:2025 Excessive Agency"
cweRefs:
  - "CWE-862"
  - "CWE-639"
  - "CWE-863"
realWorldReferences:
  - title: "OWASP Top 10 for LLM — access control and data boundaries in LLM apps"
    url: "https://genai.owasp.org/llmrisk/llm06-excessive-agency/"
    type: security_blog
  - title: "Cross-user data leakage when an LLM backend fetches context with a shared/service identity instead of the caller's"
    url: "https://embracethered.com/blog/posts/2024/whats-the-worst-that-could-happen-rag/"
    type: security_blog
  - title: "OWASP API Security — Broken Object Level Authorization (BOLA), the shape most LLM data-access bugs take"
    url: "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
    type: security_blog
quickModeSummary: >
  The classic access-control question — does THIS user get to see/do THIS thing —
  is easy to lose when an LLM sits in the middle. Check that data the model
  fetches for a request is retrieved with the REQUESTING USER's authority (their
  identity/permissions), not a shared service/admin identity that can read
  everything (which turns any query into a cross-user leak). Check that the model
  is never the authorization decision-maker (see output_overreliance/
  excessive_agency): access and actions must be gated by deterministic checks
  against the caller's permissions, outside the model. Check tenant isolation
  across the whole LLM path — prompt context, retrieval, memory, caches, tools —
  so one user's data can't surface in another's session. The LLM is a text
  transformer in the middle of a request; the request's authorization rules still
  apply at every hop.
fileSelectionHint:
  roles: ["service", "controller", "route_handler", "agent", "rag", "auth"]
  matchImports: ["openai", "@anthropic-ai/sdk", "langchain", "@langchain/core", "llamaindex"]
  matchAuthMapTags: ["llm-app", "llm-api"]
  maxFiles: 12
  priorityOrder: ["auth", "controller", "rag", "agent"]
severityHeuristics:
  critical:
    - "The LLM backend fetches data/context (DB rows, documents, files, other records) with a shared service/admin identity rather than the requesting user's authority, so the model can be steered — or simply asked — to return data the user isn't authorized for (broken object/function-level authorization via the LLM)"
    - "Access or actions are authorized by the model's own judgment (the model decides who may see/do what) with no deterministic check against the caller's permissions"
  high:
    - "Tenant/user isolation is broken somewhere on the LLM path — shared prompt context, retrieval, memory, or cache keyed too broadly — allowing cross-user data exposure"
    - "Tool/function calls act with more authority than the requesting user has (shared credentials, unscoped identity), enabling privileged actions on their behalf"
  medium:
    - "Authorization is enforced at the app edge but the LLM sub-request (retrieval/tool) re-fetches with a broader identity, or object-level checks are inconsistent across LLM-mediated paths"
    - "The requesting user's identity is propagated but not consistently applied to every data hop the model triggers"
  low:
    - "Every data fetch and action on the LLM path uses the requesting user's scoped identity with deterministic authorization — the correct case; confirm identity propagation across all hops before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:authorization"
  relatedNodeIds: ["component:llm_boundary", "component:data_store"]
graphEdgeMapping:
  - relation: protects
    from: "component:authorization"
    to: "component:data_store"
  - relation: depends_on
    from: "component:llm_boundary"
    to: "component:authorization"
commonAiCodingMistakes:
  - "AI builds the LLM backend to fetch context/data with a single service or admin identity ('the assistant can read everything, then answers per user'), so the model — via injection or a direct request — can surface any user's data. Retrieval must run with the requesting user's authority."
  - "AI lets the model decide authorization ('only answer if this user owns the record') instead of enforcing it with a deterministic check against the caller's permissions outside the model — injectable and wrong-able (see output_overreliance)."
  - "AI keys prompt context, memory, or caches too broadly (per-org or global), so one user's data appears in another's session — cross-tenant leakage on the LLM path."
  - "AI propagates the user's identity at the edge but then triggers retrieval/tool calls that re-authenticate as a broad service account, dropping the caller's scope mid-request."
  - "AI gives tools a shared credential so LLM-triggered actions act with more authority than the requesting user holds (privilege escalation)."
  - "AI treats 'the model only returns what's relevant' as an access control, when relevance is not authorization."
falsePositiveGuardrails:
  - "Do not flag an LLM path where every data fetch and action runs with the requesting user's scoped identity and deterministic authorization is enforced outside the model — that is the correct architecture. Confirm the caller's identity is propagated to each hop (retrieval, tools, memory)."
  - "Authorization enforced by the app's own logic against the caller's permissions (with the model only transforming text) is correct — the concern is the model being the decision or a broad identity fetching data."
  - "Per-user/tenant scoping of context, retrieval, memory, and caches (keyed to server-verified identity) is correct isolation — only broad keying is the finding."
  - "Cross-reference sensitive_information_disclosure (RAG cross-user leakage), agent_excessive_agency (tool authority), and output_overreliance (model as decision) — report the identity/boundary-propagation angle here without double-counting the specific control already flagged elsewhere."
---

## Root Cause Explanation

Inserting an LLM into a request doesn't suspend the request's authorization
rules — but it makes them easy to lose, because the model feels like a single
trusted component that "just answers." Two errors follow. First, **identity
collapse**: the LLM backend fetches the data it needs (rows, documents, files)
using a *shared* service or admin identity that can read everything, then relies
on the model to only surface "relevant" results. But relevance is not
authorization, and the model can be injected or simply asked to return more — so
any query becomes a potential cross-user leak. The fix is to fetch with the
**requesting user's** authority at every hop, so the data layer itself refuses
what the user can't see (object-level authorization, the BOLA shape).

Second, **model-as-decider**: letting the model judge who may see or do what,
instead of enforcing it with deterministic checks against the caller's
permissions outside the model (cross-reference output_overreliance and
excessive_agency). Add the isolation dimension — prompt context, retrieval,
memory, caches, and tools must all be scoped to the server-verified user/tenant —
and the rule is simply: the LLM is a text transformer in the middle of an
authenticated request; the caller's identity and permissions must flow to, and be
enforced at, every data and action hop.

## Vulnerable Patterns

```ts
// Identity collapse: backend reads everything with a service identity
const ctx = await db.query("SELECT * FROM docs WHERE topic=$1", [topic], SERVICE_CONN);  // reads all users' docs
const answer = await llm.complete({ context: ctx, question });   // model "picks relevant" — not authz

// Model as the authorization decision
if ((await llm.complete(`may ${user} read ${docId}? yes/no`)).includes("yes")) return read(docId);
```

Correct: fetch with the caller's authority; authorize deterministically.

```ts
const ctx = await db.query(
  "SELECT * FROM docs WHERE topic=$1 AND owner_id=$2", [topic, session.user.id]);  // caller's scope
if (!authz.canRead(session.user, docId)) throw new Error("denied");                 // deterministic
```

## Data Flow Tracing Guide

1. For each data fetch the LLM path performs (direct queries, RAG retrieval, file
   reads, tool calls), check whose identity it uses — the requesting user's scoped
   identity, or a shared service/admin one.
2. Check that authorization decisions are made by deterministic app logic against
   the caller's permissions, not by the model.
3. Trace user identity propagation across every hop; flag places it collapses to
   a broad identity mid-request.
4. Check isolation of context, retrieval, memory, caches, and tool credentials
   (per-user/tenant vs. broad).
5. Cross-reference the RAG, agency, and overreliance playbooks for the specific
   sub-controls.

## Evidence Checklist

- [ ] Each LLM-path data fetch and the identity it uses, quoted.
- [ ] Whether authorization is deterministic (app logic) or model-decided.
- [ ] Identity propagation across hops (edge → retrieval → tools → memory).
- [ ] Isolation keying of context/memory/cache/tool credentials.

## Attack Scenario Template

> An authenticated user [asks for / injects a request for] data they don't own.
> Because [file:line] fetches context with [a shared service identity / lets the
> model decide access], the request returns [another user's/tenant's data], or an
> LLM-triggered [tool/action] executes with [broader authority than the user
> holds], resulting in [cross-user data disclosure / privileged action].

## Graph Mapping Instructions

- Ensure a `component:authorization` node with a `protects` edge to
  `component:data_store` and a `depends_on` edge from `component:llm_boundary`.
- Identity-collapse findings add an `exposes` edge to the over-read data store;
  note the BOLA/identity-collapse rationale in `reasoning`.
- Cross-link to sensitive_information_disclosure / agent_excessive_agency /
  output_overreliance rather than duplicating those controls.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:authorization`.
