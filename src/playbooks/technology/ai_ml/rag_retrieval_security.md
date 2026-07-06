---
id: technology.ai_ml.rag_retrieval_security
title: "LLM: RAG & Retrieval Security"
category: technology
vulnerabilityClass: rag_security
appliesToStack: retrieval-augmented generation over a document corpus / vector store
requiresAnyTag: ["vector-db", "llm-app"]
deepOnly: false
reviewPass: 2
owaspRefs:
  - "OWASP LLM08:2025 Vector and Embedding Weaknesses"
  - "A01:2021 Broken Access Control"
cweRefs:
  - "CWE-863"
  - "CWE-94"
  - "CWE-200"
realWorldReferences:
  - title: "OWASP Top 10 for LLM — Vector and Embedding Weaknesses (RAG access control, poisoning, leakage)"
    url: "https://genai.owasp.org/llmrisk/llm08-vector-and-embedding-weaknesses/"
    type: security_blog
  - title: "NVIDIA AI Red Team — indirect prompt injection through poisoned RAG documents"
    url: "https://developer.nvidia.com/blog/securing-llm-systems-against-prompt-injection/"
    type: research_paper
  - title: "Data-exfiltration and cross-tenant leakage in RAG when retrieval ignores per-user ACLs (Embrace the Red)"
    url: "https://embracethered.com/blog/posts/2024/whats-the-worst-that-could-happen-rag/"
    type: security_blog
quickModeSummary: >
  RAG has two security jobs the happy path skips: (1) retrieval must respect the
  requesting user's access — filtering by semantic similarity alone lets a query
  surface documents the user isn't allowed to see (cross-tenant/cross-user
  leakage), and (2) retrieved content is untrusted and can carry injected
  instructions (indirect prompt injection) or be deliberately poisoned to bias
  answers. Check that every retrieval is scoped by an ACL/metadata filter tied
  to the caller (or per-user indexes), that ingested documents are treated as
  data not instructions (delimited, provenance-marked — see prompt_injection),
  and that the ingestion pipeline validates/authenticates its sources so an
  attacker can't plant poisoned documents. Also confirm citations/sources
  returned to the user don't leak document existence or content they can't
  access.
fileSelectionHint:
  roles: ["rag", "service", "pipeline", "controller", "ingestion"]
  matchImports: ["langchain", "@langchain/core", "llamaindex", "llama-index", "pinecone-client", "@pinecone-database/pinecone", "weaviate-client", "chromadb", "qdrant-client"]
  matchAuthMapTags: ["vector-db", "llm-app"]
  maxFiles: 12
  priorityOrder: ["rag", "ingestion", "pipeline", "service"]
severityHeuristics:
  critical:
    - "Retrieval is not filtered by the requesting user's permissions, so a crafted query can return another user's/tenant's private documents into the answer or citations (cross-tenant disclosure)"
  high:
    - "The RAG corpus ingests documents from a source an attacker can influence (user uploads, crawled web, shared drives, emails) with no provenance/trust marking, enabling indirect prompt injection or answer poisoning through retrieved content"
    - "Returned citations/sources reveal the existence or content of documents the requester is not authorized to see (metadata leakage even when the body is withheld)"
  medium:
    - "Retrieval is scoped but the filter is applied in application code after an unfiltered vector query (documents briefly leave the trust boundary / could be mis-filtered), or the ingestion source is semi-trusted without validation"
    - "No relevance/authenticity checks on retrieved chunks, so poisoned or low-quality documents can dominate answers without detection"
  low:
    - "RAG over a fully public, read-only corpus with no per-user data and injection handled at the prompt boundary — residual risk only; confirm no private data is in the index"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:rag_retrieval"
  relatedNodeIds: ["component:authorization", "component:llm_boundary", "component:data_store"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:rag_retrieval"
    to: "component:authorization"
  - relation: enables
    from: "component:rag_retrieval"
    to: "component:llm_boundary"
commonAiCodingMistakes:
  - "AI implements 'chat with your documents' over a shared index and retrieves with `similarity_search(query)` alone — no per-user filter — so any user's query can pull back and cite documents belonging to others. The most common serious RAG bug."
  - "AI ingests documents from user uploads, crawled pages, or shared inboxes into the same corpus the assistant trusts, letting an attacker plant a document with hidden instructions (indirect injection) or false 'facts' (poisoning)."
  - "AI applies the access filter in application code AFTER an unfiltered vector query, so the raw matches (including forbidden docs) are fetched and could be logged or mis-handled before filtering."
  - "AI returns source citations that name or excerpt documents the requester can't access, leaking their existence/content even when the answer is withheld."
  - "AI treats retrieved chunks as authoritative and lets them override the system instructions, so a single poisoned/injected chunk steers the answer."
falsePositiveGuardrails:
  - "Do not flag retrieval that applies a per-user/tenant ACL or metadata filter as part of the vector query (or uses per-user indexes) — confirm the filter is pushed into the query and matches the caller's identity, not applied loosely afterward."
  - "RAG over a genuinely public, read-only corpus with no private/per-user documents has no cross-tenant surface — establish that the index contains no restricted data before dismissing."
  - "An ingestion pipeline that authenticates/validates its sources and marks provenance (so retrieved content is handled as untrusted data, delimited at the prompt) is the correct pattern — the residual injection risk is covered by prompt_injection handling."
  - "Citations restricted to documents the requester is authorized for are not leakage — confirm the citation set is filtered by the same ACL as retrieval."
---

## Root Cause Explanation

Retrieval-augmented generation bolts a search engine onto an LLM, and it
inherits both a search-engine problem and an injection problem. The search
problem is **authorization**: a vector store returns the nearest neighbors to a
query embedding, and "nearest" has nothing to do with "allowed." Unless the
retrieval is filtered by the requesting user's permissions, a query can surface
— and the model can quote — documents belonging to other users or tenants. This
is the dominant serious RAG vulnerability, and it hides because the happy-path
demo (one user, one corpus) never exercises it.

The injection problem is that **retrieved content is untrusted**. Any document
that can enter the corpus — a user upload, a crawled web page, a shared drive, an
email the assistant reads — can carry instructions the model will follow
(indirect prompt injection) or false facts crafted to bias answers (poisoning).
So RAG security is: scope every retrieval to the caller's access (ACL/metadata
filter pushed into the query, or per-user indexes), validate and mark the
provenance of ingested documents, treat retrieved text as delimited data rather
than instructions, and ensure citations never reveal documents the requester
can't see.

## Vulnerable Patterns

```python
# Cross-tenant retrieval: similarity only
hits = index.query(vector=embed(q), top_k=5)                 # returns anyone's docs
answer = llm.predict(context=hits, question=q)

# Poisonable ingestion: untrusted uploads into the trusted corpus, no provenance
for doc in user_uploads + crawl(web):
    index.upsert(embed(doc), metadata={"text": doc})         # attacker can plant instructions
```

Correct: filter retrieval by the caller, validate/mark ingestion, delimit.

```python
hits = index.query(vector=embed(q), top_k=5,
                   filter={"owner": user.id})                 # per-user ACL in the query
answer = llm.predict(
  context=[f"<untrusted_doc src={h.src}>{h.text}</untrusted_doc>" for h in hits],
  question=q)
```

## Data Flow Tracing Guide

1. Find every retrieval/query call and check for a caller-scoped filter (owner/
   tenant/ACL) pushed into the query, or per-user indexes.
2. Trace the ingestion pipeline: what sources feed the corpus, and can an
   attacker get a document in? Is provenance recorded and validated?
3. Check how retrieved content is placed in the prompt (delimited data vs.
   trusted instructions) — cross-reference prompt_injection.
4. Check citations/sources returned to the user against the same ACL.
5. Note whether filtering happens in the query (correct) or after an unfiltered
   fetch (leaky).

## Evidence Checklist

- [ ] The retrieval call and its access filter (or its absence), quoted.
- [ ] The ingestion sources and any provenance/validation, quoted.
- [ ] How retrieved text enters the prompt (data vs. instructions).
- [ ] Whether citations are ACL-filtered.

## Attack Scenario Template

> An attacker [issues a query engineered to match another tenant's private
> document / uploads a document containing hidden instructions]. Because
> [file:line] retrieves by similarity with no per-user filter / ingests
> untrusted documents into the trusted corpus, the model [quotes another user's
> data in its answer/citations / follows the injected instructions], resulting
> in [cross-tenant disclosure / answer manipulation / indirect injection].

## Graph Mapping Instructions

- Ensure a `component:rag_retrieval` node with a `depends_on` edge to
  `component:authorization`.
- Cross-tenant findings add an `exposes` edge to `component:data_store`; note the
  cross-tenant class in `reasoning`.
- Poisoning/injection-via-RAG findings add an `enables` edge to
  `component:llm_boundary` and cross-reference the prompt_injection finding.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:rag_retrieval`.
