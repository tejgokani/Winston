---
id: technology.ai_ml.vector_store_security
title: "LLM: Vector Store & Embedding Infrastructure Security"
category: technology
vulnerabilityClass: vector_store_security
appliesToStack: applications using a vector database for embeddings
requiresAnyTag: ["vector-db"]
deepOnly: false
reviewPass: 2
owaspRefs:
  - "OWASP LLM08:2025 Vector and Embedding Weaknesses"
  - "A01:2021 Broken Access Control"
  - "A05:2021 Security Misconfiguration"
cweRefs:
  - "CWE-284"
  - "CWE-863"
  - "CWE-16"
realWorldReferences:
  - title: "OWASP Top 10 for LLM — Vector and Embedding Weaknesses"
    url: "https://genai.owasp.org/llmrisk/llm08-vector-and-embedding-weaknesses/"
    type: security_blog
  - title: "Exposed vector databases (unauthenticated Pinecone/Weaviate/Qdrant/Chroma endpoints) leaking embedded corpora"
    url: "https://www.trendmicro.com/en_us/research/24/f/exposed-vector-databases.html"
    type: research_paper
  - title: "Multi-tenant isolation pitfalls in shared vector indexes (namespace/collection misconfiguration)"
    url: "https://qdrant.tech/documentation/guides/security/"
    type: security_blog
quickModeSummary: >
  The vector database is a data store and needs data-store security, which is
  easy to forget because it feels like "just an index". Check that it is not
  exposed unauthenticated (a public endpoint / default no-auth), that
  multi-tenant separation uses real isolation (per-tenant namespaces/collections/
  API keys, not just a metadata field the query is supposed to filter on), that
  the embedding/query API isn't reachable directly by clients bypassing the
  app's authorization, that connection secrets aren't hardcoded, and that
  metadata stored alongside vectors (which often contains the raw source text
  and PII) is protected the same as the primary datastore. Also watch for
  writable indexes an attacker could poison or delete.
fileSelectionHint:
  roles: ["config", "service", "rag", "pipeline", "infra"]
  matchImports: ["pinecone-client", "@pinecone-database/pinecone", "weaviate-client", "chromadb", "qdrant-client"]
  matchAuthMapTags: ["vector-db"]
  maxFiles: 10
  priorityOrder: ["config", "infra", "service", "rag"]
severityHeuristics:
  critical:
    - "The vector store is exposed without authentication (public endpoint, default open access, no API key) so anyone can read the embedded corpus and its metadata (often the raw source text/PII)"
    - "Multi-tenant data shares one index with isolation enforced only by a query-time metadata filter that a client or a missing filter can bypass, allowing cross-tenant reads"
  high:
    - "Clients can call the vector store / embedding API directly (keys shipped to the browser/mobile, or an unauthenticated proxy) bypassing the app's authorization layer"
    - "Connection secrets/API keys for the vector store are hardcoded or committed, or the index is writable by untrusted parties (poisoning/deletion)"
  medium:
    - "Tenant separation uses namespaces/collections but they are provisioned or selected from client-supplied identifiers without server-side verification, risking a tenant selecting another's namespace"
    - "Metadata containing sensitive source text/PII is stored unprotected or over-retained beyond need"
  low:
    - "A single-tenant, network-isolated, authenticated vector store with secrets sourced from a manager — residual hardening only; confirm exposure and isolation before dismissing"
graphNodeMapping:
  primaryNodeType: data_store
  primaryNodeId: "component:vector_store"
  relatedNodeIds: ["component:authorization", "component:secrets"]
graphEdgeMapping:
  - relation: protects
    from: "component:authorization"
    to: "component:vector_store"
  - relation: stores
    from: "component:vector_store"
    to: "component:data_store"
commonAiCodingMistakes:
  - "AI stands up a local Chroma/Qdrant/Weaviate with default no-auth settings and exposes its port, so the whole embedded corpus (and the raw text in metadata) is readable by anyone who finds it — the exposed-vector-DB class."
  - "AI puts all tenants in one index and 'isolates' them with a `tenant_id` metadata filter, which fails open the moment a query forgets the filter or a client controls the value — real isolation needs separate namespaces/collections/keys."
  - "AI ships the vector store API key to the client (browser/mobile) for 'direct search', letting users query the entire index directly, bypassing app authorization."
  - "AI hardcodes the vector DB connection string/API key in source or commits it."
  - "AI stores the full source document text and PII in vector metadata and forgets it's now a second copy of sensitive data with weaker controls than the primary store."
  - "AI leaves the index publicly writable, so an attacker can inject poisoned vectors or delete the corpus."
falsePositiveGuardrails:
  - "Do not flag a vector store that requires authentication, is network-isolated (private network/VPC, not a public endpoint), and is only reached server-side — confirm the deployment before flagging exposure."
  - "Per-tenant namespaces/collections/API keys selected from the server-verified session identity are correct isolation — only shared-index-with-query-filter (or client-controlled namespace) is the finding."
  - "Server-side-only access (the app mediates all queries and enforces authorization) is correct even if a metadata filter is also used — the concern is direct client access or a missing server gate."
  - "Secrets sourced from env/secrets manager (not literals) are fine — only hardcoded/committed credentials are the finding."
---

## Root Cause Explanation

A vector database is a datastore holding embeddings and, almost always, the raw
source text and metadata alongside them — yet it is frequently treated as "just
an index" and deployed without the controls the primary datastore gets. The
result is three classic datastore failures in a new place: **exposure**
(unauthenticated or default-open endpoints — researchers have found many public
vector DBs leaking whole corpora), **weak multi-tenant isolation** (all tenants
in one index separated only by a query-time metadata filter that fails open if
the filter is dropped or client-controlled, instead of real per-tenant
namespaces/collections/keys), and **bypassable authorization** (shipping the
store's API key to clients so they query the index directly, around the app's
access checks).

Because the metadata typically contains the sensitive source text and PII, an
exposed or cross-tenant-readable vector store is a direct data breach. The fixes
are ordinary datastore hygiene applied deliberately: authenticate and
network-isolate the store, enforce tenant isolation with real separation keyed
to the server-verified identity, mediate all access server-side, source secrets
from a manager, and lock down write access.

## Vulnerable Patterns

```python
# Default no-auth local store, exposed
client = chromadb.HttpClient(host="0.0.0.0", port=8000)      # open to the network

# Shared index, isolation by a filter that can be dropped/spoofed
index.query(vector=v, top_k=5, filter={"tenant": req.tenant})  # client-supplied tenant
```

```ts
// Vector store key shipped to the browser → direct index access
const pinecone = new Pinecone({ apiKey: process.env.NEXT_PUBLIC_PINECONE_KEY });
```

Correct: authenticated + isolated store, server-verified namespace, server-side
access.

```python
index = client.namespace(session.tenant_id)                  # server-verified tenant
hits = index.query(vector=v, top_k=5)                        # isolated by namespace
```

## Data Flow Tracing Guide

1. Check the deployment: is the vector store authenticated and network-isolated,
   or exposed/default-open?
2. Check tenant isolation: real separation (namespace/collection/key) keyed to
   server-verified identity, or a shared index with a query filter?
3. Check who can call it: server-side only, or a client-held key / unauthenticated
   proxy?
4. Trace connection secrets to their origin (manager vs. hardcoded/committed).
5. Check what's in metadata (source text/PII) and its protection, and whether the
   index is writable by untrusted parties.

## Evidence Checklist

- [ ] The store configuration (auth, host/exposure), quoted.
- [ ] The isolation mechanism and whether it's keyed to server-verified identity.
- [ ] Where the store is called from (server vs. client) and key handling.
- [ ] What sensitive data lives in metadata.

## Attack Scenario Template

> An attacker [connects to the unauthenticated vector endpoint / supplies another
> tenant's id to the shared-index filter / uses the client-shipped API key].
> Because [file:line] [exposes the store without auth / isolates tenants only by a
> query filter / ships the key to the client], the attacker reads [the embedded
> corpus / another tenant's documents / the whole index], resulting in [data
> breach / cross-tenant disclosure].

## Graph Mapping Instructions

- Ensure a `component:vector_store` data_store node with a `protects` edge from
  `component:authorization`.
- Exposure/cross-tenant findings add an `exposes` edge to the underlying data;
  note the datastore-breach class.
- Hardcoded-secret findings add an `exposes` edge to `component:secrets`.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:vector_store`.
