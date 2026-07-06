---
id: technology.ai_ml.model_theft_extraction
title: "ML: Model Theft & Extraction"
category: technology
vulnerabilityClass: model_theft
appliesToStack: apps exposing a proprietary model via inference API or shipping it to clients
requiresAnyTag: ["ml-model"]
deepOnly: true
reviewPass: 3
owaspRefs:
  - "OWASP LLM10:2025 Unbounded Consumption"
  - "A04:2021 Insecure Design"
cweRefs:
  - "CWE-200"
  - "CWE-668"
realWorldReferences:
  - title: "OWASP Top 10 for LLM — model exfiltration / theft (unbounded consumption & extraction)"
    url: "https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/"
    type: security_blog
  - title: "Model extraction attacks — stealing a model's functionality via its prediction API"
    url: "https://arxiv.org/abs/1609.02943"
    type: research_paper
  - title: "Shipping model weights to the client (mobile/browser on-device models) exposes the proprietary artifact"
    url: "https://owasp.org/www-project-machine-learning-security-top-10/"
    type: security_blog
quickModeSummary: >
  A proprietary model is intellectual property and often trained on sensitive
  data; two exposures let attackers steal it. (1) Direct: the model file/weights
  are shipped to clients (bundled in a mobile/desktop app or browser) or stored
  where untrusted parties can read them, handing over the artifact. (2)
  Extraction: an inference API with no rate/quota limits lets an attacker query
  it enough to train a functional clone (model extraction), and rich responses
  (full logits/probabilities, verbose explanations) accelerate it. Check whether
  weights are exposed to clients or in a reachable store, whether the inference
  API is authenticated and rate/quota-limited, whether responses expose more than
  needed (raw logits/confidences), and whether abuse (systematic querying) is
  detectable. Treat the model as a protected asset behind the API, not a file to
  ship.
fileSelectionHint:
  roles: ["service", "controller", "config", "infra", "model"]
  matchImports: ["torch", "tensorflow", "onnxruntime", "transformers", "coreml", "tensorflowjs"]
  matchAuthMapTags: ["ml-model"]
  maxFiles: 10
  priorityOrder: ["service", "config", "infra", "model"]
severityHeuristics:
  critical:
    - "Proprietary model weights are shipped to clients (bundled in a mobile/desktop/browser app) or stored somewhere untrusted parties can read them, directly exposing the model artifact (and any sensitive data encoded in it)"
  high:
    - "A proprietary/high-value inference API has no authentication or no rate/quota limits, allowing systematic querying sufficient to extract (clone) the model's functionality"
    - "Inference responses expose more than the task requires — full logit/probability vectors, per-token confidences, or verbose rationales — materially accelerating extraction"
  medium:
    - "The inference API is authenticated and limited but lacks abuse detection for extraction-pattern querying, or the model store's access controls are weaker than the asset warrants"
    - "On-device models are shipped with only light obfuscation (no meaningful protection) where the model is genuinely proprietary"
  low:
    - "A public/open-weights model, or a proprietary model served behind an authenticated, rate-limited API returning minimal outputs — residual only; confirm the model's value and exposure before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:model_asset"
  relatedNodeIds: ["component:rate_limiting", "component:authorization"]
graphEdgeMapping:
  - relation: protects
    from: "component:rate_limiting"
    to: "component:model_asset"
  - relation: protects
    from: "component:authorization"
    to: "component:model_asset"
commonAiCodingMistakes:
  - "AI ships a proprietary model's weights inside a mobile/desktop app or a browser bundle (on-device inference) without recognizing that anything on the client is extractable — the model file is now the attacker's."
  - "AI exposes an inference API with no authentication or rate limiting for a valuable model, letting an attacker query at scale to train a functional clone (model extraction)."
  - "AI returns full probability/logit vectors or verbose reasoning in inference responses when the app only needs the top label, handing extractors a high-information signal that speeds cloning."
  - "AI stores model artifacts in a bucket/registry readable by broad principals, exposing the artifact to anyone with that access."
  - "AI relies on client-side obfuscation of a shipped model as if it were protection."
  - "AI has no monitoring for extraction-pattern querying (high-volume, systematic, boundary-probing requests)."
falsePositiveGuardrails:
  - "Do not flag open-weights/public models — there is no proprietary asset to steal. Establish that the model is genuinely proprietary/high-value before flagging."
  - "A proprietary model served behind an authenticated, rate/quota-limited API that returns only the minimal output the task needs is handled correctly — confirm auth, limits, and minimal responses."
  - "Model weights kept strictly server-side (never shipped to clients) under access controls matching the asset's value are correct — only client-shipped or broadly-readable weights are the direct-theft finding."
  - "Cross-reference llm_dos_and_cost for the rate-limiting control (extraction and denial-of-wallet share it) — report the theft/extraction angle here without double-counting the limit itself."
  - "On-device models that are intentionally open or low-value do not need weight protection — scope by the model's proprietary value."
---

## Root Cause Explanation

A trained model is often the most valuable and sensitive artifact a company owns:
it encodes expensive training and, frequently, information about its training
data. Two exposures let attackers take it. **Direct theft** is the simple one:
if the weights are shipped to clients (bundled into a mobile/desktop app or a
browser for on-device inference) or stored where untrusted parties can read them,
the artifact is simply *there* for the taking — client-side obfuscation is not
protection. **Extraction** is subtler: even when the model stays server-side, an
inference API that accepts unlimited queries can be systematically probed to
train a *functional clone* (model extraction), and the more each response reveals
— full logit/probability vectors, per-token confidences, verbose rationales — the
faster the clone converges.

So protecting the model means treating it as an asset behind the API, not a file
to distribute: keep weights server-side under access controls matching their
value; authenticate and **rate/quota-limit** the inference API (the same control
that bounds denial-of-wallet — see llm_dos_and_cost); return the **minimum**
output the task requires rather than rich probability signals; and monitor for
extraction-pattern querying.

## Vulnerable Patterns

```ts
// Weights shipped to the client (browser/mobile on-device) — direct theft
import model from "./proprietary_model.onnx";       // bundled into the app

// Unauthenticated, unlimited inference API returning rich signals — extraction
app.post("/infer", async (req, res) => {
  const { logits } = await model.forward(req.body.input);   // full logits, no auth/limit
  res.json({ logits });
});
```

Correct: server-side weights, authenticated + limited API, minimal output.

```ts
app.post("/infer", requireAuth, rateLimitPerUser, async (req, res) => {
  const { label } = await model.predict(req.body.input);    // minimal output
  res.json({ label });                                       // no raw logits
});
```

## Data Flow Tracing Guide

1. Determine whether the model is proprietary/high-value (else no asset to steal).
2. Check whether weights are shipped to clients (on-device bundles) or stored
   where untrusted parties can read them.
3. Check the inference API for authentication and rate/quota limits.
4. Check what responses reveal (top label vs. full logits/confidences/rationales).
5. Check for abuse/extraction-pattern monitoring and model-store access controls.

## Evidence Checklist

- [ ] The model's proprietary status, established.
- [ ] Whether weights reach clients or a broadly-readable store, quoted.
- [ ] Inference API auth and rate/quota limits.
- [ ] Response richness (minimal vs. logits/confidences).

## Attack Scenario Template

> An attacker [extracts the model file from the shipped app/bundle / queries the
> unauthenticated, unlimited inference API at scale using the returned logits].
> Because [file:line] [ships the weights to the client / serves a valuable model
> with no auth/rate limit and rich outputs], the attacker [obtains the artifact
> directly / trains a functional clone], resulting in theft of the proprietary
> model (and exposure of data it encodes).

## Graph Mapping Instructions

- Ensure a `component:model_asset` node protected by `component:rate_limiting`
  and `component:authorization`.
- Direct-theft findings add an `exposes` edge to the artifact/data it encodes.
- Extraction findings cross-link to llm_dos_and_cost (shared rate-limit control).
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:model_asset`.
