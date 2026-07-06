---
id: technology.ai_ml.model_supply_chain
title: "ML: Model & Data Supply Chain"
category: technology
vulnerabilityClass: supply_chain
appliesToStack: apps pulling models/datasets from hubs or third parties
requiresAnyTag: ["ml-model"]
deepOnly: false
reviewPass: 2
owaspRefs:
  - "OWASP LLM03:2025 Supply Chain"
  - "A08:2021 Software and Data Integrity Failures"
cweRefs:
  - "CWE-1357"
  - "CWE-494"
  - "CWE-829"
realWorldReferences:
  - title: "JFrog — malicious models on Hugging Face with silent backdoors (supply-chain compromise via model hubs)"
    url: "https://jfrog.com/blog/data-scientists-targeted-by-malicious-hugging-face-ml-models-with-silent-backdoor/"
    type: research_paper
  - title: "Hugging Face — model/dataset provenance, signing, and malware scanning; pinning revisions"
    url: "https://huggingface.co/docs/hub/security"
    type: vendor_security_advisory
  - title: "'Sleepy Pickle' and model-level backdoors that survive standard evaluation"
    url: "https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/"
    type: research_paper
quickModeSummary: >
  Models, datasets, and their loaders are dependencies, and the ML hub ecosystem
  is a live supply-chain attack surface (thousands of malicious models found on
  public hubs). Check that third-party models/datasets are pinned to an exact
  revision/hash (not a mutable name or `latest`), verified by checksum/signature
  before use, and pulled from trusted sources — a typosquatted or hijacked model
  name silently swaps in a backdoor. Confirm artifacts are loaded via safe
  formats/scanning (see model_deserialization for the pickle-RCE half), that
  `from_pretrained`/download calls specify a revision, that datasets used for
  fine-tuning are trusted/validated (poisoning), and that the ML dependency
  chain (transformers/torch versions, custom `trust_remote_code`) isn't pulling
  and executing remote code. `trust_remote_code=True` in particular executes
  arbitrary repo code on load.
fileSelectionHint:
  roles: ["service", "pipeline", "loader", "config", "model"]
  matchImports: ["transformers", "huggingface_hub", "torch", "tensorflow", "datasets", "onnxruntime"]
  matchAuthMapTags: ["ml-model"]
  maxFiles: 10
  priorityOrder: ["loader", "pipeline", "config", "model"]
severityHeuristics:
  critical:
    - "A model is loaded with `trust_remote_code=True` (or an equivalent that executes repository-provided code) from a source that is not fully trusted and pinned — arbitrary code execution from the model repo on load"
    - "A third-party model/dataset is pulled by mutable name/`latest` with no revision pin and no integrity verification, so a hub-side compromise, hijack, or typosquat swaps in a backdoored artifact that the app then runs/trusts"
  high:
    - "Models/artifacts are downloaded from public hubs without provenance/signature verification or malware scanning before use, or from an unpinned/untrusted source (cross-reference model_deserialization for the pickle-exec risk)"
    - "Fine-tuning/training consumes third-party datasets with no validation or trust basis, enabling data poisoning that backdoors the resulting model"
  medium:
    - "Models are pinned to a revision but not integrity-verified (no checksum/signature), or the ML dependency versions themselves are unpinned, leaving a smaller but real supply-chain window"
    - "Model provenance is trusted-by-default with no policy (allow-list of sources/orgs) governing what may be pulled"
  low:
    - "Models/datasets are first-party or from a vetted, pinned, verified source with safe loaders — residual only; confirm pinning and verification before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:model_supply_chain"
  relatedNodeIds: ["component:model_loading", "component:remote_code_execution"]
graphEdgeMapping:
  - relation: causes
    from: "component:model_supply_chain"
    to: "component:remote_code_execution"
commonAiCodingMistakes:
  - "AI calls `AutoModel.from_pretrained('some/model', trust_remote_code=True)` to load a model that needs custom code, not registering that this executes arbitrary Python from the model repo on load — a backdoored or hijacked repo achieves RCE."
  - "AI pulls a model/dataset by bare name with no `revision=` pin, so the artifact it gets can change under it (hub compromise, force-push, typosquat) — the JFrog malicious-model class."
  - "AI downloads models from a hub and uses them with no signature/checksum verification or malware scan, trusting the hub implicitly."
  - "AI fine-tunes on a scraped or third-party dataset with no validation, letting poisoned training data backdoor the model."
  - "AI leaves transformers/torch and other ML deps unpinned, widening the dependency supply-chain window (compounds with the general dependency_supply_chain playbook)."
  - "AI typos a popular model/org name and pulls a lookalike (model-name squatting)."
falsePositiveGuardrails:
  - "Do not flag `trust_remote_code=True` when the source is a fully-trusted, pinned first-party or vetted repo at an exact revision — confirm the source trust and pin; the flag is dangerous specifically with untrusted/unpinned sources."
  - "Models pulled with an exact `revision=` pin AND checksum/signature verification before use are the correct pattern — only unpinned/unverified pulls are the finding."
  - "First-party models/datasets produced and controlled by the same org are not third-party supply chain — establish external provenance before flagging."
  - "Cross-reference model_deserialization for the load-time pickle-RCE and dependency_supply_chain for package typosquatting; report the model/dataset-provenance gap here without double-counting."
---

## Root Cause Explanation

Machine-learning apps depend on artifacts — pretrained models, datasets,
tokenizers — that are pulled from public hubs at least as casually as npm
packages, and the hub ecosystem has become an active supply-chain battlefield:
researchers have catalogued thousands of malicious models carrying backdoors. An
ML artifact is a dependency, and it deserves the same supply-chain discipline as
code: **pin** to an exact revision/hash rather than a mutable name or `latest`,
**verify** integrity (checksum/signature) before use, pull only from **trusted**
sources under a policy, and **scan** artifacts. Skip these and a hub compromise,
a hijacked or force-pushed repo, or a typosquatted model name silently substitutes
a backdoored artifact that your app then loads and trusts.

The sharpest edge is `trust_remote_code=True` (and equivalents): it executes
arbitrary Python shipped in the model repository at load time, so an untrusted or
unpinned source with that flag is direct remote code execution. The other edges
are load-time pickle execution (see model_deserialization) and **data poisoning**
— fine-tuning on untrusted datasets can implant backdoors that survive normal
evaluation. Treat models and datasets as untrusted inputs until pinned, verified,
and sourced from somewhere you trust.

## Vulnerable Patterns

```python
# Executes arbitrary repo code on load
m = AutoModel.from_pretrained("random/model", trust_remote_code=True)

# Mutable, unverified pull — swappable under you
m = AutoModel.from_pretrained("some-org/model")        # no revision=, no checksum

ds = load_dataset("scraped/data")                      # untrusted training data → poisoning
```

Correct: pin, verify, trust policy, safe formats.

```python
m = AutoModel.from_pretrained(
    "some-org/model",
    revision="a1b2c3d4",            # exact commit pin
    # verify a known-good checksum/signature before/after download; avoid trust_remote_code
)
```

## Data Flow Tracing Guide

1. Find every model/dataset pull (`from_pretrained`, `hf_hub_download`,
   `load_dataset`, direct URLs) and check for an exact revision pin.
2. Check for integrity verification (checksum/signature) and a source-trust
   policy (allow-listed orgs/sources).
3. Flag any `trust_remote_code=True` and assess the source's trust + pin.
4. For fine-tuning, check dataset provenance and validation (poisoning).
5. Cross-reference model_deserialization (load-time exec) and
   dependency_supply_chain (package typosquatting).

## Evidence Checklist

- [ ] The pull call with (or without) a revision pin, quoted.
- [ ] Integrity verification present or absent.
- [ ] Any `trust_remote_code=True` and the source's trust/pin status.
- [ ] Dataset provenance for any fine-tuning.

## Attack Scenario Template

> An attacker [publishes a backdoored model under a typosquatted/hijacked name /
> compromises the hub repo the app pulls]. Because [file:line] pulls it [by
> mutable name with no pin / with trust_remote_code=True / without verification],
> the app [executes the repo's code on load / runs a backdoored model], resulting
> in [RCE / a compromised/backdoored model in production].

## Graph Mapping Instructions

- Ensure a `component:model_supply_chain` node.
- `trust_remote_code`/exec findings add a `causes` edge to
  `component:remote_code_execution`.
- Note the pinning/verification gap in `reasoning`; cross-link to any
  model_deserialization finding on the same load.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:model_supply_chain`.
