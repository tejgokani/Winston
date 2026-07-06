---
id: technology.ai_ml.model_deserialization
title: "ML: Unsafe Model/Artifact Deserialization"
category: technology
vulnerabilityClass: unsafe_deserialization
appliesToStack: apps that load ML models/artifacts (PyTorch, TF, scikit-learn, joblib, pickle)
requiresAnyTag: ["ml-model"]
deepOnly: false
reviewPass: 2
owaspRefs:
  - "OWASP LLM03:2025 Supply Chain"
  - "A08:2021 Software and Data Integrity Failures"
cweRefs:
  - "CWE-502"
  - "CWE-94"
realWorldReferences:
  - title: "Hugging Face — malicious pickle models executing code on load; the push to safetensors and the picklescan/model-scanning program"
    url: "https://huggingface.co/docs/hub/security-pickle"
    type: vendor_security_advisory
  - title: "JFrog / ReversingLabs — thousands of malicious ML models on public hubs abusing pickle __reduce__ for RCE"
    url: "https://jfrog.com/blog/data-scientists-targeted-by-malicious-hugging-face-ml-models-with-silent-backdoor/"
    type: research_paper
  - title: "PyTorch — torch.load executes arbitrary code with the default pickle module; weights_only guidance (CVE-2025-32434 class)"
    url: "https://github.com/pytorch/pytorch/security/advisories"
    type: vendor_security_advisory
  - title: "CVE-2019-20916 / long tail — Python pickle.load on untrusted data is remote code execution by design"
    url: "https://cwe.mitre.org/data/definitions/502.html"
    type: security_blog
quickModeSummary: >
  Loading an ML model or artifact from an untrusted or externally-sourced file
  is remote code execution when the format is pickle-based, because pickle runs
  arbitrary code on deserialization (via __reduce__). This covers
  `pickle.load`, `joblib.load`, `torch.load` (default pickle path, not
  weights_only=True), `numpy.load(allow_pickle=True)`, and scikit-learn/Keras
  artifacts saved as pickle. The attacker vector is a model downloaded from a
  hub, uploaded by a user, or pulled from a bucket — "just load the .pt/.pkl/
  .joblib" is a code-exec sink. Flag any load of a model/artifact whose
  provenance isn't fully trusted and pinned, especially from a hub or user
  upload. The fix: prefer non-executable formats (safetensors, ONNX with a safe
  loader), pass weights_only=True / allow_pickle=False, verify checksums/
  signatures, and scan artifacts before loading.
fileSelectionHint:
  roles: ["service", "model", "pipeline", "loader", "config"]
  matchImports: ["torch", "tensorflow", "sklearn", "scikit-learn", "joblib", "pickle", "numpy", "transformers", "huggingface_hub", "onnxruntime"]
  matchAuthMapTags: ["ml-model"]
  maxFiles: 10
  priorityOrder: ["loader", "pipeline", "model", "service"]
severityHeuristics:
  critical:
    - "A pickle-based load (pickle.load, joblib.load, torch.load without weights_only=True, numpy.load with allow_pickle=True, a Keras/sklearn pickle) is performed on a model/artifact whose source is a public hub, a user upload, a remote URL, or any not-fully-trusted origin — remote code execution on load"
  high:
    - "A pickle-based model load where the artifact is stored in shared/writable storage (a bucket, a mounted volume, a cache another process can write) such that an attacker who can write the file achieves code execution when it is next loaded"
  medium:
    - "A pickle-based load of an artifact from a source that is trusted today but not integrity-verified (no checksum/signature pinning), so a future compromise of that source (hub account takeover, MITM, cache poisoning) yields code execution — latent supply-chain exposure"
  low:
    - "A pickle-based load of an artifact generated and consumed entirely within the same trusted boundary (produced by this app, never externally sourced or externally writable) — lowest risk; confirm provenance and storage permissions before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:model_loading"
  relatedNodeIds: ["component:remote_code_execution", "component:secrets"]
graphEdgeMapping:
  - relation: causes
    from: "component:model_loading"
    to: "component:remote_code_execution"
commonAiCodingMistakes:
  - "AI writes `model = torch.load(path)` or `joblib.load(f)` to load a model downloaded from Hugging Face or a URL, not knowing the default path runs arbitrary code embedded in the file — a backdoored model on a hub achieves RCE on load (the JFrog/ReversingLabs finding)."
  - "AI accepts a user-uploaded model/artifact ('bring your own model') and loads it with pickle, handing any uploader code execution on the server."
  - "AI uses `numpy.load(path, allow_pickle=True)` or `pickle.load` on a cached/remote `.npy`/`.pkl`, treating a data file as inert when allow_pickle turns it into a code-exec sink."
  - "AI pulls a model by name from a hub without pinning a revision/hash, so a later hub-side compromise or typosquat silently swaps in a malicious artifact."
  - "AI stores model artifacts in a shared/writable bucket or cache and loads them with pickle, so anyone who can write the bucket gets code execution at load time."
  - "AI reaches for pickle because it's the default `save`/`load` in the ecosystem, unaware that safetensors/ONNX exist specifically to avoid executable deserialization."
falsePositiveGuardrails:
  - "Do not flag loads that use non-executable formats: safetensors (safe by design), ONNX via a safe runtime, or `torch.load(..., weights_only=True)` / `numpy.load(..., allow_pickle=False)`. These do not execute arbitrary code — confirm the actual flag/format."
  - "A pickle load of an artifact produced and consumed entirely inside the trusted boundary (this app generated it, it is not externally sourced and its storage is not attacker-writable) is low risk — verify provenance and that no external/user/hub input can reach that path."
  - "Integrity-verified loads (checksum/signature pinned to a known-good hash before load) materially reduce risk even for pickle — factor the verification in, and confirm it runs before the load."
  - "Do not assume every `torch.load`/`joblib.load` is critical — establish that the artifact's source is untrusted, externally writable, or unpinned. A fully-trusted, pinned, permissioned artifact is lower severity."
---

## Root Cause Explanation

Most of the ML ecosystem's default serialization is Python `pickle`, and
`pickle` is not a data format — it is a program. Deserializing a pickle executes
whatever the pickle's `__reduce__` methods say, so `pickle.load` on data an
attacker controls is remote code execution *by design*, not by bug. This is
inherited by `joblib.load`, `torch.load` (whose default loader is pickle-based
unless `weights_only=True`), `numpy.load(allow_pickle=True)`, and the pickle
save paths of scikit-learn and older Keras. The consequence: **loading a model
is a code-execution sink**, and the security of "load this .pt/.pkl/.joblib"
depends entirely on whether the file is trustworthy.

In an AI application the untrusted files arrive naturally: models downloaded
from public hubs (where researchers have planted thousands of backdoored pickle
models), artifacts uploaded by users ("bring your own model"), files pulled from
buckets or caches other processes can write, and dependencies fetched without a
pinned hash. Any of these turns model loading into RCE. The fixes are concrete:
prefer **non-executable formats** (safetensors is safe by construction; ONNX via
a safe runtime), pass `weights_only=True`/`allow_pickle=False` when you must use
the native loader, **verify integrity** (pin a revision and check a
checksum/signature before loading), scan artifacts (picklescan-style), and lock
down write access to artifact storage.

## Vulnerable Patterns

```python
import torch, joblib, pickle, numpy as np
model = torch.load("downloaded_model.pt")          # default pickle path → RCE
clf   = joblib.load(user_uploaded_file)            # user-controlled → RCE
obj   = pickle.load(open(cache_path, "rb"))        # cache poisoning → RCE
arr   = np.load(remote_npy, allow_pickle=True)     # data file as code sink
```

Correct: non-executable formats, safe flags, pinned + verified provenance.

```python
from safetensors.torch import load_file
weights = load_file("model.safetensors")            # no code execution

model = torch.load("model.pt", weights_only=True)   # weights only, no pickle exec
# or: verify a pinned sha256 before any load; pull hub models by exact revision.
```

## Data Flow Tracing Guide

1. Find every model/artifact load: `torch.load`, `joblib.load`, `pickle.load`,
   `numpy.load(allow_pickle=True)`, sklearn/Keras pickle loads, and hub
   `from_pretrained`/download calls.
2. For each, identify the artifact's source: this app's own trusted output, a
   public hub, a user upload, a remote URL, or shared/writable storage.
3. Determine the format/flags: pickle-based (executable) vs. safetensors/ONNX/
   weights_only/allow_pickle=False (non-executable).
4. Check integrity: is the source pinned to a revision and verified by
   checksum/signature before load, or loaded by mutable name/path?
5. Check storage permissions: can any other user/process write the artifact
   before it's loaded?

## Evidence Checklist

- [ ] The load call and the format/flags, quoted.
- [ ] The artifact's source (hub / upload / URL / bucket / own output) and
      whether it's trusted, established from the code.
- [ ] Integrity verification present or absent (pinned hash/revision/signature).
- [ ] Storage write-permissions if the artifact is on shared storage.

## Attack Scenario Template

> An attacker [publishes a backdoored model on the hub the app downloads from /
> uploads a crafted artifact / writes to the shared bucket the app loads from].
> When [file:line] loads it via [pickle-based loader] with no [safetensors/
> weights_only/integrity check], the artifact's embedded `__reduce__` executes,
> giving the attacker code execution on the server at load time, resulting in
> [full compromise].

## Graph Mapping Instructions

- Ensure a `component:model_loading` node exists.
- Add a `causes` edge from the finding node to a `component:remote_code_execution`
  node; flag the RCE-on-load class in `reasoning`.
- If the artifact source is a hub/upload, add an `enables`/`exposes` edge toward
  the external source component to capture the supply-chain path.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:model_loading`.
