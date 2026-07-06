---
id: technology.ai_ml.training_pipeline_security
title: "ML: Training & MLOps Pipeline Security"
category: technology
vulnerabilityClass: mlops_security
appliesToStack: ML training/fine-tuning pipelines, notebooks, and model registries
requiresAnyTag: ["ml-model"]
deepOnly: true
reviewPass: 3
owaspRefs:
  - "OWASP LLM03:2025 Supply Chain"
  - "A05:2021 Security Misconfiguration"
cweRefs:
  - "CWE-522"
  - "CWE-16"
  - "CWE-798"
realWorldReferences:
  - title: "Exposed Jupyter notebooks abused for cryptomining and data theft (unauthenticated notebook servers)"
    url: "https://www.aquasec.com/blog/threat-alert-attackers-exploiting-jupyter-notebooks/"
    type: research_paper
  - title: "MLflow / model registry path traversal and unauthenticated access (CVE-2023-6014 class)"
    url: "https://github.com/advisories/GHSA-83fm-w79m-64r5"
    type: vendor_security_advisory
  - title: "Secrets in notebooks and ML pipelines — hardcoded cloud/data credentials in shared training code"
    url: "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
    type: security_blog
quickModeSummary: >
  Training/MLOps pipelines are production infrastructure with production
  credentials, but they're often built like scratch work. Check for: secrets
  (cloud keys, data-warehouse creds, hub tokens) hardcoded in notebooks/training
  scripts/configs; exposed or unauthenticated services (Jupyter, MLflow/model
  registry, experiment trackers) reachable beyond the intended network; the
  pipeline pulling untrusted code/models/datasets and executing them (compounds
  with model_supply_chain/model_deserialization); pipeline credentials that are
  over-broad (a single admin key across data, storage, and deploy); and the
  trained model or its artifacts being writable/replaceable by untrusted parties
  before deployment (model registry poisoning). Treat the pipeline as a
  high-value target: it has access to the training data, the credentials, and
  the path to production.
fileSelectionHint:
  roles: ["pipeline", "config", "notebook", "service", "infra"]
  matchImports: ["mlflow", "wandb", "transformers", "huggingface_hub", "torch", "tensorflow", "datasets"]
  matchAuthMapTags: ["ml-model"]
  maxFiles: 12
  priorityOrder: ["config", "pipeline", "notebook", "infra"]
severityHeuristics:
  critical:
    - "Cloud/data/hub credentials are hardcoded or committed in notebooks, training scripts, or pipeline configs (production access sitting in shared/versioned code)"
    - "An MLOps service (Jupyter, MLflow/model registry, experiment tracker) is exposed unauthenticated / beyond its intended network, granting access to code execution, training data, or the model registry"
  high:
    - "The pipeline pulls and executes untrusted code/models/datasets (trust_remote_code, pickle loads, unpinned artifacts) so a supply-chain artifact achieves code execution in an environment holding production credentials"
    - "The model registry / artifact store is writable by untrusted parties, allowing a poisoned model to be substituted before deployment (registry poisoning → production compromise)"
  medium:
    - "Pipeline credentials are over-broad (one key spanning data, storage, deploy) rather than least-privilege scoped per stage, enlarging blast radius of any compromise"
    - "Notebooks/experiment logs capture sensitive training data or secrets in outputs that are then shared/stored without protection"
  low:
    - "A pipeline with sourced secrets, authenticated/isolated services, pinned artifacts, and least-privilege credentials — residual hardening only; confirm the core controls before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:ml_pipeline"
  relatedNodeIds: ["component:secrets", "component:model_supply_chain"]
graphEdgeMapping:
  - relation: exposes
    from: "component:ml_pipeline"
    to: "component:secrets"
  - relation: depends_on
    from: "component:ml_pipeline"
    to: "component:model_supply_chain"
commonAiCodingMistakes:
  - "AI hardcodes cloud/data-warehouse/hub credentials directly in a training notebook or script ('for convenience') and commits it, leaking production access into shared, versioned code."
  - "AI stands up a Jupyter or MLflow server bound to a public interface with no auth, exposing arbitrary code execution and the training data/registry to anyone who finds it (the exposed-notebook cryptomining class)."
  - "AI has the pipeline pull models/datasets with trust_remote_code or pickle loads from unpinned sources, so a supply-chain artifact executes code in the credentialed pipeline environment."
  - "AI leaves the model registry/artifact bucket writable by broad principals, so a poisoned model can replace the legitimate one before deployment."
  - "AI uses one over-broad service credential across all pipeline stages instead of least-privilege per stage."
  - "AI leaves secrets/training data in notebook outputs or experiment logs that are then shared."
falsePositiveGuardrails:
  - "Do not flag pipelines that source secrets from a manager/env (not literals) and keep them out of committed code — confirm the credential origin before flagging."
  - "MLOps services that are authenticated and network-isolated (private network/VPC, not public) are correct — only exposed/unauthenticated services are the finding."
  - "Pinned, verified artifacts and safe loaders address the supply-chain exec concern (see model_supply_chain/model_deserialization) — don't double-count; report the pipeline-environment-and-credentials angle here."
  - "Least-privilege, per-stage credentials are correct even if verbose — only over-broad/shared keys are the finding."
  - "A registry/artifact store writable only by the authorized pipeline identity is correct — the concern is untrusted write access."
---

## Root Cause Explanation

An ML training pipeline is production infrastructure wearing a lab coat. It holds
the credentials to the data warehouse, the object storage, the model hub, and
often the deployment path — yet it is frequently assembled from notebooks and
scripts written with the informality of experiments: secrets pasted inline,
services stood up with default/no auth, artifacts pulled and executed without
pinning. That mismatch is the vulnerability. A pipeline compromise is not a lab
inconvenience; it is access to the training data, the production credentials, and
a route to swap the model that ships.

The recurring failures: **secrets in code** (cloud/data/hub keys hardcoded in
notebooks and configs, committed to shared repos), **exposed services**
(unauthenticated Jupyter/MLflow/experiment trackers reachable off-network — the
exact target of the notebook-cryptomining campaigns and MLflow CVEs),
**untrusted execution** (the pipeline pulling and running untrusted code/models/
datasets in a credentialed environment — see model_supply_chain and
model_deserialization), **over-broad credentials** (one admin key across all
stages), and **registry poisoning** (a writable model store letting an attacker
substitute a poisoned model pre-deploy). Treat the pipeline like the high-value
production system it is: source secrets, authenticate and isolate services, pin
and verify artifacts, scope credentials least-privilege per stage, and lock down
who can write the registry.

## Vulnerable Patterns

```python
# Secrets hardcoded in a committed notebook/script
AWS_KEY = "AKIA..."; HF_TOKEN = "hf_..."; DB_URL = "postgres://user:pass@warehouse/db"

# Exposed, unauthenticated MLOps service
mlflow.server(host="0.0.0.0")                        # registry + artifacts, no auth
# jupyter notebook --ip=0.0.0.0 --NotebookApp.token=''
```

Correct: sourced secrets, authenticated/isolated services, pinned artifacts,
scoped creds.

```python
HF_TOKEN = os.environ["HF_TOKEN"]                    # from a secrets manager
# MLflow/Jupyter behind auth on a private network; artifacts pinned & verified;
# per-stage least-privilege credentials.
```

## Data Flow Tracing Guide

1. Grep notebooks/scripts/configs for hardcoded credentials and connection
   strings.
2. Check how MLOps services (Jupyter, MLflow, trackers) are exposed and
   authenticated.
3. Check what the pipeline pulls and executes (untrusted code/models/datasets;
   cross-reference model_supply_chain/model_deserialization).
4. Assess credential scope (per-stage least privilege vs. one broad key).
5. Check write access to the model registry/artifact store.
6. Check notebook outputs/experiment logs for captured secrets/data.

## Evidence Checklist

- [ ] Hardcoded secrets in pipeline code, quoted (redacted).
- [ ] Exposed/unauthenticated MLOps services, quoted.
- [ ] Untrusted execution and its environment's credentials.
- [ ] Credential scope and registry write access.

## Attack Scenario Template

> An attacker [finds the exposed Jupyter/MLflow server / reads the committed
> notebook secret / plants a poisoned artifact the pipeline pulls]. Because
> [file:line] [exposes the service unauthenticated / hardcodes production
> credentials / executes untrusted artifacts in the credentialed pipeline], the
> attacker gains [code execution with production access / the credentials / the
> ability to ship a poisoned model], resulting in [production compromise].

## Graph Mapping Instructions

- Ensure a `component:ml_pipeline` node.
- Secret-in-code findings add an `exposes` edge to `component:secrets`.
- Untrusted-execution findings add a `depends_on` edge to
  `component:model_supply_chain` and cross-link accordingly.
- Registry-poisoning findings note the pre-deploy substitution path.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:ml_pipeline`.
