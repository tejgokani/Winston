---
id: technology.ai_ml.training_data_poisoning
title: "ML: Training Data Poisoning"
category: technology
vulnerabilityClass: data_poisoning
appliesToStack: apps that train/fine-tune models on collected or third-party data
requiresAnyTag: ["ml-model"]
deepOnly: true
reviewPass: 3
owaspRefs:
  - "OWASP LLM04:2025 Data and Model Poisoning"
  - "A08:2021 Software and Data Integrity Failures"
cweRefs:
  - "CWE-1395"
  - "CWE-20"
realWorldReferences:
  - title: "OWASP Top 10 for LLM — Data and Model Poisoning"
    url: "https://genai.owasp.org/llmrisk/llm04-data-and-model-poisoning/"
    type: security_blog
  - title: "'Poisoning the well' — practical web-scale data poisoning of training corpora (research)"
    url: "https://arxiv.org/abs/2302.10149"
    type: research_paper
  - title: "Backdoor attacks that implant triggers surviving normal evaluation (BadNets and successors)"
    url: "https://arxiv.org/abs/1708.06733"
    type: research_paper
quickModeSummary: >
  If your app trains or fine-tunes on data you collect (user submissions,
  feedback/RLHF signals, scraped web, third-party datasets), an attacker who can
  influence that data can poison the model — implanting backdoors (a trigger that
  causes chosen behavior), skewing outputs, or degrading safety — and poisoning
  can survive normal evaluation. Check whether training/fine-tuning data comes
  from sources an attacker can influence, whether that data is validated,
  provenance-tracked, and filtered before training, whether user feedback that
  updates the model can be gamed, and whether there's any detection (anomaly
  checks, holdout/backdoor testing) before a newly-trained model is promoted.
  The trust boundary is the training set; treat contributed/scraped data as
  untrusted input to the model's behavior.
fileSelectionHint:
  roles: ["pipeline", "service", "ingestion", "config"]
  matchImports: ["transformers", "datasets", "torch", "tensorflow", "huggingface_hub", "trl"]
  matchAuthMapTags: ["ml-model"]
  maxFiles: 10
  priorityOrder: ["ingestion", "pipeline", "config", "service"]
severityHeuristics:
  critical:
    - "Model training/fine-tuning consumes attacker-influenceable data (open user submissions, scraped web, unvetted third-party datasets) with no validation/provenance, AND the resulting model gates security or high-impact decisions — a backdoor/poison directly compromises those decisions"
  high:
    - "A continuous/online learning or RLHF loop updates the deployed model from user-provided signals that can be gamed, with no abuse controls, letting an attacker steer model behavior over time"
    - "Third-party or scraped training data is used with no provenance, validation, or filtering, enabling backdoors/bias that survive to production"
  medium:
    - "Training data is semi-trusted or partially validated, or a newly-trained model is promoted with no anomaly/backdoor/holdout testing to detect poisoning before deployment"
    - "User feedback influences ranking/behavior in a bounded way that is gameable but not model-altering"
  low:
    - "Training exclusively on first-party, controlled, validated data with promotion gated by evaluation — residual only; confirm data provenance and promotion gating before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:training_data"
  relatedNodeIds: ["component:ml_pipeline", "component:business_logic"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:business_logic"
    to: "component:training_data"
  - relation: enables
    from: "component:training_data"
    to: "component:ml_pipeline"
commonAiCodingMistakes:
  - "AI fine-tunes or continuously trains on open user submissions or scraped web data with no validation, so an attacker who contributes crafted data implants a backdoor trigger or skews behavior (the classic poisoning setup)."
  - "AI builds an online-learning/RLHF loop that updates the deployed model from user thumbs-up/down or corrections without abuse controls, letting coordinated users steer the model."
  - "AI pulls third-party datasets with no provenance or filtering and trusts them, inheriting any poisoning they carry."
  - "AI promotes a newly-trained model to production with only aggregate accuracy checks, which backdoors (designed to trigger only on a specific input) pass — no holdout/backdoor/anomaly testing."
  - "AI lets the same principal contribute training data and benefit from the model's decisions, creating an incentive and path to poison."
falsePositiveGuardrails:
  - "Do not flag training on first-party, controlled data that no external attacker can influence — establish that the training set includes attacker-influenceable data before flagging."
  - "Training data that is validated, provenance-tracked, and filtered (dedup, anomaly/outlier detection, trusted sources) before training is the correct control — confirm the filtering runs before training."
  - "A promotion gate with holdout/backdoor/anomaly testing before deploying a newly-trained model materially mitigates — factor it in."
  - "Bounded feedback that influences ranking/UX but does not alter the model weights is lower risk than a model-altering training loop — distinguish the two."
  - "Cross-reference model_supply_chain (third-party model/dataset provenance); report the poisoning-of-your-own-training-data angle here without double-counting."
---

## Root Cause Explanation

When an application learns from data it collects — user submissions, feedback and
RLHF signals, scraped web content, third-party datasets — the *training set
becomes an attack surface*. Data poisoning is the manipulation of that set to
change the model's behavior: implanting a **backdoor** (a specific trigger input
that causes attacker-chosen output, while the model behaves normally otherwise),
skewing outputs or rankings, or eroding safety. The insidious property, shown by
BadNets and a decade of successors, is that a well-crafted backdoor is designed
to be dormant on ordinary inputs, so it *passes standard accuracy evaluation* —
the model looks fine and ships poisoned.

The trust boundary is the data pipeline into training. The controls: establish
**provenance** and use trusted sources; **validate and filter** contributed/
scraped data (deduplication, outlier/anomaly detection, content checks) before it
trains anything; put **abuse controls** on any online-learning/RLHF loop so a
small set of users can't steer the model; and gate model **promotion** with
holdout and backdoor/anomaly testing, not just aggregate metrics. Where the model
then gates security or high-impact decisions, poisoning those decisions is the
critical outcome (cross-reference output_overreliance).

## Vulnerable Patterns

```python
# Fine-tuning on unvalidated attacker-influenceable data
data = collect_user_submissions() + scrape_web()      # attacker can contribute
model = finetune(base, data)                          # no validation/provenance → poisoning

# Online loop updating the deployed model from gameable feedback
on_feedback(lambda fb: update_model(fb))              # no abuse controls
```

Correct: provenance + validation/filtering + promotion gating.

```python
data = filter_and_validate(collect(), trusted_sources_only=True)   # provenance + filtering
candidate = finetune(base, data)
if passes_holdout_and_backdoor_tests(candidate):                   # promotion gate
    promote(candidate)
```

## Data Flow Tracing Guide

1. Identify all data that trains/fine-tunes/updates the model, and whether any of
   it is attacker-influenceable (open submissions, scraped, third-party).
2. Check for provenance tracking, validation, and filtering before training.
3. Check any online-learning/RLHF loop for abuse controls on the signals.
4. Check the model promotion gate for holdout/backdoor/anomaly testing.
5. Determine what the model decides downstream (blast radius of a poison).

## Evidence Checklist

- [ ] The training/fine-tuning data sources and their attacker-influenceability.
- [ ] Validation/provenance/filtering present or absent, quoted.
- [ ] Any online-update loop and its abuse controls.
- [ ] The promotion/evaluation gate and whether it can catch backdoors.

## Attack Scenario Template

> An attacker contributes crafted data [via open submissions / a scraped source /
> gamed feedback]. Because [file:line] trains on it with no [validation/provenance/
> promotion gating], the attacker implants [a backdoor trigger / skewed behavior]
> that survives evaluation and reaches production, resulting in [attacker-chosen
> model behavior gating decisions / degraded safety].

## Graph Mapping Instructions

- Ensure a `component:training_data` node with an `enables` edge to
  `component:ml_pipeline`.
- Where the poisoned model gates decisions, add a `depends_on` edge from
  `component:business_logic`; cross-link to output_overreliance.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:training_data`.
