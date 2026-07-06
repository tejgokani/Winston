---
id: technology.ai_ml.output_overreliance
title: "LLM: Overreliance on Model Output"
category: technology
vulnerabilityClass: overreliance
appliesToStack: apps that act on LLM output for security/correctness decisions
requiresAnyTag: ["llm-api", "llm-app", "llm-agent"]
deepOnly: true
reviewPass: 3
owaspRefs:
  - "OWASP LLM09:2025 Misinformation"
  - "A04:2021 Insecure Design"
cweRefs:
  - "CWE-1025"
  - "CWE-807"
realWorldReferences:
  - title: "OWASP Top 10 for LLM — Misinformation and overreliance on model output"
    url: "https://genai.owasp.org/llmrisk/llm09-misinformation/"
    type: security_blog
  - title: "Package hallucination / 'slopsquatting' — LLMs inventing dependency names attackers then register"
    url: "https://www.theregister.com/2024/03/28/ai_bots_hallucinate_software_packages/"
    type: research_paper
  - title: "Air Canada held liable for its chatbot's incorrect (hallucinated) policy statement"
    url: "https://www.bbc.com/travel/article/20240222-air-canada-chatbot-misinformation-what-travellers-should-know"
    type: incident_postmortem
quickModeSummary: >
  The security bug here is trusting model output as authoritative for a decision
  it can get wrong. Find places where LLM output is used, without human review or
  independent validation, to: make an access/authorization/eligibility decision;
  install/import a dependency the model named (hallucinated packages →
  slopsquatting supply-chain compromise); execute or commit generated code
  unreviewed; state facts/policy the business is bound by (the Air Canada case);
  or drive an automated action whose correctness matters. The model is a
  probabilistic component — its output must be validated, constrained, or
  human-checked before it becomes a decision or action with security/financial/
  legal weight. Flag automated reliance on unverified model output for
  consequential decisions.
fileSelectionHint:
  roles: ["service", "controller", "agent", "pipeline"]
  matchImports: ["openai", "@anthropic-ai/sdk", "langchain", "@langchain/core"]
  matchAuthMapTags: ["llm-api", "llm-app"]
  maxFiles: 10
  priorityOrder: ["controller", "agent", "service", "pipeline"]
severityHeuristics:
  critical:
    - "The model's output is used to make an authorization/access/eligibility decision (grant access, approve, verify identity) with no independent check — a wrong or injected output directly bypasses the control"
    - "Model-generated code or a model-named dependency is executed/installed automatically without review, enabling RCE or a slopsquatting supply-chain compromise (an attacker pre-registers the hallucinated package name)"
  high:
    - "The model's output drives a consequential automated action (financial, data mutation, external effect) with no validation or human-in-the-loop, so an incorrect/injected output causes real harm"
    - "The model states facts/policy the business is bound by to users with no grounding/verification, creating liability (the Air Canada class)"
  medium:
    - "Model output feeds a decision but with partial validation whose coverage is unclear, or reliance is high in a context where errors are recoverable but not cheap"
    - "Generated code is committed with review that is nominal (rubber-stamped) rather than meaningful"
  low:
    - "Model output is advisory only, clearly presented as AI-generated and unverified, and does not gate any consequential decision/action — the acceptable case; confirm no downstream automated reliance"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:business_logic"
  relatedNodeIds: ["component:authorization", "component:llm_boundary"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:business_logic"
    to: "component:llm_boundary"
commonAiCodingMistakes:
  - "AI wires model output into an authorization decision ('ask the model if this user is allowed') — a probabilistic, injectable component now gates access, and a wrong/injected answer bypasses the control."
  - "AI auto-installs or imports a dependency name the model produced, not accounting for package hallucination — attackers pre-register the invented names (slopsquatting), so following the model's suggestion pulls a malicious package."
  - "AI executes or auto-commits model-generated code without meaningful review, trusting it to be correct/safe."
  - "AI has the chatbot state policies/prices/eligibility as fact with no grounding, binding the business to hallucinated claims (Air Canada)."
  - "AI automates a financial or data-mutating action on the model's say-so with no validation or confirmation step."
  - "AI treats structured model output as guaranteed-valid and skips schema validation, so malformed/incorrect fields flow into decisions."
falsePositiveGuardrails:
  - "Do not flag model output that is advisory/informational and clearly does not gate a consequential decision or action — overreliance requires the output to DRIVE a security/financial/legal/correctness decision. Establish that dependency before flagging."
  - "Output that is independently validated (schema + business-rule checks, ground-truth lookup, deterministic verification) before it drives a decision is handled correctly — the control is the validation, confirm it covers the decision."
  - "Human-in-the-loop review for consequential actions (generated code reviewed, decisions confirmed) is a valid control — do not flag reliance when a meaningful review gate exists."
  - "Authorization decisions made by the application's own logic (not the model) with the model only summarizing are fine — the concern is the model BEING the decision."
  - "Cross-reference dependency_supply_chain for slopsquatting specifics; report the overreliance-on-output angle here without double-counting."
---

## Root Cause Explanation

An LLM is a probabilistic component: it produces plausible output, not
guaranteed-correct output, and it can be steered by injection. Overreliance is
the design flaw of treating that output as authoritative for a decision or action
where being wrong matters. The failure isn't that the model errs — it will — it's
that nothing between the model and the consequence catches the error. When model
output *is* the authorization decision, a wrong or injected answer bypasses the
control outright. When the app installs a dependency the model named, package
**hallucination** becomes a supply-chain attack: attackers pre-register the
invented names ("slopsquatting"), so faithfully following the suggestion pulls
malicious code. When generated code runs unreviewed, hallucinated output becomes
RCE. And when a chatbot states policy as fact, the business can be bound by it —
Air Canada was held liable for its bot's incorrect claim.

The fix is to keep the model out of the position of final authority for anything
consequential: validate output against schemas and business rules, ground factual
claims, verify or human-review generated code and named dependencies, and make
authorization/financial/data decisions with deterministic logic — using the model
to assist, not to decide.

## Vulnerable Patterns

```python
# Model as the authorization decision
if "yes" in llm.predict(f"Is user {u} allowed to access {r}?"):  # injectable, wrong-able
    grant(u, r)

# Auto-installing a model-named (possibly hallucinated) dependency
pkg = llm.predict("what package do I need?")
os.system(f"pip install {pkg}")                                   # slopsquatting

exec(llm.predict("write code to do X"))                          # unreviewed generated code
```

Correct: deterministic decisions, validation, review.

```python
if policy.is_allowed(u, r):            # app logic, not the model
    grant(u, r)
# dependencies chosen from a vetted allow-list; generated code reviewed before running
```

## Data Flow Tracing Guide

1. Find where model output feeds a decision or action; classify the consequence
   (authorization, dependency install, code exec, financial/data mutation, stated
   fact/policy).
2. For each consequential use, check for an independent gate: validation against
   ground truth/rules, human review, or deterministic logic making the actual
   decision.
3. Flag model output that directly gates access, installs dependencies, executes
   code, or binds the business with no such gate.
4. Cross-reference dependency_supply_chain (slopsquatting) and
   insecure_output_handling (execution sinks).

## Evidence Checklist

- [ ] The code where model output drives the decision/action, quoted.
- [ ] The consequence class (authz / dependency / code / financial / stated fact).
- [ ] The independent validation/review/deterministic gate present or absent.

## Attack Scenario Template

> [A wrong or injected model output occurs / the model hallucinates a package
> name an attacker has pre-registered]. Because [file:line] [uses the output as the
> authorization decision / auto-installs the named package / executes the generated
> code] with no independent check, the result is [access bypass / malicious
> dependency pulled / RCE / the business bound by a false claim].

## Graph Mapping Instructions

- Ensure a `component:business_logic` node with a `depends_on` edge to
  `component:llm_boundary`.
- Authorization-overreliance findings add a `depends_on` edge to
  `component:authorization` and note that the model is acting as the control.
- Slopsquatting/code-exec findings cross-link to dependency_supply_chain /
  insecure_output_handling.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:business_logic`.
