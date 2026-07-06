---
id: ai_security.ssti
title: Server-Side Template Injection (SSTI)
category: ai_security
vulnerabilityClass: ssti
appliesToStack: server-side templating engines (Jinja2, Twig, Freemarker, Velocity, Handlebars, Pug, EJS, ERB, Blade)
requiresAnyTag:
  - templating
  - flask
  - django
  - laravel
  - rails
  - java
  - express
  - nestjs
  - fastify
  - php
deepOnly: false
reviewPass: 3
owaspRefs:
  - "A03:2021 Injection"
cweRefs:
  - "CWE-1336"
  - "CWE-94"
  - "CWE-95"
realWorldReferences:
  - title: "PortSwigger — the original Server-Side Template Injection research (James Kettle) mapping engine → RCE"
    url: "https://portswigger.net/research/server-side-template-injection"
    type: research_paper
  - title: "Jinja2 SSTI to RCE via the object sandbox escape (`__class__.__mro__` / cycler gadget) — PortSwigger Web Security Academy labs"
    url: "https://portswigger.net/web-security/server-side-template-injection"
    type: security_blog
  - title: "Apache Freemarker / Velocity SSTI leading to RCE in real applications (bug-bounty class writeups)"
    url: "https://hackerone.com/reports/125980"
    type: bug_bounty_disclosure
  - title: "Handlebars / Node template-engine SSTI and prototype-pollution-to-RCE research"
    url: "https://mahmoudsec.blogspot.com/2019/04/handlebars-template-injection-and-rce.html"
    type: security_blog
quickModeSummary: >
  Find every place a template is rendered from a string that is built with, or
  chosen by, user input — as opposed to a fixed template file with user data
  passed as *context variables*. The dangerous shape is compiling/rendering a
  template whose text contains user input: `render_template_string(f"Hello
  {name}")`, `Template(userInput).render()`, `handlebars.compile(userInput)`,
  `new Function`-style eval templating, or passing user input as the template
  name/path. Because server-side template engines evaluate expressions (and in
  many engines can reach language internals), template injection escalates
  from reflected output to sandbox escape and remote code execution — far more
  severe than XSS. The safe pattern is always: fixed template, user data as
  bound context, autoescaping on. Flag any user input reaching the template
  *source* rather than the template *data*.
fileSelectionHint:
  roles: ["route_handler", "controller", "view", "template", "service", "mailer"]
  matchImports:
    ["jinja2", "flask", "django", "handlebars", "pug", "ejs", "nunjucks", "mustache", "mako", "twig", "freemarker", "velocity", "liquid", "eta"]
  matchAuthMapTags: ["templating"]
  maxFiles: 10
  priorityOrder: ["route_handler", "controller", "view", "mailer"]
severityHeuristics:
  critical:
    - "User input is concatenated/interpolated into a template STRING that is then compiled/rendered by a server-side engine capable of expression evaluation (Jinja2, Twig, Freemarker, Velocity, ERB, Handlebars/Pug/EJS with helpers), providing a path to sandbox escape and remote code execution"
    - "User input selects the template name/path passed to the renderer, allowing an attacker to render an unintended template or (with traversal) an attacker-controlled/arbitrary template"
  high:
    - "User input reaches a template-string render in an engine with a more limited evaluation surface, enabling information disclosure (config/objects/env exposed through template context) or a logic-tampering primitive even if direct RCE isn't demonstrated"
  medium:
    - "User input is interpolated into a template string but the engine is logic-less/heavily sandboxed (e.g. strict Mustache) such that the immediate impact is content injection rather than evaluation — still confirm the engine's actual evaluation capabilities before downgrading"
  low:
    - "A template is built dynamically from values that appear server-controlled but flow through a path a maintainer could wire user input into — latent SSTI; confirm no current user-reachable path before downgrading"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:template_engine"
  relatedNodeIds: ["component:input_validation", "component:remote_code_execution"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:template_engine"
    to: "component:input_validation"
  - relation: causes
    from: "component:template_engine"
    to: "component:remote_code_execution"
commonAiCodingMistakes:
  - "AI builds the template from an f-string/concatenation to 'personalize' output — `render_template_string(f'<h1>Hello {username}</h1>')` — instead of `render_template('hello.html', username=username)`, putting user input into the template SOURCE where Jinja evaluates it, opening `{{7*7}}` → sandbox-escape → RCE."
  - "AI compiles a template at request time from a user-provided value (a 'custom email template', a 'user-defined report format', a 'dynamic message') with `handlebars.compile(userInput)` / `Template(userInput)` / `ejs.render(userInput)`, handing the attacker the template language directly."
  - "AI passes a user-controlled value as the template NAME/path (`render_template(req.query.page)`), enabling rendering of unintended templates or, combined with traversal, arbitrary template files."
  - "AI disables autoescaping or uses a 'raw'/'safe' filter on user input to 'make the HTML render', conflating the XSS-escaping concern with the template-source concern and sometimes enabling both."
  - "AI treats a server-side template engine like a client-side string formatter, not recognizing that engines like Jinja2/Twig/Freemarker expose object attributes and method calls that chain into the host language runtime (the `__class__`/`__mro__`/`cycler` and Freemarker `Execute` gadgets)."
falsePositiveGuardrails:
  - "Do not flag the correct pattern: a FIXED template file (or a constant template string) rendered with user input passed as CONTEXT variables/data, with autoescaping enabled. In that pattern user input is data, never evaluated as template code — this is the intended, safe usage and is extremely common. Confirm whether user input reaches the template SOURCE or only the template DATA before flagging."
  - "Client-side templating (a template compiled and rendered in the browser) is XSS/prototype-pollution territory, not server-side RCE — classify it under XSS unless the compile happens server-side."
  - "A logic-less engine used strictly for interpolation with no expression evaluation (e.g. plain Mustache without lambdas) rendering a fixed template with user data is not SSTI — the concern is user input in the template source of an evaluating engine."
  - "Do not equate the presence of a template engine or `{{ }}` syntax with a vulnerability — the vulnerability requires user-controlled data to reach the template's source/name, not merely its context. Trace the data path."
  - "A template name chosen from a fixed server-side allow-list (a map/switch from a user token to a known template) is safe even though the name is 'dynamic' — confirm the allow-list rejects arbitrary input."
---

## Root Cause Explanation

Server-side template engines are, functionally, small programming languages:
they evaluate expressions, resolve object attributes, and in many engines can
call methods on those objects. That power is fine when the *template* is
trusted code written by developers and the *user input* is passed in as data
(context variables) that the engine treats as inert values. Server-Side
Template Injection happens when user input crosses from the data side to the
code side — when it becomes part of the template *source* that the engine
compiles and evaluates.

The distinction is the entire vulnerability, and it's exactly the distinction
AI-generated code blurs. `render_template('hello.html', name=name)` is safe:
`hello.html` is fixed code, `name` is data. `render_template_string(f'Hello
{name}')` is catastrophic: `name` is now part of the template source, so an
attacker who submits `{{7*7}}` sees `49`, confirms evaluation, and then
walks the engine's object graph (`{{ ''.__class__.__mro__ }}` in Jinja,
Freemarker's `Execute`, ERB's backticks) to reach the host runtime and
execute code. This is why SSTI sits at the top of the severity scale — it's
not reflected output like XSS, it's server-side code execution.

AI produces this pattern whenever it tries to make templating "dynamic":
personalizing a string with an f-string, letting users supply a "custom
template" for emails or reports, or choosing the template by a user-supplied
name. Each feels like a reasonable feature and each moves user input into the
code position. The fix is invariant: keep templates fixed, pass user input
only as bound context, keep autoescaping on, and select template names only
from a server-side allow-list.

## Vulnerable Patterns

```python
# Jinja2 — user input in the template SOURCE → SSTI → RCE
from flask import render_template_string
@app.route("/hi")
def hi():
    return render_template_string(f"<h1>Hello {request.args['name']}</h1>")
# attacker: ?name={{7*7}} → 49, then object-graph escape to RCE
```

```js
// Node — compiling a template from user input
const tpl = Handlebars.compile(req.body.template);   // attacker controls the template
res.send(tpl({}));
// or: ejs.render(userInput), new Function-style eval templating
```

```python
# User-controlled template NAME
return render_template(request.args["page"])         # unintended/arbitrary template
```

Correct shapes keep the template fixed and user input as bound data:

```python
return render_template("hello.html", name=request.args["name"])   # data, not code
```

```js
res.render("hello", { name: req.body.name });                      // fixed view, autoescaped
```

## Data Flow Tracing Guide

1. Enumerate all render/compile calls: `render_template_string`,
   `Template(...).render`, `env.from_string`, `handlebars.compile`,
   `ejs.render`, `pug.compile`, `nunjucks.renderString`, Freemarker/Velocity
   `Template` construction from a string, ERB `.result`, Twig `createTemplate`.
2. For each, determine whether the template SOURCE is a fixed file/constant or
   built from / equal to user input. User input in the source = SSTI.
3. Separately, check render calls where the template NAME/path is
   user-controlled; confirm whether it's allow-listed.
4. Identify the engine and its evaluation capabilities to set severity (full
   RCE-capable engines are critical).
5. Confirm the data path from a request source to the template source/name,
   quoting it.

## Evidence Checklist

- [ ] The render/compile call site quoted, showing the template source or
      name argument.
- [ ] The user-controlled origin of the template source/name, traced from the
      request.
- [ ] The engine named, with its evaluation capability (RCE-capable vs.
      limited) stated to justify severity.
- [ ] A concrete probe/payload (e.g. `{{7*7}}`) that the traced path admits.

A finding must establish that user input reaches the template SOURCE or NAME,
not merely its context data.

## Attack Scenario Template

> An attacker sends [request] with [parameter] set to a template-injection
> payload (e.g. `{{7*7}}` then an object-graph escape). Because [file:line]
> [builds the template string from user input / compiles a user-provided
> template / renders a user-chosen template name], the [engine] evaluates the
> payload as template code, allowing [confirmation via 7*7=49 then] [sandbox
> escape and remote code execution / disclosure of context objects and config
> / rendering of an unintended template], resulting in [impact].

## Graph Mapping Instructions

- Ensure a `component:template_engine` node exists, with a `depends_on` edge
  to `component:input_validation`.
- RCE-capable SSTI findings add a `causes` edge from the finding node to a
  `component:remote_code_execution` node (create it if the schema supports
  one) and must be flagged as RCE-class in `reasoning` so severity
  aggregation treats them at the top of the scale.
- Each concrete injection point is a `finding:<uuid>` vulnerability node with
  a `causes` edge from `component:template_engine`.
