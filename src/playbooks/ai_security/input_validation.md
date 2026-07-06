---
id: ai_security.input_validation
title: Input Validation
category: ai_security
vulnerabilityClass: improper_input_validation
appliesToStack: technology-agnostic
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A03:2021 Injection"
  - "A04:2021 Insecure Design"
cweRefs:
  - "CWE-20"
  - "CWE-1284"
  - "CWE-602"
realWorldReferences:
  - title: "IRCCloud disclosed on HackerOne: Inadequate input validation on API endpoint"
    url: "https://hackerone.com/reports/90912"
    type: bug_bounty_disclosure
  - title: "Legal Robot disclosed on HackerOne: Lack of input validation in signup (email/name fields)"
    url: "https://hackerone.com/reports/254927"
    type: bug_bounty_disclosure
  - title: "X / xAI disclosed on HackerOne: Lack of input validation can lead to Denial of Service"
    url: "https://hackerone.com/reports/768677"
    type: bug_bounty_disclosure
  - title: "HackerOne Report #161947: Lack of length validation on user address attribute"
    url: "https://hackerone.com/reports/161947"
    type: bug_bounty_disclosure
  - title: "OWASP Cheat Sheet Series — Input Validation Cheat Sheet"
    url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"
    type: security_blog
  - title: "MITRE CWE-602: Client-Side Enforcement of Server-Side Security"
    url: "https://cwe.mitre.org/data/definitions/602.html"
    type: research_paper
quickModeSummary: >
  Is every field the server actually reads validated server-side (type, range,
  format, length), or does the code rely on frontend validation / a Zod-Joi-Yup
  schema that covers only the "happy path" fields? Look for fields read from
  `req.body`/`req.query`/`req.params` that bypass the schema entirely (e.g.
  spread into a DB call, or read after `.parse()` via the raw object), missing
  `.max()`/length caps enabling resource exhaustion, and any endpoint reachable
  without going through the validation layer at all. Treat this as the
  root-cause playbook: if a finding here also matches injection, XSS, command
  injection, or SSRF patterns, cross-reference those playbooks rather than
  filing a duplicate.
fileSelectionHint:
  roles: ["route_handler", "middleware", "schema", "controller"]
  matchImports: ["zod", "joi", "yup", "class-validator", "express-validator", "ajv", "pydantic", "marshmallow"]
  matchAuthMapTags: []
  maxFiles: 10
  priorityOrder: ["schema", "route_handler", "middleware", "controller"]
severityHeuristics:
  critical:
    - "A field with no server-side validation is used directly in a sink that changes behavior based on its content (SQL/NoSQL query construction, shell command, file path, outbound URL) — file this under the specific injection/SSRF playbook, but record the missing-validation root cause here."
    - "An endpoint that accepts arbitrary-size input with no length/size cap and performs expensive server-side work per byte (regex, parsing, hashing, file write) — remote resource exhaustion with no auth required."
  high:
    - "A validation schema exists but a field actually read downstream is not covered by it (schema drift) — e.g. `UserSchema` validates `email`/`name` but the handler also reads `req.body.role` or `req.body.metadata` unchecked."
    - "Only client-side (frontend form / JS) validation exists for a security-relevant constraint (price, quantity, role, permission level) with no equivalent server-side re-check."
  medium:
    - "Missing format/range validation on a field that is not directly a sink but feeds business logic (e.g. unbounded quantity, negative price, out-of-range enum) — data-integrity risk more than direct exploit."
    - "Validation schema uses a permissive type (e.g. `z.any()`, `z.string()` with no `.max()`) where a narrower type was clearly intended."
  low:
    - "Missing `.strict()`/unknown-key rejection on an object schema where extra keys are logged or stored but not used in any sensitive branch (defense-in-depth gap only)."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:input_validation"
  relatedNodeIds: ["component:api_security", "component:injection", "component:xss", "component:command_injection", "component:ssrf"]
graphEdgeMapping:
  - relation: protects
    from: "component:input_validation"
    to: "component:api_security"
  - relation: enables
    from: "component:input_validation"
    to: "component:injection"
  - relation: enables
    from: "component:input_validation"
    to: "component:xss"
  - relation: enables
    from: "component:input_validation"
    to: "component:ssrf"
commonAiCodingMistakes:
  - "AI scaffolds a Zod/Joi/Yup schema that validates the fields shown in the example request in the prompt or the happy-path UI form, then the handler is later extended to read additional fields directly off the raw body/query object without updating the schema — schema and handler drift apart over incremental edits."
  - "AI writes frontend form validation (required, min/max, regex pattern) and treats that as sufficient, never adding an equivalent server-side check, because the acceptance criterion in the prompt was 'the form should validate X' rather than 'the API should reject invalid X'."
  - "AI adds a numeric or string field with no `.max()`/upper bound because the example inputs used during generation were always small, so nothing in the scaffold forces a length or size cap; this ships as an unbounded-input resource-exhaustion vector."
  - "AI uses `z.record(z.any())`, `z.any()`, or a loosely-typed catch-all for a 'metadata' or 'options' field to keep the schema simple, silently disabling validation for whatever ends up in that field at runtime."
  - "AI validates the top-level request shape but not nested/array elements (e.g. validates that `items` is an array but not that each item matches a strict per-item schema), letting malformed or oversized nested objects through."
falsePositiveGuardrails:
  - "Do not flag a field as unvalidated if it is consumed only for display/logging and never reaches a sink, a database write, or a business-logic branch that affects authorization or state — the risk must be traced to a concrete downstream effect, not asserted generically."
  - "Do not flag missing validation on internal, service-to-service, or trusted-input paths (e.g. values populated by the server itself, not derived from user input) — trace the field back to its actual origin before concluding it is attacker-controlled."
  - "If a field lacks a dedicated Zod/Joi/Yup rule but the runtime/ORM/type system enforces an equivalent constraint before use (e.g. a Prisma/SQL column type that will reject the wrong type, or a strictly-typed deserializer), do not double-count it as a missing-validation finding — note the mitigating control instead."
  - "This playbook is the umbrella/root-cause playbook. If a missing-validation gap is what enables a SQL/NoSQL injection, XSS, command injection, or SSRF finding, do not also file a duplicate `improper_input_validation` finding for the exact same code location — file under the specific injection/XSS/SSRF playbook and note the missing-validation root cause in that finding's reasoning field so the graph mapper can wire a `causes`/`enables` edge back to `component:input_validation`."
---

## Root Cause Explanation

Improper input validation is not one vulnerability — it is the missing control
that lets many *other* vulnerability classes reach an exploitable sink. Treat
this playbook as the root-cause layer underneath SQL/NoSQL injection, XSS,
command injection, and SSRF: those playbooks own the sink-specific analysis
(how a payload becomes a query, a script, a shell command, or an outbound
request), while this playbook owns the boundary question — was the input
actually constrained before it reached *any* sink?

The recurring failure modes, in order of how often they show up:

1. **Client-side-only validation.** A form or frontend framework validates
   required fields, types, and ranges in the browser, and the developer (or
   AI agent) treats that as sufficient. Any direct API call — curl, a
   modified fetch, a replayed/edited request — bypasses it entirely. Browser
   validation is a UX feature, not a security control.
2. **Missing type/range/format validation on API inputs.** An endpoint
   accepts a string where an enum was intended, a number with no min/max, or
   a string with no length cap. This shows up either as silent data
   corruption (wrong values stored) or as a resource-exhaustion vector
   (unbounded input driving expensive server-side work).
3. **Schema drift — the AI-scaffolding-specific pattern.** A validation
   library (Zod/Joi/Yup/class-validator/etc.) is wired up and genuinely
   enforces constraints on *some* fields, creating a false sense that "this
   endpoint is validated." But the schema was written against the fields
   visible when the endpoint was first scaffolded. As the handler is
   extended — new fields added to the request body, new branches added that
   read additional properties — the schema is not always updated in lockstep,
   so newly-read fields flow through completely unchecked while the
   developer's mental model (and any automated scanner keying off "a Zod
   schema exists here") says the input is safe.

Because this is a root-cause playbook, the payoff of a finding here is
usually in what it *enables* downstream, not in standalone impact. A missing
length cap that only wastes CPU is medium severity on its own; the same gap
that lets an unvalidated field reach `db.query()` or `child_process.exec()`
is a critical finding — but that critical finding belongs to the injection/
command-injection playbook, with this playbook's finding cited as its root
cause.

## Vulnerable Patterns

Look for shapes like these (illustrative, not exhaustive — reason about
equivalents in the actual stack you're reviewing, don't string-match):

```js
// Schema covers the happy-path fields only; handler reads more than the schema validates
const CreateUserSchema = z.object({
  email: z.string().email(),
  name: z.string(),
});
app.post('/users', (req, res) => {
  const { email, name } = CreateUserSchema.parse(req.body); // validated
  const role = req.body.role;        // NOT validated — read straight off raw body
  db.users.create({ email, name, role });
});

// No length/size cap — resource exhaustion, not just "bad data"
const CommentSchema = z.object({
  text: z.string(), // missing .max(...)
});

// Client-side-only enforcement: server trusts a value the UI merely disabled/hid
// (e.g. price/quantity/role sent from a <select> or hidden field, never re-checked)
app.post('/checkout', (req, res) => {
  const { price } = req.body; // price was only constrained by the frontend dropdown
  charge(price);
});

// Permissive catch-all field defeats the schema's purpose
const UpdateSchema = z.object({
  id: z.string(),
  options: z.record(z.any()), // anything goes here
});
```

## Data Flow Tracing Guide

To evaluate this playbook responsibly, trace the following before writing any
Finding:

1. For every route/handler in `route_map`, enumerate the fields it actually
   reads from the request (body, query, params, headers) — not just the
   fields named in the nearest validation schema. Diff that list against what
   the schema (if any) actually constrains. Any field read but not covered is
   evidence of schema drift.
2. For each unvalidated field, follow it forward: does it reach a sink
   (query construction, shell/process invocation, outbound HTTP request,
   file path, template/HTML output)? If so, this is the root cause for a
   finding that should be filed under the matching sink-specific playbook
   (injection/XSS/command_injection/SSRF), with this playbook's `causes` edge
   noted.
3. If a field is validated client-side (check frontend form/schema code) but
   has no corresponding server-side check, confirm the *same* endpoint is
   reachable directly (no server-side middleware re-validates it) before
   flagging — cite both the client-side check and the absence of a
   server-side equivalent.
4. For fields with no length/size bound, determine what server-side work is
   performed on them (regex evaluation, parsing, hashing, disk write, DB
   write) — an unbounded field feeding cheap, fixed-cost work is lower
   severity than one feeding per-byte expensive work.

## Evidence Checklist

Before submitting a Finding for this playbook, confirm:

- [ ] At least one concrete code snippet with an exact file + line range is
      attached as evidence — do not paraphrase, quote the actual line(s).
- [ ] If claiming schema drift: both the schema definition's location and the
      exact line where the unvalidated field is read are cited.
- [ ] If claiming client-side-only validation: the client-side check is
      cited, AND it is confirmed (not assumed) that no server-side
      equivalent exists on the same code path.
- [ ] If claiming a missing length/size cap: the exact field and the
      downstream operation performed on it are both cited, to justify the
      assigned severity.
- [ ] Confirmation that this finding is not a duplicate of a more specific
      injection/XSS/command_injection/SSRF finding already filed for the same
      code location — if the missing validation is what enables one of those,
      file it there and reference this root cause instead.

A finding without at least one concrete code-snippet evidence entry must not
be submitted.

## Attack Scenario Template

> An attacker submits [field] with [malformed/oversized/out-of-range value]
> directly to [specific endpoint], bypassing [client-side check that would
> normally block this in the UI]. Because [specific code location] does not
> validate [field] server-side, the value reaches [concrete downstream
> effect specific to this repo — a sink, a resource-exhaustion condition, a
> data-integrity violation], resulting in [concrete impact — not a generic
> description].

Fill every bracket concretely from evidence gathered in this repo. If a
bracket can't be filled from real evidence, the scenario is speculative and
severity must be capped at `medium`, with a note that exploitability is
unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:input_validation` node exists (create it on the
  first missing-validation finding in a scan) with a `protects` edge to
  `component:api_security`.
- When a missing-validation finding is the root cause of a finding filed
  under another playbook (injection, XSS, command_injection, SSRF), wire an
  `enables` edge from `component:input_validation` to that playbook's
  component node, and in the *downstream* finding's `reasoning` field state
  explicitly that it was enabled by a missing-validation root cause so the
  graph mapper can connect the two finding nodes with a `causes` edge rather
  than treating them as unrelated.
- Do not create a standalone `finding:<uuid>` vulnerability node for a
  missing-validation gap that has already been filed as the root cause of a
  more specific sink-based finding — one finding, one node; the root cause is
  metadata on that finding, not a separate node, unless the missing
  validation has independent impact on its own (e.g. pure resource
  exhaustion with no further sink involved).
- If a missing-validation gap has no identified downstream sink but is a
  standalone resource-exhaustion or data-integrity risk, create its own
  `finding:<uuid>` node with a `causes` edge from `component:input_validation`.
