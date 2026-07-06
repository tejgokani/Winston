---
id: ai_security.logging_and_error_handling
title: Logging and Error Handling
category: ai_security
vulnerabilityClass: information_disclosure
appliesToStack: technology-agnostic
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A09:2021 Security Logging and Monitoring Failures"
  - "A05:2021 Security Misconfiguration"
cweRefs:
  - "CWE-209"
  - "CWE-532"
  - "CWE-778"
  - "CWE-215"
realWorldReferences:
  - title: "U.S. Dept of Defense disclosed on HackerOne: Trace.axd debug endpoint exposed SSNs, plaintext passwords, session tokens, and CSRF tokens ($20,000 bounty)"
    url: "https://www.hackerone.com/blog/8-high-impact-bugs-and-how-hackerone-customers-avoided-breach-information-disclosure"
    type: bug_bounty_disclosure
  - title: "Enter disclosed on HackerOne: Error stack trace exposed by removing the CSRF token from a request"
    url: "https://hackerone.com/reports/41469"
    type: bug_bounty_disclosure
  - title: "CVE-2026-44025 — Fluentd Monitor Agent API exposes plugin instance variables (DB passwords, API keys, cloud credentials) in plaintext with no authentication"
    url: "https://advisories.gitlab.com/gem/fluentd/CVE-2026-44025/"
    type: vendor_security_advisory
  - title: "PortSwigger Web Security Academy — Information disclosure in error messages"
    url: "https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-error-messages"
    type: security_blog
  - title: "OWASP Cheat Sheet Series — Logging Cheat Sheet"
    url: "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"
    type: security_blog
  - title: "Security of LLM-generated Code: A Comparative Analysis — CWE-200 (debug=True / printed stack traces) was the single largest vulnerability category found, at 38.3% of all instances"
    url: "https://arxiv.org/pdf/2605.23091"
    type: research_paper
quickModeSummary: >
  Check three things: (1) does an unhandled exception path return a raw
  stack trace / framework debug page to the client (debug=True, NODE_ENV
  not enforced, custom error handler missing)? (2) does any log statement
  write a password, token, API key, session id, or other PII-grade value
  in full, not redacted? (3) are security-relevant actions (login
  success/failure, permission/role changes, payment/financial transactions,
  admin actions) actually logged at all — or would an incident responder
  have nothing to reconstruct after a breach?
fileSelectionHint:
  roles: ["error_handler", "middleware", "logging", "config", "route_handler"]
  matchImports: ["winston", "pino", "morgan", "log4j", "logging", "python-json-logger", "bunyan", "serilog"]
  matchAuthMapTags: ["logging", "error_handling"]
  maxFiles: 8
  priorityOrder: ["error_handler", "middleware", "logging", "config"]
severityHeuristics:
  critical:
    - "Production-reachable endpoint returns a full stack trace, database connection string, or internal file path on an unhandled exception (debug mode left on in a deployed environment)."
    - "Passwords, full session tokens, API keys, or full credit card / SSN values are written to logs in plaintext and those logs are shipped to a third-party aggregator or are broadly readable."
  high:
    - "Security-relevant actions (auth success/failure, privilege escalation, password reset, payment/financial transaction) are not logged at all, so post-incident reconstruction is impossible."
    - "Error responses leak internal implementation details (ORM query text, library versions, internal hostnames/IPs) that materially aid an attacker even without a full stack trace."
  medium:
    - "Logs include partial-but-still-sensitive data (e.g. unmasked email addresses, unredacted authorization headers) without a clear compliance/retention justification."
    - "Debug/verbose logging is gated by an environment flag but the flag's default value is 'on' rather than 'off'."
  low:
    - "Log messages include user-controlled input without encoding, creating a log-injection / log-forging risk (CRLF injection into log files) but no direct sensitive-data exposure."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:logging_and_error_handling"
  relatedNodeIds: ["component:observability", "component:incident_response", "component:secrets"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:observability"
    to: "component:logging_and_error_handling"
  - relation: protects
    from: "component:logging_and_error_handling"
    to: "component:incident_response"
commonAiCodingMistakes:
  - "AI scaffolds a framework app with the debug/development error handler left in place (e.g. Flask `debug=True`, Express default error middleware, Django `DEBUG = True`) with a comment like '# set to False in production' — the comment is generated but the flag is never actually flipped before deploy, and research on LLM-generated code found this exact pattern (debug mode on, or stack traces printed to the response) accounted for the largest single vulnerability category observed (~38% of all findings in one comparative study)."
  - "AI adds a `console.log(req.body)` or `logger.info(JSON.stringify(user))` for debugging during scaffolding that logs an entire request/user object — including password fields, tokens, or auth headers — and this line survives into the final code because it 'worked' during testing."
  - "AI implements a global exception handler that catches all errors and serializes the exception object directly into the JSON response (`res.json({ error: err })` or `err.stack` included) rather than mapping to a generic client-safe message plus a separate server-side log entry."
  - "AI builds login/auth/payment flows without being asked to add audit logging, since audit logging is not 'feature work' the prompt explicitly requested — the functional path works but there is no record of who did what, when, which only becomes visible after an incident when the log is needed and doesn't exist."
  - "AI-assisted debugging pipelines (AI tools that ingest logs/stack traces to help fix bugs) forward full diagnostic payloads — including embedded secrets or PII — to an external LLM API without scrubbing first, creating a new class of log-exfiltration path that didn't exist before AI tooling was introduced into the debug loop."
falsePositiveGuardrails:
  - "Do not flag error handling in local-only dev tooling, test fixtures, or CLI scripts that never run in a deployed/production context — confirm the code path is actually reachable by an external client before treating verbose errors as a finding."
  - "A stack trace written only to a server-side log file (not returned in the HTTP response) is not information disclosure to an external attacker by itself — the finding is only valid if the trace reaches the client, or if the log file itself is exposed/over-shared (check log aggregator access controls before escalating severity)."
  - "Framework-level redaction (e.g. a logging library configured with a redact/mask list for fields like `password`, `authorization`, `token`) should be verified against the actual field names used in the codebase — do not assume redaction is absent just because you don't see an explicit `delete req.body.password` call; check the logger's own config first."
  - "Missing audit logging for a genuinely non-security-relevant action (e.g. a UI theme preference change) is not a finding — scope this playbook to authentication, authorization, financial, and data-modification events, not every state change in the app."
---

## Root Cause Explanation

This playbook covers three related but distinct failure modes that all reduce to the same root cause — **the boundary between "diagnostic information useful to a developer" and "information safe to expose beyond the trust boundary" is not enforced in code**:

1. **Verbose error responses.** Most web frameworks ship with a permissive default error handler during development — one that renders a full stack trace, source snippet, and environment details to make debugging fast. That handler is meant to be swapped for a generic error page before deploy. AI coding assistants routinely scaffold applications with the dev-mode handler *and a comment saying to change it later* — but "later" doesn't happen automatically, and research on LLM-generated code has found this exact pattern (debug flags left on, exceptions printed straight to the response) to be the single largest vulnerability category observed in one large comparative study of AI-generated code (~38% of all findings). The fix an AI writes is often literally correct in isolation (`debug=True # TODO: set False in production`) but the mistake is trusting a comment to do the job of a secure default.
2. **Sensitive data written to logs.** Logging is usually added for observability, not security, so it doesn't get the same scrutiny as an auth check. A `logger.info()` or `console.log()` call that dumps a whole request/response object is convenient during development and trivially captures passwords, bearer tokens, session cookies, and PII in plaintext — and once it's in a log file, it inherits whatever (often much broader) access control the logging/observability stack has, not the access control of the original resource. CVE-2026-44025 (Fluentd) is a clean illustration of this at the infrastructure level: a monitoring API meant to expose *metrics* accidentally exposed the *raw instance variables* of every loaded plugin, including database passwords and cloud credentials, to anyone who could reach the port — no authentication required.
3. **Missing or insufficient audit logging.** This is an *absence* finding, which is harder for both humans and AI to notice than a present-but-wrong line of code. Security-relevant actions — login attempts (success and failure), password/permission changes, privilege escalation, financial transactions — need a durable, tamper-evident record specifically because the moment you need that record is *after* something has already gone wrong. An AI assistant implementing a login endpoint from a feature prompt ("add login") has no reason to also add audit logging unless asked, because audit logging isn't part of the functional spec — it's an emergent requirement of running the system safely over time.

## Vulnerable Patterns

Look for shapes like these (illustrative, not exhaustive — reason about equivalents in the actual stack you're reviewing, don't string-match):

```python
# Flask/Django-style debug mode left enabled
app.run(debug=True)  # or DEBUG = True in settings.py, reachable in prod
```

```js
// Global error handler that leaks the exception object to the client
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack }); // stack should never reach the client
});
```

```js
// Sensitive data logged in full during a "helpful" debug log
logger.info('Login attempt', { email, password, headers: req.headers }); // password + auth header logged in plaintext
console.log('user object:', JSON.stringify(user)); // may include token/hash fields
```

```python
# No audit trail for a security-relevant action
def change_user_role(user_id, new_role):
    db.execute("UPDATE users SET role = %s WHERE id = %s", (new_role, user_id))
    # no log of who made this change, when, or what the previous role was
```

## Data Flow Tracing Guide

To evaluate this playbook responsibly, trace the following before writing any Finding:

1. **Error handling path.** Find the global/default exception or error-handling middleware. Does it distinguish between what's logged server-side (can be verbose) and what's returned to the client (must be generic)? Follow a specific exception type from where it's thrown to where the response is constructed — is `err.stack`, `err.message`, or the raw exception object ever serialized into the HTTP response body?
2. **Debug/dev-mode flags.** Search for framework debug flags (`debug=True`, `DEBUG`, `NODE_ENV`, `ASPNETCORE_ENVIRONMENT`, `app.set('env', ...)`). Trace where the flag's value comes from — a hardcoded literal, an environment variable with what default, or a config file. A flag that defaults to "on" and requires an explicit production override is higher risk than one that defaults to "off."
3. **Logging call sites.** For each logging statement (`logger.*`, `console.log`, `print`, structured logging calls), check what's actually being passed — a whole object/request, or specific named fields? If a whole object is logged, cross-reference that object's shape against known sensitive field names (password, token, secret, authorization, ssn, credit_card, etc.) in the codebase's models/schemas.
4. **Redaction/masking config.** Before flagging a logging call as leaking sensitive data, check whether the logging library itself is configured with a redaction list (many production loggers support this natively) — if so, confirm the actual field names being logged are covered by that list, don't assume coverage.
5. **Audit trail for security-relevant actions.** For each of: login (success/failure), logout, password change, permission/role change, account creation/deletion, and any payment/financial mutation — find the handler and check whether a durable log entry (not just a debug-level trace) is written that records who, what, when, and outcome. Absence here is the finding; cite the specific handler file/function that lacks it.
6. **Log sink access control.** If logs are shipped to a third-party aggregator or a shared storage location, check how broadly that destination is accessible — a sensitive value logged internally is a smaller problem than one logged to a destination with wide read access (this affects severity, not whether it's a finding).

## Evidence Checklist

Before submitting a Finding for this playbook, confirm:

- [ ] At least one concrete code snippet with an exact file + line range is attached as evidence — do not paraphrase, quote the actual line(s).
- [ ] If claiming verbose error disclosure: the exact line where the exception/stack is serialized into the client-facing response is cited, and confirmation that the route is client/externally reachable (not a local-only dev script).
- [ ] If claiming sensitive data in logs: the exact logging call site is cited, and the specific sensitive field(s) present in the logged object/value are named — not just "logs may contain sensitive data."
- [ ] If claiming missing audit logging: the specific security-relevant handler (function/route) that lacks a durable log entry is cited, and confirmation that no logging middleware/decorator wraps it elsewhere in the call chain.
- [ ] Confirmation that logger-level redaction/masking config was checked and does not already cover the flagged field.

A finding without at least one concrete code-snippet evidence entry must not be submitted.

## Attack Scenario Template

> An attacker triggers [an unhandled exception / a request that hits the logging code path] at [specific endpoint/handler]. Because [specific code location] does not [strip the stack trace before responding / omit password and token fields from the log call / write an audit entry], the attacker obtains [specific leaked data — a database connection string, a plaintext session token, a bypassable audit trail], resulting in [concrete impact specific to this repo, e.g. "the attacker uses the leaked ORM connection string to enumerate the database schema and pivot to a SQL injection attempt" or "an insider abuses the permission-change endpoint with no audit trail, and there is no way to reconstruct who granted themselves admin access after the fact"].

Fill every bracket concretely from evidence gathered in this repo. If a bracket can't be filled from real evidence, the scenario is speculative and severity must be capped at `medium`, with a note that exploitability is unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:logging_and_error_handling` node exists (create it on the first finding from this playbook in a scan) with a `depends_on` edge from `component:observability`.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type `vulnerability`, with a `causes` edge from `component:logging_and_error_handling` to the finding node.
- If a sensitive-data-in-logs finding involves a specific secret type (e.g. a JWT, an API key, a database credential), add an `enables` edge from the finding node to the corresponding component node (`component:jwt`, `component:secrets`, `component:database`) to reflect that this finding can be a root cause enabling a downstream compromise of that component.
- Missing audit logging findings should get a `protects` edge from `component:logging_and_error_handling` to `component:incident_response`, reflecting that the gap specifically undermines post-incident investigation capability rather than causing an immediate exploit.
- Root cause vs. symptom: if a logging finding is what makes another finding *discoverable or exploitable* by an attacker (e.g. a leaked stack trace reveals the exact database type/version that enables a targeted SQL injection payload), say so explicitly in the finding's `reasoning` field so the graph mapper can wire a `causes` edge from the logging finding to the downstream finding rather than treating them as unrelated.
