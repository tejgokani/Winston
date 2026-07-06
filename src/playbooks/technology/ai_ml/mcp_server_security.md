---
id: technology.ai_ml.mcp_server_security
title: "AI: MCP Server & Tool Security"
category: technology
vulnerabilityClass: mcp_security
appliesToStack: Model Context Protocol servers exposing tools/resources to agents
requiresAnyTag: ["mcp"]
deepOnly: false
reviewPass: 1
owaspRefs:
  - "OWASP LLM06:2025 Excessive Agency"
  - "A01:2021 Broken Access Control"
cweRefs:
  - "CWE-862"
  - "CWE-441"
  - "CWE-78"
realWorldReferences:
  - title: "Anthropic — Model Context Protocol security concepts and best practices"
    url: "https://modelcontextprotocol.io/docs/concepts/security"
    type: security_blog
  - title: "'Tool poisoning' and confused-deputy attacks against MCP servers (Invariant Labs research)"
    url: "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks"
    type: research_paper
  - title: "MCP tool-description injection and cross-server shadowing risks"
    url: "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks"
    type: research_paper
quickModeSummary: >
  An MCP server exposes tools/resources to an LLM agent, so its tools run with
  whatever authority the server holds and are invoked based on model decisions
  driven by (often untrusted) context. Review: does each tool enforce
  authorization itself (not trusting that the agent/client already checked)? Are
  tool arguments validated and side-effecting/destructive tools gated or
  confirmable? Do tool inputs reach shell/SQL/file/HTTP sinks (command injection,
  path traversal, SSRF) since the "user" of these tools is an injectable model?
  Are the server's own credentials least-privilege rather than a shared god-token?
  Is the transport authenticated and not exposed beyond the intended client? And
  are tool descriptions/metadata (which the model reads) themselves a prompt-
  injection surface ("tool poisoning")? Treat every tool call as coming from an
  untrusted, injectable caller.
fileSelectionHint:
  roles: ["tool", "service", "server", "config", "controller"]
  matchImports: ["@modelcontextprotocol/sdk", "mcp"]
  matchAuthMapTags: ["mcp"]
  maxFiles: 12
  priorityOrder: ["tool", "server", "config", "service"]
severityHeuristics:
  critical:
    - "A tool passes its (model-supplied) arguments into a dangerous sink — shell/exec, SQL, filesystem path, or an outbound request — without validation, so a prompt-injected agent achieves command injection / path traversal / SSRF through the tool"
    - "A side-effecting or sensitive tool performs no authorization of its own, trusting the calling agent/client, so any caller (or an injected model) can invoke it with the server's full authority"
  high:
    - "The MCP server runs with broad/shared credentials (admin token, wide filesystem/network access) rather than least privilege, so tool abuse acts with excessive authority"
    - "The server transport is exposed beyond the intended local client / unauthenticated, letting untrusted parties call its tools directly"
  medium:
    - "Destructive/irreversible tools lack confirmation or scoping, or tool arguments are only partially validated; tool outputs (returned to the model) are attacker-influenceable and could carry injected instructions back to the agent"
    - "Tool descriptions/metadata incorporate untrusted content (tool poisoning surface) that the model reads as instructions"
  low:
    - "Read-only, well-scoped tools with validated arguments over an authenticated local transport and least-privilege server credentials — residual only; confirm no dangerous sink or side effect before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:authorization"
  relatedNodeIds: ["component:llm_boundary", "component:external_system"]
graphEdgeMapping:
  - relation: protects
    from: "component:authorization"
    to: "component:external_system"
  - relation: enables
    from: "component:llm_boundary"
    to: "component:external_system"
commonAiCodingMistakes:
  - "AI writes an MCP tool that runs a shell command or SQL built from the tool's arguments, assuming the arguments come from a trusted agent — but the 'caller' is an injectable model, so this is command/SQL injection reachable via prompt injection."
  - "AI builds tools that perform sensitive actions and relies on the client/agent to have authorized the user, doing no authorization in the tool itself (confused deputy)."
  - "AI runs the MCP server with broad credentials (full DB access, wide filesystem, an admin API key) so any tool call wields far more authority than needed."
  - "AI exposes the MCP server over a network transport without authentication, or binds it beyond localhost, letting other processes/hosts call its tools."
  - "AI returns tool output that includes untrusted external content straight back to the model without marking it as data, so a tool result can carry injected instructions to the agent (indirect injection loop)."
  - "AI writes tool descriptions/parameter docs that ingest untrusted text, which the model reads as trusted instructions (tool poisoning)."
falsePositiveGuardrails:
  - "Do not flag tools that validate/parameterize their arguments before any sink and enforce authorization inside the tool against the requesting user — that is the correct model. The caller being an agent does not excuse missing checks; equally, present checks are not a finding."
  - "Read-only tools scoped to non-sensitive data over an authenticated local (stdio/loopback) transport, with least-privilege server credentials, are low risk — confirm no side effects or dangerous sinks."
  - "Least-privilege server credentials (scoped to exactly what the tools need) are correct — only broad/shared credentials are the finding."
  - "Tool output that is delimited/marked as untrusted data when returned to the model mitigates the indirect-injection loop — confirm the handling."
  - "Cross-reference agent_excessive_agency (client side) and prompt_injection; report the server-side tool gap here without double-counting the same control."
---

## Root Cause Explanation

An MCP server is a bundle of tools an LLM agent can call, and it concentrates two
risks: the tools run with the *server's* authority, and they are invoked by a
*model* whose decisions are shaped by untrusted context. So every tool call must
be treated as arriving from an untrusted, potentially prompt-injected caller —
"the agent is trusted" is exactly the confused-deputy assumption that fails. Two
failure families dominate. First, **injection sinks**: tools that pass their
(model-supplied) arguments into shell, SQL, filesystem paths, or outbound
requests without validation give a prompt-injected agent command injection, path
traversal, or SSRF — with the server's privileges. Second, **missing
authorization and excessive authority**: tools that perform sensitive/destructive
actions without checking the requesting user's permissions inside the tool, and
servers that run with broad/shared credentials, let any invocation act far beyond
what the user should be able to do.

Two MCP-specific surfaces round it out: **exposure** (a transport reachable
beyond the intended local client, or unauthenticated), and **tool poisoning** —
tool descriptions/metadata and tool outputs are read by the model as
instructions, so untrusted content there is an injection vector back into the
agent. The controls are: validate/parameterize every tool argument, authorize
inside each tool against the real user, run least-privilege, authenticate and
scope the transport, and mark tool outputs/descriptions as untrusted data.

## Vulnerable Patterns

```ts
// Tool argument → shell/SQL sink; caller is an injectable model
server.tool("run", { cmd: z.string() }, async ({ cmd }) => execSync(cmd));           // command injection
server.tool("query", { sql: z.string() }, async ({ sql }) => db.query(sql));         // SQL injection

// Sensitive tool with no authorization, trusting the agent
server.tool("delete_user", { id: z.string() }, async ({ id }) => users.delete(id));  // no authz
// server started with an admin DB token and bound to 0.0.0.0
```

Correct: validate/parameterize, authorize in-tool, least privilege, scoped
transport.

```ts
server.tool("query_orders", { status: z.enum(["open","closed"]) }, async ({ status }, ctx) => {
  if (!authorize(ctx.user, "read_orders")) throw new Error("denied");
  return db.query("SELECT * FROM orders WHERE user_id=$1 AND status=$2", [ctx.user.id, status]);
});
```

## Data Flow Tracing Guide

1. For each tool, trace its arguments into any sink (shell/SQL/path/HTTP/file);
   flag unvalidated/unparameterized flows (injection via the model).
2. Check whether each side-effecting/sensitive tool authorizes the requesting
   user inside the tool, or trusts the agent/client.
3. Check the server's credentials/scope (least privilege vs. shared god-token).
4. Check the transport: local/authenticated vs. exposed/unauthenticated.
5. Check tool outputs and descriptions for untrusted content that returns to the
   model as instructions (tool poisoning / indirect injection).

## Evidence Checklist

- [ ] The tool definition and any sink its arguments reach, quoted.
- [ ] The in-tool authorization (or its absence).
- [ ] The server's credential scope and transport exposure.
- [ ] Any untrusted content in tool outputs/descriptions.

## Attack Scenario Template

> A prompt-injected agent (or a caller reaching the exposed transport) invokes
> [tool]. Because [file:line] [passes the argument into a shell/SQL sink
> unvalidated / performs no authorization / runs with a broad credential], the
> call achieves [command injection / unauthorized deletion / cross-user action]
> with the server's authority, resulting in [impact].

## Graph Mapping Instructions

- Ensure a `component:authorization` node with a `protects` edge to
  `component:external_system`.
- Injection-sink findings add a `causes` edge toward the relevant sink
  (`component:remote_code_execution`/database/external) and note the
  injection-via-model class.
- Add an `enables` edge from `component:llm_boundary` to the tool effect for
  confused-deputy findings.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:authorization`.
