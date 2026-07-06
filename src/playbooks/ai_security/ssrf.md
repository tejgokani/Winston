---
id: ai_security.ssrf
title: Server-Side Request Forgery (SSRF)
category: ai_security
vulnerabilityClass: ssrf
appliesToStack: technology-agnostic
deepOnly: false
reviewPass: 3
owaspRefs:
  - "A10:2021 Server-Side Request Forgery (SSRF)"
cweRefs:
  - "CWE-918"
quickModeSummary: >
  Find every place server-side code makes an outbound HTTP(S) request (or
  hands a URL to an LLM tool that will) where the target host/URL is
  attacker-influenced — directly (a `url`/`image`/`webhook`/`avatar` param)
  or indirectly (an LLM "fetch/browse" tool acting on content the attacker
  planted via prompt injection). Check whether the target is validated
  against an allowlist of hosts (not a denylist of "bad" IPs), whether
  redirects are followed without re-validating the final destination, and
  whether DNS is resolved once and reused rather than re-resolved after
  validation (TOCTOU/rebinding). No allowlist + redirects followed +
  reachable internal network = critical.
fileSelectionHint:
  roles: ["route_handler", "service", "webhook", "worker", "agent_tool", "integration"]
  matchImports:
    - "axios"
    - "node-fetch"
    - "got"
    - "requests"
    - "httpx"
    - "urllib"
    - "http.client"
    - "okhttp"
    - "restTemplate"
    - "net/http"
    - "puppeteer"
    - "playwright"
  matchAuthMapTags: ["ssrf", "webhook", "url_fetch", "agent_tool"]
  maxFiles: 8
  priorityOrder: ["agent_tool", "webhook", "route_handler", "service", "worker", "integration"]
severityHeuristics:
  critical:
    - "A URL/host derived from user input (directly or via an LLM tool call reasoning over attacker-influenced content) is fetched server-side with no allowlist, and the deployment plausibly has network access to cloud metadata (169.254.169.254 / fd00:ec2::254) or another instance-metadata-equivalent endpoint."
    - "An LLM agent has a raw `fetch(url)`/`browse(url)`-style tool with no host allowlist, reachable from content the model reads (indirect prompt injection surface: retrieved web pages, tool outputs, MCP resource contents, uploaded documents)."
  high:
    - "A validated URL is fetched, but the HTTP client follows redirects (3xx) without re-validating the final resolved host/IP — first-hit allowlist check, final destination unchecked."
    - "Validation is a denylist of specific strings/IPs (e.g. blocking 'localhost', '127.0.0.1') rather than a strict allowlist, and is trivially bypassed by decimal/octal/hex IP encoding, IPv6 forms, or DNS names that resolve to internal ranges."
  medium:
    - "Host is validated once at request time but the HTTP client resolves DNS independently at connect time, opening a DNS-rebinding window (TOCTOU between check and connect)."
    - "Internal service reachable via SSRF is low-value (public read-only data) but request/response is still fully attacker-controlled (blind vs full-response SSRF distinction affects exploitability, not existence)."
  low:
    - "Outbound requests are allowlisted correctly but not logged, reducing detection/forensics capability if the allowlist is later misconfigured."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:ssrf"
  relatedNodeIds:
    - "component:network_boundary"
    - "component:cloud_metadata"
    - "component:agent_tooling"
    - "component:webhook_ingestion"
graphEdgeMapping:
  - relation: depends_on
    from: "component:url_fetch_feature"
    to: "component:ssrf"
  - relation: enables
    from: "component:ssrf"
    to: "component:cloud_metadata"
  - relation: enables
    from: "component:ssrf"
    to: "component:internal_network"
  - relation: depends_on
    from: "component:agent_tooling"
    to: "component:ssrf"
commonAiCodingMistakes:
  - "AI scaffolds a 'fetch this URL and summarize/proxy it' feature (webpage summarizer, avatar-from-URL, link preview) by wiring the user-supplied URL straight into `fetch`/`axios.get`/`requests.get` with zero host validation, because the happy-path prompt ('build an image proxy') never mentions the internal-network threat model."
  - "AI adds a denylist ('block localhost, 127.0.0.1, private IPs') instead of an allowlist, and misses IPv6 forms (::1, ::ffff:127.0.0.1), decimal/octal IP encodings (2130706433, 017700000001), the AWS/GCP IPv6 metadata address (fd00:ec2::254), or DNS names that resolve to internal ranges — all of which trivially bypass string-based denylists."
  - "AI validates the URL string once before the request, but the HTTP client is left on default settings that follow redirects — so an initially-allowlisted external URL that 302s to http://169.254.169.254/ or http://localhost/admin sails through unchecked, because the AI reasoned about the input, not about the client's redirect behavior."
  - "AI gives an LLM agent a generic `fetch_url(url)` or `browse(url)` tool with no host restriction, because the task ('let the agent browse the web to answer questions') didn't obviously look like a place to add an SSRF control — the model itself, not the end user, becomes the vector for the malicious URL after indirect prompt injection from a retrieved page or tool output."
  - "AI implements the allowlist check by resolving the hostname once for validation, then lets the HTTP library re-resolve DNS independently at connect time — a scaffolded 'looks correct' check that is actually vulnerable to DNS rebinding, because the two-step resolve-then-connect gap isn't something a single-file code review surfaces."
  - "AI adds validation to the primary URL-fetch feature but not to secondary URL-consuming paths added later (webhook retry logic, a newly added 'import from URL' admin feature, an SSO metadata URL field) — the same inconsistent-enforcement pattern seen with auth checks, but for SSRF."
falsePositiveGuardrails:
  - "Do not flag a URL fetch where the target is fully server-controlled (e.g. fetching from a hardcoded internal API base URL, or a URL read from a trusted config/database value the user cannot influence) — SSRF requires attacker influence over the destination, not merely the existence of an outbound request."
  - "Do not flag if the fetch is already routed through an allowlist-based proxy/safe-fetch service (or a well-known library that explicitly documents SSRF-safe defaults) even if that enforcement point lives outside the currently scanned file set — check for evidence of a central egress-control layer (env config, infra-as-code, documented proxy) before concluding validation is absent."
  - "A tool that lets an LLM agent call other internal APIs by structured identifier (not a raw URL) is not SSRF-vulnerable merely because it makes network calls — the vulnerability requires the model or user to control the actual destination host, not just an opaque ID the backend resolves itself."
  - "Do not treat every redirect-following HTTP client call as a finding — only when the URL host is subject to a validation step that occurs before the request but the client can still follow the server through a redirect to an unvalidated host. If redirects are disabled (e.g. `maxRedirects: 0`, `redirect: 'manual'`, `allow_redirects=False`) note that as a mitigating control instead."
  - "Blind SSRF (no response body returned to the attacker) is still a valid, often critical finding — do not downgrade severity to low just because the attacker can't directly read the response; note in the finding whether it's blind or full-response, since that changes exploitation technique, not existence."
  - "In a local dev/CI/test-only code path (fixtures, integration tests hitting localhost intentionally) or a tool that is explicitly designed to be operator-only and unreachable by untrusted input (an internal admin CLI script, not a user-facing endpoint), do not apply the same severity as a user-facing feature — confirm the trust boundary before flagging."
---

## Root Cause Explanation

SSRF exists because the server, not the attacker, holds a trusted network
position. Any feature where server-side code makes an outbound request to a
URL that an attacker can influence turns the server into a proxy the attacker
can drive from outside — reaching hosts the attacker could never address
directly: cloud instance-metadata services, internal admin panels, databases
without external auth, and other services deliberately kept off the public
internet because "the network boundary is the security boundary."

The pattern recurs because URL-fetching features are usually built to solve
a benign product problem — "let users set a webhook URL," "let users provide
an avatar image URL," "let users paste a link to summarize" — and the
implementation naturally focuses on making the happy path work, not on the
fact that the server is now willing to originate a request to anywhere the
input says. Four sub-failures show up repeatedly:

1. **No allowlist, or a denylist that doesn't cover the input space.**
   Blocking known-bad strings (`localhost`, `127.0.0.1`, `0.0.0.0`) is not
   equivalent to only permitting known-good hosts. Attackers bypass
   denylists with decimal/octal/hex IP encodings, IPv6 loopback forms
   (`::1`, `::ffff:127.0.0.1`), the AWS/GCP IPv6 metadata address
   (`fd00:ec2::254`), or a DNS name they control that simply resolves to an
   internal IP.
2. **Validate-then-fetch race (TOCTOU / DNS rebinding).** The URL's hostname
   is resolved and checked once, then the HTTP client independently
   resolves DNS again when it actually connects. An attacker who controls
   DNS for the domain can return a safe, external IP for the validation
   lookup and a different, internal IP moments later for the real
   connection — the check passes, the request doesn't go where it was
   validated to go.
3. **Redirect-based bypass.** The initial URL passes an allowlist check, but
   the server it points to responds with a 3xx redirect to an internal
   address, and the HTTP client (following default behavior) transparently
   follows it. The validation logic reasoned about the URL string the user
   supplied, not about where the request actually ends up landing.
4. **The AI-agent variant: the model is the vector, not the user.** When an
   LLM agent has a "fetch a URL" / "browse the web" tool, the attacker
   doesn't need to submit a URL through a form field at all — a payload
   embedded in a web page, document, or tool output the agent reads
   (indirect prompt injection) can instruct the model to call its own fetch
   tool against an internal address "to verify" or "for more context," and
   the model, having no independent judgment about network topology, does
   it. The trust path is longer and the input is adversarial by
   construction: the URL never appears in literal user input, it's reasoned
   into existence by the model after reading untrusted content.

## Vulnerable Patterns

Look for shapes like these (illustrative, not exhaustive — reason about
equivalents in the actual stack you're reviewing, don't string-match):

```js
// Direct SSRF: user-supplied URL fetched with no validation at all
app.post('/api/webhook-test', async (req, res) => {
  const result = await fetch(req.body.url) // any host, any port
  res.send(await result.text())
})

// Denylist instead of allowlist — trivially bypassed
function isSafeUrl(url) {
  const host = new URL(url).hostname
  return !['localhost', '127.0.0.1', '0.0.0.0'].includes(host)
  // misses: 2130706433 (decimal 127.0.0.1), ::1, ::ffff:127.0.0.1,
  // fd00:ec2::254 (AWS IPv6 metadata), attacker-controlled DNS names
  // that simply resolve to 169.254.169.254
}

// Validated once, but redirects are followed to the real target unchecked
const res = await axios.get(userSuppliedUrl) // axios follows redirects by default
```

```python
# Validate-then-fetch TOCTOU: hostname checked, but requests resolves
# DNS again independently at connect time (DNS rebinding window)
def is_allowed(url):
    host = urlparse(url).hostname
    ip = socket.gethostbyname(host)  # resolved once, here
    return ipaddress.ip_address(ip) not in PRIVATE_RANGES

if is_allowed(user_url):
    resp = requests.get(user_url)  # resolves DNS again here — race window
```

```python
# LLM agent tool: raw fetch handed to the model with no host restriction
@tool
def browse_url(url: str) -> str:
    """Fetch a URL and return its contents."""
    return requests.get(url, timeout=5).text
    # any content the agent reads (a retrieved page, a tool result) can
    # contain an instruction telling the model to call this against
    # http://169.254.169.254/latest/meta-data/iam/security-credentials/...
```

## Data Flow Tracing Guide

To evaluate this playbook responsibly, trace the following before writing any
Finding:

1. Enumerate every outbound-request call site (`fetch`, `axios`, `got`,
   `requests`, `httpx`, `urllib`, `http.client`, `okhttp`, `RestTemplate`,
   `net/http`, headless-browser `.goto()`/`.navigate()` calls, and any LLM
   tool whose implementation makes a network call). For each, trace the
   target URL/host argument backward to its source.
2. If the source is a literal or a value read from trusted server config/DB
   with no user path into it — not SSRF, stop here for that call site.
3. If the source is user input (form field, query param, JSON body, webhook
   config, uploaded file content) or LLM-agent-controlled (a tool argument
   the model fills in, potentially after reading untrusted content) —
   continue.
4. Find the validation step, if any. Is it an allowlist of specific hosts,
   or a denylist/blocklist of "bad" values? A denylist is evidence of a
   likely bypass — enumerate concretely what it misses (IPv6 forms, encoded
   IPs, DNS rebinding, cloud metadata IPv6 addresses) rather than assuming.
5. Check the HTTP client's redirect behavior. Does the library follow
   redirects by default (most do), and if so, is `maxRedirects: 0` /
   `redirect: 'manual'` / `allow_redirects=False` (or equivalent) explicitly
   set? If not set, the validated URL and the actually-requested URL can
   diverge.
6. Check whether hostname validation and the actual connection use the same
   resolved IP, or whether DNS is resolved twice (once to validate, once to
   connect) — the latter is a rebinding window.
7. For agent/LLM tool call sites specifically: does the tool accept a raw
   URL/host from the model, or a structured identifier the backend resolves
   itself? Is the tool reachable from content the model reads that an
   external party could plant (search results, fetched pages, email
   content, uploaded documents, other tools' outputs)? That reachability is
   the indirect-prompt-injection-to-SSRF chain — trace it explicitly if
   present.
8. Confirm network reachability plausibility: does this deployment run in an
   environment where cloud metadata endpoints or other internal-only
   services would plausibly be reachable from the process making the
   request (cloud VM, container in a VPC, Kubernetes pod)? This affects
   severity, not existence of the flaw — an unvalidated fetch is still a
   finding even if you can't confirm the specific internal targets from
   static review alone.

## Evidence Checklist

Before submitting a Finding for this playbook, confirm:

- [ ] At least one concrete code snippet with an exact file + line range
      showing the outbound-request call site is attached as evidence.
- [ ] The exact line(s) where the target URL/host originates (user input,
      LLM tool argument, or attacker-reachable content) is cited, tracing
      from source to the request call.
- [ ] If claiming missing/weak validation: the exact validation function (or
      confirmed absence of one) is cited, with a concrete bypass example
      (specific encoded IP, IPv6 form, or attacker-controlled DNS scenario)
      — not a generic "no validation" assertion.
- [ ] If claiming a redirect-bypass: confirmed the HTTP client's redirect
      setting (default-follows vs. explicitly disabled) at the exact call
      site, not assumed from the library's general reputation.
- [ ] If claiming an agent/LLM-tool SSRF chain: cited both the tool
      definition (accepts raw URL, no allowlist) and the plausible
      untrusted-content path that could reach it (what content the agent
      reads that an outside party could influence).
- [ ] Noted whether the finding is blind (no response returned) or
      full-response SSRF, since this affects the attack scenario but not
      whether it's a valid finding.

A finding without at least one concrete code-snippet evidence entry must not
be submitted.

## Attack Scenario Template

> An attacker controls [input source: URL field / webhook config / content
> the LLM agent reads] and sets it to [specific internal target, e.g.
> `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`
> or `http://localhost:<internal-port>/<admin-path>`]. Because [specific
> code location] does not [missing allowlist check / does not re-validate
> after redirect / re-resolves DNS independently of the validation check],
> the server-side request reaches [specific internal target], resulting in
> [concrete impact specific to this repo — e.g. "exfiltration of the EC2
> instance role's temporary AWS credentials via the response body returned
> to the attacker" or, for the agent variant, "the agent includes the
> internal admin panel's contents in its response to the (attacker-adjacent)
> user, or acts on injected instructions found there"].

Fill every bracket concretely from evidence gathered in this repo. If a
bracket can't be filled from real evidence (e.g. you can't confirm the
deployment target has metadata-endpoint reachability), the scenario is
speculative and severity must be capped at `medium`, with a note that
network-topology exploitability is unconfirmed but the missing input
validation itself is still a real defect.

## Graph Mapping Instructions

- Always ensure a `component:ssrf` node exists (create it on the first
  SSRF-related finding in a scan) with a `depends_on` edge from the specific
  feature component that performs the vulnerable fetch (e.g.
  `component:url_fetch_feature`, `component:webhook_ingestion`,
  `component:agent_tooling`).
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from `component:ssrf` (or a more
  specific root-cause component, e.g. `component:input_validation` if the
  root cause is a missing/weak allowlist) to the finding node.
- If a finding enables reaching a specific sensitive internal target
  identified in this repo (cloud metadata, an internal admin service, a
  database reachable without auth), add an `enables` edge from the finding
  node to that target's component node id (e.g.
  `component:cloud_metadata`, `component:internal_network`).
- For the AI-agent variant, add a `depends_on` edge from
  `component:agent_tooling` to `component:ssrf`, and if the untrusted
  content path was traced (search results, fetched pages, other tool
  outputs), add an `enables` edge from `component:prompt_injection` (or the
  equivalent node from the indirect-prompt-injection playbook, if that scan
  pass already created one) to this finding — this is a root-cause chain,
  not two unrelated findings.
- Root cause vs. symptom: if a finding is *caused by* another finding
  already identified in this scan (e.g. a missing-redirect-revalidation
  finding is a variant of a broader "no allowlist" finding), say so
  explicitly in the finding's `reasoning` field so the graph mapper can wire
  a `causes` edge between the two finding nodes rather than treating them as
  unrelated.
