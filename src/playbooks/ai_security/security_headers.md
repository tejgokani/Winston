---
id: ai_security.security_headers
title: Security Headers
category: ai_security
vulnerabilityClass: missing_security_headers
appliesToStack: technology-agnostic
deepOnly: false
reviewPass: 3
owaspRefs:
  - "A05:2021 Security Misconfiguration"
cweRefs:
  - "CWE-1021"
  - "CWE-693"
  - "CWE-16"
realWorldReferences:
  - title: "Yelp disclosed on HackerOne: Missing X-Frame-Options header"
    url: "https://hackerone.com/reports/49888"
    type: bug_bounty_disclosure
  - title: "GlassWire disclosed on HackerOne: Clickjacking — X-Frame-Options missing on nearly every page"
    url: "https://hackerone.com/reports/27594"
    type: bug_bounty_disclosure
  - title: "GitLab disclosed on HackerOne: CSP-bypass XSS in project settings page"
    url: "https://hackerone.com/reports/1588732"
    type: bug_bounty_disclosure
  - title: "OWASP Secure Headers Project"
    url: "https://owasp.org/www-project-secure-headers/"
    type: security_blog
  - title: "MDN — Content-Security-Policy: script-src (unsafe-inline / unsafe-eval risks)"
    url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src"
    type: security_blog
quickModeSummary: >
  Check response headers on HTML-serving routes: is Content-Security-Policy
  present and does it avoid unsafe-inline/unsafe-eval for script-src? Is
  X-Frame-Options or frame-ancestors set to prevent clickjacking? Is
  Strict-Transport-Security set for HTTPS-only deployments? Is
  X-Content-Type-Options: nosniff present? Treat this as a defense-in-depth
  layer — flag it, but do not inflate severity unless it removes a mitigation
  for another confirmed finding (e.g. an XSS finding with no CSP backstop).
fileSelectionHint:
  roles: ["middleware", "server_config", "route_handler"]
  matchImports: ["helmet", "next-safe", "secure-headers", "django-csp", "flask-talisman", "nginx.conf", "next.config"]
  matchAuthMapTags: []
  maxFiles: 8
  priorityOrder: ["middleware", "server_config", "route_handler"]
severityHeuristics:
  critical: []
  high:
    - "CSP is missing entirely (or is `default-src *`) on an application that also has a confirmed reflected/stored XSS finding — the missing header removed the last mitigating control, so treat this as a severity amplifier on that finding, not a standalone critical."
  medium:
    - "Content-Security-Policy is present but includes `unsafe-inline` and/or `unsafe-eval` in script-src on an application that renders any user-influenced content into HTML."
    - "X-Frame-Options and CSP `frame-ancestors` are both absent on a page that performs a sensitive state-changing action (e.g. account settings, payment, admin actions) reachable via GET or a CSRF-susceptible form — clickjacking can chain into an actual account-takeover primitive here."
  low:
    - "Strict-Transport-Security missing on an HTTPS-only deployment (defense-in-depth against protocol downgrade / SSL-stripping)."
    - "X-Content-Type-Options: nosniff missing (defense-in-depth against MIME-sniffing-based content-type confusion)."
    - "X-Frame-Options/frame-ancestors missing on pages with no sensitive state-changing actions (e.g. static marketing pages, public read-only content)."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:security_headers"
  relatedNodeIds: ["component:http_response_layer", "component:xss_mitigation"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:http_response_layer"
    to: "component:security_headers"
  - relation: mitigates
    from: "component:security_headers"
    to: "component:xss_mitigation"
commonAiCodingMistakes:
  - "AI scaffolds a CSP header by copying a tutorial's permissive starter policy (`script-src 'self' 'unsafe-inline' 'unsafe-eval'`) meant to 'get things working during development' and it survives unmodified into the production config, silently defeating the CSP's actual purpose as an XSS backstop."
  - "AI adds a security-headers middleware (e.g. `helmet()`) with its framework defaults and never revisits it — defaults are reasonable but generic; framework-specific needs (inline scripts from a third-party widget, an iframe embed the product actually requires) get bolted on later by loosening the policy broadly (`unsafe-inline` everywhere) instead of narrowly (a specific nonce or hash for the one script that needs it)."
  - "AI configures headers only on the main app router/middleware entrypoint and misses static-file-serving routes, API routes mounted separately, or a reverse-proxy/CDN config layer that overrides or strips headers set by the app — leaving inconsistent header coverage across the deployment."
  - "AI treats HSTS as unconditionally safe to add and sets a long `max-age` with `includeSubDomains`/`preload` without the codebase actually terminating TLS correctly on every subdomain, which can lock out legitimate HTTP-only internal or staging subdomains."
falsePositiveGuardrails:
  - "Do not report a missing security header as a standalone `high` or `critical` finding — headers are a defense-in-depth layer. Cap severity at `medium` unless it demonstrably removes the only mitigation for a separately confirmed vulnerability (e.g. XSS + no CSP, or a sensitive form + no frame protection), in which case reference the other finding explicitly and raise its severity instead of inventing a new high-severity headers finding."
  - "Check whether headers are set upstream of the application code under review (reverse proxy, CDN edge config, API gateway, `next.config.js` headers() function, nginx/Caddy config) before concluding they are missing — grep the whole repo/infra config, not just the app server file, since these are commonly centralized outside route handlers."
  - "Do not flag `unsafe-inline`/`unsafe-eval` in a CSP that only ever serves non-HTML API responses (JSON APIs) — CSP only matters for HTML-rendering surfaces; confirm the route actually serves a browser-rendered page before flagging."
  - "Do not flag missing X-Frame-Options/frame-ancestors on routes that are intentionally embeddable (e.g. a widget explicitly designed to be iframed by customers) — confirm intent from the surrounding code/product context before treating framability as a bug."
  - "Do not flag missing Strict-Transport-Security on local dev configs, health-check-only listeners, or non-HTTPS internal services — HSTS is meaningful only for public HTTPS-terminating endpoints."
---

## Root Cause Explanation

Security headers are not, by themselves, usually the thing that gets an
application breached. They are the seatbelt, not the steering wheel: a
missing or weak header rarely creates a vulnerability out of nothing — it
removes a layer of mitigation that would otherwise have contained the blast
radius of a different bug (typically XSS or clickjacking-enabled UI
redressing). Reviewing this class correctly means resisting the temptation to
treat every missing header as an independent critical finding, while still
taking it seriously when it's the one thing standing between "we have XSS"
and "we have exploitable XSS."

The four headers this playbook covers, and what each actually buys you:

1. **Content-Security-Policy (CSP).** The single most impactful header here.
   A correctly scoped CSP (no `unsafe-inline`, no `unsafe-eval`, explicit
   allow-lists or nonces/hashes for scripts) is the last line of defense
   against XSS turning into script execution. An absent or overly permissive
   CSP (`unsafe-inline`/`unsafe-eval`, wildcard sources) doesn't create XSS,
   but it means any XSS bug elsewhere in the app is fully exploitable instead
   of contained.
2. **X-Frame-Options / frame-ancestors.** Prevents the page from being
   embedded in an attacker-controlled iframe for clickjacking (UI redressing)
   attacks — tricking a logged-in user into clicking something they can't
   see. Matters most on pages that perform a sensitive, low-friction action
   (a single button click that changes account state).
3. **Strict-Transport-Security (HSTS).** Tells the browser to never downgrade
   this origin to plain HTTP, closing the window for SSL-stripping /
   protocol-downgrade attacks on subsequent visits. Only meaningful for
   HTTPS-terminating public endpoints.
4. **X-Content-Type-Options: nosniff.** Stops the browser from MIME-sniffing
   a response into an executable context (e.g. treating an uploaded file as
   HTML/JS instead of the declared content type) — a narrow but real
   defense-in-depth measure, especially relevant for any endpoint that serves
   user-uploaded content.

## Vulnerable Patterns

```js
// Express/Node — no headers middleware at all
const app = express()
app.get('/', (req, res) => res.render('index'))
// (no helmet(), no manual header-setting anywhere)

// A permissive CSP copied from a "getting started" tutorial and never tightened
res.setHeader(
  'Content-Security-Policy',
  "default-src * 'unsafe-inline' 'unsafe-eval'"
)

// Headers set on the app's main router but not on a separately mounted API/static router
app.use(helmet())
app.use('/uploads', express.static('uploads')) // served with no headers at all

// HSTS enabled with subdomain coverage the deployment doesn't actually support
res.setHeader(
  'Strict-Transport-Security',
  'max-age=63072000; includeSubDomains; preload'
) // set even though staging.example.com is still HTTP-only
```

## Data Flow Tracing Guide

1. Identify every place headers could be set: app-level middleware
   (`helmet`, `next-safe`, `flask-talisman`, hand-rolled `res.setHeader`
   calls), and infrastructure config outside the app code (nginx/Caddy/Apache
   config, CDN edge rules, API gateway config, `next.config.js` `headers()`).
   Headers set upstream (reverse proxy/CDN) count — do not conclude "missing"
   from app code alone if infra config wasn't checked.
2. For CSP specifically: find the actual policy string being sent (not just
   "helmet is imported" — confirm the CSP directive block and its
   `script-src`/`style-src` values). Distinguish a default framework policy
   from one that's been explicitly loosened.
3. Cross-reference against confirmed findings from other playbooks in this
   scan (particularly XSS/injection findings). If an XSS finding exists and
   no CSP is present, that's the scenario where this playbook's severity
   should be elevated — reference the XSS finding's id.
4. For clickjacking: identify which routes perform sensitive, low-friction,
   state-changing actions (account settings, payment confirmation, admin
   toggles) versus purely informational pages. Severity differs meaningfully
   between the two.
5. For HSTS: confirm the deployment is HTTPS-only end-to-end (check for HTTP
   listeners, redirect config) before treating missing/short-max-age HSTS as
   meaningful.

## Evidence Checklist

- [ ] The exact response header set (or its absence, confirmed by checking
      both app code and infra/CDN config) is cited with file + line, or an
      explicit statement that both app and infra config were checked and
      neither sets it.
- [ ] If claiming a CSP issue: the exact policy string is quoted, not
      paraphrased.
- [ ] If elevating severity due to interaction with another finding (e.g. an
      XSS finding lacking a CSP backstop), that finding's id is cited
      explicitly.
- [ ] If claiming a clickjacking-relevant gap: the specific sensitive action
      reachable on the unprotected page is named concretely, not asserted
      generically.
- [ ] Severity is capped at `medium` unless tied to a specific, cited,
      separately-confirmed finding.

## Attack Scenario Template

> [Header] is missing/misconfigured on [specific route/page]. Because
> [specific consequence — e.g. "the page can be framed by an attacker-controlled
> origin" or "no CSP backstop exists"], combined with [another finding id, if
> applicable], an attacker can [concrete impact, e.g. "trick an authenticated
> user into clicking a disguised 'delete account' button" or "execute the
> injected script from finding X because no CSP blocks it"].

If there is no concrete downstream consequence to cite (no sensitive action,
no companion finding), the scenario should say so plainly and the finding
should be reported at `low` severity as a hardening recommendation, not
framed as an active attack path.

## Graph Mapping Instructions

- Ensure a `component:security_headers` node exists on the first
  headers-related finding, with a `depends_on` edge from
  `component:http_response_layer`.
- Add a `mitigates` edge from `component:security_headers` to
  `component:xss_mitigation` to represent the defense-in-depth relationship —
  this is what lets the graph mapper connect a missing-CSP finding to an
  existing XSS finding's severity.
- Each concrete gap becomes its own `finding:<uuid>` node of type
  `vulnerability` with a `causes` edge from `component:security_headers`.
- If a headers finding amplifies a separately identified finding (XSS,
  clickjackable sensitive action), add an `amplifies` edge from the headers
  finding node to that other finding node, and say so explicitly in the
  `reasoning` field so severity aggregation reflects the compounding risk
  rather than double-counting two unrelated low-severity issues.
