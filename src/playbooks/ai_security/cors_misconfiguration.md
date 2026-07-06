---
id: ai_security.cors_misconfiguration
title: CORS Misconfiguration
category: ai_security
vulnerabilityClass: cors_misconfiguration
appliesToStack: technology-agnostic
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A05:2021 Security Misconfiguration"
cweRefs:
  - "CWE-942"
  - "CWE-346"
realWorldReferences:
  - title: "Exploiting CORS misconfigurations for Bitcoins and bounties (PortSwigger Research)"
    url: "https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties"
    type: research_paper
  - title: "Sifchain disclosed on HackerOne: CORS Misconfiguration"
    url: "https://hackerone.com/reports/1194280"
    type: bug_bounty_disclosure
  - title: "Publitas disclosed on HackerOne: CORS Misconfiguration"
    url: "https://hackerone.com/reports/2332728"
    type: bug_bounty_disclosure
  - title: "Exploiting Misconfigured CORS (Cross Origin Resource Sharing)"
    url: "https://www.geekboy.ninja/blog/exploiting-misconfigured-cors-cross-origin-resource-sharing/"
    type: security_blog
  - title: "CORS and the Access-Control-Allow-Origin response header (PortSwigger Web Security Academy)"
    url: "https://portswigger.net/web-security/cors/access-control-allow-origin"
    type: security_blog
quickModeSummary: >
  Check every CORS middleware/header configuration for: a literal wildcard
  origin (`*`) — note browsers reject `*` combined with
  `Access-Control-Allow-Credentials: true`, so watch specifically for code
  that works around this by dynamically reflecting the request's `Origin`
  header back verbatim instead of validating it against an allowlist; any
  reflect-without-validate pattern paired with credentialed requests
  (cookies, `Authorization` headers) on an endpoint that returns
  authenticated/sensitive data is the core exploitable shape.
fileSelectionHint:
  roles: ["middleware", "config", "route_handler", "api_gateway"]
  matchImports: ["cors", "flask-cors", "django-cors-headers", "fastapi.middleware.cors", "express"]
  matchAuthMapTags: []
  maxFiles: 8
  priorityOrder: ["middleware", "config"]
severityHeuristics:
  critical:
    - "Origin is dynamically reflected (echoing the request's Origin header back as Access-Control-Allow-Origin) with no allowlist check, combined with Access-Control-Allow-Credentials: true, on an endpoint that returns authenticated user data or performs a privileged action"
    - "Wildcard origin (*) is combined with credentialed requests via a workaround (e.g. manually setting Access-Control-Allow-Origin to the literal Origin header value specifically to route around the browser's *-plus-credentials restriction)"
  high:
    - "Origin is reflected without an allowlist but Access-Control-Allow-Credentials is not set — still allows any site to read non-credentialed responses, which is dangerous if the endpoint returns sensitive data gated only by an unguessable URL, API key in a custom header, or IP allowlist that CORS reflection lets an attacker proxy through a victim's browser"
    - "The allowlist check is a substring/regex match that can be bypassed (e.g. checking origin.includes('trusted.com') which also matches 'trusted.com.attacker.com' or 'nottrusted.com')"
  medium:
    - "Wildcard origin (*) is used with no credentials involved, on an endpoint that returns non-sensitive public data — low impact but worth noting as unintentional overexposure if any sensitive field could later be added"
    - "The null origin is accepted into the allowlist (exploitable via sandboxed iframes or file:// origins, and not protected by the wildcard-plus-credentials browser restriction)"
  low:
    - "CORS is enabled broadly on an internal-only or non-authenticated endpoint with no sensitive data — permissive but not currently exploitable"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:cors_policy"
  relatedNodeIds: ["component:api_security", "component:authentication"]
graphEdgeMapping:
  - relation: protects
    from: "component:cors_policy"
    to: "component:api_security"
  - relation: depends_on
    from: "component:cors_policy"
    to: "component:authentication"
commonAiCodingMistakes:
  - "AI scaffolds a CORS middleware configured with origin: '*' during initial development to unblock frontend-backend integration quickly, then later adds cookie-based auth or Authorization headers to the same routes without revisiting the CORS config — the combination becomes exploitable only after auth was added, and nothing re-triggers a review of the CORS settings at that point."
  - "AI is asked to 'fix a CORS error' (a very common support request when a frontend can't reach an API) and the fastest fix that makes the browser error disappear is to reflect the Origin header dynamically (`res.header('Access-Control-Allow-Origin', req.headers.origin)`) instead of adding the actual frontend origin to an allowlist — this satisfies the browser's wildcard-plus-credentials restriction while defeating its purpose entirely, and the code looks like a deliberate, correct-looking allowlist pattern to a reviewer skimming it."
  - "AI copies a CORS configuration snippet from a tutorial or Stack Overflow-style example that uses reflection or wildcarding for local-development convenience, and that snippet ships unchanged to production because it was never flagged as dev-only."
  - "AI implements an origin allowlist using a naive substring or regex check (e.g. `origin.endsWith('example.com')`) that is bypassable by an attacker-controlled subdomain or lookalike domain, appearing correct in casual review but not equivalent to an exact-match allowlist."
falsePositiveGuardrails:
  - "Wildcard origin (*) with Access-Control-Allow-Credentials absent/false on a genuinely public, unauthenticated API (no cookies, no Authorization header read server-side, no session state) is not a finding — this is the correct configuration for a public API."
  - "Do not flag CORS configuration in code paths that are demonstrably dev/test-only (e.g. gated behind NODE_ENV !== 'production', or only present in a docker-compose/local dev server config) unless there's no evidence the production config differs — if both exist, cite the production one."
  - "An explicit, exact-string allowlist of known frontend origins (not a substring/regex match, not dynamic reflection) combined with credentials is the correct pattern — do not flag this as a finding even though it reads similarly to reflection at a glance; verify the check is genuinely a fixed-list exact match before concluding it's safe, and verify it's genuinely a fixed-list exact match (not reflection) before flagging it as unsafe."
  - "A framework's default CORS middleware with no explicit configuration is not automatically permissive — check the framework's actual default (e.g. Express's `cors` package defaults to reflecting all origins if used with zero config, which IS a finding; other frameworks default to same-origin-only, which is NOT). Verify the specific library's default behavior rather than assuming."
---

## Root Cause Explanation

Cross-Origin Resource Sharing exists to relax the browser's Same-Origin
Policy in a controlled way — a server explicitly opts specific origins into
reading its responses. The mechanism is entirely server-declared: the browser
sends the requesting page's `Origin` header, and trusts whatever the server
echoes back in `Access-Control-Allow-Origin` as the set of origins permitted
to read the response. There is no browser-side validation of *which* origin
the server should be trusting — that job belongs entirely to the server's
configuration.

This creates two closely related failure modes:

1. **Wildcard-plus-credentials, worked around.** The CORS spec explicitly
   forbids combining `Access-Control-Allow-Origin: *` with
   `Access-Control-Allow-Credentials: true` — browsers will refuse to expose
   the response to script if both are present, specifically because a true
   wildcard-with-credentials would expose every authenticated user's data to
   every website on the internet. Because this combination is blocked,
   developers under time pressure to "make CORS work" for a credentialed
   request often replace the wildcard with **dynamic origin reflection** —
   reading the incoming `Origin` header and echoing it back verbatim as the
   allowed origin. This technically isn't a wildcard, so the browser accepts
   it, but it has the exact same effect as a wildcard: literally any origin
   is accepted, defeating the restriction the browser was trying to enforce.
2. **Reflection without an allowlist, full stop.** Even without credentials
   in play, blindly reflecting the `Origin` header (rather than checking it
   against a known allowlist) means the server has no actual origin policy —
   it will say "yes, you're allowed" to every request, which becomes
   dangerous the moment the response contains anything sensitive, or the
   moment the endpoint is used to proxy around another access control (IP
   allowlisting, a secret in a custom header the browser will still attach).

Both failure modes are attractive to AI-assisted scaffolding because they are
the *simplest possible way to make a CORS error message disappear* — reading
the incoming Origin and reflecting it back always "works" from a
happy-path-testing perspective, since it accepts literally everything.

## Vulnerable Patterns

```js
// Express — wildcard, worked around via dynamic reflection to still allow credentials
app.use(cors({
  origin: (origin, callback) => callback(null, origin), // reflects ANY origin
  credentials: true
}));

// Express — same effect, written more explicitly (still trivially exploitable)
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin);
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});

// Flask — flask-cors configured with a wildcard resource pattern and supports_credentials
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

// Naive allowlist — substring check bypassable by attacker-controlled subdomains
const allowed = origin && origin.includes('myapp.com');
if (allowed) res.header('Access-Control-Allow-Origin', origin);
// matches https://myapp.com.attacker.com just as well as https://myapp.com
```

Correct pattern for comparison — exact-match allowlist, no reflection:

```js
const ALLOWED_ORIGINS = new Set(['https://app.example.com', 'https://admin.example.com']);
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.has(origin)) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));
```

## Data Flow Tracing Guide

1. Locate every place `Access-Control-Allow-Origin` is set — via a CORS
   middleware/library configuration (`cors`, `flask-cors`,
   `django-cors-headers`, `fastapi.middleware.cors.CORSMiddleware`, framework
   defaults) or manually via a raw header write. Frameworks sometimes have
   multiple CORS configurations (a global one plus per-route overrides) —
   find all of them, not just the first.
2. For each configuration, determine: is the origin value a literal `*`, a
   dynamic reflection of `req.headers.origin`/`request.headers['origin']`, an
   allowlist array/set checked with exact string equality, or a
   substring/regex check?
3. For each configuration, check whether `Access-Control-Allow-Credentials`
   is set to `true` alongside it, and whether the routes it applies to
   actually rely on credentials (cookie-based sessions, `Authorization`
   header read server-side) — a permissive CORS policy on a route with no
   credential-based auth is lower severity than one that is.
4. For the routes covered by a wildcard/reflected/weak-allowlist policy,
   check what the response actually contains — does it include
   user-specific/authenticated data, or trigger a state-changing action? This
   determines whether the misconfiguration is exploitable or just
   unnecessarily permissive.
5. If an allowlist check uses `includes`/`endsWith`/regex rather than exact
   equality against a known list, construct the bypass mentally (what
   attacker-controlled origin string would pass the check) before flagging
   it, and cite the specific bypassable string in the finding.

## Evidence Checklist

- [ ] The exact file + line of the CORS configuration is cited, quoting the
      actual origin-handling logic (not paraphrased).
- [ ] Confirmation of whether `Access-Control-Allow-Credentials: true` is
      present for the same configuration/route set, cited at its own line if
      set separately.
- [ ] For a reflection/wildcard finding: identification of the specific
      route(s) it applies to, and what sensitive data or action those routes
      expose.
- [ ] For a weak-allowlist finding: a concrete example origin string that
      would bypass the check, derived from the actual check logic.
- [ ] Confirmation the configuration is reachable in production (not
      exclusively behind a dev/test-only code path).

## Attack Scenario Template

> The CORS configuration at [file:line] [reflects the Origin header
> verbatim / uses a wildcard origin / uses a bypassable allowlist check:
> specific bypass string], and [does/does not] set
> Access-Control-Allow-Credentials: true. An attacker hosts a page on
> [attacker-controlled origin] that issues a credentialed
> fetch/XMLHttpRequest to [specific endpoint], which returns
> [concrete sensitive data / performs concrete privileged action]. Because
> the victim's browser attaches their session cookie/credentials
> automatically and the server's CORS policy accepts the attacker's origin,
> the attacker's page can read the response and exfiltrate
> [concrete impact — e.g. "the victim's account details and API tokens",
> "trigger a funds transfer/settings change on the victim's behalf"].

Fill every bracket concretely from evidence gathered in this repo. If the
targeted endpoint's response contents can't be confirmed from available
context, cap severity at `medium` and note that exploitability is
unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:cors_policy` node exists on the first
  CORS-related finding, with a `depends_on` edge to `component:authentication`
  if the policy interacts with credentialed routes.
- Each concrete misconfiguration becomes its own `finding:<uuid>`
  vulnerability node with a `causes` edge from `component:cors_policy`.
- If the exposed route returns data belonging to a specific component (e.g.
  a user-profile API, a billing API), add an `enables` edge from the finding
  node to that component's node id, since CORS misconfiguration is a
  cross-cutting enabler rather than the ultimate target.
- If a CORS finding is present alongside an authentication finding (e.g. weak
  session cookie handling) in the same scan, note in the finding's
  `reasoning` field whether the CORS issue amplifies that other finding
  (e.g. makes a session-riding attack possible cross-origin) so the graph
  mapper can wire an `enables` edge between the two findings.
