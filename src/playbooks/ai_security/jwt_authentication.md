---
id: ai_security.jwt_authentication
title: JWT Authentication
category: ai_security
vulnerabilityClass: broken_authentication
appliesToStack: any stack issuing or verifying JWTs
requiresAnyTag:
  - jwt
  - next-auth
  - clerk
  - supabase
  - firebase
  - better-auth
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A07:2021 Identification and Authentication Failures"
cweRefs:
  - "CWE-347"
  - "CWE-321"
  - "CWE-798"
realWorldReferences:
  - title: "Cisco IOS XE Wireless Controller — Hard-Coded JWT Signing Key (CVE-2025-20188, CVSS 10.0)"
    url: "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iox-wlc-auth-BX2VJZAj"
    type: vendor_security_advisory
  - title: "socfortress/CoPilot — Hardcoded JWT secret allows unauthenticated full admin compromise and lateral movement into all integrated SOC tools (GHSA-4gxj-hw3c-3x2x, CVE-2026-42869)"
    url: "https://github.com/socfortress/CoPilot/security/advisories/GHSA-4gxj-hw3c-3x2x"
    type: vendor_security_advisory
  - title: "Linktree — Account takeover via improper JWT expiration validation (HackerOne #1760403)"
    url: "https://hackerone.com/reports/1760403"
    type: bug_bounty_disclosure
  - title: "PortSwigger Web Security Academy — JWT 'none' algorithm supported"
    url: "https://portswigger.net/kb/issues/00200901_jwt-none-algorithm-supported"
    type: security_blog
  - title: "Semgrep — Hardcoded secrets, unverified tokens, and other common JWT mistakes"
    url: "https://semgrep.dev/blog/2020/hardcoded-secrets-unverified-tokens-and-other-common-jwt-mistakes/"
    type: security_blog
quickModeSummary: >
  Check JWT verification: is the algorithm pinned (no alg:none / algorithm
  confusion)? Is the secret/key hardcoded or a weak fallback? Are decoded
  claims (role, is_admin) trusted without a server-side re-check before
  sensitive actions? Is every state-changing route that should require auth
  actually wired to auth middleware?
fileSelectionHint:
  roles: ["auth", "middleware", "route_handler"]
  matchImports: ["jsonwebtoken", "jose", "next-auth", "pyjwt", "python-jose"]
  matchAuthMapTags: ["jwt"]
  maxFiles: 8
  priorityOrder: ["auth", "middleware", "route_handler"]
severityHeuristics:
  critical:
    - "Signature verification disabled or algorithm confusion possible (alg:none accepted, or algorithms not pinned)"
    - "Secret is hardcoded in source or a trivially guessable fallback"
  high:
    - "Token has no/very long expiry and no revocation mechanism"
    - "Sensitive claims (role, is_admin, tenant_id) trusted without re-verification server-side per request"
  medium:
    - "Token stored in localStorage (XSS-exfiltratable) instead of an httpOnly cookie"
  low:
    - "Missing iss/aud claim validation in a single-audience system (defense-in-depth gap only)"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:jwt"
  relatedNodeIds: ["component:authentication", "component:session_management"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:authentication"
    to: "component:jwt"
  - relation: protects
    from: "component:jwt"
    to: "component:api_security"
commonAiCodingMistakes:
  - "AI scaffolds JWT verification correctly in one route handler, then copy-pastes an unverified or simplified check into a newly added route, creating inconsistent enforcement across the codebase."
  - "AI writes a hardcoded fallback secret (e.g. `secret || 'dev-secret'`) during scaffolding that survives unnoticed into a production config."
  - "AI implements verification inline per-route instead of centralizing it in middleware, so a route added later simply forgets to call it."
  - "AI configures `algorithms` to accept both an asymmetric and a symmetric algorithm (e.g. `['RS256', 'HS256']`) to 'be flexible' about token formats, opening a key-confusion attack: an attacker signs a forged token with HMAC using the server's public RSA key as the secret, and the accept-both-algorithms verifier treats it as valid (CVE-2016-10555-class bug, as seen in real deployments such as Cisco IOS XE's CVE-2025-20188)."
  - "AI copies a JWT expiration/claims check from a tutorial that validates the signature but skips explicit `exp`/`nbf` validation (relying on default library behavior that varies by library and version), producing tokens that are accepted long after they should have expired — mirroring the root cause behind the Linktree JWT account-takeover disclosure (HackerOne #1760403)."
falsePositiveGuardrails:
  - "Do not flag if verification happens in framework-level middleware/plugin code outside the scanned file set (e.g. next-auth, a well-known library's internal implementation) — check auth_map/route_map before concluding verification is missing."
  - "Do not flag short-lived, library-managed tokens (e.g. next-auth session tokens) using the same severity heuristics written for hand-rolled JWT — those libraries handle algorithm pinning internally; focus instead on how claims from `getServerSession`/`getToken` are used downstream."
  - "A route with no auth middleware is not automatically a vulnerability — cross-check whether it's an intentionally public endpoint (health check, webhook receiver, public content) before writing a Finding."
  - "Don't treat a mixed `algorithms: ['RS256', 'HS256']` array as automatically critical if the codebase only ever issues RS256 tokens and the HS256 secret is not derived from (or equal to) the RS256 public key — confirm the actual key-confusion precondition (shared/derivable key material) before citing CVE-2016-10555-class severity."
---

## Root Cause Explanation

JWT-based authentication fails in a small number of recurring ways, ranked by
how often they show up in AI-assisted and human-written code alike:

1. **Algorithm confusion / verification disabled.** Libraries like
   `jsonwebtoken` will accept whatever algorithm the token itself claims
   unless the caller explicitly pins `algorithms: [...]`. This is a classic
   "happy path written, constrained path forgotten" bug — code that works in
   every manual test but accepts a forged token signed with a different
   algorithm (or none at all).
2. **Trust boundary confusion.** Claims decoded from a JWT (role, user id,
   tenant id) get used directly in business logic without a server-side
   re-check against the source of truth (the database). A forged or stale
   claim can then bypass authorization even when the signature check itself
   is intact.
3. **Secret/key management.** Symmetric secrets get hardcoded, committed, or
   given a weak fallback default that's meant to be temporary during
   scaffolding but never gets replaced before deploy.
4. **Inconsistent enforcement across routes.** Because JWT checks are easy to
   copy-paste, a codebase built incrementally (especially by an AI coding
   agent working route-by-route) often ends up with some routes correctly
   protected and structurally identical routes added later that aren't.

## Vulnerable Patterns

Look for shapes like these (illustrative, not exhaustive — reason about
equivalents in the actual stack you're reviewing, don't string-match):

```js
// Missing algorithm pinning — accepts whatever alg the token claims
jwt.verify(token, secret) // should be: { algorithms: ['HS256'] }

// Fallback secret that survives into production
const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me'

// Trusting a decoded claim without a DB re-check before a sensitive action
const { role } = jwt.decode(token)
if (role === 'admin') { /* ...perform destructive action... */ }
```

## Data Flow Tracing Guide

To evaluate this playbook responsibly, trace the following before writing any
Finding:

1. For every route in `route_map`: does its middleware chain include an entry
   also present in `auth_map`? If a route handles a state-changing verb
   (POST/PUT/PATCH/DELETE) and has no auth middleware entry, that's evidence
   — not yet a conclusion. Check whether the route is an intentionally public
   exception (e.g. `/api/webhooks/*`, `/api/health`) before flagging it.
2. Where is the JWT secret/key sourced from? Follow it to its declaration —
   is it read from an environment variable with no fallback, a fallback
   string literal, or a config file?
3. Where are claims decoded, and where are they used? If a claim is read in
   one file and used in a sensitive branch in another, cite both locations.
4. Is there a re-fetch from the database for high-privilege actions, or is
   the token's claim trusted as-is?

## Evidence Checklist

Before submitting a Finding for this playbook, confirm:

- [ ] At least one concrete code snippet with an exact file + line range is
      attached as evidence — do not paraphrase, quote the actual line(s).
- [ ] If claiming a missing-algorithm-pinning issue: the exact `verify(...)`
      call site is cited.
- [ ] If claiming a hardcoded/weak-fallback secret: the exact line where the
      secret/key is sourced is cited.
- [ ] If claiming a trust-boundary issue: both the exact line where the claim
      is read AND the exact line where it's used in a sensitive branch are
      cited.
- [ ] Confirmation that the route/flow in question is not an intentionally
      public exception (checked against `route_map` context).

A finding without at least one concrete code-snippet evidence entry must not
be submitted.

## Attack Scenario Template

> An attacker obtains or forges a token where [claim] = [privileged value].
> Because [specific code location] does not [missing check], a request
> reaches [specific endpoint/action], resulting in [concrete impact specific
> to this repo, e.g. "arbitrary read of another user's billing records" —
> not a generic description].

Fill every bracket concretely from evidence gathered in this repo. If a
bracket can't be filled from real evidence, the scenario is speculative and
severity must be capped at `medium`, with a note that exploitability is
unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:jwt` node exists (create it on the first
  JWT-related finding in a scan) with a `depends_on` edge from
  `component:authentication`.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from `component:jwt` (or a more
  specific root-cause component, e.g. `component:secrets` if the root cause
  is secret management) to the finding node.
- If a finding enables reaching a specific external system or sensitive
  component (e.g. a database, a payments provider), add an `enables` edge
  from the finding node to that component's node id.
- Root cause vs. symptom: if a finding is *caused by* another finding already
  identified in this scan (e.g. a hardcoded-secret finding causes a JWT
  forgery finding), say so explicitly in the finding's `reasoning` field so
  the graph mapper can wire a `causes` edge between the two finding nodes
  rather than treating them as unrelated.
