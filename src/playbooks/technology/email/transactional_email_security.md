---
id: technology.email.transactional_email_security
title: "Transactional Email: Injection, Spoofing & Enumeration"
category: technology
vulnerabilityClass: injection
appliesToStack: email
requiresAnyTag: ["email"]
deepOnly: false
reviewPass: 2
owaspRefs:
  - "A03:2021 Injection"
  - "A04:2021 Insecure Design"
  - "A07:2021 Identification and Authentication Failures"
cweRefs:
  - "CWE-93"
  - "CWE-640"
  - "CWE-204"
realWorldReferences:
  - title: "OWASP — Testing for Email Header Injection (SMTP/IMAP command and header injection)"
    url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_Email_Injection"
    type: security_blog
  - title: "Host header injection poisoning password-reset links to hijack accounts (Acunetix / classic reset-link write-ups)"
    url: "https://www.acunetix.com/blog/articles/password-reset-poisoning/"
    type: security_blog
  - title: "SendGrid — abuse / spoofing incidents from compromised or misconfigured sending, and the need for verified senders + SPF/DKIM/DMARC"
    url: "https://sendgrid.com/en-us/blog/email-security-best-practices"
    type: security_blog
  - title: "OWASP — Forgot Password and account-enumeration guidance (uniform responses, token entropy/expiry)"
    url: "https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html"
    type: security_blog
quickModeSummary: >
  Review transactional email (password reset, verification, invites,
  notifications) sent via Resend/SendGrid/Postmark/SMTP. Key risks: email
  header injection (user input reaching To/Cc/Bcc/Subject/Reply-To or raw
  headers unescaped, letting an attacker inject recipients or headers via
  newlines), password-reset poisoning (reset link built from the request Host
  header or a user-supplied base URL, so an attacker sets the link's domain
  and captures tokens), weak reset/verification tokens (low entropy,
  predictable, no expiry, single-use not enforced, or the token compared
  non-constant-time), account enumeration via different responses/timing for
  known vs. unknown emails, HTML-email XSS/content injection where
  user-provided content is interpolated into the HTML body unescaped, and
  API keys for the email provider committed or exposed. Also confirm the
  sending identity is a verified domain with SPF/DKIM/DMARC referenced in
  config, not an arbitrary from-address.
fileSelectionHint:
  roles: ["service", "controller", "route_handler", "mailer", "auth", "template"]
  matchImports: ["resend", "@sendgrid/mail", "postmark", "nodemailer", "@aws-sdk/client-ses"]
  matchAuthMapTags: ["email", "auth"]
  maxFiles: 12
  priorityOrder: ["mailer", "auth", "service", "route_handler"]
severityHeuristics:
  critical:
    - "A password-reset or email-verification link is constructed from the request Host header, X-Forwarded-Host, or a user-supplied base URL, so an attacker can poison the link domain and capture the victim's reset/verification token (account takeover)"
    - "A reset/verification token is weak: predictable/low-entropy (e.g. derived from timestamp or a short numeric code without rate limiting), not expired, not single-use, or compared non-constant-time, enabling token guessing/reuse"
  high:
    - "User input reaches email headers (To/Cc/Bcc/Reply-To/Subject or raw header construction) without stripping CR/LF, enabling header/recipient injection to send to arbitrary recipients or forge headers"
    - "User-provided content is interpolated into an HTML email body without escaping, enabling content/HTML injection (phishing content, or XSS in webmail contexts that render it)"
  medium:
    - "Account enumeration: the forgot-password / signup / verification flow returns distinguishable responses (or timing) for existing vs. non-existing emails, letting an attacker enumerate registered accounts"
    - "The sending from-address/domain is arbitrary or unverified (no SPF/DKIM/DMARC alignment referenced), enabling spoofing/deliverability abuse, or reset flows lack rate limiting enabling email-bombing"
  low:
    - "Email provider API key handling is loose (read from a non-secret source) though not committed, or links/tokens are logged, or bounce/complaint handling is absent"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:email_service"
  relatedNodeIds: ["component:authentication", "component:input_validation"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:email_service"
    to: "component:input_validation"
  - relation: enables
    from: "component:email_service"
    to: "component:authentication"
commonAiCodingMistakes:
  - "AI builds the password-reset URL from the incoming request's Host header (`https://${req.headers.host}/reset?token=...`) instead of a trusted, configured base URL, so an attacker who sends the reset request with a spoofed Host receives a link pointing at their own domain — when the victim clicks it, the token leaks (reset poisoning → account takeover)."
  - "AI generates a reset/verification token with a weak source (a short numeric code, Math.random, a timestamp, or a low-byte-count string) and/or never sets an expiry or enforces single-use, making tokens guessable or replayable."
  - "AI interpolates user input directly into email header fields or raw header strings without stripping newlines, so `name\\r\\nBcc: attacker@evil.com` injects an additional recipient/header (header injection)."
  - "AI returns 'No account with that email' for unknown addresses but 'Reset link sent' for known ones (or responds noticeably faster for one), enabling account enumeration — the flow should return an identical response regardless."
  - "AI interpolates user-controlled content into the HTML email template with string concatenation, no escaping, enabling content injection / phishing and XSS in rendering contexts."
  - "AI commits the Resend/SendGrid/Postmark API key or reads it from a client-exposed variable, and sends from an arbitrary from-address without a verified domain / SPF-DKIM-DMARC, inviting spoofing and abuse."
falsePositiveGuardrails:
  - "Do not flag reset-link construction that uses a trusted, server-configured base URL (an env var / constant, not the request Host) — that is the correct pattern. Confirm the origin of the URL's host portion."
  - "A token generated from a CSPRNG (crypto.randomBytes / randomUUID) with sufficient length, a stored expiry, single-use enforcement, and constant-time comparison is correct — quote the generation and validation code before flagging weak tokens."
  - "Provider SDKs (Resend/SendGrid/Postmark) that take recipient/subject as structured parameters generally handle header encoding — header injection is primarily a risk with raw SMTP/nodemailer header construction or when user input is concatenated into a header string. Confirm the sink is actually raw header building before flagging."
  - "A forgot-password flow that returns an identical generic response for all inputs (and ideally uniform timing) is not enumerable — do not flag when responses are already uniform."
  - "Email content that is fully server-controlled/templated with escaped interpolation of user values is not content injection — confirm user input actually reaches the body unescaped."
---

## Root Cause Explanation

Transactional email sits at a dangerous intersection: it's an authentication
primitive (password reset, verification, invites are how accounts are
recovered and provisioned) and it's an output channel that mixes user input
with structured protocol data (headers) and rendered content (HTML). Each
property produces a distinct vulnerability class, and AI-generated code tends
to get the authentication-primitive parts wrong because they require security
reasoning that isn't visible in the happy-path flow.

The most severe is password-reset poisoning. The reset email contains a link,
and the link needs a domain. AI frequently builds that domain from the
incoming request's `Host`/`X-Forwarded-Host` header because it's "the current
host" — but that header is attacker-controlled. An attacker triggers a reset
for the victim's account while spoofing the Host to their own domain; the
victim receives a legitimate-looking email whose link points at the
attacker, and clicking it hands over the reset token. The fix is to always
build such links from a trusted, server-configured base URL. Closely related
is weak token design: low entropy, no expiry, no single-use enforcement, or
non-constant-time comparison all make the token itself the weak link.

The output-channel issues are header injection (user input with CR/LF
reaching To/Cc/Bcc/Reply-To or raw headers, injecting recipients/headers) and
HTML content injection (user content interpolated into the email body
unescaped). And the design-level issue is account enumeration: if the
forgot-password or signup flow responds differently for known vs. unknown
emails, it becomes an oracle for which accounts exist. Provider API-key
hygiene and verified-sender/SPF-DKIM-DMARC configuration round out the review.

## Vulnerable Patterns

```js
// Reset poisoning — link host from the request Host header
const link = `https://${req.headers.host}/reset?token=${token}`;
await resend.emails.send({ to: user.email, subject: "Reset", html: `<a href="${link}">Reset</a>` });

// Weak token + no expiry
const token = Math.floor(Math.random() * 1_000_000).toString(); // guessable, no expiry

// Header injection via raw header building
transporter.sendMail({ to: `${req.body.name} <${req.body.email}>` }); // name may contain \r\n
```

```js
// Enumeration — distinguishable responses
if (!user) return res.status(404).json({ error: "No account with that email" });
return res.json({ message: "Reset link sent" });
```

Correct shapes use a trusted base URL, a CSPRNG token with expiry/single-use,
and uniform responses:

```js
const link = `${process.env.APP_BASE_URL}/reset?token=${token}`;      // trusted host
const token = crypto.randomBytes(32).toString("hex");                  // CSPRNG
await db.resetToken.create({ userId, tokenHash: sha256(token), expiresAt: in1Hour });
// Always the same response, regardless of whether the account exists:
return res.json({ message: "If an account exists, a reset link has been sent." });
```

## Data Flow Tracing Guide

1. Locate all email-sending call sites (provider SDK / SMTP) and, for auth
   emails, trace how the link URL's host is built — trusted config vs. request
   Host/user input.
2. For reset/verification tokens: find the generation (CSPRNG vs. weak
   source), storage (hashed?), expiry, single-use enforcement, and comparison
   (constant-time?).
3. Trace user input into header fields (To/Cc/Bcc/Reply-To/Subject/raw
   headers) and check for CR/LF stripping/validation.
4. Trace user input into the HTML body and check escaping.
5. Compare the forgot-password/signup/verification responses (body and
   timing) for known vs. unknown emails.
6. Check API key sourcing and sender/domain verification config.

## Evidence Checklist

- [ ] For reset poisoning: the exact link-construction line and the origin of
      its host portion.
- [ ] For token weakness: the generation call, expiry/single-use handling,
      and comparison method quoted.
- [ ] For header/content injection: the user-input origin and the header/body
      sink, with the missing sanitization/escaping noted.
- [ ] For enumeration: the differing responses/timing quoted.

## Attack Scenario Template

> An attacker [submits a password-reset request for the victim's email while
> spoofing the Host header to attacker.com / guesses the low-entropy token /
> injects a Bcc via a newline in the name field / submits emails to observe
> which return "account exists"]. Because [file:line] [builds the reset link
> from req.headers.host / generates the token from Math.random with no expiry
> / concatenates input into an email header / returns distinct responses per
> account state], the attacker [captures the victim's reset token and takes
> over the account / reuses/guesses a valid token / sends mail to arbitrary
> recipients / enumerates registered accounts], resulting in [impact].

## Graph Mapping Instructions

- Ensure a `component:email_service` node exists, with a `depends_on` edge to
  `component:input_validation`.
- Reset-poisoning / weak-token findings add an `enables` edge from the
  finding node to `component:authentication` (they are account-takeover
  class) and should be flagged as such in `reasoning` so severity
  aggregation weighs them as auth compromises, not generic email bugs.
- Header/content-injection findings become `finding:<uuid>` nodes with a
  `causes` edge from `component:email_service`.
