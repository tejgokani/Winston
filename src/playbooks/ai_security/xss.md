---
id: ai_security.xss
title: Cross-Site Scripting (XSS)
category: ai_security
vulnerabilityClass: xss
appliesToStack: anything that renders HTML (frontend frameworks, server templating, fullstack frameworks)
requiresAnyTag:
  - frontend
  - templating
  - nextjs
  - nuxt
  - sveltekit
  - remix
  - astro
  - django
  - flask
  - rails
  - laravel
  - php
  - ruby
  - java
  - dotnet
  - go
  - expo
deepOnly: false
reviewPass: 3
owaspRefs:
  - "A03:2021 Injection"
cweRefs:
  - "CWE-79"
  - "CWE-116"
realWorldReferences:
  - title: "GitLab disclosed on HackerOne: Stored XSS in Notes (with CSP bypass for gitlab.com)"
    url: "https://hackerone.com/reports/1481207"
    type: bug_bounty_disclosure
  - title: "GitLab disclosed on HackerOne: Stored XSS in \"Create Groups\""
    url: "https://hackerone.com/reports/647130"
    type: bug_bounty_disclosure
  - title: "HackerOne: Markdown parsing issue enables insertion of malicious tags and event handlers (Redcarpet, Report #46916)"
    url: "https://hackerone.com/reports/46916"
    type: bug_bounty_disclosure
  - title: "Imgur disclosed on HackerOne: XSS via React element spoofing (dangerouslySetInnerHTML)"
    url: "https://hackerone.com/reports/124277"
    type: bug_bounty_disclosure
  - title: "OWASP Cross Site Scripting Prevention Cheat Sheet"
    url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
    type: security_blog
  - title: "OWASP DOM based XSS Prevention Cheat Sheet"
    url: "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"
    type: security_blog
quickModeSummary: >
  Search for dangerouslySetInnerHTML (React), v-html (Vue), {@html} (Svelte),
  innerHTML/outerHTML/document.write (vanilla DOM), and server-template string
  concatenation into HTML. For each hit, trace the value back to its source —
  is it markdown/rich-text/LLM output, a URL param, postMessage data, or
  another user's stored content (comment, bio, display name)? If yes and no
  sanitizer (DOMPurify or equivalent) sits between source and sink, that's the
  finding. Framework auto-escaping (JSX {expr}, Vue {{ }}, Svelte {expr})
  protects the default text-binding path only — these APIs exist specifically
  to opt out of it.
fileSelectionHint:
  roles: ["frontend_component", "route_handler", "template", "api_response_renderer"]
  matchImports: ["dompurify", "sanitize-html", "marked", "markdown-it", "react-markdown", "showdown", "js-xss"]
  matchAuthMapTags: []
  maxFiles: 10
  priorityOrder: ["frontend_component", "template", "route_handler"]
severityHeuristics:
  critical:
    - "User-controlled or LLM-generated HTML/markdown is rendered via dangerouslySetInnerHTML/v-html/{@html}/innerHTML with no sanitization, on a page reachable by other users (stored XSS with session/cookie/token theft potential)"
    - "DOM-based XSS where a URL fragment/query param or postMessage payload flows directly into innerHTML/document.write/eval with no origin check on postMessage and no encoding"
  high:
    - "Stored user content (comment, profile bio, display name) is escaped correctly at the point it's first rendered, but a second rendering path (admin panel, notification email as HTML, export/report view, RSS/API consumer) renders the same field raw"
    - "A sanitizer library is present but configured with an overly permissive allowlist (e.g. allowing <script>, on* attributes, javascript: URLs, or arbitrary style attributes) or is version-pinned to a release with a known bypass"
  medium:
    - "Server-rendered template concatenates user input into an HTML attribute or tag body using string interpolation instead of the templating engine's auto-escaping helper, but the input is constrained to a narrow, low-privilege context (e.g. an internal admin tool with no external users)"
    - "Sanitization happens client-side only, with no defense-in-depth (CSP, server-side re-sanitization) if the client-side sanitizer is bypassed or removed"
  low:
    - "Missing Content-Security-Policy header as a defense-in-depth layer, with no other evidence of an actual unsanitized sink"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:xss"
  relatedNodeIds: ["component:input_validation", "component:frontend_rendering", "component:user_generated_content"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:frontend_rendering"
    to: "component:xss"
  - relation: protects
    from: "component:xss"
    to: "component:session_management"
commonAiCodingMistakes:
  - "AI scaffolds a 'render this user's rich-text bio/comment' feature using dangerouslySetInnerHTML / v-html / {@html} directly on stored HTML, because that's the fastest way to make formatted text show up, and never wires in DOMPurify or an equivalent sanitizer — this is precisely the shape of the GitLab Notes and Create Groups stored-XSS disclosures (HackerOne #1481207, #647130)."
  - "AI adds a markdown-to-HTML rendering step (marked, markdown-it, showdown) for LLM-generated or user-generated content and trusts the markdown library's default output as 'safe' because it's not raw user HTML — markdown parsers routinely leave event-handler attributes and javascript: URLs reachable through the rendered output unless a sanitizer runs afterward, as documented in the Redcarpet HackerOne disclosure (#46916)."
  - "AI builds a preview pane or 'render what the LLM just generated' feature (common in AI-app scaffolding) that pipes model output straight into innerHTML/dangerouslySetInnerHTML on the assumption that LLM output is trusted because it came from 'our own model' — but if any part of the model's context includes untrusted content (user input, fetched web pages, retrieved documents), that content can carry an injected payload the model faithfully reproduces (prompt-injection-to-XSS)."
  - "AI writes a sanitizer call in the component that first renders a piece of stored content, then later adds a second rendering surface for the same field (an admin view, a digest email template, a PDF/CSV export, a public API that echoes the field back as HTML) and forgets sanitization has to happen again at that new sink — sanitization is a per-sink property, not a per-field one."
  - "AI implements DOM-based rendering fed by `window.location`, `document.referrer`, or a `postMessage` handler with no origin check and no encoding, because the tutorial it's pattern-matching on demonstrates the 'happy path' of extracting a query param and displaying it, not the injection case."
  - "AI reaches for a regex-based blocklist (strip <script> tags, strip 'javascript:') instead of an allowlist-based sanitizer or output encoding — OWASP explicitly warns blocklists are trivially bypassed (mXSS, encoded payloads, alternate event handlers) and are not equivalent to real sanitization."
falsePositiveGuardrails:
  - "Do not flag dangerouslySetInnerHTML/v-html/{@html} usage where the value passed in is provably a compile-time constant or output of a sanitizer call (DOMPurify.sanitize(...), sanitize-html(...)) in the same expression — verify the sanitizer call wraps the actual untrusted value, not a static string next to it."
  - "Do not flag JSX {expr}, Vue {{ }}/`:text`, or Svelte {expr} text bindings as XSS risks — these are the framework's auto-escaping default path and are not equivalent to dangerouslySetInnerHTML/v-html/{@html}."
  - "Before flagging a markdown renderer, check whether the specific library already sanitizes by default (e.g. some react-markdown configurations strip raw HTML unless an explicit rehype-raw/allowDangerousHtml-style plugin is enabled) — cite the actual renderer config, not just the presence of a markdown import."
  - "Do not flag server-side templating engines with auto-escaping enabled by default (Jinja2 autoescape, most modern Go/Rails/Django template helpers) unless you find an explicit `| safe`, `Markup(...)`, `{% autoescape false %}`, or raw string-concatenation bypass at the specific line — the presence of a templating engine is not itself a finding."
  - "A CSP header alone does not make an unsanitized sink safe to leave unflagged — CSP is defense-in-depth per OWASP guidance, not a substitute for sanitization at the sink; but its absence also should not be escalated to critical/high on its own without a concrete unsanitized sink."
  - "Distinguish reflected/stored XSS (user-controlled data rendered unsafely) from self-XSS (only exploitable by pasting attacker-supplied code into your own devtools/URL bar) — self-XSS with no plausible cross-user delivery path is not a valid finding at this playbook's severity levels."
---

## Root Cause Explanation

XSS (CWE-79) exists because HTML, CSS, and JavaScript share the same document
context: anywhere untrusted data is interpreted *as markup or code* rather
than *as data*, an attacker who controls that data controls what runs in the
victim's browser. Modern frameworks made the common case safe by default —
JSX `{expr}`, Vue `{{ }}`, Svelte `{expr}`, and most server templating
engines auto-escape text bindings — but every framework also ships an
explicit escape hatch for cases where a developer legitimately needs to
render markup (`dangerouslySetInnerHTML`, `v-html`, `{@html}`, direct
`innerHTML` assignment). These escape hatches are opt-in and unsanitized by
design: the framework is trusting the developer to have already sanitized
whatever is passed in. AI coding assistants routinely reach for the escape
hatch to satisfy a "render this rich text/markdown/LLM output" requirement
because it's the most direct way to make the feature work, without carrying
forward the sanitization step that made the pattern safe in the source
material it was trained on (or without the tutorial it's mimicking ever
having covered it in the first place).

The three shapes to look for, in order of how often they appear in
AI-generated code:

1. **Framework escape hatches used on untrusted/user-controlled HTML.**
   `dangerouslySetInnerHTML={{ __html: comment.body }}`,
   `v-html="post.content"`, `{@html renderedMarkdown}` — anywhere the value
   passed in ultimately traces back to something another user, an external
   API, or an LLM produced, and no sanitizer sits between source and sink.
2. **Server-rendered templates that concatenate instead of encode.**
   String-built HTML responses (`res.send('<div>' + name + '</div>')`,
   f-string/format-string HTML construction) bypass whatever auto-escaping
   the app's templating layer would otherwise provide.
3. **DOM-based XSS via client-side sinks fed by untrusted sources.**
   `innerHTML`, `outerHTML`, `document.write`, `insertAdjacentHTML`, or
   `eval`-adjacent APIs fed by `location.hash`/`location.search`,
   `document.referrer`, or a `postMessage` listener with no origin check.
   This class is entirely client-side — no server round-trip is required —
   and is easy to miss because it doesn't show up in server-side request
   logs or typical route-map/auth-map tooling.

**Stored vs. reflected vs. DOM-based matters for severity, not for whether
it's a finding.** Stored XSS (payload persisted — a comment, a bio, a
markdown document — then rendered to other users later, unsanitized) is
generally the most severe because it requires no social engineering per
victim; the GitLab Notes and Create Groups disclosures (HackerOne #1481207,
#647130) are both this shape. Reflected XSS requires convincing a victim to
click a crafted link. DOM-based XSS can be either, depending on the source.

## Vulnerable Patterns

Look for shapes like these (illustrative, not exhaustive — reason about
equivalents in the actual stack you're reviewing, don't string-match):

```jsx
// React — unsanitized user/LLM content into the DOM
function Comment({ body }) {
  return <div dangerouslySetInnerHTML={{ __html: body }} />; // body is user input or LLM output
}
```

```vue
<!-- Vue — same escape hatch -->
<div v-html="post.renderedMarkdown"></div>
```

```svelte
<!-- Svelte -->
{@html userSuppliedHtml}
```

```js
// DOM-based XSS — untrusted source into an HTML sink
const params = new URLSearchParams(location.search);
document.getElementById('welcome').innerHTML = `Hello, ${params.get('name')}`;

// postMessage with no origin check feeding innerHTML
window.addEventListener('message', (e) => {
  document.getElementById('content').innerHTML = e.data.html; // no e.origin check, no sanitize
});
```

```python
# Server-rendered template — string concatenation bypasses auto-escaping
return f"<div class='profile-bio'>{user.bio}</div>"  # should go through the template engine's autoescape
```

```jsx
// Markdown rendering without sanitization
import { marked } from 'marked';
function Post({ markdown }) {
  return <div dangerouslySetInnerHTML={{ __html: marked(markdown) }} />; // marked() output is not sanitized HTML
}
```

## Data Flow Tracing Guide

To evaluate this playbook responsibly, trace the following before writing any
Finding:

1. Find every use of an escape-hatch sink: `dangerouslySetInnerHTML`,
   `v-html`, `{@html}`, `.innerHTML =`, `.outerHTML =`, `document.write(`,
   `insertAdjacentHTML(`. For each one, trace the value backward to its
   origin: a literal/constant (not a finding), a sanitizer call's return
   value (verify the sanitizer wraps the *actual* untrusted value), or
   unsanitized user/external/LLM-sourced data (finding).
2. For stored content specifically (comments, bios, titles, markdown docs):
   enumerate every place that field is rendered, not just the first one you
   find. A field sanitized on the profile page but echoed raw in an admin
   dashboard, a digest email, an RSS feed, or an API response consumed by
   another frontend is still a finding at the second sink.
3. For markdown/rich-text pipelines: identify the exact library
   (`marked`, `markdown-it`, `react-markdown`, `showdown`, a custom parser)
   and check whether a sanitizer (`DOMPurify.sanitize`, `sanitize-html`,
   `js-xss`, or a renderer plugin known to strip raw HTML) runs on its
   output before the result reaches a DOM/HTML sink. The presence of a
   markdown import is not evidence of safety or danger by itself — the
   configuration is what matters.
4. For DOM-based candidates: identify the source (`location.*`,
   `document.referrer`, `postMessage` listener, `document.cookie`) and
   confirm it reaches an HTML/eval sink with no encoding step and, for
   `postMessage`, no `event.origin` allowlist check.
5. For server-rendered templates: confirm whether the templating engine's
   auto-escaping is active for the specific output in question — look for
   explicit escape-bypass markers (Jinja2 `| safe`, `Markup(...)`,
   `{% autoescape false %}`; Rails `.html_safe`, `raw(...)`; Go
   `template.HTML(...)`) or raw string concatenation building the response
   instead of going through the engine at all.
6. Check for a Content-Security-Policy header as a defense-in-depth signal —
   its presence or absence should inform severity but never substitute for
   tracing an actual sink.

## Evidence Checklist

Before submitting a Finding for this playbook, confirm:

- [ ] At least one concrete code snippet with an exact file + line range is
      attached as evidence — do not paraphrase, quote the actual sink line.
- [ ] The untrusted source is identified by name and location (which route
      param, form field, database column, LLM output variable, or
      `postMessage` payload it is) — not just "user input" in the abstract.
- [ ] The data flow from source to sink is traced through every intermediate
      function/component, with no unverified assumption about what a
      library call does — if a sanitizer is present, its actual
      configuration (allowlist/denylist) is checked, not assumed safe by name.
- [ ] For stored-content findings: confirmation of whether other rendering
      surfaces for the same field were checked (or an explicit note that only
      one was found and others may exist outside the scanned file set).
- [ ] Confirmation that the sink is reachable by a genuinely untrusted actor
      (not self-XSS, not an admin-only tool with no external user path) —
      state who the attacker and victim are.

A finding without at least one concrete code-snippet evidence entry must not
be submitted.

## Attack Scenario Template

> An attacker submits [specific field, e.g. a profile bio / comment / shared
> document] containing a crafted payload (e.g. an `<img onerror=...>` or
> `<script>` equivalent surviving the sanitization gap). Because
> [specific code location] renders this field via [dangerouslySetInnerHTML /
> v-html / {@html} / innerHTML] without [missing sanitization step], the
> payload executes in the browser of [specific victim — any user who views
> the profile / an admin reviewing the queue / anyone who opens the shared
> document], resulting in [concrete impact specific to this repo — e.g.
> "theft of the victim's session cookie/token, enabling account takeover" or
> "silent modification of the victim's account settings via an authenticated
> fetch() the payload issues on their behalf"].

Fill every bracket concretely from evidence gathered in this repo. If a
bracket can't be filled from real evidence, the scenario is speculative and
severity must be capped at `medium`, with a note that exploitability is
unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:xss` node exists (create it on the first
  XSS-related finding in a scan) with a `depends_on` edge from
  `component:frontend_rendering`.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from `component:xss` (or a more
  specific root-cause component, e.g. `component:user_generated_content` if
  the root cause is unsanitized stored content) to the finding node.
- If the finding's impact reaches session/auth material (e.g. cookie theft
  enabling account takeover), add an `enables` edge from the finding node to
  `component:session_management` or `component:authentication`.
- If a finding is one of multiple unsanitized rendering surfaces for the same
  underlying stored field, note this explicitly in the finding's `reasoning`
  field and link the sibling findings with a `related_to` edge so the graph
  mapper doesn't treat them as unrelated one-off bugs when they share a root
  cause (a single missing sanitization step at the point of storage/first
  render).
