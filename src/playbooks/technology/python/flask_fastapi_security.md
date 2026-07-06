---
id: technology.python.flask_fastapi_security
title: Flask / FastAPI Security
category: technology
vulnerabilityClass: security_misconfiguration
appliesToStack: flask, fastapi
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A05:2021 Security Misconfiguration"
  - "A01:2021 Broken Access Control"
  - "A03:2021 Injection"
cweRefs:
  - "CWE-215"
  - "CWE-489"
  - "CWE-306"
  - "CWE-79"
  - "CWE-942"
realWorldReferences:
  - title: "Werkzeug debugger vulnerable to remote code execution when interacting with an attacker-controlled domain (CVE-2024-34069, GHSA-2g68-c3qc-8985)"
    url: "https://github.com/pallets/werkzeug/security/advisories/GHSA-2g68-c3qc-8985"
    type: vendor_security_advisory
  - title: "Werkzeug official documentation — 'The debugger allows the execution of arbitrary code... Do not enable the debugger in production'"
    url: "https://werkzeug.palletsprojects.com/en/stable/debug/"
    type: vendor_security_advisory
  - title: "Rapid7 Metasploit module: Werkzeug Debug Shell Remote Code Execution (pre-0.11 required no PIN/auth at all)"
    url: "https://www.rapid7.com/db/modules/exploit/multi/http/werkzeug_debug_rce/"
    type: security_blog
  - title: "StackHawk — Configuring CORS in FastAPI (wildcard origins combined with allow_credentials)"
    url: "https://www.stackhawk.com/blog/configuring-cors-in-fastapi/"
    type: security_blog
quickModeSummary: >
  Check for Flask apps run with debug=True (or app.run(debug=True) /
  FLASK_DEBUG=1) reachable outside local dev — this exposes the Werkzeug
  interactive debugger, a documented RCE vector. Check every new FastAPI route
  for a missing auth Depends() that sibling routes have, and every new Flask
  route for a missing @login_required-equivalent decorator or before_request
  check. Check Jinja2 templates for |safe, Markup(), or autoescape blocks
  wrapping anything derived from user input. Check CORS config
  (flask-cors / CORSMiddleware) for allow_origins="*" combined with
  credentials/cookies enabled.
fileSelectionHint:
  roles: ["route_handler", "middleware", "config", "template"]
  matchImports: ["flask", "fastapi", "flask_cors", "starlette", "jinja2", "werkzeug"]
  matchAuthMapTags: ["flask-login", "fastapi-depends", "session"]
  maxFiles: 8
  priorityOrder: ["config", "route_handler", "middleware", "template"]
severityHeuristics:
  critical:
    - "Flask app is run with debug=True (or FLASK_DEBUG/FLASK_ENV=development) in a production entrypoint, Dockerfile CMD, or WSGI config with no environment gating — the Werkzeug interactive debugger is reachable and grants arbitrary code execution to anyone who can trigger an unhandled exception."
    - "A state-changing route (POST/PUT/PATCH/DELETE) that handles sensitive data or privileged actions has no auth dependency/decorator at all, while structurally identical sibling routes do."
  high:
    - "User-controlled data is rendered via `|safe`, `Markup(user_input)`, or inside `{% autoescape off %}` with no sanitization step (e.g. bleach) in between."
    - "CORS is configured with `allow_origins=[\"*\"]` (or `flask-cors` `origins=\"*\"`) together with `allow_credentials=True` / `supports_credentials=True` — most frameworks reject this combination at runtime, but hand-rolled origin-reflection logic that mimics it is equally dangerous."
  medium:
    - "Debug mode is disabled by a config flag, but the flag's default value is `True` and is only overridden by an environment variable that could be unset in some deployment path (staging, a new container image, a local Kubernetes manifest)."
    - "An auth dependency exists on a route but only checks that *some* user is authenticated, not that the user is authorized for the specific resource (`Depends(get_current_user)` without an ownership/role check) — flag as a narrower authorization gap rather than a missing-auth finding."
  low:
    - "CORS wildcard is used but the API is read-only, unauthenticated, and returns no user-specific or sensitive data (defense-in-depth gap only)."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:flask_fastapi_config"
  relatedNodeIds: ["component:authentication", "component:template_rendering", "component:cors"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:route_handler"
    to: "component:flask_fastapi_config"
  - relation: protects
    from: "component:authentication"
    to: "component:route_handler"
commonAiCodingMistakes:
  - "AI scaffolds a Flask app with `app.run(debug=True)` because every tutorial and quickstart example uses it for the friendly auto-reload and interactive tracebacks, then the same entrypoint file is deployed unchanged — the flag is never revisited once the app 'works'."
  - "AI adds a new FastAPI route by copy-pasting a sibling route's shape but omits the `Depends(get_current_user)` (or equivalent) parameter, because the auth dependency lives in a function signature rather than a visually obvious decorator — easy to drop silently during a refactor or when generating a route from a spec."
  - "AI reaches for `Markup(value)` or `{{ value|safe }}` to fix a rendering bug where legitimate HTML (e.g. from a rich-text editor) was being escaped, without adding a sanitization step first — the fix for a display bug becomes a stored/reflected XSS sink."
  - "AI resolves a CORS error during local development by setting `allow_origins=[\"*\"]` (or `CORS(app, origins=\"*\")`) because it's the fastest way to make the browser error disappear, and the wildcard survives into the production config since it was never revisited after the immediate problem was solved."
  - "AI enables `flask-cors` on the whole app with `CORS(app)` (default wildcard-all-routes behavior) instead of scoping it to only the specific public endpoints that need cross-origin access, silently loosening CORS on authenticated API routes that were never intended to be cross-origin-accessible."
falsePositiveGuardrails:
  - "Do not flag `debug=True` inside a `if __name__ == \"__main__\"` block or a file that is demonstrably only used for local development (e.g. never referenced by the Dockerfile/WSGI entrypoint, gated behind `app.config['ENV'] == 'development'` read from an environment variable with a safe production default) — trace the actual production entrypoint before concluding debug mode is live."
  - "A `Depends(...)` auth check that lives in a shared `APIRouter(dependencies=[...])` or router-level `include_router(..., dependencies=[...])` protects every route registered under it — check the router/include_router call, not just the individual route decorator, before claiming a route is unprotected."
  - "`|safe` / `Markup()` applied to a value that is provably static (a hardcoded string, a value from a trusted internal constants file, i18n strings) is not a vulnerability — the finding requires a traceable path from user-controlled input to the unescaped sink."
  - "A wildcard CORS origin on a genuinely public, unauthenticated, read-only endpoint (e.g. a public API docs page, a health check, public reference data with no per-user variation) is not automatically a Finding — check whether the same CORS policy object is also applied to authenticated routes before assigning high severity."
  - "Framework-level auth (Flask-Login's `@login_required`, FastAPI security utilities like `OAuth2PasswordBearer` wired through `Depends`) implementing the check correctly should not be treated as 'hand-rolled and therefore suspect' — verify the actual dependency chain reaches the route, don't penalize using the framework's intended pattern."
---

## Root Cause Explanation

Flask and FastAPI are both intentionally low-ceremony frameworks — they get out
of your way, which also means they get out of the way of insecure defaults. The
security failures in this class share one root cause: a setting or check that
is trivial to add explicitly and trivial to forget, because the framework
provides no structural nudge that forces the developer (or an AI agent) to
notice its absence.

1. **Debug mode left on.** Flask's `debug=True` doesn't just enable
   auto-reload — it enables the Werkzeug interactive debugger, which renders a
   Python console *inside the traceback page* for any unhandled exception.
   This is not a hypothetical: it is a `os.system()`-away-from-RCE for anyone
   who can trigger an error on the app, documented and weaponized (Metasploit
   ships a module for it) for over a decade. The failure mode is almost always
   the same: `debug=True` is the version that appears in every quickstart
   example, tutorial, and AI-generated scaffold, and nothing forces it to be
   revisited before deploy.
2. **Auth checks that don't structurally propagate.** FastAPI's `Depends()`
   pattern is a function parameter, not a decorator — it is easy to miss when
   skimming a route, and trivial to omit when an AI agent generates a new
   route from a spec or copy-pastes a sibling route and forgets one line.
   Flask has the same problem with `@login_required` or manual
   `session.get('user_id')` checks scattered per-route instead of centralized.
   Both frameworks make *correct* auth easy to write per-route and *consistent*
   auth easy to lose across routes.
3. **Auto-escaping bypass.** Jinja2 (used by both Flask and, less commonly,
   FastAPI via `Jinja2Templates`) auto-escapes by default — which means the
   only way to introduce XSS through the template layer is to explicitly opt
   out via `|safe`, `Markup(...)`, or `{% autoescape off %}`. These exist for
   legitimate cases (rendering trusted, pre-sanitized HTML), but they are also
   the single sink where a "let me just fix this HTML-escaping bug" patch
   turns a display bug into a script-injection bug.
4. **CORS misconfiguration.** `flask-cors` and `CORSMiddleware` both make it
   one line to unblock a frustrating browser CORS error during development —
   `origins="*"` or `allow_origins=["*"]`. That fix is easy to apply and easy
   to never revisit, and if the API also handles cookies/credentials, the
   combination allows any origin on the internet to make authenticated
   requests to the API on behalf of a logged-in user's browser.

## Vulnerable Patterns

Look for shapes like these (illustrative, not exhaustive — reason about
equivalents in the actual stack you're reviewing, don't string-match):

```python
# Flask debug mode reachable in a real deployment path
app.run(host="0.0.0.0", debug=True)

# FastAPI route missing the auth dependency a sibling route has
@router.get("/admin/users")
def list_users(db: Session = Depends(get_db)):   # no Depends(require_admin)
    return db.query(User).all()

# Flask route missing an equivalent auth check
@app.route("/admin/users")
def list_users():
    return jsonify(get_all_users())   # no @login_required, no session check

# Auto-escaping bypassed with user-controlled input
return render_template_string(f"<div>{ '{{ bio|safe }}' }</div>", bio=user.bio)
Markup(f"<span>{request.args.get('name')}</span>")

# CORS wildcard combined with credentials
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,   # dangerous combination
)
CORS(app, supports_credentials=True, origins="*")
```

## Data Flow Tracing Guide

To evaluate this playbook responsibly, trace the following before writing any
Finding:

1. **Debug mode**: find every place `debug=` or `FLASK_DEBUG`/`FLASK_ENV` is
   set. Follow each to its actual runtime path — is it the file the
   Dockerfile/Procfile/WSGI server (gunicorn, uwsgi) actually invokes, or a
   dev-only script? Is the value hardcoded `True`, or read from an environment
   variable — and if from an environment variable, what's the default if the
   variable is unset?
2. **Auth propagation**: build a mental (or literal) list of all routes in
   `route_map` and their required auth level. For FastAPI, check both the
   per-route `Depends(...)` parameters AND any router-level or app-level
   `dependencies=[...]` that would apply automatically. For Flask, check
   per-route decorators AND any `before_request`/`before_app_request` hooks
   that might apply auth globally. A route with no visible auth is only
   evidence, not a conclusion, until you've checked both layers.
3. **Template auto-escape bypass**: for every `|safe`, `Markup(...)`, or
   `{% autoescape off %}` found, trace the value backward to its source. Is it
   a constant, an i18n string, output of a trusted sanitizer (e.g.
   `bleach.clean(...)`) — or does it originate from a request parameter, form
   field, database column that itself was populated from user input, or an
   upstream API response?
4. **CORS config**: find where `CORSMiddleware`/`CORS(...)` is instantiated,
   and read `allow_origins`/`origins` and `allow_credentials`/
   `supports_credentials` together — the combination is what matters, not
   either setting alone. If origins are validated via regex or a callback
   instead of a static list, check whether the pattern could match an
   attacker-registerable domain (e.g. a naive `.example.com` suffix check that
   also matches `evil-example.com`).

## Evidence Checklist

Before submitting a Finding for this playbook, confirm:

- [ ] At least one concrete code snippet with an exact file + line range is
      attached as evidence — do not paraphrase, quote the actual line(s).
- [ ] If claiming debug mode is live in production: the exact entrypoint file
      and line are cited, along with confirmation this is the path actually
      invoked by the deployment (Dockerfile CMD, Procfile, WSGI config) — not
      a dev-only script.
- [ ] If claiming a missing auth check: confirmation that no router-level,
      app-level, or `before_request`-style auth applies to the route, with
      the sibling route(s) that do have the check cited for comparison.
- [ ] If claiming an auto-escape bypass: both the sink (`|safe`/`Markup`/
      `autoescape off`) location and the traced source of the value are
      cited, showing the value is not a provably-constant/trusted string.
- [ ] If claiming a CORS misconfiguration: both the origins setting and the
      credentials setting are cited together, not just one in isolation.

A finding without at least one concrete code-snippet evidence entry must not
be submitted.

## Attack Scenario Template

> An attacker [triggers an unhandled exception on / sends a cross-origin
> request to / accesses] [specific endpoint/route], reaching [specific code
> location] which [lacks the auth check present on sibling routes / exposes
> the Werkzeug debugger console / reflects unsanitized `[field]` into the
> rendered page / accepts credentialed requests from any origin]. This results
> in [concrete impact specific to this repo — e.g. "arbitrary Python execution
> on the app server via the debugger console" or "session cookie theft via
> injected script in the `bio` field" — not a generic description].

Fill every bracket concretely from evidence gathered in this repo. If a
bracket can't be filled from real evidence, the scenario is speculative and
severity must be capped at `medium`, with a note that exploitability is
unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:flask_fastapi_config` node exists (create it on
  the first finding from this playbook in a scan), with a `depends_on` edge
  from `component:route_handler` to it.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from the most specific root-cause
  component (e.g. `component:template_rendering` for an XSS bypass,
  `component:cors` for a CORS misconfiguration, `component:flask_fastapi_config`
  for a debug-mode finding) to the finding node.
- If a debug-mode-enabled finding is present alongside any other finding in
  the same scan, note in the debug-mode finding's `reasoning` field that it
  amplifies the severity of every other finding (RCE via the debugger console
  can be used to directly read secrets/exploit any other flaw found), so the
  graph mapper can wire an `enables` edge from the debug-mode finding to the
  others rather than treating them as independent.
- If a missing-auth finding on a route and a CORS-wildcard-with-credentials
  finding coexist, add an `enables` edge from the CORS finding to the
  missing-auth finding — an attacker's page can silently drive a browser to
  call the unprotected route cross-origin using the victim's cookies.
