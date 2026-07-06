---
id: technology.python.django_security
title: Django Security
category: technology
vulnerabilityClass: security_misconfiguration
appliesToStack: django
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A05:2021 Security Misconfiguration"
  - "A01:2021 Broken Access Control"
  - "A03:2021 Injection"
cweRefs:
  - "CWE-215"
  - "CWE-89"
  - "CWE-79"
  - "CWE-862"
realWorldReferences:
  - title: "Django official Deployment Checklist — DEBUG, SECRET_KEY, ALLOWED_HOSTS and other settings that must change before production"
    url: "https://docs.djangoproject.com/en/6.0/howto/deployment/checklist/"
    type: vendor_security_advisory
  - title: "Django official documentation — Archive of security issues (raw SQL / .extra() / mark_safe-class CVEs and fixes)"
    url: "https://docs.djangoproject.com/en/6.0/releases/security/"
    type: vendor_security_advisory
  - title: "Glovo disclosed on HackerOne: Django DEBUG=True enabled on a production subdomain, exposing detailed error pages"
    url: "https://hackerone.com/reports/1561377"
    type: bug_bounty_disclosure
  - title: "MTN Group disclosed on HackerOne: Information disclosure via Django Debug Mode enabled, escalated to account enumeration and arbitrary account registration"
    url: "https://hackerone.com/reports/2201370"
    type: bug_bounty_disclosure
  - title: "Django disclosed on HackerOne: SQL Injection in Django ORM via WhereNode.as_sql"
    url: "https://hackerone.com/reports/3335709"
    type: bug_bounty_disclosure
quickModeSummary: >
  Check settings.py / environment config for DEBUG = True with no
  environment-based override, or a default of True. Check every view for a
  missing @login_required / PermissionRequiredMixin / permission_classes
  equivalent, especially compared to structurally similar sibling views.
  Check for .raw(), .extra(), or RawSQL(...) calls built with string
  formatting/concatenation of request data instead of parameterized queries.
  Check templates for {% autoescape off %} or mark_safe()/format_html()
  misuse wrapping user-controlled data.
fileSelectionHint:
  roles: ["config", "route_handler", "model", "template"]
  matchImports: ["django", "django.contrib.auth", "django.db.models", "django.utils.safestring"]
  matchAuthMapTags: ["django-auth", "login_required", "permission_required"]
  maxFiles: 8
  priorityOrder: ["config", "route_handler", "model", "template"]
severityHeuristics:
  critical:
    - "DEBUG = True in a settings file that is demonstrably used in production (referenced by the production WSGI/ASGI entrypoint or deployment config), with no environment-variable override defaulting to False."
    - "A raw SQL construction (`.raw()`, `.extra()`, `RawSQL(...)`, or `cursor.execute(...)`) interpolates request-derived data via f-string/`%`/`.format()` instead of passing it as a parameterized argument."
  high:
    - "A view handling sensitive data or a privileged action has no `@login_required`/`LoginRequiredMixin`/`permission_required`/DRF `permission_classes` equivalent, while structurally identical sibling views do."
    - "User-controlled data reaches `mark_safe()`, `format_html()` misused with unescaped interpolation, or is inside a `{% autoescape off %}` block with no sanitization step in between."
  medium:
    - "DEBUG is disabled via an environment variable, but the settings file's fallback/default value is `True` if the variable is absent or malformed in some deployment path."
    - "A view has an authentication check but not an object-level authorization check (e.g. `@login_required` without verifying the requesting user owns the object identified by the URL parameter) — flag as an authorization gap, not a missing-auth finding."
  low:
    - "`.extra()`/`.raw()` is used with parameters that are all provably static/constant, with no request-derived value in the SQL string (defense-in-depth: `.extra()`/`.raw()` are still discouraged, but the specific call is not exploitable as evidenced)."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:django_config"
  relatedNodeIds: ["component:authentication", "component:database", "component:template_rendering"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:route_handler"
    to: "component:django_config"
  - relation: protects
    from: "component:authentication"
    to: "component:route_handler"
  - relation: depends_on
    from: "component:route_handler"
    to: "component:database"
commonAiCodingMistakes:
  - "AI scaffolds a new Django project with `django-admin startproject`, which generates `DEBUG = True` by default, and the flag is never revisited when the project is later containerized and deployed — it is buried in `settings.py` rather than surfaced anywhere a deploy step would catch it."
  - "AI adds a new class-based view or function view by copy-pasting a sibling view's URL pattern and body, but omits `LoginRequiredMixin`/`@login_required`/`permission_classes` because the check lives in a mixin or decorator that's easy to drop silently when generating boilerplate from a spec."
  - "AI reaches for `.extra()` or builds a raw SQL string with an f-string to express a query the ORM's query-builder doesn't obviously support (e.g. a complex aggregation or window function), interpolating a request parameter directly into the SQL text instead of passing it through the `params=` argument."
  - "AI wraps a chunk of user-generated content in `mark_safe()` or `{% autoescape off %}` to fix a rendering bug where legitimate formatting (e.g. from a markdown-to-HTML pipeline) was being double-escaped, without first passing the content through a sanitizer like `bleach.clean()` — the escaping fix becomes a stored XSS sink."
  - "AI copies a `settings.py` DEBUG pattern like `DEBUG = os.environ.get('DEBUG', True)` where the fallback default is `True` instead of `False` — safe as long as the environment variable is always set, but a single deployment path (a new environment, a misconfigured secret) that omits it silently re-enables debug mode in production."
falsePositiveGuardrails:
  - "Do not flag `DEBUG = True` in a settings file demonstrably scoped to local development (e.g. `settings/local.py` in a split-settings layout that is not imported by `settings/production.py` or referenced by `manage.py`/`wsgi.py`/`asgi.py`/the deployment config) — trace which settings module is actually loaded in production (`DJANGO_SETTINGS_MODULE`) before concluding debug mode is live."
  - "A view protected by DRF's `permission_classes = [IsAuthenticated]` (or similar) at the `APIView`/`ViewSet` class level protects every method on that view — check the class attribute, not just individual method bodies, before claiming a method is unprotected."
  - "`.extra()`/`.raw()`/`RawSQL()` calls that pass all dynamic values through the `params`/positional-placeholder mechanism (e.g. `.raw('SELECT * FROM t WHERE id = %s', [user_id])`) are parameterized and NOT a SQL injection finding, even though `.raw()`/`.extra()` usage itself is worth a lower-severity note recommending the ORM query-builder where feasible."
  - "`mark_safe()`/`format_html()` applied to content that has already passed through a sanitizer (`bleach.clean()`, `nh3`, a documented allowlist-based HTML cleaner) earlier in the same data flow is not a Finding — trace the full path before concluding the escape is unguarded."
  - "Middleware-based auth (e.g. a custom `AuthenticationMiddleware` subclass, or `django.contrib.auth.middleware.LoginRequiredMiddleware` in Django 5.1+) that applies globally is a legitimate substitute for per-view decorators — check `MIDDLEWARE` in settings before concluding a view has no auth enforcement."
---

## Root Cause Explanation

Django ships with more security defaults than Flask or FastAPI — CSRF
protection, ORM parameterization, and template auto-escaping are all on by
default. That makes Django's failure modes narrower but not rarer: they cluster
around the small number of places where a developer (or an AI agent) has to
actively opt out of a safe default, or where the framework leaves enforcement
as a per-view responsibility rather than a structural guarantee.

1. **`DEBUG = True` in production.** `django-admin startproject` generates
   `DEBUG = True` by default, and Django's own detailed error pages —
   designed to be maximally helpful in development — become maximally helpful
   to an attacker in production: full tracebacks, local variable values at
   every stack frame, installed app list, and (until Django 5.1's
   `DEBUG_PROPAGATE_EXCEPTIONS` hardening in some configurations) sometimes
   `SECRET_KEY` or database credentials surfaced through settings introspection
   in a traceback. This is one of the most consistently disclosed
   misconfigurations in bug bounty programs precisely because it's a single
   boolean that's easy to leave unchanged.
2. **Missing per-view authorization.** Django's `@login_required`,
   `PermissionRequiredMixin`, and DRF's `permission_classes` are all
   opt-in, per-view mechanisms (or per-class, or global via middleware in
   5.1+). A codebase built incrementally — especially route-by-route by an AI
   agent — can easily end up with some views correctly protected and newer,
   structurally identical views that simply never got the decorator/mixin
   added.
3. **Raw SQL escape hatches.** The Django ORM parameterizes queries
   automatically, which is precisely why `.raw()`, `.extra()`, and
   `RawSQL(...)` are dangerous: they exist so developers can express a query
   the ORM can't, and it's easy to build that query with string formatting
   instead of passing values through the parameterization mechanism these
   APIs still support. Django's own documentation explicitly warns that these
   three APIs (plus direct cursor use) are the main SQL injection vectors in
   an otherwise-safe ORM.
4. **Auto-escape bypass.** Django's template engine auto-escapes by default,
   so XSS through templates requires an explicit opt-out: `mark_safe()`,
   `format_html()` misused with unescaped substitution, or `{% autoescape off
   %}`. As with Flask/Jinja2, the common failure path is a rendering bug fix
   ("my HTML is showing up escaped") that reaches for the opt-out instead of
   sanitizing the input first.

## Vulnerable Patterns

Look for shapes like these (illustrative, not exhaustive — reason about
equivalents in the actual stack you're reviewing, don't string-match):

```python
# settings.py — DEBUG left on, or defaulting to True
DEBUG = True
DEBUG = os.environ.get("DEBUG", True)   # unsafe default if unset

# View missing an auth/permission check present on sibling views
def admin_dashboard(request):
    return render(request, "admin/dashboard.html", {"stats": get_stats()})
    # no @login_required, no permission_required

# Raw SQL built with string interpolation of request data
User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{username}'")
Model.objects.extra(where=[f"status = '{request.GET['status']}'"])

# Auto-escaping bypassed with user-controlled input
mark_safe(f"<div>{user_bio}</div>")
```
```html
{% autoescape off %}{{ comment.text }}{% endautoescape %}
```

## Data Flow Tracing Guide

To evaluate this playbook responsibly, trace the following before writing any
Finding:

1. **DEBUG setting**: find the value of `DEBUG` in every settings module.
   Determine which module `DJANGO_SETTINGS_MODULE` actually points to in the
   production deployment (Dockerfile, `wsgi.py`/`asgi.py`, deployment
   manifest, `manage.py` default). If `DEBUG` is read from an environment
   variable, check the fallback/default used when that variable is absent.
2. **Auth propagation**: enumerate views/`ViewSet`s/`APIView`s in
   `route_map`. For each, check (a) per-view decorators/mixins, (b) class-level
   `permission_classes`/`authentication_classes` for DRF, and (c) whether
   `MIDDLEWARE` includes an app-wide auth enforcement layer. A view with none
   of these is evidence, not a conclusion — confirm it isn't an intentionally
   public view (login page, public content, webhook receiver) first.
3. **Raw SQL**: for every `.raw()`, `.extra()`, `RawSQL(...)`, or
   `connection.cursor().execute(...)` call, check whether dynamic values are
   passed through the query's `params`/placeholder mechanism or interpolated
   directly into the SQL string via f-string, `%`, `.format()`, or
   concatenation. Trace each interpolated value back to confirm whether it
   originates from request data (querystring, POST body, headers, URL kwargs).
4. **Template auto-escape bypass**: for every `mark_safe()`, `format_html()`
   with `{}`-style raw substitution, or `{% autoescape off %}` block, trace
   the wrapped value backward to its source — a constant, a sanitizer's
   output, or unsanitized user/database-stored input.

## Evidence Checklist

Before submitting a Finding for this playbook, confirm:

- [ ] At least one concrete code snippet with an exact file + line range is
      attached as evidence — do not paraphrase, quote the actual line(s).
- [ ] If claiming DEBUG is live in production: the exact settings file/line is
      cited along with confirmation of which settings module the production
      entrypoint actually loads.
- [ ] If claiming a missing auth check: confirmation that no class-level,
      middleware-level, or app-wide auth applies, with a comparable protected
      sibling view cited for contrast.
- [ ] If claiming raw-SQL injection: the exact `.raw()`/`.extra()`/`RawSQL()`
      call site is cited, showing the interpolated value is not passed via
      the parameterized `params` mechanism, with the request-data origin of
      that value traced.
- [ ] If claiming an auto-escape bypass: both the sink location and the
      traced source of the value are cited, showing it is not provably a
      constant or already-sanitized value.

A finding without at least one concrete code-snippet evidence entry must not
be submitted.

## Attack Scenario Template

> An attacker [triggers an application error to view the debug traceback on /
> sends a crafted `[parameter]` to / submits malicious markup via]
> [specific endpoint/view], reaching [specific code location] which [exposes
> DEBUG=True error pages including settings and stack locals / lacks the
> auth check present on sibling views / interpolates the value directly into
> a raw SQL string / renders it without escaping]. This results in [concrete
> impact specific to this repo — e.g. "disclosure of SECRET_KEY and database
> credentials via the traceback page" or "extraction of other users' password
> hashes via UNION-based SQL injection in the `.raw()` call" — not a generic
> description].

Fill every bracket concretely from evidence gathered in this repo. If a
bracket can't be filled from real evidence, the scenario is speculative and
severity must be capped at `medium`, with a note that exploitability is
unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:django_config` node exists (create it on the
  first finding from this playbook in a scan), with a `depends_on` edge from
  `component:route_handler` to it.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from the most specific root-cause
  component (`component:database` for raw-SQL injection,
  `component:template_rendering` for an autoescape bypass,
  `component:django_config` for a DEBUG finding) to the finding node.
- If a DEBUG=True finding coexists with any other finding in the same scan,
  note in the DEBUG finding's `reasoning` field that it amplifies the other
  findings' severity (detailed tracebacks can leak the exact evidence needed
  to exploit them, e.g. leaking `SECRET_KEY` to forge signed session cookies),
  so the graph mapper can wire an `enables` edge from the DEBUG finding to the
  others rather than treating them as independent.
- If a raw-SQL-injection finding could plausibly be used to read credentials
  or session data that in turn defeats an authentication/authorization
  finding elsewhere in the scan, add an `enables` edge from the SQL injection
  finding to that authentication finding.
