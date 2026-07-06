---
id: technology.laravel.laravel_security
title: Laravel Security
category: technology
vulnerabilityClass: framework_misconfiguration
appliesToStack: laravel
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A08:2021 Software and Data Integrity Failures"
  - "A01:2021 Broken Access Control"
  - "A03:2021 Injection"
cweRefs:
  - "CWE-915"
  - "CWE-862"
  - "CWE-89"
realWorldReferences:
  - title: "Securing Laravel — In Depth: Mass-Assignment Vulnerabilities (Ashley Hindle / securinglaravel.com)"
    url: "https://securinglaravel.com/in-depth-mass-assignment-vulnerabilities/"
    type: security_blog
  - title: "Laravel official documentation — Authorization (Gates and Policies)"
    url: "https://laravel.com/docs/13.x/authorization"
    type: vendor_security_advisory
  - title: "Laravel official documentation — Eloquent: Getting Started (Mass Assignment section, $fillable/$guarded)"
    url: "https://laravel.com/docs/12.x/eloquent"
    type: vendor_security_advisory
  - title: "OWASP Laravel Cheat Sheet"
    url: "https://cheatsheetseries.owasp.org/cheatsheets/Laravel_Cheat_Sheet.html"
    type: security_blog
  - title: "OWASP Mass Assignment Cheat Sheet"
    url: "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"
    type: security_blog
quickModeSummary: >
  Check three Laravel-specific footguns: (1) mass assignment — does an
  Eloquent model's `$fillable` list include privileged attributes (role,
  is_admin, user_id/owner_id), or is `$guarded = []`/`Model::unguard()` used
  with `Model::create($request->all())` and no separate validation layer
  stripping those fields? (2) missing authorization — does a controller
  action that reads/writes a specific model instance call `$this->authorize()`,
  a Policy method, or a Gate check before acting, or does it rely solely on
  authentication (any logged-in user can act on any record via route-model
  binding)? (3) raw SQL — does `DB::raw()`, `whereRaw()`, `selectRaw()`, or
  string-interpolated query-builder input embed unescaped request data
  instead of using `?`/named bindings?
fileSelectionHint:
  roles: ["controller", "model", "middleware", "route_handler"]
  matchImports: ["laravel/framework", "illuminate"]
  matchAuthMapTags: ["laravel", "eloquent", "policy", "gate"]
  maxFiles: 10
  priorityOrder: ["controller", "model", "middleware"]
severityHeuristics:
  critical:
    - "`Model::create($request->all())` or `$model->fill($request->all())`/`update($request->all())` on a model whose `$fillable` includes (or whose `$guarded` excludes) a privileged attribute — role, is_admin, permissions, user_id/owner_id, price/balance/credits — letting a client set it directly."
    - "`$guarded = []` (or `Model::unguard()`) combined with request data flowing into `create`/`update`/`fill` with no intervening validated allow-list (no Form Request `validated()` call, no explicit `->only([...])`)."
    - "Raw SQL built via string interpolation/concatenation in `DB::raw()`, `whereRaw()`, `selectRaw()`, `DB::statement()`, or `DB::select()` using unsanitized request input."
  high:
    - "A controller action operating on a specific model instance (typically via route-model binding, e.g. `Route::put('/posts/{post}', ...)`) performs an update/delete/read of sensitive data with no `$this->authorize(...)`, `Gate::allows(...)`, or Policy method call anywhere in the action or its middleware — only authentication (`auth` middleware) gates access, not ownership/role."
    - "A Policy or Gate closure exists but is defined too permissively for the operation (e.g. `return true;` unconditionally, or checks only that a user exists without comparing ownership/role)."
  medium:
    - "`$fillable`/`$guarded` correctly excludes privileged fields, but those fields are then set separately using still-unvalidated request input elsewhere in the same action (defeats the purpose of the allow-list)."
    - "Authorization check present but only enforced client-side/in a Blade `@can` directive, with no server-side `authorize()`/Policy check backing the actual controller action or API endpoint."
  low:
    - "Raw SQL used for a genuinely static, non-user-influenced expression (e.g. `DB::raw('COUNT(*) as total')`) — not exploitable, but worth a style note if inconsistent with the rest of the codebase's query style."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:laravel_framework"
  relatedNodeIds: ["component:mass_assignment", "component:authorization", "component:sql_injection"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:laravel_framework"
    to: "component:mass_assignment"
  - relation: depends_on
    from: "component:laravel_framework"
    to: "component:authorization"
  - relation: depends_on
    from: "component:laravel_framework"
    to: "component:sql_injection"
commonAiCodingMistakes:
  - "AI scaffolds a controller's `store`/`update` action with `Model::create($request->all())` because it's the shortest path to a working CRUD endpoint, without adding a Form Request class or `$request->validate([...])` allow-list — this passes every manual happy-path test since the attacker-controlled extra fields are never exercised."
  - "AI generates an Eloquent model with `$guarded = []` (a pattern some Laravel style guides and even experienced developers legitimately recommend when paired with strict Form Request validation) but does NOT also generate the corresponding Form Request validation, leaving the model fully mass-assignable with nothing upstream constraining the input."
  - "AI implements route-model binding (`Route::apiResource('posts', PostController::class)`) and CRUD actions but skips generating the corresponding Policy class, because Laravel's route/controller scaffolding is what's visibly 'required' to make requests succeed, while a missing Policy fails silently (the action just works for any authenticated user) rather than throwing an error."
  - "AI writes a Policy class but a controller method calls it inconsistently — e.g. `authorize('update', $post)` present on `update()` but missing on `destroy()` — because it copies the pattern once and doesn't re-derive it for every subsequent action added to the same controller."
  - "AI reaches for `DB::raw()`/`whereRaw()` to build a dynamic sort/filter feature (e.g. sorting by a client-supplied column name) because Eloquent's fluent query builder doesn't have an obviously named method for 'safely interpolate this column name,' and AI defaults to string interpolation rather than a validated allow-list of permitted column names or a bound parameter."
falsePositiveGuardrails:
  - "`Model::create($request->all())` is not automatically a vulnerability if the action is preceded by a Form Request class (`public function store(StorePostRequest $request)`) whose `rules()` method validates and implicitly constrains the field set, AND the controller uses `$request->validated()` rather than `$request->all()` to actually construct the model — check which one is passed to `create`/`update`, not just whether validation exists somewhere in the file."
  - "`$guarded = []` is a deliberate, documented pattern (recommended by some experienced Laravel security practitioners including SecuringLaravel's own author) when paired with strict validation upstream — do not flag it as high severity in isolation; check whether unvalidated `$request->all()`/`$request->input()` reaches `create`/`update`/`fill` for that model before concluding mass assignment is exploitable."
  - "Do not flag a controller action as missing authorization if the check happens in middleware (e.g. a custom `can:update,post` middleware alias on the route definition in `routes/web.php`/`routes/api.php`) rather than inside the controller method itself — check the route file's middleware chain, not just the controller body."
  - "Raw SQL passed through parameter bindings (`whereRaw('name = ?', [$name])`, `DB::select('select * from users where id = ?', [$id])`, `selectRaw('count(*) as total')` with no interpolated variable) is the correct parameterized pattern, not a vulnerability — do not flag the mere presence of `DB::raw`/`whereRaw`; check whether user input is interpolated into the string itself or passed as a separate bound value."
  - "A missing Policy is not a vulnerability if the model/resource is genuinely global and non-owned (e.g. public reference data with no per-user access boundary) — confirm the model has an ownership or tenancy concept (a `user_id`/`team_id` column, or role-gated visibility) before treating an authorization gap as exploitable."
---

## Root Cause Explanation

Laravel optimizes hard for developer velocity — Eloquent models, route-model
binding, and expressive query builder methods all exist to minimize
boilerplate. That same design intent produces three recurring, Laravel-shaped
vulnerability classes:

1. **Mass assignment.** Every Eloquent model ships with `create()`, `fill()`,
   and `update()` methods that accept an array and set matching attributes in
   one call — commonly fed directly from `$request->all()`. Laravel's own
   protection against this is the model's `$fillable` (allow-list) or
   `$guarded` (deny-list) property; without one correctly scoped, any
   attribute name present in the request body becomes settable, including
   ones the developer never intended to expose client-side — role flags,
   ownership foreign keys, pricing/balance fields, verification flags. This
   is functionally the same vulnerability class as Rails' 2012 mass-assignment
   incidents, and it remains common enough in Laravel codebases that Laravel
   security audits consistently rank it among the top recurring findings.
   Laravel's own Eloquent documentation is explicit that `$fillable`/`$guarded`
   exists specifically to prevent HTTP request parameters from being blindly
   bound into model attributes.
2. **Missing authorization checks.** Laravel's `auth` middleware answers "is
   this a logged-in user?" — a completely separate question from "is this
   user allowed to act on *this specific record*?" Laravel's own
   documentation describes Policies and Gates as the mechanism for the
   second question, but nothing forces a controller action to call
   `$this->authorize(...)` — a route can be fully wired, authenticated, and
   functional while silently allowing any logged-in user to read, modify, or
   delete any other user's resources via route-model binding (e.g.
   `PUT /posts/{post}` with no ownership check). Laravel security audits
   consistently rank "Missing Authorisation" among the most common Laravel
   findings — often more common than mass assignment itself — precisely
   because the framework makes the vulnerable path (skip the Policy call)
   just as easy to write as the safe one.
3. **Raw SQL via `DB::raw()`/`whereRaw()`.** Laravel's query builder and
   Eloquent are parameterized by default for the common cases (`where('email',
   $email)`), but the framework also exposes explicit raw-SQL escape hatches
   (`DB::raw()`, `whereRaw()`, `selectRaw()`, `orderByRaw()`, `DB::statement()`)
   for cases the fluent builder doesn't cleanly express, most commonly dynamic
   sorting/filtering by a client-supplied column name. Laravel treats the
   safety of these methods as the developer's responsibility — they support
   bound parameters (`whereRaw('name = ?', [$name])`) but nothing prevents
   direct string interpolation (`whereRaw("name = '$name'")`), and the two
   forms look nearly identical at a glance.

## Vulnerable Patterns

Look for shapes like these (illustrative, not exhaustive — reason about
equivalents in the actual codebase you're reviewing, don't string-match):

```php
// Mass assignment: unvalidated request data straight into create()
class UserController extends Controller
{
    public function update(Request $request, User $user)
    {
        $user->update($request->all()); // role/is_admin settable if $fillable includes them
        return $user;
    }
}

class User extends Model
{
    protected $fillable = ['name', 'email', 'role']; // role should not be client-settable
    // or: protected $guarded = []; // with no upstream validation
}

// Missing authorization: route-model binding with no ownership/role check
class PostController extends Controller
{
    public function destroy(Post $post)
    {
        $post->delete(); // any authenticated user can delete any post
    }
}

// Raw SQL via string interpolation
DB::table('users')->whereRaw("email = '" . $request->input('email') . "'")->get();
User::orderByRaw($request->input('sort'))->get(); // unsanitized column/direction
```

The safe equivalents, for contrast:

```php
// Validated Form Request + explicit allow-list
public function update(UpdateUserRequest $request, User $user)
{
    $user->update($request->validated()); // role excluded from validation rules
}

// Policy-backed authorization
public function destroy(Post $post)
{
    $this->authorize('delete', $post); // PostPolicy checks $post->user_id === auth()->id()
    $post->delete();
}

// Parameterized raw SQL
DB::table('users')->whereRaw('email = ?', [$request->input('email')])->get();
```

## Data Flow Tracing Guide

To evaluate this playbook responsibly, trace the following before writing any
Finding:

1. **Mass assignment.** For every `Model::create(...)`, `$model->fill(...)`,
   or `$model->update(...)` call, trace the argument back to its source. Is
   it `$request->all()`/`$request->input()` directly, or the result of
   `$request->validated()`/`$request->only([...])`? If `validated()`, open
   the corresponding Form Request's `rules()` method and confirm it doesn't
   include a privileged field. Then open the model and check `$fillable`
   (does it include the privileged field?) or `$guarded` (does it exclude
   the privileged field, i.e. leave it mass-assignable?).
2. **Authorization.** For every controller action that reads, modifies, or
   deletes a specific model instance (especially via route-model binding —
   a type-hinted model parameter), search the method body and its route
   definition's middleware for `$this->authorize(...)`, `Gate::allows(...)`,
   `Gate::authorize(...)`, or a `can:` middleware alias. If none is present,
   check whether the model has an ownership/tenancy concept (a `user_id`,
   `team_id`, or role-based visibility rule) — if it does, absence of any
   authorization check is a real gap, not a stylistic omission.
3. **Raw SQL.** For every `DB::raw`, `whereRaw`, `selectRaw`, `orderByRaw`,
   `havingRaw`, `DB::statement`, or `DB::select` call, determine whether its
   string argument contains PHP string interpolation (`"...{$var}..."` or
   `"..." . $var`) including a variable traceable to `$request`, route
   parameters, or any other attacker-controlled input, versus a `?`/named
   placeholder with values passed as a separate bindings array.
4. **Cross-check the model's `$fillable`/`$guarded` against every place the
   model is written**, not just the one under review — a model deemed safe
   in one controller because that controller uses `validated()` may be
   directly exposed via a different, less-careful controller, an Artisan
   command, or a queued job elsewhere in the codebase.

## Evidence Checklist

Before submitting a Finding for this playbook, confirm:

- [ ] At least one concrete code snippet with an exact file + line range is
      attached as evidence — do not paraphrase, quote the actual line(s).
- [ ] If claiming mass assignment: the exact `create`/`update`/`fill` call
      site is cited, AND the model's `$fillable`/`$guarded` declaration is
      cited showing the specific privileged attribute is exposed.
- [ ] If claiming missing authorization: the controller action is cited, AND
      confirmation is given that no `authorize()`/Gate/Policy/`can:` middleware
      check exists anywhere in the action's call path (method body + route
      middleware chain), AND the model's ownership/tenancy concept is
      identified to justify why the check is expected.
- [ ] If claiming raw SQL injection: the exact interpolated/concatenated
      string is quoted, and the traced source of the interpolated variable
      is shown.
- [ ] Confirmation that a Form Request or explicit `->only([...])`/`validated()`
      call isn't already constraining the field set before concluding mass
      assignment is exploitable.

A finding without at least one concrete code-snippet evidence entry must not
be submitted.

## Attack Scenario Template

> An attacker sends a request to [specific controller action/route] with an
> additional/modified field `[field_name]` set to [attacker-chosen value], or
> targets a resource ID belonging to another user via [route-model-bound
> parameter]. Because [specific code location] passes [request data / a raw
> SQL string] directly to [Eloquent method] without [missing check —
> $fillable/$guarded scoping, validated() allow-list, authorize() call,
> parameterization], the request [succeeds in modifying a field the attacker
> shouldn't control / acts on a record owned by a different user / executes
> attacker-influenced SQL], resulting in [concrete impact specific to this
> repo — e.g. "attacker sets their own `role` field to `admin` via the
> profile update endpoint"], not a generic description.

Fill every bracket concretely from evidence gathered in this repo. If a
bracket can't be filled from real evidence, the scenario is speculative and
severity must be capped at `medium`, with a note that exploitability is
unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:laravel_framework` node exists (create it on the
  first Laravel-related finding in a scan), with `depends_on` edges to
  `component:mass_assignment`, `component:authorization`, and
  `component:sql_injection` as relevant sub-components are actually found.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from the specific root-cause
  component (`component:mass_assignment`, `component:authorization`, or
  `component:sql_injection`) to the finding node.
- If a mass-assignment finding allows privilege escalation (a `role`/`is_admin`
  attribute becomes settable), add an `enables` edge from that finding node
  to `component:authorization` or a more specific downstream component the
  escalated privilege unlocks.
- If a missing-authorization finding allows cross-tenant/cross-user data
  access via route-model binding, add an `enables` edge from the finding node
  to `component:data_access` or the specific resource/model component
  affected.
- Root cause vs. symptom: if a missing-authorization finding is what makes an
  otherwise-contained mass-assignment finding exploitable against other
  users' records (not just the acting user's own), say so explicitly in the
  finding's `reasoning` field so the graph mapper wires a `causes` edge
  between the two finding nodes rather than treating them as unrelated.
