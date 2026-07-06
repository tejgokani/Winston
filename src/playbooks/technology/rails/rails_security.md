---
id: technology.rails.rails_security
title: Ruby on Rails Security
category: technology
vulnerabilityClass: framework_misconfiguration
appliesToStack: rails
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A08:2021 Software and Data Integrity Failures"
  - "A03:2021 Injection"
  - "A01:2021 Broken Access Control"
cweRefs:
  - "CWE-915"
  - "CWE-89"
  - "CWE-352"
realWorldReferences:
  - title: "Egor Homakov — 'How to: hijack rails/rails repo' (the 2012 GitHub mass-assignment hack)"
    url: "http://homakov.blogspot.com/2012/03/how-to.html"
    type: incident_postmortem
  - title: "Ruby on Rails Security Guide — official Rails Core documentation (mass assignment, SQL injection, CSRF sections)"
    url: "https://guides.rubyonrails.org/security.html"
    type: vendor_security_advisory
  - title: "Ruby on Rails SQL Injection advisory (CVE-2012-2695) — rubyonrails-security mailing list"
    url: "https://groups.google.com/g/rubyonrails-security/c/l4L0TEVAz1k/m/Vr84sD9B464J"
    type: vendor_security_advisory
  - title: "OWASP Ruby on Rails Cheat Sheet"
    url: "https://cheatsheetseries.owasp.org/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html"
    type: security_blog
quickModeSummary: >
  Check three Rails-specific footguns: (1) mass assignment — does every
  `create`/`update`/`update_attributes` call route through `params.require(...).permit(...)`
  (strong parameters), or is a raw `params` / `params[:x]` hash passed directly
  to an ActiveRecord model? (2) raw SQL — does `where`, `find_by_sql`, `order`,
  `pluck`, or `whereRaw`-equivalent interpolate a variable directly into a SQL
  string instead of using `?`/named placeholders or a hash condition? (3) CSRF —
  is `skip_before_action :verify_authenticity_token` applied to a controller
  action that changes state (not a webhook/API-token-authenticated endpoint)?
fileSelectionHint:
  roles: ["controller", "model", "route_handler"]
  matchImports: ["rails", "activerecord", "actionpack"]
  matchAuthMapTags: ["rails", "strong_parameters", "csrf"]
  maxFiles: 10
  priorityOrder: ["controller", "model", "route_handler"]
severityHeuristics:
  critical:
    - "A controller action calls `Model.create(params[:model])`, `Model.new(params[:model])`, or `record.update_attributes(params[:model])` with the raw `params` hash (or a bare `params[:model]` sub-hash) instead of a `.permit(...)`-filtered result, on a model that has any privileged/sensitive attribute (role, admin flag, user_id/owner_id, price, balance)."
    - "Raw SQL built via string interpolation or concatenation (`\"WHERE id = #{params[:id]}\"`, `find_by_sql(\"...#{...}\")`, `.where(\"name = '#{params[:name]}'\")`) using unsanitized request input."
  high:
    - "`skip_before_action :verify_authenticity_token` on a state-changing action (POST/PUT/PATCH/DELETE) with no compensating control (e.g. no API-token/HMAC auth on that action) and no comment/justification tying it to a legitimate webhook receiver."
    - "Mass assignment onto a model without privileged attributes but where the *set* of permitted attributes is effectively unbounded (e.g. `.permit!` used, which disables strong parameters entirely)."
  medium:
    - "`order(params[:sort])` or `pluck(params[:column])` passing raw user input as a column/direction reference — a narrower SQL-injection-adjacent primitive than a full WHERE-clause injection, but still exploitable for injection or information disclosure depending on the adapter."
    - "Strong parameters used, but the permitted list includes a sensitive field (e.g. `.permit(:name, :email, :role)`) that should be set only server-side, not client-controlled."
  low:
    - "CSRF protection skipped on a read-only or idempotent GET-only action (defense-in-depth gap only, not exploitable for state change)."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:rails_framework"
  relatedNodeIds: ["component:mass_assignment", "component:sql_injection", "component:csrf"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:rails_framework"
    to: "component:mass_assignment"
  - relation: depends_on
    from: "component:rails_framework"
    to: "component:sql_injection"
  - relation: protects
    from: "component:csrf"
    to: "component:rails_framework"
commonAiCodingMistakes:
  - "AI scaffolds a controller with `Model.create(params[:model])` because it's the shortest path to a working create action in a tutorial-style response, skipping the `params.require(:model).permit(...)` step Rails conventionally requires — this compiles and works for the happy path, so it isn't caught by manual testing."
  - "AI adds a new privileged attribute (e.g. `role`, `is_admin`, `account_id`) to a model, then updates the strong-parameters `.permit(...)` list to include it everywhere the model is written, not realizing that now makes the attribute client-settable through every one of those endpoints."
  - "AI 'fixes' a failing test or a CSRF error encountered during development by adding `skip_before_action :verify_authenticity_token`, then leaves it in place after the real cause (e.g. a missing CSRF meta tag in a fetch/AJAX call) is never addressed."
  - "AI writes a raw SQL query for a feature Rails' query interface doesn't obviously support (dynamic column sort, full-text search) using string interpolation, because parameterizing a *column name* (as opposed to a value) isn't idiomatically taught the same way `?` placeholders are for values."
  - "AI copies a working strong-parameters pattern from one controller to a new one but forgets that the new model has a different, more sensitive attribute set — the permit list from the old model doesn't automatically make the new one safe, but AI treats copy-paste as equivalent-by-construction."
falsePositiveGuardrails:
  - "Do not flag `Model.create(params[:model])`-shaped calls as mass assignment if the model itself uses `attr_accessible` (Rails 3 whitelist-based protection, functionally equivalent to strong parameters) or Rails 4+ strong parameters are enforced globally via `ActiveRecord::Base.class_attribute :whitelisted_attributes` or similar — check the model file and `config/application.rb`, not just the controller, before concluding mass assignment is unprotected."
  - "A `skip_before_action :verify_authenticity_token` is not automatically a vulnerability on an action that authenticates via a signed webhook payload, HMAC header, or a non-cookie API token (Bearer auth) — CSRF only matters when a browser's ambient cookie-based session is the auth mechanism. Confirm how the action authenticates before flagging."
  - "Raw SQL passed through `sanitize_sql_array`, `ActiveRecord::Base.sanitize_sql_for_conditions`, or built with `?`/named bind parameters (`where(\"name = ?\", params[:name])`, `where(\"name = :name\", name: params[:name])`) is the correct parameterized pattern, not a vulnerability — do not flag the mere presence of a string argument to `.where`; check whether user input is interpolated into that string or passed as a separate bind value."
  - "`.permit(:id)` or similar on a strictly server-populated, non-privileged attribute (e.g. a `content` text field with no downstream trust implications) is lower severity than permitting `role`/`admin`/ownership fields — weight severity by what the permitted attribute actually controls, not merely that `.permit` was used."
---

## Root Cause Explanation

Rails' defining design philosophy — convention over configuration, maximum
productivity from minimum code — is exactly what makes its security failure
modes distinctive. Three recurring classes account for most real-world Rails
vulnerabilities:

1. **Mass assignment.** ActiveRecord models historically let you construct or
   update a record directly from a hash: `User.new(params[:user])`,
   `user.update_attributes(params[:user])`. This is extremely convenient — and
   extremely dangerous, because it means *every* column on the model,
   including ones the developer never intended to expose (`role`, `is_admin`,
   `account_id`, `verified`), becomes settable by whatever HTTP parameters an
   attacker sends, unless the developer explicitly opts out. This is not a
   theoretical concern: it is the exact mechanism Egor Homakov used in March
   2012 to get commit access to GitHub's own `rails/rails` and `github/github`
   repositories, by adding a hidden `public_key[user_id]` form field to a key
   upload form whose controller called
   `@key.update_attributes(params[:public_key])` with no attribute
   whitelist — pointing his own SSH key at the Rails organization's account.
   That single incident is largely why Rails 4 made **strong parameters**
   (`params.require(:model).permit(:attr1, :attr2)`) the default, moving from
   opt-out (`attr_protected`) to opt-in (`permit`) attribute exposure.
2. **Raw SQL via string interpolation.** ActiveRecord's query interface is
   safe by default when used idiomatically — `where(id: params[:id])` and
   `where("id = ?", params[:id])` are both parameterized. But the same API
   also accepts raw SQL strings (`where("name = '#{params[:name]}'")`,
   `find_by_sql("SELECT * FROM users WHERE id = #{params[:id]}")`,
   `order(params[:sort])`), and nothing in the method signature distinguishes
   the safe form from the unsafe one — both are just strings passed to
   `.where`. This ambiguity is precisely why CVE-2012-2695 existed: even
   Rails' own `.where(:id => params[:id]).all`-style hash conditions had a
   parsing edge case that allowed SQL injection through a crafted `params[:id]`
   in certain configurations, which is why the Rails Security Guide explicitly
   calls out that hash-condition safety is not unconditional and dynamic
   finders/raw SQL need the same scrutiny as any other web framework.
3. **CSRF protection disabled.** Rails enables `protect_from_forgery`
   (`verify_authenticity_token` in newer versions) by default on all
   controllers, correctly assuming cookie-based session auth is the norm.
   Developers hit real friction when adding webhook receivers, JSON APIs
   consumed by non-browser clients, or single-page-app AJAX calls without a
   properly wired CSRF meta tag — the fix that "makes the error go away" is
   `skip_before_action :verify_authenticity_token`, which is correct for a
   token/HMAC-authenticated webhook endpoint but a real vulnerability if
   applied to a session-cookie-authenticated, state-changing action.

## Vulnerable Patterns

Look for shapes like these (illustrative, not exhaustive — reason about
equivalents in the actual codebase you're reviewing, don't string-match):

```ruby
# Mass assignment: raw params hash passed straight to the model
class UsersController < ApplicationController
  def update
    @user = User.find(params[:id])
    @user.update_attributes(params[:user]) # no .permit — role/admin settable
    redirect_to @user
  end
end

# Raw SQL via string interpolation
User.find_by_sql("SELECT * FROM users WHERE email = '#{params[:email]}'")
Post.where("title = '#{params[:title]}'")
Post.order(params[:sort]) # unsanitized column/direction reference

# CSRF disabled on a state-changing, cookie-authenticated action
class AccountsController < ApplicationController
  skip_before_action :verify_authenticity_token, only: [:update, :destroy]

  def destroy
    current_user.account.destroy
  end
end
```

The safe equivalents, for contrast:

```ruby
# Strong parameters — explicit allow-list
def update
  @user = User.find(params[:id])
  @user.update(user_params)
end

private

def user_params
  params.require(:user).permit(:name, :email) # role/admin intentionally excluded
end

# Parameterized query
User.where("email = ?", params[:email])
User.where(email: params[:email])
```

## Data Flow Tracing Guide

To evaluate this playbook responsibly, trace the following before writing any
Finding:

1. **Mass assignment.** For every `Model.new(...)`, `Model.create(...)`,
   `record.update(...)`, or `record.update_attributes(...)` call, trace the
   argument back to its source. Is it the direct result of `params[:x]` or
   `params`, or is it the result of a `.permit(...)` call? If it's a local
   variable or private method (commonly named `*_params`), open that method
   and confirm it actually calls `.require(...).permit(...)` rather than
   `params` unfiltered or `.permit!` (which disables filtering entirely).
2. **Privileged attributes.** For any mass-assignment call that *is*
   protected by `.permit(...)`, read the model's schema (or `db/schema.rb` /
   migrations) and check whether any permitted attribute is privileged:
   role/permission fields, ownership/foreign-key fields (`user_id`,
   `account_id`), financial fields (`price`, `balance`, `credits`), or
   verification/approval flags. A `.permit(:role)` on a self-service user
   controller is the modern equivalent of the 2012 GitHub bug.
3. **Raw SQL.** For every `.where`, `.find_by_sql`, `.order`, `.pluck`,
   `.select`, or `.group` call, determine whether its string argument (if
   any) contains a Ruby string interpolation (`#{...}`) or concatenation
   (`+`, `<<`) that includes a variable ultimately traceable to `params`,
   request headers, or any other attacker-controlled input. Bind-parameter
   forms (`?`, `:name`, or a hash condition) are safe; interpolation is not.
4. **CSRF.** For every `skip_before_action :verify_authenticity_token` (or
   `protect_from_forgery except: [...]` / `skip_forgery_protection`), identify
   which actions it applies to and whether those actions change state
   (create/update/destroy, or any custom action performing a write). Then
   determine the action's actual authentication mechanism — read the
   `before_action` chain for that controller. If the only auth is a Rails
   session cookie, the CSRF skip is a real gap. If auth is a bearer token,
   signed webhook payload, or HMAC signature (not carried automatically by
   the browser), CSRF does not apply.

## Evidence Checklist

Before submitting a Finding for this playbook, confirm:

- [ ] At least one concrete code snippet with an exact file + line range is
      attached as evidence — do not paraphrase, quote the actual line(s).
- [ ] If claiming mass assignment: the exact `create`/`update`/`update_attributes`
      call site is cited, AND either (a) no `.permit` call exists anywhere in
      its argument chain, or (b) the `.permit(...)` list is cited and shown to
      include a specific privileged attribute — name that attribute.
- [ ] If claiming raw SQL injection: the exact interpolated/concatenated
      string is quoted, and the traced source of the interpolated variable
      (e.g. `params[:email]`) is shown.
- [ ] If claiming a CSRF gap: the `skip_before_action`/`protect_from_forgery
      except:` line is cited AND the controller's actual authentication
      mechanism for that action is cited (or explicitly confirmed absent).
- [ ] Confirmation that the affected model/action isn't already protected by
      an equivalent mechanism elsewhere (global strong-parameters enforcement,
      a policy object, `attr_accessible` under Rails 3) before concluding
      protection is missing.

A finding without at least one concrete code-snippet evidence entry must not
be submitted.

## Attack Scenario Template

> An attacker sends a request to [specific controller action] with an
> additional/modified parameter `[param_name]` set to [attacker-chosen value].
> Because [specific code location] passes [params hash / raw SQL string]
> directly to [ActiveRecord method] without [missing check — permit
> filtering / parameterization / CSRF token], the request [succeeds in
> modifying a record the attacker shouldn't control / executes attacker-
> influenced SQL / performs a state change without a valid CSRF token],
> resulting in [concrete impact specific to this repo — e.g. "attacker
> escalates their own `role` column from `user` to `admin`"], not a generic
> description.

Fill every bracket concretely from evidence gathered in this repo. If a
bracket can't be filled from real evidence, the scenario is speculative and
severity must be capped at `medium`, with a note that exploitability is
unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:rails_framework` node exists (create it on the
  first Rails-related finding in a scan), with `depends_on` edges to
  `component:mass_assignment`, `component:sql_injection`, and
  `component:csrf` as relevant sub-components are actually found.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from the specific root-cause
  component (`component:mass_assignment`, `component:sql_injection`, or
  `component:csrf`) to the finding node.
- If a mass-assignment finding allows privilege escalation (a `role`/`admin`
  attribute becomes settable), add an `enables` edge from that finding node
  to `component:authorization` or to a more specific downstream component
  the escalated privilege unlocks (e.g. an admin panel or billing component).
- If a raw-SQL finding allows reading data outside the requesting user's
  scope, add an `enables` edge from the finding node to
  `component:data_access` or the specific database/table component affected.
- Root cause vs. symptom: if a CSRF-skip finding is what makes an otherwise
  session-only mass-assignment finding exploitable cross-site, say so
  explicitly in the finding's `reasoning` field so the graph mapper wires a
  `causes` edge between the two finding nodes rather than treating them as
  unrelated.
