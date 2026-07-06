---
id: technology.supabase.row_level_security
title: "Supabase: Row Level Security (RLS) Misconfiguration"
category: technology
vulnerabilityClass: broken_access_control
appliesToStack: supabase
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A01:2021 Broken Access Control"
cweRefs:
  - "CWE-284"
  - "CWE-862"
  - "CWE-863"
realWorldReferences:
  - title: "CVE-2025-48757 — Insufficient Row Level Security in Lovable-generated Supabase projects"
    url: "https://mattpalmer.io/posts/2025/05/CVE-2025-48757/"
    type: bug_bounty_disclosure
  - title: "Supabase Leaks, What We Found (Cognisys Group Labs)"
    url: "https://labs.cognisys.group/posts/Supabase-Leaks-What-We-Found/"
    type: security_blog
  - title: "Row Level Security — Supabase official documentation"
    url: "https://supabase.com/docs/guides/database/postgres/row-level-security"
    type: vendor_security_advisory
  - title: "Supabase Security Retro: 2025"
    url: "https://supabase.com/blog/supabase-security-2025-retro"
    type: vendor_security_advisory
  - title: "Is Lovable Actually Secure? I Checked the Supabase RLS on 50 Apps"
    url: "https://dev.to/tgoldi/is-lovable-actually-secure-i-checked-the-supabase-rls-on-50-apps-38o2"
    type: security_blog
quickModeSummary: >
  For every table reachable through the Supabase REST/GraphQL API (i.e. every
  table not exclusively accessed via service_role from trusted server code):
  is RLS enabled at all (`ALTER TABLE ... ENABLE ROW LEVEL SECURITY`)? If
  enabled, do the policies actually scope rows to the requesting user (e.g.
  `auth.uid() = user_id`) rather than just checking `auth.role() =
  'authenticated'` or `USING (true)`? Is the `service_role` key ever
  referenced in client-side/browser-bundled code? Were any tables created via
  raw SQL/migration (not the dashboard Table Editor), where RLS is NOT
  enabled by default?
fileSelectionHint:
  roles: ["database", "migration", "api_client", "config"]
  matchImports: ["@supabase/supabase-js", "@supabase/ssr", "@supabase/auth-helpers-nextjs"]
  matchAuthMapTags: ["supabase"]
  maxFiles: 10
  priorityOrder: ["migration", "database", "config", "api_client"]
severityHeuristics:
  critical:
    - "A table storing sensitive data (PII, credentials, tokens, financial records) has RLS disabled entirely, or has RLS enabled but zero policies attached, and is reachable through the publishable/anon key — this is full, unauthenticated read/write exposure identical in shape to CVE-2025-48757."
    - "The `service_role` key (or any `SUPABASE_SERVICE_ROLE_KEY`-equivalent secret) appears in client-side code, a public env var (e.g. `NEXT_PUBLIC_*`, `VITE_*`), or a bundled frontend file — this key bypasses RLS entirely, so its exposure is equivalent to handing out full database admin access."
    - "A policy uses `USING (true)` or `WITH CHECK (true)` on a table containing another user's private data — functionally identical to RLS being off for that operation."
  high:
    - "A policy checks only `auth.role() = 'authenticated'` (or `auth.uid() IS NOT NULL`) without also scoping to the row owner (e.g. missing `AND user_id = auth.uid()`) — any logged-in user can read/write every other user's rows."
    - "A table was created via raw SQL/migration file with no accompanying `ENABLE ROW LEVEL SECURITY` statement — Supabase does NOT enable RLS by default for SQL-created tables (only dashboard Table Editor tables get it by default)."
    - "An UPDATE or DELETE policy exists but the corresponding SELECT policy is missing or broader than intended, letting a user discover/target rows they shouldn't be able to see."
    - "A Postgres VIEW exposes joined data from RLS-protected tables without `security_invoker = true`, silently running with the view creator's elevated privileges and bypassing the underlying tables' RLS."
  medium:
    - "A policy relies on `raw_user_meta_data` (user-editable via the client SDK) for an authorization decision instead of `raw_app_meta_data` (server-only) — a user can self-escalate by editing their own metadata."
    - "A policy pattern like `auth.uid() = user_id` is used without an explicit `auth.uid() IS NOT NULL` guard, which can silently fail open/closed in edge cases involving anonymous/unauthenticated sessions depending on how the column is nullable."
  low:
    - "RLS is correctly enabled and scoped, but a Postgres function referenced by a policy is marked `SECURITY DEFINER` and lives in an API-exposed schema, creating a defense-in-depth gap if that function is ever called directly."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:supabase_rls"
  relatedNodeIds: ["component:authorization", "component:database", "component:backend_as_a_service"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:supabase_rls"
    to: "component:authorization"
  - relation: protects
    from: "component:supabase_rls"
    to: "component:database"
commonAiCodingMistakes:
  - "AI scaffolds a table via a raw SQL migration file (the natural output format for schema changes) and never adds the `ENABLE ROW LEVEL SECURITY` statement, because the dashboard's default-on behavior isn't something a migration-file-based workflow benefits from — this is the exact root cause documented in CVE-2025-48757 for Lovable-generated projects, and generalizes to any AI agent writing Supabase migrations directly."
  - "AI writes a policy that gets the *shape* right (a `USING` clause exists) but the *scope* wrong — e.g. `USING (auth.role() = 'authenticated')` instead of `USING (auth.uid() = user_id)` — because it satisfies the immediate goal ('logged-in users can access this') without reasoning about cross-tenant/cross-user isolation. Field research on Lovable-generated apps found this exact mistake in roughly 80% of reviewed projects."
  - "AI adds a `service_role` key to a `.env` file or client-side Supabase initialization to 'fix' a permissions error it can't otherwise resolve (RLS blocking a legitimate query it hasn't scoped correctly), rather than writing the correct policy — this silently converts a scoping bug into an admin-key-in-the-browser vulnerability, which is materially worse than the original bug."
  - "AI adds a scan/checklist step that confirms RLS is 'enabled' on a table but does not evaluate whether the attached policy is actually restrictive (e.g. a table with RLS on and a single `USING (true)` policy passes a naive 'is RLS on?' check while remaining fully world-readable) — mirrors the documented gap in Lovable's own post-CVE security-scan feature."
  - "AI creates a VIEW to simplify a multi-table query for the frontend and doesn't add `security_invoker = true`, so the view silently runs with elevated privileges and bypasses RLS on the underlying tables even though those tables' policies look correct in isolation."
falsePositiveGuardrails:
  - "Do not flag a table as vulnerable purely because it's queried with the `service_role` key — that is expected and safe when the calling code is confirmed server-side only (a Next.js Route Handler, an Edge Function, a backend service) and never bundled into client JS. Verify the import/usage site, not just the key's presence in the codebase."
  - "Do not flag tables that are genuinely public-by-design (e.g. a `public_listings` table meant to be world-readable) as missing RLS scoping — confirm the business intent before assuming every table needs per-user isolation. A permissive SELECT policy on public content is not a vulnerability; the same permissiveness on a `users` or `orders` table is."
  - "RLS being enabled with a correct, narrowly-scoped policy for the relevant operation (SELECT/INSERT/UPDATE/DELETE) is sufficient — do not require additional application-layer authorization checks on top of correct RLS policies unless the codebase's own threat model calls for defense-in-depth beyond the database layer."
  - "Before flagging a missing `ENABLE ROW LEVEL SECURITY` statement, confirm the table was actually created via migration/SQL in this codebase and not via the dashboard Table Editor (which enables RLS by default) — check migration history/comments for provenance if available, since the two creation paths have different default postures."
  - "Anonymous Supabase Auth users (`signInAnonymously()`) still carry the `authenticated` Postgres role, not `anon` — do not assume a policy checking `TO authenticated` excludes anonymous/guest sessions; this is a common source of both false positives and false negatives, so verify what the app's auth flow actually issues."
---

## Root Cause Explanation

Supabase exposes your Postgres database directly to the internet through an
auto-generated REST (PostgREST) and GraphQL API, gated by a public
"publishable"/`anon` API key that is *designed* to be embedded in client-side
code. Unlike a traditional backend where you write an authorization check in
each route handler, in Supabase **Row Level Security policies are the entire
authorization layer**. If RLS is off, or on with a policy that doesn't
actually scope rows to their owner, there is no other gate standing between
an anonymous internet request and your data — the anon key alone provides
full SELECT/INSERT/UPDATE/DELETE access to any RLS-unprotected table by
design.

This produces a small number of recurring failure modes, ranked by how often
they show up in AI-assisted codebases specifically:

1. **RLS never enabled.** Tables created through the Supabase dashboard
   Table Editor get RLS enabled by default. Tables created via raw SQL
   migrations — the format almost every AI coding agent uses when asked to
   "add a table" or "create a migration" — do **not**. This asymmetry is the
   single most common root cause in real incidents, including the
   Lovable/Supabase vulnerability tracked as CVE-2025-48757.
2. **RLS enabled, policy too permissive.** A table has RLS on, satisfying a
   naive "is it protected?" check, but the policy is `USING (true)` or
   checks only `auth.role() = 'authenticated'` — i.e. "you're logged in" —
   instead of `auth.uid() = user_id` — i.e. "this row belongs to you."
   Reviewers scanning real AI-generated (Lovable) apps found this exact
   pattern in roughly 80% of projects that had *some* RLS in place.
3. **The wrong column, or a missing SELECT policy.** A policy references a
   column that doesn't actually identify the row's owner, or an UPDATE/DELETE
   policy exists without a matching SELECT policy, producing inconsistent or
   silently-failing enforcement.
4. **`service_role` key exposure.** The `service_role` key bypasses RLS
   entirely — it is meant only for trusted server environments. When it ends
   up in client-side code, a public env var, or a bundled JS file, it is
   strictly worse than having no RLS at all, because it also bypasses any
   RLS that *is* correctly configured.
5. **Bypasses around otherwise-correct RLS**: views without
   `security_invoker = true`, `SECURITY DEFINER` functions exposed in an API
   schema, and user-editable JWT metadata (`raw_user_meta_data`) used in
   authorization decisions.

## Vulnerable Patterns

```sql
-- Table created via migration — RLS is OFF by default here.
-- (Dashboard-created tables default to ON; SQL-created tables do not.)
create table public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id),
  total numeric,
  payment_status text
);
-- Missing: alter table public.orders enable row level security;
```

```sql
-- RLS enabled, but the policy is wide open — functionally identical to no RLS.
alter table public.orders enable row level security;
create policy "orders_select" on public.orders
  for select using (true);
```

```sql
-- RLS enabled, policy checks login status but not ownership.
-- Any authenticated user can read every other user's orders.
create policy "orders_select" on public.orders
  for select using (auth.role() = 'authenticated');
-- Should be: using (auth.uid() = user_id)
```

```js
// service_role key referenced in code that ships to the browser —
// bypasses RLS entirely for anyone who extracts it from the bundle.
const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)
```

```sql
-- View bypasses RLS on the underlying orders table because it runs with
-- the view creator's privileges (security_invoker defaults to false).
create view public.order_summaries as
  select o.id, o.total, u.email from orders o join auth.users u on u.id = o.user_id;
-- Should specify: create view ... with (security_invoker = true) as ...
```

## Data Flow Tracing Guide

To evaluate this playbook responsibly, trace the following before writing any
Finding:

1. Enumerate every table reachable via the Supabase client SDK (`.from('table_name')` calls) across the codebase — this is your candidate list. Cross-reference each against migration files to find its `CREATE TABLE` statement and check whether `ENABLE ROW LEVEL SECURITY` appears anywhere afterward for that table.
2. For every table with RLS enabled, find every `CREATE POLICY` targeting it and classify: does the `USING`/`WITH CHECK` clause reference `auth.uid()` compared against an owner column, or does it stop at `auth.role() = 'authenticated'` / `true` / no user-scoping condition at all?
3. Grep for `service_role` and any variant of the service-role key (`SUPABASE_SERVICE_ROLE_KEY`, etc.) across the entire codebase, not just server directories — confirm every usage site is genuinely server-only (no `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_` prefix, no import reachable from a client component/bundle).
4. For any `CREATE VIEW` statement, check for `security_invoker = true` (Postgres 15+) — its absence means the view runs with elevated privileges regardless of the underlying tables' RLS policies.
5. Check whether any policy references `raw_user_meta_data` (client-editable) versus `raw_app_meta_data` (server-only) for an authorization decision.
6. If an `auth_map` or equivalent context is available, cross-check whether the app uses `signInAnonymously()` — anonymous Supabase Auth sessions carry the `authenticated` role, not `anon`, which changes which policies actually apply to them.

## Evidence Checklist

Before submitting a Finding for this playbook, confirm:

- [ ] The exact table name and its migration file + line range are cited as
      evidence that RLS is missing, or the exact `CREATE POLICY` statement
      (file + line range) is cited as evidence of an overly permissive
      policy.
- [ ] If claiming missing RLS: confirmation that the table is actually
      reachable via the client SDK/anon key (not exclusively queried through
      server-side `service_role` code).
- [ ] If claiming a `service_role` key exposure: the exact file/line where
      the key is referenced, and confirmation (via import chain or bundler
      config) that the code path is reachable from client-side/browser code.
- [ ] If claiming an overly permissive policy: the exact policy clause is
      quoted, not paraphrased, and the specific column that *should* have
      been checked (e.g. `user_id`) is identified from the table schema.
- [ ] Confirmation the table isn't intentionally public content (checked
      against business context, not assumed).

A finding without at least one concrete code-snippet or SQL-statement
evidence entry must not be submitted.

## Attack Scenario Template

> An unauthenticated (or any authenticated) attacker uses the publicly
> embedded Supabase anon key to call `[table/endpoint]` directly via the
> REST/GraphQL API. Because [specific migration/policy file:line] either
> never enables RLS on this table, or defines a policy that checks
> [insufficient condition] instead of ownership, the request returns
> [concrete data — e.g. "every user's orders table including payment_status
> and email"] with no legitimate access to that data required. This mirrors
> the pattern in CVE-2025-48757, where Lovable-generated Supabase projects
> exposed PII and financial records identically.

Fill every bracket concretely from evidence gathered in this repo. If a
bracket can't be filled from real evidence, the scenario is speculative and
severity must be capped at `medium`, with a note that exploitability is
unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:supabase_rls` node exists (create it on the
  first Supabase-RLS-related finding in a scan) with a `depends_on` edge to
  `component:authorization`.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from `component:supabase_rls` to the
  finding node.
- If a finding involves a `service_role` key exposed to client code, also add
  a `causes` edge from `component:secrets` to that finding node, and an
  `enables` edge from the finding node to `component:database`, since it
  represents full database compromise rather than a single-table leak.
- Root cause vs. symptom: if a missing-RLS finding on a table is the reason a
  downstream finding is exploitable (e.g. a table lacking RLS enables an
  account-takeover finding via a writable settings table), say so explicitly
  in the finding's `reasoning` field so the graph mapper can wire a `causes`
  edge between the two finding nodes rather than treating them as unrelated.
