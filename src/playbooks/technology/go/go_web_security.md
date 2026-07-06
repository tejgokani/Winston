---
id: technology.go.go_web_security
title: Go Web Service Security (net/http, gin, chi, gorilla/mux)
category: technology
vulnerabilityClass: injection_and_resource_exhaustion_and_race_conditions
appliesToStack: go
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A03:2021 Injection"
  - "A05:2021 Security Misconfiguration"
  - "A04:2021 Insecure Design"
cweRefs:
  - "CWE-89"
  - "CWE-400"
  - "CWE-362"
realWorldReferences:
  - title: "Cloudflare — The complete guide to Go net/http timeouts"
    url: "https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/"
    type: security_blog
  - title: "Cloudflare — So you want to expose Go on the Internet"
    url: "https://blog.cloudflare.com/exposing-go-on-the-internet/"
    type: security_blog
  - title: "Go documentation — Avoiding SQL injection risk (database/sql)"
    url: "https://go.dev/doc/database/sql-injection"
    type: vendor_security_advisory
  - title: "go-ibax — SQL Injection vulnerabilities via unparameterized query construction (GitHub Issue #2060)"
    url: "https://github.com/IBAX-io/go-ibax/issues/2060"
    type: bug_bounty_disclosure
  - title: "ZeroPath — Go database/sql Race Condition, CVE-2025-47907"
    url: "https://zeropath.com/blog/cve-2025-47907-go-database-sql-race-condition-summary"
    type: security_blog
quickModeSummary: >
  Check three Go-specific footguns: (1) are SQL queries built with
  fmt.Sprintf/string concatenation instead of database/sql placeholders
  (?, $1)? (2) is http.Server constructed as a bare &http.Server{} or
  http.ListenAndServe(...) with no ReadTimeout/WriteTimeout/IdleTimeout/
  ReadHeaderTimeout set, leaving it open to Slowloris-style exhaustion?
  (3) do concurrent request handlers read/write a shared package-level or
  struct-level variable (map, slice, counter) without a sync.Mutex/RWMutex
  or without confirming the type is safe under net/http's per-request
  goroutine model?
fileSelectionHint:
  roles: ["route_handler", "middleware", "database", "server_bootstrap"]
  matchImports:
    - "net/http"
    - "database/sql"
    - "github.com/gin-gonic/gin"
    - "github.com/go-chi/chi"
    - "github.com/gorilla/mux"
    - "github.com/labstack/echo"
  matchAuthMapTags: []
  maxFiles: 8
  priorityOrder: ["server_bootstrap", "route_handler", "database", "middleware"]
severityHeuristics:
  critical:
    - "User-controlled input reaches a SQL query string built via fmt.Sprintf/string concatenation and executed via db.Query/db.Exec/db.QueryRow with no parameterization anywhere in that query"
    - "A package-level or shared struct field mutable map/slice is written to by an HTTP handler with no mutex, and the same field is also read/written elsewhere concurrently (confirmed via multiple goroutine/handler call sites), risking corruption or crash under concurrent requests"
  high:
    - "http.Server (or the equivalent gin/chi/echo default) is started with no ReadTimeout, WriteTimeout, IdleTimeout, or ReadHeaderTimeout configured and is reachable from the public Internet, enabling Slowloris-style connection exhaustion"
    - "Partial parameterization: some query paths in a handler use placeholders correctly while a sibling code path (e.g. dynamic ORDER BY/table name) falls back to fmt.Sprintf on user input"
  medium:
    - "Timeouts are set but only ReadTimeout is configured, leaving WriteTimeout/IdleTimeout at zero (still exploitable for slow-response resource pinning, lower severity than fully unconfigured)"
    - "Shared mutable state is guarded by a mutex but the lock is held across a network/database call, creating a throughput bottleneck rather than a correctness bug — flag as a design concern, not a security vulnerability, unless it enables a denial-of-service"
  low:
    - "SQL identifiers (table/column names) are interpolated via fmt.Sprintf but the value set is a small fixed enum validated by a switch/allowlist earlier in the same function (not user-controlled at the point of interpolation)"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:go_web_service"
  relatedNodeIds:
    - "component:database"
    - "component:http_server"
    - "component:concurrency"
graphEdgeMapping:
  - relation: depends_on
    from: "component:go_web_service"
    to: "component:database"
  - relation: depends_on
    from: "component:go_web_service"
    to: "component:http_server"
  - relation: protects
    from: "component:concurrency"
    to: "component:go_web_service"
commonAiCodingMistakes:
  - "AI scaffolds a quick query with fmt.Sprintf('SELECT * FROM %s WHERE id = %s', table, id) 'to get it working,' intending to swap in placeholders later, and the fmt.Sprintf version ships because it passes every manual test with benign input."
  - "AI correctly parameterizes the WHERE clause value but still interpolates a dynamic ORDER BY column, LIMIT, or table name via fmt.Sprintf because database/sql placeholders can't be used for identifiers — and never adds an allowlist check for that identifier."
  - "AI writes `http.ListenAndServe(\":8080\", handler)` or `&http.Server{Addr: \":8080\", Handler: handler}` directly from a tutorial/quickstart example, which is exactly the zero-value-timeouts shape Go's own docs and the Cloudflare timeouts post warn is unsafe for a server exposed to the Internet."
  - "AI adds a package-level `var cache = map[string]T{}` (or similar in-memory store/counter/rate-limiter) for a quick feature, and every handler that reads/writes it runs in its own goroutine per net/http's request model — with no mutex, sync.Map, or channel serializing access, so concurrent requests race on the map (Go maps are not safe for concurrent read+write and will panic or corrupt state)."
  - "AI adds a mutex around shared state but locks it only for the write path and forgets to lock the read path (or vice versa), leaving a race that -race and code review both need to catch since it's asymmetric and easy to miss on a quick read."
falsePositiveGuardrails:
  - "Do not flag database/sql calls using `?` or `$1`-style placeholders passed as separate Query/Exec arguments — that is exactly the safe pattern; only flag when the query string itself is built with fmt.Sprintf/Sprintf-like formatting or string concatenation of untrusted input."
  - "Do not flag fmt.Sprintf used to build a SQL identifier (table/column name, sort direction) if the interpolated value is validated against a hardcoded allowlist/enum/switch immediately before use — that is the correct pattern for identifiers, which placeholders cannot cover."
  - "Do not flag missing http.Server timeouts if the service is not directly Internet-facing (e.g. sits behind a reverse proxy/load balancer that already enforces connection timeouts) — note this explicitly in the finding and check for evidence of a fronting proxy (nginx/envoy config, cloud LB) before citing Slowloris exploitability; if unconfirmed, cap severity at medium and say so."
  - "Do not flag every package-level variable as a race condition — first confirm it is (a) mutable after init and (b) actually accessed from more than one goroutine/handler path in the reviewed code. A package-level constant, a value only written once at startup before serving begins, or a variable only ever read (never written) after init is not a race."
  - "Do not flag correct uses of sync.Mutex/RWMutex, sync.Map, or channel-based serialization as vulnerable — those are the fix, not the bug. Only flag genuinely unsynchronized concurrent access."
  - "A single in-process cache with a mutex that is occasionally slow (lock contention) is a performance issue, not a security finding, unless the reviewer can show it enables an attacker-triggerable denial-of-service (e.g. an unbounded map that grows per-request with attacker-controlled keys, exhausting memory)."
---

## Root Cause Explanation

Go's standard library gives you sharp tools with unsafe defaults, and AI
coding assistants — trained on countless quickstart snippets — tend to
reproduce the *simplest working example* rather than the *production-safe*
one. Three failure modes recur across Go web services:

1. **SQL injection via string-built queries.** `database/sql` is
   parameterization-safe by design — placeholders (`?`, `$1`, `:name`
   depending on driver) are sent to the database separately from the query
   text, so user input can never be interpreted as SQL syntax. But nothing
   stops a developer (or an AI assistant reproducing a StackOverflow-style
   snippet) from building the query string themselves with `fmt.Sprintf` or
   `+` concatenation and passing the finished string to `db.Query`. At that
   point `database/sql` is just executing whatever string it was handed —
   the safety guarantee only holds if placeholders are actually used. This
   is explicitly called out as a footgun in Go's own documentation.
2. **Missing http.Server timeouts (Slowloris/resource exhaustion).** The
   zero-value `http.Server` — and the shortcut `http.ListenAndServe(addr,
   handler)`, which constructs one internally — has `ReadTimeout`,
   `WriteTimeout`, `IdleTimeout`, and `ReadHeaderTimeout` all unset (i.e.
   zero, meaning "no timeout"). A client that opens a connection and sends
   bytes at a trickle (or never finishes sending headers) ties up a
   goroutine and a file descriptor indefinitely. Enough such connections
   exhaust the server's file descriptors or memory — a classic Slowloris
   attack — with no attacker sophistication required. This is one of the
   most repeated pieces of Go production advice (Cloudflare's engineering
   blog devoted a full post to it) precisely because the unsafe form is
   also the form every tutorial teaches first.
3. **Goroutine-based races on shared mutable state.** `net/http` runs each
   incoming request in its own goroutine by default. That's the whole
   concurrency model — and it means any state shared across requests
   (a package-level map, an in-memory cache, a counter, a struct field on a
   long-lived handler receiver) is being accessed concurrently from the
   moment the server has more than one simultaneous request. Go maps are
   explicitly not safe for concurrent read/write; unsynchronized access
   causes runtime panics ("fatal error: concurrent map read and map
   write") at best and silent data corruption/logic bugs at worst. AI
   assistants scaffolding a quick in-memory cache or rate limiter routinely
   skip the mutex because single-request manual testing never exercises
   concurrency. Note this class extends to the standard library itself —
   CVE-2025-47907 is a race condition inside `database/sql` when a query
   is cancelled via context while a concurrent `Scan` is in flight,
   showing this failure mode isn't limited to hand-written application
   code.

## Vulnerable Patterns

Look for shapes like these (illustrative, not exhaustive — reason about
equivalents in the actual stack you're reviewing, don't string-match):

```go
// 1. SQL injection — query string built with user input
query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)
rows, err := db.Query(query)
// should be:
rows, err := db.Query("SELECT * FROM users WHERE username = ?", username)

// Partial fix that's still broken — dynamic identifier not allowlisted
sortCol := r.URL.Query().Get("sort")
query := fmt.Sprintf("SELECT * FROM users ORDER BY %s", sortCol) // sortCol unvalidated

// 2. http.Server with no timeouts — Slowloris-exploitable
http.ListenAndServe(":8080", mux)
// or
srv := &http.Server{Addr: ":8080", Handler: mux} // ReadTimeout/WriteTimeout/IdleTimeout all zero
srv.ListenAndServe()
// should set:
srv := &http.Server{
    Addr:              ":8080",
    Handler:           mux,
    ReadHeaderTimeout: 5 * time.Second,
    ReadTimeout:       10 * time.Second,
    WriteTimeout:      10 * time.Second,
    IdleTimeout:       120 * time.Second,
}

// 3. Unsynchronized shared state across request goroutines
var sessionCache = map[string]*Session{} // package-level, mutable

func handler(w http.ResponseWriter, r *http.Request) {
    sessionCache[token] = sess // concurrent write, no lock — races with every other request
}
// should guard with sync.RWMutex or sync.Map:
var (
    sessionCache = map[string]*Session{}
    cacheMu      sync.RWMutex
)
```

## Data Flow Tracing Guide

To evaluate this playbook responsibly, trace the following before writing any
Finding:

1. **SQL injection.** For every `db.Query`, `db.QueryRow`, `db.Exec`, or
   equivalent (`sqlx`, `gorm.Raw`, etc.) call: is the first argument a
   string literal with `?`/`$N` placeholders and the values passed as
   separate arguments, or is it a variable built earlier via
   `fmt.Sprintf`/concatenation? If built dynamically, trace every value fed
   into that format string back to its source — is it a request parameter,
   header, or path segment (untrusted), or a hardcoded/allowlisted constant
   (safe)?
2. **Server timeouts.** Find where the server is constructed and started
   (`http.ListenAndServe`, `http.ListenAndServeTLS`, `&http.Server{...}`,
   or a framework's `.Run()`/`.Start()` equivalent for gin/echo/chi, which
   typically wrap the same `http.Server` underneath). Confirm whether
   `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, and `ReadHeaderTimeout` are
   explicitly set. Then check deployment context (Dockerfile, k8s manifest,
   nginx/envoy config in the repo) for evidence the service sits behind a
   reverse proxy that already enforces its own timeouts — this changes
   exploitability but does not eliminate defense-in-depth value.
3. **Goroutine races.** Identify every package-level `var` and every field
   on a struct that outlives a single request (i.e. constructed once at
   startup, not per-request) that is a map, slice, or other mutable
   reference type. For each, grep all read and write sites. If more than
   one such site is reachable from an HTTP handler (meaning it runs inside
   the per-request goroutine), confirm whether a `sync.Mutex`/`sync.RWMutex`
   /`sync.Map`/channel wraps every access — not just some. Partial locking
   (write locked, read unlocked) is still a race.

## Evidence Checklist

Before submitting a Finding for this playbook, confirm:

- [ ] At least one concrete code snippet with an exact file + line range is
      attached as evidence — do not paraphrase, quote the actual line(s).
- [ ] If claiming SQL injection: the exact `fmt.Sprintf`/concatenation call
      site AND the exact `db.Query`/`db.Exec` call site are cited, plus the
      trace showing the interpolated value originates from an untrusted
      request input (not a hardcoded/allowlisted constant).
- [ ] If claiming missing server timeouts: the exact server construction
      site is cited, and a check was made for a fronting reverse proxy
      before asserting full Slowloris exploitability (note in the finding
      if unconfirmed and cap severity accordingly).
- [ ] If claiming a goroutine race: at least two distinct access sites
      (e.g. one read, one write) reachable from separate concurrent
      request-handling goroutines are cited, and it is confirmed no
      mutex/sync primitive wraps all of them.
- [ ] Confirmation that the finding is not one of the documented false
      positives (allowlisted identifier interpolation, proxy-fronted
      timeouts, write-once package-level constants).

A finding without at least one concrete code-snippet evidence entry must not
be submitted.

## Attack Scenario Template

> An attacker sends [request shape, e.g. "a crafted `username` parameter
> containing a SQL payload"] to [specific endpoint]. Because [specific code
> location] builds the query via [fmt.Sprintf/concatenation] instead of a
> parameterized placeholder, the payload is interpreted as SQL, resulting in
> [concrete impact specific to this repo — e.g. "bypassing the login check"
> or "exfiltrating the users table via UNION SELECT"].

> For resource exhaustion: An attacker opens [N] connections to
> [endpoint/server] and sends data at a deliberately slow rate (or never
> completes the request). Because [server construction site] has no
> ReadTimeout/ReadHeaderTimeout configured, each connection holds a
> goroutine and file descriptor open indefinitely, and with enough
> concurrent slow connections the server exhausts [file descriptors /
> memory / goroutine budget], denying service to legitimate clients.

> For a goroutine race: Two concurrent requests both reach [handler] which
> reads/writes [shared variable] at [file:line] without synchronization.
> Under Go's per-request-goroutine model this produces [a runtime panic /
> corrupted state / a stale read], resulting in [concrete impact, e.g. "a
> user occasionally receiving another user's cached session data"].

Fill every bracket concretely from evidence gathered in this repo. If a
bracket can't be filled from real evidence, the scenario is speculative and
severity must be capped at `medium`, with a note that exploitability is
unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:go_web_service` node exists (create it on the
  first finding from this playbook in a scan), with `depends_on` edges to
  `component:database` (for SQL injection findings) and
  `component:http_server` (for timeout findings) as relevant.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from the most specific root-cause
  component (`component:database` for SQL injection, `component:http_server`
  for missing timeouts, `component:concurrency` for goroutine races) to the
  finding node.
- If a SQL injection finding could lead to full data exfiltration or
  authentication bypass, add an `enables` edge from the finding node to
  `component:database` (or a more specific data-store node id if one
  exists in the graph, e.g. `component:users_table`).
- If a missing-timeout finding is only partially exploitable because a
  fronting reverse proxy was found, note this explicitly in the finding's
  `reasoning` field so the graph mapper can attach it as a lower-severity
  `causes` edge rather than a direct `enables` edge to a denial-of-service
  outcome.
- Root cause vs. symptom: if a goroutine race finding is *caused by* an
  earlier finding in this scan (e.g. a missing-mutex finding in a shared
  cache module causes a downstream data-corruption finding in a handler
  that reads that cache), say so explicitly in the finding's `reasoning`
  field so the graph mapper can wire a `causes` edge between the two
  finding nodes rather than treating them as unrelated.
