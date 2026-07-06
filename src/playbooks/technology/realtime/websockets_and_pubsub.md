---
id: technology.realtime.websockets_and_pubsub
title: WebSocket and Pub/Sub Security
category: technology
vulnerabilityClass: broken_access_control
appliesToStack: realtime
deepOnly: false
reviewPass: 1
owaspRefs:
  - "A01:2021 Broken Access Control"
  - "A07:2021 Identification and Authentication Failures"
cweRefs:
  - "CWE-306"
  - "CWE-862"
  - "CWE-863"
  - "CWE-346"
realWorldReferences:
  - title: "PortSwigger Web Security Academy — Cross-site WebSocket hijacking"
    url: "https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking"
    type: security_blog
  - title: "Coda (formerly Superhuman/Grammarly) — Lack of Origin check leads to Cross-Site WebSocket Hijacking (HackerOne #535436)"
    url: "https://hackerone.com/reports/535436"
    type: bug_bounty_disclosure
  - title: "Legal Robot — Cross Site WebSocket Hijacking via missing Origin validation (HackerOne #211283)"
    url: "https://hackerone.com/reports/211283"
    type: bug_bounty_disclosure
  - title: "Bykea — Exposed trip_no in WebSocket response leaks customer tracking data to unauthorized drivers (HackerOne #2209750)"
    url: "https://hackerone.com/reports/2209750"
    type: bug_bounty_disclosure
quickModeSummary: >
  Check three independent gaps in realtime/WebSocket code (Socket.io, ws,
  Pusher, Ably, Supabase Realtime, or any pub/sub-over-WebSocket setup):
  (1) is the connection/handshake itself authenticated — does the server
  verify a session/token before accepting the upgrade or before processing
  any message, or does it trust whatever the client claims after connecting;
  (2) is channel/room/topic subscription authorized per-subscriber — can a
  client subscribe to another user's private channel just by knowing or
  guessing its name/ID (e.g. `user-123`, `chat-456`), with no server-side
  check that the connecting principal actually owns/belongs to that channel;
  (3) is the `Origin` header validated on the handshake — WebSockets are not
  covered by the browser's same-origin policy or CORS, so any authenticated
  WebSocket endpoint that doesn't explicitly check `Origin` is vulnerable to
  Cross-Site WebSocket Hijacking (CSWSH), letting a malicious page silently
  open an authenticated connection using the victim's browser session.
fileSelectionHint:
  roles: ["route_handler", "middleware", "realtime", "socket_handler", "auth"]
  matchImports: ["socket.io", "ws", "pusher", "pusher-js", "ably", "@supabase/supabase-js"]
  matchAuthMapTags: ["realtime"]
  maxFiles: 8
  priorityOrder: ["socket_handler", "middleware", "auth", "route_handler"]
severityHeuristics:
  critical:
    - "The WebSocket handshake/connection handler performs no authentication at all — any client can connect and immediately send/receive messages, including ones that trigger privileged actions or return sensitive data."
    - "Channel/room subscription accepts a client-supplied channel name/ID with no server-side check that the connecting principal is authorized for that specific channel (e.g. `socket.join(req.data.roomId)` with no ownership/membership check), and channel identifiers are guessable, sequential, or otherwise enumerable."
  high:
    - "The handshake authenticates the connection (e.g. verifies a JWT once at `io.use()`/`connection` time) but never re-validates the `Origin` header — a same-origin-policy-adjacent gap that allows Cross-Site WebSocket Hijacking, letting an attacker's page silently ride the victim's authenticated session to read/send data over the socket."
    - "Private/broadcast pub/sub channels (Pusher/Ably) are configured as public channels instead of private/presence channels for data that should be scoped to a specific user or authorization check, so any client holding the app/channel key can subscribe."
  medium:
    - "Authentication happens on initial connection but individual message handlers (custom event types) don't re-check authorization per message for actions that should be scoped (e.g. a connection authenticated as a regular user can still emit an admin-only event because the per-event handler trusts the initial connection-level auth for everything)."
    - "Sensitive fields are included in broadcast payloads sent to all subscribers of a shared channel/room rather than filtered per-recipient, leaking data to users who can see the broadcast but shouldn't see that specific field."
  low:
    - "`wss://` (TLS) is not enforced and the app allows falling back to unencrypted `ws://` in a context where that's not caught by infrastructure-level TLS termination — defense-in-depth gap, confirm actual transport before treating as more than low."
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:realtime_channel"
  relatedNodeIds: ["component:authentication", "component:authorization"]
graphEdgeMapping:
  - relation: depends_on
    from: "component:realtime_channel"
    to: "component:authentication"
  - relation: depends_on
    from: "component:realtime_channel"
    to: "component:authorization"
commonAiCodingMistakes:
  - "AI scaffolds a Socket.io/ws server by wiring up `io.on('connection', socket => {...})` and adding event handlers directly, without adding an `io.use((socket, next) => {...})` authentication middleware first — because the HTTP routes elsewhere in the same app are already protected by session/JWT middleware, it's easy to assume that protection extends to the separate WebSocket upgrade path, when in fact it's a distinct connection that needs its own auth check."
  - "AI implements room/channel-based features (chat rooms, per-user notification channels, live document collaboration) using a predictable channel-naming scheme (`user-${userId}`, `room-${roomId}`) and has the client tell the server which channel to join (`socket.on('join', roomId => socket.join(roomId))`) without checking that the connecting principal is actually a member of/owns that room — the AI gets the feature working end-to-end (join, then receive events) without ever writing the authorization check, because nothing in the happy-path testing flow requires one."
  - "AI configures Pusher/Ably channels as public channels (the default/simplest option in most tutorials) even when the data being broadcast is private to a specific user or group, because private/presence channels require an extra server-side auth endpoint that adds friction the AI skips to get the demo working, then the auth endpoint never gets added later."
  - "AI copies a WebSocket server setup from a tutorial or boilerplate that omits Origin validation entirely, because unlike CORS (which is enforced by the browser automatically unless explicitly relaxed), WebSockets require the developer to opt IN to Origin checking — there's no secure-by-default browser behavior to accidentally rely on, so a security-naive implementation is CSWSH-vulnerable by default rather than by misconfiguration."
  - "AI reuses a single 'is the user logged in' check performed once at connection time to authorize every subsequent event on that socket, including newly-added privileged event types (e.g. an admin broadcast or a destructive action added later in the same session), without adding per-event-type authorization checks — mirroring the same 'protected once, trusted forever' failure mode seen in JWT claim trust and Prisma mass-assignment playbooks, just at the connection level instead of the request level."
falsePositiveGuardrails:
  - "Do not flag a WebSocket endpoint that carries only genuinely public, non-sensitive broadcast data (e.g. a public live-scoreboard, public stock ticker) as missing authentication — the finding requires the data or actions reachable over the socket to actually be sensitive/privileged; state explicitly what's exposed before assigning severity."
  - "Do not treat every channel/room join as unauthorized without checking for a server-side authorization check somewhere in the join handler or a preceding middleware — some frameworks (Socket.io namespaces with per-namespace middleware, Pusher/Ably private-channel auth endpoints) enforce this outside the immediate `join`/`subscribe` call; trace to the actual authorization decision point before concluding it's missing."
  - "A missing `Origin` check is not automatically critical severity — it becomes exploitable (CSWSH) specifically when the connection is cookie-authenticated (browser automatically attaches session cookies to the WebSocket handshake) and carries sensitive functionality; if auth is via a token the page must explicitly attach (not auto-sent by the browser), CSWSH does not apply the same way — confirm the authentication mechanism before citing PortSwigger's CSWSH class at critical/high."
  - "Pusher/Ably public channels are not a finding by themselves if the data broadcast on them is intentionally public — only flag when a specific piece of user-private or tenant-private data is confirmed to be sent over a public (non-private, non-presence) channel."
  - "Server frameworks / managed realtime platforms (Supabase Realtime with Row Level Security enabled on the underlying table, Ably/Pusher with a correctly implemented private-channel auth endpoint) can enforce authorization at a layer outside the immediate handler code — verify whether such a platform-level control is actually configured and active (e.g. RLS policies exist and are enabled on the relevant table) before concluding channel-level access control is absent."
---

## Root Cause Explanation

WebSocket and pub/sub-over-WebSocket systems (Socket.io, `ws`, Pusher, Ably,
Supabase Realtime) break the security assumptions developers carry over from
HTTP request/response code in three distinct, commonly-missed ways:

1. **The handshake is a separate trust boundary from HTTP routes.** A
   WebSocket connection begins with an HTTP upgrade request, but from that
   point forward it's a long-lived, stateful, bidirectional channel — not a
   series of independently-authenticated requests. Middleware that protects
   REST routes does not automatically apply to the WebSocket upgrade path or
   to events sent over an already-established socket. If the server doesn't
   explicitly verify a session/token at connection time (and, for
   longer-lived connections, doesn't handle token expiry), the entire
   channel is unauthenticated even in an application whose HTTP API is
   properly protected.
2. **Channel/room/topic subscription is authorization, not just
   addressing.** Realtime features are almost always built around named
   channels — a room ID, a user's personal notification channel, a document
   ID. The natural implementation lets the client tell the server which
   channel to join. But "which channel to join" is a client-supplied value,
   and unless the server checks that the connecting principal is actually
   entitled to that specific channel (owns it, is a member of it, was
   invited to it), any client that can guess or enumerate a channel name can
   subscribe to someone else's private data stream. This is structurally the
   same missing-row-level-scoping problem covered for Mongoose in
   `technology/mongodb/mongoose_security.md`, just expressed as "which
   channel can I join" instead of "which document can I query."
3. **WebSockets are not covered by the Same-Origin Policy or CORS.** A page
   on `evil.example` can open a `new WebSocket('wss://victim.example/...')`
   connection using the victim's browser, and the browser will happily
   attach that domain's cookies to the handshake, exactly as it would for an
   image tag or a form submission — there is no preflight, no CORS check,
   and no same-origin restriction blocking this the way there is for
   `fetch()`/XHR. This is Cross-Site WebSocket Hijacking (CSWSH), and per
   PortSwigger's Web Security Academy, the only mitigation is for the server
   to explicitly validate the `Origin` header on the handshake and reject
   connections from unexpected origins — nothing does this by default. Two
   independently disclosed HackerOne reports (Coda/Superhuman #535436 and
   Legal Robot #211283) show this is a real, recurring, exploitable gap in
   production applications, not a theoretical academy-lab-only issue.

## Vulnerable Patterns

```js
// 1. No authentication on the WebSocket connection at all
io.on('connection', (socket) => {
  socket.on('getUserData', (userId, cb) => {
    User.findById(userId).then(cb); // anyone who can connect can call this
  });
});

// Correct shape — authenticate before any handler is registered
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  const user = verifyToken(token); // throws/returns null if invalid
  if (!user) return next(new Error('unauthorized'));
  socket.data.user = user;
  next();
});

// 2. Client-controlled channel join with no ownership/membership check
socket.on('join', (roomId) => {
  socket.join(roomId); // client can join ANY room by ID, including others'
});

// Correct shape — verify membership before joining
socket.on('join', async (roomId) => {
  const isMember = await Room.exists({ _id: roomId, members: socket.data.user.id });
  if (!isMember) return socket.emit('error', 'forbidden');
  socket.join(roomId);
});

// 3. No Origin validation — vulnerable to CSWSH even though auth exists
const wss = new WebSocketServer({ port: 8080 });
wss.on('connection', (ws, req) => {
  // cookies are auto-attached by the browser regardless of origin;
  // nothing here checks req.headers.origin
});

// Correct shape — explicitly validate Origin during the handshake
wss.on('connection', (ws, req) => {
  const origin = req.headers.origin;
  if (!ALLOWED_ORIGINS.includes(origin)) {
    ws.close(1008, 'origin not allowed');
    return;
  }
});
```

## Data Flow Tracing Guide

Trace the following before writing any Finding:

1. **Handshake authentication.** Find where the WebSocket server is
   constructed and where connections are accepted (`io.on('connection', ...)`,
   `wss.on('connection', ...)`, a Pusher/Ably server-auth endpoint). Is there
   an authentication step (`io.use(...)` middleware, a token check inside
   the `connection` handler before any other logic runs, a signed auth
   response for Pusher/Ably private channels) that runs before any
   event/message handling is wired up? If authentication happens after
   handlers are already registered, or only on some handlers, that's a gap.
2. **Per-event/per-message re-authorization.** For each distinct event/message
   type the server handles after connection, determine whether it performs
   its own authorization check appropriate to what it does, or whether it
   relies solely on "the connection was authenticated once." An event that
   performs a privileged or user-scoped action needs its own check — connection-time
   auth establishes identity, not blanket permission for everything that
   comes after.
3. **Channel/room authorization.** For every `join`/`subscribe`-style
   handler, trace the channel/room identifier back to its source (client
   message payload vs. server-derived from the authenticated principal, e.g.
   auto-joining `user:${socket.data.user.id}` is safe; joining
   `socket.data.user.requestedRoomId` is not, without a check). Confirm
   whether a server-side membership/ownership check runs between receiving
   the requested channel and actually subscribing the client to it.
4. **Origin validation.** Grep for `req.headers.origin` / `socket.handshake.
   headers.origin` / equivalent in the connection handler. If absent, check
   whether the authentication mechanism is cookie-based (auto-attached by
   the browser, so vulnerable to CSWSH) or requires an explicit
   client-supplied token not automatically sent cross-site (lower risk from
   this specific vector, though still worth flagging as hardening).
5. **Managed pub/sub platforms (Pusher/Ably/Supabase Realtime).** Check
   whether channels used for private data are declared as `private-*`/
   `presence-*` (Pusher/Ably) with a real server-side authorization endpoint
   behind them, versus plain public channels. For Supabase Realtime, check
   whether Row Level Security is enabled and enforced on the underlying
   table the realtime subscription reads from — Supabase Realtime respects
   RLS, so a table with RLS disabled effectively broadcasts to any
   subscriber regardless of application-level intent.

## Evidence Checklist

Before submitting a Finding for this playbook, confirm:

- [ ] At least one concrete code snippet with exact file + line range is
      attached as evidence — do not paraphrase, quote the line(s).
- [ ] If claiming missing handshake authentication: the connection handler
      is cited, and it's shown that no auth check runs before handlers
      process messages/events.
- [ ] If claiming missing channel/room authorization: the join/subscribe
      handler is cited, AND the channel identifier's client-controlled
      origin is shown, AND confirmation that no membership/ownership check
      exists between receiving the request and subscribing.
- [ ] If claiming CSWSH: confirmation that the handshake is cookie-authenticated
      (or otherwise implicitly trusts browser-attached credentials) AND that
      no `Origin` header validation exists in the handshake handler.
- [ ] What sensitive data/actions are actually reachable through the gap is
      stated concretely — not a generic "the socket isn't authenticated"
      claim.

A finding without at least one concrete code-snippet evidence entry must not
be submitted.

## Attack Scenario Template

> An attacker [connects directly to the WebSocket endpoint with no valid
> session / lures a victim to a malicious page that opens a cross-origin
> WebSocket connection / sends a `join`/`subscribe` request for
> [channel/room ID] belonging to another user]. Because [specific code
> location] does not [missing check — authenticate the handshake / validate
> the `Origin` header / verify channel membership], the connection succeeds
> and [specific event/data] is [sent to / received from] the attacker,
> resulting in [concrete impact specific to this repo, e.g. "disclosure of
> another user's live chat messages" or "the ability to emit admin-only
> broadcast events" — not a generic description].

Fill every bracket concretely from evidence gathered in this repo. If a
bracket can't be filled from real evidence, the scenario is speculative and
severity must be capped at `medium`, with a note that exploitability is
unconfirmed.

## Graph Mapping Instructions

- Always ensure a `component:realtime_channel` node exists (create it on the
  first WebSocket/pub-sub finding in a scan) with `depends_on` edges to both
  `component:authentication` and `component:authorization`.
- Each concrete vulnerability becomes its own `finding:<uuid>` node of type
  `vulnerability`, with a `causes` edge from `component:realtime_channel` (or
  `component:authentication` specifically for handshake-level findings, or
  `component:authorization` for channel-subscription findings) to the
  finding node.
- If a finding enables reaching another user's private data stream or a
  privileged action, add an `enables` edge from the finding node to the
  relevant component (`component:authorization`, or a more specific
  component like `component:messaging` if the graph schema tracks it).
- CSWSH findings should add a `causes` edge noting the relationship to CSRF
  concepts already tracked in the graph, if a `component:csrf_protection`
  node exists in this scan, since CSWSH is CSRF's WebSocket-transport
  analog and shares the same root cause category (implicit credential
  attachment with no origin check).
- Root cause vs. symptom: if a finding is *caused by* another finding
  already identified in this scan (e.g. a missing-handshake-auth finding is
  the root cause behind several individually-vulnerable event handlers that
  all assumed the connection was authenticated), say so explicitly in the
  finding's `reasoning` field so the graph mapper wires a `causes` edge
  between them rather than treating them as unrelated duplicates.
