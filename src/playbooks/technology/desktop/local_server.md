---
id: technology.desktop.local_server
title: "Desktop: Local IPC & Embedded Servers"
category: technology
vulnerabilityClass: broken_access_control
appliesToStack: desktop apps exposing a local HTTP/WebSocket/named-pipe server
requiresAnyTag: ["electron", "tauri"]
deepOnly: false
reviewPass: 2
owaspRefs:
  - "A01:2021 Broken Access Control"
  - "A05:2021 Security Misconfiguration"
cweRefs:
  - "CWE-419"
  - "CWE-346"
  - "CWE-1385"
realWorldReferences:
  - title: "Zoom local web server RCE — a localhost HTTP server any website could reach (2019 incident)"
    url: "https://infosecwriteups.com/zoom-zero-day-4-million-webcams-maybe-an-rce-just-get-them-to-visit-your-website-ac75c83f4ef5"
    type: incident_postmortem
  - title: "'DNS rebinding' and CSRF against local desktop servers — any web page reaching a localhost service"
    url: "https://portswigger.net/web-security/dns-rebinding"
    type: research_paper
  - title: "Browser extension / desktop app local WebSocket bridges abused by malicious web pages"
    url: "https://www.tenable.com/blog/local-websocket-servers"
    type: security_blog
quickModeSummary: >
  Desktop apps that open a local server (HTTP/WebSocket on 127.0.0.1, or a named
  pipe/unix socket) to talk to their own frontend or a browser extension create a
  surface that OTHER local apps — and, crucially, ANY WEBSITE the user visits —
  can reach: a web page can `fetch`/`WebSocket` to `http://localhost:PORT` and,
  via DNS rebinding, bypass origin checks. The Zoom local-server RCE is the
  canonical case. Review any localhost/pipe server for: authentication (a
  per-session token the web page can't guess — not just "it's localhost"), strict
  origin/`Host` validation and CSRF protection, DNS-rebinding defenses (validate
  Host header), and least-privilege endpoints (a local server that runs commands
  or exposes sensitive actions is remote-triggerable by a web page). Bind to
  loopback only, authenticate, validate origin/Host, and expose the minimum.
fileSelectionHint:
  roles: ["main", "service", "server", "config"]
  matchImports: ["electron", "@tauri-apps/api", "ws", "express", "http"]
  matchAuthMapTags: ["electron", "tauri"]
  maxFiles: 10
  priorityOrder: ["server", "main", "service", "config"]
severityHeuristics:
  critical:
    - "A local HTTP/WebSocket server exposes a sensitive or command-executing endpoint with no authentication and no origin/Host validation, so any website the user visits can invoke it (the Zoom local-server class) — remote-triggered local action/RCE"
  high:
    - "A local server authenticates or checks origin but is bypassable via DNS rebinding (no Host-header validation) or lacks CSRF protection, so a malicious page can still reach it"
    - "The server binds to all interfaces (0.0.0.0) instead of loopback, exposing it to the local network / other hosts"
  medium:
    - "The local server requires a token but the token is guessable, fixed, or discoverable by other local apps; or endpoints are broader than needed"
    - "A named pipe / unix socket has overly permissive ACLs allowing other local users/apps to connect"
  low:
    - "A loopback-bound server with per-session unguessable token auth, Host/origin validation, and minimal endpoints — the target state; confirm auth + Host validation before dismissing"
graphNodeMapping:
  primaryNodeType: component
  primaryNodeId: "component:local_server"
  relatedNodeIds: ["component:authorization", "component:remote_code_execution"]
graphEdgeMapping:
  - relation: protects
    from: "component:authorization"
    to: "component:local_server"
  - relation: causes
    from: "component:local_server"
    to: "component:remote_code_execution"
commonAiCodingMistakes:
  - "AI opens a localhost HTTP/WebSocket server for the frontend or a browser extension to call and assumes 'localhost = safe', not realizing any website the user visits can `fetch`/`WebSocket` to it — a web page becomes a remote attacker against the local endpoint (Zoom's mistake)."
  - "AI checks the Origin header but not the Host header, so DNS rebinding (attacker.com resolving to 127.0.0.1) bypasses the origin check."
  - "AI binds the server to 0.0.0.0 instead of 127.0.0.1, exposing it to the whole local network."
  - "AI exposes command-executing or sensitive endpoints on the local server with no per-session token, so a page can trigger them directly."
  - "AI uses a fixed/guessable token or none, or a world-accessible named pipe, letting other local apps or pages connect."
falsePositiveGuardrails:
  - "Do not flag a loopback-bound local server that authenticates callers with a per-session, unguessable token AND validates the Host header (DNS-rebinding defense) — that is the correct pattern for a local bridge."
  - "Origin validation PLUS Host validation together defend against both cross-origin and DNS-rebinding — confirm both before flagging; origin-only is bypassable."
  - "Named pipes/unix sockets with ACLs restricting to the current user are correctly scoped — only world-accessible ones are the finding."
  - "Endpoints that are read-only and non-sensitive are lower risk — severity scales with what a page can trigger (commands/sensitive actions highest)."
---

## Root Cause Explanation

Desktop apps frequently open a local server — an HTTP or WebSocket listener on
`127.0.0.1`, or a named pipe / unix socket — so their web frontend or a companion
browser extension can talk to the native side. The dangerous and widely-missed
fact is that **"localhost" is not a security boundary against the web**: any
website the user visits can issue `fetch()` or open a `WebSocket` to
`http://localhost:PORT`, and with **DNS rebinding** it can even satisfy naive
origin checks. So a local server is reachable by every web page the user browses,
and if it exposes anything sensitive — worst of all, command execution — that
page becomes a remote attacker. Zoom's 2019 local web server, which any website
could use to trigger the camera and (via an update path) run code, is the canonical
lesson.

The controls treat the local server as an exposed, untrusted-reachable service:
bind to loopback only, require a **per-session unguessable token** that a blind
web page can't supply (not "it's localhost"), validate the **Host** header to
defeat DNS rebinding (and Origin for good measure), add CSRF protection, and
expose the **minimum** functionality — never remote-triggerable command execution.
For pipes/sockets, restrict ACLs to the current user.

## Vulnerable Patterns

```js
// Local server any website can reach; sensitive endpoint, no auth/Host check
const srv = http.createServer((req, res) => {
  if (req.url.startsWith("/run")) exec(query(req).cmd);   // page → command execution
});
srv.listen(19222, "0.0.0.0");                              // and bound to all interfaces
```

Correct: loopback + token + Host validation + minimal endpoints.

```js
const srv = http.createServer((req, res) => {
  if (req.headers.host !== `127.0.0.1:${PORT}`) return res.writeHead(403).end();  // anti-rebinding
  if (req.headers["x-app-token"] !== SESSION_TOKEN) return res.writeHead(401).end();
  // handle only specific, non-command endpoints
});
srv.listen(PORT, "127.0.0.1");
```

## Data Flow Tracing Guide

1. Find any local server: `http`/`express`/`ws` listeners, Tauri/Electron local
   servers, named pipes/unix sockets. Note the bind address and port.
2. Check authentication — a per-session unguessable token, or reliance on
   "localhost"?
3. Check Host-header validation (DNS-rebinding defense) and Origin/CSRF checks.
4. Enumerate the endpoints and what they can trigger (read-only vs. sensitive vs.
   command execution).
5. For pipes/sockets, check ACLs.

## Evidence Checklist

- [ ] The server bind address/port and transport, quoted.
- [ ] The authentication mechanism (token vs. none).
- [ ] Host/Origin/CSRF validation present or absent.
- [ ] The most sensitive endpoint a web page could reach.

## Attack Scenario Template

> The victim visits an attacker's web page while the app is running. The page
> [fetches / opens a WebSocket to] `http://localhost:PORT/...` (using DNS
> rebinding to pass any origin check). Because [file:line] [requires no token /
> validates only Origin not Host / exposes a command endpoint], the page invokes
> [the sensitive/command endpoint], resulting in [local action triggered by any
> website / RCE].

## Graph Mapping Instructions

- Ensure a `component:local_server` node protected by `component:authorization`;
  command-endpoint findings add a `causes` edge to
  `component:remote_code_execution`.
- Note the "reachable by any website + DNS rebinding" rationale in `reasoning`.
- Each finding is a `finding:<uuid>` vulnerability node with a `causes` edge
  from `component:local_server`.
