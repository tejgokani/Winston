# Winston — VS Code Extension

The VS Code face of [Winston](../README.md), the AI security auditor. It wraps
the Winston MCP server and renders its findings as an interactive **root-cause
threat graph** right inside the editor — no browser, no web viewer.

## What it does

- **`Winston: Enable in this workspace`** — writes/merges a `.vscode/mcp.json`
  entry so your AI agent (Copilot Chat, Claude, Cursor, any MCP-aware client)
  can call the Winston server.
- **`Winston: Audit this repository`** — registers the server and puts a ready
  audit prompt on your clipboard to paste into your agent.
- **`Winston: Open Threat Graph`** — opens the graph panel. It reads the graph
  the MCP server persists to `~/.winston/graphs/` and **live-updates** as the
  agent submits findings. The **crown** (👑, the highest-impact root cause)
  sits at the top; the vulnerabilities and components it causes branch beneath
  it, severity-colored. Click a node for evidence, reasoning, the attack
  scenario, affected files (click to open), and the AI fix prompt.
- **`Winston: Detect AI Coding Tooling`** — heuristic detection of which AI
  tools were used in the repo (git trailers + config artifacts), with
  confidence levels. Honest by design: signals, not per-file authorship claims.

The graph view is fully self-contained (a custom SVG renderer — no external
libraries), so it respects VS Code's webview CSP and your light/dark theme.

## Develop

```bash
npm install
npm run build      # compile src/ → dist/
# press F5 in VS Code to launch an Extension Development Host
```

Before publishing to the Marketplace, add a `media/icon.png` and restore the
`icon` field in `package.json`, then `npx @vscode/vsce package`.

## Relationship to the MCP server

The extension is the packaging; the MCP server is the engine. The server does
the auditing and owns all writes to `~/.winston`; the extension only reads that
store to visualize it and provides one-click registration + commands. Install
the server (`npm i -g winston_sec_mcp` or via `npx`) for the audit to run.
