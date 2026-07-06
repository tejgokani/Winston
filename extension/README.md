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

AI-tooling detection (which coding tools were used in a repo, from git
trailers and config artifacts) is available as the `detect_ai_tooling` MCP
tool — ask your agent to call it. It's not duplicated as a standalone
extension command, since a local, extension-side `git` shell-out is exactly
the kind of process-spawning pattern marketplace security scanners flag;
routing it through the MCP server (which already runs with the trust the
user granted the agent) avoids that with no loss of functionality.

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
the server (`npm i -g winston_sec_mcp`, exposing the `winston-mcp` command)
for the audit to run. The extension's default config uses `npx -y -p
winston_sec_mcp winston-mcp` instead — the `-p`/package flag is required
because the published npm package name (`winston_sec_mcp`) differs from the
executable it provides (`winston-mcp`), so plain `npx winston_sec_mcp` can't
resolve which command to run.
