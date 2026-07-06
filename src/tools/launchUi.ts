import type { Server } from "node:http";
import { createUiApp } from "../ui/app.js";

// In-process HTTP server rather than a spawned child process: simpler and
// more reliable than managing a detached process from within an MCP stdio
// tool call (no orphan-process/port-conflict handling needed), while still
// keeping the UI on its own HTTP transport, not tunneled through MCP.
let runningServer: { server: Server; port: number } | null = null;

export interface LaunchUiInput {
  repoPath?: string;
  port?: number;
}

export interface LaunchUiResult {
  url: string;
}

export function launchUi({ repoPath, port = 8787 }: LaunchUiInput): LaunchUiResult {
  if (!runningServer) {
    const app = createUiApp();
    const server = app.listen(port);
    runningServer = { server, port };
  }
  const base = `http://localhost:${runningServer.port}`;
  const url = repoPath ? `${base}/?repoPath=${encodeURIComponent(repoPath)}` : base;
  return { url };
}
