import { existsSync, mkdirSync, readFileSync, watch, writeFileSync, type FSWatcher } from "node:fs";
import { join } from "node:path";
import * as vscode from "vscode";
import { graphFilePathForRepo, readGraphForRepo } from "./graphReader";
import { detectAiTooling } from "./toolingDetector";

let panel: vscode.WebviewPanel | undefined;
let watcher: FSWatcher | undefined;

export function activate(context: vscode.ExtensionContext) {
  context.subscriptions.push(
    vscode.commands.registerCommand("winston.openGraph", () => openGraph(context)),
    vscode.commands.registerCommand("winston.registerMcp", () => registerMcp()),
    vscode.commands.registerCommand("winston.detectTooling", () => detectTooling()),
    vscode.commands.registerCommand("winston.audit", () => audit())
  );
}

export function deactivate() {
  watcher?.close();
  panel?.dispose();
}

function workspaceRoot(): string | undefined {
  return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
}

// --- Threat graph webview -------------------------------------------------

function openGraph(context: vscode.ExtensionContext) {
  const root = workspaceRoot();
  if (!root) {
    vscode.window.showWarningMessage("Winston: open a folder first.");
    return;
  }

  if (panel) {
    panel.reveal(vscode.ViewColumn.Beside);
  } else {
    panel = vscode.window.createWebviewPanel(
      "winstonGraph",
      "Winston — Threat Graph",
      vscode.ViewColumn.Beside,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: [vscode.Uri.joinPath(context.extensionUri, "media")],
      }
    );
    panel.webview.html = webviewHtml(panel.webview, context.extensionUri);
    panel.onDidDispose(() => {
      panel = undefined;
      watcher?.close();
      watcher = undefined;
    });
    panel.webview.onDidReceiveMessage((msg) => {
      if (msg.type === "ready") postGraph(root);
      else if (msg.type === "openFile") openAffectedFile(root, msg.file);
    });
  }

  postGraph(root);
  watchGraph(root);
}

function postGraph(root: string) {
  const graph = readGraphForRepo(root);
  panel?.webview.postMessage({ type: "graph", graph });
}

// Live updates: re-post whenever the MCP server rewrites this repo's graph
// file (i.e. every time the agent submits findings).
function watchGraph(root: string) {
  watcher?.close();
  const file = graphFilePathForRepo(root);
  const dir = join(file, "..");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  try {
    watcher = watch(dir, (_event, filename) => {
      if (filename && file.endsWith(filename)) postGraph(root);
    });
  } catch {
    // fs.watch unsupported on some platforms — the manual reopen still works.
  }
}

async function openAffectedFile(root: string, file: string) {
  const abs = join(root, file);
  const uri = existsSync(abs) ? vscode.Uri.file(abs) : vscode.Uri.file(file);
  try {
    const doc = await vscode.workspace.openTextDocument(uri);
    await vscode.window.showTextDocument(doc, vscode.ViewColumn.One);
  } catch {
    vscode.window.showWarningMessage(`Winston: could not open ${file}`);
  }
}

function webviewHtml(webview: vscode.Webview, extensionUri: vscode.Uri): string {
  const nonce = String(Math.random()).slice(2);
  const cssUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, "media", "main.css"));
  const jsUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, "media", "main.js"));
  const csp =
    `default-src 'none'; img-src ${webview.cspSource} https: data:; ` +
    `style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}';`;
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta http-equiv="Content-Security-Policy" content="${csp}" />
  <link rel="stylesheet" href="${cssUri}" />
</head>
<body>
  <div id="app">
    <div id="graph">
      <div id="toolbar"></div>
      <div id="empty"><h2>Winston</h2><p id="emptyMsg"></p></div>
    </div>
    <div id="panel" class="hidden"></div>
  </div>
  <script nonce="${nonce}" src="${jsUri}"></script>
</body>
</html>`;
}

// --- MCP registration (workspace .vscode/mcp.json) ------------------------

async function registerMcp() {
  const root = workspaceRoot();
  if (!root) {
    vscode.window.showWarningMessage("Winston: open a folder first.");
    return;
  }
  const cfg = vscode.workspace.getConfiguration("winston");
  const command = cfg.get<string>("serverCommand", "npx");
  const args = cfg.get<string[]>("serverArgs", ["-y", "winston_sec_mcp"]);

  const dir = join(root, ".vscode");
  const file = join(dir, "mcp.json");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

  let doc: any = {};
  if (existsSync(file)) {
    try {
      doc = JSON.parse(readFileSync(file, "utf-8"));
    } catch {
      vscode.window.showErrorMessage("Winston: .vscode/mcp.json is not valid JSON; not modifying it.");
      return;
    }
  }
  // Support both the `servers` (VS Code) and `mcpServers` (portable) shapes.
  const key = doc.servers ? "servers" : doc.mcpServers ? "mcpServers" : "servers";
  doc[key] = doc[key] || {};
  doc[key].winston = { command, args };
  writeFileSync(file, JSON.stringify(doc, null, 2));
  vscode.window.showInformationMessage(
    "Winston registered in .vscode/mcp.json. Reload your MCP client / agent to pick it up."
  );
}

// --- Detect AI tooling ----------------------------------------------------

function detectTooling() {
  const root = workspaceRoot();
  if (!root) {
    vscode.window.showWarningMessage("Winston: open a folder first.");
    return;
  }
  const report = detectAiTooling(root);
  const channel = vscode.window.createOutputChannel("Winston — AI Tooling");
  channel.clear();
  channel.appendLine("Detected AI coding tooling (heuristic signals — not proof of authorship)");
  channel.appendLine("=".repeat(72));
  if (report.detectedTools.length === 0) {
    channel.appendLine("No AI-tooling signals found in git history or config artifacts.");
  } else {
    for (const t of report.detectedTools) channel.appendLine(`  • ${t.tool}  [${t.confidence} confidence]`);
    channel.appendLine("");
    channel.appendLine("Evidence:");
    for (const s of report.signals) channel.appendLine(`  - ${s.tool}: ${s.evidence} (${s.source})`);
  }
  channel.appendLine("");
  channel.appendLine(report.disclaimer);
  channel.show(true);

  const summary =
    report.detectedTools.length === 0
      ? "No AI-tooling signals found."
      : "Detected: " + report.detectedTools.map((t) => `${t.tool} (${t.confidence})`).join(", ");
  vscode.window.showInformationMessage(`Winston: ${summary}`);
}

// --- Audit helper ---------------------------------------------------------

async function audit() {
  const root = workspaceRoot();
  if (!root) {
    vscode.window.showWarningMessage("Winston: open a folder first.");
    return;
  }
  await registerMcp();
  const prompt =
    `Use the Winston MCP server to security-audit this repository. ` +
    `Call audit_repository(repoPath="${root}", mode="deep"), then follow its ` +
    `instructions: for each review pass call get_playbook, reason over the code, ` +
    `and call submit_findings. Then open the Winston threat graph.`;
  await vscode.env.clipboard.writeText(prompt);
  const choice = await vscode.window.showInformationMessage(
    "Winston is registered. An audit prompt is copied to your clipboard — paste it into your AI agent (Copilot Chat, Claude, Cursor). Open the graph to watch findings appear.",
    "Open Threat Graph"
  );
  if (choice === "Open Threat Graph") vscode.commands.executeCommand("winston.openGraph");
}
