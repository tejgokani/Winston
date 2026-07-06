import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { generateReport as renderReport } from "../pipeline/reportGenerator.js";
import { loadGraphForRepo } from "../storage/graphStore.js";
import { loadScan } from "../storage/scanStore.js";
import { loadWinstonConfig } from "../config/winstonConfig.js";

export interface GenerateReportInput {
  scanId: string;
  format?: "markdown" | "html" | "json" | "sarif";
}

export interface GenerateReportResult {
  ok: boolean;
  content?: string;
  path?: string;
  error?: string;
}

let reportsBaseDirOverride: string | null = null;

export function setReportsBaseDir(dir: string): void {
  reportsBaseDirOverride = dir;
}

function reportsDir(): string {
  const base = reportsBaseDirOverride ?? join(homedir(), ".winston");
  const dir = join(base, "reports");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  return dir;
}

const EXTENSION: Record<string, string> = {
  markdown: "md",
  html: "html",
  json: "json",
  sarif: "sarif",
};

export function generateReportTool({
  scanId,
  format = "markdown",
}: GenerateReportInput): GenerateReportResult {
  const scan = loadScan(scanId);
  if (!scan) {
    return { ok: false, error: `Unknown scanId "${scanId}". Call audit_repository first.` };
  }

  const graph = loadGraphForRepo(scan.repoPath);
  const config = loadWinstonConfig(scan.repoPath);
  const content = renderReport(graph, format, config.minSeverity);
  const path = join(reportsDir(), `${scanId}.${EXTENSION[format]}`);
  writeFileSync(path, content);

  return { ok: true, content, path };
}
