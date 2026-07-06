import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

// Mirrors the MCP server's storage keying (src/storage/graphStore.ts): one
// graph JSON per repo, keyed by sha1(repoPath).slice(0,16), under ~/.winston.
// The extension only READS this file — the MCP server owns writes — so the
// webview is a live view of whatever the agent has submitted so far.

export interface GraphNode {
  id: string;
  type: "component" | "vulnerability" | "external_system" | "data_store" | "root_cause_marker";
  label: string;
  severity: "critical" | "high" | "medium" | "low" | "info" | null;
  description: string;
  affectedFiles: string[];
  reasoning: string | null;
  attackScenario: string | null;
  recommendedFix: string | null;
  aiFixPrompt: string | null;
  rootCause: boolean;
  crownScore: number;
  downstreamImpact: number;
  impactRank: number | null;
  status: "open" | "fixed" | "regressed";
}

export interface GraphEdge {
  source: string;
  target: string;
  relation: string;
  description: string;
}

export interface ThreatGraph {
  repoPath: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  riskScore: { overall: number; critical: number; high: number; medium: number; low: number };
  crownNodeId: string | null;
  updatedAt: string;
}

export function graphFilePathForRepo(repoPath: string): string {
  const key = createHash("sha1").update(repoPath).digest("hex").slice(0, 16);
  return join(homedir(), ".winston", "graphs", `${key}.json`);
}

export function readGraphForRepo(repoPath: string): ThreatGraph | null {
  const path = graphFilePathForRepo(repoPath);
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, "utf-8")) as ThreatGraph;
  } catch {
    return null;
  }
}
