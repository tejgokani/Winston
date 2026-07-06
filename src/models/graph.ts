import { z } from "zod";
import { EvidenceSchema } from "./findings.js";

export const CodeSnippetSchema = z.object({
  file: z.string(),
  lineStart: z.number().int().positive(),
  lineEnd: z.number().int().positive(),
  code: z.string(),
});
export type CodeSnippet = z.infer<typeof CodeSnippetSchema>;

export const GraphNodeSchema = z.object({
  id: z.string(),
  type: z.enum([
    "component",
    "vulnerability",
    "external_system",
    "data_store",
    "root_cause_marker",
  ]),
  label: z.string(),
  severity: z.enum(["critical", "high", "medium", "low", "info"]).nullable(),
  description: z.string(),
  evidence: z.array(EvidenceSchema),
  reasoning: z.string().nullable(),
  attackScenario: z.string().nullable(),
  affectedFiles: z.array(z.string()),
  codeSnippets: z.array(CodeSnippetSchema),
  recommendedFix: z.string().nullable(),
  aiFixPrompt: z.string().nullable(),
  rootCause: z.boolean(),
  // Root-cause ranking ("the crown"). crownScore = severity-weighted count of
  // open vulnerabilities reachable downstream from this node via `causes`
  // edges (including itself if it is a vulnerability); downstreamImpact = the
  // raw count of those reachable open vulnerabilities; impactRank = 1-based
  // rank among nodes with crownScore > 0 (1 = the crown), or null. All three
  // are recomputed on every findings submission and default safely for graphs
  // persisted before this field existed.
  crownScore: z.number().nonnegative().default(0),
  downstreamImpact: z.number().int().nonnegative().default(0),
  impactRank: z.number().int().positive().nullable().default(null),
  playbookId: z.string().nullable(),
  scanIds: z.array(z.string()),
  status: z.enum(["open", "fixed", "regressed"]),
});
export type GraphNode = z.infer<typeof GraphNodeSchema>;

export const GraphEdgeSchema = z.object({
  source: z.string(),
  target: z.string(),
  relation: z.enum([
    "causes",
    "depends_on",
    "protects",
    "reads",
    "writes",
    "calls",
    "trusts",
    "stores",
    "authorizes",
    "authenticates",
    "exposes",
    "enables",
  ]),
  description: z.string(),
  scanIds: z.array(z.string()),
});
export type GraphEdge = z.infer<typeof GraphEdgeSchema>;

export const RiskScoreSchema = z.object({
  overall: z.number().int().nonnegative(),
  critical: z.number().int().nonnegative(),
  high: z.number().int().nonnegative(),
  medium: z.number().int().nonnegative(),
  low: z.number().int().nonnegative(),
});
export type RiskScore = z.infer<typeof RiskScoreSchema>;

export const ThreatGraphSchema = z.object({
  repoPath: z.string(),
  nodes: z.array(GraphNodeSchema),
  edges: z.array(GraphEdgeSchema),
  riskScore: RiskScoreSchema,
  // The id of the highest-ranked root-cause node — the "crown" the UI renders
  // at the top of the tree — or null when there are no open vulnerabilities.
  crownNodeId: z.string().nullable().default(null),
  updatedAt: z.string(),
});
export type ThreatGraph = z.infer<typeof ThreatGraphSchema>;

export function emptyGraph(repoPath: string): ThreatGraph {
  return {
    repoPath,
    nodes: [],
    edges: [],
    riskScore: { overall: 0, critical: 0, high: 0, medium: 0, low: 0 },
    crownNodeId: null,
    updatedAt: new Date().toISOString(),
  };
}
