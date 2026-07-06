import { loadGraphForRepo } from "../storage/graphStore.js";
import type { ThreatGraph } from "../models/graph.js";

export interface GetGraphInput {
  repoPath: string;
  format?: "json" | "summary";
}

export interface GraphSummary {
  repoPath: string;
  nodeCount: number;
  edgeCount: number;
  openVulnerabilities: number;
  rootCauseCount: number;
  // The crown: the single highest-impact root-cause node ("fix this first"),
  // with the blast radius that earned it the top rank. Null when the graph has
  // no open vulnerabilities.
  crown: {
    id: string;
    label: string;
    downstreamImpact: number;
    crownScore: number;
  } | null;
  riskScore: ThreatGraph["riskScore"];
  updatedAt: string;
}

function summarize(graph: ThreatGraph): GraphSummary {
  const crownNode = graph.crownNodeId
    ? graph.nodes.find((n) => n.id === graph.crownNodeId)
    : undefined;
  return {
    repoPath: graph.repoPath,
    nodeCount: graph.nodes.length,
    edgeCount: graph.edges.length,
    openVulnerabilities: graph.nodes.filter(
      (n) => n.type === "vulnerability" && n.status === "open"
    ).length,
    rootCauseCount: graph.nodes.filter((n) => n.rootCause).length,
    crown: crownNode
      ? {
          id: crownNode.id,
          label: crownNode.label,
          downstreamImpact: crownNode.downstreamImpact,
          crownScore: crownNode.crownScore,
        }
      : null,
    riskScore: graph.riskScore,
    updatedAt: graph.updatedAt,
  };
}

export function getGraph({
  repoPath,
  format = "summary",
}: GetGraphInput): ThreatGraph | GraphSummary {
  const graph = loadGraphForRepo(repoPath);
  return format === "json" ? graph : summarize(graph);
}
