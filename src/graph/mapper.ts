import { createHash } from "node:crypto";
import { DirectedGraph } from "graphology";
import type { Finding } from "../models/findings.js";
import type { GraphEdge, GraphNode, ThreatGraph } from "../models/graph.js";
import { isKnownComponentId, isKnownRelation, labelForComponentId } from "./ontology.js";

export interface MapFindingsResult {
  graph: ThreatGraph;
  droppedEdges: Array<{ finding: string; targetIdHint: string; reason: string }>;
}

function deterministicFindingId(repoPath: string, title: string): string {
  const hash = createHash("sha1").update(`${repoPath}::${title}`).digest("hex").slice(0, 12);
  return `finding:${hash}`;
}

// Canonicalize a Finding's proposed graph_node id against the controlled
// vocabulary. Known component ids are reused as-is (so "component:jwt"
// always refers to the same node); vulnerability drafts get a deterministic
// id derived from (repoPath, title) — NOT scanId, which is a fresh uuid per
// audit_repository call — so the same vulnerability re-found on a later scan
// of the same repo maps to the same node instead of duplicating it.
function canonicalizeNodeId(
  idHint: string,
  type: GraphNode["type"],
  repoPath: string,
  title: string
): string {
  if (type === "component" && isKnownComponentId(idHint)) return idHint;
  if (type === "vulnerability") return deterministicFindingId(repoPath, title);
  return idHint;
}

function upsertComponentNode(graph: ThreatGraph, id: string, scanId: string): GraphNode {
  const existing = graph.nodes.find((n) => n.id === id);
  if (existing) {
    if (!existing.scanIds.includes(scanId)) existing.scanIds.push(scanId);
    return existing;
  }
  const node: GraphNode = {
    id,
    type: "component",
    label: labelForComponentId(id),
    severity: null,
    description: `Architectural component: ${labelForComponentId(id)}`,
    evidence: [],
    reasoning: null,
    attackScenario: null,
    affectedFiles: [],
    codeSnippets: [],
    recommendedFix: null,
    aiFixPrompt: null,
    rootCause: false,
    crownScore: 0,
    downstreamImpact: 0,
    impactRank: null,
    playbookId: null,
    scanIds: [scanId],
    status: "open",
  };
  graph.nodes.push(node);
  return node;
}

function upsertVulnerabilityNode(
  graph: ThreatGraph,
  id: string,
  finding: Finding,
  scanId: string
): GraphNode {
  const existing = graph.nodes.find((n) => n.id === id);
  const codeSnippets = finding.evidence.map((e) => ({
    file: e.file,
    lineStart: e.lineStart,
    lineEnd: e.lineEnd,
    code: e.snippet,
  }));

  if (existing) {
    existing.label = finding.title;
    existing.severity = finding.severity;
    existing.description = finding.description;
    existing.evidence = finding.evidence;
    existing.reasoning = finding.reasoning;
    existing.attackScenario = finding.attackScenario;
    existing.affectedFiles = finding.affectedFiles;
    existing.codeSnippets = codeSnippets;
    existing.recommendedFix = finding.recommendedFix;
    existing.aiFixPrompt = finding.aiFixPrompt;
    existing.playbookId = finding.playbookId;
    existing.status = "open";
    if (!existing.scanIds.includes(scanId)) existing.scanIds.push(scanId);
    return existing;
  }

  const node: GraphNode = {
    id,
    type: "vulnerability",
    label: finding.title,
    severity: finding.severity,
    description: finding.description,
    evidence: finding.evidence,
    reasoning: finding.reasoning,
    attackScenario: finding.attackScenario,
    affectedFiles: finding.affectedFiles,
    codeSnippets,
    recommendedFix: finding.recommendedFix,
    aiFixPrompt: finding.aiFixPrompt,
    rootCause: false,
    crownScore: 0,
    downstreamImpact: 0,
    impactRank: null,
    playbookId: finding.playbookId,
    scanIds: [scanId],
    status: "open",
  };
  graph.nodes.push(node);
  return node;
}

function resolveTargetId(
  targetIdHint: string,
  idHintToCanonical: Map<string, string>,
  graph: ThreatGraph,
  scanId: string
): string | null {
  if (idHintToCanonical.has(targetIdHint)) return idHintToCanonical.get(targetIdHint)!;
  if (isKnownComponentId(targetIdHint)) {
    // Edges may reference a known component that no finding in this batch
    // explicitly created (e.g. "protects component:api_security") — create
    // it lazily so the edge always has a real node on both ends.
    upsertComponentNode(graph, targetIdHint, scanId);
    return targetIdHint;
  }
  if (graph.nodes.some((n) => n.id === targetIdHint)) return targetIdHint;
  return null;
}

function upsertEdge(
  graph: ThreatGraph,
  source: string,
  target: string,
  relation: GraphEdge["relation"],
  description: string,
  scanId: string
): void {
  const existing = graph.edges.find(
    (e) => e.source === source && e.target === target && e.relation === relation
  );
  if (existing) {
    if (!existing.scanIds.includes(scanId)) existing.scanIds.push(scanId);
    return;
  }
  graph.edges.push({ source, target, relation, description, scanIds: [scanId] });
}

function computeRootCauseFlags(graph: ThreatGraph): void {
  const g = new DirectedGraph();
  for (const node of graph.nodes) g.addNode(node.id);
  for (const edge of graph.edges) {
    if (edge.relation !== "causes") continue;
    if (!g.hasEdge(edge.source, edge.target)) {
      g.addEdge(edge.source, edge.target);
    }
  }
  for (const node of graph.nodes) {
    if (node.type !== "vulnerability") {
      node.rootCause = false;
      continue;
    }
    const inDegree = g.hasNode(node.id) ? g.inDegree(node.id) : 0;
    const outDegree = g.hasNode(node.id) ? g.outDegree(node.id) : 0;
    node.rootCause = inDegree === 0 && outDegree > 0;
  }
}

const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 10,
  high: 5,
  medium: 2,
  low: 1,
  info: 0,
};

// Root-cause ranking — "the crown". For each node we follow `causes` edges
// downstream and collect every distinct OPEN vulnerability reachable from it
// (including itself if it is one). crownScore is the severity-weighted sum of
// those reachable vulnerabilities; the node with the biggest downstream blast
// radius is the crown. This is what lets the UI put the single
// most-damaging root cause at the top of the tree, with the vulnerabilities
// it causes hanging beneath it, and gives the report a "fix this first"
// ordering rather than a flat list.
function computeCrownRanking(graph: ThreatGraph): void {
  const nodeById = new Map(graph.nodes.map((n) => [n.id, n]));
  // Adjacency for `causes` edges only, in cause → effect direction.
  const downstream = new Map<string, string[]>();
  for (const node of graph.nodes) downstream.set(node.id, []);
  for (const edge of graph.edges) {
    if (edge.relation !== "causes") continue;
    if (!downstream.has(edge.source) || !nodeById.has(edge.target)) continue;
    downstream.get(edge.source)!.push(edge.target);
  }

  const isOpenVuln = (id: string): boolean => {
    const n = nodeById.get(id);
    return !!n && n.type === "vulnerability" && n.status === "open";
  };
  const weightOf = (id: string): number => {
    const n = nodeById.get(id);
    return n?.severity ? SEVERITY_WEIGHT[n.severity] ?? 0 : 0;
  };

  // Reachable open-vulnerability set from each node (BFS over `causes`),
  // cycle-safe via a visited set. Graphs here are small (tens of nodes), so a
  // per-node traversal is fine and keeps the logic obvious.
  for (const node of graph.nodes) {
    const seen = new Set<string>();
    const queue = [...(downstream.get(node.id) ?? [])];
    if (isOpenVuln(node.id)) seen.add(node.id); // a root-cause vuln counts itself
    while (queue.length) {
      const cur = queue.shift()!;
      if (seen.has(cur)) continue;
      seen.add(cur);
      for (const next of downstream.get(cur) ?? []) {
        if (!seen.has(next)) queue.push(next);
      }
    }
    const reachableVulns = [...seen].filter(isOpenVuln);
    node.downstreamImpact = reachableVulns.length;
    node.crownScore = reachableVulns.reduce((sum, id) => sum + weightOf(id), 0);
    node.impactRank = null;
  }

  // Rank nodes with any downstream impact. Deterministic tie-break:
  // crownScore desc, then downstreamImpact desc, then id asc.
  const ranked = graph.nodes
    .filter((n) => n.crownScore > 0)
    .sort(
      (a, b) =>
        b.crownScore - a.crownScore ||
        b.downstreamImpact - a.downstreamImpact ||
        a.id.localeCompare(b.id)
    );
  ranked.forEach((n, i) => {
    n.impactRank = i + 1;
  });
  graph.crownNodeId = ranked.length ? ranked[0].id : null;
}

function computeRiskScore(graph: ThreatGraph): ThreatGraph["riskScore"] {
  const open = graph.nodes.filter((n) => n.type === "vulnerability" && n.status === "open");
  const score = {
    overall: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  for (const node of open) {
    if (!node.severity) continue;
    if (node.severity === "critical") score.critical++;
    else if (node.severity === "high") score.high++;
    else if (node.severity === "medium") score.medium++;
    else if (node.severity === "low") score.low++;
    score.overall += SEVERITY_WEIGHT[node.severity] ?? 0;
  }
  return score;
}

export interface MapFindingsOptions {
  // Whether to mark previously-open vulnerability nodes not re-found in this
  // call as "fixed". Only correct for a single, full-repo submission per
  // scan. Deep mode's multi-pass round-trips (Phase 7 — several
  // audit_repository/submit_findings calls sharing one scanId) must pass
  // `false` on intermediate passes, since an untouched node there just means
  // "not this pass's playbook," not "fixed" — and set it `true` only once,
  // on the final pass.
  reconcileFixed: boolean;
}

export function mapFindingsToGraph(
  graph: ThreatGraph,
  findings: Finding[],
  scanId: string,
  options: MapFindingsOptions = { reconcileFixed: true }
): MapFindingsResult {
  const droppedEdges: MapFindingsResult["droppedEdges"] = [];
  const idHintToCanonical = new Map<string, string>();
  const touchedVulnerabilityIds = new Set<string>();

  for (const finding of findings) {
    const canonicalId = canonicalizeNodeId(
      finding.graphNode.idHint,
      finding.graphNode.type,
      graph.repoPath,
      finding.title
    );
    idHintToCanonical.set(finding.graphNode.idHint, canonicalId);

    if (finding.graphNode.type === "component") {
      upsertComponentNode(graph, canonicalId, scanId);
    } else {
      upsertVulnerabilityNode(graph, canonicalId, finding, scanId);
      touchedVulnerabilityIds.add(canonicalId);
    }
  }

  // Second pass: resolve edges now that every finding in this batch has a
  // canonical id, including cross-references between findings in the batch.
  for (const finding of findings) {
    const sourceId = idHintToCanonical.get(finding.graphNode.idHint)!;
    for (const edgeDraft of finding.graphEdges) {
      if (!isKnownRelation(edgeDraft.relation)) {
        droppedEdges.push({
          finding: finding.title,
          targetIdHint: edgeDraft.targetIdHint,
          reason: `Unknown relation "${edgeDraft.relation}"`,
        });
        continue;
      }
      const targetId = resolveTargetId(edgeDraft.targetIdHint, idHintToCanonical, graph, scanId);
      if (!targetId) {
        droppedEdges.push({
          finding: finding.title,
          targetIdHint: edgeDraft.targetIdHint,
          reason: "Target id could not be resolved to any known or created node",
        });
        continue;
      }
      upsertEdge(graph, sourceId, targetId, edgeDraft.relation, edgeDraft.description, scanId);
    }
  }

  if (options.reconcileFixed) {
    for (const node of graph.nodes) {
      if (node.type !== "vulnerability") continue;
      if (node.status === "open" && !touchedVulnerabilityIds.has(node.id)) {
        node.status = "fixed";
      }
    }
  }

  computeRootCauseFlags(graph);
  computeCrownRanking(graph);
  graph.riskScore = computeRiskScore(graph);
  graph.updatedAt = new Date().toISOString();

  return { graph, droppedEdges };
}
