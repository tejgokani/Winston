import { mapFindingsToGraph, type MapFindingsResult } from "../graph/mapper.js";
import type { Finding } from "../models/findings.js";
import { loadGraphForRepo, saveGraphForRepo } from "../storage/graphStore.js";

export function updateGraphWithFindings(
  repoPath: string,
  findings: Finding[],
  scanId: string,
  reconcileFixed = true
): MapFindingsResult {
  const graph = loadGraphForRepo(repoPath);
  const result = mapFindingsToGraph(graph, findings, scanId, { reconcileFixed });
  saveGraphForRepo(result.graph);
  return result;
}
