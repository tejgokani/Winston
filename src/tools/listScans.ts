import { listScans as listScanRecords } from "../storage/scanStore.js";

export interface ListScansInput {
  repoPath?: string;
  limit?: number;
}

export interface ScanSummary {
  scanId: string;
  repoPath: string;
  mode: "quick" | "deep";
  createdAt: string;
  findingsSubmitted: number;
  riskScoreOverall: number | null;
  riskScoreDelta: number | null;
}

export function listScans({ repoPath, limit = 10 }: ListScansInput): ScanSummary[] {
  const records = listScanRecords(repoPath, limit);
  // listScanRecords is sorted newest-first; walk oldest-to-newest to compute
  // deltas against the risk-score snapshot taken at each scan's
  // submit_findings call, then present newest-first again.
  const chronological = [...records].reverse();

  const summaries: ScanSummary[] = [];
  let previousRisk: number | null = null;

  for (const record of chronological) {
    const overall = record.riskScoreAtSubmission;
    summaries.push({
      scanId: record.scanId,
      repoPath: record.repoPath,
      mode: record.mode,
      createdAt: record.createdAt,
      findingsSubmitted: record.findings.length,
      riskScoreOverall: overall,
      riskScoreDelta:
        previousRisk === null || overall === null ? null : overall - previousRisk,
    });
    if (overall !== null) previousRisk = overall;
  }

  return summaries.reverse();
}
