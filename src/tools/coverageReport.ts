import { loadScan } from "../storage/scanStore.js";

export interface CoverageReportInput {
  scanId: string;
}

export interface CoverageReport {
  ok: boolean;
  scanId?: string;
  mode?: "quick" | "deep";
  playbooksSelected?: string[];
  playbooksExecuted?: string[];
  playbooksNotExecuted?: string[];
  filesReviewed?: string[];
  coveragePercent?: number;
  diffScoped?: boolean;
  note?: string;
  error?: string;
}

// Honest coverage: what Winston actually reviewed vs. what it selected. Security
// buyers need to know what was NOT checked — a playbook can be selected for the
// stack but never executed if the model stopped early. "Executed" means its
// full body + files were fetched via get_playbook.
export function coverageReport({ scanId }: CoverageReportInput): CoverageReport {
  const scan = loadScan(scanId);
  if (!scan) {
    return { ok: false, error: `Unknown scanId "${scanId}". Call audit_repository first.` };
  }
  const selected = scan.playbooksLoaded;
  const executed = [...new Set([...(scan.playbooksFetched ?? []), ...(scan.playbooksReviewed ?? [])])].filter(
    (id) => selected.includes(id)
  );
  const notExecuted = selected.filter((id) => !executed.includes(id));
  const coveragePercent =
    selected.length === 0 ? 100 : Math.round((executed.length / selected.length) * 100);

  return {
    ok: true,
    scanId,
    mode: scan.mode,
    playbooksSelected: selected,
    playbooksExecuted: executed,
    playbooksNotExecuted: notExecuted,
    filesReviewed: scan.filesReviewed ?? [],
    coveragePercent,
    diffScoped: Boolean(scan.changedFiles && scan.changedFiles.length > 0),
    note:
      notExecuted.length > 0
        ? `${notExecuted.length} selected playbook(s) were not executed — those areas were not reviewed in this scan.`
        : "All selected playbooks were executed.",
  };
}
