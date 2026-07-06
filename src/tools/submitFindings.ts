import { writeFileSync } from "node:fs";
import { FindingSchema, type Finding } from "../models/findings.js";
import { updateGraphWithFindings } from "../pipeline/graphBuilder.js";
import { attachFindings, loadScan, recordReviewed } from "../storage/scanStore.js";
import { checkSuppressed, loadSuppressions } from "../suppress/suppressions.js";
import { verifyFindingEvidence } from "../verify/evidence.js";

export interface SubmitFindingsInput {
  scanId: string;
  findings: unknown[];
}

export interface SubmitFindingsResult {
  ok: boolean;
  scanId: string;
  acceptedCount?: number;
  severityCounts?: Record<string, number>;
  riskScore?: { overall: number; critical: number; high: number; medium: number; low: number };
  droppedEdges?: Array<{ finding: string; targetIdHint: string; reason: string }>;
  // Findings dropped by the false-positive / suppression gates — reported, not
  // hidden, so the model and user can see what was filtered and why.
  suppressed?: Array<{ finding: string; reason: string }>;
  unverified?: Array<{ finding: string; reason: string }>;
  error?: string;
  validationErrors?: string[];
}

export function submitFindings({
  scanId,
  findings,
}: SubmitFindingsInput): SubmitFindingsResult {
  const scan = loadScan(scanId);
  if (!scan) {
    return {
      ok: false,
      scanId,
      error: `Unknown scanId "${scanId}". Call audit_repository first.`,
    };
  }

  const parsed: Finding[] = [];
  const validationErrors: string[] = [];

  findings.forEach((raw, index) => {
    const result = FindingSchema.safeParse(raw);
    if (result.success) {
      parsed.push(result.data);
    } else {
      validationErrors.push(`findings[${index}]: ${result.error.message}`);
    }
  });

  if (validationErrors.length > 0) {
    return {
      ok: false,
      scanId,
      error: "One or more findings failed validation. Fix and retry.",
      validationErrors,
    };
  }

  // False-positive gates. (1) Suppression: honour .winston-ignore + inline
  // markers. (2) Evidence verification: the quoted code must actually exist in
  // the repo. Both filter BEFORE the graph is touched, and both report what
  // they dropped rather than hiding it.
  const rules = loadSuppressions(scan.repoPath);
  const accepted: Finding[] = [];
  const suppressed: Array<{ finding: string; reason: string }> = [];
  const unverified: Array<{ finding: string; reason: string }> = [];

  for (const f of parsed) {
    const sup = checkSuppressed(f, rules, scan.repoPath);
    if (sup.suppressed) {
      suppressed.push({ finding: f.title, reason: sup.reason ?? "suppressed" });
      continue;
    }
    const verdict = verifyFindingEvidence(f, scan.repoPath);
    if (!verdict.verified) {
      unverified.push({ finding: f.title, reason: verdict.reason });
      continue;
    }
    accepted.push(f);
  }

  const { graph, droppedEdges } = updateGraphWithFindings(scan.repoPath, accepted, scanId);
  attachFindings(scanId, accepted, graph.riskScore.overall);
  // Coverage: record which playbooks actually produced (or were checked for)
  // findings in this submission, so coverage_report can show what ran.
  recordReviewed(scanId, {
    playbooks: [...new Set(parsed.map((f) => f.playbookId))],
    files: [],
  });

  const severityCounts: Record<string, number> = {};
  for (const f of accepted) {
    severityCounts[f.severity] = (severityCounts[f.severity] ?? 0) + 1;
  }

  // Eval-harness capture hook: when WINSTON_EVAL_CAPTURE is set, dump the
  // accepted findings as JSON so `winston eval` can score them against
  // ground truth. No-op (and zero behavior change) when the env var is unset.
  if (process.env.WINSTON_EVAL_CAPTURE) {
    try {
      writeFileSync(process.env.WINSTON_EVAL_CAPTURE, JSON.stringify(accepted, null, 2));
    } catch {
      // Capture is best-effort diagnostics; never let it affect the submit result.
    }
  }

  return {
    ok: true,
    scanId,
    acceptedCount: accepted.length,
    severityCounts,
    riskScore: graph.riskScore,
    droppedEdges: droppedEdges.length > 0 ? droppedEdges : undefined,
    suppressed: suppressed.length > 0 ? suppressed : undefined,
    unverified: unverified.length > 0 ? unverified : undefined,
  };
}
