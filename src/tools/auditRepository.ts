import { randomUUID } from "node:crypto";
import { buildSecurityContext } from "../pipeline/contextEngine.js";
import { changedFilesSince } from "../pipeline/gitDiff.js";
import { customPlaybookPaths, selectPlaybooks } from "../pipeline/playbookLoader.js";
import { buildReasoningInstructions } from "../pipeline/promptBuilder.js";
import { scanRepository } from "../pipeline/scanner.js";
import { detectTechnology } from "../pipeline/techDetector.js";
import { createScan } from "../storage/scanStore.js";
import { estimateTokens } from "../utils/tokenEstimation.js";

export interface AuditRepositoryInput {
  repoPath: string;
  mode?: "quick" | "deep";
  // Diff-scoped audit: when set (e.g. "main", "HEAD~1", "origin/main"), the
  // review is restricted to files changed vs. this base — get_playbook only
  // returns changed files. Faster/cheaper PR-style reviews.
  diffBase?: string;
}

export interface AuditRepositoryResult {
  scanId: string;
  mode: "quick" | "deep";
  estimatedTokens: number;
  technologyProfile: unknown;
  playbooksLoaded: string[];
  reasoningInstructions: string;
  diffScope?: { base: string; changedFiles: string[] };
}

export function auditRepository({
  repoPath,
  mode = "quick",
  diffBase,
}: AuditRepositoryInput): AuditRepositoryResult {
  const repoSummary = scanRepository(repoPath);
  const techProfile = detectTechnology(repoPath);
  const playbookViews = selectPlaybooks(techProfile.detectedTags, mode, repoPath);
  const customPaths = customPlaybookPaths(repoPath);
  const changedFiles = diffBase ? changedFilesSince(repoPath, diffBase) : [];
  // Recon skeleton only — no file bodies. Files are fetched per pass via
  // get_playbook (the piece-by-piece contract).
  const securityContext = buildSecurityContext({
    repoSummary,
    techProfile,
    playbookViews,
    mode,
    includeFiles: false,
  });

  const scanId = randomUUID();
  const reasoningInstructions = buildReasoningInstructions(
    securityContext,
    playbookViews,
    scanId,
    mode
  );

  createScan({
    scanId,
    repoPath,
    mode,
    technologyProfile: techProfile,
    playbooksLoaded: playbookViews.map((p) => p.id),
    // Persisted so get_playbook can resolve each pass's file slice on demand.
    repoSummary,
    playbookViews,
    customPlaybookPaths: Object.keys(customPaths).length > 0 ? customPaths : undefined,
    diffBase,
    changedFiles: changedFiles.length > 0 ? changedFiles : undefined,
  });

  return {
    scanId,
    mode,
    estimatedTokens: estimateTokens(reasoningInstructions),
    technologyProfile: techProfile,
    playbooksLoaded: playbookViews.map((p) => p.id),
    reasoningInstructions,
    diffScope: diffBase ? { base: diffBase, changedFiles } : undefined,
  };
}
