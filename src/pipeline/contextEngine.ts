import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { PlaybookPromptView } from "../models/playbook.js";
import type { FileInfo, RepoSummary } from "../models/repoContext.js";
import type {
  DependencyFlag,
  FileContentRef,
  SecurityContextPayload,
} from "../models/securityContext.js";
import type { TechnologyProfile } from "../models/techProfile.js";

export const QUICK_MODE_BYTE_BUDGET = 40_000;
export const DEEP_MODE_BYTE_BUDGET = 150_000;

const RISKY_DEPENDENCY_NOTES: Record<string, string> = {
  jwt: "JWT verification library detected — algorithm pinning and secret management need review.",
  stripe: "Payment provider detected — webhook signature verification is a common gap.",
  "file-upload": "File upload handling detected — validate type/size and storage path handling.",
  docker: "Containerized deployment detected — review base image and secret injection.",
};

export function buildRepoSummaryProse(
  repoSummary: RepoSummary,
  techProfile: TechnologyProfile
): string {
  const langList = Object.entries(repoSummary.languages)
    .sort((a, b) => b[1] - a[1])
    .map(([lang]) => lang)
    .join(", ");
  const frameworks = techProfile.frameworks.length
    ? techProfile.frameworks.join(", ")
    : "none detected";

  return (
    `Repository at ${repoSummary.repoPath} contains ${repoSummary.fileCount} files. ` +
    `Primary languages: ${langList || "none detected"}. ` +
    `Detected frameworks: ${frameworks}.`
  );
}

export function buildArchitectureSummaryProse(repoSummary: RepoSummary): string {
  const totalRoutes = repoSummary.routeMap.length;
  const protectedRoutes = repoSummary.routeMap.filter(
    (r) => r.middlewareChain.length > 0
  ).length;
  const authFiles = Array.from(new Set(repoSummary.authMap.map((a) => a.file)));

  return (
    `${totalRoutes} route(s) detected, ${protectedRoutes} appear to have a middleware ` +
    `chain attached. Auth-related patterns appear in: ${
      authFiles.length ? authFiles.join(", ") : "no files"
    }.`
  );
}

export function buildDependencySummary(techProfile: TechnologyProfile): DependencyFlag[] {
  const flags: DependencyFlag[] = [];
  for (const tag of techProfile.detectedTags) {
    const note = RISKY_DEPENDENCY_NOTES[tag];
    if (note) flags.push({ name: tag, reason: note });
  }
  return flags;
}

export function buildSecurityAssumptions(repoSummary: RepoSummary): string[] {
  const assumptions: string[] = [];
  const unprotected = repoSummary.routeMap.filter(
    (r) => r.middlewareChain.length === 0
  );
  if (unprotected.length > 0) {
    assumptions.push(
      `${unprotected.length} route(s) appear to have no middleware attached ` +
        `(unverified — some may be intentionally public, e.g. health checks or webhooks).`
    );
  }
  if (repoSummary.authMap.length === 0) {
    assumptions.push(
      "No recognized auth library imports detected — this app may use a custom or " +
        "framework-native auth mechanism not yet in the technology registry."
    );
  }
  return assumptions;
}

// Case-insensitive, prefix-aware match against a hint's matchImports list —
// so a hint of "@tauri-apps/api" still matches an import of
// "@tauri-apps/api/core".
function importMatches(importedModules: string[], matchImports: string[]): boolean {
  if (matchImports.length === 0 || importedModules.length === 0) return false;
  const lowerImports = importedModules.map((m) => m.toLowerCase());
  return matchImports.some((hint) => {
    const h = hint.toLowerCase();
    return lowerImports.some((imp) => imp === h || imp.startsWith(`${h}/`));
  });
}

export function selectFilesForContext(
  repoSummary: RepoSummary,
  hints: PlaybookPromptView[],
  byteBudget: number
): FileContentRef[] {
  const roles = new Set(hints.flatMap((h) => h.fileSelectionHint.roles));
  const matchImports = hints.flatMap((h) => h.fileSelectionHint.matchImports);
  const maxFilesTotal = hints.length
    ? Math.min(
        hints.reduce((sum, h) => sum + h.fileSelectionHint.maxFiles, 0),
        60
      )
    : 20;

  // Union role-matched and import-matched files (dedupe by path), so a file
  // whose role doesn't land in the web-oriented role enum can still be
  // selected via an import matching the playbook's matchImports hint. When
  // neither roles nor matchImports are provided at all (or hints is empty),
  // fall back to the full candidate pool — identical to prior behavior.
  let candidatePool: FileInfo[];
  if (roles.size === 0 && matchImports.length === 0) {
    candidatePool = repoSummary.importantFiles;
  } else {
    const seen = new Set<string>();
    candidatePool = [];
    for (const f of repoSummary.importantFiles) {
      if (roles.has(f.role) || importMatches(f.importedModules, matchImports)) {
        if (!seen.has(f.path)) {
          seen.add(f.path);
          candidatePool.push(f);
        }
      }
    }
  }

  const candidates = candidatePool
    .slice()
    .sort((a, b) => b.relevanceScore - a.relevanceScore)
    .slice(0, maxFilesTotal);

  const refs: FileContentRef[] = [];
  let usedBytes = 0;

  for (const file of candidates) {
    if (usedBytes >= byteBudget) break;
    let content: string;
    try {
      content = readFileSync(join(repoSummary.repoPath, file.path), "utf-8");
    } catch {
      continue;
    }
    const remaining = byteBudget - usedBytes;
    const contentBytes = Buffer.byteLength(content, "utf-8");

    if (contentBytes <= remaining) {
      refs.push({ path: file.path, role: file.role, content, truncated: false });
      usedBytes += contentBytes;
    } else {
      const slice = content.slice(0, remaining);
      refs.push({ path: file.path, role: file.role, content: slice, truncated: true });
      usedBytes += Buffer.byteLength(slice, "utf-8");
      break;
    }
  }

  return refs;
}

export interface BuildSecurityContextOptions {
  repoSummary: RepoSummary;
  techProfile: TechnologyProfile;
  playbookViews: PlaybookPromptView[];
  mode: "quick" | "deep";
  // When false (the phased flow's default), the recon payload carries the
  // structural map but NO file bodies — files are fetched per playbook via
  // get_playbook in Phase 3, so the model never holds the whole repo at once.
  includeFiles?: boolean;
}

export function buildSecurityContext({
  repoSummary,
  techProfile,
  playbookViews,
  mode,
  includeFiles = false,
}: BuildSecurityContextOptions): SecurityContextPayload {
  const byteBudget = mode === "deep" ? DEEP_MODE_BYTE_BUDGET : QUICK_MODE_BYTE_BUDGET;
  const fileContents = includeFiles
    ? selectFilesForContext(repoSummary, playbookViews, byteBudget)
    : [];
  const usedBytes = fileContents.reduce(
    (sum, f) => sum + Buffer.byteLength(f.content, "utf-8"),
    0
  );

  return {
    repoSummaryProse: buildRepoSummaryProse(repoSummary, techProfile),
    architectureSummaryProse: buildArchitectureSummaryProse(repoSummary),
    technologySummary: techProfile,
    dependencySummary: buildDependencySummary(techProfile),
    routeMap: repoSummary.routeMap,
    authMap: repoSummary.authMap,
    folderTree: repoSummary.folderTree,
    fileContents,
    playbookIds: playbookViews.map((p) => p.id),
    securityAssumptions: buildSecurityAssumptions(repoSummary),
    byteBudget: { limit: byteBudget, used: usedBytes },
  };
}
