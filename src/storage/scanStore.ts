import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Finding } from "../models/findings.js";
import type { PlaybookPromptView } from "../models/playbook.js";
import type { RepoSummary } from "../models/repoContext.js";
import type { TechnologyProfile } from "../models/techProfile.js";

// Phase 3 minimal persistence: one JSON file per scan. Phase 4 introduces the
// versioned ThreatGraph blob + SQLite scan-history index on top of this same
// directory layout — this store's job (record a scan, attach findings to it)
// doesn't change, only what else gets written alongside it.

export interface ScanRecord {
  scanId: string;
  repoPath: string;
  mode: "quick" | "deep";
  technologyProfile: TechnologyProfile;
  playbooksLoaded: string[];
  // Persisted so get_playbook can resolve each playbook's file slice at fetch
  // time (Phase 3) instead of audit_repository front-loading every file's
  // contents up front — the "piece by piece" contract. repoSummary is the
  // scanner's structural map; playbookViews carry each playbook's
  // fileSelectionHint. Optional so scans written before this change still load.
  repoSummary?: RepoSummary;
  playbookViews?: PlaybookPromptView[];
  // Custom org playbook id → absolute source path, so get_playbook can resolve
  // a body the built-in id index doesn't know about.
  customPlaybookPaths?: Record<string, string>;
  // Coverage tracking: which playbooks were actually fetched (executed) via
  // get_playbook, which produced/were-checked in submit_findings, and which
  // files were pulled for review. Powers coverage_report — honesty about what
  // was and wasn't checked.
  playbooksFetched?: string[];
  playbooksReviewed?: string[];
  filesReviewed?: string[];
  // Optional diff scoping: when the audit was restricted to a changed-file set.
  diffBase?: string;
  changedFiles?: string[];
  createdAt: string;
  findings: Finding[];
  // Snapshot of the repo's overall risk score at the moment this scan's
  // findings were submitted. The threat graph itself is one evolving
  // document per repo (not versioned per scan — see plan's storage
  // simplification), so without this snapshot every scan's "current" risk
  // score would read as identical, making list_scans' delta meaningless.
  riskScoreAtSubmission: number | null;
}

let baseDirOverride: string | null = null;

export function setStorageBaseDir(dir: string): void {
  baseDirOverride = dir;
}

function scansDir(): string {
  const base = baseDirOverride ?? join(homedir(), ".winston");
  const dir = join(base, "scans");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  return dir;
}

function scanFilePath(scanId: string): string {
  return join(scansDir(), `${scanId}.json`);
}

// Atomic write: write to a temp file then rename, so a concurrent reader never
// sees a half-written JSON and two writers can't interleave a partial file.
function writeJsonAtomic(path: string, data: unknown): void {
  const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
  writeFileSync(tmp, JSON.stringify(data, null, 2));
  renameSync(tmp, path);
}

export function createScan(
  record: Omit<ScanRecord, "findings" | "createdAt" | "riskScoreAtSubmission">
): ScanRecord {
  const full: ScanRecord = {
    ...record,
    createdAt: new Date().toISOString(),
    findings: [],
    riskScoreAtSubmission: null,
  };
  writeJsonAtomic(scanFilePath(record.scanId), full);
  return full;
}

export function loadScan(scanId: string): ScanRecord | null {
  const path = scanFilePath(scanId);
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf-8")) as ScanRecord;
}

export function attachFindings(
  scanId: string,
  findings: Finding[],
  riskScoreAtSubmission: number
): ScanRecord {
  const scan = loadScan(scanId);
  if (!scan) throw new Error(`Unknown scanId: ${scanId}`);
  scan.findings = [...scan.findings, ...findings];
  scan.riskScoreAtSubmission = riskScoreAtSubmission;
  writeJsonAtomic(scanFilePath(scanId), scan);
  return scan;
}

// Coverage bookkeeping. Append-and-dedupe the playbooks/files touched, so the
// scan record accumulates what was actually executed across passes.
export function recordFetched(
  scanId: string,
  data: { playbooks: string[]; files: string[] }
): void {
  const scan = loadScan(scanId);
  if (!scan) return;
  scan.playbooksFetched = [...new Set([...(scan.playbooksFetched ?? []), ...data.playbooks])];
  scan.filesReviewed = [...new Set([...(scan.filesReviewed ?? []), ...data.files])];
  writeJsonAtomic(scanFilePath(scanId), scan);
}

export function recordReviewed(
  scanId: string,
  data: { playbooks: string[]; files: string[] }
): void {
  const scan = loadScan(scanId);
  if (!scan) return;
  scan.playbooksReviewed = [...new Set([...(scan.playbooksReviewed ?? []), ...data.playbooks])];
  scan.filesReviewed = [...new Set([...(scan.filesReviewed ?? []), ...data.files])];
  writeJsonAtomic(scanFilePath(scanId), scan);
}

export function listScans(repoPath?: string, limit = 10): ScanRecord[] {
  const dir = scansDir();
  const files = readdirSync(dir).filter((f) => f.endsWith(".json"));
  const records = files
    .map((f) => JSON.parse(readFileSync(join(dir, f), "utf-8")) as ScanRecord)
    .filter((r) => !repoPath || r.repoPath === repoPath)
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  return records.slice(0, limit);
}
