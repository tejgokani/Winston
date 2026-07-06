import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { emptyGraph, type ThreatGraph } from "../models/graph.js";

// One graph per repo, keyed by a hash of its absolute path, so successive
// scans of the same repo update the same graph in place rather than
// producing a disconnected graph per scan. Shares the storage base dir
// override with scanStore.ts for test isolation.

let baseDirOverride: string | null = null;

export function setGraphStorageBaseDir(dir: string): void {
  baseDirOverride = dir;
}

function graphsDir(): string {
  const base = baseDirOverride ?? join(homedir(), ".winston");
  const dir = join(base, "graphs");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  return dir;
}

function graphFilePath(repoPath: string): string {
  const key = createHash("sha1").update(repoPath).digest("hex").slice(0, 16);
  return join(graphsDir(), `${key}.json`);
}

export function loadGraphForRepo(repoPath: string): ThreatGraph {
  const path = graphFilePath(repoPath);
  if (!existsSync(path)) return emptyGraph(repoPath);
  return JSON.parse(readFileSync(path, "utf-8")) as ThreatGraph;
}

export function saveGraphForRepo(graph: ThreatGraph): void {
  // Atomic write (temp + rename) so a concurrent reader (e.g. the VS Code
  // extension watching the file) never sees a half-written graph, and two
  // multi-pass writes can't interleave a partial file.
  const path = graphFilePath(graph.repoPath);
  const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
  writeFileSync(tmp, JSON.stringify(graph, null, 2));
  renameSync(tmp, path);
}
