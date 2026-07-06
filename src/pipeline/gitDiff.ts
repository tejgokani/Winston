import { execFileSync } from "node:child_process";

// Changed-file set for diff-scoped audits. Given a base ref (branch, tag, or
// commit — e.g. "main", "HEAD~1", "origin/main"), return the repo-relative
// paths that differ, so the review can be restricted to the diff plus its
// blast radius. Deterministic, no LLM. Non-fatal: a bad ref / non-git repo
// yields an empty set (caller falls back to a full scan).
export function changedFilesSince(repoPath: string, base: string): string[] {
  try {
    const out = execFileSync("git", ["diff", "--name-only", `${base}...HEAD`], {
      cwd: repoPath,
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    // Also include not-yet-committed working-tree changes vs. the base.
    const wt = execFileSync("git", ["diff", "--name-only", base], {
      cwd: repoPath,
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    const set = new Set(
      [...out.split("\n"), ...wt.split("\n")].map((l) => l.trim()).filter(Boolean)
    );
    return [...set];
  } catch {
    return [];
  }
}
