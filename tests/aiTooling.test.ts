import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { detectAiTooling } from "../src/detect/aiTooling.js";

let repo: string;
beforeEach(() => {
  repo = mkdtempSync(join(tmpdir(), "winston-tooling-"));
});
afterEach(() => rmSync(repo, { recursive: true, force: true }));

describe("detectAiTooling", () => {
  it("detects config artifacts with high confidence and no per-file claims", () => {
    mkdirSync(join(repo, ".cursor"));
    writeFileSync(join(repo, "CLAUDE.md"), "# instructions");
    const report = detectAiTooling(repo);
    const tools = report.detectedTools.map((t) => t.tool);
    expect(tools).toContain("Cursor");
    expect(tools).toContain("Claude Code");
    expect(report.detectedTools.every((t) => t.confidence === "high")).toBe(true);
    // Honest framing is part of the contract.
    expect(report.disclaimer).toMatch(/not proof/i);
  });

  it("detects tooling from git commit trailers", () => {
    execFileSync("git", ["init", "-q"], { cwd: repo });
    execFileSync("git", ["config", "user.email", "t@example.com"], { cwd: repo });
    execFileSync("git", ["config", "user.name", "Tester"], { cwd: repo });
    writeFileSync(join(repo, "a.txt"), "hello");
    execFileSync("git", ["add", "."], { cwd: repo });
    execFileSync(
      "git",
      ["commit", "-q", "-m", "feat: add thing\n\nCo-Authored-By: Claude <noreply@anthropic.com>"],
      { cwd: repo }
    );
    const report = detectAiTooling(repo);
    expect(report.isGitRepo).toBe(true);
    expect(report.detectedTools.map((t) => t.tool)).toContain("Claude Code");
    expect(report.signals.some((s) => s.source === "git_trailer")).toBe(true);
  });

  it("returns no signals for a clean repo", () => {
    const report = detectAiTooling(repo);
    expect(report.detectedTools).toEqual([]);
    expect(report.isGitRepo).toBe(false);
  });
});
