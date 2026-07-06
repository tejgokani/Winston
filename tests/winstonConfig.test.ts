import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadWinstonConfig } from "../src/config/winstonConfig.js";
import { selectPlaybooks } from "../src/pipeline/playbookLoader.js";

let tmpDir: string | null = null;

function makeRepo(): string {
  tmpDir = mkdtempSync(join(tmpdir(), "winston-config-test-"));
  return tmpDir;
}

afterEach(() => {
  if (tmpDir) {
    rmSync(tmpDir, { recursive: true, force: true });
    tmpDir = null;
  }
});

describe("loadWinstonConfig", () => {
  it("returns safe defaults when winston.config.json is absent", () => {
    const repoPath = makeRepo();
    const config = loadWinstonConfig(repoPath);
    expect(config.disabledPlaybooks).toEqual([]);
    expect(config.minSeverity).toBeUndefined();
  });

  it("does not throw and falls back to defaults on invalid JSON", () => {
    const repoPath = makeRepo();
    writeFileSync(join(repoPath, "winston.config.json"), "{ not valid json");
    expect(() => loadWinstonConfig(repoPath)).not.toThrow();
    const config = loadWinstonConfig(repoPath);
    expect(config.disabledPlaybooks).toEqual([]);
  });

  it("does not throw and falls back to defaults on schema-invalid content", () => {
    const repoPath = makeRepo();
    writeFileSync(
      join(repoPath, "winston.config.json"),
      JSON.stringify({ minSeverity: "not-a-severity" })
    );
    expect(() => loadWinstonConfig(repoPath)).not.toThrow();
    const config = loadWinstonConfig(repoPath);
    expect(config.disabledPlaybooks).toEqual([]);
    expect(config.minSeverity).toBeUndefined();
  });

  it("parses a valid config", () => {
    const repoPath = makeRepo();
    writeFileSync(
      join(repoPath, "winston.config.json"),
      JSON.stringify({ minSeverity: "high", disabledPlaybooks: ["ai_security.xss"] })
    );
    const config = loadWinstonConfig(repoPath);
    expect(config.minSeverity).toBe("high");
    expect(config.disabledPlaybooks).toEqual(["ai_security.xss"]);
  });
});

describe("selectPlaybooks — disabledPlaybooks wiring", () => {
  it("removes a disabled playbook from selection even though its tag matches", () => {
    const repoPath = makeRepo();
    writeFileSync(
      join(repoPath, "winston.config.json"),
      JSON.stringify({ disabledPlaybooks: ["ai_security.xss"] })
    );

    const withoutConfig = selectPlaybooks(["frontend"], "quick").map((v) => v.id);
    expect(withoutConfig).toContain("ai_security.xss");

    const withConfig = selectPlaybooks(["frontend"], "quick", repoPath).map((v) => v.id);
    expect(withConfig).not.toContain("ai_security.xss");
  });

  it("behaves exactly as before when repoPath is omitted (no config lookup)", () => {
    const ids = selectPlaybooks(["frontend"], "quick").map((v) => v.id);
    expect(ids).toContain("ai_security.xss");
  });

  it("behaves exactly as before when the repo has no winston.config.json", () => {
    const repoPath = makeRepo();
    const ids = selectPlaybooks(["frontend"], "quick", repoPath).map((v) => v.id);
    expect(ids).toContain("ai_security.xss");
  });
});
