import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { scanSecrets } from "../src/detect/secrets.js";
import { generateSarifReport } from "../src/pipeline/reportGenerator.js";
import { selectPlaybooks } from "../src/pipeline/playbookLoader.js";
import { setGraphStorageBaseDir } from "../src/storage/graphStore.js";
import { setStorageBaseDir } from "../src/storage/scanStore.js";
import { auditRepository } from "../src/tools/auditRepository.js";
import { coverageReport } from "../src/tools/coverageReport.js";
import { getPlaybook } from "../src/tools/getPlaybook.js";
import { submitFindings } from "../src/tools/submitFindings.js";
import { verifyFix } from "../src/tools/verifyFix.js";
import { emptyGraph } from "../src/models/graph.js";
import { mapFindingsToGraph } from "../src/graph/mapper.js";
import type { Finding } from "../src/models/findings.js";

let store: string;
let repo: string;
beforeEach(() => {
  store = mkdtempSync(join(tmpdir(), "winston-feat-"));
  setStorageBaseDir(store);
  setGraphStorageBaseDir(store);
  repo = mkdtempSync(join(tmpdir(), "winston-feat-repo-"));
  writeFileSync(join(repo, "package.json"), JSON.stringify({ dependencies: { jsonwebtoken: "^9", pg: "^8" } }));
  writeFileSync(
    join(repo, "auth.js"),
    "const jwt=require('jsonwebtoken');\nreq.user = jwt.verify(token, SECRET);\n"
  );
});
afterEach(() => {
  rmSync(store, { recursive: true, force: true });
  rmSync(repo, { recursive: true, force: true });
});

function finding(over: Partial<Finding> = {}): Finding {
  return {
    playbookId: "ai_security.jwt_authentication",
    vulnerabilityClass: "broken_authentication",
    title: "JWT missing algorithm allow-list",
    severity: "critical",
    description: "d",
    reasoning: "r",
    evidence: [{ file: "auth.js", lineStart: 2, lineEnd: 2, snippet: "jwt.verify(token, SECRET)" }],
    attackScenario: "s",
    affectedFiles: ["auth.js"],
    recommendedFix: "fix",
    aiFixPrompt: "pin algorithms",
    graphNode: { type: "vulnerability", idHint: "finding:jwt", label: "JWT" },
    graphEdges: [{ targetIdHint: "component:jwt", relation: "causes", description: "rc" }],
    confidence: "high",
    ...over,
  };
}

describe("T2.5 secret scanner", () => {
  it("detects a high-confidence provider key but not a placeholder", () => {
    writeFileSync(join(repo, "config.js"), 'const k = "AKIAIOSFODNN7EXAMPLE";\nconst p = "changeme";\n');
    const report = scanSecrets(repo);
    const types = report.findings.map((f) => f.type);
    expect(types).toContain("AWS Access Key ID");
    expect(report.findings.every((f) => !f.redacted.includes("EXAMPLE"))).toBe(true); // redacted
  });

  it("respects an inline winston:ignore marker", () => {
    writeFileSync(join(repo, "config.js"), 'const k = "AKIAIOSFODNN7EXAMPLE"; // winston:ignore\n');
    expect(scanSecrets(repo).findings.length).toBe(0);
  });
});

describe("T2.6 coverage report", () => {
  it("distinguishes selected vs executed playbooks", () => {
    const audit = auditRepository({ repoPath: repo, mode: "quick" });
    // Execute exactly one playbook.
    getPlaybook({ scanId: audit.scanId, playbookIds: ["ai_security.jwt_authentication"] });
    const cov = coverageReport({ scanId: audit.scanId });
    expect(cov.ok).toBe(true);
    expect(cov.playbooksExecuted).toContain("ai_security.jwt_authentication");
    expect(cov.playbooksNotExecuted!.length).toBeGreaterThan(0);
    expect(cov.coveragePercent).toBeLessThan(100);
  });
});

describe("T1.3 verify_fix", () => {
  it("reports still_open while the vulnerable code is present, fixed once removed", () => {
    const audit = auditRepository({ repoPath: repo, mode: "quick" });
    submitFindings({ scanId: audit.scanId, findings: [finding()] });
    // graph node id is deterministic from (repoPath, title)
    const { graph } = mapFindingsToGraph(emptyGraph(repo), [finding()], "probe");
    const nodeId = graph.nodes.find((n) => n.type === "vulnerability")!.id;

    const before = verifyFix({ scanId: audit.scanId, findingId: nodeId });
    expect(before.status).toBe("still_open");
    expect(before.aiFixPrompt).toBe("pin algorithms");

    // Apply the fix: remove the vulnerable line.
    writeFileSync(join(repo, "auth.js"), "const jwt=require('jsonwebtoken');\n// fixed\n");
    const after = verifyFix({ scanId: audit.scanId, findingId: nodeId });
    expect(after.status).toBe("fixed");
    expect(after.proof).toMatch(/no longer appears/i);
  });
});

describe("T3.7 custom org playbooks", () => {
  it("loads a repo's custom playbook when its tag matches, and get_playbook returns its body", () => {
    const dir = join(repo, ".winston", "playbooks");
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, "org_rule.md"),
      [
        "---",
        "id: org.custom_rule",
        "title: Org Custom Rule",
        "category: ai_security",
        "vulnerabilityClass: custom",
        "appliesToStack: jwt apps",
        "requiresAnyTag: [jwt]",
        "reviewPass: 1",
        'quickModeSummary: "Check the org-specific rule."',
        "fileSelectionHint: { roles: [auth], matchImports: [], matchAuthMapTags: [], maxFiles: 3, priorityOrder: [] }",
        "severityHeuristics: { critical: [], high: [], medium: [], low: [] }",
        "graphNodeMapping: { primaryNodeType: component, primaryNodeId: 'component:authentication' }",
        "---",
        "## Root Cause Explanation",
        "The org rule body.",
      ].join("\n")
    );
    const views = selectPlaybooks(["jwt"], "deep", repo).map((v) => v.id);
    expect(views).toContain("org.custom_rule");

    const audit = auditRepository({ repoPath: repo, mode: "deep" });
    expect(audit.playbooksLoaded).toContain("org.custom_rule");
    const gp = getPlaybook({ scanId: audit.scanId, playbookIds: ["org.custom_rule"] });
    expect(gp.ok).toBe(true);
    expect(gp.playbooks?.[0].body).toContain("The org rule body");
  });
});

describe("T2.4 diff-scoped audit", () => {
  it("records the changed-file set from a git base", () => {
    execFileSync("git", ["init", "-q"], { cwd: repo });
    execFileSync("git", ["config", "user.email", "t@e.com"], { cwd: repo });
    execFileSync("git", ["config", "user.name", "T"], { cwd: repo });
    execFileSync("git", ["add", "."], { cwd: repo });
    execFileSync("git", ["commit", "-qm", "base"], { cwd: repo });
    writeFileSync(join(repo, "new.js"), "const x = 1;\n");
    execFileSync("git", ["add", "."], { cwd: repo });

    const audit = auditRepository({ repoPath: repo, mode: "quick", diffBase: "HEAD" });
    expect(audit.diffScope?.base).toBe("HEAD");
    expect(audit.diffScope?.changedFiles).toContain("new.js");
  });
});

describe("T1.2 SARIF export", () => {
  it("emits valid SARIF 2.1.0 with a result per open vulnerability", () => {
    const { graph } = mapFindingsToGraph(emptyGraph(repo), [finding()], "s1");
    const sarif = JSON.parse(generateSarifReport(graph));
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].tool.driver.name).toBe("Winston");
    expect(sarif.runs[0].results.length).toBe(1);
    expect(sarif.runs[0].results[0].level).toBe("error"); // critical → error
    expect(sarif.runs[0].results[0].ruleId).toBe("ai_security.jwt_authentication");
  });
});
