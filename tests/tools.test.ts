import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { setGraphStorageBaseDir } from "../src/storage/graphStore.js";
import { setStorageBaseDir } from "../src/storage/scanStore.js";
import { auditRepository } from "../src/tools/auditRepository.js";
import { generateReportTool, setReportsBaseDir } from "../src/tools/generateReport.js";
import { getGraph } from "../src/tools/getGraph.js";
import { getPlaybook } from "../src/tools/getPlaybook.js";
import { listScans } from "../src/tools/listScans.js";
import { submitFindings } from "../src/tools/submitFindings.js";

const EXPRESS_FIXTURE = fileURLToPath(
  new URL("./fixtures/sample-repos/express-fixture", import.meta.url)
);

let tempStorageDir: string;

beforeEach(() => {
  tempStorageDir = mkdtempSync(join(tmpdir(), "winston-test-"));
  setStorageBaseDir(tempStorageDir);
  setGraphStorageBaseDir(tempStorageDir);
  setReportsBaseDir(tempStorageDir);
});

afterEach(() => {
  rmSync(tempStorageDir, { recursive: true, force: true });
});

const WELL_FORMED_FINDING = {
  playbookId: "ai_security.jwt_authentication",
  vulnerabilityClass: "broken_authentication",
  title: "JWT verification missing algorithm allow-list",
  severity: "critical",
  description: "jwt.verify() is called without pinning algorithms.",
  reasoning: "Without an algorithms allow-list, the library accepts any algorithm the token declares.",
  evidence: [
    {
      file: "src/middleware/auth.js",
      lineStart: 11,
      lineEnd: 11,
      snippet: "req.user = jwt.verify(token, SECRET);",
    },
  ],
  attackScenario:
    "An attacker crafts an alg:none token; since src/middleware/auth.js:11 does not pin algorithms, it is accepted.",
  affectedFiles: ["src/middleware/auth.js"],
  recommendedFix: "Pass { algorithms: ['HS256'] } to jwt.verify().",
  aiFixPrompt: "Update jwt.verify(token, SECRET) to jwt.verify(token, SECRET, { algorithms: ['HS256'] }).",
  graphNode: { type: "vulnerability", idHint: "finding:jwt-alg-confusion", label: "JWT algorithm confusion" },
  graphEdges: [
    { targetIdHint: "component:jwt", relation: "causes", description: "root cause is component:jwt" },
  ],
  confidence: "high",
};

describe("audit_repository -> submit_findings round trip", () => {
  it("returns a scanId and reasoning instructions that reference the JWT playbook", () => {
    const result = auditRepository({ repoPath: EXPRESS_FIXTURE, mode: "quick" });

    expect(result.error).toBeUndefined();
    expect(result.scanId).toBeTruthy();
    expect(result.playbooksLoaded).toContain("ai_security.jwt_authentication");
    expect(result.reasoningInstructions).toContain("submit_findings");
    expect(result.reasoningInstructions).toContain("src/middleware/auth.js");
  });

  it("accepts a well-formed finding referencing a valid scanId", () => {
    const audit = auditRepository({ repoPath: EXPRESS_FIXTURE, mode: "quick" });
    const result = submitFindings({
      scanId: audit.scanId!,
      findings: [WELL_FORMED_FINDING],
    });

    expect(result.ok).toBe(true);
    expect(result.acceptedCount).toBe(1);
    expect(result.severityCounts).toEqual({ critical: 1 });
  });

  it("rejects a finding with no evidence", () => {
    const audit = auditRepository({ repoPath: EXPRESS_FIXTURE, mode: "quick" });
    const badFinding = { ...WELL_FORMED_FINDING, evidence: [] };
    const result = submitFindings({ scanId: audit.scanId!, findings: [badFinding] });

    expect(result.ok).toBe(false);
    expect(result.validationErrors?.length).toBeGreaterThan(0);
  });

  it("updates the persisted threat graph and risk score when findings are submitted", () => {
    const audit = auditRepository({ repoPath: EXPRESS_FIXTURE, mode: "quick" });
    const submitResult = submitFindings({
      scanId: audit.scanId!,
      findings: [WELL_FORMED_FINDING],
    });

    expect(submitResult.riskScore?.critical).toBe(1);

    const summary = getGraph({ repoPath: EXPRESS_FIXTURE }) as {
      nodeCount: number;
      openVulnerabilities: number;
    };
    expect(summary.openVulnerabilities).toBe(1);
    expect(summary.nodeCount).toBeGreaterThanOrEqual(2); // vulnerability + component:jwt
  });

  it("generates a markdown report reflecting submitted findings", () => {
    const audit = auditRepository({ repoPath: EXPRESS_FIXTURE, mode: "quick" });
    submitFindings({ scanId: audit.scanId!, findings: [WELL_FORMED_FINDING] });

    const report = generateReportTool({ scanId: audit.scanId!, format: "markdown" });
    expect(report.ok).toBe(true);
    expect(report.content).toContain("JWT verification missing algorithm allow-list");
    expect(report.path).toBeTruthy();
  });

  it("rejects findings submitted against an unknown scanId", () => {
    const result = submitFindings({
      scanId: "does-not-exist",
      findings: [WELL_FORMED_FINDING],
    });
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/unknown scanid/i);
  });
});

describe("phased flow (piece by piece)", () => {
  it("audit_repository returns a persona + map + plan, but NO inlined file bodies", () => {
    const audit = auditRepository({ repoPath: EXPRESS_FIXTURE, mode: "deep" });
    const ri = audit.reasoningInstructions;
    expect(ri).toContain("You are Winston"); // persona / Phase 0
    expect(ri).toContain("How You Work"); // piece-by-piece protocol
    expect(ri).toContain("get_playbook"); // fetch-per-pass instruction
    expect(ri).toContain("Folder Tree"); // structural map, not bodies
    // The whole point: no file contents front-loaded into the recon prompt.
    expect(ri).not.toContain("Included File Contents");
  });
});

describe("get_playbook lazy fetch (body + its file slice)", () => {
  it("returns the full body for a playbook selected in the scan", () => {
    const audit = auditRepository({ repoPath: EXPRESS_FIXTURE, mode: "deep" });
    const result = getPlaybook({
      scanId: audit.scanId,
      playbookIds: ["ai_security.jwt_authentication"],
    });
    expect(result.ok).toBe(true);
    expect(result.playbooks?.[0].body).toContain("Root Cause Explanation");
  });

  it("returns the file slice resolved from the playbook's fileSelectionHint", () => {
    const audit = auditRepository({ repoPath: EXPRESS_FIXTURE, mode: "deep" });
    const result = getPlaybook({
      scanId: audit.scanId,
      playbookIds: ["ai_security.jwt_authentication"],
    });
    // Files ride with the playbook that examines them — the auth middleware is
    // exactly what the JWT playbook's hint points at.
    const paths = (result.files ?? []).map((f) => f.path);
    expect(paths.length).toBeGreaterThan(0);
    expect(paths).toContain("src/middleware/auth.js");
    expect(result.files?.[0].content).toBeTruthy(); // actual code, not just a path
  });

  it("delivers the precision layer (guardrails, severity rubric, mistakes) to the model", () => {
    const audit = auditRepository({ repoPath: EXPRESS_FIXTURE, mode: "deep" });
    const result = getPlaybook({
      scanId: audit.scanId,
      playbookIds: ["ai_security.jwt_authentication"],
    });
    const pb = result.playbooks?.[0];
    // Without these reaching the model, "check against falsePositiveGuardrails"
    // is pointing at nothing. They must be present and non-empty.
    expect(pb?.falsePositiveGuardrails.length).toBeGreaterThan(0);
    expect(pb?.commonAiCodingMistakes.length).toBeGreaterThan(0);
    expect(pb?.severityHeuristics).toBeTruthy();
    expect(pb?.vulnerabilityClass).toBe("broken_authentication");
  });

  it("refuses playbooks not selected for the scan's stack (ignore-the-rest contract)", () => {
    const audit = auditRepository({ repoPath: EXPRESS_FIXTURE, mode: "deep" });
    const result = getPlaybook({
      scanId: audit.scanId,
      // The express fixture is not a Rails app — this playbook must be refused.
      playbookIds: ["technology.rails.rails_security"],
    });
    expect(result.ok).toBe(false);
    expect(result.notApplicable).toContain("technology.rails.rails_security");
  });

  it("rejects an unknown scanId", () => {
    const result = getPlaybook({
      scanId: "does-not-exist",
      playbookIds: ["ai_security.jwt_authentication"],
    });
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/unknown scanid/i);
  });
});

describe("list_scans risk-score diffing", () => {
  it("shows a null delta for the first scan and a negative delta once an issue is fixed", () => {
    const first = auditRepository({ repoPath: EXPRESS_FIXTURE, mode: "quick" });
    submitFindings({ scanId: first.scanId!, findings: [WELL_FORMED_FINDING] });

    const second = auditRepository({ repoPath: EXPRESS_FIXTURE, mode: "quick" });
    submitFindings({ scanId: second.scanId!, findings: [] });

    const summaries = listScans({ repoPath: EXPRESS_FIXTURE });
    expect(summaries).toHaveLength(2);

    // newest first
    const [newest, oldest] = summaries;
    expect(oldest.riskScoreDelta).toBeNull();
    expect(oldest.riskScoreOverall).toBe(10);
    expect(newest.riskScoreOverall).toBe(0);
    expect(newest.riskScoreDelta).toBe(-10);
  });
});

describe("quick vs deep mode differentiation", () => {
  it("deep mode loads a strictly larger playbook set (includes deep_only playbooks) than quick mode", () => {
    const quick = auditRepository({ repoPath: EXPRESS_FIXTURE, mode: "quick" });
    const deep = auditRepository({ repoPath: EXPRESS_FIXTURE, mode: "deep" });

    expect(deep.playbooksLoaded!.length).toBeGreaterThan(quick.playbooksLoaded!.length);
    expect(deep.playbooksLoaded).toContain("ai_security.business_logic");
    expect(quick.playbooksLoaded).not.toContain("ai_security.business_logic");
  });

  it("deep mode's reasoning instructions are substantially larger (higher token estimate) than quick mode's", () => {
    const quick = auditRepository({ repoPath: EXPRESS_FIXTURE, mode: "quick" });
    const deep = auditRepository({ repoPath: EXPRESS_FIXTURE, mode: "deep" });

    expect(deep.estimatedTokens!).toBeGreaterThan(quick.estimatedTokens!);
    expect(deep.reasoningInstructions!.length).toBeGreaterThan(
      quick.reasoningInstructions!.length
    );
  });
});
