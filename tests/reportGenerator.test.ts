import { describe, expect, it } from "vitest";
import { mapFindingsToGraph } from "../src/graph/mapper.js";
import { emptyGraph } from "../src/models/graph.js";
import type { Finding } from "../src/models/findings.js";
import {
  deriveAttackChains,
  generateHtmlReport,
  generateMarkdownReport,
  generateReport,
  generateSarifReport,
} from "../src/pipeline/reportGenerator.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    playbookId: "ai_security.jwt_authentication",
    vulnerabilityClass: "broken_authentication",
    title: "Hardcoded fallback JWT secret",
    severity: "critical",
    description: "desc",
    reasoning: "reasoning",
    evidence: [{ file: "src/middleware/auth.js", lineStart: 3, lineEnd: 3, snippet: "const SECRET = ..." }],
    attackScenario: "scenario",
    affectedFiles: ["src/middleware/auth.js"],
    recommendedFix: "Use a required env var with no fallback.",
    aiFixPrompt: "prompt",
    graphNode: { type: "vulnerability", idHint: "finding:hardcoded-secret", label: "Hardcoded secret" },
    graphEdges: [
      { targetIdHint: "component:secrets", relation: "causes", description: "root cause" },
      { targetIdHint: "finding:jwt-alg-confusion", relation: "causes", description: "enables forgery" },
    ],
    confidence: "high",
    ...overrides,
  };
}

const CAUSED_FINDING = makeFinding({
  title: "JWT verification missing algorithm allow-list",
  severity: "high",
  graphNode: { type: "vulnerability", idHint: "finding:jwt-alg-confusion", label: "JWT algorithm confusion" },
  graphEdges: [{ targetIdHint: "component:jwt", relation: "causes", description: "root cause is jwt" }],
});

function buildTestGraph() {
  return mapFindingsToGraph(emptyGraph("/repo"), [makeFinding(), CAUSED_FINDING], "scan-1").graph;
}

describe("deriveAttackChains", () => {
  it("chains a root-cause finding through its causes edge to the downstream finding", () => {
    const graph = buildTestGraph();
    const chains = deriveAttackChains(graph);
    expect(chains).toHaveLength(1);
    // Prefers chaining through the downstream vulnerability before the
    // architectural component it also points at.
    expect(chains[0]).toEqual([
      "Hardcoded fallback JWT secret",
      "JWT verification missing algorithm allow-list",
      "Jwt",
    ]);
  });
});

describe("generateMarkdownReport", () => {
  it("includes executive summary, root causes, findings, and attack chains", () => {
    const graph = buildTestGraph();
    const report = generateMarkdownReport(graph);

    expect(report).toContain("# Winston Threat Report");
    expect(report).toContain("## Executive Summary");
    expect(report).toContain("## Root Causes");
    expect(report).toContain("Hardcoded fallback JWT secret");
    expect(report).toContain("## Attack Chains");
    expect(report).toContain("Hardcoded fallback JWT secret → JWT verification missing algorithm allow-list");
  });

  it("reports no open findings after all issues are fixed", () => {
    const first = mapFindingsToGraph(emptyGraph("/repo"), [makeFinding(), CAUSED_FINDING], "scan-1");
    const second = mapFindingsToGraph(first.graph, [], "scan-2");
    const report = generateMarkdownReport(second.graph);
    expect(report).toContain("No open findings.");
  });
});

describe("generateHtmlReport", () => {
  it("renders valid-looking HTML with escaped content", () => {
    const graph = buildTestGraph();
    const html = generateHtmlReport(graph);
    expect(html).toContain("<!doctype html>");
    expect(html).toContain("Hardcoded fallback JWT secret");
  });
});

describe("generateSarifReport — playbook citation enrichment", () => {
  it("populates non-empty tags and a real helpUri for a known playbook id", () => {
    const graph = buildTestGraph();
    const sarif = JSON.parse(generateSarifReport(graph));
    const rules = sarif.runs[0].tool.driver.rules;
    const rule = rules.find((r: { id: string }) => r.id === "ai_security.jwt_authentication");
    expect(rule).toBeDefined();
    expect(rule.properties.tags.length).toBeGreaterThan(0);
    expect(rule.helpUri).not.toBe("https://github.com/winston-sec/winston");
  });
});

describe("generateMarkdownReport — References line", () => {
  it("includes an OWASP/CWE references line for a finding whose playbook has refs", () => {
    const graph = buildTestGraph();
    const report = generateMarkdownReport(graph);
    expect(report).toContain("**References:** OWASP:");
    expect(report).toContain("CWE:");
  });
});

describe("generateReport — minSeverity filtering", () => {
  it("excludes medium/low findings when minSeverity is high", () => {
    const mediumFinding = makeFinding({
      title: "Missing security header",
      severity: "medium",
      graphNode: { type: "vulnerability", idHint: "finding:missing-header", label: "Missing security header" },
      graphEdges: [],
    });
    const graph = mapFindingsToGraph(
      emptyGraph("/repo"),
      [makeFinding(), CAUSED_FINDING, mediumFinding],
      "scan-1"
    ).graph;

    const fullReport = generateReport(graph, "markdown");
    expect(fullReport).toContain("Missing security header");

    const filtered = generateReport(graph, "markdown", "high");
    expect(filtered).toContain("### Hardcoded fallback JWT secret (critical)");
    expect(filtered).toContain("### JWT verification missing algorithm allow-list (high)");
    // medium-severity finding excluded from the Findings section
    expect(filtered).not.toContain("### Missing security header (medium)");
  });
});
