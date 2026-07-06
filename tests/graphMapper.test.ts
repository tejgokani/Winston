import { describe, expect, it } from "vitest";
import { mapFindingsToGraph } from "../src/graph/mapper.js";
import { emptyGraph } from "../src/models/graph.js";
import type { Finding } from "../src/models/findings.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    playbookId: "ai_security.jwt_authentication",
    vulnerabilityClass: "broken_authentication",
    title: "JWT verification missing algorithm allow-list",
    severity: "critical",
    description: "desc",
    reasoning: "reasoning",
    evidence: [{ file: "src/middleware/auth.js", lineStart: 11, lineEnd: 11, snippet: "jwt.verify(token, SECRET)" }],
    attackScenario: "scenario",
    affectedFiles: ["src/middleware/auth.js"],
    recommendedFix: "fix",
    aiFixPrompt: "prompt",
    graphNode: { type: "vulnerability", idHint: "finding:jwt-alg-confusion", label: "JWT algorithm confusion" },
    graphEdges: [
      { targetIdHint: "component:jwt", relation: "causes", description: "root cause is jwt component" },
    ],
    confidence: "high",
    ...overrides,
  };
}

const HARDCODED_SECRET_FINDING = makeFinding({
  title: "Hardcoded fallback JWT secret",
  graphNode: { type: "vulnerability", idHint: "finding:hardcoded-secret", label: "Hardcoded secret" },
  graphEdges: [
    { targetIdHint: "component:secrets", relation: "causes", description: "root cause" },
    // This finding causes the alg-confusion finding via a cross-finding edge
    { targetIdHint: "finding:jwt-alg-confusion", relation: "causes", description: "secret leak enables forgery" },
  ],
});

describe("mapFindingsToGraph", () => {
  it("creates a vulnerability node and a lazily-created component node from graph edges", () => {
    const { graph } = mapFindingsToGraph(emptyGraph("/repo"), [makeFinding()], "scan-1");

    const vulnNode = graph.nodes.find((n) => n.type === "vulnerability");
    expect(vulnNode).toBeDefined();
    expect(vulnNode?.severity).toBe("critical");

    const componentNode = graph.nodes.find((n) => n.id === "component:jwt");
    expect(componentNode).toBeDefined();
    expect(componentNode?.type).toBe("component");

    const edge = graph.edges.find((e) => e.relation === "causes");
    expect(edge?.target).toBe("component:jwt");
  });

  it("deduplicates the same finding across scans into one node, keyed by (scanId, title)", () => {
    const first = mapFindingsToGraph(emptyGraph("/repo"), [makeFinding()], "scan-1");
    const second = mapFindingsToGraph(first.graph, [makeFinding()], "scan-2");

    const vulnNodes = second.graph.nodes.filter((n) => n.type === "vulnerability");
    expect(vulnNodes).toHaveLength(1);
    expect(vulnNodes[0].scanIds).toEqual(["scan-1", "scan-2"]);
  });

  it("transitions a node's status to fixed when a later full scan no longer finds it", () => {
    const first = mapFindingsToGraph(emptyGraph("/repo"), [makeFinding()], "scan-1");
    expect(first.graph.nodes.find((n) => n.type === "vulnerability")?.status).toBe("open");

    const second = mapFindingsToGraph(first.graph, [], "scan-2", { reconcileFixed: true });
    expect(second.graph.nodes.find((n) => n.type === "vulnerability")?.status).toBe("fixed");
  });

  it("does not mark nodes fixed when reconcileFixed is false (multi-pass deep mode)", () => {
    const first = mapFindingsToGraph(emptyGraph("/repo"), [makeFinding()], "scan-1");
    const second = mapFindingsToGraph(first.graph, [], "scan-1", { reconcileFixed: false });
    expect(second.graph.nodes.find((n) => n.type === "vulnerability")?.status).toBe("open");
  });

  it("resolves cross-finding edges within the same batch and flags root causes correctly", () => {
    const { graph } = mapFindingsToGraph(
      emptyGraph("/repo"),
      [makeFinding(), HARDCODED_SECRET_FINDING],
      "scan-1"
    );

    const secretNode = graph.nodes.find((n) => n.label === "Hardcoded fallback JWT secret");
    const algNode = graph.nodes.find(
      (n) => n.label === "JWT verification missing algorithm allow-list"
    );

    // secret -> causes -> algNode, and secret has no incoming causes edges: it's the root cause.
    expect(secretNode?.rootCause).toBe(true);
    expect(algNode?.rootCause).toBe(false);
  });

  it("drops edges whose target cannot be resolved, reporting them instead of failing silently", () => {
    const dangling = makeFinding({
      graphEdges: [{ targetIdHint: "component:does_not_exist", relation: "causes", description: "x" }],
    });
    const { droppedEdges } = mapFindingsToGraph(emptyGraph("/repo"), [dangling], "scan-1");
    expect(droppedEdges).toHaveLength(1);
    expect(droppedEdges[0].targetIdHint).toBe("component:does_not_exist");
  });

  it("computes an aggregate risk score from open vulnerability severities", () => {
    const { graph } = mapFindingsToGraph(emptyGraph("/repo"), [makeFinding()], "scan-1");
    expect(graph.riskScore.critical).toBe(1);
    expect(graph.riskScore.overall).toBeGreaterThan(0);
  });

  it("crowns the node with the largest downstream blast radius", () => {
    // secret --causes--> alg-confusion (both critical). The secret reaches 2
    // open vulns downstream (itself + alg), alg reaches 1 (itself), so the
    // secret is the crown.
    const { graph } = mapFindingsToGraph(
      emptyGraph("/repo"),
      [makeFinding(), HARDCODED_SECRET_FINDING],
      "scan-1"
    );

    const secret = graph.nodes.find((n) => n.label === "Hardcoded fallback JWT secret")!;
    const alg = graph.nodes.find(
      (n) => n.label === "JWT verification missing algorithm allow-list"
    )!;

    expect(graph.crownNodeId).toBe(secret.id);
    expect(secret.impactRank).toBe(1);
    expect(secret.downstreamImpact).toBe(2); // itself + alg
    expect(secret.crownScore).toBe(20); // 10 (critical) + 10 (critical)
    expect(alg.impactRank).toBe(2);
    expect(alg.downstreamImpact).toBe(1);
  });

  it("clears the crown when all vulnerabilities are fixed", () => {
    const first = mapFindingsToGraph(emptyGraph("/repo"), [makeFinding()], "scan-1");
    expect(first.graph.crownNodeId).not.toBeNull();
    const second = mapFindingsToGraph(first.graph, [], "scan-2", { reconcileFixed: true });
    expect(second.graph.crownNodeId).toBeNull();
    expect(second.graph.nodes.every((n) => n.impactRank === null)).toBe(true);
  });
});
