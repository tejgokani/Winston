import { describe, expect, it } from "vitest";
import { scoreFindings } from "../../src/eval/scorer.js";
import type { GroundTruthEntry } from "../../src/eval/groundTruth.js";
import type { Finding } from "../../src/models/findings.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    playbookId: "ai_security.jwt_authentication",
    vulnerabilityClass: "jwt-missing-algorithm-allowlist",
    title: "JWT verification missing algorithm allow-list",
    severity: "high",
    description: "jwt.verify is called without restricting algorithms.",
    reasoning: "No `algorithms` option is passed to jwt.verify.",
    evidence: [
      {
        file: "src/middleware/auth.js",
        lineStart: 11,
        lineEnd: 11,
        snippet: 'req.user = jwt.verify(token, SECRET);',
      },
    ],
    attackScenario: "An attacker forges a token using the `none` algorithm.",
    affectedFiles: ["src/middleware/auth.js"],
    recommendedFix: "Pass `{ algorithms: [\"HS256\"] }` to jwt.verify.",
    aiFixPrompt: "Add an algorithms allow-list to jwt.verify.",
    graphNode: { type: "vulnerability", idHint: "jwt-alg", label: "JWT algorithm confusion" },
    graphEdges: [],
    confidence: "high",
    ...overrides,
  };
}

const singleEntryGroundTruth: GroundTruthEntry[] = [
  {
    file: "src/middleware/auth.js",
    lineStart: 11,
    lineEnd: 11,
    playbookId: "ai_security.jwt_authentication",
    vulnerabilityClass: "jwt-missing-algorithm-allowlist",
    description: "jwt.verify() missing algorithms allow-list.",
  },
];

describe("scoreFindings", () => {
  it("scores an exact-match finding as 100% precision and recall", () => {
    const result = scoreFindings(singleEntryGroundTruth, [makeFinding()]);
    expect(result.precision).toBe(1);
    expect(result.recall).toBe(1);
    expect(result.f1).toBe(1);
    expect(result.matched).toHaveLength(1);
    expect(result.missed).toHaveLength(0);
    expect(result.falsePositives).toHaveLength(0);
  });

  it("counts a finding on the wrong file/line as a false positive and misses the ground truth", () => {
    const wrongLocation = makeFinding({
      evidence: [
        {
          file: "src/routes/account.js",
          lineStart: 200,
          lineEnd: 205,
          snippet: "// unrelated code",
        },
      ],
    });
    const result = scoreFindings(singleEntryGroundTruth, [wrongLocation]);
    expect(result.precision).toBe(0);
    expect(result.recall).toBe(0);
    expect(result.f1).toBe(0);
    expect(result.matched).toHaveLength(0);
    expect(result.missed).toHaveLength(1);
    expect(result.falsePositives).toHaveLength(1);
  });

  it("handles empty ground truth without NaN (nextjs-fixture true-negative case)", () => {
    const result = scoreFindings([], [makeFinding()]);
    expect(result.recall).toBe(1); // nothing to miss
    expect(result.precision).toBe(0); // one unmatched finding against zero ground truth
    expect(Number.isNaN(result.precision)).toBe(false);
    expect(Number.isNaN(result.recall)).toBe(false);
    expect(Number.isNaN(result.f1)).toBe(false);
    expect(result.falsePositives).toHaveLength(1);
    expect(result.missed).toHaveLength(0);
  });

  it("handles empty ground truth with zero submitted findings as fully clean (no NaN)", () => {
    const result = scoreFindings([], []);
    expect(result.precision).toBe(1);
    expect(result.recall).toBe(1);
    expect(result.f1).toBe(1);
  });

  it("yields 50% recall when only one of two ground-truth entries is matched", () => {
    const twoEntries: GroundTruthEntry[] = [
      ...singleEntryGroundTruth,
      {
        file: "src/routes/account.js",
        lineStart: 11,
        lineEnd: 11,
        playbookId: "ai_security.authorization",
        vulnerabilityClass: "missing-authorization",
        description: "Refund route missing auth middleware.",
      },
    ];
    const result = scoreFindings(twoEntries, [makeFinding()]);
    expect(result.recall).toBe(0.5);
    expect(result.precision).toBe(1);
    expect(result.matched).toHaveLength(1);
    expect(result.missed).toHaveLength(1);
    expect(result.missed[0].file).toBe("src/routes/account.js");
  });

  it("applies +/-3 line tolerance when matching", () => {
    const nearMiss = makeFinding({
      evidence: [
        {
          file: "src/middleware/auth.js",
          lineStart: 13, // 2 lines past the seeded line 11, within tolerance
          lineEnd: 13,
          snippet: "next();",
        },
      ],
    });
    const result = scoreFindings(singleEntryGroundTruth, [nearMiss]);
    expect(result.matched).toHaveLength(1);
    expect(result.recall).toBe(1);
  });
});
