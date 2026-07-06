import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { setGraphStorageBaseDir } from "../src/storage/graphStore.js";
import { setStorageBaseDir } from "../src/storage/scanStore.js";
import { auditRepository } from "../src/tools/auditRepository.js";
import { submitFindings } from "../src/tools/submitFindings.js";
import { checkSuppressed, parseSuppressionFile } from "../src/suppress/suppressions.js";
import { verifyFindingEvidence } from "../src/verify/evidence.js";
import type { Finding } from "../src/models/findings.js";

const EXPRESS_FIXTURE = fileURLToPath(
  new URL("./fixtures/sample-repos/express-fixture", import.meta.url)
);

function finding(over: Partial<Finding> = {}): Finding {
  return {
    playbookId: "ai_security.jwt_authentication",
    vulnerabilityClass: "broken_authentication",
    title: "JWT missing algorithm allow-list",
    severity: "critical",
    description: "d",
    reasoning: "r",
    evidence: [
      { file: "src/middleware/auth.js", lineStart: 11, lineEnd: 11, snippet: "jwt.verify(token, SECRET)" },
    ],
    attackScenario: "s",
    affectedFiles: ["src/middleware/auth.js"],
    recommendedFix: "fix",
    aiFixPrompt: "p",
    graphNode: { type: "vulnerability", idHint: "finding:x", label: "x" },
    graphEdges: [{ targetIdHint: "component:jwt", relation: "causes", description: "rc" }],
    confidence: "high",
    ...over,
  };
}

describe("evidence verification", () => {
  it("verifies a finding whose snippet actually appears in the cited file", () => {
    expect(verifyFindingEvidence(finding(), EXPRESS_FIXTURE).verified).toBe(true);
  });

  it("rejects a finding whose quoted code does not exist in the file (hallucinated evidence)", () => {
    const bogus = finding({
      evidence: [
        { file: "src/middleware/auth.js", lineStart: 5, lineEnd: 5, snippet: "dangerouslyRunUserSql(totallyMadeUp)" },
      ],
    });
    expect(verifyFindingEvidence(bogus, EXPRESS_FIXTURE).verified).toBe(false);
  });
});

describe("suppression parsing + matching", () => {
  it("parses playbook-id, path, and combined rules, ignoring comments", () => {
    const rules = parseSuppressionFile(
      ["# comment", "ai_security.xss", "src/legacy/**", "ai_security.jwt_authentication src/auth/*.js", ""].join("\n")
    );
    expect(rules).toHaveLength(3);
    expect(rules[0].playbookId).toBe("ai_security.xss");
    expect(rules[1].pathPattern).toBe("src/legacy/**");
    expect(rules[2].playbookId).toBe("ai_security.jwt_authentication");
    expect(rules[2].pathPattern).toBe("src/auth/*.js");
  });

  it("suppresses by playbook id and by path glob", () => {
    const byId = parseSuppressionFile("ai_security.jwt_authentication");
    expect(checkSuppressed(finding(), byId, EXPRESS_FIXTURE).suppressed).toBe(true);

    const byPath = parseSuppressionFile("src/middleware/**");
    expect(checkSuppressed(finding(), byPath, EXPRESS_FIXTURE).suppressed).toBe(true);

    const noMatch = parseSuppressionFile("ai_security.xss src/other/**");
    expect(checkSuppressed(finding(), noMatch, EXPRESS_FIXTURE).suppressed).toBe(false);
  });
});

describe("submit_findings integration with the FP gates", () => {
  let dir: string;
  let repo: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "winston-fp-"));
    setStorageBaseDir(dir);
    setGraphStorageBaseDir(dir);
    repo = mkdtempSync(join(tmpdir(), "winston-fp-repo-"));
    writeFileSync(join(repo, "package.json"), JSON.stringify({ dependencies: { jsonwebtoken: "^9" } }));
    writeFileSync(
      join(repo, "auth.js"),
      "const jwt=require('jsonwebtoken');\nreq.user = jwt.verify(token, SECRET);\n"
    );
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    rmSync(repo, { recursive: true, force: true });
  });

  it("drops a fabricated-evidence finding as unverified, not into the graph", () => {
    const audit = auditRepository({ repoPath: repo, mode: "quick" });
    const res = submitFindings({
      scanId: audit.scanId,
      findings: [
        finding({ affectedFiles: ["auth.js"], evidence: [{ file: "auth.js", lineStart: 2, lineEnd: 2, snippet: "jwt.verify(token, SECRET)" }] }),
        finding({ title: "Fake", affectedFiles: ["auth.js"], graphNode: { type: "vulnerability", idHint: "finding:fake", label: "Fake" }, evidence: [{ file: "auth.js", lineStart: 1, lineEnd: 1, snippet: "eval(userInput123)" }] }),
      ],
    });
    expect(res.acceptedCount).toBe(1);
    expect(res.unverified?.length).toBe(1);
    expect(res.unverified?.[0].finding).toBe("Fake");
  });

  it("suppresses a finding matched by .winston-ignore", () => {
    writeFileSync(join(repo, ".winston-ignore"), "ai_security.jwt_authentication\n");
    const audit = auditRepository({ repoPath: repo, mode: "quick" });
    const res = submitFindings({
      scanId: audit.scanId,
      findings: [
        finding({ affectedFiles: ["auth.js"], evidence: [{ file: "auth.js", lineStart: 2, lineEnd: 2, snippet: "jwt.verify(token, SECRET)" }] }),
      ],
    });
    expect(res.acceptedCount).toBe(0);
    expect(res.suppressed?.length).toBe(1);
  });
});
