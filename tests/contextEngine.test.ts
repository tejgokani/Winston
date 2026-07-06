import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  buildArchitectureSummaryProse,
  buildSecurityAssumptions,
  buildSecurityContext,
  QUICK_MODE_BYTE_BUDGET,
  selectFilesForContext,
} from "../src/pipeline/contextEngine.js";
import type { PlaybookPromptView } from "../src/models/playbook.js";
import { scanRepository } from "../src/pipeline/scanner.js";
import { detectTechnology } from "../src/pipeline/techDetector.js";

const EXPRESS_FIXTURE = fileURLToPath(
  new URL("./fixtures/sample-repos/express-fixture", import.meta.url)
);

const authPlaybookView: PlaybookPromptView = {
  id: "ai_security.jwt_authentication",
  title: "JWT Authentication",
  reviewPass: 1,
  fileSelectionHint: {
    roles: ["auth", "middleware"],
    matchImports: ["jsonwebtoken"],
    matchAuthMapTags: ["jwt"],
    maxFiles: 8,
    priorityOrder: ["auth", "middleware"],
  },
  renderedContent: "stub playbook content",
};

describe("selectFilesForContext", () => {
  it("includes only files matching playbook-hinted roles, excluding noise files", () => {
    const summary = scanRepository(EXPRESS_FIXTURE);
    const refs = selectFilesForContext(summary, [authPlaybookView], QUICK_MODE_BYTE_BUDGET);

    const paths = refs.map((r) => r.path);
    expect(paths).toContain("src/middleware/auth.js");
    expect(paths).not.toContain("src/utils/formatDate.js");
    expect(paths).not.toContain("src/utils/stringHelpers.js");
  });

  it("falls back to top-relevance files across all roles when no hints given", () => {
    const summary = scanRepository(EXPRESS_FIXTURE);
    const refs = selectFilesForContext(summary, [], QUICK_MODE_BYTE_BUDGET);
    expect(refs.length).toBeGreaterThan(0);
  });

  it("never exceeds the given byte budget", () => {
    const summary = scanRepository(EXPRESS_FIXTURE);
    const tinyBudget = 50;
    const refs = selectFilesForContext(summary, [authPlaybookView], tinyBudget);

    const totalBytes = refs.reduce((sum, r) => sum + Buffer.byteLength(r.content), 0);
    expect(totalBytes).toBeLessThanOrEqual(tinyBudget);
  });

  it("marks a file truncated when it doesn't fully fit the remaining budget", () => {
    const summary = scanRepository(EXPRESS_FIXTURE);
    const tinyBudget = 50;
    const refs = selectFilesForContext(summary, [authPlaybookView], tinyBudget);
    expect(refs.some((r) => r.truncated)).toBe(true);
  });
});

describe("selectFilesForContext — import-based matching", () => {
  let repo: string;
  beforeEach(() => {
    repo = mkdtempSync(join(tmpdir(), "winston-import-match-"));
  });
  afterEach(() => rmSync(repo, { recursive: true, force: true }));

  it("selects a file with no role match purely via a matchImports hit", () => {
    // "src/lib/aiClient.ts" hits none of scanner.ts's ROLE_RULES (no auth/
    // payment/upload/database/middleware/config/route keywords), so it
    // classifies as "generic" — but it imports "openai", which an AI/ML
    // playbook's fileSelectionHint.matchImports would list.
    mkdirSync(join(repo, "src", "lib"), { recursive: true });
    writeFileSync(
      join(repo, "src", "lib", "aiClient.ts"),
      "import OpenAI from 'openai';\nexport const client = new OpenAI();\n"
    );
    writeFileSync(
      join(repo, "src", "lib", "unrelated.ts"),
      "export function noop() { return 1; }\n"
    );

    const aiPlaybookView: PlaybookPromptView = {
      id: "technology.ai_ml.prompt_injection",
      title: "Prompt Injection",
      reviewPass: 1,
      fileSelectionHint: {
        roles: ["auth"], // deliberately a role this repo has no files for
        matchImports: ["openai"],
        matchAuthMapTags: [],
        maxFiles: 8,
        priorityOrder: [],
      },
      renderedContent: "stub playbook content",
    };

    const summary = scanRepository(repo);
    const aiClientFile = summary.importantFiles.find((f) => f.path === "src/lib/aiClient.ts");
    expect(aiClientFile?.role).toBe("generic");

    const refs = selectFilesForContext(summary, [aiPlaybookView], QUICK_MODE_BYTE_BUDGET);
    const paths = refs.map((r) => r.path);
    expect(paths).toContain("src/lib/aiClient.ts");
    expect(paths).not.toContain("src/lib/unrelated.ts");
  });
});

describe("buildArchitectureSummaryProse", () => {
  it("reports unprotected routes distinctly from protected ones", () => {
    const summary = scanRepository(EXPRESS_FIXTURE);
    const prose = buildArchitectureSummaryProse(summary);
    expect(prose).toMatch(/\d+ route\(s\) detected/);
    expect(prose).toMatch(/1 appear to have a middleware chain/);
  });
});

describe("buildSecurityAssumptions", () => {
  it("hedges unverified claims rather than asserting vulnerabilities", () => {
    const summary = scanRepository(EXPRESS_FIXTURE);
    const assumptions = buildSecurityAssumptions(summary);
    expect(assumptions.some((a) => a.includes("unverified"))).toBe(true);
  });
});

describe("buildSecurityContext", () => {
  it("assembles a full payload within budget for quick mode", () => {
    const summary = scanRepository(EXPRESS_FIXTURE);
    const techProfile = detectTechnology(EXPRESS_FIXTURE);
    const payload = buildSecurityContext({
      repoSummary: summary,
      techProfile,
      playbookViews: [authPlaybookView],
      mode: "quick",
    });

    expect(payload.byteBudget.used).toBeLessThanOrEqual(payload.byteBudget.limit);
    expect(payload.playbookIds).toEqual(["ai_security.jwt_authentication"]);
    expect(payload.dependencySummary.some((d) => d.name === "jwt")).toBe(true);
  });
});
