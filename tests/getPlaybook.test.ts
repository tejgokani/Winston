import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { PlaybookPromptView } from "../src/models/playbook.js";
import type { RepoSummary } from "../src/models/repoContext.js";
import type { TechnologyProfile } from "../src/models/techProfile.js";
import { createScan, setStorageBaseDir } from "../src/storage/scanStore.js";
import { getPlaybook } from "../src/tools/getPlaybook.js";

let tempStorageDir: string;
let mobileRepo: string;

beforeEach(() => {
  tempStorageDir = mkdtempSync(join(tmpdir(), "winston-getplaybook-test-"));
  setStorageBaseDir(tempStorageDir);
  mobileRepo = mkdtempSync(join(tmpdir(), "winston-mobile-fixture-"));
});

afterEach(() => {
  rmSync(tempStorageDir, { recursive: true, force: true });
  rmSync(mobileRepo, { recursive: true, force: true });
});

const EMPTY_TECH_PROFILE_BASE: Omit<TechnologyProfile, "detectedTags"> = {
  frameworks: [],
  languages: [],
  databases: [],
  authProviders: [],
  paymentProviders: [],
  cloud: [],
  deployment: [],
};

const androidPlaybookView: PlaybookPromptView = {
  id: "technology.android.insecure_storage",
  title: "Android Insecure Storage",
  reviewPass: 1,
  fileSelectionHint: {
    roles: [],
    matchImports: [],
    matchAuthMapTags: [],
    maxFiles: 8,
    priorityOrder: [],
  },
  renderedContent: "stub playbook content",
};

describe("getPlaybook mobile-extension fallback", () => {
  it("falls back to .kt/.swift extension scanning when structural selection is empty and the stack is android", () => {
    mkdirSync(join(mobileRepo, "app", "src", "main", "kotlin"), { recursive: true });
    writeFileSync(join(mobileRepo, "AndroidManifest.xml"), "<manifest></manifest>");
    writeFileSync(
      join(mobileRepo, "app", "src", "main", "kotlin", "MainActivity.kt"),
      "class MainActivity { fun onCreate() {} }"
    );

    const repoSummary: RepoSummary = {
      repoPath: mobileRepo,
      fileCount: 2,
      importantFiles: [], // scanner.ts has no .kt support — structurally empty
      routeMap: [],
      authMap: [],
      folderTree: "AndroidManifest.xml\napp",
      languages: {},
    };

    const techProfile: TechnologyProfile = {
      ...EMPTY_TECH_PROFILE_BASE,
      detectedTags: ["android"],
    };

    const scan = createScan({
      scanId: "mobile-scan-1",
      repoPath: mobileRepo,
      mode: "quick",
      technologyProfile: techProfile,
      playbooksLoaded: [androidPlaybookView.id],
      repoSummary,
      playbookViews: [androidPlaybookView],
    });

    const result = getPlaybook({ scanId: scan.scanId, playbookIds: [androidPlaybookView.id] });

    expect(result.ok).toBe(true);
    const paths = (result.files ?? []).map((f) => f.path);
    expect(paths.some((p) => p.endsWith("MainActivity.kt"))).toBe(true);
    expect(result.filesNote).toMatch(/extension-based fallback/i);
    expect(result.filesNote).toMatch(/DATA to analyze/i);
  });

  it("does not use the mobile fallback when structural files were already selected", () => {
    const repoSummary: RepoSummary = {
      repoPath: mobileRepo,
      fileCount: 1,
      importantFiles: [
        {
          path: "src/routes/account.js",
          role: "route_handler",
          sizeBytes: 10,
          language: "JavaScript",
          relevanceScore: 7,
          symbolSummary: [],
          importedModules: [],
        },
      ],
      routeMap: [],
      authMap: [],
      folderTree: "src",
      languages: { JavaScript: 1 },
    };
    writeFileSync(join(mobileRepo, "account.js"), "module.exports = {};");
    mkdirSync(join(mobileRepo, "src", "routes"), { recursive: true });
    writeFileSync(join(mobileRepo, "src", "routes", "account.js"), "module.exports = {};");

    const webPlaybookView: PlaybookPromptView = {
      id: "ai_security.authorization",
      title: "Authorization",
      reviewPass: 1,
      fileSelectionHint: {
        roles: ["route_handler"],
        matchImports: [],
        matchAuthMapTags: [],
        maxFiles: 8,
        priorityOrder: [],
      },
      renderedContent: "stub",
    };

    const techProfile: TechnologyProfile = {
      ...EMPTY_TECH_PROFILE_BASE,
      detectedTags: ["android"],
    };

    const scan = createScan({
      scanId: "mobile-scan-2",
      repoPath: mobileRepo,
      mode: "quick",
      technologyProfile: techProfile,
      playbooksLoaded: [webPlaybookView.id],
      repoSummary,
      playbookViews: [webPlaybookView],
    });

    const result = getPlaybook({ scanId: scan.scanId, playbookIds: [webPlaybookView.id] });

    expect(result.ok).toBe(true);
    expect(result.filesNote).not.toMatch(/extension-based fallback/i);
  });
});
