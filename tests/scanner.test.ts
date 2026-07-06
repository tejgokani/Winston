import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { scanRepository } from "../src/pipeline/scanner.js";

const EXPRESS_FIXTURE = fileURLToPath(
  new URL("./fixtures/sample-repos/express-fixture", import.meta.url)
);
const NEXTJS_FIXTURE = fileURLToPath(
  new URL("./fixtures/sample-repos/nextjs-fixture", import.meta.url)
);

describe("scanRepository", () => {
  it("builds a route map from Express route decorators", () => {
    const summary = scanRepository(EXPRESS_FIXTURE);

    const paths = summary.routeMap.map((r) => `${r.method} ${r.path}`);
    expect(paths).toContain("GET /billing/:userId");
    expect(paths).toContain("POST /billing/:userId/refund");
  });

  it("captures a leading middleware identifier into the route's middlewareChain", () => {
    const summary = scanRepository(EXPRESS_FIXTURE);

    const protectedRoute = summary.routeMap.find((r) => r.path === "/billing/:userId");
    expect(protectedRoute?.middlewareChain).toContain("requireAuth");

    const unprotectedRoute = summary.routeMap.find(
      (r) => r.path === "/billing/:userId/refund"
    );
    expect(unprotectedRoute?.middlewareChain).toEqual([]);
  });

  it("flags auth-related files into the auth map via import matching", () => {
    const summary = scanRepository(EXPRESS_FIXTURE);

    const authFiles = summary.authMap.map((a) => a.file);
    expect(authFiles).toContain("src/middleware/auth.js");
    expect(summary.authMap.some((a) => a.matchedPattern === "jsonwebtoken")).toBe(
      true
    );
  });

  it("classifies file roles correctly", () => {
    const summary = scanRepository(EXPRESS_FIXTURE);

    const authFile = summary.importantFiles.find(
      (f) => f.path === "src/middleware/auth.js"
    );
    expect(authFile?.role).toBe("auth");

    const routeFile = summary.importantFiles.find(
      (f) => f.path === "src/routes/account.js"
    );
    expect(routeFile?.role).toBe("route_handler");
  });

  it("caps important files at 150 and ranks by relevance", () => {
    const summary = scanRepository(EXPRESS_FIXTURE);
    expect(summary.importantFiles.length).toBeLessThanOrEqual(150);
    for (let i = 1; i < summary.importantFiles.length; i++) {
      expect(summary.importantFiles[i - 1].relevanceScore).toBeGreaterThanOrEqual(
        summary.importantFiles[i].relevanceScore
      );
    }
  });

  it("scans a Next.js fixture without error and records languages", () => {
    const summary = scanRepository(NEXTJS_FIXTURE);
    expect(summary.fileCount).toBeGreaterThan(0);
    expect(Object.keys(summary.languages)).toContain("JavaScript");
  });

  it("excludes ignored directories like node_modules from the scan", () => {
    const summary = scanRepository(EXPRESS_FIXTURE);
    expect(summary.importantFiles.every((f) => !f.path.includes("node_modules"))).toBe(
      true
    );
  });
});
