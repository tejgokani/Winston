import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  detectTechnology,
  playbooksForTags,
} from "../src/pipeline/techDetector.js";

const EXPRESS_FIXTURE = fileURLToPath(
  new URL("./fixtures/sample-repos/express-fixture", import.meta.url)
);
const NEXTJS_FIXTURE = fileURLToPath(
  new URL("./fixtures/sample-repos/nextjs-fixture", import.meta.url)
);

describe("detectTechnology", () => {
  it("detects Express + JWT from package.json dependencies", () => {
    const profile = detectTechnology(EXPRESS_FIXTURE);
    expect(profile.frameworks).toContain("express");
    expect(profile.authProviders).toContain("jwt");
    expect(profile.detectedTags).toEqual(
      expect.arrayContaining(["express", "jwt"])
    );
  });

  it("detects Next.js + next-auth from package.json dependencies", () => {
    const profile = detectTechnology(NEXTJS_FIXTURE);
    expect(profile.frameworks).toContain("nextjs");
    expect(profile.authProviders).toContain("next-auth");
  });

  it("does not detect unrelated technologies", () => {
    const profile = detectTechnology(EXPRESS_FIXTURE);
    expect(profile.paymentProviders).toEqual([]);
    expect(profile.frameworks).not.toContain("nextjs");
  });
});

describe("detectTechnology — monorepo & extension detection", () => {
  let repo: string;
  beforeEach(() => {
    repo = mkdtempSync(join(tmpdir(), "winston-detect-"));
  });
  afterEach(() => rmSync(repo, { recursive: true, force: true }));

  it("detects a framework from a nested workspace manifest (apps/web/package.json)", () => {
    mkdirSync(join(repo, "apps", "web"), { recursive: true });
    writeFileSync(
      join(repo, "package.json"),
      JSON.stringify({ workspaces: ["apps/*"] })
    );
    writeFileSync(
      join(repo, "apps", "web", "package.json"),
      JSON.stringify({ dependencies: { next: "^15.0.0", pg: "^8.0.0" } })
    );
    const profile = detectTechnology(repo);
    expect(profile.frameworks).toContain("nextjs");
    expect(profile.detectedTags).toContain("postgres"); // pg → postgres tag
  });

  it("detects a stack from a file extension (Terraform .tf, .NET .csproj)", () => {
    mkdirSync(join(repo, "infra"), { recursive: true });
    writeFileSync(join(repo, "infra", "main.tf"), 'resource "aws_s3_bucket" "b" {}');
    mkdirSync(join(repo, "svc"), { recursive: true });
    writeFileSync(join(repo, "svc", "Api.csproj"), "<Project></Project>");
    const profile = detectTechnology(repo);
    expect(profile.detectedTags).toContain("terraform");
    expect(profile.detectedTags).toContain("dotnet");
  });

  it("does not descend into node_modules / build output", () => {
    mkdirSync(join(repo, "node_modules", "evil"), { recursive: true });
    writeFileSync(
      join(repo, "node_modules", "evil", "package.json"),
      JSON.stringify({ dependencies: { rails: "^7.0.0" } })
    );
    const profile = detectTechnology(repo);
    expect(profile.detectedTags).not.toContain("rails");
  });
});

describe("playbooksForTags", () => {
  it("resolves playbook paths for detected tags", () => {
    const playbooks = playbooksForTags(["jwt", "express"]);
    expect(playbooks).toContain("ai_security/jwt_authentication.md");
    expect(playbooks).toContain("technology/express/middleware_and_routing.md");
  });

  it("returns an empty list for unmatched tags", () => {
    expect(playbooksForTags(["nonexistent-tag"])).toEqual([]);
  });
});
