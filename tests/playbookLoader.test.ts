import { describe, expect, it } from "vitest";
import {
  loadPlaybookById,
  loadPlaybookFile,
  selectPlaybooks,
} from "../src/pipeline/playbookLoader.js";

describe("loadPlaybookFile", () => {
  it("parses the JWT playbook frontmatter and validates against the schema", () => {
    const pb = loadPlaybookFile("ai_security/jwt_authentication.md");
    expect(pb.frontmatter.id).toBe("ai_security.jwt_authentication");
    expect(pb.frontmatter.fileSelectionHint.roles).toContain("auth");
    expect(pb.frontmatter.severityHeuristics.critical.length).toBeGreaterThan(0);
    expect(pb.body).toContain("Root Cause Explanation");
  });

  it("throws a clear error for a missing playbook file", () => {
    expect(() => loadPlaybookFile("ai_security/does_not_exist.md")).toThrow();
  });
});

describe("selectPlaybooks — stack gating (hit the exact playbook, ignore the rest)", () => {
  it("always includes the universally-applicable baseline fundamentals", () => {
    const ids = selectPlaybooks([], "quick").map((v) => v.id);
    for (const id of [
      "ai_security.authorization",
      "ai_security.secrets_management",
      "ai_security.environment_secrets_exposure",
      "ai_security.cors_misconfiguration",
      "ai_security.webhook_verification",
      "ai_security.ssrf",
      "ai_security.command_injection",
      "ai_security.input_validation",
      "ai_security.session_management",
      "ai_security.logging_and_error_handling",
      "ai_security.path_traversal",
      "ai_security.open_redirect",
      "ai_security.security_headers",
      "ai_security.dependency_supply_chain",
      "ai_security.cryptographic_failures",
      "ai_mistakes.hallucinated_dependencies",
      "ai_mistakes.error_swallowing_and_fake_success",
      "ai_mistakes.destructive_operations_without_safeguards",
    ]) {
      expect(ids).toContain(id);
    }
  });

  it("loads race_conditions as a deepOnly universal baseline", () => {
    expect(selectPlaybooks([], "quick").map((v) => v.id)).not.toContain(
      "ai_security.race_conditions"
    );
    expect(selectPlaybooks([], "deep").map((v) => v.id)).toContain(
      "ai_security.race_conditions"
    );
  });

  it("does NOT load stack-conditional baseline playbooks when their stack is absent", () => {
    const ids = selectPlaybooks([], "deep").map((v) => v.id);
    // Each requires a matching tag; none are present for the empty stack.
    expect(ids).not.toContain("ai_security.jwt_authentication");
    expect(ids).not.toContain("ai_security.xss");
    expect(ids).not.toContain("ai_security.nosql_injection");
    expect(ids).not.toContain("ai_security.ssti");
    expect(ids).not.toContain("ai_security.csrf");
    expect(ids).not.toContain("ai_security.mass_assignment");
    expect(ids).not.toContain("ai_security.xxe");
  });

  it("loads ssti/csrf/mass_assignment for a matching web+ORM stack, but xxe only for xml-capable stacks", () => {
    const web = selectPlaybooks(["flask", "templating", "sql"], "deep").map((v) => v.id);
    expect(web).toContain("ai_security.ssti");
    expect(web).toContain("ai_security.csrf");
    expect(web).toContain("ai_security.mass_assignment");
    expect(web).not.toContain("ai_security.xxe"); // no java/dotnet/php/xml

    const java = selectPlaybooks(["java"], "deep").map((v) => v.id);
    expect(java).toContain("ai_security.xxe");

    const xmlStack = selectPlaybooks(["xml"], "deep").map((v) => v.id);
    expect(xmlStack).toContain("ai_security.xxe"); // entity-resolving parser → xml tag
  });

  it("loads jwt_authentication only when a JWT/auth-provider tag is present", () => {
    expect(selectPlaybooks(["jwt"], "quick").map((v) => v.id)).toContain(
      "ai_security.jwt_authentication"
    );
    expect(selectPlaybooks(["next-auth"], "quick").map((v) => v.id)).toContain(
      "ai_security.jwt_authentication"
    );
    expect(selectPlaybooks(["express"], "quick").map((v) => v.id)).not.toContain(
      "ai_security.jwt_authentication"
    );
  });

  it("loads xss only for a rendering stack", () => {
    expect(selectPlaybooks(["frontend"], "quick").map((v) => v.id)).toContain(
      "ai_security.xss"
    );
    expect(selectPlaybooks(["nextjs"], "quick").map((v) => v.id)).toContain(
      "ai_security.xss"
    );
    expect(selectPlaybooks(["postgres"], "quick").map((v) => v.id)).not.toContain(
      "ai_security.xss"
    );
  });

  it("loads sql_injection only when a relational database access tag is present", () => {
    expect(selectPlaybooks(["sql"], "quick").map((v) => v.id)).toContain(
      "ai_security.sql_injection"
    );
    expect(selectPlaybooks(["postgres"], "quick").map((v) => v.id)).toContain(
      "ai_security.sql_injection"
    );
    expect(selectPlaybooks([], "quick").map((v) => v.id)).not.toContain(
      "ai_security.sql_injection"
    );
  });

  it("loads nosql_injection only for a document store", () => {
    expect(selectPlaybooks(["mongodb"], "quick").map((v) => v.id)).toContain(
      "ai_security.nosql_injection"
    );
    expect(selectPlaybooks(["sql"], "quick").map((v) => v.id)).not.toContain(
      "ai_security.nosql_injection"
    );
  });

  it("includes the Express technology playbook when the express tag is detected", () => {
    const views = selectPlaybooks(["express"], "quick");
    expect(views.some((v) => v.id === "technology.express.middleware_and_routing")).toBe(true);
  });

  it("loads the newly authored nextjs api_routes playbook when nextjs is detected", () => {
    const ids = selectPlaybooks(["nextjs"], "quick").map((v) => v.id);
    expect(ids).toContain("technology.nextjs.auth_and_middleware");
    expect(ids).toContain("technology.nextjs.api_routes");
  });

  it("skips registry playbook paths that don't exist on disk, without erroring", () => {
    // The registry may reference not-yet-authored playbooks; selection skips
    // missing files rather than crashing the scan.
    expect(() => selectPlaybooks(["nextjs", "sql", "kubernetes"], "deep")).not.toThrow();
  });
});

describe("selectPlaybooks — rendering & mode", () => {
  it("ships only the short quick_mode_summary inline in BOTH modes (body is lazy-fetched)", () => {
    const quick = selectPlaybooks(["jwt"], "quick").find(
      (v) => v.id === "ai_security.jwt_authentication"
    )!;
    const deep = selectPlaybooks(["jwt"], "deep").find(
      (v) => v.id === "ai_security.jwt_authentication"
    )!;
    expect(quick.renderedContent).not.toContain("Root Cause Explanation");
    expect(deep.renderedContent).not.toContain("Root Cause Explanation");
    expect(deep.renderedContent).toBe(quick.renderedContent);
  });

  it("includes the deepOnly ai_mistakes playbooks in deep mode but not quick mode", () => {
    const quickIds = selectPlaybooks([], "quick").map((v) => v.id);
    const deepIds = selectPlaybooks([], "deep").map((v) => v.id);
    for (const id of [
      "ai_mistakes.test_manipulation_to_pass",
      "ai_mistakes.logic_duplication_and_drift",
      "ai_mistakes.unrequested_scope_creep",
    ]) {
      expect(quickIds).not.toContain(id);
      expect(deepIds).toContain(id);
    }
  });

  it("excludes the deep_only business_logic playbook in quick mode but includes it in deep mode", () => {
    const quickIds = selectPlaybooks([], "quick").map((v) => v.id);
    const deepIds = selectPlaybooks([], "deep").map((v) => v.id);
    expect(quickIds).not.toContain("ai_security.business_logic");
    expect(deepIds).toContain("ai_security.business_logic");
  });

  it("resolves tag-gated technology playbooks only for their matching tag", () => {
    const deepAllTags = selectPlaybooks(
      [
        "supabase", "firebase", "clerk", "nextjs", "trpc", "graphql", "stripe", "prisma",
        "llm-api", "upstash", "file-upload", "flask", "django", "rails", "laravel", "go",
        "astro", "sveltekit", "remix", "nuxt", "drizzle", "mongodb", "realtime",
        "background-jobs", "expo", "docker", "vercel", "github-actions", "email",
        "nestjs", "fastify", "java", "dotnet", "kubernetes", "terraform", "serverless", "sql",
      ],
      "deep"
    );
    const ids = deepAllTags.map((v) => v.id);
    for (const id of [
      "technology.supabase.row_level_security",
      "technology.stripe.webhook_and_payment_safety",
      "ai_security.ai_llm_api_security",
      "ai_security.rate_limiting",
      "ai_security.file_uploads",
      "ai_security.sql_injection",
      "technology.nestjs.security",
      "technology.fastify.security",
      "technology.java_spring.security",
      "technology.dotnet.aspnet_core_security",
      "technology.kubernetes.workload_security",
      "technology.terraform.iac_security",
      "technology.serverless.lambda_security",
      "technology.email.transactional_email_security",
    ]) {
      expect(ids).toContain(id);
    }

    const untagged = selectPlaybooks([], "quick").map((v) => v.id);
    expect(untagged).not.toContain("technology.supabase.row_level_security");
    expect(untagged).not.toContain("ai_security.ai_llm_api_security");
    expect(untagged).not.toContain("technology.nestjs.security");
  });
});

describe("loadPlaybookById", () => {
  it("resolves a playbook by its frontmatter id", () => {
    const pb = loadPlaybookById("ai_security.sql_injection");
    expect(pb).not.toBeNull();
    expect(pb!.frontmatter.title).toBe("SQL Injection");
    expect(pb!.body).toContain("Root Cause Explanation");
  });

  it("returns null for an unknown id", () => {
    expect(loadPlaybookById("ai_security.not_a_real_playbook")).toBeNull();
  });
});
