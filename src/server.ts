#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { auditRepository } from "./tools/auditRepository.js";
import { coverageReport } from "./tools/coverageReport.js";
import { detectTooling } from "./tools/detectTooling.js";
import { generateReportTool } from "./tools/generateReport.js";
import { getGraph } from "./tools/getGraph.js";
import { getPlaybook } from "./tools/getPlaybook.js";
import { launchUi } from "./tools/launchUi.js";
import { scanSecretsTool } from "./tools/scanSecrets.js";
import { verifyFix } from "./tools/verifyFix.js";
import { listScans } from "./tools/listScans.js";
import { submitFindings } from "./tools/submitFindings.js";

const server = new McpServer({
  name: "winston",
  version: "0.1.0",
});

server.registerTool(
  "ping",
  {
    description: "Health check for the Winston MCP server.",
    inputSchema: { message: z.string().optional() },
  },
  async ({ message }) => ({
    content: [{ type: "text", text: `pong${message ? `: ${message}` : ""}` }],
  })
);

server.registerTool(
  "audit_repository",
  {
    description:
      "Scan a repository, detect its technology stack, load applicable security " +
      "playbooks, and return structured context for the calling agent to reason " +
      "over. Does not perform the review itself — call submit_findings next with " +
      "your findings.",
    inputSchema: {
      repoPath: z.string().describe("Absolute path to the repository to audit"),
      mode: z.enum(["quick", "deep"]).default("quick"),
      diffBase: z
        .string()
        .optional()
        .describe(
          "Optional git ref (branch/commit) to scope the audit to changed files only, e.g. \"main\" or \"HEAD~1\""
        ),
    },
  },
  async ({ repoPath, mode, diffBase }) => {
    const result = auditRepository({ repoPath, mode, diffBase });
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  }
);

server.registerTool(
  "submit_findings",
  {
    description:
      "Submit structured security findings for a scan started via audit_repository. " +
      "Findings must match the Finding schema described in that tool's response.",
    inputSchema: {
      scanId: z.string(),
      findings: z.array(z.record(z.string(), z.unknown())),
    },
  },
  async ({ scanId, findings }) => {
    const result = submitFindings({ scanId, findings });
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  }
);

server.registerTool(
  "get_playbook",
  {
    description:
      "Fetch the full methodology body of one or more playbooks selected for a " +
      "scan (deep mode works pass-by-pass: fetch a pass's playbooks, apply them, " +
      "then fetch the next pass). Only playbooks matched to the repository's " +
      "detected stack can be fetched — anything else returns a hard error.",
    inputSchema: {
      scanId: z.string(),
      playbookIds: z
        .array(z.string())
        .min(1)
        .describe("Playbook ids as listed in audit_repository's playbooksLoaded"),
    },
  },
  async ({ scanId, playbookIds }) => {
    const result = getPlaybook({ scanId, playbookIds });
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  }
);

server.registerTool(
  "scan_secrets",
  {
    description:
      "Deterministic (no-LLM) scan for hardcoded secrets — API keys, tokens, private " +
      "keys, high-entropy credential assignments. Fast pre-audit gate; results are " +
      "redacted. Respects .winston-ignore inline markers.",
    inputSchema: {
      repoPath: z.string().describe("Absolute path to the repository to scan"),
    },
  },
  async ({ repoPath }) => ({
    content: [{ type: "text", text: JSON.stringify(scanSecretsTool({ repoPath }), null, 2) }],
  })
);

server.registerTool(
  "detect_ai_tooling",
  {
    description:
      "Detect which AI coding tools were plausibly used in a repository, from git " +
      "commit trailers/messages and config artifacts — no LLM, no per-file " +
      "authorship claims. Returns heuristic signals with confidence levels, not " +
      "proof. Useful as a pre-audit step to understand how the code was produced.",
    inputSchema: {
      repoPath: z.string().describe("Absolute path to the repository to inspect"),
    },
  },
  async ({ repoPath }) => ({
    content: [{ type: "text", text: JSON.stringify(detectTooling({ repoPath }), null, 2) }],
  })
);

server.registerTool(
  "generate_graph",
  {
    description:
      "Return or refresh the threat graph for a repository without re-running a review.",
    inputSchema: {
      repoPath: z.string(),
      format: z.enum(["json", "summary"]).default("summary"),
    },
  },
  async ({ repoPath, format }) => {
    const result = getGraph({ repoPath, format });
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  }
);

server.registerTool(
  "verify_fix",
  {
    description:
      "Deterministically verify a fix: re-reads the repo and checks whether the " +
      "vulnerable code cited in a finding's evidence is gone. If so, marks the graph " +
      "node fixed (with proof); if not, returns still_open plus the fix prompt to apply. " +
      "findingId is the vulnerability node id from the graph.",
    inputSchema: {
      scanId: z.string(),
      findingId: z.string(),
    },
  },
  async ({ scanId, findingId }) => ({
    content: [{ type: "text", text: JSON.stringify(verifyFix({ scanId, findingId }), null, 2) }],
  })
);

server.registerTool(
  "generate_report",
  {
    description:
      "Export the threat graph and findings for a scan as Markdown, HTML, JSON, or " +
      "SARIF (for GitHub Code Scanning / CI). Pure rendering — reports are exports of " +
      "the graph, not a new review.",
    inputSchema: {
      scanId: z.string(),
      format: z.enum(["markdown", "html", "json", "sarif"]).default("markdown"),
    },
  },
  async ({ scanId, format }) => {
    const result = generateReportTool({ scanId, format });
    return {
      content: [
        {
          type: "text",
          text: result.ok ? result.content! : JSON.stringify(result, null, 2),
        },
      ],
    };
  }
);

server.registerTool(
  "launch_ui",
  {
    description:
      "Launch (or return the URL of an already-running) local web UI showing the " +
      "interactive threat graph. No auto-open — MCP has no browser primitive.",
    inputSchema: {
      repoPath: z.string().optional(),
      port: z.number().int().positive().default(8787),
    },
  },
  async ({ repoPath, port }) => {
    const result = launchUi({ repoPath, port });
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  }
);

server.registerTool(
  "coverage_report",
  {
    description:
      "Report what this scan actually reviewed vs. what it selected: which playbooks " +
      "were executed, which were selected but never run (unreviewed areas), and the " +
      "files pulled for review. Honest coverage — surfaces gaps, doesn't hide them.",
    inputSchema: { scanId: z.string() },
  },
  async ({ scanId }) => ({
    content: [{ type: "text", text: JSON.stringify(coverageReport({ scanId }), null, 2) }],
  })
);

server.registerTool(
  "list_scans",
  {
    description:
      "List scan history, optionally filtered by repository, with the risk-score " +
      "delta versus the previous scan so you can watch the attack surface evolve.",
    inputSchema: {
      repoPath: z.string().optional(),
      limit: z.number().int().positive().default(10),
    },
  },
  async ({ repoPath, limit }) => {
    const result = listScans({ repoPath, limit });
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error("Winston MCP server failed to start:", error);
  process.exit(1);
});
