#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { detectAiTooling } from "./detect/aiTooling.js";
import { scanSecrets } from "./detect/secrets.js";
import { coverageReport } from "./tools/coverageReport.js";
import { generateReportTool } from "./tools/generateReport.js";
import { getGraph } from "./tools/getGraph.js";
import { groundTruth } from "./eval/groundTruth.js";
import { scoreFindings } from "./eval/scorer.js";
import type { Finding } from "./models/findings.js";

// Winston CLI — the deterministic + export surface for CI. The LLM-driven audit
// runs through an MCP-capable agent (see the GitHub Action); this CLI covers
// the no-LLM checks (secrets, tooling) and exporting results (SARIF/report) so
// a pipeline can gate on them without an agent in the loop.

// Printed to stderr (never stdout) so it brands the CLI without corrupting
// piped machine output like `winston report --format sarif > out.sarif`.
const BANNER = [
  "██╗    ██╗██╗███╗   ██╗███████╗████████╗ ██████╗ ███╗   ██╗",
  "██║    ██║██║████╗  ██║██╔════╝╚══██╔══╝██╔═══██╗████╗  ██║",
  "██║ █╗ ██║██║██╔██╗ ██║███████╗   ██║   ██║   ██║██╔██╗ ██║",
  "██║███╗██║██║██║╚██╗██║╚════██║   ██║   ██║   ██║██║╚██╗██║",
  "╚███╔███╔╝██║██║ ╚████║███████║   ██║   ╚██████╔╝██║ ╚████║",
  " ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝",
  "        AI security auditing — the interactive threat graph",
].join("\n");

function banner(): void {
  process.stderr.write(BANNER + "\n\n");
}

const [, , cmd, ...rest] = process.argv;

function flag(name: string, def?: string): string | undefined {
  const i = rest.indexOf(`--${name}`);
  return i !== -1 && rest[i + 1] ? rest[i + 1] : def;
}
function positional(): string {
  return rest.find((a) => !a.startsWith("--")) ?? process.cwd();
}

function usage(): never {
  banner();
  console.log(
    [
      "Winston — security auditing CLI",
      "",
      "Usage:",
      "  winston secrets [path]                 Deterministic secret scan (exit 1 on high-confidence hits)",
      "  winston detect  [path]                 Detect AI coding tooling (git + config artifacts)",
      "  winston graph   [path]                 Print the threat-graph summary (incl. the crown)",
      "  winston report  --scan <id> [--format markdown|json|sarif|html] [--out <file>]",
      "  winston coverage --scan <id>           What was reviewed vs. selected",
      "  winston eval <fixturePath> --findings <findingsJsonPath>",
      "                                          Score submitted findings against seeded ground truth",
      "",
      "The full LLM audit runs via an MCP agent — see the GitHub Action in the README.",
    ].join("\n")
  );
  process.exit(cmd ? 0 : 1);
}

function main() {
  // Brand human-facing commands on stderr; machine-output commands (report,
  // graph, coverage) stay clean for piping.
  if (cmd === "secrets" || cmd === "detect" || cmd === "eval") banner();
  switch (cmd) {
    case "secrets": {
      const path = resolve(positional());
      const report = scanSecrets(path);
      const high = report.findings.filter((f) => f.confidence === "high");
      console.log(`Scanned ${report.filesScanned} files. ${report.findings.length} potential secret(s).`);
      for (const f of report.findings) {
        console.log(`  [${f.confidence}] ${f.type} — ${f.file}:${f.line} (${f.redacted})`);
      }
      if (high.length > 0) {
        console.error(`\n${high.length} high-confidence secret(s) found — failing.`);
        process.exit(1);
      }
      break;
    }
    case "detect": {
      const report = detectAiTooling(resolve(positional()));
      if (report.detectedTools.length === 0) console.log("No AI-tooling signals found.");
      else for (const t of report.detectedTools) console.log(`  ${t.tool} [${t.confidence}]`);
      console.log(`\n${report.disclaimer}`);
      break;
    }
    case "graph": {
      const summary = getGraph({ repoPath: resolve(positional()), format: "summary" });
      console.log(JSON.stringify(summary, null, 2));
      break;
    }
    case "report": {
      const scan = flag("scan");
      if (!scan) usage();
      const format = (flag("format", "markdown") ?? "markdown") as
        | "markdown"
        | "json"
        | "sarif"
        | "html";
      const res = generateReportTool({ scanId: scan!, format });
      if (!res.ok) {
        console.error(res.error);
        process.exit(1);
      }
      const out = flag("out");
      if (out) console.log(`Report written to ${res.path}`);
      else console.log(res.content);
      break;
    }
    case "coverage": {
      const scan = flag("scan");
      if (!scan) usage();
      console.log(JSON.stringify(coverageReport({ scanId: scan! }), null, 2));
      break;
    }
    case "eval": {
      const fixturePath = positional();
      const findingsPath = flag("findings");
      if (!fixturePath || !findingsPath) usage();

      // Match the fixture arg against the ground-truth keys either literally
      // (as written, e.g. "tests/fixtures/sample-repos/express-fixture") or
      // by resolving both sides to absolute paths (so an absolute or
      // cwd-relative fixture path still finds its entry).
      const normalizedArg = fixturePath.replace(/\/+$/, "");
      const resolvedArg = resolve(normalizedArg);
      const key = Object.keys(groundTruth).find(
        (k) => k === normalizedArg || resolve(k) === resolvedArg
      );
      if (!key) {
        console.error(
          `No ground truth registered for fixture "${fixturePath}". Known fixtures:\n` +
            Object.keys(groundTruth)
              .map((k) => `  ${k}`)
              .join("\n")
        );
        process.exit(1);
      }
      const entries = groundTruth[key!];

      let submitted: Finding[];
      try {
        const raw = JSON.parse(readFileSync(resolve(findingsPath!), "utf8"));
        if (!Array.isArray(raw)) throw new Error("findings file must contain a JSON array");
        submitted = raw as Finding[];
      } catch (err) {
        console.error(
          `Failed to read/parse findings file "${findingsPath}": ${(err as Error).message}`
        );
        process.exit(1);
      }

      const result = scoreFindings(entries, submitted);
      const pct = (n: number) => `${(n * 100).toFixed(1)}%`;

      console.log(`Fixture: ${key}`);
      console.log(`Ground truth entries: ${entries.length}   Submitted findings: ${submitted.length}`);
      console.log("");
      console.log(`Precision: ${pct(result.precision)}`);
      console.log(`Recall:    ${pct(result.recall)}`);
      console.log(`F1:        ${pct(result.f1)}`);
      console.log("");

      if (result.matched.length > 0) {
        console.log(`Matched (${result.matched.length}):`);
        for (const m of result.matched) {
          console.log(
            `  [x] ${m.groundTruth.file}:${m.groundTruth.lineStart}-${m.groundTruth.lineEnd} ` +
              `(${m.groundTruth.vulnerabilityClass}) <- "${m.finding.title}"`
          );
        }
        console.log("");
      }
      if (result.missed.length > 0) {
        console.log(`Missed (${result.missed.length}):`);
        for (const gt of result.missed) {
          console.log(
            `  [ ] ${gt.file}:${gt.lineStart}-${gt.lineEnd} (${gt.vulnerabilityClass}) — ${gt.description}`
          );
        }
        console.log("");
      }
      if (result.falsePositives.length > 0) {
        console.log(`False positives (${result.falsePositives.length}):`);
        for (const f of result.falsePositives) {
          const loc = f.evidence[0]
            ? `${f.evidence[0].file}:${f.evidence[0].lineStart}-${f.evidence[0].lineEnd}`
            : "no evidence";
          console.log(`  [!] "${f.title}" (${f.playbookId}) — ${loc}`);
        }
        console.log("");
      }

      if (entries.length > 0 && (result.precision === 0 || result.recall === 0)) {
        process.exit(1);
      }
      break;
    }
    default:
      usage();
  }
}

main();
