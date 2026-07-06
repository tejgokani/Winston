import { DirectedGraph } from "graphology";
import type { GraphNode, ThreatGraph } from "../models/graph.js";
import { loadPlaybookById } from "./playbookLoader.js";

const SEVERITY_ORDER: Array<GraphNode["severity"]> = ["critical", "high", "medium", "low", "info"];

function openVulnerabilities(graph: ThreatGraph, minSeverity?: GraphNode["severity"]): GraphNode[] {
  const open = graph.nodes.filter((n) => n.type === "vulnerability" && n.status === "open");
  if (!minSeverity) return open;
  const threshold = SEVERITY_ORDER.indexOf(minSeverity);
  return open.filter((n) => {
    const idx = SEVERITY_ORDER.indexOf(n.severity);
    return idx !== -1 && idx <= threshold;
  });
}

// Referenced-citations lookup for a playbookId, used to enrich both the
// Markdown report ("**References:**" line) and the SARIF rules
// (properties.tags / helpUri / fullDescription). Returns null when the
// playbook can't be resolved (custom/removed playbook) so callers fall back
// to their existing minimal shape rather than throwing.
function referencesFor(playbookId: string | null): {
  title: string;
  owaspRefs: string[];
  cweRefs: string[];
  realWorldReferences: { title: string; url: string; type: string }[];
} | null {
  if (!playbookId) return null;
  const pb = loadPlaybookById(playbookId);
  if (!pb) return null;
  return {
    title: pb.frontmatter.title,
    owaspRefs: pb.frontmatter.owaspRefs,
    cweRefs: pb.frontmatter.cweRefs,
    realWorldReferences: pb.frontmatter.realWorldReferences,
  };
}

function buildCausesGraph(graph: ThreatGraph): DirectedGraph {
  const g = new DirectedGraph();
  for (const node of graph.nodes) g.addNode(node.id);
  for (const edge of graph.edges) {
    if (edge.relation !== "causes") continue;
    if (!g.hasEdge(edge.source, edge.target)) g.addEdge(edge.source, edge.target);
  }
  return g;
}

function labelFor(graph: ThreatGraph, id: string): string {
  return graph.nodes.find((n) => n.id === id)?.label ?? id;
}

// Attack chains: for each root-cause vulnerability, follow outgoing "causes"
// edges to build a human-readable chain. Pure graph traversal, no LLM call.
// A node can have multiple causes edges (e.g. to both an architectural
// component and a downstream finding) — prefer chaining through downstream
// vulnerabilities, since those are exploit steps; a component is the
// affected surface, not a next step.
export function deriveAttackChains(graph: ThreatGraph): string[][] {
  const g = buildCausesGraph(graph);
  const nodeById = new Map(graph.nodes.map((n) => [n.id, n]));
  const rootCauses = graph.nodes.filter((n) => n.type === "vulnerability" && n.rootCause);
  const chains: string[][] = [];

  function pickNext(current: string, visited: Set<string>): string | undefined {
    const neighbors = g.outNeighbors(current).filter((n) => !visited.has(n));
    const vulnNeighbor = neighbors.find((n) => nodeById.get(n)?.type === "vulnerability");
    return vulnNeighbor ?? neighbors[0];
  }

  for (const root of rootCauses) {
    const chain = [labelFor(graph, root.id)];
    let current = root.id;
    const visited = new Set([current]);
    while (g.hasNode(current) && g.outDegree(current) > 0) {
      const next = pickNext(current, visited);
      if (!next) break;
      chain.push(labelFor(graph, next));
      visited.add(next);
      current = next;
    }
    if (chain.length > 1) chains.push(chain);
  }

  return chains;
}

function executiveSummary(graph: ThreatGraph): string {
  const open = openVulnerabilities(graph);
  return (
    `**Overall risk score:** ${graph.riskScore.overall}\n\n` +
    `| Severity | Count |\n|---|---|\n` +
    `| Critical | ${graph.riskScore.critical} |\n` +
    `| High | ${graph.riskScore.high} |\n` +
    `| Medium | ${graph.riskScore.medium} |\n` +
    `| Low | ${graph.riskScore.low} |\n\n` +
    `${open.length} open finding(s) across ${graph.nodes.filter((n) => n.type === "component").length} tracked component(s).`
  );
}

export function generateMarkdownReport(graph: ThreatGraph, minSeverity?: GraphNode["severity"]): string {
  const open = openVulnerabilities(graph, minSeverity).sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );
  const rootCauses = open.filter((n) => n.rootCause);
  const chains = deriveAttackChains(graph);

  const sections: string[] = [];
  sections.push(`# Winston Threat Report\n\n**Repository:** ${graph.repoPath}\n\n**Generated:** ${graph.updatedAt}`);
  sections.push(`## Executive Summary\n\n${executiveSummary(graph)}`);

  // "Fix First" — the crown and the ranked root causes beneath it. This is the
  // readable form of what the graph tree shows: the node causing the most
  // trouble at the top, ordered by downstream blast radius.
  const crown = graph.crownNodeId
    ? graph.nodes.find((n) => n.id === graph.crownNodeId)
    : undefined;
  const rankedRoots = graph.nodes
    .filter((n) => n.impactRank !== null)
    .sort((a, b) => (a.impactRank ?? 0) - (b.impactRank ?? 0));
  sections.push(
    `## Fix First\n\n` +
      (crown
        ? `**👑 The crown: ${crown.label}** — the highest-impact root cause, ` +
          `implicated in ${crown.downstreamImpact} downstream ` +
          `${crown.downstreamImpact === 1 ? "issue" : "issues"} ` +
          `(impact score ${crown.crownScore}). Address this first.\n\n` +
          `Ranked root causes by blast radius:\n\n` +
          rankedRoots
            .map(
              (n) =>
                `${n.impactRank}. **${n.label}**${
                  n.severity ? ` (${n.severity})` : ""
                } — ${n.downstreamImpact} downstream, impact ${n.crownScore}`
            )
            .join("\n")
        : "No open vulnerabilities to prioritize.")
  );

  sections.push(
    `## Root Causes\n\n` +
      (rootCauses.length
        ? rootCauses.map((n) => `- **${n.label}** (${n.severity}) — ${n.description}`).join("\n")
        : "No root-cause vulnerabilities identified.")
  );

  sections.push(
    `## Findings\n\n` +
      (open.length
        ? open
            .map((n) => {
              const refs = referencesFor(n.playbookId);
              const refsLine =
                refs && (refs.owaspRefs.length > 0 || refs.cweRefs.length > 0)
                  ? `\n\n**References:** OWASP: ${refs.owaspRefs.join(", ")} · CWE: ${refs.cweRefs.join(", ")}`
                  : "";
              return (
                `### ${n.label} (${n.severity})\n\n` +
                `${n.description}\n\n` +
                `**Reasoning:** ${n.reasoning ?? "n/a"}\n\n` +
                `**Attack scenario:** ${n.attackScenario ?? "n/a"}\n\n` +
                `**Affected files:** ${n.affectedFiles.join(", ") || "none"}\n\n` +
                `**Recommended fix:** ${n.recommendedFix ?? "n/a"}\n\n` +
                `**AI fix prompt:** \`${n.aiFixPrompt ?? "n/a"}\`` +
                refsLine
              );
            })
            .join("\n\n---\n\n")
        : "No open findings.")
  );

  sections.push(
    `## Attack Chains\n\n` +
      (chains.length
        ? chains.map((chain) => `- ${chain.join(" → ")}`).join("\n")
        : "No multi-step attack chains identified from current findings.")
  );

  sections.push(
    `## Recommendations\n\n` +
      (open.length
        ? open.map((n) => `- **${n.label}:** ${n.recommendedFix ?? "n/a"}`).join("\n")
        : "No outstanding recommendations.")
  );

  return sections.join("\n\n");
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: "#b91c1c",
  high: "#c2410c",
  medium: "#a16207",
  low: "#4d7c0f",
  info: "#6b7280",
};

export function generateHtmlReport(graph: ThreatGraph, minSeverity?: GraphNode["severity"]): string {
  const open = openVulnerabilities(graph, minSeverity).sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );
  const chains = deriveAttackChains(graph);

  const findingsHtml = open
    .map((n) => {
      const color = SEVERITY_COLOR[n.severity ?? "info"];
      return `
        <div class="finding">
          <h3><span class="severity" style="background:${color}">${n.severity}</span> ${escapeHtml(n.label)}</h3>
          <p>${escapeHtml(n.description)}</p>
          <p><strong>Attack scenario:</strong> ${escapeHtml(n.attackScenario ?? "n/a")}</p>
          <p><strong>Affected files:</strong> ${escapeHtml(n.affectedFiles.join(", ") || "none")}</p>
          <p><strong>Recommended fix:</strong> ${escapeHtml(n.recommendedFix ?? "n/a")}</p>
        </div>`;
    })
    .join("\n");

  const chainsHtml = chains.length
    ? `<ul>${chains.map((c) => `<li>${c.map(escapeHtml).join(" &rarr; ")}</li>`).join("")}</ul>`
    : "<p>No multi-step attack chains identified.</p>";

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Winston Threat Report</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 860px; margin: 2rem auto; color: #1f2937; }
    .severity { color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; text-transform: uppercase; }
    .finding { border: 1px solid #e5e7eb; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
  </style>
</head>
<body>
  <h1>Winston Threat Report</h1>
  <p><strong>Repository:</strong> ${escapeHtml(graph.repoPath)}</p>
  <p><strong>Overall risk score:</strong> ${graph.riskScore.overall} (critical: ${graph.riskScore.critical}, high: ${graph.riskScore.high}, medium: ${graph.riskScore.medium}, low: ${graph.riskScore.low})</p>
  <h2>Findings</h2>
  ${findingsHtml || "<p>No open findings.</p>"}
  <h2>Attack Chains</h2>
  ${chainsHtml}
</body>
</html>`;
}

// SARIF 2.1.0 — the industry-standard static-analysis format. Emitting it lets
// Winston findings appear natively in GitHub Code Scanning and any SARIF
// consumer, which is how security tools earn a place in CI. Each playbook is a
// rule; each open vulnerability is a result anchored to its evidence location.
const SARIF_LEVEL: Record<string, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

export function generateSarifReport(graph: ThreatGraph, minSeverity?: GraphNode["severity"]): string {
  const open = openVulnerabilities(graph, minSeverity);
  const ruleIds = [...new Set(open.map((n) => n.playbookId).filter((x): x is string => !!x))];
  const DEFAULT_HELP_URI = "https://github.com/winston-sec/winston";
  const rules = ruleIds.map((id) => {
    const refs = referencesFor(id);
    if (!refs) {
      return {
        id,
        name: id,
        shortDescription: { text: id },
        helpUri: DEFAULT_HELP_URI,
      };
    }
    const primaryRef = refs.realWorldReferences[0];
    const tags = [...new Set([...refs.owaspRefs, ...refs.cweRefs])];
    return {
      id,
      name: id,
      shortDescription: { text: id },
      fullDescription: {
        text: primaryRef ? `${refs.title} — ${primaryRef.title}` : refs.title,
      },
      helpUri: primaryRef ? primaryRef.url : DEFAULT_HELP_URI,
      properties: { tags },
    };
  });

  const results = open.map((n) => {
    const ev = n.evidence[0];
    const locations = ev
      ? [
          {
            physicalLocation: {
              artifactLocation: { uri: ev.file },
              region: { startLine: ev.lineStart, endLine: ev.lineEnd },
            },
          },
        ]
      : n.affectedFiles.map((f) => ({
          physicalLocation: { artifactLocation: { uri: f } },
        }));
    return {
      ruleId: n.playbookId ?? n.id,
      level: SARIF_LEVEL[n.severity ?? "info"],
      message: {
        text: `${n.label}: ${n.description}${
          n.recommendedFix ? ` — Fix: ${n.recommendedFix}` : ""
        }`,
      },
      locations,
      properties: {
        severity: n.severity,
        impactRank: n.impactRank,
        downstreamImpact: n.downstreamImpact,
        crown: n.id === graph.crownNodeId,
      },
    };
  });

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Winston",
            informationUri: "https://github.com/winston-sec/winston",
            version: "0.1.0",
            rules,
          },
        },
        results,
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}

export function generateReport(
  graph: ThreatGraph,
  format: "markdown" | "html" | "json" | "sarif",
  minSeverity?: GraphNode["severity"]
): string {
  if (format === "markdown") return generateMarkdownReport(graph, minSeverity);
  if (format === "html") return generateHtmlReport(graph, minSeverity);
  if (format === "sarif") return generateSarifReport(graph, minSeverity);
  return JSON.stringify(graph, null, 2);
}
