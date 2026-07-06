const SEVERITY_COLOR = {
  critical: "#b91c1c",
  high: "#c2410c",
  medium: "#a16207",
  low: "#4d7c0f",
  info: "#6b7280",
};
const COMPONENT_COLOR = "#374151";

let cy = null;

function colorForNode(node) {
  if (node.type === "component") return COMPONENT_COLOR;
  return SEVERITY_COLOR[node.severity] ?? SEVERITY_COLOR.info;
}

function renderSummary(graph) {
  const open = graph.nodes.filter((n) => n.type === "vulnerability" && n.status === "open");
  document.getElementById("summary").innerHTML = `
    <div style="font-size:0.8rem;margin-bottom:1rem;">
      <div><strong>Risk score:</strong> ${graph.riskScore.overall}</div>
      <div>${open.length} open finding(s)</div>
      <div>${graph.nodes.length} node(s), ${graph.edges.length} edge(s)</div>
    </div>`;
}

function field(label, value) {
  if (!value) return "";
  return `<div class="field"><div class="field-label">${label}</div><div>${value}</div></div>`;
}

function showPanel(node) {
  const panel = document.getElementById("panel");
  const severityBadge = node.severity
    ? `<span class="severity-badge" style="background:${SEVERITY_COLOR[node.severity]}">${node.severity}</span>`
    : "";
  const evidenceHtml = (node.evidence || [])
    .map((e) => `<pre>${e.file}:${e.lineStart}-${e.lineEnd}\n${escapeHtml(e.snippet)}</pre>`)
    .join("");

  panel.innerHTML = `
    <h2>${severityBadge} ${escapeHtml(node.label)}</h2>
    ${field("Type", node.type)}
    ${field("Status", node.status)}
    ${field("Root cause", node.rootCause ? "Yes" : "No")}
    ${field("Description", escapeHtml(node.description))}
    ${field("Reasoning", escapeHtml(node.reasoning))}
    ${field("Attack scenario", escapeHtml(node.attackScenario))}
    ${field("Evidence", evidenceHtml)}
    ${field("Recommended fix", escapeHtml(node.recommendedFix))}
    ${field("AI fix prompt", node.aiFixPrompt ? `<pre>${escapeHtml(node.aiFixPrompt)}</pre>` : "")}
  `;
  panel.style.display = "block";
}

function escapeHtml(text) {
  if (!text) return "";
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

async function loadGraph(repoPath) {
  const res = await fetch(`/api/graph?repoPath=${encodeURIComponent(repoPath)}`);
  const graph = await res.json();
  renderSummary(graph);

  const elements = [
    ...graph.nodes.map((n) => ({
      data: { id: n.id, label: n.label, ...n },
      style: { "background-color": colorForNode(n) },
    })),
    ...graph.edges.map((e, i) => ({
      data: { id: `edge-${i}`, source: e.source, target: e.target, label: e.relation },
    })),
  ];

  if (cy) cy.destroy();
  cy = cytoscape({
    container: document.getElementById("cy"),
    elements,
    style: [
      {
        selector: "node",
        style: {
          label: "data(label)",
          "background-color": "data(background-color)",
          color: "#111827",
          "font-size": "10px",
          "text-valign": "bottom",
          "text-margin-y": 4,
          width: 24,
          height: 24,
        },
      },
      {
        selector: "edge",
        style: {
          width: 1.5,
          "line-color": "#9ca3af",
          "target-arrow-color": "#9ca3af",
          "target-arrow-shape": "triangle",
          "curve-style": "bezier",
          label: "data(label)",
          "font-size": "8px",
          color: "#6b7280",
        },
      },
      {
        selector: "node:selected",
        style: { "border-width": 3, "border-color": "#2563eb" },
      },
    ],
    layout: { name: "cose", animate: false },
  });

  cy.on("tap", "node", (evt) => {
    const node = evt.target.data();
    showPanel(node);
    cy.elements().removeClass("dimmed");
    const neighborhood = evt.target.closedNeighborhood();
    cy.elements().difference(neighborhood).addClass("dimmed");
  });

  cy.on("tap", (evt) => {
    if (evt.target === cy) {
      document.getElementById("panel").style.display = "none";
      cy.elements().removeClass("dimmed");
    }
  });
}

document.getElementById("loadBtn").addEventListener("click", () => {
  const repoPath = document.getElementById("repoInput").value.trim();
  if (repoPath) loadGraph(repoPath);
});

const params = new URLSearchParams(window.location.search);
const initialRepo = params.get("repoPath");
if (initialRepo) {
  document.getElementById("repoInput").value = initialRepo;
  loadGraph(initialRepo);
}
