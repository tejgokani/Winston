// Winston threat-graph webview. Self-contained: no external libraries (VS Code
// webview CSP forbids remote scripts), renders the graph as a top-down tree
// with the crown at the top and the vulnerabilities/components it causes
// branching beneath — the "Obsidian-style" map the product describes, laid out
// by BFS over `causes` edges from the crown.
const vscode = acquireVsCodeApi();

const SEV_COLOR = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#84cc16", info: "#9ca3af" };
const SVG_NS = "http://www.w3.org/2000/svg";

let graph = null;
let selectedId = null;

window.addEventListener("message", (e) => {
  const msg = e.data;
  if (msg.type === "graph") {
    graph = msg.graph;
    render();
  }
});

function el(ns, name, attrs, children) {
  const node = ns ? document.createElementNS(ns, name) : document.createElement(name);
  for (const k in attrs || {}) node.setAttribute(k, attrs[k]);
  for (const c of children || []) node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  return node;
}

// Assign each node a depth level. Roots = crown + any node with no incoming
// `causes` edge. Then BFS down `causes` edges. Nodes never touched by a causes
// edge (orphan components) go on a trailing row.
function computeLevels(nodes, edges) {
  const causes = edges.filter((e) => e.relation === "causes");
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const hasIncoming = new Set(causes.map((e) => e.target));
  const outAdj = new Map(nodes.map((n) => [n.id, []]));
  for (const e of causes) if (outAdj.has(e.source) && byId.has(e.target)) outAdj.get(e.source).push(e.target);

  const level = new Map();
  const roots = nodes.filter((n) => !hasIncoming.has(n.id) && (outAdj.get(n.id) || []).length > 0);
  // Crown first so it anchors the top-left of level 0.
  roots.sort((a, b) => (a.id === graph.crownNodeId ? -1 : b.id === graph.crownNodeId ? 1 : 0));
  const queue = roots.map((n) => n.id);
  for (const id of queue) if (!level.has(id)) level.set(id, 0);
  while (queue.length) {
    const id = queue.shift();
    const d = level.get(id) || 0;
    for (const next of outAdj.get(id) || []) {
      if (!level.has(next) || level.get(next) < d + 1) {
        level.set(next, d + 1);
        queue.push(next);
      }
    }
  }
  // Anything with no level yet (isolated components / no causes edges) → last row.
  const maxLvl = Math.max(0, ...[...level.values()]);
  for (const n of nodes) if (!level.has(n.id)) level.set(n.id, maxLvl + 1);
  return level;
}

function render() {
  const host = document.getElementById("graph");
  host.innerHTML = "";
  const empty = document.getElementById("empty");
  const openVulns = graph ? graph.nodes.filter((n) => n.type === "vulnerability" && n.status === "open") : [];

  renderToolbar();

  if (!graph || openVulns.length === 0) {
    empty.classList.remove("hidden");
    empty.querySelector("#emptyMsg").textContent = graph
      ? "No open vulnerabilities yet. Run an audit, then submit findings — the graph builds itself here."
      : "No threat graph for this repository yet. Run “Winston: Audit this repository”.";
    return;
  }
  empty.classList.add("hidden");

  // Only render nodes that are part of the open-finding subgraph (open vulns,
  // plus any component/other node connected to one). Fixed findings are hidden.
  const openIds = new Set(openVulns.map((n) => n.id));
  const keep = new Set(openIds);
  for (const e of graph.edges) {
    if (openIds.has(e.source)) keep.add(e.target);
    if (openIds.has(e.target)) keep.add(e.source);
  }
  const nodes = graph.nodes.filter((n) => keep.has(n.id) && n.status !== "fixed");
  const edges = graph.edges.filter((e) => keep.has(e.source) && keep.has(e.target));

  const level = computeLevels(nodes, edges);
  const rows = new Map();
  for (const n of nodes) {
    const l = level.get(n.id);
    if (!rows.has(l)) rows.set(l, []);
    rows.get(l).push(n);
  }

  const NODE_W = 190, NODE_H = 52, GAP_X = 40, GAP_Y = 90, PAD = 40;
  const pos = new Map();
  let maxCols = 0;
  for (const [, arr] of rows) maxCols = Math.max(maxCols, arr.length);
  const width = PAD * 2 + maxCols * NODE_W + (maxCols - 1) * GAP_X;
  const sortedLevels = [...rows.keys()].sort((a, b) => a - b);

  sortedLevels.forEach((l, rowIdx) => {
    const arr = rows.get(l);
    // Crown pinned to the front of its row; others by impactRank then severity.
    arr.sort((a, b) => (a.id === graph.crownNodeId ? -1 : b.id === graph.crownNodeId ? 1 : (a.impactRank || 99) - (b.impactRank || 99)));
    const rowWidth = arr.length * NODE_W + (arr.length - 1) * GAP_X;
    const startX = (width - rowWidth) / 2;
    arr.forEach((n, i) => {
      pos.set(n.id, { x: startX + i * (NODE_W + GAP_X), y: PAD + rowIdx * (NODE_H + GAP_Y) });
    });
  });

  const height = PAD * 2 + sortedLevels.length * NODE_H + (sortedLevels.length - 1) * GAP_Y;
  const svg = el(SVG_NS, "svg", { width: String(width), height: String(height), viewBox: `0 0 ${width} ${height}` });

  // Edges first (under nodes).
  for (const e of edges) {
    const s = pos.get(e.source), t = pos.get(e.target);
    if (!s || !t) continue;
    const x1 = s.x + NODE_W / 2, y1 = s.y + NODE_H;
    const x2 = t.x + NODE_W / 2, y2 = t.y;
    const my = (y1 + y2) / 2;
    const path = el(SVG_NS, "path", {
      class: "edge " + e.relation,
      d: `M ${x1} ${y1} C ${x1} ${my}, ${x2} ${my}, ${x2} ${y2}`,
    });
    svg.appendChild(path);
  }

  // Nodes.
  for (const n of nodes) {
    const p = pos.get(n.id);
    if (!p) continue;
    const isCrown = n.id === graph.crownNodeId;
    const color = n.type === "vulnerability" ? SEV_COLOR[n.severity || "info"] : "var(--comp)";
    const g = el(SVG_NS, "g", {
      class: "node" + (isCrown ? " crown" : "") + (n.id === selectedId ? " selected" : ""),
      transform: `translate(${p.x}, ${p.y})`,
    });
    g.appendChild(el(SVG_NS, "rect", {
      width: String(NODE_W), height: String(NODE_H), rx: "8",
      fill: n.type === "vulnerability" ? color : "var(--vscode-editorWidget-background, #2a2a2a)",
      "fill-opacity": n.type === "vulnerability" ? "0.22" : "0.6",
    }));
    // severity dot
    g.appendChild(el(SVG_NS, "circle", { cx: "14", cy: String(NODE_H / 2), r: "5", fill: color, stroke: "none" }));
    const label = (isCrown ? "👑 " : "") + truncate(n.label, 24);
    g.appendChild(el(SVG_NS, "text", { x: "26", y: "22" }, [label]));
    const sub =
      n.type === "vulnerability"
        ? `${n.severity || "info"}${n.impactRank ? ` · rank #${n.impactRank}` : ""}${n.downstreamImpact > 1 ? ` · ${n.downstreamImpact} downstream` : ""}`
        : "component";
    g.appendChild(el(SVG_NS, "text", { class: "sub", x: "26", y: "40" }, [sub]));
    g.addEventListener("click", () => selectNode(n.id));
    svg.appendChild(g);
  }

  host.appendChild(svg);
  if (selectedId) showPanel(nodes.find((n) => n.id === selectedId));
}

function renderToolbar() {
  const tb = document.getElementById("toolbar");
  if (!graph) { tb.innerHTML = ""; return; }
  const r = graph.riskScore;
  const crown = graph.crownNodeId ? graph.nodes.find((n) => n.id === graph.crownNodeId) : null;
  tb.innerHTML = "";
  tb.appendChild(el(null, "span", { class: "stat crit" }, [`risk ${r.overall}`]));
  tb.appendChild(el(null, "span", { class: "stat" }, [`· C${r.critical} H${r.high} M${r.medium} L${r.low}`]));
  if (crown) tb.appendChild(el(null, "span", { class: "stat" }, [`· 👑 ${truncate(crown.label, 30)}`]));
}

function selectNode(id) {
  selectedId = id;
  render();
}

function showPanel(node) {
  const panel = document.getElementById("panel");
  if (!node) { panel.classList.add("hidden"); return; }
  panel.classList.remove("hidden");
  panel.innerHTML = "";
  const color = node.type === "vulnerability" ? SEV_COLOR[node.severity || "info"] : "#9ca3af";
  panel.appendChild(el(null, "h2", {}, [(node.id === graph.crownNodeId ? "👑 " : "") + node.label]));
  if (node.severity)
    panel.appendChild(el(null, "span", { class: "badge", style: `background:${color}` }, [node.severity]));

  const field = (label, value) => {
    if (!value) return;
    const f = el(null, "div", { class: "field" });
    f.appendChild(el(null, "div", { class: "field-label" }, [label]));
    f.appendChild(el(null, "div", {}, [value]));
    panel.appendChild(f);
  };
  if (node.impactRank)
    field("Impact", `Rank #${node.impactRank} · ${node.downstreamImpact} downstream issue(s) · score ${node.crownScore}`);
  field("Description", node.description);
  field("Reasoning", node.reasoning);
  field("Attack scenario", node.attackScenario);

  if (node.affectedFiles && node.affectedFiles.length) {
    const f = el(null, "div", { class: "field" });
    f.appendChild(el(null, "div", { class: "field-label" }, ["Affected files"]));
    for (const file of node.affectedFiles) {
      const link = el(null, "span", { class: "file" }, [file]);
      link.addEventListener("click", () => vscode.postMessage({ type: "openFile", file }));
      f.appendChild(link);
    }
    panel.appendChild(f);
  }
  field("Recommended fix", node.recommendedFix);
  if (node.aiFixPrompt) {
    const f = el(null, "div", { class: "field" });
    f.appendChild(el(null, "div", { class: "field-label" }, ["AI fix prompt"]));
    f.appendChild(el(null, "pre", {}, [node.aiFixPrompt]));
    panel.appendChild(f);
  }
}

function truncate(s, n) {
  return s && s.length > n ? s.slice(0, n - 1) + "…" : s || "";
}

vscode.postMessage({ type: "ready" });
