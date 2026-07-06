import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "../models/findings.js";

// Suppression / baseline control. Accepted-risk findings must stop re-surfacing
// on every scan, or the tool drowns users in noise. Two mechanisms:
//   1. A `.winston-ignore` file at the repo root (git-committable baseline).
//   2. Inline `winston:ignore [playbookId] — reason` markers on/above the
//      flagged line in the source.
// A suppressed finding is dropped from the graph but reported back so it is
// visible, never silently hidden.

export interface SuppressionRule {
  playbookId?: string;
  pathPattern?: string; // glob-ish (* and **) relative path
  raw: string;
}

const PLAYBOOK_ID_RE = /^[a-z][a-z0-9_]*\.[a-z0-9_.]+$/i;
// Built-in playbook ids start with one of these categories. Checked first so a
// dotted id like `ai_security.xss` isn't mistaken for a file with an
// `.xss` extension.
const KNOWN_PLAYBOOK_PREFIXES = ["ai_security.", "ai_mistakes.", "technology."];

// Classify a bare token in a .winston-ignore line as a playbook id or a path.
function classifyToken(token: string): "id" | "path" | "unknown" {
  if (KNOWN_PLAYBOOK_PREFIXES.some((p) => token.startsWith(p))) return "id";
  if (token.includes("/") || token.includes("*")) return "path";
  // Custom playbook ids follow the dotted+underscored convention; anything
  // else that looks like a bare filename is treated as a path.
  if (PLAYBOOK_ID_RE.test(token) && token.includes("_")) return "id";
  if (/\.[a-z0-9]+$/i.test(token)) return "path";
  return "unknown";
}

export function parseSuppressionFile(content: string): SuppressionRule[] {
  const rules: SuppressionRule[] = [];
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const tokens = trimmed.split(/\s+/);
    const rule: SuppressionRule = { raw: trimmed };
    for (const tok of tokens) {
      if (tok === "—" || tok === "-" || tok.startsWith("#")) break; // reason follows
      const kind = classifyToken(tok);
      if (kind === "path") rule.pathPattern = tok;
      else if (kind === "id") rule.playbookId = tok;
    }
    if (rule.playbookId || rule.pathPattern) rules.push(rule);
  }
  return rules;
}

export function loadSuppressions(repoPath: string): SuppressionRule[] {
  const file = join(repoPath, ".winston-ignore");
  if (!existsSync(file)) return [];
  try {
    return parseSuppressionFile(readFileSync(file, "utf-8"));
  } catch {
    return [];
  }
}

// Minimal glob → RegExp: `**` matches across path separators, `*` within a
// segment. Anchored to the whole relative path.
function globToRegExp(glob: string): RegExp {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        re += ".*";
        i++;
        if (glob[i + 1] === "/") i++; // consume trailing slash of **/
      } else {
        re += "[^/]*";
      }
    } else if (".+?^${}()|[]\\".includes(c)) {
      re += "\\" + c;
    } else {
      re += c;
    }
  }
  return new RegExp(`^${re}$`);
}

function pathMatches(pattern: string, filePath: string): boolean {
  const norm = filePath.replace(/^\.\//, "");
  // A bare filename or directory prefix should match anywhere in the path too.
  if (!pattern.includes("/") && !pattern.includes("*")) {
    return norm === pattern || norm.endsWith("/" + pattern) || norm.split("/").includes(pattern);
  }
  return globToRegExp(pattern).test(norm) || globToRegExp("**/" + pattern).test(norm);
}

function ruleMatches(rule: SuppressionRule, finding: Finding): boolean {
  if (rule.playbookId && rule.playbookId !== finding.playbookId) return false;
  if (rule.pathPattern) {
    const anyFile = finding.affectedFiles.some((f) => pathMatches(rule.pathPattern!, f));
    if (!anyFile) return false;
  }
  // A rule with neither field never matches (guarded at parse time).
  return Boolean(rule.playbookId || rule.pathPattern);
}

// Inline: `winston:ignore` on or one line above a piece of evidence. An
// optional playbook id after the marker scopes it to that playbook.
function inlineSuppressed(finding: Finding, repoPath: string): boolean {
  for (const ev of finding.evidence) {
    let lines: string[];
    try {
      lines = readFileSync(join(repoPath, ev.file), "utf-8").split("\n");
    } catch {
      continue;
    }
    const from = Math.max(0, ev.lineStart - 2); // the line and the one above
    const to = Math.min(lines.length, ev.lineEnd);
    for (let i = from; i < to; i++) {
      const m = /winston:ignore(?:\s+([a-z0-9_.]+))?/i.exec(lines[i] ?? "");
      if (m && (!m[1] || m[1] === finding.playbookId)) return true;
    }
  }
  return false;
}

export interface SuppressionCheck {
  suppressed: boolean;
  reason?: string;
}

export function checkSuppressed(
  finding: Finding,
  rules: SuppressionRule[],
  repoPath: string
): SuppressionCheck {
  const rule = rules.find((r) => ruleMatches(r, finding));
  if (rule) return { suppressed: true, reason: `.winston-ignore rule "${rule.raw}"` };
  if (inlineSuppressed(finding, repoPath)) return { suppressed: true, reason: "inline winston:ignore marker" };
  return { suppressed: false };
}
