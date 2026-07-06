import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";

// Detect which AI coding tools were plausibly used in a repository — WITHOUT an
// LLM, and WITHOUT claiming per-file authorship (which has no reliable ground
// truth). We surface *signals*: git commit trailers/messages that tools add by
// convention, and config/cache artifacts tools leave in the repo. Each signal
// is evidence that a tool touched the repo *somewhere*, reported with a
// confidence level — never asserted as fact, never attributed to a specific
// file. This framing is deliberate: it is honest about what is actually
// knowable. See README "Detected AI tooling".

export type Confidence = "high" | "medium" | "low";

export interface ToolSignal {
  tool: string;
  confidence: Confidence;
  source: "git_trailer" | "git_message" | "config_artifact";
  evidence: string;
}

export interface ToolingReport {
  repoPath: string;
  isGitRepo: boolean;
  signals: ToolSignal[];
  // Tools ranked by strongest signal, de-duplicated. This is the headline.
  detectedTools: Array<{ tool: string; confidence: Confidence }>;
  disclaimer: string;
}

const DISCLAIMER =
  "These are heuristic signals (git trailers/messages and config artifacts), not " +
  "proof of authorship. They indicate a tool was used somewhere in this repo's " +
  "history, not that any specific file was written by it. AI tools that leave no " +
  "trace will not appear here.";

// Config/cache artifacts. Presence = high confidence the tool was set up here.
// dir=true means match a directory. Keep in sync with the extension's copy.
const ARTIFACTS: Array<{ tool: string; path: string; dir?: boolean }> = [
  { tool: "Cursor", path: ".cursor", dir: true },
  { tool: "Cursor", path: ".cursorrules" },
  { tool: "Cursor", path: ".cursorignore" },
  { tool: "Claude Code", path: ".claude", dir: true },
  { tool: "Claude Code", path: "CLAUDE.md" },
  { tool: "Windsurf", path: ".windsurfrules" },
  { tool: "Windsurf", path: ".windsurf", dir: true },
  { tool: "GitHub Copilot", path: ".github/copilot-instructions.md" },
  { tool: "Aider", path: ".aider.conf.yml" },
  { tool: "Aider", path: ".aiderignore" },
  { tool: "Continue", path: ".continue", dir: true },
  { tool: "Codeium", path: ".codeium", dir: true },
  { tool: "Cline", path: ".clinerules" },
  { tool: "Zed", path: ".zed", dir: true },
  { tool: "Gemini CLI", path: ".gemini", dir: true },
  { tool: "Gemini CLI", path: "GEMINI.md" },
];

// Substrings found in commit messages / trailers. A trailer match is high
// confidence (tools add these deliberately); a loose message match is lower.
const GIT_PATTERNS: Array<{ tool: string; needle: RegExp; source: ToolSignal["source"]; confidence: Confidence }> = [
  { tool: "Claude Code", needle: /Co-Authored-By:\s*Claude/i, source: "git_trailer", confidence: "high" },
  { tool: "Claude Code", needle: /Generated with \[?Claude Code/i, source: "git_message", confidence: "high" },
  { tool: "Cursor", needle: /Co-Authored-By:\s*Cursor/i, source: "git_trailer", confidence: "high" },
  { tool: "GitHub Copilot", needle: /Co-Authored-By:.*Copilot/i, source: "git_trailer", confidence: "high" },
  { tool: "Aider", needle: /\(aider\)/i, source: "git_message", confidence: "medium" },
  { tool: "Aider", needle: /Co-Authored-By:\s*aider/i, source: "git_trailer", confidence: "high" },
  { tool: "Devin", needle: /Co-Authored-By:.*Devin/i, source: "git_trailer", confidence: "high" },
  { tool: "OpenAI Codex", needle: /Co-Authored-By:.*Codex/i, source: "git_trailer", confidence: "high" },
];

function isGitRepo(repoPath: string): boolean {
  return existsSync(join(repoPath, ".git"));
}

function scanArtifacts(repoPath: string): ToolSignal[] {
  const signals: ToolSignal[] = [];
  for (const a of ARTIFACTS) {
    if (existsSync(join(repoPath, a.path))) {
      signals.push({
        tool: a.tool,
        confidence: "high",
        source: "config_artifact",
        evidence: `${a.dir ? "directory" : "file"} "${a.path}" present`,
      });
    }
  }
  return signals;
}

function scanGitHistory(repoPath: string, maxCommits = 2000): ToolSignal[] {
  const signals: ToolSignal[] = [];
  let log = "";
  try {
    // Read commit bodies (%B) for the last N commits. execFileSync avoids shell
    // injection; a failure (not a git repo, empty history) is non-fatal.
    log = execFileSync(
      "git",
      ["log", `-${maxCommits}`, "--no-merges", "--format=%B%x00"],
      { cwd: repoPath, encoding: "utf-8", maxBuffer: 32 * 1024 * 1024, stdio: ["ignore", "pipe", "ignore"] }
    );
  } catch {
    return signals;
  }
  const seen = new Set<string>();
  for (const { tool, needle, source, confidence } of GIT_PATTERNS) {
    const match = log.match(needle);
    if (match && !seen.has(tool + source)) {
      seen.add(tool + source);
      signals.push({
        tool,
        confidence,
        source,
        evidence: `commit ${source === "git_trailer" ? "trailer" : "message"} matched "${match[0].trim().slice(0, 60)}"`,
      });
    }
  }
  return signals;
}

const CONFIDENCE_RANK: Record<Confidence, number> = { high: 3, medium: 2, low: 1 };

export function detectAiTooling(repoPath: string): ToolingReport {
  const gitRepo = isGitRepo(repoPath);
  const signals = [...scanArtifacts(repoPath), ...(gitRepo ? scanGitHistory(repoPath) : [])];

  // Collapse to one entry per tool at its strongest confidence.
  const strongest = new Map<string, Confidence>();
  for (const s of signals) {
    const cur = strongest.get(s.tool);
    if (!cur || CONFIDENCE_RANK[s.confidence] > CONFIDENCE_RANK[cur]) {
      strongest.set(s.tool, s.confidence);
    }
  }
  const detectedTools = [...strongest.entries()]
    .map(([tool, confidence]) => ({ tool, confidence }))
    .sort((a, b) => CONFIDENCE_RANK[b.confidence] - CONFIDENCE_RANK[a.confidence] || a.tool.localeCompare(b.tool));

  return { repoPath, isGitRepo: gitRepo, signals, detectedTools, disclaimer: DISCLAIMER };
}
