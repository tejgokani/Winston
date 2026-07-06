import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { isIgnoredDir, isIgnoredFile } from "../utils/ignorePatterns.js";

// Deterministic secret pre-scan — no LLM. Runs before (or independently of) the
// model to catch hardcoded credentials cheaply: known high-signal token
// formats plus generic high-entropy assignments. Findings are redacted (we
// never echo the full secret) and reported with a confidence level. This is a
// fast CI gate and a complement to the crypto/secrets playbooks; it does not
// replace the LLM review, it front-runs the obvious cases for free.

export type Confidence = "high" | "medium" | "low";

export interface SecretFinding {
  file: string;
  line: number;
  type: string;
  confidence: Confidence;
  redacted: string;
}

interface Pattern {
  type: string;
  re: RegExp;
  confidence: Confidence;
}

// High-signal, low-false-positive provider token formats.
const PATTERNS: Pattern[] = [
  { type: "AWS Access Key ID", re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/, confidence: "high" },
  { type: "GitHub token", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/, confidence: "high" },
  { type: "Slack token", re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/, confidence: "high" },
  { type: "Stripe secret key", re: /\bsk_(live|test)_[0-9A-Za-z]{16,}\b/, confidence: "high" },
  { type: "Google API key", re: /\bAIza[0-9A-Za-z\-_]{35}\b/, confidence: "high" },
  { type: "OpenAI API key", re: /\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b/, confidence: "high" },
  { type: "Anthropic API key", re: /\bsk-ant-[A-Za-z0-9\-_]{20,}\b/, confidence: "high" },
  { type: "Private key block", re: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/, confidence: "high" },
  { type: "JWT", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, confidence: "medium" },
  { type: "Generic bearer token", re: /\bBearer\s+[A-Za-z0-9\-._~+/]{20,}=*/, confidence: "low" },
];

// Generic "SECRET = long-random-string" assignments, gated by Shannon entropy
// so ordinary config values (URLs, enum strings) don't trip it.
const ASSIGN_RE =
  /\b([A-Z0-9_]*(SECRET|TOKEN|PASSWORD|PASSWD|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)[A-Z0-9_]*)\s*[:=]\s*["'`]([^"'`\s]{12,})["'`]/i;

function shannonEntropy(s: string): number {
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let e = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    e -= p * Math.log2(p);
  }
  return e;
}

// Obvious placeholders should not be reported as real secrets.
const PLACEHOLDER_RE =
  /^(x{3,}|\*{3,}|<[^>]+>|your[-_ ]?|changeme|placeholder|example|dummy|test|dev-secret|todo|redacted|null|none|\$\{)/i;

function redact(value: string): string {
  if (value.length <= 8) return value[0] + "***";
  return value.slice(0, 4) + "…" + value.slice(-2);
}

// Detect binary content without embedding a NUL literal in this source file.
function looksBinary(content: string): boolean {
  const cap = Math.min(content.length, 4096);
  for (let i = 0; i < cap; i++) {
    if (content.charCodeAt(i) === 0) return true;
  }
  return false;
}

function scanLine(text: string): Array<{ type: string; confidence: Confidence; redacted: string }> {
  const hits: Array<{ type: string; confidence: Confidence; redacted: string }> = [];
  for (const p of PATTERNS) {
    const m = p.re.exec(text);
    if (m) hits.push({ type: p.type, confidence: p.confidence, redacted: redact(m[0]) });
  }
  const a = ASSIGN_RE.exec(text);
  if (a) {
    const value = a[3];
    if (!PLACEHOLDER_RE.test(value) && shannonEntropy(value) >= 3.2) {
      hits.push({
        type: `Hardcoded ${a[2].toLowerCase()}`,
        confidence: "medium",
        redacted: `${a[1]}=${redact(value)}`,
      });
    }
  }
  return hits;
}

export interface SecretScanReport {
  repoPath: string;
  findings: SecretFinding[];
  filesScanned: number;
}

export function scanSecrets(repoPath: string, maxFiles = 5000): SecretScanReport {
  const findings: SecretFinding[] = [];
  let filesScanned = 0;

  const walk = (dir: string) => {
    if (filesScanned > maxFiles) return;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(dir, entry);
      let isDir = false;
      try {
        isDir = statSync(full).isDirectory();
      } catch {
        continue;
      }
      if (isDir) {
        if (!isIgnoredDir(entry)) walk(full);
        continue;
      }
      if (isIgnoredFile(entry)) continue;
      if (entry === ".winston-ignore") continue; // don't flag the baseline file
      filesScanned++;
      if (filesScanned > maxFiles) return;
      let content: string;
      try {
        content = readFileSync(full, "utf-8");
      } catch {
        continue;
      }
      if (looksBinary(content)) continue;
      const rel = relative(repoPath, full);
      content.split("\n").forEach((line, i) => {
        if (/winston:ignore/i.test(line)) return;
        for (const hit of scanLine(line)) {
          findings.push({ file: rel, line: i + 1, ...hit });
        }
      });
    }
  };
  walk(repoPath);

  const rank: Record<Confidence, number> = { high: 3, medium: 2, low: 1 };
  findings.sort((a, b) => rank[b.confidence] - rank[a.confidence]);
  return { repoPath, findings, filesScanned };
}
