import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "../models/findings.js";

// Deterministic false-positive gate. A finding must be anchored to code that
// actually exists: we check that each evidence snippet really appears in the
// cited file. This catches the single biggest source of security-tool noise —
// hallucinated or paraphrased evidence — without another LLM call. We are
// lenient about line drift (line numbers may be slightly off, files may have
// shifted) but strict about existence: if the quoted code appears nowhere in
// the file, the finding is not verified and is rejected.

export interface EvidenceVerdict {
  verified: boolean;
  reason: string;
}

// Normalize whitespace so trivial formatting differences don't cause a miss,
// while still requiring the substantive characters to be present.
function normalize(s: string): string {
  return s.replace(/\s+/g, " ").trim();
}

// Collapse a snippet to its significant tokens for a looser fallback match
// (handles a model reflowing/truncating a multi-line snippet).
function significant(s: string): string[] {
  return normalize(s)
    .split(/[^A-Za-z0-9_$.]+/)
    .filter((t) => t.length >= 3);
}

function snippetPresent(fileText: string, snippet: string): boolean {
  const haystack = normalize(fileText);
  const needle = normalize(snippet);
  if (!needle) return false;
  if (haystack.includes(needle)) return true;
  // Fallback: require that a strong majority of the snippet's significant
  // tokens appear in the file, in any order. Guards against paraphrase while
  // still rejecting evidence that simply isn't in the code.
  const tokens = significant(snippet);
  if (tokens.length === 0) return false;
  const present = tokens.filter((t) => haystack.includes(t)).length;
  return present / tokens.length >= 0.8;
}

export function verifyFindingEvidence(finding: Finding, repoPath: string): EvidenceVerdict {
  let anyFileRead = false;
  for (const ev of finding.evidence) {
    const abs = join(repoPath, ev.file);
    if (!existsSync(abs)) continue;
    let text: string;
    try {
      text = readFileSync(abs, "utf-8");
    } catch {
      continue;
    }
    anyFileRead = true;
    if (snippetPresent(text, ev.snippet)) {
      return { verified: true, reason: `evidence located in ${ev.file}` };
    }
  }
  // If we couldn't read any cited file (e.g. generated/virtual paths), don't
  // reject on that basis — absence of the file is not proof of a false finding.
  if (!anyFileRead) {
    return { verified: true, reason: "cited file(s) not readable on disk; evidence not machine-checkable (accepted)" };
  }
  return {
    verified: false,
    reason:
      "none of the evidence snippets could be located in the cited file(s) — the quoted code " +
      "does not appear in the repository, so this finding is treated as unverified and dropped",
  };
}
