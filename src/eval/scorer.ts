import type { Finding } from "../models/findings.js";
import type { GroundTruthEntry } from "./groundTruth.js";

// Matching tolerance: a submitted finding's evidence line range is allowed to
// drift this many lines from the seeded ground-truth range before it no
// longer counts as the same finding (LLMs commonly cite a line or two off
// from the exact seeded line, e.g. quoting the statement instead of the
// declaration).
const LINE_TOLERANCE = 3;

export interface MatchedPair {
  groundTruth: GroundTruthEntry;
  finding: Finding;
}

export interface EvalResult {
  precision: number; // 0..1
  recall: number; // 0..1
  f1: number; // 0..1
  matched: MatchedPair[];
  missed: GroundTruthEntry[];
  falsePositives: Finding[];
}

function normalizeFile(file: string): string {
  return file.replace(/\\/g, "/").replace(/^\.\//, "");
}

function overlaps(entry: GroundTruthEntry, evLineStart: number, evLineEnd: number): boolean {
  const lo = entry.lineStart - LINE_TOLERANCE;
  const hi = entry.lineEnd + LINE_TOLERANCE;
  return evLineStart <= hi && evLineEnd >= lo;
}

function findingMatchesEntry(finding: Finding, entry: GroundTruthEntry): boolean {
  const entryFile = normalizeFile(entry.file);
  return finding.evidence.some(
    (ev) => normalizeFile(ev.file) === entryFile && overlaps(entry, ev.lineStart, ev.lineEnd)
  );
}

/**
 * Score a set of submitted findings against known, seeded ground truth for a
 * fixture repo.
 *
 * Matching rule: a submitted finding matches a ground-truth entry if ANY of
 * its evidence entries has the same file (relative to the fixture root) and
 * a line range overlapping the ground-truth range within +/- LINE_TOLERANCE
 * lines. playbookId / vulnerabilityClass equality is NOT required — a
 * correct finding may reasonably classify the same real vulnerability under
 * a related-but-not-identical playbook, so those fields are recorded on the
 * ground-truth entry only for human-readable reporting.
 *
 * Each ground-truth entry can be claimed by at most one submitted finding
 * (first match wins, in submission order); once claimed, additional findings
 * that land on the same entry don't get extra recall credit and count as
 * false positives for precision (duplicate/overlapping reports of the same
 * seeded vuln shouldn't inflate the score).
 *
 * NaN-free empty-ground-truth convention (documented per the task spec):
 *   - recall: with zero ground-truth entries there is nothing to miss, so
 *     recall is defined as 1 (100%) regardless of what was submitted.
 *   - precision: with zero submitted findings there is nothing that could be
 *     wrong, so precision is defined as 1 (100%, effectively N/A) — this
 *     applies whether or not ground truth is empty. Otherwise precision is
 *     the usual truePositives / submitted.length, which is naturally 0 when
 *     ground truth is empty and at least one finding was submitted (every
 *     submitted finding is a false positive against an empty fixture).
 *   - f1: the harmonic mean of precision and recall, or 0 if both are 0.
 */
export function scoreFindings(
  groundTruth: GroundTruthEntry[],
  submitted: Finding[]
): EvalResult {
  const claimed = new Set<number>();
  const matched: MatchedPair[] = [];
  const falsePositives: Finding[] = [];

  for (const finding of submitted) {
    let matchedIndex = -1;
    for (let i = 0; i < groundTruth.length; i++) {
      if (claimed.has(i)) continue;
      if (findingMatchesEntry(finding, groundTruth[i])) {
        matchedIndex = i;
        break;
      }
    }
    if (matchedIndex === -1) {
      falsePositives.push(finding);
    } else {
      claimed.add(matchedIndex);
      matched.push({ groundTruth: groundTruth[matchedIndex], finding });
    }
  }

  const missed = groundTruth.filter((_, i) => !claimed.has(i));

  const truePositives = matched.length;

  const precision = submitted.length === 0 ? 1 : truePositives / submitted.length;
  const recall = groundTruth.length === 0 ? 1 : truePositives / groundTruth.length;
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);

  return { precision, recall, f1, matched, missed, falsePositives };
}
