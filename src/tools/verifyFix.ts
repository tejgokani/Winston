import { loadGraphForRepo, saveGraphForRepo } from "../storage/graphStore.js";
import { loadScan } from "../storage/scanStore.js";
import { verifyFindingEvidence } from "../verify/evidence.js";

export interface VerifyFixInput {
  scanId: string;
  findingId: string;
}

export interface VerifyFixResult {
  ok: boolean;
  findingId?: string;
  status?: "fixed" | "still_open";
  proof?: string;
  aiFixPrompt?: string | null;
  error?: string;
}

// Close the fix loop deterministically. A finding's evidence is the exact
// vulnerable code. If that code no longer appears in the repo, the specific
// issue is plausibly resolved — we flip the graph node to "fixed" with the
// proof "evidence no longer present". If the code is still there, the finding
// stays open and we hand back the aiFixPrompt to apply. This is proof, not
// assumption: we re-read the file on disk, not the model's word.
export function verifyFix({ scanId, findingId }: VerifyFixInput): VerifyFixResult {
  const scan = loadScan(scanId);
  if (!scan) {
    return { ok: false, error: `Unknown scanId "${scanId}". Call audit_repository first.` };
  }
  const graph = loadGraphForRepo(scan.repoPath);
  const node = graph.nodes.find((n) => n.id === findingId && n.type === "vulnerability");
  if (!node) {
    return { ok: false, error: `No vulnerability node "${findingId}" in this repo's graph.` };
  }

  // Reuse the evidence verifier: "verified" here means the vulnerable snippet
  // still exists. If it can no longer be located, the fix removed it.
  const verdict = verifyFindingEvidence(
    {
      // minimal shape the verifier needs
      evidence: node.evidence,
    } as Parameters<typeof verifyFindingEvidence>[0],
    scan.repoPath
  );

  if (!verdict.verified) {
    node.status = "fixed";
    saveGraphForRepo(graph);
    return {
      ok: true,
      findingId,
      status: "fixed",
      proof: "The vulnerable code cited in this finding's evidence no longer appears in the repository.",
    };
  }

  return {
    ok: true,
    findingId,
    status: "still_open",
    proof: "The vulnerable code cited in this finding's evidence is still present in the repository.",
    aiFixPrompt: node.aiFixPrompt,
  };
}
