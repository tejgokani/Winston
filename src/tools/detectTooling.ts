import { detectAiTooling, type ToolingReport } from "../detect/aiTooling.js";

export interface DetectToolingInput {
  repoPath: string;
}

export function detectTooling({ repoPath }: DetectToolingInput): ToolingReport {
  return detectAiTooling(repoPath);
}
