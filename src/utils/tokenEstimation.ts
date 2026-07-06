// Rough token estimate (chars / 4, the standard cheap heuristic) — good
// enough for the "estimated_tokens" transparency field. Not a tokenizer.
export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}
