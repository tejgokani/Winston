import { z } from "zod";

// Minimal "selection hint" contract the Context Engine needs from a playbook.
// The full Playbook model (frontmatter + Markdown body) is defined here too,
// but playbookLoader.ts (Phase 3) is what actually parses real .md files into
// it. Keeping this schema in models/ lets the Context Engine depend only on
// the shape, not on the loader, so the two stages stay independently testable.

export const FileSelectionHintSchema = z.object({
  roles: z.array(z.string()).default([]),
  matchImports: z.array(z.string()).default([]),
  matchAuthMapTags: z.array(z.string()).default([]),
  maxFiles: z.number().int().positive().default(8),
  priorityOrder: z.array(z.string()).default([]),
});
export type FileSelectionHint = z.infer<typeof FileSelectionHintSchema>;

export const SeverityHeuristicsSchema = z.object({
  critical: z.array(z.string()).default([]),
  high: z.array(z.string()).default([]),
  medium: z.array(z.string()).default([]),
  low: z.array(z.string()).default([]),
});
export type SeverityHeuristics = z.infer<typeof SeverityHeuristicsSchema>;

export const GraphNodeMappingSchema = z.object({
  primaryNodeType: z.string(),
  primaryNodeId: z.string(),
  relatedNodeIds: z.array(z.string()).default([]),
});

export const GraphEdgeMappingSchema = z.object({
  relation: z.string(),
  from: z.string(),
  to: z.string(),
});

// Beyond OWASP/CWE — a citable trail proving the playbook's guidance is
// grounded in something more specific than the same taxonomy every scanner
// already references: real incident postmortems, disclosed bug-bounty
// writeups, vendor security advisories, and original research on AI-coding
// failure patterns. Every entry must be a real, checkable source.
export const RealWorldReferenceSchema = z.object({
  title: z.string(),
  url: z.string().url(),
  type: z.enum([
    "incident_postmortem",
    "bug_bounty_disclosure",
    "vendor_security_advisory",
    "research_paper",
    "conference_talk",
    "security_blog",
  ]),
});
export type RealWorldReference = z.infer<typeof RealWorldReferenceSchema>;

export const PlaybookFrontmatterSchema = z.object({
  id: z.string(),
  title: z.string(),
  category: z.enum(["ai_security", "technology", "ai_mistakes"]),
  vulnerabilityClass: z.string(),
  appliesToStack: z.string(),
  // Stack gating for baseline playbooks: empty = universally applicable
  // (always loads); non-empty = loads only when at least one listed tag is in
  // the repo's detected tags. Technology playbooks are additionally gated via
  // registry.yaml; this field lets ai_security/ai_mistakes playbooks that are
  // conditional (NoSQL injection, XSS) opt out of stacks they can't apply to.
  requiresAnyTag: z.array(z.string()).default([]),
  deepOnly: z.boolean().default(false),
  reviewPass: z.number().int().min(1).max(3).default(1),
  owaspRefs: z.array(z.string()).default([]),
  cweRefs: z.array(z.string()).default([]),
  realWorldReferences: z.array(RealWorldReferenceSchema).default([]),
  quickModeSummary: z.string(),
  fileSelectionHint: FileSelectionHintSchema,
  severityHeuristics: SeverityHeuristicsSchema,
  graphNodeMapping: GraphNodeMappingSchema,
  graphEdgeMapping: z.array(GraphEdgeMappingSchema).default([]),
  commonAiCodingMistakes: z.array(z.string()).default([]),
  falsePositiveGuardrails: z.array(z.string()).default([]),
});
export type PlaybookFrontmatter = z.infer<typeof PlaybookFrontmatterSchema>;

export const PlaybookSchema = z.object({
  frontmatter: PlaybookFrontmatterSchema,
  body: z.string(),
  sourcePath: z.string(),
});
export type Playbook = z.infer<typeof PlaybookSchema>;

// What the Context Engine and Prompt Builder actually consume per playbook —
// either the full rendered body (deep mode) or the frontmatter's
// quick_mode_summary (quick mode).
export interface PlaybookPromptView {
  id: string;
  title: string;
  reviewPass: number;
  fileSelectionHint: FileSelectionHint;
  renderedContent: string;
}
