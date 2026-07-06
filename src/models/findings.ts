import { z } from "zod";

export const EvidenceSchema = z.object({
  file: z.string(),
  lineStart: z.number().int().positive(),
  lineEnd: z.number().int().positive(),
  snippet: z.string().min(1),
});
export type Evidence = z.infer<typeof EvidenceSchema>;

export const GraphNodeDraftSchema = z.object({
  type: z.enum([
    "component",
    "vulnerability",
    "external_system",
    "data_store",
    "root_cause_marker",
  ]),
  idHint: z.string(),
  label: z.string(),
});
export type GraphNodeDraft = z.infer<typeof GraphNodeDraftSchema>;

export const GraphEdgeDraftSchema = z.object({
  targetIdHint: z.string(),
  relation: z.enum([
    "causes",
    "depends_on",
    "protects",
    "reads",
    "writes",
    "calls",
    "trusts",
    "stores",
    "authorizes",
    "authenticates",
    "exposes",
    "enables",
  ]),
  description: z.string(),
});
export type GraphEdgeDraft = z.infer<typeof GraphEdgeDraftSchema>;

export const FindingSchema = z.object({
  playbookId: z.string(),
  vulnerabilityClass: z.string(),
  title: z.string().min(1),
  severity: z.enum(["critical", "high", "medium", "low", "info"]),
  description: z.string().min(1),
  reasoning: z.string().min(1),
  evidence: z.array(EvidenceSchema).min(1),
  attackScenario: z.string().min(1),
  affectedFiles: z.array(z.string()).min(1),
  recommendedFix: z.string().min(1),
  aiFixPrompt: z.string().min(1),
  graphNode: GraphNodeDraftSchema,
  graphEdges: z.array(GraphEdgeDraftSchema).default([]),
  confidence: z.enum(["high", "medium", "low"]),
});
export type Finding = z.infer<typeof FindingSchema>;
