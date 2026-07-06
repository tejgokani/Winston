// Canonical node-id and edge-relation vocabulary. Findings propose *drafts*
// (idHint, targetIdHint); graph/mapper.ts canonicalizes against this list so
// the same architectural concept always maps to the same node across
// findings and across scans — this is what makes cross-scan graph merging
// (and "watch the attack surface evolve") deterministic instead of relying
// on the LLM to be consistent about ids.

export const KNOWN_COMPONENT_IDS = [
  "component:authentication",
  "component:authorization",
  "component:jwt",
  "component:session_management",
  "component:secrets",
  "component:api_security",
  "component:input_validation",
  "component:file_uploads",
  "component:payments",
  "component:rate_limiting",
  "component:logging",
  "component:database",
  "component:business_logic",
] as const;

export type KnownComponentId = (typeof KNOWN_COMPONENT_IDS)[number];

export function isKnownComponentId(id: string): id is KnownComponentId {
  return (KNOWN_COMPONENT_IDS as readonly string[]).includes(id);
}

export function labelForComponentId(id: string): string {
  const name = id.replace(/^component:/, "").replace(/_/g, " ");
  return name.replace(/\b\w/g, (c) => c.toUpperCase());
}

export const EDGE_RELATIONS = [
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
] as const;

export type EdgeRelation = (typeof EDGE_RELATIONS)[number];

export function isKnownRelation(relation: string): relation is EdgeRelation {
  return (EDGE_RELATIONS as readonly string[]).includes(relation);
}
