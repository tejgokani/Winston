import { z } from "zod";
import { AuthEntrySchema, RouteEntrySchema } from "./repoContext.js";
import { TechnologyProfileSchema } from "./techProfile.js";

export const FileContentRefSchema = z.object({
  path: z.string(),
  role: z.string(),
  content: z.string(),
  truncated: z.boolean(),
});
export type FileContentRef = z.infer<typeof FileContentRefSchema>;

export const DependencyFlagSchema = z.object({
  name: z.string(),
  reason: z.string(),
});
export type DependencyFlag = z.infer<typeof DependencyFlagSchema>;

export const SecurityContextPayloadSchema = z.object({
  repoSummaryProse: z.string(),
  architectureSummaryProse: z.string(),
  technologySummary: TechnologyProfileSchema,
  dependencySummary: z.array(DependencyFlagSchema),
  routeMap: z.array(RouteEntrySchema),
  authMap: z.array(AuthEntrySchema),
  folderTree: z.string().default(""),
  fileContents: z.array(FileContentRefSchema),
  playbookIds: z.array(z.string()),
  securityAssumptions: z.array(z.string()),
  byteBudget: z.object({
    limit: z.number().int().positive(),
    used: z.number().int().nonnegative(),
  }),
});
export type SecurityContextPayload = z.infer<typeof SecurityContextPayloadSchema>;
