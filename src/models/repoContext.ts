import { z } from "zod";

export const FileInfoSchema = z.object({
  path: z.string(),
  role: z.enum([
    "route_handler",
    "middleware",
    "auth",
    "config",
    "payment",
    "upload_handler",
    "database",
    "ci_cd",
    "docker",
    "generic",
  ]),
  sizeBytes: z.number().int().nonnegative(),
  language: z.string(),
  relevanceScore: z.number(),
  symbolSummary: z.array(z.string()).default([]),
  // Cheap regex-extracted module names from require()/import/from statements
  // in the file's first ~2000 chars (or full content if smaller). Lets the
  // Context Engine match playbooks' fileSelectionHint.matchImports even when
  // a file's role doesn't land in the filename-based role enum below (AI/ML,
  // mobile, desktop stacks). Not a real parser — best-effort, capped.
  importedModules: z.array(z.string()).default([]),
});
export type FileInfo = z.infer<typeof FileInfoSchema>;

export const RouteEntrySchema = z.object({
  method: z.string(),
  path: z.string(),
  handlerFile: z.string(),
  handlerSymbol: z.string(),
  middlewareChain: z.array(z.string()).default([]),
});
export type RouteEntry = z.infer<typeof RouteEntrySchema>;

export const AuthEntrySchema = z.object({
  file: z.string(),
  symbol: z.string().optional(),
  matchedPattern: z.string(),
  kind: z.enum(["import", "decorator", "middleware_call"]),
});
export type AuthEntry = z.infer<typeof AuthEntrySchema>;

export const RepoSummarySchema = z.object({
  repoPath: z.string(),
  fileCount: z.number().int().nonnegative(),
  importantFiles: z.array(FileInfoSchema).max(150),
  routeMap: z.array(RouteEntrySchema),
  authMap: z.array(AuthEntrySchema),
  folderTree: z.string(),
  languages: z.record(z.string(), z.number()),
});
export type RepoSummary = z.infer<typeof RepoSummarySchema>;
