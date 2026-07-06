import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";

// Per-repo configuration. Teams can drop a `winston.config.json` at the repo
// root to set a minimum severity threshold for reports and to disable
// specific built-in (or custom) playbooks by id — without touching
// suppressions (accepted-risk findings) or forking playbook files. Mirrors
// suppressions.ts's error handling exactly: missing or invalid config is
// silently treated as defaults, never thrown, so a scan never fails because
// of a malformed config file.

export const WinstonConfigSchema = z.object({
  minSeverity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
  disabledPlaybooks: z.array(z.string()).default([]),
});
export type WinstonConfig = z.infer<typeof WinstonConfigSchema>;

const DEFAULT_CONFIG: WinstonConfig = { disabledPlaybooks: [] };

export function loadWinstonConfig(repoPath: string): WinstonConfig {
  const file = join(repoPath, "winston.config.json");
  if (!existsSync(file)) return DEFAULT_CONFIG;
  try {
    const raw = readFileSync(file, "utf-8");
    const parsed = JSON.parse(raw);
    const result = WinstonConfigSchema.safeParse(parsed);
    if (!result.success) {
      console.error(`[winston] ignoring invalid winston.config.json: ${result.error.message}`);
      return DEFAULT_CONFIG;
    }
    return result.data;
  } catch (e) {
    console.error(`[winston] ignoring unreadable winston.config.json: ${(e as Error).message}`);
    return DEFAULT_CONFIG;
  }
}
