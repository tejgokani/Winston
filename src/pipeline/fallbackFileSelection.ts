import { readFileSync, readdirSync, statSync } from "node:fs";
import { extname, join, relative } from "node:path";
import type { FileContentRef } from "../models/securityContext.js";
import { isIgnoredDir, isIgnoredFile } from "../utils/ignorePatterns.js";

// scanner.ts's LANGUAGE_BY_EXT has no entries for mobile-native languages, so
// a pure Android/iOS/Flutter repo can come back with zero structural
// importantFiles. This is a deliberate, cheap fallback for that gap: a plain
// extension-based walk, not structural parsing — used only when the primary
// role/import-based selection returned nothing for a mobile-tagged stack.
const MOBILE_EXTENSIONS = new Set([".kt", ".swift", ".dart", ".java", ".m", ".mm"]);

export function mobileExtensionFallback(repoPath: string, maxFiles: number): FileContentRef[] {
  const refs: FileContentRef[] = [];
  const stack: string[] = [repoPath];

  while (stack.length > 0 && refs.length < maxFiles) {
    const dir = stack.pop()!;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (refs.length >= maxFiles) break;
      const fullPath = join(dir, entry);
      let stat;
      try {
        stat = statSync(fullPath);
      } catch {
        continue;
      }
      if (stat.isDirectory()) {
        if (!isIgnoredDir(entry)) stack.push(fullPath);
      } else if (stat.isFile()) {
        if (isIgnoredFile(entry) || !MOBILE_EXTENSIONS.has(extname(entry))) continue;
        let content: string;
        try {
          content = readFileSync(fullPath, "utf-8");
        } catch {
          continue;
        }
        refs.push({
          path: relative(repoPath, fullPath),
          role: "generic",
          content,
          truncated: false,
        });
      }
    }
  }

  return refs;
}
