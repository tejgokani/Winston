import { readFileSync, readdirSync, statSync } from "node:fs";
import { extname, join, relative, sep } from "node:path";
import type {
  AuthEntry,
  FileInfo,
  RepoSummary,
  RouteEntry,
} from "../models/repoContext.js";
import { isIgnoredDir, isIgnoredFile } from "../utils/ignorePatterns.js";

const LANGUAGE_BY_EXT: Record<string, string> = {
  ".ts": "TypeScript",
  ".tsx": "TypeScript",
  ".js": "JavaScript",
  ".jsx": "JavaScript",
  ".mjs": "JavaScript",
  ".py": "Python",
  ".go": "Go",
  ".rs": "Rust",
  ".java": "Java",
  ".rb": "Ruby",
  ".php": "PHP",
};

const ROLE_RULES: Array<{
  role: FileInfo["role"];
  test: (path: string) => boolean;
}> = [
  { role: "ci_cd", test: (p) => p.includes(".github/workflows/") },
  { role: "docker", test: (p) => /(^|\/)(Dockerfile|docker-compose.*\.ya?ml)$/i.test(p) },
  { role: "auth", test: (p) => /auth|session|jwt|passport|login/i.test(p) },
  { role: "payment", test: (p) => /stripe|payment|billing|checkout/i.test(p) },
  { role: "upload_handler", test: (p) => /upload|multer|storage/i.test(p) },
  { role: "database", test: (p) => /prisma|schema\.sql|migrations?\//i.test(p) },
  {
    role: "middleware",
    test: (p) => /middleware/i.test(p),
  },
  {
    role: "config",
    test: (p) =>
      /(^|\/)(\.env|config|settings)/i.test(p) || /\.config\.(js|ts|json)$/i.test(p),
  },
  {
    role: "route_handler",
    test: (p) => /(^|\/)(routes?|controllers?|api|pages\/api|app\/api)\//i.test(p),
  },
];

const AUTH_IMPORT_PATTERNS = [
  "next-auth",
  "passport",
  "jsonwebtoken",
  "jose",
  "@supabase/auth-helpers",
  "express-session",
  "pyjwt",
  "python-jose",
];

// Captures method + path always; captures a single leading middleware
// identifier when the call site looks like `.get(path, middlewareName, ...)`.
// Full multi-middleware chains and non-identifier handlers require a real
// parser (tree-sitter) rather than regex — this is a deliberate interim
// simplification, not full structural extraction.
const ROUTE_DECORATOR_RE =
  /\b(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*(?:([A-Za-z_$][\w$]*)\s*,\s*)?/gi;

function classifyRole(relPath: string): FileInfo["role"] {
  for (const rule of ROLE_RULES) {
    if (rule.test(relPath)) return rule.role;
  }
  return "generic";
}

// Cheap, regex-based module-name extraction — not a real parser. Reads only
// the first ~2000 chars (imports live at the top of virtually every file in
// our supported languages) and caps at 50 matches so this stays O(1)-ish per
// file even on pathological inputs.
const IMPORT_SCAN_CHAR_LIMIT = 2000;
const IMPORT_MATCH_CAP = 50;
const IMPORT_RE =
  /(?:require\(\s*['"]([^'"]+)['"]\s*\)|from\s+['"]([^'"]+)['"]|import\s+['"]([^'"]+)['"])/g;

function extractImportedModules(content: string): string[] {
  const slice = content.slice(0, IMPORT_SCAN_CHAR_LIMIT);
  const modules: string[] = [];
  let match: RegExpExecArray | null;
  IMPORT_RE.lastIndex = 0;
  while ((match = IMPORT_RE.exec(slice)) !== null && modules.length < IMPORT_MATCH_CAP) {
    const name = match[1] ?? match[2] ?? match[3];
    if (name) modules.push(name);
  }
  return modules;
}

function walk(repoPath: string): string[] {
  const results: string[] = [];
  const stack: string[] = [repoPath];

  while (stack.length > 0) {
    const dir = stack.pop()!;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      continue;
    }
    for (const entry of entries) {
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
        if (!isIgnoredFile(entry)) results.push(fullPath);
      }
    }
  }
  return results;
}

function extractRoutes(relPath: string, content: string): RouteEntry[] {
  const routes: RouteEntry[] = [];
  let match: RegExpExecArray | null;
  ROUTE_DECORATOR_RE.lastIndex = 0;
  while ((match = ROUTE_DECORATOR_RE.exec(content)) !== null) {
    routes.push({
      method: match[1].toUpperCase(),
      path: match[2],
      handlerFile: relPath,
      handlerSymbol: "anonymous",
      middlewareChain: match[3] ? [match[3]] : [],
    });
  }
  return routes;
}

function extractAuthEntries(relPath: string, content: string): AuthEntry[] {
  const entries: AuthEntry[] = [];
  for (const pattern of AUTH_IMPORT_PATTERNS) {
    if (content.includes(pattern)) {
      entries.push({
        file: relPath,
        matchedPattern: pattern,
        kind: "import",
      });
    }
  }
  return entries;
}

function buildFolderTree(paths: string[], repoPath: string, maxDepth = 3): string {
  const lines = new Set<string>();
  for (const p of paths) {
    const rel = relative(repoPath, p);
    const parts = rel.split(sep);
    for (let depth = 1; depth <= Math.min(parts.length, maxDepth); depth++) {
      lines.add(parts.slice(0, depth).join("/"));
    }
  }
  return Array.from(lines).sort().join("\n");
}

function relevanceScore(role: FileInfo["role"], sizeBytes: number): number {
  const roleWeight: Record<FileInfo["role"], number> = {
    auth: 10,
    payment: 9,
    middleware: 8,
    route_handler: 7,
    upload_handler: 7,
    database: 6,
    config: 6,
    docker: 4,
    ci_cd: 4,
    generic: 1,
  };
  const sizePenalty = Math.min(sizeBytes / 50_000, 3);
  return roleWeight[role] - sizePenalty;
}

export function scanRepository(repoPath: string): RepoSummary {
  const allPaths = walk(repoPath);
  const languages: Record<string, number> = {};
  const importantFiles: FileInfo[] = [];
  const routeMap: RouteEntry[] = [];
  const authMap: AuthEntry[] = [];

  for (const fullPath of allPaths) {
    const relPath = relative(repoPath, fullPath);
    const ext = extname(fullPath);
    const language = LANGUAGE_BY_EXT[ext];
    const stat = statSync(fullPath);

    if (language) {
      let content = "";
      try {
        content = readFileSync(fullPath, "utf-8");
      } catch {
        continue;
      }
      const loc = content.split("\n").length;
      languages[language] = (languages[language] ?? 0) + loc;

      const role = classifyRole(relPath);
      importantFiles.push({
        path: relPath,
        role,
        sizeBytes: stat.size,
        language,
        relevanceScore: relevanceScore(role, stat.size),
        symbolSummary: [],
        importedModules: extractImportedModules(content),
      });

      routeMap.push(...extractRoutes(relPath, content));
      authMap.push(...extractAuthEntries(relPath, content));
    }
  }

  importantFiles.sort((a, b) => b.relevanceScore - a.relevanceScore);

  return {
    repoPath,
    fileCount: allPaths.length,
    importantFiles: importantFiles.slice(0, 150),
    routeMap,
    authMap,
    folderTree: buildFolderTree(allPaths, repoPath),
    languages,
  };
}
