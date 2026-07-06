import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import matter from "gray-matter";
import {
  PlaybookFrontmatterSchema,
  type Playbook,
  type PlaybookPromptView,
} from "../models/playbook.js";
import { playbooksForTags } from "./techDetector.js";
import { loadWinstonConfig } from "../config/winstonConfig.js";

const PLAYBOOKS_ROOT_URL = new URL("../playbooks/", import.meta.url);

// Always-loaded regardless of detected stack — technology-agnostic playbooks
// (ai_security/* and ai_mistakes/*) broadly applicable to almost any server.
// Tag-gated playbooks (Supabase, Stripe, ai_llm_api_security, rate_limiting,
// file_uploads, etc.) live in technology/registry.yaml instead and only load
// when their exact stack tag is detected — techDetector.ts reads the repo's
// manifest first, then playbooksForTags() resolves only the matching
// playbooks, so no stack-irrelevant tech playbook ever reaches the prompt.
// business_logic.md and some ai_mistakes/* entries are deepOnly, so
// selectPlaybooks naturally excludes them in quick mode even though they're
// listed here.
const BASELINE_PLAYBOOK_PATHS = [
  "ai_security/authorization.md",
  "ai_security/secrets_management.md",
  "ai_security/business_logic.md",
  "ai_security/environment_secrets_exposure.md",
  "ai_security/cors_misconfiguration.md",
  "ai_security/webhook_verification.md",
  "ai_security/ssrf.md",
  "ai_security/xss.md",
  "ai_security/command_injection.md",
  "ai_security/input_validation.md",
  "ai_security/session_management.md",
  "ai_security/logging_and_error_handling.md",
  "ai_security/path_traversal.md",
  "ai_security/open_redirect.md",
  "ai_security/security_headers.md",
  "ai_security/dependency_supply_chain.md",
  "ai_security/cryptographic_failures.md",
  "ai_security/race_conditions.md",
  // Stack-conditional (gated by requiresAnyTag frontmatter): load only when a
  // matching tag is present, otherwise silently excluded by selectPlaybooks.
  "ai_security/nosql_injection.md",
  "ai_security/ssti.md",
  "ai_security/csrf.md",
  "ai_security/mass_assignment.md",
  "ai_security/xxe.md",
  "ai_mistakes/hallucinated_dependencies.md",
  "ai_mistakes/error_swallowing_and_fake_success.md",
  "ai_mistakes/test_manipulation_to_pass.md",
  "ai_mistakes/destructive_operations_without_safeguards.md",
  "ai_mistakes/logic_duplication_and_drift.md",
  "ai_mistakes/unrequested_scope_creep.md",
];

export function loadPlaybookFile(relativePath: string): Playbook {
  const fullPath = fileURLToPath(new URL(relativePath, PLAYBOOKS_ROOT_URL));
  const raw = readFileSync(fullPath, "utf-8");
  const parsed = matter(raw);

  const result = PlaybookFrontmatterSchema.safeParse(parsed.data);
  if (!result.success) {
    throw new Error(
      `Invalid playbook frontmatter in ${relativePath}: ${result.error.message}`
    );
  }

  return {
    frontmatter: result.data,
    body: parsed.content.trim(),
    sourcePath: relativePath,
  };
}

function playbookFileExists(relativePath: string): boolean {
  return existsSync(fileURLToPath(new URL(relativePath, PLAYBOOKS_ROOT_URL)));
}

// Custom / org playbooks: teams drop their own `.md` files (same frontmatter
// schema) under <repo>/.winston/playbooks/. They go through the exact same
// stack gating as built-ins, so an org can extend Winston with internal rules
// without touching the package. Invalid custom playbooks are skipped with a
// warning rather than failing the whole scan.
function loadCustomPlaybook(absPath: string): Playbook {
  const raw = readFileSync(absPath, "utf-8");
  const parsed = matter(raw);
  const result = PlaybookFrontmatterSchema.safeParse(parsed.data);
  if (!result.success) {
    throw new Error(`Invalid custom playbook frontmatter in ${absPath}: ${result.error.message}`);
  }
  return { frontmatter: result.data, body: parsed.content.trim(), sourcePath: absPath };
}

export function loadCustomPlaybooks(repoPath: string): Playbook[] {
  const dir = join(repoPath, ".winston", "playbooks");
  if (!existsSync(dir)) return [];
  const out: Playbook[] = [];
  const walk = (d: string) => {
    for (const entry of readdirSync(d)) {
      if (entry.startsWith(".")) continue;
      const full = join(d, entry);
      if (statSync(full).isDirectory()) walk(full);
      else if (entry.endsWith(".md")) {
        try {
          out.push(loadCustomPlaybook(full));
        } catch (e) {
          console.error(`[winston] skipping custom playbook: ${(e as Error).message}`);
        }
      }
    }
  };
  walk(dir);
  return out;
}

// Map of custom-playbook id → absolute path for a repo, so get_playbook can
// resolve a custom body the built-in id index doesn't know about.
export function customPlaybookPaths(repoPath: string): Record<string, string> {
  const map: Record<string, string> = {};
  for (const pb of loadCustomPlaybooks(repoPath)) map[pb.frontmatter.id] = pb.sourcePath;
  return map;
}

export function loadPlaybookFromAbsPath(absPath: string): Playbook {
  return loadCustomPlaybook(absPath);
}

export function selectPlaybooks(
  detectedTags: string[],
  mode: "quick" | "deep",
  repoPath?: string
): PlaybookPromptView[] {
  const techPaths = playbooksForTags(detectedTags);
  const allPaths = Array.from(new Set([...BASELINE_PLAYBOOK_PATHS, ...techPaths]));

  // registry.yaml may reference technology playbooks that haven't been
  // authored yet (extensibility over day-one coverage) — skip those rather
  // than fail the whole scan. A playbook file that exists but fails to
  // parse/validate is a real bug and still throws.
  const builtIn = allPaths.filter((p) => playbookFileExists(p)).map((p) => loadPlaybookFile(p));
  const custom = repoPath ? loadCustomPlaybooks(repoPath) : [];
  const disabledPlaybooks = repoPath ? loadWinstonConfig(repoPath).disabledPlaybooks : [];

  // Dedupe by id (a custom playbook may intentionally override a built-in).
  const byId = new Map<string, Playbook>();
  for (const pb of [...builtIn, ...custom]) byId.set(pb.frontmatter.id, pb);

  const playbooks = [...byId.values()]
    .filter((pb) => mode === "deep" || !pb.frontmatter.deepOnly)
    // Stack gating: a playbook that declares requiresAnyTag only loads when the
    // repo actually has one of those tags. This is the "hit the exact playbook,
    // ignore all others" contract — applied identically to custom playbooks.
    .filter(
      (pb) =>
        pb.frontmatter.requiresAnyTag.length === 0 ||
        pb.frontmatter.requiresAnyTag.some((t) => detectedTags.includes(t))
    )
    .filter((pb) => !disabledPlaybooks.includes(pb.frontmatter.id))
    .sort((a, b) => a.frontmatter.reviewPass - b.frontmatter.reviewPass);

  // Both modes ship only the quickModeSummary inline. The full methodology body
  // is fetched on demand via get_playbook, one review pass at a time — the
  // model never pays tokens for a playbook body it hasn't decided to execute.
  return playbooks.map((pb) => ({
    id: pb.frontmatter.id,
    title: pb.frontmatter.title,
    reviewPass: pb.frontmatter.reviewPass,
    fileSelectionHint: pb.frontmatter.fileSelectionHint,
    renderedContent: pb.frontmatter.quickModeSummary,
  }));
}

// --- id-based lookup (used by the get_playbook tool) ---------------------

let cachedIdIndex: Map<string, string> | null = null;

function walkPlaybookFiles(dir: string, base: string): string[] {
  const results: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (entry.startsWith("_") || entry.startsWith(".")) continue; // _schema/, dotfiles
    const fullPath = join(dir, entry);
    const relPath = base ? `${base}/${entry}` : entry;
    if (statSync(fullPath).isDirectory()) {
      results.push(...walkPlaybookFiles(fullPath, relPath));
    } else if (entry.endsWith(".md")) {
      results.push(relPath);
    }
  }
  return results;
}

export function playbookIdIndex(): Map<string, string> {
  if (cachedIdIndex) return cachedIdIndex;
  const root = fileURLToPath(PLAYBOOKS_ROOT_URL);
  const index = new Map<string, string>();
  for (const relPath of walkPlaybookFiles(root, "")) {
    try {
      const pb = loadPlaybookFile(relPath);
      index.set(pb.frontmatter.id, relPath);
    } catch {
      // invalid playbooks are caught by validate-playbooks; don't break lookup
    }
  }
  cachedIdIndex = index;
  return index;
}

export function loadPlaybookById(id: string): Playbook | null {
  const relPath = playbookIdIndex().get(id);
  return relPath ? loadPlaybookFile(relPath) : null;
}
