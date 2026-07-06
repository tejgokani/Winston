import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import type { TechnologyProfile } from "../models/techProfile.js";

interface RegistryEntry {
  tag: string;
  category: string;
  playbooks: string[];
}

interface Registry {
  dependencies: Record<string, RegistryEntry>;
  files: Record<string, RegistryEntry>;
  extensions: Record<string, RegistryEntry>;
  ciDirs: Record<string, RegistryEntry>;
}

const REGISTRY_PATH = fileURLToPath(
  new URL("../playbooks/technology/registry.yaml", import.meta.url)
);

let cachedRegistry: Registry | null = null;

export function loadRegistry(): Registry {
  if (cachedRegistry) return cachedRegistry;
  const raw = readFileSync(REGISTRY_PATH, "utf-8");
  const parsed = parseYaml(raw) as {
    dependencies?: Record<string, RegistryEntry>;
    files?: Record<string, RegistryEntry>;
    extensions?: Record<string, RegistryEntry>;
    ci_dirs?: Record<string, RegistryEntry>;
  };
  cachedRegistry = {
    dependencies: parsed.dependencies ?? {},
    files: parsed.files ?? {},
    extensions: parsed.extensions ?? {},
    ciDirs: parsed.ci_dirs ?? {},
  };
  return cachedRegistry;
}

// Monorepos keep manifests in apps/*/ and packages/*/, so detection walks a
// few levels deep instead of only reading the repo root. Skip lists and the
// visit cap keep this cheap even on large repos.
const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "out",
  ".next",
  ".nuxt",
  ".svelte-kit",
  "coverage",
  "vendor",
  "target",
  "__pycache__",
  ".venv",
  "venv",
  ".terraform",
  "bin",
  "obj",
]);
const MAX_DEPTH = 3;
const MAX_ENTRIES = 20_000;

interface RepoFileInventory {
  manifestPaths: {
    packageJson: string[];
    requirementsTxt: string[];
    pyprojectToml: string[];
    gemfile: string[];
    composerJson: string[];
  };
  fileNames: Set<string>; // basenames of files and directories seen
  extensions: Set<string>; // lowercased extensions seen, e.g. ".tf"
}

function walkRepo(repoPath: string): RepoFileInventory {
  const inv: RepoFileInventory = {
    manifestPaths: {
      packageJson: [],
      requirementsTxt: [],
      pyprojectToml: [],
      gemfile: [],
      composerJson: [],
    },
    fileNames: new Set(),
    extensions: new Set(),
  };

  let visited = 0;
  const walk = (dir: string, depth: number) => {
    if (depth > MAX_DEPTH || visited > MAX_ENTRIES) return;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      if (visited++ > MAX_ENTRIES) return;
      const fullPath = join(dir, entry);
      let isDir = false;
      try {
        isDir = statSync(fullPath).isDirectory();
      } catch {
        continue;
      }
      inv.fileNames.add(entry);
      if (isDir) {
        if (!SKIP_DIRS.has(entry) && !entry.startsWith(".")) walk(fullPath, depth + 1);
        continue;
      }
      const ext = extname(entry).toLowerCase();
      if (ext) inv.extensions.add(ext);
      switch (entry) {
        case "package.json":
          inv.manifestPaths.packageJson.push(fullPath);
          break;
        case "requirements.txt":
          inv.manifestPaths.requirementsTxt.push(fullPath);
          break;
        case "pyproject.toml":
          inv.manifestPaths.pyprojectToml.push(fullPath);
          break;
        case "Gemfile":
          inv.manifestPaths.gemfile.push(fullPath);
          break;
        case "composer.json":
          inv.manifestPaths.composerJson.push(fullPath);
          break;
      }
    }
  };
  walk(repoPath, 0);
  return inv;
}

function readDependencyKeys(inv: RepoFileInventory): string[] {
  const keys: string[] = [];

  for (const pkgJsonPath of inv.manifestPaths.packageJson) {
    try {
      const pkg = JSON.parse(readFileSync(pkgJsonPath, "utf-8"));
      keys.push(
        ...Object.keys(pkg.dependencies ?? {}),
        ...Object.keys(pkg.devDependencies ?? {})
      );
    } catch {
      // malformed package.json, skip
    }
  }

  for (const requirementsPath of inv.manifestPaths.requirementsTxt) {
    const content = readFileSync(requirementsPath, "utf-8");
    for (const line of content.split("\n")) {
      const name = line.trim().split(/[=<>~\[;]/)[0].toLowerCase().trim();
      if (name && !name.startsWith("#") && !name.startsWith("-")) keys.push(name);
    }
  }

  for (const pyprojectPath of inv.manifestPaths.pyprojectToml) {
    keys.push("pyproject.toml");
    // Loose extraction of dependency names from [project] dependencies /
    // poetry sections — quoted specifiers like "django>=4.2" or table keys.
    const content = readFileSync(pyprojectPath, "utf-8");
    const quotedRe = /["']([a-zA-Z0-9._-]+)\s*(?:[=<>~!\[][^"']*)?["']/g;
    let match: RegExpExecArray | null;
    while ((match = quotedRe.exec(content)) !== null) {
      keys.push(match[1].toLowerCase());
    }
  }

  for (const gemfilePath of inv.manifestPaths.gemfile) {
    const content = readFileSync(gemfilePath, "utf-8");
    const gemRe = /^\s*gem\s+["']([^"']+)["']/gm;
    let match: RegExpExecArray | null;
    while ((match = gemRe.exec(content)) !== null) keys.push(match[1].toLowerCase());
  }

  for (const composerPath of inv.manifestPaths.composerJson) {
    try {
      const composer = JSON.parse(readFileSync(composerPath, "utf-8"));
      keys.push(
        ...Object.keys(composer.require ?? {}),
        ...Object.keys(composer["require-dev"] ?? {})
      );
    } catch {
      // malformed composer.json, skip
    }
  }

  return keys;
}

export function detectTechnology(repoPath: string): TechnologyProfile {
  const registry = loadRegistry();
  const inv = walkRepo(repoPath);
  const depKeys = readDependencyKeys(inv);

  const matched: RegistryEntry[] = [];

  for (const key of depKeys) {
    const entry = registry.dependencies[key];
    if (entry) matched.push(entry);
  }
  for (const [fileName, entry] of Object.entries(registry.files)) {
    if (inv.fileNames.has(fileName)) matched.push(entry);
  }
  for (const [ext, entry] of Object.entries(registry.extensions)) {
    if (inv.extensions.has(ext.toLowerCase())) matched.push(entry);
  }
  if (existsSync(join(repoPath, ".github", "workflows"))) {
    const entry = registry.ciDirs[".github/workflows"];
    if (entry) matched.push(entry);
  }

  const byCategory = (cat: string) =>
    Array.from(new Set(matched.filter((m) => m.category === cat).map((m) => m.tag)));

  return {
    frameworks: byCategory("framework"),
    languages: byCategory("language"),
    databases: Array.from(
      new Set(
        matched
          .filter((m) => m.category === "database" || m.category === "cache")
          .map((m) => m.tag)
      )
    ),
    authProviders: byCategory("auth"),
    paymentProviders: byCategory("payments"),
    cloud: byCategory("cloud"),
    deployment: byCategory("deployment"),
    detectedTags: Array.from(new Set(matched.map((m) => m.tag))),
  };
}

export function playbooksForTags(tags: string[]): string[] {
  const registry = loadRegistry();
  const all = [
    ...Object.values(registry.dependencies),
    ...Object.values(registry.files),
    ...Object.values(registry.extensions),
    ...Object.values(registry.ciDirs),
  ];
  const playbooks = new Set<string>();
  for (const entry of all) {
    if (tags.includes(entry.tag)) {
      for (const pb of entry.playbooks) playbooks.add(pb);
    }
  }
  return Array.from(playbooks);
}
