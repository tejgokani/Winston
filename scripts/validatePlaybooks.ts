import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadPlaybookFile } from "../src/pipeline/playbookLoader.js";

const PLAYBOOKS_DIR = fileURLToPath(new URL("../src/playbooks/", import.meta.url));

function findPlaybookFiles(dir: string, base: string): string[] {
  const results: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (entry.startsWith("_")) continue; // _schema/, etc.
    const fullPath = join(dir, entry);
    const relPath = join(base, entry);
    if (statSync(fullPath).isDirectory()) {
      results.push(...findPlaybookFiles(fullPath, relPath));
    } else if (entry.endsWith(".md")) {
      results.push(relPath);
    }
  }
  return results;
}

const files = findPlaybookFiles(PLAYBOOKS_DIR, "");
let failures = 0;

for (const relPath of files) {
  try {
    const playbook = loadPlaybookFile(relPath);
    console.log(`OK   ${relPath} (${playbook.frontmatter.id})`);
  } catch (error) {
    failures++;
    console.error(`FAIL ${relPath}`);
    console.error(`     ${(error as Error).message}`);
  }
}

console.log(`\n${files.length - failures}/${files.length} playbooks valid.`);
if (failures > 0) process.exit(1);
