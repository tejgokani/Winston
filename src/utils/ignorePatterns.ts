const IGNORED_DIR_NAMES = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  ".next",
  "__pycache__",
  ".venv",
  "venv",
  "target",
  ".turbo",
  "coverage",
  ".cache",
  ".tokensave",
]);

const IGNORED_FILE_EXTENSIONS = new Set([
  ".lock",
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".svg",
  ".ico",
  ".woff",
  ".woff2",
  ".ttf",
  ".map",
]);

const IGNORED_FILE_NAMES = new Set([
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
]);

export function isIgnoredDir(dirName: string): boolean {
  return IGNORED_DIR_NAMES.has(dirName) || dirName.startsWith(".");
}

export function isIgnoredFile(fileName: string): boolean {
  if (IGNORED_FILE_NAMES.has(fileName)) return true;
  const dotIndex = fileName.lastIndexOf(".");
  if (dotIndex === -1) return false;
  const ext = fileName.slice(dotIndex);
  return IGNORED_FILE_EXTENSIONS.has(ext);
}
