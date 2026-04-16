/* eslint-disable no-console */
const fs = require("fs");
const path = require("path");

const REPO_ROOT = path.resolve(__dirname, "..", "..");
const SKIP_DIRS = new Set([
  ".git",
  ".firebase",
  ".vscode",
  "node_modules",
  "build",
  "dist",
  "tmp",
  "temp",
  "coverage",
  ".nyc_output",
]);

const FILE_NAME_PATTERNS = [
  /service-account/i,
  /serviceaccount/i,
  /firebase-adminsdk-/i,
  /google-credentials/i,
  /gcp-key/i,
  /gcloud-key/i,
];

const FILE_CONTENT_PATTERNS = [
  /-----BEGIN PRIVATE KEY-----/i,
  /"type"\s*:\s*"service_account"/i,
  /"private_key"\s*:\s*"/i,
  /"client_email"\s*:\s*".+\.gserviceaccount\.com"/i,
];

const TEXT_EXTENSIONS = new Set([
  ".json",
  ".env",
  ".yaml",
  ".yml",
  ".txt",
  ".md",
  ".ts",
  ".js",
  ".cjs",
  ".mjs",
]);
const SELF_RELATIVE_PATH = normalizeForCompare(path.relative(REPO_ROOT, __filename));

function splitCsv(input) {
  return String(input || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

function parseArg(name) {
  const prefix = `--${name}=`;
  const hit = process.argv.find((arg) => arg.startsWith(prefix));
  return hit ? hit.slice(prefix.length).trim() : "";
}

function normalizeForCompare(filePath) {
  return filePath.replace(/\\/g, "/").toLowerCase();
}

function shouldAllow(relativePath, allowSet) {
  const normalized = normalizeForCompare(relativePath);
  for (const allowed of allowSet) {
    if (normalized === allowed || normalized.startsWith(`${allowed}/`)) {
      return true;
    }
  }
  return false;
}

function isTextCandidate(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (TEXT_EXTENSIONS.has(ext)) return true;
  const base = path.basename(filePath).toLowerCase();
  if (base.includes(".env")) return true;
  return false;
}

function walkDir(dirPath, callback) {
  const entries = fs.readdirSync(dirPath, {withFileTypes: true});
  for (const entry of entries) {
    if (entry.name === "." || entry.name === "..") continue;
    const absolute = path.join(dirPath, entry.name);
    const relative = path.relative(REPO_ROOT, absolute);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      callback({
        type: "dir",
        absolute,
        relative,
      });
      walkDir(absolute, callback);
      continue;
    }
    callback({
      type: "file",
      absolute,
      relative,
    });
  }
}

function main() {
  const allowPaths = splitCsv(
    parseArg("allow-paths") || process.env.ALLOW_KEY_SCAN_PATHS
  ).map((value) => normalizeForCompare(value));
  const allowSet = new Set(allowPaths);
  const findings = [];

  walkDir(REPO_ROOT, ({type, absolute, relative}) => {
    if (type !== "file") return;
    if (normalizeForCompare(relative) === SELF_RELATIVE_PATH) return;
    if (shouldAllow(relative, allowSet)) return;

    const baseName = path.basename(absolute);
    const byFileName = FILE_NAME_PATTERNS.some((pattern) => pattern.test(baseName));
    if (byFileName) {
      findings.push({
        relative,
        reason: "filename-pattern",
      });
      return;
    }

    if (!isTextCandidate(absolute)) return;
    let content = "";
    try {
      content = fs.readFileSync(absolute, "utf8");
    } catch (_error) {
      return;
    }
    const byContent = FILE_CONTENT_PATTERNS.some((pattern) => pattern.test(content));
    if (byContent) {
      findings.push({
        relative,
        reason: "content-pattern",
      });
    }
  });

  if (findings.length === 0) {
    console.log("[PASS] No local service-account key material detected.");
    process.exit(0);
  }

  console.error("[FAIL] Potential service-account key material detected:");
  for (const finding of findings) {
    console.error(`- ${finding.relative} (${finding.reason})`);
  }
  console.error(
    "Remove keys from disk/repo, rotate if exposed, and use Firebase-managed runtime credentials."
  );
  process.exit(2);
}

try {
  main();
} catch (error) {
  console.error(`[ERROR] ${String(error && error.message ? error.message : error)}`);
  process.exit(1);
}
