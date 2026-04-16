/* eslint-disable no-console */
const {execFileSync} = require("child_process");
const fs = require("fs");
const path = require("path");

function parseArg(name) {
  const prefix = `--${name}=`;
  const hit = process.argv.find((arg) => arg.startsWith(prefix));
  return hit ? hit.slice(prefix.length).trim() : "";
}

function hasFlag(name) {
  return process.argv.includes(`--${name}`);
}

function printUsage() {
  console.log("Usage:");
  console.log(
    "  node scripts/check-user-managed-sa-keys.js --project=<project-id> " +
      "[--allow-accounts=email1,email2] [--warn-only]"
  );
}

function splitCsv(input) {
  return String(input || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

function runGcloud(args) {
  const gcloudBin = resolveGcloudBin();
  try {
    if (process.platform === "win32" && /\.cmd$/i.test(gcloudBin)) {
      const command = `& '${gcloudBin.replace(/'/g, "''")}' ${args
        .map((value) => quotePowerShellArg(value))
        .join(" ")}`;
      return execFileSync("powershell", ["-NoProfile", "-Command", command], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      });
    }
    return execFileSync(gcloudBin, args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (error) {
    if (error && error.code === "ENOENT") {
      throw new Error(
        "gcloud CLI not found. Install Google Cloud SDK and/or set GCLOUD_BIN."
      );
    }
    const stderr = String(error && error.stderr ? error.stderr : "").trim();
    const stdout = String(error && error.stdout ? error.stdout : "").trim();
    const message = stderr || stdout || String(error && error.message);
    throw new Error(`gcloud command failed: ${message}`);
  }
}

function quotePowerShellArg(value) {
  const text = String(value);
  if (/^[A-Za-z0-9_./:@=-]+$/.test(text)) {
    return text;
  }
  return `'${text.replace(/'/g, "''")}'`;
}

function resolveGcloudBin() {
  const fromEnv = String(process.env.GCLOUD_BIN || "").trim();
  if (fromEnv) {
    return fromEnv;
  }
  if (process.platform !== "win32") {
    return "gcloud";
  }
  const candidates = [];
  const localAppData = process.env.LOCALAPPDATA;
  if (localAppData) {
    candidates.push(
      path.join(
        localAppData,
        "Google",
        "Cloud SDK",
        "google-cloud-sdk",
        "bin",
        "gcloud.cmd"
      )
    );
  }
  const userProfile = process.env.USERPROFILE;
  if (userProfile) {
    candidates.push(
      path.join(
        userProfile,
        "AppData",
        "Local",
        "Google",
        "Cloud SDK",
        "google-cloud-sdk",
        "bin",
        "gcloud.cmd"
      )
    );
  }
  const programFiles = process.env["ProgramFiles"];
  if (programFiles) {
    candidates.push(
      path.join(
        programFiles,
        "Google",
        "Cloud SDK",
        "google-cloud-sdk",
        "bin",
        "gcloud.cmd"
      )
    );
  }
  for (const candidate of candidates) {
    if (candidate && fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return "gcloud";
}

function runGcloudJson(args) {
  const output = runGcloud(args);
  try {
    return JSON.parse(output || "[]");
  } catch (error) {
    throw new Error(`Failed to parse gcloud JSON output: ${String(error.message)}`);
  }
}

function resolveProjectId() {
  const fromArg = parseArg("project");
  if (fromArg) return fromArg;
  const fromEnv = String(
    process.env.GCLOUD_PROJECT ||
      process.env.GOOGLE_CLOUD_PROJECT ||
      process.env.FIREBASE_PROJECT_ID ||
      ""
  ).trim();
  return fromEnv;
}

function listServiceAccounts(projectId) {
  return runGcloudJson([
    "iam",
    "service-accounts",
    "list",
    "--project",
    projectId,
    "--format=json",
  ]);
}

function listUserManagedKeys(projectId, email) {
  return runGcloudJson([
    "iam",
    "service-accounts",
    "keys",
    "list",
    "--project",
    projectId,
    "--iam-account",
    email,
    "--managed-by",
    "user",
    "--format=json",
  ]);
}

function main() {
  if (hasFlag("help") || hasFlag("h")) {
    printUsage();
    process.exit(0);
  }

  const projectId = resolveProjectId();
  if (!projectId) {
    printUsage();
    throw new Error(
      "Missing project id. Use --project=<id> or set GCLOUD_PROJECT."
    );
  }

  const allowedAccounts = new Set(splitCsv(parseArg("allow-accounts")));
  const failOnKeys = !hasFlag("warn-only");
  const accounts = listServiceAccounts(projectId);
  const findings = [];

  for (const account of accounts) {
    const email = String(account && account.email ? account.email : "").trim();
    if (!email) continue;
    if (allowedAccounts.has(email)) continue;

    const keys = listUserManagedKeys(projectId, email);
    if (!Array.isArray(keys) || keys.length === 0) continue;

    findings.push({
      email,
      keys: keys.map((key) => ({
        name: String(key && key.name ? key.name : ""),
        validAfterTime: String(key && key.validAfterTime ? key.validAfterTime : ""),
      })),
    });
  }

  if (findings.length === 0) {
    console.log(
      `[PASS] No user-managed service-account keys found in project ${projectId}.`
    );
    process.exit(0);
  }

  console.error(
    `[FAIL] Found user-managed service-account keys in project ${projectId}:`
  );
  for (const finding of findings) {
    console.error(`- ${finding.email}`);
    for (const key of finding.keys) {
      const keyName = key.name || "(unknown key name)";
      const issued = key.validAfterTime || "unknown issue time";
      console.error(`  - ${keyName} (issued: ${issued})`);
    }
  }
  console.error(
    "Policy: disable then delete unnecessary user-managed keys. " +
      "If temporary exception is required, use --allow-accounts=email1,email2."
  );

  if (failOnKeys) {
    process.exit(2);
  }
  process.exit(0);
}

try {
  main();
} catch (error) {
  console.error(`[ERROR] ${String(error && error.message ? error.message : error)}`);
  process.exit(1);
}
