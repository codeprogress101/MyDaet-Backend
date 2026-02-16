/* eslint-disable no-console */
const path = require("path");
const admin = require("firebase-admin");

function parseArg(name) {
  const prefix = `--${name}=`;
  const hit = process.argv.find((arg) => arg.startsWith(prefix));
  return hit ? hit.slice(prefix.length) : null;
}

function hasFlag(name) {
  return process.argv.includes(`--${name}`);
}

function normalizeRole(raw) {
  const role = String(raw || "").trim().toLowerCase();
  if (role === "admin") return "super_admin";
  if (["super_admin", "office_admin", "moderator", "resident"].includes(role)) {
    return role;
  }
  return "resident";
}

function initAdmin() {
  if (admin.apps.length > 0) return;

  const projectId = parseArg("project") || process.env.GCLOUD_PROJECT || process.env.FIREBASE_PROJECT_ID;
  const keyPath = parseArg("key") || process.env.GOOGLE_APPLICATION_CREDENTIALS;
  const options = {};

  if (projectId) options.projectId = projectId;
  if (keyPath) {
    const absoluteKeyPath = path.isAbsolute(keyPath)
      ? keyPath
      : path.resolve(process.cwd(), keyPath);
    // eslint-disable-next-line global-require, import/no-dynamic-require
    options.credential = admin.credential.cert(require(absoluteKeyPath));
  }

  admin.initializeApp(options);
}

async function run() {
  initAdmin();
  const db = admin.firestore();
  const shouldFix = hasFlag("fix");

  const usersSnap = await db.collection("users").get();
  if (usersSnap.empty) {
    console.log("No users found.");
    return;
  }

  let checked = 0;
  let flagged = 0;
  let fixed = 0;
  let batch = db.batch();
  let batchSize = 0;

  const commitBatch = async () => {
    if (batchSize === 0) return;
    await batch.commit();
    batch = db.batch();
    batchSize = 0;
  };

  for (const doc of usersSnap.docs) {
    checked += 1;
    const data = doc.data() || {};
    const role = normalizeRole(data.role);
    const officeId = String(data.officeId || "").trim();
    const officeName = String(data.officeName || "").trim();
    const updates = {};
    const issues = [];

    if (String(data.role || "").trim().toLowerCase() === "admin") {
      issues.push("legacy admin role");
      updates.role = "super_admin";
    }

    if ((role === "moderator" || role === "office_admin") && !officeId) {
      issues.push("staff role missing officeId");
    }

    if ((role === "resident" || role === "super_admin") && (officeId || officeName)) {
      issues.push(`${role} should not have office assignment`);
      updates.officeId = null;
      updates.officeName = null;
    }

    if (issues.length > 0) {
      flagged += 1;
      console.log(
        `[ISSUE] uid=${doc.id} role=${role} officeId=${officeId || "-"} -> ${issues.join(", ")}`
      );
      if (shouldFix && Object.keys(updates).length > 0) {
        batch.set(
          doc.ref,
          {
            ...updates,
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          },
          {merge: true}
        );
        batchSize += 1;
        fixed += 1;
      }
      if (batchSize >= 400) {
        await commitBatch();
      }
    }
  }

  await commitBatch();
  console.log(`Done. checked=${checked}, flagged=${flagged}, fixed=${fixed}`);
}

run()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Audit failed:", error);
    process.exit(1);
  });
