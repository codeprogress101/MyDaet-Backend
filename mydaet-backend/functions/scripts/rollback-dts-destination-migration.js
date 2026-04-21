/* eslint-disable no-console */
const fs = require("fs");
const path = require("path");
const admin = require("firebase-admin");

const SCRIPT_ACTOR = "script:rollback-dts-destination-migration";
const RUNS_COLLECTION = "dts_distribution_backfill_runs";

function parseArg(name) {
  const prefix = `--${name}=`;
  const hit = process.argv.find((arg) => arg.startsWith(prefix));
  return hit ? hit.slice(prefix.length) : null;
}

function hasFlag(name) {
  return process.argv.includes(`--${name}`);
}

function allowServiceAccountKey() {
  if (hasFlag("allow-service-account-key")) return true;
  const raw = String(process.env.ALLOW_SERVICE_ACCOUNT_KEY || "").trim().toLowerCase();
  return raw === "1" || raw === "true" || raw === "yes";
}

function reportPathFromArg() {
  const filePath = parseArg("report");
  if (!filePath) return null;
  return path.isAbsolute(filePath) ? filePath : path.resolve(process.cwd(), filePath);
}

function toReportSafe(value) {
  if (value instanceof admin.firestore.Timestamp) {
    return value.toDate().toISOString();
  }
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (Array.isArray(value)) {
    return value.map((entry) => toReportSafe(entry));
  }
  if (value && typeof value === "object") {
    const mapped = {};
    for (const [key, entry] of Object.entries(value)) {
      mapped[key] = toReportSafe(entry);
    }
    return mapped;
  }
  return value;
}

function initAdmin() {
  if (admin.apps.length > 0) return;

  const projectId = parseArg("project") || process.env.GCLOUD_PROJECT || process.env.FIREBASE_PROJECT_ID;
  const keyPath = parseArg("key") || process.env.GOOGLE_APPLICATION_CREDENTIALS;
  const options = {};
  if (projectId) options.projectId = projectId;

  if (keyPath) {
    if (!allowServiceAccountKey()) {
      throw new Error(
        "Refusing to load a JSON service-account key without explicit approval. " +
          "Use --allow-service-account-key (or ALLOW_SERVICE_ACCOUNT_KEY=true) " +
          "only for approved break-glass operations."
      );
    }
    console.warn(
      "[security] Loading service-account key from keyPath. " +
      "Ensure key file is stored securely and deleted after use."
    );
    const absoluteKeyPath = path.isAbsolute(keyPath) ?
      keyPath :
      path.resolve(process.cwd(), keyPath);
    // eslint-disable-next-line global-require, import/no-dynamic-require
    options.credential = admin.credential.cert(require(absoluteKeyPath));
  }

  admin.initializeApp(options);
}

function buildRestorePatch(beforeFields, missingFields) {
  const patch = {};
  for (const [field, value] of Object.entries(beforeFields || {})) {
    patch[field] = value;
  }
  for (const field of missingFields || []) {
    patch[field] = admin.firestore.FieldValue.delete();
  }
  patch.updatedAt = admin.firestore.FieldValue.serverTimestamp();
  return patch;
}

async function run() {
  const runId = parseArg("run-id");
  const apply = hasFlag("apply");
  const reportPath = reportPathFromArg();
  if (!runId) {
    throw new Error("run-id is required. Usage: --run-id=<migrationRunId>");
  }

  initAdmin();
  const db = admin.firestore();
  const runRef = db.collection(RUNS_COLLECTION).doc(runId);
  const runSnap = await runRef.get();
  if (!runSnap.exists) {
    throw new Error(`Migration run not found: ${runId}`);
  }

  const itemsSnap = await runRef.collection("items").get();
  const report = {
    script: SCRIPT_ACTOR,
    runId,
    apply,
    generatedAt: new Date().toISOString(),
    items: itemsSnap.size,
    toRestore: 0,
    toDeleteDestinations: 0,
    samples: [],
  };

  const plans = [];
  for (const row of itemsSnap.docs) {
    const data = row.data() || {};
    const docId = String(data.docId || row.id).trim();
    if (!docId) continue;
    const destinationId = String(data.destinationId || "").trim();
    const destinationCreated = data.destinationCreated === true && destinationId.length > 0;
    plans.push({
      docId,
      restorePatch: buildRestorePatch(data.beforeFields || {}, data.missingFields || []),
      destinationId: destinationCreated ? destinationId : null,
    });
    report.toRestore += 1;
    if (destinationCreated) {
      report.toDeleteDestinations += 1;
    }
    if (report.samples.length < 40) {
      report.samples.push({
        docId,
        destinationId: destinationCreated ? destinationId : null,
      });
    }
  }

  if (!apply) {
    if (reportPath) {
      fs.mkdirSync(path.dirname(reportPath), {recursive: true});
      fs.writeFileSync(reportPath, JSON.stringify(toReportSafe(report), null, 2));
      console.log(`[md-7] wrote rollback dry-run report: ${reportPath}`);
    }
    console.log("[md-7] rollback dry-run summary:", JSON.stringify(toReportSafe(report)));
    return;
  }

  let batch = db.batch();
  let opCount = 0;
  const flush = async () => {
    if (opCount === 0) return;
    await batch.commit();
    batch = db.batch();
    opCount = 0;
  };
  const setMerge = (ref, payload) => {
    batch.set(ref, payload, {merge: true});
    opCount += 1;
  };
  const deleteRef = (ref) => {
    batch.delete(ref);
    opCount += 1;
  };

  for (const plan of plans) {
    const docRef = db.collection("dts_documents").doc(plan.docId);
    setMerge(docRef, plan.restorePatch);
    if (plan.destinationId) {
      deleteRef(docRef.collection("destinations").doc(plan.destinationId));
    }
    if (opCount >= 360) {
      await flush();
    }
  }
  await flush();

  await runRef.set({
    rollbackAppliedAt: admin.firestore.FieldValue.serverTimestamp(),
    rollbackAppliedBy: SCRIPT_ACTOR,
    rollbackItems: plans.length,
  }, {merge: true});

  if (reportPath) {
    fs.mkdirSync(path.dirname(reportPath), {recursive: true});
    fs.writeFileSync(reportPath, JSON.stringify(toReportSafe(report), null, 2));
    console.log(`[md-7] wrote rollback apply report: ${reportPath}`);
  }
  console.log("[md-7] rollback apply summary:", JSON.stringify(toReportSafe(report)));
}

run()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("[md-7] rollback failed:", error);
    process.exit(1);
  });
