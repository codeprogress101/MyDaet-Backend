/* eslint-disable no-console */
const path = require("path");
const admin = require("firebase-admin");

const SCRIPT_ACTOR = "script:backfill-dts-legacy-qr-batch";
const LEGACY_BATCH_ID = "legacy-imported-qr-batch";
const LEGACY_BATCH_LABEL = "QR Batch Legacy Imported";

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

function initAdmin() {
  if (admin.apps.length > 0) return;
  const projectId = parseArg("project") || process.env.GCLOUD_PROJECT || process.env.FIREBASE_PROJECT_ID;
  const keyPath = parseArg("key") || process.env.GOOGLE_APPLICATION_CREDENTIALS;
  const options = {};
  if (projectId) options.projectId = projectId;

  if (keyPath) {
    if (!allowServiceAccountKey()) {
      throw new Error(
        "Refusing to load JSON key without --allow-service-account-key " +
          "(or ALLOW_SERVICE_ACCOUNT_KEY=true)."
      );
    }
    const absoluteKeyPath = path.isAbsolute(keyPath) ? keyPath : path.resolve(process.cwd(), keyPath);
    // eslint-disable-next-line global-require, import/no-dynamic-require
    options.credential = admin.credential.cert(require(absoluteKeyPath));
  }
  admin.initializeApp(options);
}

async function commitInChunks(writes) {
  if (writes.length === 0) return;
  const db = admin.firestore();
  for (let i = 0; i < writes.length; i += 400) {
    const batch = db.batch();
    for (const write of writes.slice(i, i + 400)) {
      batch.set(write.ref, write.data, {merge: true});
    }
    await batch.commit();
  }
}

async function run() {
  const apply = hasFlag("apply");
  initAdmin();
  const db = admin.firestore();
  const qrSnap = await db.collection("dts_qr_codes").get();

  const legacyDocs = qrSnap.docs.filter((doc) => {
    const row = doc.data() || {};
    const batchId = String(row.batchId || "").trim();
    return batchId.length === 0;
  });

  if (legacyDocs.length === 0) {
    console.log("[legacy-qr-backfill] no unbatched QR codes found.");
    return;
  }

  let usedCount = 0;
  let voidedCount = 0;
  let unusedCount = 0;
  const writes = [];
  for (const doc of legacyDocs) {
    const row = doc.data() || {};
    const status = String(row.status || "").trim().toLowerCase();
    if (status === "voided") {
      voidedCount += 1;
    } else if (status === "used" || row.docId || row.usedAt) {
      usedCount += 1;
    } else {
      unusedCount += 1;
    }

    writes.push({
      ref: doc.ref,
      data: {
        batchId: LEGACY_BATCH_ID,
        batchLabel: LEGACY_BATCH_LABEL,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedBy: SCRIPT_ACTOR,
      },
    });
  }

  const totalCount = legacyDocs.length;
  const batchRef = db.collection("dts_qr_batches").doc(LEGACY_BATCH_ID);
  writes.push({
    ref: batchRef,
    data: {
      batchId: LEGACY_BATCH_ID,
      batchLabel: LEGACY_BATCH_LABEL,
      prefix: "DTS-QR",
      totalCount,
      unusedCount,
      usedCount,
      voidedCount,
      exportCount: 0,
      status: "legacy",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      createdByUid: SCRIPT_ACTOR,
      updatedBy: SCRIPT_ACTOR,
    },
  });

  console.log("[legacy-qr-backfill] plan:");
  console.log(`  apply=${apply}`);
  console.log(`  legacy docs=${legacyDocs.length}`);
  console.log(`  counts total/unused/used/voided=${totalCount}/${unusedCount}/${usedCount}/${voidedCount}`);
  console.log(`  target batch id=${LEGACY_BATCH_ID}`);

  if (!apply) {
    console.log("Dry run only. Re-run with --apply to commit.");
    return;
  }

  await commitInChunks(writes);
  console.log("[legacy-qr-backfill] complete.");
}

run()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("[legacy-qr-backfill] failed:", error.message || error);
    process.exit(1);
  });

