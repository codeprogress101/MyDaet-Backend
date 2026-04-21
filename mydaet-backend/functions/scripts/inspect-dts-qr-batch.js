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

function allowServiceAccountKey() {
  if (hasFlag("allow-service-account-key")) return true;
  const raw = String(process.env.ALLOW_SERVICE_ACCOUNT_KEY || "").trim().toLowerCase();
  return raw === "1" || raw === "true" || raw === "yes";
}

function coerceString(value) {
  const text = String(value || "").trim();
  return text.length > 0 ? text : null;
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

async function resolveBatchDoc(db, batchId, batchLabel) {
  if (batchId) {
    const snap = await db.collection("dts_qr_batches").doc(batchId).get();
    if (!snap.exists) {
      throw new Error(`Batch not found by id: ${batchId}`);
    }
    return snap;
  }
  if (!batchLabel) {
    throw new Error("Pass --batch-id=<id> or --batch-label=\"QR Batch ...\"");
  }
  const byLabel = await db
    .collection("dts_qr_batches")
    .where("batchLabel", "==", batchLabel)
    .limit(1)
    .get();
  if (!byLabel.empty) {
    return byLabel.docs[0];
  }
  const recent = await db
    .collection("dts_qr_batches")
    .orderBy("createdAt", "desc")
    .limit(100)
    .get();
  const match = recent.docs.find((doc) => {
    const label = coerceString((doc.data() || {}).batchLabel);
    return label && label.toLowerCase().includes(batchLabel.toLowerCase());
  });
  if (!match) {
    throw new Error(`Batch not found by label: ${batchLabel}`);
  }
  return match;
}

async function run() {
  initAdmin();
  const db = admin.firestore();
  const batchIdArg = coerceString(parseArg("batch-id"));
  const batchLabelArg = coerceString(parseArg("batch-label"));
  const batchDoc = await resolveBatchDoc(db, batchIdArg, batchLabelArg);
  const batchId = batchDoc.id;
  const batch = batchDoc.data() || {};

  console.log("=== Batch ===");
  console.log(`id: ${batchId}`);
  console.log(`label: ${coerceString(batch.batchLabel) || "-"}`);
  console.log(`stored total/unused/used/voided: ${batch.totalCount || 0}/${batch.unusedCount || 0}/${batch.usedCount || 0}/${batch.voidedCount || 0}`);

  const codesSnap = await db.collection("dts_qr_codes").where("batchId", "==", batchId).get();
  const codeIds = codesSnap.docs.map((d) => d.id);
  console.log(`codes in batch: ${codesSnap.size}`);

  const statusCounts = {};
  const byDocId = new Set();
  const byUsedAt = new Set();
  const unresolved = [];
  for (const doc of codesSnap.docs) {
    const row = doc.data() || {};
    const status = (coerceString(row.status) || "").toLowerCase() || "(empty)";
    statusCounts[status] = (statusCounts[status] || 0) + 1;
    if (coerceString(row.docId)) byDocId.add(doc.id);
    if (row.usedAt) byUsedAt.add(doc.id);
    if (status === "unused" || status === "(empty)") {
      unresolved.push(doc.id);
    }
  }

  const byIndex = new Set();
  if (codeIds.length > 0) {
    const indexSnaps = await Promise.all(codeIds.map((code) => db.collection("dts_qr_index").doc(code).get()));
    for (let i = 0; i < indexSnaps.length; i += 1) {
      const snap = indexSnaps[i];
      if (snap.exists && coerceString((snap.data() || {}).docId)) {
        byIndex.add(codeIds[i]);
      }
    }
  }

  const byDocuments = new Set();
  for (let i = 0; i < codeIds.length; i += 30) {
    const chunk = codeIds.slice(i, i + 30);
    if (chunk.length === 0) continue;
    const docsByQr = await db.collection("dts_documents").where("qrCode", "in", chunk).get();
    docsByQr.forEach((snap) => {
      const qrCode = coerceString((snap.data() || {}).qrCode);
      if (qrCode) byDocuments.add(qrCode);
    });
  }

  const usedUnion = new Set([...byDocId, ...byUsedAt, ...byIndex, ...byDocuments]);
  const voidedCount = statusCounts.voided || 0;
  const usedCount = usedUnion.size;
  const unusedCount = Math.max(0, codeIds.length - usedCount - voidedCount);

  console.log("\n=== Computed ===");
  console.log(`status counts: ${JSON.stringify(statusCounts)}`);
  console.log(`has docId: ${byDocId.size}`);
  console.log(`has usedAt: ${byUsedAt.size}`);
  console.log(`in qr_index: ${byIndex.size}`);
  console.log(`in dts_documents.qrCode: ${byDocuments.size}`);
  console.log(`computed total/unused/used/voided: ${codeIds.length}/${unusedCount}/${usedCount}/${voidedCount}`);

  const suspicious = unresolved.filter((code) => byIndex.has(code) || byDocuments.has(code) || byDocId.has(code));
  console.log(`suspicious unused-but-linked codes: ${suspicious.length}`);
  if (suspicious.length > 0) {
    console.log(`sample: ${suspicious.slice(0, 10).join(", ")}`);
  }
}

run()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("[inspect-dts-qr-batch] failed:", error.message || error);
    process.exit(1);
  });

