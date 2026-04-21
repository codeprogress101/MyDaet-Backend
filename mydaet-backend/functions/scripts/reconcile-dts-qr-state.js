/* eslint-disable no-console */
const path = require("path");
const admin = require("firebase-admin");

const SCRIPT_ACTOR = "script:reconcile-dts-qr-state";
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

function coerceString(value) {
  const text = String(value || "").trim();
  return text.length > 0 ? text : null;
}

async function commitInChunks(db, writes) {
  if (writes.length === 0) return;
  for (let i = 0; i < writes.length; i += 400) {
    const batch = db.batch();
    for (const write of writes.slice(i, i + 400)) {
      const options = write.merge ? {merge: true} : undefined;
      batch.set(write.ref, write.data, options);
    }
    await batch.commit();
  }
}

async function run() {
  const apply = hasFlag("apply");
  initAdmin();
  const db = admin.firestore();

  const [qrSnap, docsSnap, indexSnap, batchSnap] = await Promise.all([
    db.collection("dts_qr_codes").get(),
    db.collection("dts_documents").select("qrCode", "trackingNo").get(),
    db.collection("dts_qr_index").get(),
    db.collection("dts_qr_batches").get(),
  ]);

  const docByQr = new Map();
  for (const doc of docsSnap.docs) {
    const row = doc.data() || {};
    const qrCode = coerceString(row.qrCode);
    if (!qrCode) continue;
    docByQr.set(qrCode, {
      docId: doc.id,
      trackingNo: coerceString(row.trackingNo),
    });
  }

  const indexByQr = new Map();
  for (const doc of indexSnap.docs) {
    const row = doc.data() || {};
    indexByQr.set(doc.id, {
      docId: coerceString(row.docId),
      trackingNo: coerceString(row.trackingNo),
    });
  }

  const existingBatchById = new Map();
  for (const doc of batchSnap.docs) {
    existingBatchById.set(doc.id, doc.data() || {});
  }

  let changedQrDocs = 0;
  let createdIndexDocs = 0;
  let removedIndexDocs = 0;
  let statusFixed = 0;
  let batchAssigned = 0;
  let linkFixed = 0;

  const writes = [];
  const desiredIndex = new Map();
  const countersByBatch = new Map();

  function getCounter(batchId, batchLabel) {
    if (!countersByBatch.has(batchId)) {
      countersByBatch.set(batchId, {
        batchId,
        batchLabel,
        totalCount: 0,
        unusedCount: 0,
        usedCount: 0,
        voidedCount: 0,
      });
    }
    return countersByBatch.get(batchId);
  }

  for (const qrDoc of qrSnap.docs) {
    const qrCode = qrDoc.id;
    const row = qrDoc.data() || {};
    const existingStatus = (coerceString(row.status) || "unused").toLowerCase();
    const existingBatchId = coerceString(row.batchId);
    const existingBatchLabel = coerceString(row.batchLabel);
    const existingDocId = coerceString(row.docId);
    const existingUsedAt = row.usedAt || null;

    const docLink = docByQr.get(qrCode);
    const indexLink = indexByQr.get(qrCode);
    const linkedDocId = coerceString(existingDocId) || coerceString(docLink?.docId) || coerceString(indexLink?.docId);
    const linkedTracking = coerceString(docLink?.trackingNo) || coerceString(indexLink?.trackingNo);

    const targetBatchId = existingBatchId || LEGACY_BATCH_ID;
    const targetBatchLabel = existingBatchLabel || (targetBatchId === LEGACY_BATCH_ID ? LEGACY_BATCH_LABEL : existingBatchId || LEGACY_BATCH_LABEL);

    let targetStatus = existingStatus;
    if (existingStatus !== "voided") {
      targetStatus = linkedDocId ? "used" : "unused";
    }
    if (existingStatus === "voided" && linkedDocId) {
      // Linked documents should never stay voided.
      targetStatus = "used";
    }

    const update = {};
    let hasUpdate = false;
    if (existingBatchId !== targetBatchId || existingBatchLabel !== targetBatchLabel) {
      update.batchId = targetBatchId;
      update.batchLabel = targetBatchLabel;
      batchAssigned += existingBatchId ? 0 : 1;
      hasUpdate = true;
    }
    if (existingStatus !== targetStatus) {
      update.status = targetStatus;
      statusFixed += 1;
      hasUpdate = true;
    }

    if (targetStatus === "used") {
      if (existingDocId !== linkedDocId) {
        update.docId = linkedDocId;
        linkFixed += 1;
        hasUpdate = true;
      }
      if (!existingUsedAt) {
        update.usedAt = admin.firestore.FieldValue.serverTimestamp();
        hasUpdate = true;
      }
      desiredIndex.set(qrCode, {
        docId: linkedDocId,
        trackingNo: linkedTracking,
      });
    } else if (targetStatus === "unused") {
      if (existingDocId) {
        update.docId = admin.firestore.FieldValue.delete();
        linkFixed += 1;
        hasUpdate = true;
      }
      if (existingUsedAt) {
        update.usedAt = admin.firestore.FieldValue.delete();
        hasUpdate = true;
      }
    }

    if (hasUpdate) {
      update.updatedAt = admin.firestore.FieldValue.serverTimestamp();
      update.updatedBy = SCRIPT_ACTOR;
      writes.push({ref: qrDoc.ref, data: update, merge: true});
      changedQrDocs += 1;
    }

    const counter = getCounter(targetBatchId, targetBatchLabel);
    counter.totalCount += 1;
    if (targetStatus === "voided") {
      counter.voidedCount += 1;
    } else if (targetStatus === "used") {
      counter.usedCount += 1;
    } else {
      counter.unusedCount += 1;
    }
  }

  for (const [qrCode, data] of desiredIndex.entries()) {
    const current = indexByQr.get(qrCode);
    const sameDoc = coerceString(current?.docId) === data.docId;
    const sameTracking = coerceString(current?.trackingNo) === coerceString(data.trackingNo);
    if (!sameDoc || !sameTracking) {
      writes.push({
        ref: db.collection("dts_qr_index").doc(qrCode),
        data: {
          docId: data.docId,
          trackingNo: data.trackingNo || null,
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          updatedBy: SCRIPT_ACTOR,
          ...(current ? {} : {
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
          }),
        },
        merge: true,
      });
      if (!current) {
        createdIndexDocs += 1;
      }
    }
  }

  for (const indexDoc of indexSnap.docs) {
    if (desiredIndex.has(indexDoc.id)) continue;
    writes.push({
      ref: indexDoc.ref,
      data: {
        tombstonedAt: admin.firestore.FieldValue.serverTimestamp(),
        tombstonedBy: SCRIPT_ACTOR,
      },
      merge: true,
    });
    writes.push({ref: indexDoc.ref, data: {}, merge: true});
    // delete with batch.delete isn't represented here, do direct delete when apply below.
    removedIndexDocs += 1;
  }

  const batchWrites = [];
  for (const [batchId, counter] of countersByBatch.entries()) {
    const existing = existingBatchById.get(batchId) || {};
    const payload = {
      batchId,
      batchLabel: counter.batchLabel,
      prefix: coerceString(existing.prefix) || "DTS-QR",
      totalCount: counter.totalCount,
      unusedCount: counter.unusedCount,
      usedCount: counter.usedCount,
      voidedCount: counter.voidedCount,
      exportCount: Number(existing.exportCount || 0),
      status: coerceString(existing.status) || (batchId === LEGACY_BATCH_ID ? "legacy" : "active"),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedBy: SCRIPT_ACTOR,
      createdByUid: coerceString(existing.createdByUid) || SCRIPT_ACTOR,
      createdAt: existing.createdAt || admin.firestore.FieldValue.serverTimestamp(),
    };
    batchWrites.push({
      ref: db.collection("dts_qr_batches").doc(batchId),
      data: payload,
      merge: true,
    });
  }

  console.log("[reconcile-dts-qr-state] plan:");
  console.log(`  apply=${apply}`);
  console.log(`  qrs=${qrSnap.size}, docsWithQr=${docByQr.size}, qrIndex=${indexSnap.size}`);
  console.log(`  changedQrDocs=${changedQrDocs}`);
  console.log(`  statusFixed=${statusFixed}, batchAssigned=${batchAssigned}, linkFixed=${linkFixed}`);
  console.log(`  indexCreatedOrUpdated=${createdIndexDocs}, indexMarkedForRemoval=${removedIndexDocs}`);
  console.log(`  batchesToUpsert=${batchWrites.length}`);

  if (!apply) {
    console.log("Dry run only. Re-run with --apply to commit.");
    return;
  }

  await commitInChunks(db, writes.filter((w) => w.data && Object.keys(w.data).length > 0));
  await commitInChunks(db, batchWrites);

  if (removedIndexDocs > 0) {
    for (const indexDoc of indexSnap.docs) {
      if (desiredIndex.has(indexDoc.id)) continue;
      await indexDoc.ref.delete();
    }
  }

  console.log("[reconcile-dts-qr-state] complete.");
}

run()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("[reconcile-dts-qr-state] failed:", error.message || error);
    process.exit(1);
  });

