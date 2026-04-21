/* eslint-disable no-console */
const fs = require("fs");
const path = require("path");
const admin = require("firebase-admin");

const SCRIPT_ACTOR = "script:backfill-dts-destination-migration";
const RUNS_COLLECTION = "dts_distribution_backfill_runs";
const MUTABLE_PARENT_FIELDS = [
  "status",
  "distributionMode",
  "distributionBaseStatus",
  "destTotal",
  "destPending",
  "destInTransit",
  "destReceived",
  "destRejected",
  "destCancelled",
  "activeDestinationOfficeIds",
  "destinationOfficeIds",
  "pendingTransfer",
  "currentCustodianUid",
];

function parseArg(name) {
  const prefix = `--${name}=`;
  const hit = process.argv.find((arg) => arg.startsWith(prefix));
  return hit ? hit.slice(prefix.length) : null;
}

function parseArgList(name) {
  const prefix = `--${name}=`;
  return process.argv
    .filter((arg) => arg.startsWith(prefix))
    .map((arg) => arg.slice(prefix.length))
    .map((value) => String(value || "").trim())
    .filter(Boolean);
}

function parseIntArg(name, fallback) {
  const raw = parseArg(name);
  if (!raw) return fallback;
  const value = Number.parseInt(raw, 10);
  if (!Number.isFinite(value) || value <= 0) return fallback;
  return value;
}

function hasFlag(name) {
  return process.argv.includes(`--${name}`);
}

function allowServiceAccountKey() {
  if (hasFlag("allow-service-account-key")) return true;
  const raw = String(process.env.ALLOW_SERVICE_ACCOUNT_KEY || "").trim().toLowerCase();
  return raw === "1" || raw === "true" || raw === "yes";
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

function normalizeStatus(value, fallback = "WITH_OFFICE") {
  const raw = String(value || "").trim().toUpperCase();
  const allowed = new Set([
    "CREATED",
    "RECEIVED",
    "WITH_OFFICE",
    "IN_PROCESS",
    "FOR_APPROVAL",
    "IN_TRANSIT",
    "RELEASED",
    "ARCHIVED",
    "PULLED_OUT",
    "VOIDED",
  ]);
  if (allowed.has(raw)) return raw;
  return fallback;
}

function normalizeDestinationStatus(value) {
  const raw = String(value || "").trim().toUpperCase();
  const allowed = new Set(["PENDING", "IN_TRANSIT", "RECEIVED", "REJECTED", "CANCELLED"]);
  if (allowed.has(raw)) return raw;
  return "PENDING";
}

function coerceString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function coerceTimestamp(value) {
  if (value instanceof admin.firestore.Timestamp) return value;
  if (value instanceof Date) return admin.firestore.Timestamp.fromDate(value);
  return null;
}

function uniqueSortedStrings(values) {
  const bucket = new Set();
  for (const raw of values) {
    const value = coerceString(raw);
    if (value) {
      bucket.add(value);
    }
  }
  return Array.from(bucket).sort((left, right) => left.localeCompare(right));
}

function summarizeDestinations(rows) {
  let pending = 0;
  let inTransit = 0;
  let received = 0;
  let rejected = 0;
  let cancelled = 0;
  for (const row of rows) {
    const status = normalizeDestinationStatus(row.status);
    if (status === "PENDING") pending += 1;
    if (status === "IN_TRANSIT") inTransit += 1;
    if (status === "RECEIVED") received += 1;
    if (status === "REJECTED") rejected += 1;
    if (status === "CANCELLED") cancelled += 1;
  }
  return {
    total: rows.length,
    pending,
    inTransit,
    received,
    rejected,
    cancelled,
    activeOfficeIds: uniqueSortedStrings(
      rows
        .filter((row) => {
          const status = normalizeDestinationStatus(row.status);
          return status === "PENDING" || status === "IN_TRANSIT";
        })
        .map((row) => row.toOfficeId)
    ),
    allOfficeIds: uniqueSortedStrings(rows.map((row) => row.toOfficeId)),
  };
}

function countersFromParent(row) {
  return {
    total: Number(row.destTotal || 0),
    pending: Number(row.destPending || 0),
    inTransit: Number(row.destInTransit || 0),
    received: Number(row.destReceived || 0),
    rejected: Number(row.destRejected || 0),
    cancelled: Number(row.destCancelled || 0),
  };
}

function hasAnyDistributionField(row) {
  return (
    Object.prototype.hasOwnProperty.call(row, "distributionMode") ||
    Object.prototype.hasOwnProperty.call(row, "destTotal") ||
    Object.prototype.hasOwnProperty.call(row, "destPending") ||
    Object.prototype.hasOwnProperty.call(row, "destInTransit") ||
    Object.prototype.hasOwnProperty.call(row, "destReceived") ||
    Object.prototype.hasOwnProperty.call(row, "destRejected") ||
    Object.prototype.hasOwnProperty.call(row, "destCancelled") ||
    Object.prototype.hasOwnProperty.call(row, "activeDestinationOfficeIds") ||
    Object.prototype.hasOwnProperty.call(row, "destinationOfficeIds")
  );
}

function pendingTransferFromRow(row) {
  if (!row.pendingTransfer || typeof row.pendingTransfer !== "object") return null;
  return row.pendingTransfer;
}

function captureBeforeSnapshot(row) {
  const beforeFields = {};
  const missingFields = [];
  for (const field of MUTABLE_PARENT_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(row, field)) {
      beforeFields[field] = row[field];
    } else {
      missingFields.push(field);
    }
  }
  return {
    beforeFields,
    missingFields,
  };
}

function parseDestinations(destinationSnap) {
  return destinationSnap.docs.map((doc) => {
    const row = doc.data() || {};
    return {
      id: doc.id,
      status: normalizeDestinationStatus(row.status),
      toOfficeId: coerceString(row.toOfficeId),
    };
  });
}

function verifyDocument(row, destinations, pendingTransfer) {
  const status = normalizeStatus(row.status, "WITH_OFFICE");
  const summary = summarizeDestinations(destinations);
  const parentCounters = countersFromParent(row);
  const hasDestinations = summary.total > 0;
  const hasPendingTransfer = !!pendingTransfer;
  const pendingDestinationId = coerceString(pendingTransfer?.destinationId);
  const inTransitDestinationCount = destinations.filter((entry) => entry.status === "IN_TRANSIT").length;

  return {
    orphanInTransitNoRoute: status === "IN_TRANSIT" && !hasPendingTransfer && !hasDestinations,
    orphanPendingTransferNoDestination: hasPendingTransfer && !hasDestinations,
    pendingDestinationIdMismatch:
      hasPendingTransfer &&
      hasDestinations &&
      pendingDestinationId != null &&
      !destinations.some((entry) => entry.id === pendingDestinationId),
    counterMismatch:
      hasDestinations &&
      (
        parentCounters.total !== summary.total ||
        parentCounters.pending !== summary.pending ||
        parentCounters.inTransit !== summary.inTransit ||
        parentCounters.received !== summary.received ||
        parentCounters.rejected !== summary.rejected ||
        parentCounters.cancelled !== summary.cancelled
      ),
    multiInTransitLegacyPendingConflict:
      hasPendingTransfer &&
      inTransitDestinationCount > 1 &&
      pendingDestinationId != null,
  };
}

function buildInitializePatch() {
  return {
    distributionMode: "SINGLE",
    destTotal: 0,
    destPending: 0,
    destInTransit: 0,
    destReceived: 0,
    destRejected: 0,
    destCancelled: 0,
    activeDestinationOfficeIds: [],
    destinationOfficeIds: [],
    pendingTransfer: null,
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
  };
}

function buildPendingTransferMigration({
  row,
  pendingTransfer,
  destinationId,
  officeNamesById,
}) {
  const sourceOfficeId = coerceString(pendingTransfer.fromOfficeId) || coerceString(row.currentOfficeId);
  const toOfficeId = coerceString(pendingTransfer.toOfficeId);
  const toOfficeName = coerceString(pendingTransfer.toOfficeName) ||
    (toOfficeId ? officeNamesById.get(toOfficeId) || toOfficeId : null);
  const sourceOfficeName = coerceString(row.currentOfficeName) ||
    (sourceOfficeId ? officeNamesById.get(sourceOfficeId) || sourceOfficeId : null);
  const previousStatus = normalizeStatus(pendingTransfer.previousStatus, "WITH_OFFICE");
  const initiatedAt = coerceTimestamp(pendingTransfer.initiatedAt);
  const createdByUid = coerceString(pendingTransfer.fromUid);
  const toUid = coerceString(pendingTransfer.toUid);

  if (!toOfficeId || !toOfficeName) {
    return {
      valid: false,
      reason: "Pending transfer has no target officeId/officeName.",
      parentPatch: null,
      destinationPatch: null,
    };
  }

  const nextPendingTransfer = {
    ...pendingTransfer,
    toOfficeId,
    toOfficeName,
    fromOfficeId: sourceOfficeId,
    destinationId,
  };

  return {
    valid: true,
    reason: null,
    parentPatch: {
      status: "IN_TRANSIT",
      distributionMode: "SINGLE",
      distributionBaseStatus: previousStatus,
      destTotal: 1,
      destPending: 0,
      destInTransit: 1,
      destReceived: 0,
      destRejected: 0,
      destCancelled: 0,
      activeDestinationOfficeIds: [toOfficeId],
      destinationOfficeIds: [toOfficeId],
      pendingTransfer: nextPendingTransfer,
      currentCustodianUid: null,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    },
    destinationPatch: {
      id: destinationId,
      docId: coerceString(row.id) || null,
      toOfficeId,
      toOfficeName,
      toUid,
      sourceOfficeId,
      sourceOfficeName,
      status: "IN_TRANSIT",
      previousStatus,
      createdByUid,
      createdByName: null,
      createdAt: initiatedAt || admin.firestore.FieldValue.serverTimestamp(),
      dispatchedAt: initiatedAt || admin.firestore.FieldValue.serverTimestamp(),
      receivedAt: null,
      rejectedAt: null,
      cancelledAt: null,
      reason: null,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      migratedByScript: SCRIPT_ACTOR,
    },
  };
}

function makeRunId() {
  const stamp = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
  const suffix = Math.random().toString(36).slice(2, 8).toUpperCase();
  return `dts-md-backfill-${stamp}-${suffix}`;
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

async function resolveOfficeNameMap(db) {
  const snap = await db.collection("offices").get();
  const mapping = new Map();
  for (const doc of snap.docs) {
    const name = coerceString(doc.data()?.name);
    if (name) {
      mapping.set(doc.id, name);
    }
  }
  return mapping;
}

function pushSample(samples, value, maxSize) {
  if (samples.length < maxSize) {
    samples.push(value);
  }
}

async function loadTargetDocs(db, options) {
  const docIds = options.docIds;
  if (docIds.length > 0) {
    const uniqueIds = Array.from(new Set(docIds));
    const rows = await Promise.all(
      uniqueIds.map(async (docId) => db.collection("dts_documents").doc(docId).get())
    );
    return rows.filter((doc) => doc.exists);
  }

  let query = db.collection("dts_documents");
  if (options.limit != null) {
    query = query.limit(options.limit);
  }
  const snap = await query.get();
  return snap.docs;
}

function reportPathFromArg() {
  const filePath = parseArg("report");
  if (!filePath) return null;
  return path.isAbsolute(filePath) ? filePath : path.resolve(process.cwd(), filePath);
}

async function run() {
  const apply = hasFlag("apply");
  const allowAll = hasFlag("all");
  const requestedLimit = parseIntArg("limit", null);
  const limit = allowAll ? null : Math.min(requestedLimit ?? 500, 5000);
  const sampleLimit = parseIntArg("sample-limit", 40);
  const reportPath = reportPathFromArg();
  const docIds = parseArgList("doc-id");

  initAdmin();
  const db = admin.firestore();
  const officeNamesById = await resolveOfficeNameMap(db);
  const docs = await loadTargetDocs(db, {limit, docIds});
  const runId = makeRunId();

  const report = {
    script: SCRIPT_ACTOR,
    runId,
    apply,
    generatedAt: new Date().toISOString(),
    projectId: parseArg("project") || process.env.GCLOUD_PROJECT || process.env.FIREBASE_PROJECT_ID || null,
    scanned: docs.length,
    considered: 0,
    mutations: {
      migratePendingTransfers: 0,
      initializeDistributionFields: 0,
      skippedInvalidPendingTransfer: 0,
    },
    verification: {
      orphanInTransitNoRoute: 0,
      orphanPendingTransferNoDestination: 0,
      pendingDestinationIdMismatch: 0,
      counterMismatch: 0,
      multiInTransitLegacyPendingConflict: 0,
    },
    samples: {
      mutations: [],
      skipped: [],
      anomalies: [],
    },
    notes: [],
  };

  const plans = [];

  for (const doc of docs) {
    const row = doc.data() || {};
    row.id = doc.id;
    const destinationSnap = await doc.ref.collection("destinations").get();
    const destinations = parseDestinations(destinationSnap);
    const pendingTransfer = pendingTransferFromRow(row);
    const verification = verifyDocument(row, destinations, pendingTransfer);

    for (const [key, flag] of Object.entries(verification)) {
      if (flag === true && Object.prototype.hasOwnProperty.call(report.verification, key)) {
        report.verification[key] += 1;
        pushSample(
          report.samples.anomalies,
          {docId: doc.id, issue: key},
          sampleLimit
        );
      }
    }

    const hasDestinations = destinations.length > 0;
    const hasPendingTransfer = pendingTransfer != null;
    const distributionMissing = !hasAnyDistributionField(row);
    if (!hasDestinations && (hasPendingTransfer || distributionMissing)) {
      report.considered += 1;
    }

    if (!hasDestinations && hasPendingTransfer) {
      const pendingDestinationId = coerceString(pendingTransfer.destinationId) || `legacy-${doc.id}`;
      const migrated = buildPendingTransferMigration({
        row,
        pendingTransfer,
        destinationId: pendingDestinationId,
        officeNamesById,
      });
      if (!migrated.valid) {
        report.mutations.skippedInvalidPendingTransfer += 1;
        pushSample(
          report.samples.skipped,
          {
            docId: doc.id,
            action: "SKIP_INVALID_PENDING_TRANSFER",
            reason: migrated.reason,
          },
          sampleLimit
        );
        continue;
      }
      report.mutations.migratePendingTransfers += 1;
      plans.push({
        type: "MIGRATE_PENDING_TRANSFER",
        docRef: doc.ref,
        docId: doc.id,
        destinationId: pendingDestinationId,
        parentPatch: migrated.parentPatch,
        destinationPatch: migrated.destinationPatch,
        beforeSnapshot: captureBeforeSnapshot(row),
      });
      pushSample(
        report.samples.mutations,
        {
          docId: doc.id,
          action: "MIGRATE_PENDING_TRANSFER",
          destinationId: pendingDestinationId,
          toOfficeId: migrated.destinationPatch.toOfficeId,
        },
        sampleLimit
      );
      continue;
    }

    if (!hasDestinations && distributionMissing) {
      report.mutations.initializeDistributionFields += 1;
      plans.push({
        type: "INITIALIZE_DISTRIBUTION_FIELDS",
        docRef: doc.ref,
        docId: doc.id,
        destinationId: null,
        parentPatch: buildInitializePatch(),
        destinationPatch: null,
        beforeSnapshot: captureBeforeSnapshot(row),
      });
      pushSample(
        report.samples.mutations,
        {
          docId: doc.id,
          action: "INITIALIZE_DISTRIBUTION_FIELDS",
        },
        sampleLimit
      );
    }
  }

  if (!apply) {
    if (!allowAll) {
      report.notes.push(
        `Safety limit applied: scanning up to ${limit} documents. ` +
          "Use --all only for approved full-dataset runs."
      );
    }
    report.notes.push("Dry run only. Re-run with --apply to commit migration writes.");
    if (reportPath) {
      fs.mkdirSync(path.dirname(reportPath), {recursive: true});
      fs.writeFileSync(reportPath, JSON.stringify(toReportSafe(report), null, 2));
      console.log(`[md-7] wrote dry-run report: ${reportPath}`);
    }
    console.log("[md-7] dry-run summary:", JSON.stringify(toReportSafe({
      scanned: report.scanned,
      considered: report.considered,
      mutations: report.mutations,
      verification: report.verification,
      runId: report.runId,
    })));
    return;
  }

  const runRef = db.collection(RUNS_COLLECTION).doc(runId);
  const startedAt = admin.firestore.FieldValue.serverTimestamp();
  await runRef.set({
    runId,
    script: SCRIPT_ACTOR,
    startedAt,
    apply: true,
    projectId: report.projectId,
    scanned: report.scanned,
    considered: report.considered,
    plannedMutations: plans.length,
    limitApplied: limit,
    allowAll,
    actor: SCRIPT_ACTOR,
  }, {merge: true});

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

  for (const plan of plans) {
    const itemRef = runRef.collection("items").doc(plan.docId);
    setMerge(itemRef, {
      docId: plan.docId,
      action: plan.type,
      destinationId: plan.destinationId,
      destinationCreated: plan.type === "MIGRATE_PENDING_TRANSFER",
      beforeFields: plan.beforeSnapshot.beforeFields,
      missingFields: plan.beforeSnapshot.missingFields,
      loggedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    if (plan.type === "MIGRATE_PENDING_TRANSFER") {
      const destinationRef = plan.docRef.collection("destinations").doc(plan.destinationId);
      setMerge(destinationRef, plan.destinationPatch);
    }
    setMerge(plan.docRef, plan.parentPatch);

    if (opCount >= 360) {
      await flush();
    }
  }
  await flush();

  await runRef.set({
    completedAt: admin.firestore.FieldValue.serverTimestamp(),
    migratedPendingTransfers: report.mutations.migratePendingTransfers,
    initializedDistributionFields: report.mutations.initializeDistributionFields,
    skippedInvalidPendingTransfer: report.mutations.skippedInvalidPendingTransfer,
    verification: report.verification,
  }, {merge: true});

  report.notes.push(
    "Apply mode complete. Use rollback script with --run-id to restore migration changes if needed."
  );
  if (reportPath) {
    fs.mkdirSync(path.dirname(reportPath), {recursive: true});
    fs.writeFileSync(reportPath, JSON.stringify(toReportSafe(report), null, 2));
    console.log(`[md-7] wrote apply report: ${reportPath}`);
  }
  console.log("[md-7] apply summary:", JSON.stringify(toReportSafe({
    runId,
    scanned: report.scanned,
    considered: report.considered,
    mutations: report.mutations,
    verification: report.verification,
  })));
}

run()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("[md-7] backfill failed:", error);
    process.exit(1);
  });
