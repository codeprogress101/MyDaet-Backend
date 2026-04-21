/* eslint-disable no-console */
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const {spawnSync} = require("child_process");
const admin = require("firebase-admin");

const SCRIPT_BACKFILL = "scripts/backfill-dts-destination-migration.js";
const SCRIPT_ROLLBACK = "scripts/rollback-dts-destination-migration.js";

function contextFor(uid, role, officeId = null, officeName = null) {
  return {
    auth: {
      uid,
      token: {
        role,
        officeId,
        officeName,
        isActive: true,
      },
    },
    rawRequest: {
      ip: "127.0.0.1",
      headers: {
        "x-forwarded-for": "127.0.0.1",
      },
    },
  };
}

function runNodeScript(args) {
  const command = process.platform === "win32" ? "node.exe" : "node";
  const result = spawnSync(command, args, {
    cwd: path.resolve(__dirname, ".."),
    env: process.env,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    throw new Error(
      `Command failed (${command} ${args.join(" ")}):\n` +
      `${result.stdout || ""}\n${result.stderr || ""}`
    );
  }
  return result.stdout || "";
}

async function seedData(db) {
  await db.doc("system/settings").set({
    features: {
      reports: true,
      messages: true,
    },
    readOnly: false,
  }, {merge: true});

  await db.doc("users/office1").set({
    uid: "office1",
    role: "office_admin",
    isActive: true,
    officeId: "OFF-1",
    officeName: "Office 1",
  });
  await db.doc("users/office2").set({
    uid: "office2",
    role: "office_admin",
    isActive: true,
    officeId: "OFF-2",
    officeName: "Office 2",
  });

  await db.doc("offices/OFF-1").set({
    officeId: "OFF-1",
    name: "Office 1",
    isActive: true,
  }, {merge: true});
  await db.doc("offices/OFF-2").set({
    officeId: "OFF-2",
    name: "Office 2",
    isActive: true,
  }, {merge: true});

  const initiatedAt = admin.firestore.Timestamp.fromMillis(1700000000000);
  await db.doc("dts_documents/doc-legacy-transit").set({
    trackingNo: "DTS-2026-M-9001",
    qrCode: "DTS-QR-LEGACYAA112233",
    status: "IN_TRANSIT",
    currentOfficeId: "OFF-1",
    currentOfficeName: "Office 1",
    currentCustodianUid: null,
    pendingTransfer: {
      fromOfficeId: "OFF-1",
      fromUid: "office1",
      toOfficeId: "OFF-2",
      toOfficeName: "Office 2",
      toUid: "office2",
      previousStatus: "WITH_OFFICE",
      initiatedAt,
    },
    updatedAt: initiatedAt,
  }, {merge: true});

  await db.doc("dts_documents/doc-legacy-idle").set({
    trackingNo: "DTS-2026-M-9002",
    qrCode: "DTS-QR-LEGACYBB445566",
    status: "WITH_OFFICE",
    currentOfficeId: "OFF-1",
    currentOfficeName: "Office 1",
    currentCustodianUid: "office1",
    updatedAt: initiatedAt,
  }, {merge: true});
}

async function run() {
  if (!process.env.FIRESTORE_EMULATOR_HOST) {
    throw new Error("FIRESTORE_EMULATOR_HOST is required for migration integration tests.");
  }

  const projectId =
    process.env.GCLOUD_PROJECT ||
    process.env.FIREBASE_PROJECT_ID ||
    "mydaet";

  const functionsModule = require("../lib/index.js");
  if (admin.apps.length === 0) {
    admin.initializeApp({projectId});
  }
  const db = admin.firestore();
  await seedData(db);

  const dryRunReport = path.join(os.tmpdir(), `md7-backfill-dry-${Date.now()}.json`);
  runNodeScript([
    SCRIPT_BACKFILL,
    `--project=${projectId}`,
    `--report=${dryRunReport}`,
    "--sample-limit=10",
  ]);
  const dryReport = JSON.parse(fs.readFileSync(dryRunReport, "utf8"));
  assert.ok(dryReport.mutations.migratePendingTransfers >= 1, "dry-run should plan pending-transfer migration");
  assert.ok(dryReport.mutations.initializeDistributionFields >= 1, "dry-run should plan distribution initialization");

  const applyReportPath = path.join(os.tmpdir(), `md7-backfill-apply-${Date.now()}.json`);
  runNodeScript([
    SCRIPT_BACKFILL,
    `--project=${projectId}`,
    "--apply",
    `--report=${applyReportPath}`,
    "--sample-limit=10",
  ]);
  const applyReport = JSON.parse(fs.readFileSync(applyReportPath, "utf8"));
  assert.ok(applyReport.runId, "apply report should include runId");

  const migratedDocSnap = await db.doc("dts_documents/doc-legacy-transit").get();
  const migratedDoc = migratedDocSnap.data() || {};
  assert.strictEqual(migratedDoc.distributionMode, "SINGLE", "legacy transit doc should be single distribution");
  assert.strictEqual(Number(migratedDoc.destTotal || 0), 1, "legacy transit doc should have one destination");
  assert.strictEqual(Number(migratedDoc.destInTransit || 0), 1, "legacy transit doc should be in transit after migration");
  assert.ok(migratedDoc.pendingTransfer && migratedDoc.pendingTransfer.destinationId, "pending transfer should carry destinationId");

  const destinationId = String(migratedDoc.pendingTransfer.destinationId);
  const destinationSnap = await db
    .collection("dts_documents")
    .doc("doc-legacy-transit")
    .collection("destinations")
    .doc(destinationId)
    .get();
  assert.strictEqual(destinationSnap.exists, true, "migration should create destination row");
  assert.strictEqual(
    String(destinationSnap.data()?.status || "").toUpperCase(),
    "IN_TRANSIT",
    "created destination row should be in transit"
  );

  const initializedDocSnap = await db.doc("dts_documents/doc-legacy-idle").get();
  const initializedDoc = initializedDocSnap.data() || {};
  assert.strictEqual(initializedDoc.distributionMode, "SINGLE", "legacy idle doc should initialize distribution mode");
  assert.strictEqual(Number(initializedDoc.destTotal || 0), 0, "legacy idle doc should have zero destinations");

  const rollbackDryPath = path.join(os.tmpdir(), `md7-rollback-dry-${Date.now()}.json`);
  runNodeScript([
    SCRIPT_ROLLBACK,
    `--project=${projectId}`,
    `--run-id=${applyReport.runId}`,
    `--report=${rollbackDryPath}`,
  ]);
  const rollbackDryReport = JSON.parse(fs.readFileSync(rollbackDryPath, "utf8"));
  assert.ok(rollbackDryReport.toRestore >= 2, "rollback dry-run should include migrated docs");

  const receiptResult = await functionsModule.__testing.dtsConfirmDestinationReceiptHandler(
    {
      docId: "doc-legacy-transit",
      destinationId,
      verificationValue: "112233",
      verificationMethod: "MANUAL_INPUT",
      confirmPhysicalReceipt: true,
    },
    contextFor("office2", "office_admin", "OFF-2", "Office 2")
  );
  assert.strictEqual(receiptResult.success, true, "migrated single-destination flow should remain callable");

  const postReceiptDoc = (await db.doc("dts_documents/doc-legacy-transit").get()).data() || {};
  assert.strictEqual(postReceiptDoc.status, "WITH_OFFICE", "single-destination receipt should return parent to with_office");
  assert.strictEqual(Number(postReceiptDoc.destReceived || 0), 1, "single-destination receipt should increment received counter");

  const noOrphan = !(postReceiptDoc.status === "IN_TRANSIT" && Number(postReceiptDoc.destInTransit || 0) === 0);
  assert.strictEqual(noOrphan, true, "migrated record should not end in orphan in-transit state");

  console.log("dts-destination-backfill.integration.test: PASS");
}

run().catch((error) => {
  console.error("dts-destination-backfill.integration.test: FAIL", error);
  process.exit(1);
});
