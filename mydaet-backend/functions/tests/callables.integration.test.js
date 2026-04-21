/* eslint-disable no-console */
const assert = require("assert");
const admin = require("firebase-admin");

function timestampFromSeed(seed) {
  return admin.firestore.Timestamp.fromMillis(seed);
}

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

async function seedData(db) {
  await db.doc("system/settings").set({
    features: {
      reports: true,
      messages: true,
    },
    readOnly: false,
  }, {merge: true});

  await db.doc("users/super1").set({
    uid: "super1",
    role: "super_admin",
    isActive: true,
    officeId: null,
    officeName: null,
  });
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
  await db.doc("users/office4").set({
    uid: "office4",
    role: "office_admin",
    isActive: true,
    officeId: "OFF-4",
    officeName: "Office 4",
  });

  await db.doc("dts_documents/doc-md-1").set({
    qrCode: "DTS-QR-ABCD99123456",
    trackingNo: "DTS-2026-M-0001",
    publicPinHash: "legacy",
    pinHash: "legacy",
    pinHashAlgo: "bcrypt",
    title: "Office Memo",
    docType: "MEMO",
    status: "WITH_OFFICE",
    distributionMode: "SINGLE",
    destTotal: 0,
    destPending: 0,
    destInTransit: 0,
    destReceived: 0,
    destRejected: 0,
    destCancelled: 0,
    activeDestinationOfficeIds: [],
    destinationOfficeIds: [],
    currentOfficeId: "OFF-1",
    currentOfficeName: "Office 1",
    currentCustodianUid: "office1",
    updatedAt: timestampFromSeed(1700000200000),
  });

  const rows = [];
  const statusRing = ["submitted", "assigned", "in_review", "in_progress"];
  for (let index = 0; index < 25; index += 1) {
    const mode = index % 5;
    const status = index === 0 ? "closed" : (index === 1 ? "resolved" : (index === 2 ? "rejected" : statusRing[index % statusRing.length]));
    const row = {
      id: `report-scoped-${index + 1}`,
      status,
      officeId: mode === 0 ? "OFF-1" : "OFF-2",
      assignedOfficeId: mode === 1 ? "OFF-1" : null,
      currentOfficeId: mode === 2 ? "OFF-1" : (mode === 0 ? "OFF-1" : "OFF-2"),
      assignedToUid: mode === 3 ? "office1" : null,
      createdByUid: mode === 4 ? "office1" : `resident${index + 1}`,
      lane: mode === 2 ? "emergency" : "issue",
      emergencyType: mode === 2 ? "medical" : null,
      updatedAt: timestampFromSeed(1700000100000 - (index * 1000)),
      createdAt: timestampFromSeed(1700000000000 + index),
    };
    rows.push(row);
  }

  rows.push({
    id: "report-out-of-scope",
    status: "submitted",
    officeId: "OFF-9",
    assignedOfficeId: null,
    currentOfficeId: "OFF-9",
    assignedToUid: null,
    createdByUid: "resident-outside",
    lane: "issue",
    updatedAt: timestampFromSeed(1699999999000),
    createdAt: timestampFromSeed(1699999998000),
  });

  await Promise.all(rows.map((row) => db.doc(`reports/${row.id}`).set(row)));
}

async function run() {
  if (!process.env.FIRESTORE_EMULATOR_HOST) {
    throw new Error("FIRESTORE_EMULATOR_HOST is required for callable integration tests.");
  }

  const functionsModule = require("../lib/index.js");
  if (!functionsModule.__testing || typeof functionsModule.__testing.adminReportsBootstrapHandler !== "function") {
    throw new Error("__testing adminReportsBootstrapHandler export is missing.");
  }

  if (admin.apps.length === 0) {
    const projectId = process.env.GCLOUD_PROJECT || process.env.GCLOUD_PROJECT_ID || "mydaet";
    admin.initializeApp({projectId});
  }

  const db = admin.firestore();
  await seedData(db);

  const officeContext = contextFor("office1", "office_admin", "OFF-1", "Office 1");
  const office2Context = contextFor("office2", "office_admin", "OFF-2", "Office 2");
  const office4Context = contextFor("office4", "office_admin", "OFF-4", "Office 4");
  const firstPage = await functionsModule.__testing.adminReportsBootstrapHandler({limit: 2}, officeContext);
  assert.strictEqual(Array.isArray(firstPage.reports), true, "first page should include reports array");
  assert.strictEqual(firstPage.reports.length, 20, "first page should respect minimum page size of 20");
  assert.ok(firstPage.nextCursor && firstPage.nextCursor.cursorId, "first page should include next cursor");
  assert.strictEqual(firstPage.viewCounts.allReports, 25, "office scope should include all scoped reports");
  assert.strictEqual(firstPage.viewCounts.archive, 3, "office scope archive count should include resolved/closed/rejected");
  assert.strictEqual(firstPage.viewCounts.allActive, 22, "office scope active count should be authoritative");

  const seenIds = new Set(firstPage.reports.map((row) => row.id));
  let cursor = firstPage.nextCursor;
  let guard = 0;
  while (cursor && guard < 10) {
    const page = await functionsModule.__testing.adminReportsBootstrapHandler(
      {
        limit: 2,
        cursorUpdatedAt: cursor.cursorUpdatedAt,
        cursorId: cursor.cursorId,
      },
      officeContext
    );
    page.reports.forEach((row) => seenIds.add(row.id));
    cursor = page.nextCursor;
    guard += 1;
  }

  assert.strictEqual(seenIds.size, 25, "cursor pagination should eventually return every scoped report exactly once");
  assert.strictEqual(seenIds.has("report-out-of-scope"), false, "out-of-scope report must never leak");

  const superContext = contextFor("super1", "super_admin", null, null);
  const superPage = await functionsModule.__testing.adminReportsBootstrapHandler({limit: 1}, superContext);
  assert.strictEqual(superPage.reports.length, 20, "super page should respect minimum page size of 20");
  assert.strictEqual(superPage.viewCounts.allReports, 26, "super-admin should receive municipal-wide report count");

  const destinationCreate = await functionsModule.__testing.dtsCreateDestinationsHandler(
    {
      docId: "doc-md-1",
      destinations: [
        {toOfficeId: "OFF-2", toOfficeName: "Office 2"},
        {toOfficeId: "OFF-3", toOfficeName: "Office 3"},
        {toOfficeId: "OFF-4", toOfficeName: "Office 4"},
      ],
    },
    officeContext
  );
  assert.strictEqual(destinationCreate.success, true, "destination create should succeed");
  assert.strictEqual(destinationCreate.created.length, 3, "should create three destination rows");

  const destinationIds = destinationCreate.created.map((row) => row.id);
  const dispatch = await functionsModule.__testing.dtsDispatchDestinationsHandler(
    {
      docId: "doc-md-1",
      destinationIds,
    },
    officeContext
  );
  assert.strictEqual(dispatch.success, true, "dispatch should succeed");
  assert.strictEqual(dispatch.dispatchedCount, 3, "all destinations should be dispatched");

  const receiptResult = await functionsModule.__testing.dtsConfirmDestinationReceiptHandler(
    {
      docId: "doc-md-1",
      destinationId: destinationIds[0],
      verificationValue: "123456",
      verificationMethod: "MANUAL_INPUT",
      confirmPhysicalReceipt: true,
    },
    office2Context
  );
  assert.strictEqual(receiptResult.success, true, "destination receipt should succeed");

  await assert.rejects(
    async () => functionsModule.__testing.dtsConfirmDestinationReceiptHandler(
      {
        docId: "doc-md-1",
        destinationId: destinationIds[1],
        verificationValue: "123456",
        verificationMethod: "MANUAL_INPUT",
        confirmPhysicalReceipt: true,
      },
      office2Context
    ),
    /not authorized|Select a destination transfer/i,
    "office without target scope should not confirm other destination"
  );

  const cancelResult = await functionsModule.__testing.dtsCancelDestinationHandler(
    {
      docId: "doc-md-1",
      destinationId: destinationIds[1],
      reason: "Memo no longer needed for this office.",
    },
    officeContext
  );
  assert.strictEqual(cancelResult.success, true, "source office should cancel destination");

  const rejectResult = await functionsModule.__testing.dtsRejectDestinationHandler(
    {
      docId: "doc-md-1",
      destinationId: destinationIds[2],
      reason: "Destination office cannot process this item.",
    },
    office4Context
  );
  assert.strictEqual(rejectResult.success, true, "receiving office should reject destination");

  const docAfterDestinations = await db.doc("dts_documents/doc-md-1").get();
  const afterData = docAfterDestinations.data();
  assert.strictEqual(afterData.destTotal, 3, "parent should keep total destination count");
  assert.strictEqual(afterData.destPending, 0, "parent pending counter should reconcile");
  assert.strictEqual(afterData.destInTransit, 0, "no destination should remain in transit");
  assert.strictEqual(afterData.destReceived, 1, "parent received counter should increment");
  assert.strictEqual(afterData.destRejected, 1, "parent rejected counter should increment");
  assert.strictEqual(afterData.destCancelled, 1, "parent cancelled counter should increment");
  assert.strictEqual(afterData.status, "WITH_OFFICE", "parent should return to with_office after all in-transit rows resolve");
  assert.strictEqual(afterData.distributionMode, "MULTI", "multi-destination docs should remain in MULTI mode");

  const destinationSnap = await db
    .collection("dts_documents")
    .doc("doc-md-1")
    .collection("destinations")
    .get();
  assert.strictEqual(destinationSnap.size, 3, "destination collection should contain 3 rows");
  const destinationCounts = destinationSnap.docs.reduce((acc, item) => {
    const status = (item.data()?.status || "PENDING").toString().toUpperCase();
    acc.total += 1;
    if (status === "PENDING") acc.pending += 1;
    if (status === "IN_TRANSIT") acc.inTransit += 1;
    if (status === "RECEIVED") acc.received += 1;
    if (status === "REJECTED") acc.rejected += 1;
    if (status === "CANCELLED") acc.cancelled += 1;
    return acc;
  }, {
    total: 0,
    pending: 0,
    inTransit: 0,
    received: 0,
    rejected: 0,
    cancelled: 0,
  });

  assert.strictEqual(afterData.destTotal, destinationCounts.total, "destTotal must match destination truth");
  assert.strictEqual(afterData.destPending, destinationCounts.pending, "destPending must match destination truth");
  assert.strictEqual(afterData.destInTransit, destinationCounts.inTransit, "destInTransit must match destination truth");
  assert.strictEqual(afterData.destReceived, destinationCounts.received, "destReceived must match destination truth");
  assert.strictEqual(afterData.destRejected, destinationCounts.rejected, "destRejected must match destination truth");
  assert.strictEqual(afterData.destCancelled, destinationCounts.cancelled, "destCancelled must match destination truth");
  assert.deepStrictEqual(afterData.activeDestinationOfficeIds || [], [], "no active destination offices should remain");
  assert.deepStrictEqual(
    afterData.destinationOfficeIds || [],
    ["OFF-2", "OFF-3", "OFF-4"],
    "destinationOfficeIds should contain the full office set"
  );

  const timelineSnap = await db
    .collection("dts_documents")
    .doc("doc-md-1")
    .collection("timeline")
    .get();
  const timelineRows = timelineSnap.docs
    .map((item) => ({id: item.id, ...item.data()}))
    .sort((left, right) => {
      const leftMillis = left.createdAt?.toMillis ? left.createdAt.toMillis() : 0;
      const rightMillis = right.createdAt?.toMillis ? right.createdAt.toMillis() : 0;
      if (leftMillis !== rightMillis) {
        return leftMillis - rightMillis;
      }
      return left.id.localeCompare(right.id);
    });

  const eventTypeOf = (row) => (row.actionType || row.type || "").toString().toUpperCase();
  const firstIndexOf = (eventType) => timelineRows.findIndex((row) => eventTypeOf(row) === eventType);
  const createdIndex = firstIndexOf("DESTINATIONS_UPDATED");
  const routedIndex = firstIndexOf("DOCUMENT_ROUTED");
  const receivedIndex = firstIndexOf("DOCUMENT_RECEIVED");
  const cancelledIndex = firstIndexOf("TRANSFER_CANCELLED");
  const rejectedIndex = firstIndexOf("TRANSFER_REJECTED");

  assert.ok(createdIndex >= 0, "timeline should include DESTINATIONS_UPDATED");
  assert.ok(routedIndex >= 0, "timeline should include DOCUMENT_ROUTED");
  assert.ok(receivedIndex >= 0, "timeline should include DOCUMENT_RECEIVED");
  assert.ok(cancelledIndex >= 0, "timeline should include TRANSFER_CANCELLED");
  assert.ok(rejectedIndex >= 0, "timeline should include TRANSFER_REJECTED");
  assert.ok(createdIndex < routedIndex, "destinations should be created before dispatch");
  assert.ok(routedIndex < receivedIndex, "dispatch should happen before receipt confirmation");
  assert.ok(receivedIndex < cancelledIndex, "receipt should occur before source cancellation");
  assert.ok(cancelledIndex < rejectedIndex, "cancellation should occur before rejection in this scripted flow");

  const cancelledEvent = timelineRows[cancelledIndex];
  const rejectedEvent = timelineRows[rejectedIndex];
  assert.strictEqual(cancelledEvent.reason, "Memo no longer needed for this office.", "cancel timeline should keep reason");
  assert.strictEqual(cancelledEvent.byUid, "office1", "cancel timeline should keep actor uid");
  assert.strictEqual(cancelledEvent.byOfficeId, "OFF-1", "cancel timeline should keep actor office");
  assert.strictEqual(rejectedEvent.reason, "Destination office cannot process this item.", "reject timeline should keep reason");
  assert.strictEqual(rejectedEvent.byUid, "office4", "reject timeline should keep actor uid");
  assert.strictEqual(rejectedEvent.byOfficeId, "OFF-4", "reject timeline should keep actor office");
  assert.ok(cancelledEvent.createdAt && cancelledEvent.createdAt.toMillis, "cancel timeline should include timestamp");
  assert.ok(rejectedEvent.createdAt && rejectedEvent.createdAt.toMillis, "reject timeline should include timestamp");

  console.log("callables.integration.test: PASS");
}

run().catch((error) => {
  console.error("callables.integration.test: FAIL", error);
  process.exit(1);
});
