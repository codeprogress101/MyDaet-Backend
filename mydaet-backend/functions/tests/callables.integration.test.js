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

  console.log("callables.integration.test: PASS");
}

run().catch((error) => {
  console.error("callables.integration.test: FAIL", error);
  process.exit(1);
});
