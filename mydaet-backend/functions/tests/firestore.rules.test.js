/* eslint-disable no-console */
const fs = require("fs");
const path = require("path");
const assert = require("assert/strict");
const {
  initializeTestEnvironment,
  assertFails,
} = require("@firebase/rules-unit-testing");

async function run() {
  const projectId = `mydaet-rules-${Date.now()}`;
  const rules = fs.readFileSync(
    path.resolve(__dirname, "../../firestore.rules"),
    "utf8"
  );

  const testEnv = await initializeTestEnvironment({
    projectId,
    firestore: {rules},
  });

  await testEnv.withSecurityRulesDisabled(async (context) => {
    const db = context.firestore();
    await db.doc("users/staff1").set({
      uid: "staff1",
      role: "office_admin",
      officeId: "OFF-1",
      officeName: "Office 1",
      isActive: true,
    });
    await db.doc("users/resident1").set({
      uid: "resident1",
      role: "resident",
      isActive: true,
    });
    await db.doc("dts_documents/doc-1").set({
      qrCode: "QR-1",
      trackingNo: "DTS-2026-OFF-0001",
      publicPinHash: "hash",
      title: "Sample",
      docType: "Request",
      status: "WITH_OFFICE",
      currentOfficeId: "OFF-1",
      currentOfficeName: "Office 1",
      updatedAt: new Date(),
    });
  });

  const staff = testEnv.authenticatedContext("staff1", {
    role: "office_admin",
    officeId: "OFF-1",
    officeName: "Office 1",
    isActive: true,
  });
  const resident = testEnv.authenticatedContext("resident1", {
    role: "resident",
    isActive: true,
  });

  const staffDb = staff.firestore();
  const residentDb = resident.firestore();

  await assertFails(
    staffDb.doc("dts_documents/doc-1").set(
      {
        status: "IN_PROCESS",
        updatedAt: new Date(),
      },
      {merge: true}
    )
  );

  await assertFails(
    residentDb.doc("dts_documents/doc-1").set(
      {
        status: "IN_PROCESS",
      },
      {merge: true}
    )
  );

  await assertFails(
    staffDb.doc("dts_documents/doc-1/timeline/event-1").set({
      type: "STATUS_CHANGED",
      byUid: "another-user",
      createdAt: new Date(),
    })
  );

  await testEnv.cleanup();
  console.log("firestore rules test passed");
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});

