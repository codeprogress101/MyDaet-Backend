/* eslint-disable no-console */
const fs = require("fs");
const path = require("path");
const {
  initializeTestEnvironment,
  assertFails,
  assertSucceeds,
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

  try {
    await testEnv.withSecurityRulesDisabled(async (context) => {
      const db = context.firestore();

      await db.doc("users/super1").set({
        uid: "super1",
        role: "super_admin",
        isActive: true,
      });
      await db.doc("users/admin1").set({
        uid: "admin1",
        role: "admin",
        officeId: "OFF-1",
        officeName: "Office 1",
        isActive: true,
      });
      await db.doc("users/mod1").set({
        uid: "mod1",
        role: "moderator",
        officeId: "OFF-1",
        officeName: "Office 1",
        isActive: true,
      });
      await db.doc("users/mod2").set({
        uid: "mod2",
        role: "moderator",
        officeId: "OFF-2",
        officeName: "Office 2",
        isActive: true,
      });
      await db.doc("users/resident1").set({
        uid: "resident1",
        role: "resident",
        isActive: true,
      });
      await db.doc("users/resident2").set({
        uid: "resident2",
        role: "resident",
        isActive: true,
      });

      await db.doc("reports/report-1").set({
        title: "Streetlight issue",
        category: "Road",
        status: "submitted",
        officeId: "OFF-1",
        officeName: "Office 1",
        createdByUid: "resident1",
        assignedToUid: "mod1",
        assignedOfficeId: "OFF-1",
        currentOfficeId: "OFF-1",
      });

      await db.doc("audit_logs/log-1").set({
        action: "report_created",
        entityType: "report",
        entityId: "report-1",
        officeId: "OFF-1",
      });

      await db.doc("dts_documents/doc-1").set({
        qrCode: "QR-1",
        trackingNo: "DTS-2026-OFF-0001",
        publicPinHash: "legacy",
        title: "Sample",
        docType: "Request",
        status: "WITH_OFFICE",
        currentOfficeId: "OFF-1",
        currentOfficeName: "Office 1",
        updatedAt: new Date(),
      });
    });

    const superCtx = testEnv.authenticatedContext("super1", {
      role: "super_admin",
      isActive: true,
    });
    const adminCtx = testEnv.authenticatedContext("admin1", {
      role: "admin",
      officeId: "OFF-1",
      officeName: "Office 1",
      isActive: true,
    });
    const modCtx = testEnv.authenticatedContext("mod2", {
      role: "moderator",
      officeId: "OFF-2",
      officeName: "Office 2",
      isActive: true,
    });
    const residentCtx = testEnv.authenticatedContext("resident1", {
      role: "resident",
      isActive: true,
    });
    const otherResidentCtx = testEnv.authenticatedContext("resident2", {
      role: "resident",
      isActive: true,
    });

    const superDb = superCtx.firestore();
    const adminDb = adminCtx.firestore();
    const modDb = modCtx.firestore();
    const residentDb = residentCtx.firestore();
    const otherResidentDb = otherResidentCtx.firestore();

    // Reports visibility
    await assertSucceeds(adminDb.doc("reports/report-1").get());
    await assertSucceeds(modDb.doc("reports/report-1").get());
    await assertSucceeds(residentDb.doc("reports/report-1").get());
    await assertFails(otherResidentDb.doc("reports/report-1").get());

    // Audit logs are server-write only
    await assertFails(
      adminDb.doc("audit_logs/new-log").set({
        action: "manual_write",
      })
    );
    await assertSucceeds(adminDb.doc("audit_logs/log-1").get());
    await assertFails(modDb.doc("audit_logs/log-1").get());
    await assertSucceeds(superDb.doc("audit_logs/log-1").get());

    // User management constraints
    await assertSucceeds(
      residentDb.doc("users/resident1").set(
        {
          displayName: "Resident One",
          updatedAt: new Date(),
        },
        {merge: true}
      )
    );
    await assertFails(
      residentDb.doc("users/resident1").set(
        {
          role: "admin",
          updatedAt: new Date(),
        },
        {merge: true}
      )
    );
    await assertFails(
      adminDb.doc("users/mod1").set(
        {
          role: "super_admin",
          updatedAt: new Date(),
        },
        {merge: true}
      )
    );
  } finally {
    await testEnv.cleanup();
  }

  console.log("firestore rules tests passed");
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
