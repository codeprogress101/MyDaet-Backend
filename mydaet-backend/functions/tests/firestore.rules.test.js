/* eslint-disable no-console */
const fs = require("fs");
const path = require("path");
const {
  initializeTestEnvironment,
  assertFails,
  assertSucceeds,
} = require("@firebase/rules-unit-testing");

function nowIso() {
  return new Date().toISOString();
}

async function seedBaseData(testEnv) {
  await testEnv.withSecurityRulesDisabled(async (context) => {
    const db = context.firestore();

    await db.doc("users/super1").set({
      uid: "super1",
      role: "super_admin",
      isActive: true,
      officeId: null,
      officeName: null,
    });
    await db.doc("users/admin1").set({
      uid: "admin1",
      role: "admin",
      isActive: true,
      officeId: null,
      officeName: "Municipal Admin",
    });
    await db.doc("users/office1").set({
      uid: "office1",
      role: "office_admin",
      isActive: true,
      officeId: "OFF-1",
      officeName: "Office 1",
    });
    await db.doc("users/mod1").set({
      uid: "mod1",
      role: "moderator",
      isActive: true,
      officeId: "OFF-1",
      officeName: "Office 1",
    });
    await db.doc("users/mod2").set({
      uid: "mod2",
      role: "moderator",
      isActive: true,
      officeId: "OFF-2",
      officeName: "Office 2",
    });
    await db.doc("users/civilMod").set({
      uid: "civilMod",
      role: "moderator",
      isActive: true,
      officeId: "OFF-CIVIL",
      officeName: "Municipal Civil Registry Office",
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
      status: "assigned",
      officeId: "OFF-1",
      officeName: "Office 1",
      createdByUid: "resident1",
      assignedToUid: "mod1",
      assignedOfficeId: "OFF-1",
      currentOfficeId: "OFF-1",
      updatedAt: nowIso(),
    });
    await db.doc("reports/report-2").set({
      title: "Flooded street",
      category: "Emergency",
      status: "in_progress",
      officeId: "OFF-2",
      officeName: "Office 2",
      createdByUid: "resident2",
      assignedToUid: "mod2",
      assignedOfficeId: "OFF-2",
      currentOfficeId: "OFF-2",
      updatedAt: nowIso(),
    });
    await db.doc("reports/report-3").set({
      title: "Loose wire",
      category: "Road",
      status: "submitted",
      officeId: "OFF-1",
      officeName: "Office 1",
      createdByUid: "resident1",
      assignedToUid: null,
      assignedOfficeId: null,
      currentOfficeId: "OFF-1",
      updatedAt: nowIso(),
    });

    await db.doc("reports/report-1/timeline/event-1").set({
      type: "STATUS_CHANGED",
      actorUid: "mod1",
      actorRole: "moderator",
      notes: "Assigned to moderator.",
      createdByUid: "resident1",
      officeId: "OFF-1",
      currentOfficeId: "OFF-1",
      assignedOfficeId: "OFF-1",
      assignedToUid: "mod1",
      createdAt: nowIso(),
    });

    await db.doc("audit_logs/log-1").set({
      action: "report_created",
      entityType: "report",
      entityId: "report-1",
      officeId: "OFF-1",
    });
    await db.doc("auditLogs/log-2").set({
      action: "reports_bootstrap",
      entityType: "reports",
      entityId: "bootstrap",
      officeId: "OFF-1",
    });

    await db.doc("dts_documents/doc-1").set({
      qrCode: "QR-1",
      trackingNo: "DTS-2026-OFF1-0001",
      publicPinHash: "legacy",
      title: "Office 1 Doc",
      docType: "Request",
      status: "IN_TRANSIT",
      currentOfficeId: "OFF-1",
      currentOfficeName: "Office 1",
      currentCustodianUid: null,
      distributionMode: "MULTI",
      destTotal: 2,
      destPending: 1,
      destInTransit: 1,
      destReceived: 0,
      destRejected: 0,
      destCancelled: 0,
      activeDestinationOfficeIds: ["OFF-2"],
      destinationOfficeIds: ["OFF-2", "OFF-3"],
      updatedAt: new Date(),
    });
    await db.doc("dts_documents/doc-2").set({
      qrCode: "QR-2",
      trackingNo: "DTS-2026-OFF2-0001",
      publicPinHash: "legacy",
      title: "Office 2 Doc",
      docType: "Request",
      status: "WITH_OFFICE",
      currentOfficeId: "OFF-2",
      currentOfficeName: "Office 2",
      currentCustodianUid: "mod2",
      updatedAt: new Date(),
    });
    await db.doc("dts_documents/doc-1/timeline/event-1").set({
      type: "STATUS_CHANGED",
      notePublic: "Document received.",
      byUid: "mod1",
      officeName: "Office 1",
      createdAt: nowIso(),
    });
    await db.doc("dts_documents/doc-2/timeline/event-1").set({
      type: "STATUS_CHANGED",
      notePublic: "Document received.",
      byUid: "mod2",
      officeName: "Office 2",
      createdAt: nowIso(),
    });
    await db.doc("dts_documents/doc-1/destinations/dest-1").set({
      docId: "doc-1",
      toOfficeId: "OFF-2",
      toOfficeName: "Office 2",
      sourceOfficeId: "OFF-1",
      sourceOfficeName: "Office 1",
      status: "IN_TRANSIT",
      createdByUid: "mod1",
      createdByName: "Office 1 Admin",
      updatedAt: nowIso(),
    });
    await db.doc("dts_documents/doc-1/destinations/dest-2").set({
      docId: "doc-1",
      toOfficeId: "OFF-3",
      toOfficeName: "Office 3",
      sourceOfficeId: "OFF-1",
      sourceOfficeName: "Office 1",
      status: "PENDING",
      createdByUid: "mod1",
      createdByName: "Office 1 Admin",
      updatedAt: nowIso(),
    });
    await db.doc("dts_documents/doc-2/destinations/dest-1").set({
      docId: "doc-2",
      toOfficeId: "OFF-2",
      toOfficeName: "Office 2",
      sourceOfficeId: "OFF-2",
      sourceOfficeName: "Office 2",
      status: "PENDING",
      createdByUid: "mod2",
      createdByName: "Office 2 Admin",
      updatedAt: nowIso(),
    });

    await db.doc("civil_registry_requests/cr-1").set({
      fullName: "Test Citizen",
      status: "submitted",
      createdAt: nowIso(),
    });

    await db.doc("staff_threads/thread-1").set({
      memberIds: ["mod1", "admin1"],
      updatedAt: nowIso(),
    });
    await db.doc("staff_threads/thread-1/messages/msg-1").set({
      senderUid: "mod1",
      text: "Hello admin",
      createdAt: nowIso(),
    });

    await db.doc("posts/post-1").set({
      type: "announcement",
      title: "Existing post",
      body: "Hello",
      status: "draft",
      officeId: "OFF-1",
    });
    await db.doc("public_docs/doc-1").set({
      docType: "ordinance",
      docNo: "2026-001",
      title: "Ordinance",
      summary: "Summary",
      status: "draft",
      officeId: "SANGGUNIANG_BAYAN",
    });
    await db.doc("jobs/job-1").set({
      title: "Engineer",
      status: "draft",
      officeId: "OFF-1",
    });
    await db.doc("directory_entries/dir-1").set({
      officeId: "OFF-1",
      officeName: "Office 1",
      contactName: "Office Head",
      position: "Head",
      phone: "09170000000",
      status: "draft",
      isPublic: false,
    });
    await db.doc("directory_entries/dir-2").set({
      officeId: "OFF-1",
      officeName: "Office 1",
      contactName: "Published Head",
      position: "Head",
      phone: "09171111111",
      status: "published",
      isPublic: true,
    });
    await db.doc("emergency_hotlines/hotline-1").set({
      label: "COMCEN",
      group: "Dispatch",
      contactNumbers: ["(054) 472-3000"],
      status: "draft",
      isPublic: false,
    });
    await db.doc("emergency_hotlines/hotline-2").set({
      label: "BFP",
      group: "Fire",
      contactNumbers: ["(054) 473-8472"],
      status: "published",
      isPublic: true,
    });
  });
}

async function run() {
  const projectId = process.env.GCLOUD_PROJECT || "mydaet";
  const rules = fs.readFileSync(
    path.resolve(__dirname, "../../firestore.rules"),
    "utf8"
  );

  const testEnv = await initializeTestEnvironment({
    projectId,
    firestore: {rules},
  });

  try {
    await seedBaseData(testEnv);

    const superDb = testEnv.authenticatedContext("super1", {
      role: "super_admin",
      officeId: "",
      officeName: "",
      isActive: true,
    }).firestore();
    const adminDb = testEnv.authenticatedContext("admin1", {
      role: "admin",
      officeId: "",
      officeName: "",
      isActive: true,
    }).firestore();
    const officeDb = testEnv.authenticatedContext("office1", {
      role: "office_admin",
      officeId: "OFF-1",
      officeName: "Office 1",
      isActive: true,
    }).firestore();
    const mod1Db = testEnv.authenticatedContext("mod1", {
      role: "moderator",
      officeId: "OFF-1",
      officeName: "Office 1",
      isActive: true,
    }).firestore();
    const mod2Db = testEnv.authenticatedContext("mod2", {
      role: "moderator",
      officeId: "OFF-2",
      officeName: "Office 2",
      isActive: true,
    }).firestore();
    const civilModDb = testEnv.authenticatedContext("civilMod", {
      role: "moderator",
      officeId: "OFF-CIVIL",
      officeName: "Municipal Civil Registry Office",
      isActive: true,
    }).firestore();
    const resident1Db = testEnv.authenticatedContext("resident1", {
      role: "resident",
      officeId: "",
      officeName: "",
      isActive: true,
    }).firestore();
    const publicDb = testEnv.unauthenticatedContext().firestore();

    // Role + scope: reports.
    await assertSucceeds(adminDb.doc("reports/report-1").get());
    await assertSucceeds(adminDb.doc("reports/report-2").get());
    await assertSucceeds(officeDb.doc("reports/report-1").get());
    await assertFails(officeDb.doc("reports/report-2").get());
    await assertSucceeds(mod1Db.doc("reports/report-1").get());
    await assertFails(mod1Db.doc("reports/report-2").get());
    await assertSucceeds(resident1Db.doc("reports/report-1").get());
    await assertFails(resident1Db.doc("reports/report-2").get());

    // Residents can edit only their own submitted/in_review content fields.
    await assertSucceeds(
      resident1Db.doc("reports/report-3").set(
        {
          title: "Loose wire near post",
          description: "Updated details from resident",
          status: "submitted",
          assignedToUid: null,
          assignedToName: null,
          assignedOfficeId: null,
          createdByUid: "resident1",
        },
        {merge: true}
      )
    );
    await assertFails(
      resident1Db.doc("reports/report-3").set(
        {
          status: "assigned",
          createdByUid: "resident1",
        },
        {merge: true}
      )
    );
    await assertFails(
      mod1Db.doc("reports/report-1").set(
        {status: "resolved"},
        {merge: true}
      )
    );

    // Timeline is append-only from backend.
    await assertSucceeds(mod1Db.doc("reports/report-1/timeline/event-1").get());
    await assertFails(mod2Db.doc("reports/report-1/timeline/event-1").get());
    await assertFails(
      mod1Db.doc("reports/report-1/timeline/event-client").set({
        type: "STATUS_CHANGED",
        actorUid: "mod1",
        createdAt: nowIso(),
      })
    );

    // Privileged content mutations are callable-only.
    await assertFails(
      adminDb.doc("posts/post-1").set({title: "Client edit blocked"}, {merge: true})
    );
    await assertFails(
      superDb.doc("public_docs/doc-1").set({status: "published"}, {merge: true})
    );
    await assertFails(
      adminDb.doc("jobs/job-1").set({status: "published"}, {merge: true})
    );

    // Public contacts: staff can read drafts; public can read only published
    // directory entries when the directory feature is enabled, while emergency
    // hotlines remain publicly readable regardless of the directory toggle.
    await assertSucceeds(adminDb.doc("directory_entries/dir-1").get());
    await assertSucceeds(mod1Db.doc("directory_entries/dir-1").get());
    await assertFails(publicDb.doc("directory_entries/dir-1").get());
    await assertSucceeds(publicDb.doc("directory_entries/dir-2").get());
    await assertSucceeds(adminDb.doc("emergency_hotlines/hotline-1").get());
    await assertFails(publicDb.doc("emergency_hotlines/hotline-1").get());
    await assertSucceeds(publicDb.doc("emergency_hotlines/hotline-2").get());

    // Staff reads for admin-managed content should remain available even when
    // the public feature toggle is off. Public readers still stay blocked.
    await testEnv.withSecurityRulesDisabled(async (context) => {
      await context.firestore().doc("posts/post-news-hidden").set({
        type: "news",
        title: "Hidden news draft",
        body: "Draft body",
        status: "draft",
        officeId: "OFF-1",
      });
      await context.firestore().doc("posts/post-news-published").set({
        type: "news",
        title: "Hidden published news",
        body: "Published body",
        status: "published",
        officeId: "OFF-1",
      });
      await context.firestore().doc("system/settings").set({
        features: {
          announcements: false,
          news: false,
          transparency: false,
          jobs: false,
          directory: false,
        },
      }, {merge: true});
    });

    await assertSucceeds(superDb.doc("posts/post-news-hidden").get());
    await assertSucceeds(adminDb.doc("posts/post-news-hidden").get());
    await assertSucceeds(mod1Db.doc("posts/post-news-hidden").get());
    await assertFails(publicDb.doc("posts/post-news-published").get());
    await assertFails(publicDb.doc("directory_entries/dir-2").get());
    await assertSucceeds(publicDb.doc("emergency_hotlines/hotline-2").get());

    await testEnv.withSecurityRulesDisabled(async (context) => {
      await context.firestore().doc("system/settings").delete();
    });

    // Messaging scope and write restrictions.
    await assertSucceeds(mod1Db.doc("staff_threads/thread-1").get());
    await assertSucceeds(mod1Db.doc("staff_threads/thread-1/messages/msg-1").get());
    await assertFails(officeDb.doc("staff_threads/thread-1").get());
    await assertFails(
      mod1Db.doc("staff_threads/thread-1/messages/msg-2").set({
        senderUid: "mod1",
        text: "Client write should fail",
        createdAt: nowIso(),
      })
    );

    // Messaging feature is independent from reports toggle.
    await testEnv.withSecurityRulesDisabled(async (context) => {
      await context.firestore().doc("system/settings").set({
        features: {
          reports: false,
          messages: true,
        },
      }, {merge: true});
    });
    await assertSucceeds(mod1Db.doc("staff_threads/thread-1").get());
    await testEnv.withSecurityRulesDisabled(async (context) => {
      await context.firestore().doc("system/settings").delete();
    });

    // DTS scope boundaries.
    await assertSucceeds(officeDb.doc("dts_documents/doc-1").get());
    await assertFails(officeDb.doc("dts_documents/doc-2").get());
    await assertSucceeds(adminDb.doc("dts_documents/doc-2").get());
    await assertSucceeds(mod2Db.doc("dts_documents/doc-1").get());
    await assertSucceeds(mod1Db.doc("dts_documents/doc-1/timeline/event-1").get());
    await assertFails(mod1Db.doc("dts_documents/doc-2/timeline/event-1").get());
    await assertSucceeds(mod1Db.doc("dts_documents/doc-1/destinations/dest-1").get());
    await assertSucceeds(mod2Db.doc("dts_documents/doc-1/destinations/dest-1").get());
    await assertFails(mod2Db.doc("dts_documents/doc-1/destinations/dest-2").get());
    await assertFails(resident1Db.doc("dts_documents/doc-1/destinations/dest-1").get());
    await assertFails(
      mod2Db.doc("dts_documents/doc-1/destinations/dest-2").set(
        {status: "RECEIVED"},
        {merge: true}
      )
    );
    await assertFails(
      mod1Db.doc("dts_documents/doc-1/timeline/event-2").set({
        type: "NOTE",
        byUid: "mod1",
        createdAt: nowIso(),
      })
    );
    await assertFails(
      mod1Db.doc("dts_documents/doc-2/timeline/event-3").set({
        type: "NOTE",
        byUid: "mod1",
        createdAt: nowIso(),
      })
    );
    await assertFails(
      adminDb.doc("dts_documents/doc-new").set({
        qrCode: "QR-NEW",
        trackingNo: "DTS-NEW",
        publicPinHash: "hash",
        title: "New Doc",
        docType: "REQUEST",
        status: "RECEIVED",
        currentOfficeId: "OFF-1",
      })
    );
    await assertFails(
      adminDb.doc("dts_qr_index/QR-NEW").set({
        docId: "doc-new",
      })
    );

    // Civil registry scope.
    await assertSucceeds(adminDb.doc("civil_registry_requests/cr-1").get());
    await assertSucceeds(civilModDb.doc("civil_registry_requests/cr-1").get());
    await assertFails(mod2Db.doc("civil_registry_requests/cr-1").get());

    // User management boundaries.
    await assertSucceeds(officeDb.doc("users/mod1").get());
    await assertFails(officeDb.doc("users/super1").get());
    await assertSucceeds(
      resident1Db.doc("users/resident1").set(
        {displayName: "Resident One", updatedAt: new Date()},
        {merge: true}
      )
    );
    await assertFails(
      resident1Db.doc("users/resident1").set(
        {role: "admin", updatedAt: new Date()},
        {merge: true}
      )
    );
    await assertFails(
      adminDb.doc("users/mod1").set(
        {role: "super_admin", updatedAt: new Date()},
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
