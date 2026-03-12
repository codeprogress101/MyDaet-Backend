/* eslint-disable no-console */
const fs = require("fs");
const path = require("path");
const {
  initializeTestEnvironment,
  assertFails,
  assertSucceeds,
} = require("@firebase/rules-unit-testing");
const {ref, uploadString, getDownloadURL} = require("firebase/storage");

async function seedStorageAndFirestore(testEnv, bucket) {
  await testEnv.withSecurityRulesDisabled(async (context) => {
    const db = context.firestore();
    const storage = context.storage(bucket);

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
      createdByUid: "resident1",
      officeId: "OFF-1",
      currentOfficeId: "OFF-1",
      assignedOfficeId: "OFF-1",
      assignedToUid: "mod1",
    });
    await db.doc("reports/report-2").set({
      createdByUid: "resident2",
      officeId: "OFF-2",
      currentOfficeId: "OFF-2",
      assignedOfficeId: "OFF-2",
      assignedToUid: "mod2",
    });

    await db.doc("dts_documents/doc-1").set({
      currentOfficeId: "OFF-1",
      currentOfficeName: "Office 1",
      currentCustodianUid: "mod1",
    });
    await db.doc("dts_documents/doc-2").set({
      currentOfficeId: "OFF-2",
      currentOfficeName: "Office 2",
      currentCustodianUid: "mod2",
    });

    await uploadString(
      ref(storage, "reports/resident2/report-2/existing.jpg"),
      "seed",
      "raw",
      {contentType: "image/jpeg"}
    );
  });
}

async function run() {
  const projectId = process.env.GCLOUD_PROJECT || "mydaet";
  const bucket = "mydaet.appspot.com";
  const firestoreRules = fs.readFileSync(
    path.resolve(__dirname, "../../firestore.rules"),
    "utf8"
  );
  const storageRules = fs.readFileSync(
    path.resolve(__dirname, "../../storage.rules"),
    "utf8"
  );

  const testEnv = await initializeTestEnvironment({
    projectId,
    firestore: {rules: firestoreRules},
    storage: {rules: storageRules},
  });

  try {
    await seedStorageAndFirestore(testEnv, bucket);

    const unauthStorage = testEnv.unauthenticatedContext().storage(bucket);
    const superStorage = testEnv.authenticatedContext("super1", {
      role: "super_admin",
      officeId: "",
      officeName: "",
      isActive: true,
    }).storage(bucket);
    const adminStorage = testEnv.authenticatedContext("admin1", {
      role: "admin",
      officeId: "",
      officeName: "",
      isActive: true,
    }).storage(bucket);
    const officeStorage = testEnv.authenticatedContext("office1", {
      role: "office_admin",
      officeId: "OFF-1",
      officeName: "Office 1",
      isActive: true,
    }).storage(bucket);
    const mod1Storage = testEnv.authenticatedContext("mod1", {
      role: "moderator",
      officeId: "OFF-1",
      officeName: "Office 1",
      isActive: true,
    }).storage(bucket);
    const mod2Storage = testEnv.authenticatedContext("mod2", {
      role: "moderator",
      officeId: "OFF-2",
      officeName: "Office 2",
      isActive: true,
    }).storage(bucket);
    const resident1Storage = testEnv.authenticatedContext("resident1", {
      role: "resident",
      officeId: "",
      officeName: "",
      isActive: true,
    }).storage(bucket);
    const resident2Storage = testEnv.authenticatedContext("resident2", {
      role: "resident",
      officeId: "",
      officeName: "",
      isActive: true,
    }).storage(bucket);

    // Public intake storage is backend-only.
    await assertFails(
      uploadString(ref(unauthStorage, "reports_public/new.txt"), "x", "raw", {
        contentType: "text/plain",
      })
    );
    await assertFails(
      uploadString(ref(superStorage, "reports_public/new.txt"), "x", "raw", {
        contentType: "text/plain",
      })
    );

    // Report attachments: owner only.
    await assertSucceeds(
      uploadString(ref(resident1Storage, "reports/resident1/report-1/photo.png"), "png", "raw", {
        contentType: "image/png",
      })
    );
    await assertFails(
      uploadString(ref(resident2Storage, "reports/resident1/report-1/photo.png"), "png", "raw", {
        contentType: "image/png",
      })
    );

    // Report notes: scoped staff only.
    await assertSucceeds(
      uploadString(ref(officeStorage, "report_notes/report-1/msg-1/file.pdf"), "pdf", "raw", {
        contentType: "application/pdf",
      })
    );
    await assertSucceeds(
      uploadString(ref(mod1Storage, "report_notes/report-1/msg-2/file.pdf"), "pdf", "raw", {
        contentType: "application/pdf",
      })
    );
    await assertFails(
      uploadString(ref(mod2Storage, "report_notes/report-1/msg-3/file.pdf"), "pdf", "raw", {
        contentType: "application/pdf",
      })
    );

    // Scoped report reads through storage paths.
    await assertFails(getDownloadURL(ref(officeStorage, "reports/resident2/report-2/existing.jpg")));
    await assertSucceeds(getDownloadURL(ref(adminStorage, "reports/resident2/report-2/existing.jpg")));

    // DTS scope boundaries.
    await assertSucceeds(
      uploadString(ref(officeStorage, "dts/doc-1/attachments/a.pdf"), "pdf", "raw", {
        contentType: "application/pdf",
      })
    );
    await assertFails(
      uploadString(ref(officeStorage, "dts/doc-2/attachments/a.pdf"), "pdf", "raw", {
        contentType: "application/pdf",
      })
    );
    await assertSucceeds(
      uploadString(ref(adminStorage, "dts/doc-2/cover/c.jpg"), "jpg", "raw", {
        contentType: "image/jpeg",
      })
    );

    // Staff-only content uploads.
    await assertSucceeds(
      uploadString(ref(mod1Storage, "posts/post-1/banner.jpg"), "jpg", "raw", {
        contentType: "image/jpeg",
      })
    );
    await assertFails(
      uploadString(ref(resident1Storage, "posts/post-1/banner.jpg"), "jpg", "raw", {
        contentType: "image/jpeg",
      })
    );

    // Public docs enforce mime/size policy.
    await assertSucceeds(
      uploadString(ref(adminStorage, "public_docs/ordinance/pdf/sample.pdf"), "pdf", "raw", {
        contentType: "application/pdf",
      })
    );
    await assertFails(
      uploadString(ref(adminStorage, "public_docs/ordinance/pdf/sample.txt"), "txt", "raw", {
        contentType: "text/plain",
      })
    );
  } finally {
    await testEnv.cleanup();
  }

  console.log("storage rules tests passed");
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
