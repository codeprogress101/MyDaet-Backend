/* eslint-disable no-console */
const path = require("path");
const admin = require("firebase-admin");

function parseArg(name) {
  const prefix = `--${name}=`;
  const hit = process.argv.find((arg) => arg.startsWith(prefix));
  return hit ? hit.slice(prefix.length) : null;
}

function normalize(text) {
  return String(text || "")
    .toLowerCase()
    .replace(/\s+/g, " ")
    .trim();
}

const CATEGORY_OFFICE_MAP = {
  "solid waste": [
    "Municipal Environment and Natural Resources Office (MENRO)",
    "General Services Office (GSO)",
  ],
  "road/traffic": [
    "Public Safety and Traffic Management Unit (PSTMU)",
    "Municipal Engineering Office",
  ],
  streetlight: [
    "Municipal Engineering Office",
    "General Services Office (GSO)",
  ],
  "peace & order": [
    "Public Safety and Traffic Management Unit (PSTMU)",
    "Mayor's Office",
  ],
  health: ["Municipal Health Office (MHO)"],
  others: ["Mayor's Office", "Municipal Administrator's Office"],
};

function initAdmin() {
  if (admin.apps.length > 0) return;

  const projectId = parseArg("project") || process.env.GCLOUD_PROJECT || process.env.FIREBASE_PROJECT_ID;
  const keyPath = parseArg("key") || process.env.GOOGLE_APPLICATION_CREDENTIALS;
  const options = {};

  if (projectId) options.projectId = projectId;
  if (keyPath) {
    const absoluteKeyPath = path.isAbsolute(keyPath)
      ? keyPath
      : path.resolve(process.cwd(), keyPath);
    // eslint-disable-next-line global-require, import/no-dynamic-require
    options.credential = admin.credential.cert(require(absoluteKeyPath));
  }

  admin.initializeApp(options);
}

async function run() {
  initAdmin();
  const db = admin.firestore();

  const officesSnap = await db.collection("offices").get();
  if (officesSnap.empty) {
    throw new Error("No offices found. Seed offices before running this script.");
  }

  const offices = officesSnap.docs.map((doc) => {
    const data = doc.data() || {};
    return {
      id: doc.id,
      name: String(data.name || "").trim(),
      isActive: data.isActive !== false,
    };
  });

  const activeOffices = offices.filter((o) => o.isActive && o.name.length > 0);
  const fallbackOffice = activeOffices[0] || offices[0];
  const officeByName = new Map(
    offices
      .filter((o) => o.name.length > 0)
      .map((o) => [normalize(o.name), o])
  );

  const reportsSnap = await db.collection("reports").get();
  if (reportsSnap.empty) {
    console.log("No reports found.");
    return;
  }

  let scanned = 0;
  let updated = 0;
  let batch = db.batch();
  let batchSize = 0;

  const commitBatch = async () => {
    if (batchSize === 0) return;
    await batch.commit();
    batch = db.batch();
    batchSize = 0;
  };

  for (const doc of reportsSnap.docs) {
    scanned += 1;
    const data = doc.data() || {};
    const existingOfficeId = String(data.officeId || "").trim();
    const existingOfficeName = String(data.officeName || "").trim();
    if (existingOfficeId && existingOfficeName) {
      continue;
    }

    const categoryKey = normalize(data.category || "");
    const preferred = CATEGORY_OFFICE_MAP[categoryKey] || [];
    let target = null;

    for (const officeName of preferred) {
      const hit = officeByName.get(normalize(officeName));
      if (hit) {
        target = hit;
        break;
      }
    }
    if (!target) {
      target = fallbackOffice;
    }
    if (!target || !target.id || !target.name) {
      continue;
    }

    batch.set(
      doc.ref,
      {
        officeId: target.id,
        officeName: target.name,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      {merge: true}
    );
    batchSize += 1;
    updated += 1;

    if (batchSize >= 400) {
      await commitBatch();
      console.log(`Committed ${updated} report updates...`);
    }
  }

  await commitBatch();
  console.log(`Done. scanned=${scanned}, updated=${updated}`);
}

run()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Backfill failed:", error);
    process.exit(1);
  });
