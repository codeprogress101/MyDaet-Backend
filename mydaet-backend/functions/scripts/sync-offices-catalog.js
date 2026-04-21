/* eslint-disable no-console */
const path = require("path");
const admin = require("firebase-admin");

const OFFICE_CATALOG = [
  {id: "OFFICE_OF_THE_MAYOR", name: "Office of the Mayor", aliases: ["Mayor's Office"]},
  {
    id: "MUNICIPAL_INFORMATION_OFFICE",
    name: "Municipal Information Office (MIO)",
    aliases: ["Municipal Information Office", "Municipal Information office (MIO)", "MIO"],
  },
  {
    id: "DAET_PUBLIC_SAFETY_AND_TRAFFIC_MANAGEMENT_UNIT",
    name: "Daet Public Safety and Traffic Management Unit",
    aliases: ["Public Safety and Traffic Management Unit", "PSTMU"],
  },
  {id: "TRICYCLE_REGULATORY_UNIT_OFFICE", name: "Tricycle Regulatory Unit Office"},
  {
    id: "PESO",
    name: "Public Employment Service Office (PESO)",
    aliases: ["Public Employment Service Office"],
  },
  {id: "SANGGUNIANG_BAYAN", name: "Sangguniang Bayan Office", aliases: ["Sangguniang Bayan"]},
  {id: "GENERAL_SERVICES_OFFICE", name: "General Services Office", aliases: ["GSO"]},
  {id: "MUNICIPAL_ACCOUNTING_OFFICE", name: "Municipal Accounting Office"},
  {
    id: "BPLO",
    name: "Business Permit and Licensing Office",
    aliases: [
      "Business Permit & Licensing Office",
      "Business Permits and Licensing Office",
      "Business Permits & Licensing Office",
      "Business Permit and Licensing Office (BPLO)",
    ],
  },
  {id: "MUNICIPAL_BUDGET_OFFICE", name: "Municipal Budget Office"},
  {
    id: "MUNICIPAL_PLANNING_AND_DEVELOPMENT_OFFICE",
    name: "Municipal Planning and Development Office",
    aliases: ["MPDO"],
  },
  {id: "MUNICIPAL_LEGAL_OFFICE", name: "Municipal Legal Office"},
  {
    id: "MUNICIPAL_HUMAN_RESOURCE_MANAGEMENT_OFFICE",
    name: "Municipal Human Resource Management Office",
    aliases: ["MHRMO"],
  },
  {id: "MUNICIPAL_AGRICULTURE_OFFICE", name: "Municipal Agriculture Office"},
  {
    id: "OFFICE_OF_THE_CIVIL_REGISTRAR",
    name: "Municipal Civil Registrar",
    aliases: ["Municipal Civil Registry Office", "Municipal Local Civil Registry Office"],
  },
  {
    id: "MUNICIPAL_TOURISM_CULTURE_AND_ARTS_OFFICE",
    name: "Municipal Tourism, Culture and Arts Office",
  },
  {
    id: "MDRRMO",
    name: "Municipal Disaster Risk Reduction and Management Office",
  },
  {id: "MUNICIPAL_ENGINEERS_OFFICE", name: "Municipal Engineers Office"},
  {id: "MUNICIPAL_TREASURERS_OFFICE", name: "Municipal Treasurer's Office"},
  {id: "MUNICIPAL_HEALTH_OFFICE", name: "Municipal Health Office"},
  {id: "RURAL_HEALTH_UNIT_III", name: "Rural Health Unit III"},
  {id: "RURAL_HEALTH_UNIT_II", name: "Rural Health Unit II"},
  {id: "RURAL_HEALTH_UNIT_I", name: "Rural Health Unit I"},
  {
    id: "MENRO",
    name: "Municipal Environment and Natural Resources Office (MENRO)",
  },
  {
    id: "MSWDO",
    name: "Municipal Social Welfare and Development Office (MSWDO)",
  },
  {id: "MUNICIPAL_VETERINARY_OFFICE", name: "Municipal Veterinary Office"},
  {id: "MARKET_DIVISION", name: "Market Division"},
  {id: "MUNICIPAL_COOPERATIVE_OFFICE", name: "Municipal Cooperative Office"},
  {id: "BUSINESS_DEVELOPMENT_OFFICE", name: "Business Development Office"},
  {id: "BIDS_AND_AWARDS_COMMITTEE", name: "Bids and Awards Committee", aliases: ["BAC"]},
];

const SCRIPT_ACTOR = "script:sync-offices-catalog";
const OFFICE_SCOPED_ROLES = new Set(["moderator", "office_admin"]);

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

function normalizeKey(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function normalizeRole(value) {
  const role = String(value || "").trim().toLowerCase();
  if (role === "superadmin" || role === "super-admin") return "super_admin";
  if (role === "officeadmin" || role === "office-admin") return "office_admin";
  if (role === "mod") return "moderator";
  if (role === "admin") return "admin";
  if (role === "super_admin" || role === "office_admin" || role === "moderator" || role === "resident") {
    return role;
  }
  return role || "resident";
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

function buildOfficeLookup() {
  const byKey = new Map();
  for (const office of OFFICE_CATALOG) {
    const keys = new Set([
      normalizeKey(office.id),
      normalizeKey(office.name),
      ...((office.aliases || []).map((alias) => normalizeKey(alias))),
    ]);
    for (const key of keys) {
      if (!key) continue;
      byKey.set(key, office);
    }
  }
  return byKey;
}

async function commitWrites(writes) {
  if (writes.length === 0) return;
  const db = admin.firestore();
  for (let i = 0; i < writes.length; i += 400) {
    const batch = db.batch();
    const slice = writes.slice(i, i + 400);
    for (const write of slice) {
      if (write.type === "set") {
        batch.set(write.ref, write.data, {merge: write.merge !== false});
      } else if (write.type === "delete") {
        batch.delete(write.ref);
      }
    }
    await batch.commit();
  }
}

async function syncOfficesCollection({apply, purge, exact, deleteMissing}) {
  const db = admin.firestore();
  const officesRef = db.collection("offices");
  const existingSnap = await officesRef.get();
  const existingById = new Map(existingSnap.docs.map((doc) => [doc.id, doc]));
  const targetIds = new Set(OFFICE_CATALOG.map((office) => office.id));
  const writes = [];

  let purgedCount = 0;
  if (purge) {
    for (const doc of existingSnap.docs) {
      writes.push({type: "delete", ref: doc.ref});
      purgedCount += 1;
    }
  }

  let upsertCount = 0;
  let createCount = 0;
  for (let index = 0; index < OFFICE_CATALOG.length; index += 1) {
    const office = OFFICE_CATALOG[index];
    const existed = existingById.has(office.id);
    const payload = {
      officeId: office.id,
      name: office.name,
      label: office.name,
      aliases: office.aliases || [],
      isActive: true,
      sortOrder: index + 1,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedBy: SCRIPT_ACTOR,
      retiredAt: admin.firestore.FieldValue.delete(),
      retiredBy: admin.firestore.FieldValue.delete(),
    };
    if (!existed || purge) {
      payload.createdAt = admin.firestore.FieldValue.serverTimestamp();
      payload.createdBy = SCRIPT_ACTOR;
      createCount += 1;
    }
    writes.push({type: "set", ref: officesRef.doc(office.id), data: payload});
    upsertCount += 1;
  }

  let deactivationCount = 0;
  let deleteCount = 0;
  if (!purge && exact) {
    for (const doc of existingSnap.docs) {
      if (targetIds.has(doc.id)) continue;
      if (deleteMissing) {
        writes.push({type: "delete", ref: doc.ref});
        deleteCount += 1;
      } else {
        writes.push({
          type: "set",
          ref: doc.ref,
          data: {
            isActive: false,
            retiredAt: admin.firestore.FieldValue.serverTimestamp(),
            retiredBy: SCRIPT_ACTOR,
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
            updatedBy: SCRIPT_ACTOR,
          },
        });
        deactivationCount += 1;
      }
    }
  }

  console.log("[office-catalog] planned collection changes:");
  console.log(`  purge=${purge} purged=${purgedCount}`);
  console.log(`  upserts=${upsertCount}`);
  console.log(`  creates=${createCount}`);
  if (!purge && exact) {
    if (deleteMissing) {
      console.log(`  deletes=${deleteCount}`);
    } else {
      console.log(`  deactivations=${deactivationCount}`);
    }
  }

  if (!apply) {
    return {
      purgedCount,
      upsertCount,
      createCount,
      deactivationCount,
      deleteCount,
      targetIds,
      applied: false,
    };
  }

  await commitWrites(writes);
  return {
    purgedCount,
    upsertCount,
    createCount,
    deactivationCount,
    deleteCount,
    targetIds,
    applied: true,
  };
}

function resolveCanonicalOffice(userData, officeLookup) {
  const officeId = String(userData.officeId || "").trim();
  const officeName = String(userData.officeName || "").trim();
  const keys = [officeId, officeName].map((value) => normalizeKey(value)).filter(Boolean);
  for (const key of keys) {
    if (officeLookup.has(key)) {
      return officeLookup.get(key);
    }
  }
  return null;
}

async function rewireUserOfficeAssignments({apply}) {
  const db = admin.firestore();
  const usersSnap = await db.collection("users").get();
  const officeLookup = buildOfficeLookup();

  let checked = 0;
  let rewired = 0;
  let rewiredClaims = 0;
  let unresolved = 0;
  let skippedNoOffice = 0;
  let skippedNoChange = 0;
  const unresolvedRows = [];
  const writes = [];

  for (const userDoc of usersSnap.docs) {
    checked += 1;
    const data = userDoc.data() || {};
    const currentOfficeId = String(data.officeId || "").trim();
    const currentOfficeName = String(data.officeName || "").trim();
    const role = normalizeRole(data.role);
    const hasOfficeData = currentOfficeId.length > 0 || currentOfficeName.length > 0;

    if (!hasOfficeData) {
      if (OFFICE_SCOPED_ROLES.has(role)) {
        unresolved += 1;
        unresolvedRows.push({
          uid: userDoc.id,
          reason: "office-scoped role without office assignment",
          role,
          officeId: currentOfficeId,
          officeName: currentOfficeName,
        });
      } else {
        skippedNoOffice += 1;
      }
      continue;
    }

    const canonical = resolveCanonicalOffice(data, officeLookup);
    if (!canonical) {
      unresolved += 1;
      unresolvedRows.push({
        uid: userDoc.id,
        reason: "unmapped office",
        role,
        officeId: currentOfficeId,
        officeName: currentOfficeName,
      });
      continue;
    }

    const noChange = currentOfficeId === canonical.id && currentOfficeName === canonical.name;
    if (noChange) {
      skippedNoChange += 1;
      continue;
    }

    rewired += 1;
    writes.push({
      type: "set",
      ref: userDoc.ref,
      data: {
        officeId: canonical.id,
        officeName: canonical.name,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedBy: SCRIPT_ACTOR,
      },
    });

    if (apply) {
      try {
        const authUser = await admin.auth().getUser(userDoc.id);
        const currentClaims = authUser.customClaims || {};
        await admin.auth().setCustomUserClaims(userDoc.id, {
          ...currentClaims,
          officeId: canonical.id,
          officeName: canonical.name,
        });
        rewiredClaims += 1;
      } catch (error) {
        unresolved += 1;
        unresolvedRows.push({
          uid: userDoc.id,
          reason: `auth-claims-update-failed: ${String(error.message || error)}`,
          role,
          officeId: currentOfficeId,
          officeName: currentOfficeName,
        });
      }
    }
  }

  if (apply) {
    await commitWrites(writes);
  }

  console.log("[office-catalog] planned account rewiring:");
  console.log(`  checked=${checked}`);
  console.log(`  rewired=${rewired}`);
  console.log(`  rewiredAuthClaims=${rewiredClaims}`);
  console.log(`  skippedNoOffice=${skippedNoOffice}`);
  console.log(`  skippedNoChange=${skippedNoChange}`);
  console.log(`  unresolved=${unresolved}`);
  if (unresolvedRows.length > 0) {
    console.log("  unresolved sample (up to 15):");
    unresolvedRows.slice(0, 15).forEach((row) => {
      console.log(
        `    uid=${row.uid} role=${row.role} officeId=${row.officeId || "-"} officeName=${row.officeName || "-"} reason=${row.reason}`
      );
    });
  }

  return {
    checked,
    rewired,
    rewiredClaims,
    unresolved,
    skippedNoOffice,
    skippedNoChange,
  };
}

async function run() {
  const apply = hasFlag("apply");
  const exact = hasFlag("exact");
  const deleteMissing = hasFlag("delete-missing");
  const purge = hasFlag("purge");
  const rewireUsers = hasFlag("rewire-users");

  initAdmin();

  console.log("[office-catalog] options:");
  console.log(`  apply=${apply}`);
  console.log(`  purge=${purge}`);
  console.log(`  exact=${exact}`);
  console.log(`  delete-missing=${deleteMissing}`);
  console.log(`  rewire-users=${rewireUsers}`);

  await syncOfficesCollection({apply, purge, exact, deleteMissing});

  if (rewireUsers) {
    await rewireUserOfficeAssignments({apply});
  }

  if (!apply) {
    console.log("");
    console.log("Dry run only. Re-run with --apply to commit.");
    return;
  }

  console.log("[office-catalog] sync complete.");
}

run()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("[office-catalog] sync failed:", error);
    process.exit(1);
  });
