/*
 * Super-admin bootstrap helper.
 *
 * Security guardrails:
 * - UID is never hardcoded; pass via --uid or SUPER_ADMIN_UID env.
 * - Script requires explicit confirmation before applying claims.
 *
 * Usage:
 *   node set-super-admin.js --uid <FIREBASE_UID>
 *   SUPER_ADMIN_UID=<FIREBASE_UID> node set-super-admin.js
 *
 * Optional non-interactive confirm (CI only):
 *   SUPER_ADMIN_CONFIRM=SET_SUPER_ADMIN:<FIREBASE_UID> node set-super-admin.js --uid <FIREBASE_UID>
 */

let admin;
try {
  admin = require("firebase-admin");
} catch (_) {
  admin = require("./functions/node_modules/firebase-admin");
}

const readline = require("readline");

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const item = String(argv[i] || "").trim();
    if (!item.startsWith("--")) continue;
    const key = item.slice(2);
    const next = argv[i + 1];
    if (!next || String(next).startsWith("--")) {
      args[key] = "true";
      continue;
    }
    args[key] = String(next).trim();
    i += 1;
  }
  return args;
}

function prompt(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    rl.question(question, (answer) => {
      rl.close();
      resolve(String(answer || "").trim());
    });
  });
}

async function requireConfirmation(uid, args) {
  const expected = `SET_SUPER_ADMIN:${uid}`;
  const envConfirmation = String(process.env.SUPER_ADMIN_CONFIRM || "").trim();
  const argConfirmation = String(args.confirm || "").trim();

  if (envConfirmation === expected || argConfirmation === expected) {
    return true;
  }

  console.log("[guard] This operation grants full super_admin privileges.");
  console.log(`[guard] Confirm by typing: ${expected}`);
  const answer = await prompt("> ");
  return answer === expected;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const uid = String(
    args.uid ||
      process.env.SUPER_ADMIN_UID ||
      process.env.MYDAET_SUPER_ADMIN_UID ||
      ""
  ).trim();

  if (!uid) {
    console.error("ERROR: Missing UID. Provide --uid <FIREBASE_UID> or SUPER_ADMIN_UID env.");
    process.exit(1);
  }

  const confirmed = await requireConfirmation(uid, args);
  if (!confirmed) {
    console.error("ABORTED: Confirmation mismatch. No changes were applied.");
    process.exit(1);
  }

  admin.initializeApp({
    credential: admin.credential.applicationDefault(),
  });

  const db = admin.firestore();
  const claims = {
    role: "super_admin",
    officeId: null,
    officeName: null,
    isActive: true,
  };

  await admin.auth().setCustomUserClaims(uid, claims);
  await db.collection("users").doc(uid).set(
    {
      uid,
      role: "super_admin",
      officeId: null,
      officeName: null,
      isActive: true,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    },
    {merge: true}
  );

  console.log(`OK: super_admin claim and user profile updated for uid=${uid}`);
}

main().catch((error) => {
  console.error("ERROR: Failed to set super_admin claim:", error);
  process.exit(1);
});
