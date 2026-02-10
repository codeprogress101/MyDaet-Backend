let admin;
try {
  admin = require("firebase-admin");
} catch (_) {
  admin = require("./functions/node_modules/firebase-admin");
}

admin.initializeApp({
  credential: admin.credential.applicationDefault(),
});

const db = admin.firestore();
const UID = "YqE3I8997gZo6lZuEDpseGtTXqy1";

admin
  .auth()
  .setCustomUserClaims(UID, {
    role: "super_admin",
    officeId: null,
    officeName: null,
    isActive: true,
  })
  .then(() => {
    return db.collection("users").doc(UID).set(
      {
        role: "super_admin",
        officeId: null,
        officeName: null,
        isActive: true,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );
  })
  .then(() => {
    console.log("OK: super_admin claim and user record updated");
    process.exit(0);
  })
  .catch((error) => {
    console.error("ERROR: Failed to set custom claims:", error);
    process.exit(1);
  });
