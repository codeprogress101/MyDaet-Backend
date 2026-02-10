const admin = require("firebase-admin");

admin.initializeApp({
  credential: admin.credential.applicationDefault(),
});

const UID = "YqE3I8997gZo6lZuEDpseGtTXqy1";

admin
  .auth()
  .setCustomUserClaims(UID, { role: "super_admin" })
  .then(() => {
    console.log("✅ super_admin claim set successfully");
    process.exit(0);
  })
  .catch((error) => {
    console.error("❌ Error setting custom claims:", error);
    process.exit(1);
  });
 