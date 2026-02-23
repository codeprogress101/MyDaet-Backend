const { onCall } = require("firebase-functions/v2/https");
exports.pingTempV2 = onCall(async () => ({ ok: true, ts: Date.now() }));
