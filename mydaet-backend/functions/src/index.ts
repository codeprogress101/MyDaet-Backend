import * as functions from "firebase-functions/v1";
import * as admin from "firebase-admin";
import * as crypto from "crypto";
import * as qrcode from "qrcode";
import AdmZip from "adm-zip";

admin.initializeApp();
const db = admin.firestore();

/**
 * Role definitions
 */
type Role = "resident" | "moderator" | "office_admin" | "super_admin" | "admin";
type NormalizedRole = "resident" | "moderator" | "office_admin" | "super_admin";
const ALLOWED_ROLES: Role[] = [
  "resident",
  "moderator",
  "office_admin",
  "super_admin",
  "admin",
];

const OPEN_STATUSES = ["submitted", "in_review", "assigned", "in_progress"] as const;

function isOpenStatus(s: string): boolean {
  return (OPEN_STATUSES as readonly string[]).includes(s);
}

function normalizeRole(raw: unknown): NormalizedRole {
  if (!raw) return "resident";
  const role = String(raw).trim().toLowerCase();
  if (role === "admin") return "super_admin";
  if (role === "super_admin") return "super_admin";
  if (role === "office_admin") return "office_admin";
  if (role === "moderator") return "moderator";
  return "resident";
}

function coerceString(value: unknown): string | null {
  if (!value) return null;
  const text = String(value).trim();
  return text.length > 0 ? text : null;
}

function coerceBool(value: unknown, fallback = true): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function ymd(date: Date): string {
  // YYYY-MM-DD
  const yyyy = date.getFullYear();
  const mm = String(date.getMonth() + 1).padStart(2, "0");
  const dd = String(date.getDate()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd}`;
}

function incField(path: string, delta: number) {
  return admin.firestore.FieldValue.increment(delta);
}

type NotificationData = {
  title: string;
  body: string;
  type: string;
  reportId?: string;
  dtsDocId?: string;
  announcementId?: string;
  status?: string;
  createdByUid?: string;
  assignedToUid?: string;
};

function chunk<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) {
    out.push(items.slice(i, i + size));
  }
  return out;
}

async function getTokensForUids(uids: string[]) {
  const results: Array<{ uid: string; token: string }> = [];
  for (const uid of uids) {
    const snap = await db.collection("users").doc(uid).collection("fcmTokens").get();
    snap.forEach((doc) => {
      results.push({ uid, token: doc.id });
    });
  }
  return results;
}

async function getResidentUids(): Promise<string[]> {
  const snap = await db.collection("users").where("role", "==", "resident").get();
  return snap.docs.map((d) => d.id);
}

async function getUserProfile(uid: string) {
  const snap = await db.collection("users").doc(uid).get();
  const data = snap.exists ? snap.data() ?? {} : {};
  const role = normalizeRole(data.role);
  const officeId = coerceString(data.officeId);
  const officeName = coerceString(data.officeName);
  const isActive = coerceBool(data.isActive, true);
  return { role, officeId, officeName, isActive, data };
}

async function sendPushToUsers(uids: string[], payload: NotificationData) {
  if (uids.length === 0) return;
  const tokenRows = await getTokensForUids(uids);
  if (tokenRows.length === 0) return;

  const rowsChunks = chunk(tokenRows, 500);
  for (const rows of rowsChunks) {
    const tokens = rows.map((r) => r.token);
    const response = await admin.messaging().sendEachForMulticast({
      tokens,
      notification: {
        title: payload.title,
        body: payload.body,
      },
      data: {
        type: payload.type,
        reportId: payload.reportId ?? "",
        dtsDocId: payload.dtsDocId ?? "",
        announcementId: payload.announcementId ?? "",
        status: payload.status ?? "",
        createdByUid: payload.createdByUid ?? "",
        assignedToUid: payload.assignedToUid ?? "",
      },
    });

    const invalid: Array<{ uid: string; token: string }> = [];
    response.responses.forEach((resp, idx) => {
      if (resp.success) return;
      const code = resp.error?.code ?? "";
      if (
        code === "messaging/registration-token-not-registered" ||
        code === "messaging/invalid-registration-token"
      ) {
        invalid.push(rows[idx]);
      }
    });

    await Promise.all(
      invalid.map((r) =>
        db.collection("users").doc(r.uid).collection("fcmTokens").doc(r.token).delete()
      )
    );
  }
}

async function addNotifications(uids: string[], payload: NotificationData) {
  if (uids.length === 0) return;
  const batches = chunk(uids, 450);
  for (const group of batches) {
    const batch = db.batch();
    for (const uid of group) {
      const ref = db
        .collection("users")
        .doc(uid)
        .collection("notifications")
        .doc();
      batch.set(ref, {
        title: payload.title,
        body: payload.body,
        type: payload.type,
        reportId: payload.reportId ?? "",
        dtsDocId: payload.dtsDocId ?? "",
        announcementId: payload.announcementId ?? null,
        status: payload.status ?? null,
        createdByUid: payload.createdByUid ?? null,
        assignedToUid: payload.assignedToUid ?? null,
        read: false,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    }
    await batch.commit();
  }
}

async function notifyUsers(uids: string[], payload: NotificationData) {
  const unique = Array.from(new Set(uids.filter((u) => u && u.trim().length > 0)));
  if (unique.length === 0) return;
  await addNotifications(unique, payload);
  await sendPushToUsers(unique, payload);
}

function prettyStatus(status: string) {
  return status.replace(/_/g, " ").trim();
}

async function addHistory(
  reportId: string,
  entry: Record<string, unknown>
): Promise<void> {
  await db
    .collection("reports")
    .doc(reportId)
    .collection("history")
    .add({
      ...entry,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
}

async function addAuditLog(entry: Record<string, unknown>): Promise<void> {
  await db.collection("audit_logs").add({
    ...entry,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  });
}

function announcementActor(data: Record<string, unknown> | null) {
  if (!data) {
    return {
      actorUid: null,
      actorEmail: null,
      actorName: null,
      actorRole: null,
    };
  }

  const d = data as Record<string, unknown>;
  return {
    actorUid: (d.lastActionByUid ?? d.createdByUid ?? null) as string | null,
    actorEmail: (d.lastActionByEmail ?? d.createdByEmail ?? null) as string | null,
    actorName: (d.lastActionByName ?? d.createdByName ?? null) as string | null,
    actorRole: (d.lastActionByRole ?? null) as string | null,
  };
}

function sha256(input: string): string {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function randomCode(prefix = "DTS-QR"): string {
  const bytes = crypto.randomBytes(6).toString("hex").toUpperCase();
  return `${prefix}-${bytes}`;
}

async function createQrPng(value: string): Promise<Buffer> {
  return qrcode.toBuffer(value, {
    type: "png",
    margin: 1,
    width: 512,
    errorCorrectionLevel: "M",
  });
}

function dtsInstructions(status: string) {
  const normalized = status.toUpperCase();
  switch (normalized) {
    case "IN_TRANSIT":
      return "Your document is in transit to the next office.";
    case "WITH_OFFICE":
      return "Your document has been received by the office.";
    case "IN_PROCESS":
      return "Your document is being processed.";
    case "FOR_APPROVAL":
      return "Your document is pending approval.";
    case "RELEASED":
      return "Your document is ready for release or pickup.";
    case "ARCHIVED":
      return "Your document has been archived.";
    case "PULLED_OUT":
      return "Your document has been pulled out for review.";
    case "RECEIVED":
    default:
      return "Your document has been received by Records.";
  }
}

type StaffContext = {
  uid: string;
  role: NormalizedRole;
  officeId: string | null;
  officeName: string | null;
  profileData: Record<string, unknown>;
};

const DTS_STATUSES = new Set([
  "RECEIVED",
  "IN_TRANSIT",
  "WITH_OFFICE",
  "IN_PROCESS",
  "FOR_APPROVAL",
  "RELEASED",
  "ARCHIVED",
  "PULLED_OUT",
]);

const DTS_PIN_MAX_ATTEMPTS = 5;
const DTS_PIN_LOCK_MINUTES = 15;
const DTS_TRACK_SESSION_TTL_HOURS = 12;
const DTS_TRACK_SESSION_ROTATION_BYTES = 24;
const FUNCTIONS_BUILD_VERSION = "2026.02.16.1";

function normalizeDtsStatus(raw: unknown, fallback = "RECEIVED"): string {
  const value = String(raw ?? "")
    .trim()
    .toUpperCase()
    .replace(/\s+/g, "_");
  if (DTS_STATUSES.has(value)) return value;
  return fallback;
}

function prettyDtsStatus(status: string): string {
  const value = normalizeDtsStatus(status, "RECEIVED");
  return value
    .toLowerCase()
    .split("_")
    .map((part) => part.substring(0, 1).toUpperCase() + part.substring(1))
    .join(" ");
}

const DTS_ALLOWED_TRANSITIONS: Record<string, Set<string>> = {
  RECEIVED: new Set(["WITH_OFFICE", "IN_PROCESS", "FOR_APPROVAL", "IN_TRANSIT", "ARCHIVED"]),
  WITH_OFFICE: new Set(["IN_PROCESS", "FOR_APPROVAL", "IN_TRANSIT", "RELEASED", "ARCHIVED", "PULLED_OUT"]),
  IN_PROCESS: new Set(["WITH_OFFICE", "FOR_APPROVAL", "IN_TRANSIT", "RELEASED", "ARCHIVED"]),
  FOR_APPROVAL: new Set(["WITH_OFFICE", "IN_PROCESS", "IN_TRANSIT", "RELEASED", "ARCHIVED"]),
  RELEASED: new Set(["ARCHIVED", "PULLED_OUT"]),
  ARCHIVED: new Set(["PULLED_OUT"]),
  PULLED_OUT: new Set(["WITH_OFFICE", "IN_PROCESS", "FOR_APPROVAL", "RELEASED", "ARCHIVED"]),
  IN_TRANSIT: new Set(["WITH_OFFICE"]),
};

function canTransitionDtsStatus(fromStatus: string, toStatus: string): boolean {
  if (fromStatus === toStatus) return true;
  const allowed = DTS_ALLOWED_TRANSITIONS[fromStatus];
  if (!allowed) return false;
  return allowed.has(toStatus);
}

async function requireStaffContext(
  context: functions.https.CallableContext
): Promise<StaffContext> {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "Auth required.");
  }
  const uid = context.auth.uid;
  const tokenRole = normalizeRole(context.auth.token.role);
  const tokenOfficeId = coerceString(context.auth.token.officeId);
  const tokenOfficeName = coerceString(context.auth.token.officeName);
  const tokenIsActive =
    typeof context.auth.token.isActive === "boolean"
      ? context.auth.token.isActive
      : null;

  const profile = await getUserProfile(uid);
  const role = tokenRole === "resident" ? profile.role : tokenRole;
  const officeId = tokenOfficeId ?? profile.officeId;
  const officeName = tokenOfficeName ?? profile.officeName;
  const isActive = tokenIsActive ?? profile.isActive;

  if (!isActive) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Inactive account."
    );
  }
  if (!(role === "super_admin" || role === "office_admin" || role === "moderator")) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Staff access required."
    );
  }

  return {
    uid,
    role,
    officeId,
    officeName,
    profileData: profile.data as Record<string, unknown>,
  };
}

function dtsPendingTransfer(data: Record<string, unknown>) {
  const pending = data.pendingTransfer;
  if (!pending || typeof pending !== "object") return null;
  return pending as Record<string, unknown>;
}

function sameNormalizedName(a: string | null, b: string | null): boolean {
  if (!a || !b) return false;
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}

function isIntendedDtsReceiver(
  actor: StaffContext,
  pending: Record<string, unknown>
): boolean {
  const toOfficeId = coerceString(pending.toOfficeId);
  const toOfficeName = coerceString(pending.toOfficeName);
  const toUid = coerceString(pending.toUid);
  return (
    (actor.officeId != null && toOfficeId != null && actor.officeId === toOfficeId) ||
    sameNormalizedName(actor.officeName, toOfficeName) ||
    (toUid != null && toUid === actor.uid)
  );
}

function canOperateOnDtsDoc(
  actor: StaffContext,
  data: Record<string, unknown>
): boolean {
  if (actor.role === "super_admin") return true;

  const currentOfficeId = coerceString(data.currentOfficeId);
  const currentOfficeName = coerceString(data.currentOfficeName);
  const currentCustodianUid = coerceString(data.currentCustodianUid);

  if (currentCustodianUid && currentCustodianUid === actor.uid) {
    return true;
  }
  if (actor.officeId && currentOfficeId && actor.officeId === currentOfficeId) {
    return true;
  }
  if (sameNormalizedName(actor.officeName, currentOfficeName)) {
    return true;
  }

  const pending = dtsPendingTransfer(data);
  if (!pending) return false;
  return isIntendedDtsReceiver(actor, pending);
}

function actorDisplayName(actor: StaffContext): string {
  return (
    coerceString(actor.profileData.displayName) ??
    coerceString(actor.profileData.email) ??
    actor.uid
  );
}

function sanitizeDtsAttachments(raw: unknown): Array<Record<string, unknown>> {
  if (!Array.isArray(raw)) return [];
  const allowed = ["name", "path", "url", "uploadedAt", "contentType"];
  const output: Array<Record<string, unknown>> = [];
  for (const entry of raw) {
    if (!entry || typeof entry !== "object") continue;
    const src = entry as Record<string, unknown>;
    const clean: Record<string, unknown> = {};
    for (const key of allowed) {
      const value = src[key];
      if (value != null) clean[key] = value;
    }
    if (Object.keys(clean).length > 0) {
      output.push(clean);
    }
    if (output.length >= 10) break;
  }
  return output;
}

function pinHashFromDoc(pin: string, data: Record<string, unknown>): string {
  const salt = coerceString(data.publicPinSalt);
  return salt ? sha256(`${pin}:${salt}`) : sha256(pin);
}

function trackingAttemptDocId(trackingNo: string): string {
  return trackingNo.toUpperCase().replace(/[^A-Z0-9_-]/g, "_");
}

function contextUid(context: functions.https.CallableContext): string {
  return context.auth?.uid?.trim() || "anon";
}

function contextIpHash(context: functions.https.CallableContext): string {
  const raw = context.rawRequest?.ip ?? "unknown";
  return sha256(raw).substring(0, 16);
}

function rateScopeDocId(trackingNo: string, scope: string, value: string): string {
  const safeValue = value.toUpperCase().replace(/[^A-Z0-9_-]/g, "_");
  return `${trackingAttemptDocId(trackingNo)}__${scope}__${safeValue}`;
}

function parseLockUntil(data: Record<string, unknown>): Date | null {
  const raw = data.lockUntil;
  if (raw instanceof admin.firestore.Timestamp) return raw.toDate();
  return null;
}

function parseFailCount(data: Record<string, unknown>): number {
  const raw = data.failCount;
  if (typeof raw === "number" && Number.isFinite(raw)) {
    return Math.max(0, Math.floor(raw));
  }
  return 0;
}

function buildAttemptRefs(
  trackingNo: string,
  context: functions.https.CallableContext
): admin.firestore.DocumentReference[] {
  const uid = contextUid(context);
  const ipHash = contextIpHash(context);
  return [
    db.collection("dts_track_attempts").doc(rateScopeDocId(trackingNo, "TRACKING", "GLOBAL")),
    db.collection("dts_track_attempts").doc(rateScopeDocId(trackingNo, "UID", uid)),
    db.collection("dts_track_attempts").doc(rateScopeDocId(trackingNo, "IP", ipHash)),
  ];
}

function trackingSessionHash(token: string): string {
  return sha256(token);
}

function createTrackingSessionToken(): string {
  return crypto.randomBytes(DTS_TRACK_SESSION_ROTATION_BYTES).toString("base64url");
}

async function issueTrackingSession(
  docId: string,
  trackingNo: string,
  context: functions.https.CallableContext
): Promise<{token: string; expiresAtMs: number}> {
  const token = createTrackingSessionToken();
  const tokenHash = trackingSessionHash(token);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + DTS_TRACK_SESSION_TTL_HOURS * 60 * 60 * 1000);
  await db.collection("dts_track_sessions").doc(tokenHash).set({
    docId,
    trackingNo,
    ownerUid: context.auth?.uid ?? null,
    issuedAt: admin.firestore.FieldValue.serverTimestamp(),
    lastUsedAt: admin.firestore.FieldValue.serverTimestamp(),
    expiresAt: admin.firestore.Timestamp.fromDate(expiresAt),
  });
  return {token, expiresAtMs: expiresAt.getTime()};
}

type TrackingSessionResolution = {
  ref: admin.firestore.DocumentReference;
  data: Record<string, unknown>;
};

async function resolveTrackingSession(
  token: string,
  context: functions.https.CallableContext
): Promise<TrackingSessionResolution> {
  const ref = db.collection("dts_track_sessions").doc(trackingSessionHash(token));
  const snap = await ref.get();
  if (!snap.exists) {
    throw new functions.https.HttpsError("permission-denied", "Invalid or expired tracking token.");
  }
  const data = snap.data() ?? {};
  const ownerUid = coerceString(data.ownerUid);
  if (ownerUid && context.auth?.uid !== ownerUid) {
    throw new functions.https.HttpsError("permission-denied", "Tracking token is bound to another user.");
  }
  const expiresAt = data.expiresAt instanceof admin.firestore.Timestamp
    ? data.expiresAt.toDate()
    : null;
  if (!expiresAt || expiresAt.getTime() <= Date.now()) {
    await ref.delete();
    throw new functions.https.HttpsError("permission-denied", "Tracking token expired. Re-enter PIN.");
  }
  return {ref, data: data as Record<string, unknown>};
}

function buildSanitizedTrackingResult(
  trackingNo: string,
  dataRow: Record<string, unknown>
): Record<string, unknown> {
  const confidentiality = (dataRow.confidentiality ?? "public")
    .toString()
    .toLowerCase();
  const hideSensitive = confidentiality === "confidential";
  const title = hideSensitive
    ? null
    : (dataRow.title ?? "").toString().trim() || null;
  const currentOfficeName = hideSensitive
    ? null
    : (dataRow.currentOfficeName ?? dataRow.currentOfficeId ?? null);

  let updatedAt: number | null = null;
  if (dataRow.updatedAt instanceof admin.firestore.Timestamp) {
    updatedAt = dataRow.updatedAt.toMillis();
  } else if (dataRow.createdAt instanceof admin.firestore.Timestamp) {
    updatedAt = dataRow.createdAt.toMillis();
  }

  const status = (dataRow.status ?? "RECEIVED").toString();
  return {
    trackingNo,
    title,
    status,
    lastUpdated: updatedAt,
    currentOfficeName,
    instructions: dtsInstructions(status),
  };
}

async function verifyPinWithRateLimit(
  trackingNo: string,
  pin: string,
  data: Record<string, unknown>,
  context: functions.https.CallableContext
): Promise<void> {
  const attemptRefs = buildAttemptRefs(trackingNo, context);
  const now = new Date();
  const snaps = await Promise.all(attemptRefs.map((ref) => ref.get()));
  let activeLockUntil: Date | null = null;
  for (const snap of snaps) {
    const lockUntil = parseLockUntil((snap.data() ?? {}) as Record<string, unknown>);
    if (!lockUntil) continue;
    if (lockUntil.getTime() > now.getTime() &&
      (activeLockUntil == null || lockUntil.getTime() < activeLockUntil.getTime())) {
      activeLockUntil = lockUntil;
    }
  }
  if (activeLockUntil) {
    throw new functions.https.HttpsError(
      "resource-exhausted",
      `Too many failed attempts. Try again after ${activeLockUntil.toISOString()}.`
    );
  }

  const hash = coerceString(data.publicPinHash) ?? "";
  const valid = hash.length > 0 && pinHashFromDoc(pin, data) === hash;
  if (valid) {
    const batch = db.batch();
    for (const ref of attemptRefs) {
      batch.set(
        ref,
        {
          failCount: 0,
          lockUntil: admin.firestore.FieldValue.delete(),
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        {merge: true}
      );
    }
    await batch.commit();
    return;
  }

  let shouldLock = false;
  const lockUntil = new Date(now.getTime() + DTS_PIN_LOCK_MINUTES * 60 * 1000);
  const batch = db.batch();
  for (const [index, ref] of attemptRefs.entries()) {
    const row = (snaps[index].data() ?? {}) as Record<string, unknown>;
    const previousFails = parseFailCount(row);
    const nextFails = previousFails + 1;
    const scopeLocked = nextFails >= DTS_PIN_MAX_ATTEMPTS;
    shouldLock = shouldLock || scopeLocked;
    batch.set(
      ref,
      {
        failCount: scopeLocked ? 0 : nextFails,
        lockUntil: scopeLocked
          ? admin.firestore.Timestamp.fromDate(lockUntil)
          : admin.firestore.FieldValue.delete(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      {merge: true}
    );
  }
  await batch.commit();

  if (shouldLock) {
    throw new functions.https.HttpsError(
      "resource-exhausted",
      `Too many failed attempts. Try again after ${lockUntil.toISOString()}.`
    );
  }

  throw new functions.https.HttpsError(
    "permission-denied",
    "Invalid tracking PIN."
  );
}

function dtsEventLabel(type: string): string {
  switch ((type || "").toUpperCase()) {
    case "TRANSFER_INITIATED":
      return "Transfer initiated";
    case "TRANSFER_CONFIRMED":
      return "Transfer confirmed";
    case "STATUS_CHANGED":
      return "Status changed";
    case "RETURNED":
      return "Transfer returned";
    case "RELEASED":
      return "Released";
    case "ARCHIVED":
      return "Archived";
    case "PULLED_OUT":
      return "Pulled out";
    case "NOTE":
      return "Note added";
    case "RECEIVED":
    default:
      return "Received";
  }
}

function formatEventTime(date: Date): string {
  return new Intl.DateTimeFormat("en-US", {
    timeZone: "Asia/Manila",
    hour: "numeric",
    minute: "2-digit",
    hour12: true,
  }).format(date);
}

/**
 * =========================
 * AUTH TRIGGER
 * =========================
 * Runs when a user is created.
 */
export const onAuthUserCreated = functions.auth.user().onCreate(async (user) => {
  const uid = user.uid;

  await db.collection("users").doc(uid).set(
    {
      uid,
      email: user.email ?? null,
      role: "resident", // display only; authority is via custom claims
      officeId: null,
      officeName: null,
      isActive: true,
      status: "active",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    },
    { merge: true }
  );
});

/**
 * =========================
 * GET MY CLAIMS
 * =========================
 */
export const getMyClaims = functions.https.onCall(async (_data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "Auth required.");
  }
  const uid = context.auth.uid;
  const token = context.auth.token ?? {};

  const tokenRole = normalizeRole(token.role);
  const tokenOfficeId = coerceString(token.officeId);
  const tokenOfficeName = coerceString(token.officeName);
  const tokenIsActive =
    typeof token.isActive === "boolean" ? token.isActive : undefined;

  const profile = await getUserProfile(uid);

  return {
    role: token.role ? tokenRole : profile.role,
    officeId: tokenOfficeId ?? profile.officeId,
    officeName: tokenOfficeName ?? profile.officeName,
    isActive: tokenIsActive ?? profile.isActive,
  };
});

/**
 * =========================
 * GET SERVER TIME
 * =========================
 * Trusted online time source for clients.
 */
export const getServerTime = functions.https.onCall(async (_data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "Auth required.");
  }
  const now = new Date();
  return {
    epochMs: now.getTime(),
    iso: now.toISOString(),
  };
});

/**
 * =========================
 * OPS RUNTIME HEALTH
 * =========================
 * Lightweight runtime/version signal for admin operational checks.
 */
export const opsRuntimeHealth = functions.https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "Auth required.");
  }
  let callerRole = normalizeRole(context.auth.token.role);
  if (callerRole !== "super_admin") {
    const profile = await getUserProfile(context.auth.uid);
    callerRole = profile.role;
  }
  if (callerRole !== "super_admin") {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Only super_admin can access runtime health."
    );
  }

  const expectedBuild = coerceString(data?.expectedBuild);
  const requiredCallables: string[] = [
    "dtsInitiateTransfer",
    "dtsConfirmReceipt",
    "dtsRejectTransfer",
    "dtsUpdateStatus",
    "dtsTrackByTrackingNo",
    "dtsTrackByToken",
    "exportDtsQrZip",
  ];
  return {
    nowIso: new Date().toISOString(),
    functionsBuild: FUNCTIONS_BUILD_VERSION,
    runtimeNode: process.version,
    driftDetected: expectedBuild != null && expectedBuild !== FUNCTIONS_BUILD_VERSION,
    expectedBuild: expectedBuild ?? null,
    requiredCallables,
  };
});

/**
 * =========================
 * SET USER ROLE (super_admin only)
 * =========================
 */
export const setUserRole = functions.https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "Auth required.");
  }

  const callerRole = normalizeRole(context.auth.token.role);
  if (callerRole !== "super_admin") {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Only super_admin can change roles."
    );
  }

  const uid = data?.uid;
  const rawRole = data?.role as Role;

  if (typeof uid !== "string" || !ALLOWED_ROLES.includes(rawRole)) {
    throw new functions.https.HttpsError("invalid-argument", "Invalid uid or role.");
  }

  const nextRole = normalizeRole(rawRole);
  const targetProfile = await getUserProfile(uid);

  if (targetProfile.role === "super_admin" && nextRole !== "super_admin") {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Cannot change role of super_admin."
    );
  }

  const needsOffice = nextRole === "office_admin" || nextRole === "moderator";
  let officeId = coerceString(data?.officeId) ?? targetProfile.officeId;
  let officeName = coerceString(data?.officeName) ?? targetProfile.officeName;
  const isActive =
    typeof data?.isActive === "boolean" ? data.isActive : targetProfile.isActive;

  if (needsOffice && !officeId) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "officeId is required for office_admin or moderator."
    );
  }

  if (!needsOffice) {
    officeId = null;
    officeName = null;
  }

  if (officeId && !officeName) {
    const officeSnap = await db.collection("offices").doc(officeId).get();
    officeName = coerceString(officeSnap.data()?.name);
  }

  await admin.auth().setCustomUserClaims(uid, {
    role: nextRole,
    officeId,
    officeName,
    isActive,
  });

  // keep Firestore display role in-sync (critical for dropdowns / UI)
  await db.collection("users").doc(uid).set(
    {
      role: nextRole,
      officeId,
      officeName,
      isActive,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    },
    { merge: true }
  );

  return { success: true };
});

/**
 * =========================
 * SYNC USER CLAIMS
 * =========================
 * Keep auth custom claims in sync with Firestore user profile.
 */
export const onUserWrite = functions.firestore
  .document("users/{uid}")
  .onWrite(async (change, context) => {
    const uid = context.params.uid as string;
    if (!change.after.exists) {
      await admin.auth().setCustomUserClaims(uid, {});
      return;
    }

    const data = change.after.data() ?? {};
    const role = normalizeRole(data.role);
    let officeId = coerceString(data.officeId);
    let officeName = coerceString(data.officeName);
    const isActive = coerceBool(data.isActive, true);

    if (role === "super_admin" || role === "resident") {
      officeId = null;
      officeName = null;
    }

    await admin.auth().setCustomUserClaims(uid, {
      role,
      officeId,
      officeName,
      isActive,
    });

    if (data.role === "admin") {
      await change.after.ref.set(
        {
          role: "super_admin",
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        { merge: true }
      );
    }
  });

/**
 * =========================
 * DASHBOARD STATS TRIGGER
 * =========================
 * Maintain fast dashboard counters for production use.
 *
 * - global stats: /stats/global
 * - daily stats: /stats/daily/YYYY-MM-DD
 * - assignee stats: /stats/assignees/{uid}
 */
export const onReportWrite = functions.firestore
  .document("reports/{reportId}")
  .onWrite(async (change, context) => {
    const before = change.before.exists ? change.before.data() : null;
    const after = change.after.exists ? change.after.data() : null;

    // Determine operation
    const isCreate = !before && !!after;
    const isDelete = !!before && !after;
    const isUpdate = !!before && !!after;

    // Extract fields (safe defaults)
    const beforeStatus = (before?.status ?? "submitted") as string;
    const afterStatus = (after?.status ?? "submitted") as string;

    const beforeAssignedUid = (before?.assignedToUid ?? null) as string | null;
    const afterAssignedUid = (after?.assignedToUid ?? null) as string | null;

    // createdAt can be serverTimestamp; for daily stats we count creates only
    const now = new Date();
    const dayId = ymd(now);

    const globalRef = db.doc("stats/global");
    const dailyRef = db.doc(`stats/daily/${dayId}`);

    await db.runTransaction(async (tx) => {
      // Ensure docs exist
      const globalSnap = await tx.get(globalRef);
      if (!globalSnap.exists) {
        tx.set(globalRef, {
          totalReports: 0,
          openReports: 0,
          byStatus: {},
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        });
      }

      const dailySnap = await tx.get(dailyRef);
      if (!dailySnap.exists) {
        tx.set(dailyRef, {
          totalCreated: 0,
          byStatusCreated: {},
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        });
      }

      // Helpers to change status counters
      const decStatus = (status: string) => {
        tx.set(
          globalRef,
          {
            totalReports: incField("totalReports", 0),
            byStatus: { [status]: incField(`byStatus.${status}`, -1) },
            openReports: incField("openReports", isOpenStatus(status) ? -1 : 0),
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          },
          { merge: true }
        );
      };

      const incStatus = (status: string) => {
        tx.set(
          globalRef,
          {
            byStatus: { [status]: incField(`byStatus.${status}`, 1) },
            openReports: incField("openReports", isOpenStatus(status) ? 1 : 0),
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          },
          { merge: true }
        );
      };

      const incTotalReports = (delta: number) => {
        tx.set(
          globalRef,
          {
            totalReports: incField("totalReports", delta),
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          },
          { merge: true }
        );
      };

      const incDailyCreated = (status: string) => {
        tx.set(
          dailyRef,
          {
            totalCreated: incField("totalCreated", 1),
            byStatusCreated: {
              [status]: incField(`byStatusCreated.${status}`, 1),
            },
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          },
          { merge: true }
        );
      };

      const bumpAssignee = (
        uid: string,
        fromStatus: string | null,
        toStatus: string | null
      ) => {
        const ref = db.doc(`stats/assignees/${uid}`);

        tx.set(
          ref,
          {
            byStatus: {},
            assignedOpen: 0,
            assignedResolved: 0,
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          },
          { merge: true }
        );

        // decrement previous status bucket
        if (fromStatus) {
          tx.set(
            ref,
            {
              byStatus: { [fromStatus]: incField(`byStatus.${fromStatus}`, -1) },
              assignedOpen: incField("assignedOpen", isOpenStatus(fromStatus) ? -1 : 0),
              assignedResolved: incField("assignedResolved", fromStatus === "resolved" ? -1 : 0),
              updatedAt: admin.firestore.FieldValue.serverTimestamp(),
            },
            { merge: true }
          );
        }

        // increment new status bucket
        if (toStatus) {
          tx.set(
            ref,
            {
              byStatus: { [toStatus]: incField(`byStatus.${toStatus}`, 1) },
              assignedOpen: incField("assignedOpen", isOpenStatus(toStatus) ? 1 : 0),
              assignedResolved: incField("assignedResolved", toStatus === "resolved" ? 1 : 0),
              updatedAt: admin.firestore.FieldValue.serverTimestamp(),
            },
            { merge: true }
          );
        }
      };

      // CREATE
      if (isCreate && after) {
        incTotalReports(1);
        incStatus(afterStatus);
        incDailyCreated(afterStatus);

        // assignee stats
        if (afterAssignedUid) {
          bumpAssignee(afterAssignedUid, null, afterStatus);
        }
        return;
      }

      // DELETE
      if (isDelete && before) {
        incTotalReports(-1);
        decStatus(beforeStatus);

        // assignee stats
        if (beforeAssignedUid) {
          bumpAssignee(beforeAssignedUid, beforeStatus, null);
        }
        return;
      }

      // UPDATE
      if (isUpdate && before && after) {
        // status changed
        if (beforeStatus !== afterStatus) {
          decStatus(beforeStatus);
          incStatus(afterStatus);
        }

        // assignment changed
        if (beforeAssignedUid !== afterAssignedUid) {
          if (beforeAssignedUid) {
            bumpAssignee(beforeAssignedUid, beforeStatus, null);
          }
          if (afterAssignedUid) {
            bumpAssignee(afterAssignedUid, null, afterStatus);
          }
        } else {
          // same assignee but status changed => update that assignee’s buckets
          if (afterAssignedUid && beforeStatus !== afterStatus) {
            bumpAssignee(afterAssignedUid, beforeStatus, afterStatus);
          }
        }

        // touch global updatedAt
        tx.set(
          globalRef,
          { updatedAt: admin.firestore.FieldValue.serverTimestamp() },
          { merge: true }
        );
      }
    });
  });

/**
 * =========================
 * REPORT NOTIFICATIONS
 * =========================
 * - Admins get notified on new report
 * - Moderator gets notified on assignment
 * - Resident gets notified on status/assignment changes
 */
export const onReportNotify = functions.firestore
  .document("reports/{reportId}")
  .onWrite(async (change, context) => {
    const before = change.before.exists ? change.before.data() : null;
    const after = change.after.exists ? change.after.data() : null;
    const reportId = context.params.reportId as string;

    if (!before && after) {
      const title = (after.title ?? "Untitled") as string;
      const category = (after.category ?? "Report") as string;
      const status = (after.status ?? "submitted") as string;
      const createdByUid = (after.createdByUid ?? "") as string;
      const assignedToUid = (after.assignedToUid ?? null) as string | null;
      const createdByEmail = (after.createdByEmail ?? null) as string | null;
      const createdByName = (after.createdByName ?? null) as string | null;
      const reportOfficeId = coerceString(after.officeId);

      const superSnap = await db
        .collection("users")
        .where("role", "in", ["admin", "super_admin"])
        .get();
      const superUids = superSnap.docs.map((d) => d.id);

      let officeAdminUids: string[] = [];
      if (reportOfficeId) {
        const officeSnap = await db
          .collection("users")
          .where("role", "==", "office_admin")
          .where("officeId", "==", reportOfficeId)
          .get();
        officeAdminUids = officeSnap.docs.map((d) => d.id);
      } else {
        const officeSnap = await db
          .collection("users")
          .where("role", "==", "office_admin")
          .get();
        officeAdminUids = officeSnap.docs.map((d) => d.id);
      }

      const adminUids = Array.from(new Set([...superUids, ...officeAdminUids]));

      await notifyUsers(adminUids, {
        title: "New report submitted",
        body: `${title} - ${category}`,
        type: "report_created",
        reportId,
        status,
        createdByUid,
      });

      await addHistory(reportId, {
        type: "created",
        status,
        assignedToUid: assignedToUid ?? null,
        message: "Report created.",
      });

      await addAuditLog({
        action: "report_created",
        reportId,
        reportTitle: title,
        reportCategory: category,
        status,
        assignedToUid: assignedToUid ?? null,
        officeId: reportOfficeId ?? null,
        actorUid: createdByUid,
        actorEmail: createdByEmail,
        actorName: createdByName,
        actorRole: "resident",
        message: "Report created.",
      });
      return;
    }

    if (!before || !after) return;

    const title = (after.title ?? "Untitled") as string;
    const category = (after.category ?? "Report") as string;
    const createdByUid = (after.createdByUid ?? before.createdByUid ?? "") as string;
    const actorUid = (after.lastActionByUid ?? "") as string;
    const actorEmail = (after.lastActionByEmail ?? "") as string;
    const actorName = (after.lastActionByName ?? "") as string;
    const actorRole = (after.lastActionByRole ?? "") as string;
    const reportOfficeId = coerceString(after.officeId ?? before.officeId);

    const beforeStatus = (before.status ?? "submitted") as string;
    const afterStatus = (after.status ?? "submitted") as string;
    const statusChanged = beforeStatus !== afterStatus;

    const beforeAssigned = (before.assignedToUid ?? null) as string | null;
    const afterAssigned = (after.assignedToUid ?? null) as string | null;
    const assignedChanged = beforeAssigned !== afterAssigned;

    const beforeArchived = (before.archived ?? false) === true;
    const afterArchived = (after.archived ?? false) === true;
    const archivedChanged = beforeArchived !== afterArchived;

    if (assignedChanged) {
      if (afterAssigned) {
        await notifyUsers([afterAssigned], {
          title: "Report assigned to you",
          body: `${title} - ${category}`,
          type: "report_assigned",
          reportId,
          status: afterStatus,
          createdByUid,
          assignedToUid: afterAssigned,
        });
      }

      await addHistory(reportId, {
        type: "assignment_changed",
        fromAssignedUid: beforeAssigned ?? null,
        toAssignedUid: afterAssigned ?? null,
        status: afterStatus,
        message: afterAssigned ? "Report assigned." : "Report unassigned.",
      });

      await addAuditLog({
        action: "assignment_changed",
        reportId,
        reportTitle: title,
        reportCategory: category,
        status: afterStatus,
        fromAssignedUid: beforeAssigned ?? null,
        toAssignedUid: afterAssigned ?? null,
        officeId: reportOfficeId ?? null,
        actorUid: actorUid || null,
        actorEmail: actorEmail || null,
        actorName: actorName || null,
        actorRole: actorRole || null,
        message: afterAssigned ? "Report assigned." : "Report unassigned.",
      });
    }

    if (createdByUid && (statusChanged || assignedChanged)) {
      const detail = statusChanged
        ? `Status updated to ${prettyStatus(afterStatus)}`
        : "Your report was assigned to a moderator.";
      await notifyUsers([createdByUid], {
        title: "Report update",
        body: `${title} - ${detail}`,
        type: "report_updated",
        reportId,
        status: afterStatus,
        createdByUid,
        assignedToUid: afterAssigned ?? "",
      });
    }

    if (statusChanged) {
      await addHistory(reportId, {
        type: "status_changed",
        fromStatus: beforeStatus,
        toStatus: afterStatus,
        assignedToUid: afterAssigned ?? null,
        message: `Status changed from ${prettyStatus(beforeStatus)} to ${prettyStatus(
          afterStatus
        )}.`,
      });

      await addAuditLog({
        action: "status_changed",
        reportId,
        reportTitle: title,
        reportCategory: category,
        fromStatus: beforeStatus,
        toStatus: afterStatus,
        status: afterStatus,
        assignedToUid: afterAssigned ?? null,
        officeId: reportOfficeId ?? null,
        actorUid: actorUid || null,
        actorEmail: actorEmail || null,
        actorName: actorName || null,
        actorRole: actorRole || null,
        message: `Status changed from ${prettyStatus(beforeStatus)} to ${prettyStatus(
          afterStatus
        )}.`,
      });
    }

    if (archivedChanged) {
      const msg = afterArchived ? "Report archived." : "Report restored.";
      await addHistory(reportId, {
        type: afterArchived ? "archived" : "restored",
        status: afterStatus,
        assignedToUid: afterAssigned ?? null,
        message: msg,
      });

      await addAuditLog({
        action: afterArchived ? "report_archived" : "report_restored",
        reportId,
        reportTitle: title,
        reportCategory: category,
        status: afterStatus,
        assignedToUid: afterAssigned ?? null,
        officeId: reportOfficeId ?? null,
        actorUid: actorUid || null,
        actorEmail: actorEmail || null,
        actorName: actorName || null,
        actorRole: actorRole || null,
        message: msg,
      });
    }
  });

/**
 * =========================
 * ANNOUNCEMENT NOTIFICATIONS
 * =========================
 * Notify residents when an announcement is published.
 */
export const onAnnouncementNotify = functions.firestore
  .document("announcements/{announcementId}")
  .onWrite(async (change, context) => {
    const before = change.before.exists ? change.before.data() : null;
    const after = change.after.exists ? change.after.data() : null;
    if (!after) return;

    const beforeStatus = (before?.status ?? null) as string | null;
    const afterStatus = (after.status ?? "draft") as string;
    const newlyPublished = afterStatus === "published" && beforeStatus !== "published";
    if (!newlyPublished) return;

    const title = (after.title ?? "Announcement") as string;
    const category = (after.category ?? "") as string;
    const announcementId = context.params.announcementId as string;

    const body = category ? `${title} - ${category}` : title;
    const residentUids = await getResidentUids();

    await notifyUsers(residentUids, {
      title: "New announcement",
      body,
      type: "announcement_published",
      announcementId,
    });
  });

/**
 * =========================
 * ANNOUNCEMENT AUDIT LOGS
 * =========================
 */
export const onAnnouncementAudit = functions.firestore
  .document("announcements/{announcementId}")
  .onWrite(async (change, context) => {
    const before = change.before.exists ? change.before.data() : null;
    const after = change.after.exists ? change.after.data() : null;
    const announcementId = context.params.announcementId as string;

    if (!before && after) {
      const title = (after.title ?? "Announcement") as string;
      const category = (after.category ?? "") as string;
      const status = (after.status ?? "draft") as string;
      const actor = announcementActor(after as Record<string, unknown>);
      const officeId = coerceString((after as Record<string, unknown>).officeId);

      await addAuditLog({
        action: "announcement_created",
        announcementId,
        announcementTitle: title,
        announcementCategory: category,
        status,
        officeId: officeId ?? null,
        ...actor,
        message: "Announcement created.",
      });
      return;
    }

    if (before && !after) {
      const title = (before.title ?? "Announcement") as string;
      const category = (before.category ?? "") as string;
      const status = (before.status ?? "draft") as string;
      const actor = announcementActor(before as Record<string, unknown>);
      const officeId = coerceString((before as Record<string, unknown>).officeId);

      await addAuditLog({
        action: "announcement_deleted",
        announcementId,
        announcementTitle: title,
        announcementCategory: category,
        status,
        officeId: officeId ?? null,
        ...actor,
        message: "Announcement deleted.",
      });
      return;
    }

    if (!before || !after) return;

    const beforeStatus = (before.status ?? "draft") as string;
    const afterStatus = (after.status ?? "draft") as string;
    const statusChanged = beforeStatus !== afterStatus;
    const title = (after.title ?? "Announcement") as string;
    const category = (after.category ?? "") as string;
    const actor = announcementActor(after as Record<string, unknown>);
    const officeId = coerceString((after as Record<string, unknown>).officeId);

    if (statusChanged && afterStatus === "published") {
      await addAuditLog({
        action: "announcement_published",
        announcementId,
        announcementTitle: title,
        announcementCategory: category,
        status: afterStatus,
        officeId: officeId ?? null,
        ...actor,
        message: "Announcement published.",
      });
      return;
    }

    if (statusChanged && beforeStatus === "published" && afterStatus !== "published") {
      await addAuditLog({
        action: "announcement_unpublished",
        announcementId,
        announcementTitle: title,
        announcementCategory: category,
        status: afterStatus,
        officeId: officeId ?? null,
        ...actor,
        message: "Announcement unpublished.",
      });
      return;
    }

    await addAuditLog({
      action: "announcement_updated",
      announcementId,
      announcementTitle: title,
      announcementCategory: category,
      status: afterStatus,
      officeId: officeId ?? null,
      ...actor,
      message: statusChanged ? "Announcement status updated." : "Announcement updated.",
    });
  });

/**
 * =========================
 * ANNOUNCEMENT VIEW COUNT
 * =========================
 * Count unique viewers.
 */
export const onAnnouncementView = functions.firestore
  .document("announcements/{announcementId}/views/{uid}")
  .onCreate(async (_snap, context) => {
    const announcementId = context.params.announcementId as string;
    await db.doc(`announcements/${announcementId}`).set(
      {
        views: admin.firestore.FieldValue.increment(1),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );
  });

/**
 * =========================
 * NOTIFICATION CLEANUP
 * =========================
 * Removes read notifications older than 7 days.
 */
export const cleanupReadNotifications = functions.pubsub
  .schedule("every 24 hours")
  .timeZone("Asia/Manila")
  .onRun(async () => {
    const cutoff = admin.firestore.Timestamp.fromDate(
      new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
    );
    let deleted = 0;

    while (true) {
      const snap = await db
        .collectionGroup("notifications")
        .where("read", "==", true)
        .where("createdAt", "<", cutoff)
        .limit(400)
        .get();
      if (snap.empty) break;

      const batch = db.batch();
      for (const doc of snap.docs) {
        batch.delete(doc.ref);
      }
      await batch.commit();
      deleted += snap.size;
      if (snap.size < 400) break;
    }

    console.log(`cleanupReadNotifications deleted ${deleted} docs`);
    return null;
  });

/**
 * =========================
 * DTS TRACK SESSION CLEANUP
 * =========================
 * Removes expired public tracking sessions.
 */
export const cleanupExpiredDtsTrackSessions = functions.pubsub
  .schedule("every 24 hours")
  .timeZone("Asia/Manila")
  .onRun(async () => {
    const now = admin.firestore.Timestamp.now();
    let deleted = 0;
    while (true) {
      const snap = await db
        .collection("dts_track_sessions")
        .where("expiresAt", "<=", now)
        .limit(400)
        .get();
      if (snap.empty) break;
      const batch = db.batch();
      for (const doc of snap.docs) {
        batch.delete(doc.ref);
      }
      await batch.commit();
      deleted += snap.size;
      if (snap.size < 400) break;
    }
    console.log(`cleanupExpiredDtsTrackSessions deleted ${deleted} docs`);
    return null;
  });

/**
 * =========================
 * AD REACTIONS TRIGGER
 * =========================
 * Keeps aggregated like/dislike counts on /ads/{adId}
 */
export const onAdReactionWrite = functions.firestore
  .document("ads/{adId}/reactions/{uid}")
  .onWrite(async (change, context) => {
    const before = change.before.exists ? change.before.data() : null;
    const after = change.after.exists ? change.after.data() : null;

    const beforeType = (before?.type ?? null) as string | null;
    const afterType = (after?.type ?? null) as string | null;

    if (beforeType === afterType) return;

    let likeDelta = 0;
    let dislikeDelta = 0;

    if (beforeType === "like") likeDelta -= 1;
    if (beforeType === "dislike") dislikeDelta -= 1;
    if (afterType === "like") likeDelta += 1;
    if (afterType === "dislike") dislikeDelta += 1;

    if (likeDelta === 0 && dislikeDelta === 0) return;

    const adId = context.params.adId;
    const adRef = db.doc(`ads/${adId}`);

    await db.runTransaction(async (tx) => {
      const snap = await tx.get(adRef);
      if (!snap.exists) return;

      const data = snap.data() ?? {};
      const reactions = (data.reactions ?? {}) as Record<string, number>;
      const currentLike = Number(reactions.like ?? 0);
      const currentDislike = Number(reactions.dislike ?? 0);

      const nextLike = Math.max(0, currentLike + likeDelta);
      const nextDislike = Math.max(0, currentDislike + dislikeDelta);

      tx.set(
        adRef,
        {
          reactions: {
            like: nextLike,
            dislike: nextDislike,
          },
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        { merge: true }
      );
    });
  });

/**
 * =========================
 * DTS MOVEMENT NOTIFICATIONS
 * =========================
 * Push notification + inbox entry whenever a timeline movement is appended.
 */
export const onDtsTimelineNotify = functions.firestore
  .document("dts_documents/{docId}/timeline/{eventId}")
  .onCreate(async (snap, context) => {
    const docId = context.params.docId as string;
    const event = snap.data() ?? {};

    const dtsSnap = await db.collection("dts_documents").doc(docId).get();
    if (!dtsSnap.exists) return;

    const dts = dtsSnap.data() ?? {};
    const trackingNo = coerceString(dts.trackingNo) ?? docId;
    const status = coerceString(dts.status) ?? "RECEIVED";
    const eventType = coerceString(event.type) ?? "NOTE";
    const notifiableTypes = new Set([
      "RECEIVED",
      "TRANSFER_INITIATED",
      "TRANSFER_CONFIRMED",
      "STATUS_CHANGED",
      "RETURNED",
      "RELEASED",
      "ARCHIVED",
      "PULLED_OUT",
    ]);
    if (!notifiableTypes.has(eventType.toUpperCase())) return;
    const actorUid = coerceString(event.byUid);

    let actorName = "Staff";
    let actorEmail: string | null = null;
    let actorRole: string | null = null;
    let actorOfficeId: string | null = null;
    if (actorUid) {
      const actorSnap = await db.collection("users").doc(actorUid).get();
      const actor = actorSnap.data() ?? {};
      actorName =
        coerceString(actor.displayName) ??
        coerceString(actor.email) ??
        actorUid;
      actorEmail = coerceString(actor.email);
      actorRole = normalizeRole(actor.role);
      actorOfficeId = coerceString(actor.officeId);
    }

    const when = snap.createTime?.toDate() ?? new Date();
    const whenLabel = formatEventTime(when);
    const movementLabel = dtsEventLabel(eventType);
    const eventNotes = coerceString(event.notes);
    const fromOfficeId = coerceString(event.fromOfficeId);
    const toOfficeId = coerceString(event.toOfficeId);
    const currentOfficeId = coerceString(dts.currentOfficeId);
    const currentOfficeName = coerceString(dts.currentOfficeName);
    const title = coerceString(dts.title) ?? "Document";
    const trackingNoText = coerceString(dts.trackingNo) ?? docId;
    const officeIdForScope =
      toOfficeId ?? currentOfficeId ?? fromOfficeId ?? actorOfficeId;

    await addAuditLog({
      action: `dts_${eventType.toLowerCase()}`,
      dtsDocId: docId,
      dtsTrackingNo: trackingNoText,
      dtsQrCode: coerceString(dts.qrCode),
      dtsTitle: title,
      dtsDocType: coerceString(dts.docType),
      dtsConfidentiality: coerceString(dts.confidentiality),
      status,
      eventType: eventType.toUpperCase(),
      eventNotes: eventNotes ?? null,
      fromOfficeId: fromOfficeId ?? null,
      toOfficeId: toOfficeId ?? null,
      officeId: officeIdForScope ?? null,
      currentOfficeId: currentOfficeId ?? null,
      currentOfficeName: currentOfficeName ?? null,
      actorUid: actorUid ?? null,
      actorName,
      actorEmail: actorEmail ?? null,
      actorRole: actorRole ?? null,
      actorOfficeId: actorOfficeId ?? null,
      message: eventNotes != null && eventNotes.length > 0
        ? `DTS ${trackingNoText}: ${movementLabel}. ${eventNotes}`
        : `DTS ${trackingNoText}: ${movementLabel} by ${actorName} at ${whenLabel}.`,
    });

    const recipients = new Set<string>();
    const submittedByUid = coerceString(dts.submittedByUid);
    const createdByUid = coerceString(dts.createdByUid);
    const currentCustodianUid = coerceString(dts.currentCustodianUid);
    if (submittedByUid) recipients.add(submittedByUid);
    if (createdByUid) recipients.add(createdByUid);
    if (currentCustodianUid) recipients.add(currentCustodianUid);

    // Notify receiving office staff on transfer initiation.
    if (eventType.toUpperCase() === "TRANSFER_INITIATED") {
      const toOfficeId =
        coerceString(event.toOfficeId) ??
        coerceString((dts.pendingTransfer as Record<string, unknown> | undefined)?.toOfficeId);
      if (toOfficeId) {
        const officeStaffSnap = await db
          .collection("users")
          .where("officeId", "==", toOfficeId)
          .get();
        for (const doc of officeStaffSnap.docs) {
          const role = normalizeRole(doc.data().role);
          if (role === "office_admin" || role === "moderator") {
            recipients.add(doc.id);
          }
        }
      }
    }

    if (actorUid) recipients.delete(actorUid);
    if (recipients.size === 0) return;

    await notifyUsers(Array.from(recipients), {
      title: "Document update",
      body: `${trackingNo}: ${movementLabel} by ${actorName} at ${whenLabel}.`,
      type: "dts_movement",
      dtsDocId: docId,
      status,
      createdByUid: actorUid ?? undefined,
    });
  });

/**
 * =========================
 * DTS STAFF MUTATIONS (CALLABLES)
 * =========================
 * All transition-critical state changes are enforced server-side.
 */
export const dtsInitiateTransfer = functions.https.onCall(
  async (data, context) => {
    const actor = await requireStaffContext(context);
    const docId = coerceString(data?.docId);
    const toOfficeId = coerceString(data?.toOfficeId);
    const toOfficeName = coerceString(data?.toOfficeName);
    const toUid = coerceString(data?.toUid);

    if (!docId || !toOfficeId) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "docId and toOfficeId are required."
      );
    }

    const docRef = db.collection("dts_documents").doc(docId);
    const actorName = actorDisplayName(actor);

    await db.runTransaction(async (tx) => {
      const snap = await tx.get(docRef);
      if (!snap.exists) {
        throw new functions.https.HttpsError("not-found", "Document not found.");
      }

      const row = snap.data() ?? {};
      if (!canOperateOnDtsDoc(actor, row)) {
        throw new functions.https.HttpsError(
          "permission-denied",
          "You cannot transfer this document."
        );
      }

      if (dtsPendingTransfer(row)) {
        throw new functions.https.HttpsError(
          "failed-precondition",
          "Document already has a pending transfer."
        );
      }

      const fromOfficeId = coerceString(row.currentOfficeId);
      if (!fromOfficeId) {
        throw new functions.https.HttpsError(
          "failed-precondition",
          "Document current office is missing."
        );
      }

      const previousStatus = normalizeDtsStatus(row.status, "WITH_OFFICE");
      if (previousStatus === "IN_TRANSIT") {
        throw new functions.https.HttpsError(
          "failed-precondition",
          "Document is already in transit."
        );
      }
      if (previousStatus === "RELEASED" || previousStatus === "ARCHIVED") {
        throw new functions.https.HttpsError(
          "failed-precondition",
          "Released or archived documents cannot be transferred."
        );
      }
      tx.set(
        docRef,
        {
          pendingTransfer: {
            fromOfficeId,
            fromUid: actor.uid,
            toOfficeId,
            toOfficeName,
            toUid,
            previousStatus,
            initiatedAt: admin.firestore.FieldValue.serverTimestamp(),
          },
          status: "IN_TRANSIT",
          currentCustodianUid: null,
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        {merge: true}
      );

      const timelineRef = docRef.collection("timeline").doc();
      tx.set(timelineRef, {
        type: "TRANSFER_INITIATED",
        byUid: actor.uid,
        byName: actorName,
        fromOfficeId,
        toOfficeId,
        notes: toOfficeName
          ? `Transfer initiated to ${toOfficeName}.`
          : "Transfer initiated.",
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    });

    return {success: true};
  }
);

export const dtsCancelTransfer = functions.https.onCall(
  async (data, context) => {
    const actor = await requireStaffContext(context);
    const docId = coerceString(data?.docId);
    if (!docId) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "docId is required."
      );
    }

    const docRef = db.collection("dts_documents").doc(docId);
    const actorName = actorDisplayName(actor);

    await db.runTransaction(async (tx) => {
      const snap = await tx.get(docRef);
      if (!snap.exists) {
        throw new functions.https.HttpsError("not-found", "Document not found.");
      }
      const row = snap.data() ?? {};
      const currentStatus = normalizeDtsStatus(row.status, "RECEIVED");
      if (currentStatus !== "IN_TRANSIT") {
        throw new functions.https.HttpsError(
          "failed-precondition",
          "Document is not currently in transit."
        );
      }
      const pending = dtsPendingTransfer(row);
      if (!pending) {
        throw new functions.https.HttpsError(
          "failed-precondition",
          "No pending transfer to cancel."
        );
      }

      const fromOfficeId =
        coerceString(pending.fromOfficeId) ?? coerceString(row.currentOfficeId);
      if (!fromOfficeId) {
        throw new functions.https.HttpsError(
          "failed-precondition",
          "Unable to resolve source office."
        );
      }

      const canCancel =
        actor.role === "super_admin" ||
        coerceString(pending.fromUid) === actor.uid ||
        (actor.officeId != null && actor.officeId === fromOfficeId) ||
        sameNormalizedName(actor.officeName, coerceString(row.currentOfficeName));

      if (!canCancel) {
        throw new functions.https.HttpsError(
          "permission-denied",
          "Only the source office can cancel this transfer."
        );
      }

      const previousStatus = normalizeDtsStatus(
        pending.previousStatus,
        "WITH_OFFICE"
      );

      tx.set(
        docRef,
        {
          pendingTransfer: null,
          status: previousStatus,
          currentOfficeId: fromOfficeId,
          currentCustodianUid: actor.uid,
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        {merge: true}
      );

      const timelineRef = docRef.collection("timeline").doc();
      tx.set(timelineRef, {
        type: "RETURNED",
        byUid: actor.uid,
        byName: actorName,
        fromOfficeId: coerceString(pending.fromOfficeId),
        toOfficeId: coerceString(pending.toOfficeId),
        notes: "Transfer cancelled while in transit.",
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    });

    return {success: true};
  }
);

export const dtsRejectTransfer = functions.https.onCall(
  async (data, context) => {
    const actor = await requireStaffContext(context);
    const docId = coerceString(data?.docId);
    const reason = coerceString(data?.reason);
    const attachments = sanitizeDtsAttachments(data?.attachments);

    if (!docId || !reason) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "docId and reason are required."
      );
    }

    const docRef = db.collection("dts_documents").doc(docId);
    const actorName = actorDisplayName(actor);

    await db.runTransaction(async (tx) => {
      const snap = await tx.get(docRef);
      if (!snap.exists) {
        throw new functions.https.HttpsError("not-found", "Document not found.");
      }
      const row = snap.data() ?? {};
      const currentStatus = normalizeDtsStatus(row.status, "RECEIVED");
      if (currentStatus !== "IN_TRANSIT") {
        throw new functions.https.HttpsError(
          "failed-precondition",
          "Document is not currently in transit."
        );
      }
      const pending = dtsPendingTransfer(row);
      if (!pending) {
        throw new functions.https.HttpsError(
          "failed-precondition",
          "No pending transfer to reject."
        );
      }

      if (actor.role !== "super_admin" && !isIntendedDtsReceiver(actor, pending)) {
        throw new functions.https.HttpsError(
          "permission-denied",
          "You are not the receiving office for this transfer."
        );
      }

      const fromOfficeId =
        coerceString(pending.fromOfficeId) ?? coerceString(row.currentOfficeId);
      const previousStatus = normalizeDtsStatus(
        pending.previousStatus,
        "WITH_OFFICE"
      );

      tx.set(
        docRef,
        {
          pendingTransfer: null,
          status: previousStatus,
          currentOfficeId: fromOfficeId,
          currentCustodianUid: coerceString(pending.fromUid),
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        {merge: true}
      );

      const timelineRef = docRef.collection("timeline").doc();
      tx.set(timelineRef, {
        type: "RETURNED",
        byUid: actor.uid,
        byName: actorName,
        fromOfficeId: coerceString(pending.toOfficeId),
        toOfficeId: coerceString(pending.fromOfficeId),
        notes: `Transfer rejected: ${reason}`,
        attachments,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    });

    return {success: true};
  }
);

export const dtsConfirmReceipt = functions.https.onCall(
  async (data, context) => {
    const actor = await requireStaffContext(context);
    const docId = coerceString(data?.docId);
    if (!docId) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "docId is required."
      );
    }

    const docRef = db.collection("dts_documents").doc(docId);
    const actorName = actorDisplayName(actor);

    await db.runTransaction(async (tx) => {
      const snap = await tx.get(docRef);
      if (!snap.exists) {
        throw new functions.https.HttpsError("not-found", "Document not found.");
      }

      const row = snap.data() ?? {};
      const currentStatus = normalizeDtsStatus(row.status, "RECEIVED");
      if (currentStatus !== "IN_TRANSIT") {
        throw new functions.https.HttpsError(
          "failed-precondition",
          "Document is not currently in transit."
        );
      }
      const pending = dtsPendingTransfer(row);
      if (!pending) {
        throw new functions.https.HttpsError(
          "failed-precondition",
          "No pending transfer to confirm."
        );
      }

      if (actor.role !== "super_admin" && !isIntendedDtsReceiver(actor, pending)) {
        throw new functions.https.HttpsError(
          "permission-denied",
          "You are not the receiving office for this transfer."
        );
      }

      const toOfficeId = coerceString(pending.toOfficeId);
      if (!toOfficeId) {
        throw new functions.https.HttpsError(
          "failed-precondition",
          "Transfer destination office is missing."
        );
      }
      const toOfficeName =
        coerceString(pending.toOfficeName) ??
        actor.officeName ??
        coerceString(row.currentOfficeName) ??
        toOfficeId;

      tx.set(
        docRef,
        {
          currentOfficeId: toOfficeId,
          currentOfficeName: toOfficeName,
          currentCustodianUid: actor.uid,
          pendingTransfer: null,
          status: "WITH_OFFICE",
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        {merge: true}
      );

      const timelineRef = docRef.collection("timeline").doc();
      tx.set(timelineRef, {
        type: "TRANSFER_CONFIRMED",
        byUid: actor.uid,
        byName: actorName,
        toOfficeId,
        notes: `Transfer confirmed by ${actorName}.`,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    });

    return {success: true};
  }
);

export const dtsUpdateStatus = functions.https.onCall(
  async (data, context) => {
    const actor = await requireStaffContext(context);
    const docId = coerceString(data?.docId);
    const requestedStatus = coerceString(data?.status);
    if (!docId || !requestedStatus) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "docId and status are required."
      );
    }

    const status = normalizeDtsStatus(requestedStatus);
    const actorName = coerceString(data?.actorName) ?? actorDisplayName(actor);
    const docRef = db.collection("dts_documents").doc(docId);

    await db.runTransaction(async (tx) => {
      const snap = await tx.get(docRef);
      if (!snap.exists) {
        throw new functions.https.HttpsError("not-found", "Document not found.");
      }
      const row = snap.data() ?? {};
      if (!canOperateOnDtsDoc(actor, row)) {
        throw new functions.https.HttpsError(
          "permission-denied",
          "You cannot update this document."
        );
      }
      if (dtsPendingTransfer(row)) {
        throw new functions.https.HttpsError(
          "failed-precondition",
          "Cannot update status while transfer is in transit."
        );
      }
      const currentStatus = normalizeDtsStatus(row.status, "RECEIVED");
      if (status === "IN_TRANSIT") {
        throw new functions.https.HttpsError(
          "invalid-argument",
          "Use transfer actions to set IN_TRANSIT."
        );
      }
      if (!canTransitionDtsStatus(currentStatus, status)) {
        throw new functions.https.HttpsError(
          "failed-precondition",
          `Invalid status transition from ${prettyDtsStatus(currentStatus)} to ${prettyDtsStatus(status)}.`
        );
      }

      tx.set(
        docRef,
        {
          status,
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        {merge: true}
      );
      const timelineRef = docRef.collection("timeline").doc();
      tx.set(timelineRef, {
        type: "STATUS_CHANGED",
        byUid: actor.uid,
        byName: actorName,
        status,
        notes: `Status updated to ${prettyDtsStatus(status)} by ${actorName}.`,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    });

    return {success: true, status};
  }
);

export const dtsAddNote = functions.https.onCall(
  async (data, context) => {
    const actor = await requireStaffContext(context);
    const docId = coerceString(data?.docId);
    const notes = coerceString(data?.notes) ?? "";
    const attachments = sanitizeDtsAttachments(data?.attachments);
    if (!docId || (notes.length === 0 && attachments.length === 0)) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "docId and note or attachments are required."
      );
    }

    const actorName = actorDisplayName(actor);
    const docRef = db.collection("dts_documents").doc(docId);
    await db.runTransaction(async (tx) => {
      const snap = await tx.get(docRef);
      if (!snap.exists) {
        throw new functions.https.HttpsError("not-found", "Document not found.");
      }
      const row = snap.data() ?? {};
      if (!canOperateOnDtsDoc(actor, row)) {
        throw new functions.https.HttpsError(
          "permission-denied",
          "You cannot update this document."
        );
      }

      const pending = dtsPendingTransfer(row);
      if (pending && actor.role !== "super_admin" && isIntendedDtsReceiver(actor, pending)) {
        throw new functions.https.HttpsError(
          "failed-precondition",
          "Confirm or reject receipt first before adding notes."
        );
      }

      tx.set(
        docRef,
        {
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        {merge: true}
      );
      const timelineRef = docRef.collection("timeline").doc();
      tx.set(timelineRef, {
        type: "NOTE",
        byUid: actor.uid,
        byName: actorName,
        notes,
        attachments,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    });

    return {success: true};
  }
);

export const dtsSetCoverPhoto = functions.https.onCall(
  async (data, context) => {
    const actor = await requireStaffContext(context);
    const docId = coerceString(data?.docId);
    const rawCover = data?.coverPhoto;
    if (!docId || !rawCover || typeof rawCover !== "object") {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "docId and coverPhoto are required."
      );
    }
    const coverPhoto = sanitizeDtsAttachments([rawCover])[0];
    if (!coverPhoto) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "Invalid coverPhoto payload."
      );
    }

    const docRef = db.collection("dts_documents").doc(docId);
    const actorName = actorDisplayName(actor);
    await db.runTransaction(async (tx) => {
      const snap = await tx.get(docRef);
      if (!snap.exists) {
        throw new functions.https.HttpsError("not-found", "Document not found.");
      }
      const row = snap.data() ?? {};
      if (!canOperateOnDtsDoc(actor, row)) {
        throw new functions.https.HttpsError(
          "permission-denied",
          "You cannot update this document."
        );
      }
      tx.set(
        docRef,
        {
          coverPhoto,
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        {merge: true}
      );
      tx.set(docRef.collection("timeline").doc(), {
        type: "NOTE",
        byUid: actor.uid,
        byName: actorName,
        notes: "Cover photo uploaded.",
        attachments: [coverPhoto],
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    });

    return {success: true};
  }
);

export const dtsAuditAttachmentAccess = functions.https.onCall(
  async (data, context) => {
    const actor = await requireStaffContext(context);
    const docId = coerceString(data?.docId);
    const eventId = coerceString(data?.eventId);
    const action = (coerceString(data?.action) ?? "open").toLowerCase();
    const attachmentName = coerceString(data?.attachmentName);
    const attachmentPath = coerceString(data?.attachmentPath);
    const attachmentUrl = coerceString(data?.attachmentUrl);

    if (!docId || !eventId || !attachmentName) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "docId, eventId, and attachmentName are required."
      );
    }
    if (!["open", "preview", "download"].includes(action)) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "action must be open, preview, or download."
      );
    }

    const docRef = db.collection("dts_documents").doc(docId);
    const snap = await docRef.get();
    if (!snap.exists) {
      throw new functions.https.HttpsError("not-found", "Document not found.");
    }
    const row = snap.data() ?? {};
    if (!canOperateOnDtsDoc(actor, row)) {
      throw new functions.https.HttpsError(
        "permission-denied",
        "You cannot access attachments for this document."
      );
    }

    await docRef.collection("attachment_access").add({
      eventId,
      action,
      attachmentName,
      attachmentPath: attachmentPath ?? null,
      attachmentUrl: attachmentUrl ?? null,
      byUid: actor.uid,
      byName: actorDisplayName(actor),
      byRole: actor.role,
      byOfficeId: actor.officeId ?? null,
      ipHash: contextIpHash(context),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    await addAuditLog({
      action: "dts_attachment_access",
      dtsDocId: docId,
      eventId,
      attachmentName,
      accessAction: action,
      actorUid: actor.uid,
      actorRole: actor.role,
      actorOfficeId: actor.officeId ?? null,
      actorOfficeName: actor.officeName ?? null,
      message: `Attachment ${action}: ${attachmentName}`,
    });
    return {success: true};
  }
);

/**
 * =========================
 * DTS TRACKING LOOKUP
 * =========================
 * Lookup by trackingNo + PIN and return a sanitized payload.
 */
export const dtsTrackByTrackingNo = functions.https.onCall(
  async (data, context) => {
    const trackingNo = coerceString(data?.trackingNo);
    const pin = coerceString(data?.pin);

    if (!trackingNo || !pin) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "trackingNo and pin are required."
      );
    }

    const snap = await db
      .collection("dts_documents")
      .where("trackingNo", "==", trackingNo)
      .limit(1)
      .get();

    if (snap.empty) {
      throw new functions.https.HttpsError("not-found", "Document not found.");
    }

    const doc = snap.docs[0];
    const dataRow = doc.data() ?? {};
    await verifyPinWithRateLimit(trackingNo, pin, dataRow, context);
    const session = await issueTrackingSession(doc.id, trackingNo, context);
    const sanitized = buildSanitizedTrackingResult(trackingNo, dataRow);
    return {
      ...sanitized,
      sessionToken: session.token,
      sessionExpiresAt: session.expiresAtMs,
    };
  }
);

/**
 * =========================
 * DTS TRACKING LOOKUP (QR + PIN)
 * =========================
 * Allows public tracking using the QR sticker value, still requiring PIN.
 */
export const dtsTrackByQrAndPin = functions.https.onCall(
  async (data, context) => {
    const qrCode = coerceString(data?.qrCode);
    const pin = coerceString(data?.pin);
    if (!qrCode || !pin) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "qrCode and pin are required."
      );
    }

    const qrSnap = await db.collection("dts_qr_index").doc(qrCode).get();
    if (!qrSnap.exists) {
      throw new functions.https.HttpsError("not-found", "Document not found.");
    }
    const docId = coerceString(qrSnap.data()?.docId);
    if (!docId) {
      throw new functions.https.HttpsError("not-found", "Document not found.");
    }

    const docSnap = await db.collection("dts_documents").doc(docId).get();
    if (!docSnap.exists) {
      throw new functions.https.HttpsError("not-found", "Document not found.");
    }
    const row = docSnap.data() ?? {};
    const trackingNo = coerceString(row.trackingNo);
    if (!trackingNo) {
      throw new functions.https.HttpsError(
        "failed-precondition",
        "Document tracking number is missing."
      );
    }

    await verifyPinWithRateLimit(trackingNo, pin, row, context);
    const session = await issueTrackingSession(docId, trackingNo, context);
    const sanitized = buildSanitizedTrackingResult(trackingNo, row);
    return {
      ...sanitized,
      qrCode,
      sessionToken: session.token,
      sessionExpiresAt: session.expiresAtMs,
    };
  }
);

/**
 * =========================
 * DTS TRACKING LOOKUP (TOKEN)
 * =========================
 * Re-check status using a short-lived token and rotate token on every successful call.
 */
export const dtsTrackByToken = functions.https.onCall(
  async (data, context) => {
    const token = coerceString(data?.sessionToken);
    if (!token) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "sessionToken is required."
      );
    }

    const session = await resolveTrackingSession(token, context);
    const docId = coerceString(session.data.docId);
    const trackingNo = coerceString(session.data.trackingNo);
    if (!docId || !trackingNo) {
      await session.ref.delete();
      throw new functions.https.HttpsError(
        "failed-precondition",
        "Tracking session is corrupted. Re-enter PIN."
      );
    }

    const docSnap = await db.collection("dts_documents").doc(docId).get();
    if (!docSnap.exists) {
      await session.ref.delete();
      throw new functions.https.HttpsError("not-found", "Document not found.");
    }
    const row = docSnap.data() ?? {};
    const nextSession = await issueTrackingSession(docId, trackingNo, context);
    await session.ref.delete();
    const sanitized = buildSanitizedTrackingResult(trackingNo, row);
    return {
      ...sanitized,
      sessionToken: nextSession.token,
      sessionExpiresAt: nextSession.expiresAtMs,
    };
  }
);

/**
 * =========================
 * DTS SAVE TRACKED DOC TO ACCOUNT
 * =========================
 * Allows a signed-in user to save a tracked hard-copy record into My Documents.
 */
export const dtsSaveTrackedDocument = functions.https.onCall(
  async (data, context) => {
    if (!context.auth) {
      throw new functions.https.HttpsError("unauthenticated", "Auth required.");
    }

    const trackingNo = coerceString(data?.trackingNo);
    const pin = coerceString(data?.pin);
    const sessionToken = coerceString(data?.sessionToken);
    if (!trackingNo || (!pin && !sessionToken)) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "trackingNo and either pin or sessionToken are required."
      );
    }

    let docRef: admin.firestore.DocumentReference | null = null;
    let dataRow: Record<string, unknown> = {};
    if (sessionToken) {
      const session = await resolveTrackingSession(sessionToken, context);
      const sessionTrackingNo = coerceString(session.data.trackingNo);
      if (sessionTrackingNo !== trackingNo) {
        throw new functions.https.HttpsError(
          "permission-denied",
          "Tracking token does not match tracking number."
        );
      }
      const docId = coerceString(session.data.docId);
      if (!docId) {
        throw new functions.https.HttpsError(
          "failed-precondition",
          "Tracking token is invalid."
        );
      }
      const docSnap = await db.collection("dts_documents").doc(docId).get();
      if (!docSnap.exists) {
        throw new functions.https.HttpsError("not-found", "Document not found.");
      }
      docRef = docSnap.ref;
      dataRow = docSnap.data() ?? {};
      await session.ref.delete();
    } else {
      const snap = await db
        .collection("dts_documents")
        .where("trackingNo", "==", trackingNo)
        .limit(1)
        .get();

      if (snap.empty) {
        throw new functions.https.HttpsError("not-found", "Document not found.");
      }

      docRef = snap.docs[0].ref;
      dataRow = snap.docs[0].data() ?? {};
      await verifyPinWithRateLimit(trackingNo, pin ?? "", dataRow, context);
    }

    if (!docRef) {
      throw new functions.https.HttpsError(
        "failed-precondition",
        "Unable to resolve document reference."
      );
    }

    const existingOwner = coerceString(dataRow.submittedByUid);
    if (existingOwner && existingOwner !== context.auth.uid) {
      throw new functions.https.HttpsError(
        "failed-precondition",
        "This document is already linked to another account."
      );
    }

    await docRef.set(
      {
        submittedByUid: context.auth.uid,
        saveToResidentAccount: true,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );

    await docRef.collection("timeline").add({
      type: "NOTE",
      byUid: context.auth.uid,
      notes: "Resident linked this document to account.",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return {
      saved: true,
      docId: docRef.id,
      trackingNo,
    };
  }
);

/**
 * =========================
 * DTS UNSAVE TRACKED DOC FROM ACCOUNT
 * =========================
 * Allows resident to unlink a previously saved tracked document.
 */
export const dtsUnsaveTrackedDocument = functions.https.onCall(
  async (data, context) => {
    if (!context.auth) {
      throw new functions.https.HttpsError("unauthenticated", "Auth required.");
    }
    const docId = coerceString(data?.docId);
    if (!docId) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "docId is required."
      );
    }

    const docRef = db.collection("dts_documents").doc(docId);
    const snap = await docRef.get();
    if (!snap.exists) {
      throw new functions.https.HttpsError("not-found", "Document not found.");
    }
    const row = snap.data() ?? {};
    const ownerUid = coerceString(row.submittedByUid);
    if (!ownerUid || ownerUid !== context.auth.uid) {
      throw new functions.https.HttpsError(
        "permission-denied",
        "Only the linked resident can remove this document."
      );
    }

    await docRef.set(
      {
        submittedByUid: null,
        saveToResidentAccount: false,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      {merge: true}
    );
    await docRef.collection("timeline").add({
      type: "NOTE",
      byUid: context.auth.uid,
      notes: "Resident removed this document from account.",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return {success: true};
  }
);

/**
 * =========================
 * DTS QR GENERATION
 * =========================
 * Generates QR codes and stores them in Firestore + Storage.
 */
export const generateDtsQrCodes = functions.https.onCall(
  async (data, context) => {
    if (!context.auth) {
      throw new functions.https.HttpsError("unauthenticated", "Auth required.");
    }

    let callerRole = normalizeRole(context.auth.token.role);
    if (callerRole !== "super_admin") {
      const profile = await getUserProfile(context.auth.uid);
      callerRole = profile.role;
    }
    if (callerRole !== "super_admin") {
      throw new functions.https.HttpsError(
        "permission-denied",
        "Only super_admin can generate QR codes."
      );
    }

    const countRaw = typeof data?.count === "number" ? data.count : 50;
    const prefix = coerceString(data?.prefix) ?? "DTS-QR";
    const count = Math.max(1, Math.min(200, Math.floor(countRaw)));

    const created: Array<{ code: string; path: string }> = [];
    const bucket = admin.storage().bucket();

    let batch = db.batch();
    let batchSize = 0;

    async function commitBatch() {
      if (batchSize === 0) return;
      await batch.commit();
      batch = db.batch();
      batchSize = 0;
    }

    while (created.length < count) {
      const code = randomCode(prefix);
      const ref = db.collection("dts_qr_codes").doc(code);
      const snap = await ref.get();
      if (snap.exists) {
        continue;
      }

      const path = `dts_qr_codes/${code}.png`;
      const png = await createQrPng(code);
      await bucket.file(path).save(png, {
        metadata: {
          contentType: "image/png",
        },
      });

      batch.set(ref, {
        qrCode: code,
        status: "unused",
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        createdByUid: context.auth.uid,
        imagePath: path,
      });
      batchSize += 1;
      created.push({ code, path });

      if (batchSize >= 400) {
        await commitBatch();
      }
    }

    await commitBatch();

    return {
      count: created.length,
      codes: created.map((c) => c.code),
      items: created,
    };
  }
);

/**
 * =========================
 * DTS QR EXPORT ZIP
 * =========================
 * Exports up to 10 QR PNGs into a zip file and returns a download URL.
 */
export const exportDtsQrZip = functions.https.onCall(
  async (data, context) => {
    if (!context.auth) {
      throw new functions.https.HttpsError("unauthenticated", "Auth required.");
    }

    let callerRole = normalizeRole(context.auth.token.role);
    if (callerRole !== "super_admin") {
      const profile = await getUserProfile(context.auth.uid);
      callerRole = profile.role;
    }
    if (callerRole !== "super_admin") {
      throw new functions.https.HttpsError(
        "permission-denied",
        "Only super_admin can export QR codes."
      );
    }

    const bucket = admin.storage().bucket();
    let codes: string[] = [];
    if (Array.isArray(data?.codes)) {
      codes = data.codes
        .map((c: unknown) => (c ? String(c).trim() : ""))
        .filter((c: string) => c.length > 0);
    }

    if (codes.length === 0) {
      const snap = await db
        .collection("dts_qr_codes")
        .orderBy("createdAt", "desc")
        .limit(10)
        .get();
      codes = snap.docs.map((d) => d.id);
    }

    codes = codes.slice(0, 10);
    if (codes.length === 0) {
      throw new functions.https.HttpsError(
        "failed-precondition",
        "No QR codes available."
      );
    }

    const zip = new AdmZip();
    const exportedCodes: string[] = [];
    for (const code of codes) {
      const doc = await db.collection("dts_qr_codes").doc(code).get();
      if (!doc.exists) {
        continue;
      }
      // Generate QR PNG on the fly to avoid storage download errors.
      const png = await createQrPng(code);
      zip.addFile(`${code}.png`, png);
      exportedCodes.push(code);
    }

    if (exportedCodes.length === 0) {
      throw new functions.https.HttpsError(
        "failed-precondition",
        "No valid QR code records found for export."
      );
    }

    const zipBuffer = zip.toBuffer();
    const exportPath = `dts_qr_exports/qr-batch-${Date.now()}.zip`;
    await bucket.file(exportPath).save(zipBuffer, {
      metadata: { contentType: "application/zip" },
    });

    let downloadUrl: string | null = null;
    try {
      const result = await bucket.file(exportPath).getSignedUrl({
        action: "read",
        expires: Date.now() + 1000 * 60 * 60,
      });
      downloadUrl = result[0];
    } catch (error) {
      console.warn("exportDtsQrZip: signed URL generation failed", error);
    }

    return {
      count: exportedCodes.length,
      path: exportPath,
      downloadUrl,
      codes: exportedCodes,
    };
  }
);
