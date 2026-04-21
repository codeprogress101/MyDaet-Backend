/*
 * Revised 5-role RBAC model for Cloud Functions.
 * Roles are now distinct across five values: resident, moderator, office_admin, admin, and super_admin.
 * Office Admin stays office-scoped, while Admin is municipal-wide.
 * Cloud Functions remain the authoritative RBAC enforcement layer and must stay aligned with Firestore rules.
 * This pass also hardens report SOP enforcement (claim/assign/status/SLA escalation)
 * so the admin UI mirrors the workflow but does not become the authority.
 */
import * as functions from "firebase-functions/v1";
import * as admin from "firebase-admin";
import * as crypto from "crypto";
import * as qrcode from "qrcode";
import AdmZip from "adm-zip";
import bcrypt from "bcryptjs";
import {PDFDocument, StandardFonts, rgb} from "pdf-lib";
import {
  HttpsError as HttpsErrorV2,
  onCall as onCallV2,
  onRequest as onRequestV2,
  type CallableRequest,
} from "firebase-functions/v2/https";
import {defineSecret} from "firebase-functions/params";
import nodemailer from "nodemailer";

admin.initializeApp();
const db = admin.firestore();
const REGION = "us-central1";
const regionalFunctions = functions.region(REGION);
const TRACKING_NO_REGEX = /^[A-Z0-9][A-Z0-9._-]{3,63}$/;
const TRACKING_PIN_REGEX = /^[A-Za-z0-9@#$%^&*()_+\-=]{4,32}$/;
const TRACK_LOOKUP_ALLOWED_ORIGINS = String(process.env.TRACK_LOOKUP_ALLOWED_ORIGINS ?? "")
  .split(",")
  .map((value) => value.trim())
  .filter((value) => value.length > 0);
const PUBLIC_REPORT_ALLOWED_ORIGINS = String(process.env.PUBLIC_REPORT_ALLOWED_ORIGINS ?? "")
  .split(",")
  .map((value) => value.trim())
  .filter((value) => value.length > 0);
const CORS_MODE = String(process.env.CORS_MODE ?? "").trim().toLowerCase();
const FUNCTIONS_EMULATOR_ENABLED =
  String(process.env.FUNCTIONS_EMULATOR ?? "").trim().toLowerCase() === "true";
const APP_CHECK_MODE = String(process.env.APP_CHECK_MODE ?? "").trim().toLowerCase();
const POST_COLLECTIONS = ["posts"] as const;
const PUBLISHED_STATUS_VARIANTS = ["published", "Published", "PUBLISHED"] as const;
const SYSTEM_SETTINGS_FEATURE_KEYS = [
  "tourism",
  "announcements",
  "news",
  "jobs",
  "publicDocs",
  "directory",
  "documentTracking",
  "feedback",
  "reports",
  "messages",
  "transparency",
  "civilRegistry",
] as const;
type SystemFeatureKey = typeof SYSTEM_SETTINGS_FEATURE_KEYS[number];
type SystemFeatureFlags = Record<SystemFeatureKey, boolean>;

/*
 * Callable App Check policy:
 * - Emulator remains permissive for local development.
 * - Deployed production defaults to enforced App Check.
 * - Emergency toggle: APP_CHECK_MODE=off|permissive disables enforcement.
 * - Explicit enable: APP_CHECK_MODE=on|strict|enforce.
 */
function strictAppCheckEnabled(): boolean {
  if (FUNCTIONS_EMULATOR_ENABLED) return false;
  if (["off", "open", "permissive"].includes(APP_CHECK_MODE)) return false;
  if (["on", "strict", "enforce"].includes(APP_CHECK_MODE)) return true;
  // Default to enforced outside emulator; use APP_CHECK_MODE=permissive for staged rollback.
  return true;
}

const protectedCallableFunctions = strictAppCheckEnabled() ?
  regionalFunctions.runWith({enforceAppCheck: true}) :
  regionalFunctions;
const protectedCallableV2Options = strictAppCheckEnabled() ?
  {region: REGION, enforceAppCheck: true} :
  {region: REGION};

/**
 * Role definitions
 */
type Role = "resident" | "moderator" | "office_admin" | "super_admin" | "admin";
type NormalizedRole = "resident" | "moderator" | "office_admin" | "admin" | "super_admin";
const ALLOWED_ROLES: Role[] = [
  "resident",
  "moderator",
  "office_admin",
  "admin",
  "super_admin",
];
const USER_MANAGEMENT_ROLES: NormalizedRole[] = [
  "resident",
  "moderator",
  "office_admin",
  "admin",
  "super_admin",
];
const USER_MIN_PASSWORD_LENGTH = 8;

// The report workflow follows the LGU SOP:
// Submission -> Verification -> Assignment -> In Progress -> Resolution -> Closure.
// `acknowledged` is the explicit acknowledgement checkpoint before full review.
const OPEN_STATUSES = ["submitted", "acknowledged", "in_review", "assigned", "in_progress"] as const;
const PUBLIC_REPORT_WRITE_SERVICE = "Public reporting HTTP endpoints";
const PUBLIC_REPORT_RATE_LIMIT_WINDOW_MS = 5 * 60 * 1000;
const PUBLIC_REPORT_RATE_LIMIT_MAX_REQUESTS = 5;
const PUBLIC_REPORT_LOOKUP_RATE_LIMIT_WINDOW_MS = 5 * 60 * 1000;
const PUBLIC_REPORT_LOOKUP_RATE_LIMIT_MAX_REQUESTS = 12;
const FEATURE_SUGGESTION_COOLDOWN_MS = 24 * 60 * 60 * 1000;
const EMERGENCY_DUPLICATE_WINDOW_MS = 45 * 60 * 1000;
const EMERGENCY_DUPLICATE_DISTANCE_METERS = 250;
const FEEDBACK_EMAIL_APP_PASSWORD = defineSecret("FEEDBACK_EMAIL_APP_PASSWORD");
const FEEDBACK_EMAIL_FUNCTION_SECRETS = [FEEDBACK_EMAIL_APP_PASSWORD];
const protectedCallableV2FeedbackOptions = strictAppCheckEnabled() ?
  {region: REGION, enforceAppCheck: true, secrets: FEEDBACK_EMAIL_FUNCTION_SECRETS} :
  {region: REGION, secrets: FEEDBACK_EMAIL_FUNCTION_SECRETS};
const FEEDBACK_EMAIL_SENDER = String(process.env.FEEDBACK_EMAIL_SENDER ?? "maogmangdaet.portal@gmail.com")
  .trim() || "maogmangdaet.portal@gmail.com";
const FEEDBACK_EMAIL_SENDER_NAME =
  String(process.env.FEEDBACK_EMAIL_SENDER_NAME ?? "Municipality of Daet Portal").trim() ||
  "Municipality of Daet Portal";
const PORTAL_PUBLIC_BASE_URL =
  String(process.env.PORTAL_PUBLIC_BASE_URL ?? "https://maogmangdaet.gov.ph")
    .trim()
    .replace(/\/+$/, "") || "https://maogmangdaet.gov.ph";
const DTS_ATTACHMENT_BUCKET_PATTERN = /^mydaet(?:\.appspot\.com|\.firebasestorage\.app)$/i;
const DTS_ATTACHMENT_PATH_PATTERN = /^dts(?:[/_-]|$)/i;
const INVALID_TRACKING_CREDENTIALS_MESSAGE = "Invalid tracking credentials.";

function isOpenStatus(s: string): boolean {
  return (OPEN_STATUSES as readonly string[]).includes(s);
}

function normalizeRole(raw: unknown): NormalizedRole {
  if (!raw) return "resident";
  const role = String(raw).trim().toLowerCase();
  if (role === "super_admin" || role === "superadmin" || role === "super-admin") return "super_admin";
  if (
    role === "office_admin" ||
    role === "officeadmin" ||
    role === "office-admin"
  ) {
    return "office_admin";
  }
  if (
    role === "admin"
  ) {
    return "admin";
  }
  if (role === "moderator") return "moderator";
  return "resident";
}

function coerceString(value: unknown): string | null {
  if (!value) return null;
  const text = String(value).trim();
  return text.length > 0 ? text : null;
}

function coerceRecord(value: unknown): Record<string, unknown> {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return {};
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

function roleDisplayLabel(role: NormalizedRole): string {
  if (role === "super_admin") return "Super Admin";
  if (role === "admin") return "Admin";
  if (role === "office_admin") return "Office Admin";
  if (role === "moderator") return "Moderator";
  return "Resident";
}

function roleRequiresOffice(role: NormalizedRole): boolean {
  // Only office-scoped staff roles must carry office metadata.
  return role === "office_admin" || role === "moderator";
}

function isMunicipalAdminRole(role: NormalizedRole): boolean {
  return role === "admin" || role === "super_admin";
}

function isStaffRole(role: NormalizedRole): boolean {
  return role === "moderator" || role === "office_admin" || role === "admin" || role === "super_admin";
}

function canAssignReportsRole(role: NormalizedRole): boolean {
  return role === "office_admin" || role === "admin" || role === "super_admin";
}

function reportTouchesOfficeId(
  row: Record<string, unknown>,
  officeId: string | null
): boolean {
  if (!officeId) return false;
  return [
    coerceString(row.officeId),
    coerceString(row.assignedOfficeId),
    coerceString(row.currentOfficeId),
  ].some((value) => value != null && value === officeId);
}

function canClaimReportInActorScope(
  actor: StaffContext,
  row: Record<string, unknown>
): boolean {
  if (actor.role === "super_admin" || actor.role === "admin") {
    return true;
  }

  if (actor.role === "moderator") {
    // Moderators can only claim to themselves from their office queue. Once
    // claimed, later status updates still require assignedToUid == actor.uid.
    return reportTouchesOfficeId(row, actor.officeId);
  }

  if (coerceString(row.assignedToUid) === actor.uid) return true;
  if (coerceString(row.createdByUid) === actor.uid) return true;
  return reportTouchesOfficeId(row, actor.officeId);
}

const REPORT_STATUS_TRANSITIONS: Record<string, string[]> = {
  submitted: ["acknowledged", "in_review", "assigned", "rejected"],
  acknowledged: ["in_review", "assigned", "rejected"],
  in_review: ["assigned", "rejected"],
  assigned: ["in_progress", "resolved", "rejected", "in_review"],
  in_progress: ["resolved", "rejected", "in_review"],
  resolved: ["closed", "in_progress"],
  closed: [],
  rejected: [],
};

function canTransitionReportStatus(
  previousStatus: string,
  nextStatus: string
): boolean {
  if (previousStatus === nextStatus) {
    return true;
  }
  const allowed = REPORT_STATUS_TRANSITIONS[previousStatus] ?? [];
  return allowed.includes(nextStatus);
}

function parseEpochMs(value: unknown): number {
  if (!value) return 0;
  if (value instanceof admin.firestore.Timestamp) {
    return value.toDate().getTime();
  }
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? 0 : value.getTime();
  }
  if (typeof value === "string") {
    const time = Date.parse(value);
    return Number.isNaN(time) ? 0 : time;
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  return 0;
}

function toIsoString(value: unknown): string | null {
  if (!value) return null;
  if (value instanceof admin.firestore.Timestamp) {
    return value.toDate().toISOString();
  }
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value.toISOString();
  }
  const parsed = new Date(String(value));
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString();
}

type FeedbackEmailTemplateKey =
  | "submitted"
  | "acknowledged"
  | "in_review"
  | "assigned"
  | "in_progress"
  | "resolved"
  | "closed"
  | "rejected";

type FeedbackEmailPayload = {
  residentName: string;
  residentEmail: string;
  ticketNumber: string;
  subject: string;
  category: string;
  status: FeedbackEmailTemplateKey;
  submittedAt: string;
  updatedAt: string;
  trackingUrl: string;
  assignedOffice: string | null;
  note: string | null;
};

let feedbackMailerTransport: nodemailer.Transporter | null = null;
let feedbackMailerCacheKey = "";
let feedbackMailerMissingConfigLogged = false;

function titleCaseWords(value: string): string {
  return value.replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function feedbackStatusLabel(status: string): string {
  return titleCaseWords(prettyStatus(status));
}

function formatPortalDateTime(value: unknown, fallback = "Not available"): string {
  const timestamp = parseEpochMs(value);
  if (!timestamp) return fallback;
  return new Date(timestamp).toLocaleString("en-PH", {
    timeZone: "Asia/Manila",
    dateStyle: "long",
    timeStyle: "short",
  });
}

function buildFeedbackTrackingUrl(ticketNumber: string): string {
  return `${PORTAL_PUBLIC_BASE_URL}/track-feedback?ticket=${encodeURIComponent(ticketNumber)}`;
}

function normalizeFeedbackEmailNote(note: unknown): string | null {
  const text = coerceString(note);
  if (!text) return null;
  return text
    .replace(/\r\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function buildFeedbackEmailFooter(trackingUrl: string): string[] {
  return [
    "This is an automated message from the Municipality of Daet Portal.",
    "",
    "Track your feedback here:",
    trackingUrl,
    "",
    "If your concern is an emergency, do not use the feedback channel. Please contact the proper emergency hotline immediately.",
    "",
    `Temporary notification sender: ${FEEDBACK_EMAIL_SENDER}`,
  ];
}

function buildFeedbackEmailMessage(payload: FeedbackEmailPayload): {subject: string; text: string} {
  const residentName = payload.residentName || "Resident";
  const note = normalizeFeedbackEmailNote(payload.note);
  const assignedOffice = payload.assignedOffice ? `Assigned Office: ${payload.assignedOffice}` : null;
  const lines: string[] = [];

  switch (payload.status) {
    case "submitted":
      lines.push(
        `Hello ${residentName},`,
        "",
        "Your feedback has been received successfully by the Municipality of Daet Portal.",
        "",
        `Ticket Number: ${payload.ticketNumber}`,
        `Subject: ${payload.subject}`,
        `Category: ${payload.category}`,
        `Date Submitted: ${payload.submittedAt}`,
        "Current Status: Submitted",
        "",
        "Please keep your ticket number so you can track the progress of your feedback online.",
        "",
        payload.trackingUrl,
        "",
        "Your feedback will be reviewed by the proper office. You will receive another email whenever the status of your ticket changes.",
      );
      return {
        subject: `Feedback Received: ${payload.ticketNumber}`,
        text: [...lines, "", ...buildFeedbackEmailFooter(payload.trackingUrl)].join("\n"),
      };
    case "acknowledged":
      lines.push(
        `Hello ${residentName},`,
        "",
        "Your feedback has been acknowledged by the Municipality of Daet.",
        "",
        `Ticket Number: ${payload.ticketNumber}`,
        `Subject: ${payload.subject}`,
        "Updated Status: Acknowledged",
        `Updated At: ${payload.updatedAt}`,
        "",
        "Your concern is now part of the active handling queue and will be reviewed by the responsible office.",
      );
      return {
        subject: `Feedback Update: ${payload.ticketNumber} has been acknowledged`,
        text: [...lines, "", ...buildFeedbackEmailFooter(payload.trackingUrl)].join("\n"),
      };
    case "in_review":
      lines.push(
        `Hello ${residentName},`,
        "",
        "Your feedback is now under review.",
        "",
        `Ticket Number: ${payload.ticketNumber}`,
        `Subject: ${payload.subject}`,
        "Updated Status: In Review",
        `Updated At: ${payload.updatedAt}`,
        "",
        "The concerned office is currently checking the details of your submission and confirming the proper handling route.",
      );
      return {
        subject: `Feedback Update: ${payload.ticketNumber} is under review`,
        text: [...lines, "", ...buildFeedbackEmailFooter(payload.trackingUrl)].join("\n"),
      };
    case "assigned":
      lines.push(
        `Hello ${residentName},`,
        "",
        "Your feedback has been assigned for action.",
        "",
        `Ticket Number: ${payload.ticketNumber}`,
        `Subject: ${payload.subject}`,
        "Updated Status: Assigned",
        ...(assignedOffice ? [assignedOffice] : []),
        `Updated At: ${payload.updatedAt}`,
        "",
        "The responsible office has been notified and will continue handling your concern.",
      );
      return {
        subject: `Feedback Update: ${payload.ticketNumber} has been assigned`,
        text: [...lines, "", ...buildFeedbackEmailFooter(payload.trackingUrl)].join("\n"),
      };
    case "in_progress":
      lines.push(
        `Hello ${residentName},`,
        "",
        "Your feedback is now being actively handled.",
        "",
        `Ticket Number: ${payload.ticketNumber}`,
        `Subject: ${payload.subject}`,
        "Updated Status: In Progress",
        `Updated At: ${payload.updatedAt}`,
        "",
        note ?? "The responsible office is actively handling your concern.",
      );
      return {
        subject: `Feedback Update: ${payload.ticketNumber} is now in progress`,
        text: [...lines, "", ...buildFeedbackEmailFooter(payload.trackingUrl)].join("\n"),
      };
    case "resolved":
      lines.push(
        `Hello ${residentName},`,
        "",
        "Your feedback has been marked as resolved.",
        "",
        `Ticket Number: ${payload.ticketNumber}`,
        `Subject: ${payload.subject}`,
        "Updated Status: Resolved",
        `Updated At: ${payload.updatedAt}`,
        "",
        "Resolution Summary:",
        note ?? "The responsible office marked your feedback as resolved.",
      );
      return {
        subject: `Feedback Update: ${payload.ticketNumber} has been resolved`,
        text: [...lines, "", ...buildFeedbackEmailFooter(payload.trackingUrl)].join("\n"),
      };
    case "closed":
      lines.push(
        `Hello ${residentName},`,
        "",
        "Your feedback record is now closed.",
        "",
        `Ticket Number: ${payload.ticketNumber}`,
        `Subject: ${payload.subject}`,
        "Updated Status: Closed",
        `Updated At: ${payload.updatedAt}`,
        "",
        note ??
          "If you need to review the final status of this concern, you may still check the tracking page using your ticket number.",
      );
      return {
        subject: `Feedback Update: ${payload.ticketNumber} is now closed`,
        text: [...lines, "", ...buildFeedbackEmailFooter(payload.trackingUrl)].join("\n"),
      };
    case "rejected":
      lines.push(
        `Hello ${residentName},`,
        "",
        "Your feedback could not be accepted for processing.",
        "",
        `Ticket Number: ${payload.ticketNumber}`,
        `Subject: ${payload.subject}`,
        "Updated Status: Rejected",
        `Updated At: ${payload.updatedAt}`,
        "",
        "Reason:",
        note ?? "The submission could not be accepted for processing.",
        "",
        "If this concern was sent through the wrong channel, please use the appropriate municipal service or reporting page.",
      );
      return {
        subject: `Feedback Update: ${payload.ticketNumber} was not accepted`,
        text: [...lines, "", ...buildFeedbackEmailFooter(payload.trackingUrl)].join("\n"),
      };
    default:
      lines.push(
        `Hello ${residentName},`,
        "",
        "Your feedback has a new update.",
        "",
        `Ticket Number: ${payload.ticketNumber}`,
        `Subject: ${payload.subject}`,
        `Updated Status: ${feedbackStatusLabel(payload.status)}`,
        `Updated At: ${payload.updatedAt}`,
      );
      return {
        subject: `Feedback Update: ${payload.ticketNumber} is now ${feedbackStatusLabel(payload.status)}`,
        text: [...lines, "", ...buildFeedbackEmailFooter(payload.trackingUrl)].join("\n"),
      };
  }
}

function getFeedbackMailerTransport(): nodemailer.Transporter | null {
  const appPassword = coerceString(FEEDBACK_EMAIL_APP_PASSWORD.value());
  if (!FEEDBACK_EMAIL_SENDER || !appPassword) {
    if (!feedbackMailerMissingConfigLogged) {
      functions.logger.warn("Feedback email delivery is disabled because Gmail credentials are not configured.", {
        hasSender: Boolean(FEEDBACK_EMAIL_SENDER),
        hasAppPassword: Boolean(appPassword),
      });
      feedbackMailerMissingConfigLogged = true;
    }
    return null;
  }

  const cacheKey = `${FEEDBACK_EMAIL_SENDER}:${appPassword}`;
  if (feedbackMailerTransport && feedbackMailerCacheKey === cacheKey) {
    return feedbackMailerTransport;
  }

  feedbackMailerTransport = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: FEEDBACK_EMAIL_SENDER,
      pass: appPassword,
    },
  });
  feedbackMailerCacheKey = cacheKey;
  feedbackMailerMissingConfigLogged = false;
  return feedbackMailerTransport;
}

async function sendFeedbackEmailNotification(
  row: Record<string, unknown>,
  options: {
    status?: string | null;
    note?: string | null;
    updatedAt?: unknown;
  } = {}
): Promise<void> {
  if (getPublicReportLane(row) !== "feedback") {
    return;
  }

  const residentEmail =
    coerceString((row.reporter as Record<string, unknown> | undefined)?.email) ??
    coerceString(row.email) ??
    coerceString(row.createdByEmail);
  if (!residentEmail) {
    return;
  }

  const transport = getFeedbackMailerTransport();
  if (!transport) {
    return;
  }

  const normalizedStatus = normalizeReportStatusInput(options.status ?? row.status ?? "submitted");
  const ticketNumber =
    coerceString(row.trackingNumber) ??
    coerceString(row.ticketNumber) ??
    coerceString(row.referenceNo);
  if (!ticketNumber) {
    return;
  }

  const subject = coerceString(row.subject) ?? coerceString(row.title) ?? "Citizen Feedback";
  const category = coerceString(row.category) ?? "General Feedback";
  const residentName =
    coerceString((row.reporter as Record<string, unknown> | undefined)?.name) ??
    coerceString(row.createdByName) ??
    coerceString(row.name) ??
    "Resident";
  const assignedOffice =
    coerceString(row.assignedOfficeName) ??
    coerceString(row.officeName) ??
    coerceString(row.assignedToName);
  const submittedAt = formatPortalDateTime(row.createdAt);
  const updatedAt = formatPortalDateTime(options.updatedAt ?? row.updatedAt ?? row.lastActionAt ?? row.createdAt);
  const note = normalizeFeedbackEmailNote(options.note);
  const emailMessage = buildFeedbackEmailMessage({
    residentName,
    residentEmail,
    ticketNumber,
    subject,
    category,
    status: normalizedStatus as FeedbackEmailTemplateKey,
    submittedAt,
    updatedAt,
    trackingUrl: buildFeedbackTrackingUrl(ticketNumber),
    assignedOffice,
    note,
  });

  try {
    await transport.sendMail({
      from: {
        name: FEEDBACK_EMAIL_SENDER_NAME,
        address: FEEDBACK_EMAIL_SENDER,
      },
      to: residentEmail,
      replyTo: FEEDBACK_EMAIL_SENDER,
      subject: emailMessage.subject,
      text: emailMessage.text,
    });
  } catch (error) {
    functions.logger.warn("Feedback email delivery failed.", {
      reportId: coerceString(row.id) ?? null,
      trackingNumber: ticketNumber,
      status: normalizedStatus,
      residentEmail,
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

function serializeReportRow(
  id: string,
  row: FirebaseFirestore.DocumentData
): Record<string, unknown> {
  const data = row ?? {};
  const latestTimelineEvent =
    data.latestTimelineEvent && typeof data.latestTimelineEvent === "object"
      ? {
          ...(data.latestTimelineEvent as Record<string, unknown>),
          createdAt: toIsoString((data.latestTimelineEvent as Record<string, unknown>).createdAt),
        }
      : null;
  return {
    id,
    // Report list responses intentionally include the stored fields so the admin queue
    // and the active map can reuse the same payload without another fetch layer.
    ...data,
    latestTimelineEvent,
    createdAt: toIsoString(data.createdAt),
    updatedAt: toIsoString(data.updatedAt),
    lastActionAt: toIsoString(data.lastActionAt),
  };
}

function isAuthUserNotFound(error: unknown): boolean {
  const code = String((error as { code?: unknown })?.code ?? "");
  return code.includes("auth/user-not-found");
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

function statusRequiresResidentNote(status: string): boolean {
  return status === "resolved" || status === "rejected";
}

function buildReportWorkflowSummary(
  options: {
    beforeStatus: string;
    afterStatus: string;
    beforeAssignedUid?: string | null;
    afterAssignedUid?: string | null;
    assignedToName?: string | null;
    assigneeRemovedMessage?: string;
  }
): string {
  const parts: string[] = [];
  const assignedChanged =
    (options.beforeAssignedUid ?? null) !== (options.afterAssignedUid ?? null);
  const statusChanged = options.beforeStatus !== options.afterStatus;

  if (assignedChanged) {
    if (options.afterAssignedUid) {
      parts.push(`Assigned to ${options.assignedToName ?? "staff"}.`);
    } else {
      parts.push(options.assigneeRemovedMessage || "Removed assignee and returned to queue.");
    }
  }

  if (statusChanged) {
    parts.push(
      `Status changed from ${prettyStatus(options.beforeStatus)} to ${prettyStatus(options.afterStatus)}.`
    );
  }

  return parts.join(" ").trim();
}

async function addHistory(
  reportId: string,
  entry: Record<string, unknown>
): Promise<void> {
  const reportSnap = await db.collection("reports").doc(reportId).get();
  const reportRow = coerceRecord(reportSnap.data());
  const scopeMirror = {
    createdByUid: coerceString(reportRow?.createdByUid) ?? null,
    officeId: coerceString(reportRow?.officeId) ?? null,
    currentOfficeId: coerceString(reportRow?.currentOfficeId) ?? null,
    assignedOfficeId: coerceString(reportRow?.assignedOfficeId) ?? null,
    assignedToUid: coerceString(reportRow?.assignedToUid) ?? null,
  };

  await db
    .collection("reports")
    .doc(reportId)
    .collection("history")
    .add({
      ...entry,
      ...scopeMirror,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
}

async function addReportTimeline(
  reportId: string,
  entry: Record<string, unknown>
): Promise<{
  id: string;
  type: string;
  actorRole: string;
  notes: string;
  createdAt: string;
}> {
  // Report timeline is append-only so each workflow movement stays auditable
  // even if summary fields on the parent report document change later.
  const reportRef = db.collection("reports").doc(reportId);
  const timelineRef = reportRef.collection("timeline").doc();
  const reportSnapshot = await reportRef.get();
  const reportRow = coerceRecord(reportSnapshot.data());
  const createdAt = admin.firestore.Timestamp.now();
  const actorUid = coerceString(entry.actorUid) ?? coerceString(entry.byUid);
  const actorRole = coerceString(entry.actorRole) ?? coerceString(entry.byRole);
  const actorName = coerceString(entry.actorName) ?? coerceString(entry.byName);
  const type = coerceString(entry.type) ?? "UPDATE";
  const notes = coerceString(entry.notes);
  const fromStatus = coerceString(entry.fromStatus);
  const toStatus = coerceString(entry.toStatus);
  const scopeMirror = {
    createdByUid: coerceString(reportRow?.createdByUid) ?? null,
    officeId: coerceString(reportRow?.officeId) ?? null,
    currentOfficeId: coerceString(reportRow?.currentOfficeId) ?? null,
    assignedOfficeId: coerceString(reportRow?.assignedOfficeId) ?? null,
    assignedToUid: coerceString(reportRow?.assignedToUid) ?? null,
  };

  const batch = db.batch();
  batch.set(timelineRef, {
    ...entry,
    ...scopeMirror,
    createdAt,
  });
  batch.set(
    reportRef,
    {
      latestTimelineEvent: {
        id: timelineRef.id,
        type,
        notes: notes ?? null,
        actorUid: actorUid ?? null,
        actorRole: actorRole ?? null,
        actorName: actorName ?? null,
        fromStatus: fromStatus ?? null,
        toStatus: toStatus ?? null,
        createdAt,
      },
      lastActionAt: createdAt,
      ...(actorUid ? {lastActionByUid: actorUid} : {}),
      ...(actorRole ? {lastActionByRole: actorRole} : {}),
      ...(actorName ? {lastActionByName: actorName} : {}),
    },
    {merge: true}
  );
  await batch.commit();

  return {
    id: timelineRef.id,
    type,
    actorRole: actorRole ?? "staff",
    notes: notes ?? "",
    createdAt: createdAt.toDate().toISOString(),
  };
}

async function addAuditLog(entry: Record<string, unknown>): Promise<void> {
  await db.collection("audit_logs").add({
    ...entry,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  });
}

async function listActiveUserIdsByQuery(
  queryRef: FirebaseFirestore.Query
): Promise<string[]> {
  const snapshot = await queryRef.get();
  return snapshot.docs
    .filter((doc) => coerceBool((doc.data() ?? {}).isActive, true))
    .map((doc) => doc.id);
}

async function listReportEscalationRecipients(
  row: Record<string, unknown>
): Promise<string[]> {
  const officeId =
    coerceString(row.currentOfficeId) ??
    coerceString(row.officeId) ??
    coerceString(row.assignedOfficeId);
  const recipients = new Set<string>();

  const adminUids = await listActiveUserIdsByQuery(
    db.collection("users").where("role", "in", ["admin", "super_admin"]).limit(200)
  );
  adminUids.forEach((uid) => recipients.add(uid));

  if (officeId) {
    const officeAdminUids = await listActiveUserIdsByQuery(
      db
        .collection("users")
        .where("role", "==", "office_admin")
        .where("officeId", "==", officeId)
        .limit(200)
    );
    officeAdminUids.forEach((uid) => recipients.add(uid));
  }

  return Array.from(recipients);
}

async function recordReportEscalation(
  reportId: string,
  row: Record<string, unknown>,
  stage: "emergency" | "acknowledge" | "verify" | "assign",
  notes: string
): Promise<void> {
  const recipients = await listReportEscalationRecipients(row);
  const title =
    coerceString(row.title) ??
    coerceString(row.subject) ??
    coerceString(row.concern) ??
    "Report";
  let status = "submitted";
  try {
    status = normalizeReportStatusInput(row.status ?? "submitted");
  } catch {
    status = "submitted";
  }

  await addReportTimeline(reportId, {
    type: "ESCALATED",
    actorUid: null,
    actorRole: "system",
    notes,
    fromStatus: status,
    toStatus: status,
  });

  await db.collection("reports").doc(reportId).set(
    {
      slaEscalation: {
        stage,
        notes,
        notifiedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
    },
    {merge: true}
  );

  await notifyUsers(recipients, {
    title: stage === "emergency" ? "Emergency escalation" : "Report SLA escalation",
    body: `${title} - ${notes}`,
    type: "report_escalated",
    reportId,
    status,
    assignedToUid: coerceString(row.assignedToUid) ?? "",
  });
}

function defaultSystemFeatureFlags(enabled: boolean): SystemFeatureFlags {
  return SYSTEM_SETTINGS_FEATURE_KEYS.reduce((acc, key) => {
    acc[key] = enabled;
    return acc;
  }, {} as SystemFeatureFlags);
}

function normalizeSystemFeatureFlags(
  raw: unknown,
  fallbackEnabled: boolean
): SystemFeatureFlags {
  const base = defaultSystemFeatureFlags(fallbackEnabled);
  if (!raw || typeof raw !== "object") {
    return base;
  }

  const source = raw as Record<string, unknown>;
  for (const key of SYSTEM_SETTINGS_FEATURE_KEYS) {
    if (key in source) {
      base[key] = Boolean(source[key]);
    }
  }

  return base;
}

type SystemSettingsShape = {
  maintenance: {
    enabled: boolean;
    message: string;
  };
  readOnly: boolean;
  features: SystemFeatureFlags;
};

function normalizeStoredSystemSettings(
  raw: unknown,
  fallbackEnabled: boolean
): SystemSettingsShape {
  const source = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  const maintenanceRaw =
    source.maintenance && typeof source.maintenance === "object"
      ? (source.maintenance as Record<string, unknown>)
      : {};
  return {
    maintenance: {
      enabled: Boolean(maintenanceRaw.enabled),
      message: String(maintenanceRaw.message ?? ""),
    },
    readOnly: Boolean(source.readOnly),
    features: normalizeSystemFeatureFlags(source.features, fallbackEnabled),
  };
}

function systemSettingsMergePatch(
  current: SystemSettingsShape,
  rawPatch: unknown
): SystemSettingsShape {
  const patch = rawPatch && typeof rawPatch === "object"
    ? (rawPatch as Record<string, unknown>)
    : {};
  const maintenancePatch =
    patch.maintenance && typeof patch.maintenance === "object"
      ? (patch.maintenance as Record<string, unknown>)
      : {};
  const featuresPatch =
    patch.features && typeof patch.features === "object"
      ? (patch.features as Record<string, unknown>)
      : {};

  const nextFeatures = {
    ...current.features,
  };
  for (const key of SYSTEM_SETTINGS_FEATURE_KEYS) {
    if (key in featuresPatch) {
      nextFeatures[key] = Boolean(featuresPatch[key]);
    }
  }

  return {
    maintenance: {
      enabled:
        typeof maintenancePatch.enabled === "boolean"
          ? maintenancePatch.enabled
          : current.maintenance.enabled,
      message:
        typeof maintenancePatch.message === "string"
          ? maintenancePatch.message.trim()
          : current.maintenance.message,
    },
    readOnly: typeof patch.readOnly === "boolean" ? patch.readOnly : current.readOnly,
    features: nextFeatures,
  };
}

async function addDualSettingsAuditLog(entry: Record<string, unknown>): Promise<void> {
  const base = {
    ...entry,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  };

  await Promise.all([
    db.collection("auditLogs").add(base),
    db.collection("audit_logs").add(base),
  ]);
}

async function getEffectiveSystemSettings(): Promise<SystemSettingsShape> {
  const snapshot = await db.collection("system").doc("settings").get();
  if (!snapshot.exists) {
    return normalizeStoredSystemSettings(null, true);
  }
  return normalizeStoredSystemSettings(snapshot.data(), true);
}

async function requireFeatureEnabled(featureKey: SystemFeatureKey): Promise<SystemSettingsShape> {
  const settings = await getEffectiveSystemSettings();
  if (!settings.features[featureKey]) {
    throw new functions.https.HttpsError(
      "permission-denied",
      `${featureKey} feature is currently disabled by Command Center.`
    );
  }
  return settings;
}

async function requireFeatureWritable(featureKey: SystemFeatureKey): Promise<SystemSettingsShape> {
  const settings = await requireFeatureEnabled(featureKey);
  if (settings.readOnly) {
    throw new functions.https.HttpsError(
      "failed-precondition",
      "System is in read-only mode. Feature write operations are temporarily blocked."
    );
  }
  return settings;
}

async function requireSystemWritable(): Promise<SystemSettingsShape> {
  const settings = await getEffectiveSystemSettings();
  if (settings.readOnly) {
    throw new functions.https.HttpsError(
      "failed-precondition",
      "System is in read-only mode. Write operations are temporarily blocked."
    );
  }
  return settings;
}

type LifecycleStatus = "draft" | "published" | "archived";
const LIFECYCLE_STATUSES: LifecycleStatus[] = ["draft", "published", "archived"];
const PUBLIC_DOC_TYPES = ["ordinance", "resolution", "executive_order", "public_hearing"] as const;
type PublicDocType = typeof PUBLIC_DOC_TYPES[number];
const PUBLIC_DOC_FIXED_OFFICE_BY_TYPE: Record<Exclude<PublicDocType, "public_hearing">, string> = {
  ordinance: "SANGGUNIANG_BAYAN",
  resolution: "SANGGUNIANG_BAYAN",
  executive_order: "OFFICE_OF_THE_MAYOR",
};
const DEFAULT_PUBLIC_HEARING_OFFICES = ["SANGGUNIANG_BAYAN", "OFFICE_OF_THE_MAYOR"];

function isContentDraftRole(role: NormalizedRole): boolean {
  return role === "moderator" || role === "office_admin" || role === "admin" || role === "super_admin";
}

function isContentPublishRole(role: NormalizedRole): boolean {
  return role === "admin" || role === "super_admin";
}

function isJobsManageRole(role: NormalizedRole): boolean {
  return role === "admin" || role === "super_admin";
}

function isDirectoryManageRole(role: NormalizedRole): boolean {
  return role === "admin" || role === "super_admin";
}

function isEmergencyHotlinesManageRole(role: NormalizedRole): boolean {
  return role === "super_admin";
}

function normalizeLifecycleStatus(raw: unknown, fallback: LifecycleStatus = "draft"): LifecycleStatus {
  const value = String(raw ?? "")
    .trim()
    .toLowerCase();
  if (LIFECYCLE_STATUSES.includes(value as LifecycleStatus)) {
    return value as LifecycleStatus;
  }
  return fallback;
}

function normalizeKeywordTokens(...values: unknown[]): string[] {
  const unique = new Set<string>();
  values.forEach((value) => {
    String(value ?? "")
      .toLowerCase()
      .split(/[^a-z0-9]+/g)
      .map((token) => token.trim())
      .filter((token) => token.length >= 2)
      .forEach((token) => unique.add(token));
  });
  return Array.from(unique).slice(0, 64);
}

function parseStringList(
  raw: unknown,
  {maxItems = 20, maxLen = 80}: {maxItems?: number; maxLen?: number} = {}
): string[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  const out: string[] = [];
  for (const item of raw) {
    const value = coerceString(item);
    if (!value) continue;
    if (value.length > maxLen) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        `List item length must be ${maxLen} characters or fewer.`
      );
    }
    out.push(value);
    if (out.length >= maxItems) break;
  }
  return out;
}

function parseDateField(raw: unknown): admin.firestore.Timestamp | null {
  if (!raw) return null;
  const date = new Date(String(raw));
  if (Number.isNaN(date.getTime())) return null;
  return admin.firestore.Timestamp.fromDate(date);
}

function assertOptionalStringLength(value: string | null, fieldName: string, maxLen: number): string | null {
  const normalized = coerceString(value);
  if (!normalized) {
    return null;
  }
  if (normalized.length > maxLen) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      `${fieldName} must be ${maxLen} characters or fewer.`
    );
  }
  return normalized;
}

function normalizeSortOrder(raw: unknown, fallback = 0): number {
  const value = Number(raw);
  if (!Number.isFinite(value)) {
    return fallback;
  }
  return Math.max(-9999, Math.min(9999, Math.trunc(value)));
}

function parsePhoneList(
  raw: unknown,
  {maxItems = 8, maxLen = 80}: {maxItems?: number; maxLen?: number} = {}
): string[] {
  const source = Array.isArray(raw)
    ? raw
    : (coerceString(raw)?.split(/[\n\r;|]+/g) ?? []);
  const out: string[] = [];
  for (const item of source) {
    const value = coerceString(item);
    if (!value) continue;
    if (value.length > maxLen) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        `Contact number must be ${maxLen} characters or fewer.`
      );
    }
    out.push(value);
    if (out.length >= maxItems) break;
  }
  return out;
}

function buildDirectorySearchKeywords(
  officeName: string,
  contactName: string,
  position: string,
  phone: string,
  email: string | null,
  facebook: string | null,
  address: string | null
): string[] {
  return normalizeKeywordTokens(
    officeName,
    contactName,
    position,
    phone,
    email ?? "",
    facebook ?? "",
    address ?? ""
  );
}

function buildEmergencyHotlineSearchKeywords(
  label: string,
  group: string,
  description: string | null,
  numbers: string[],
  notes: string | null
): string[] {
  return normalizeKeywordTokens(
    label,
    group,
    description ?? "",
    numbers.join(" "),
    notes ?? ""
  );
}

function isActorOfficeScoped(actor: StaffContext): boolean {
  return actor.role === "moderator" || actor.role === "office_admin";
}

function ensureActorOfficeScope(actor: StaffContext, targetOfficeId: string | null) {
  if (!isActorOfficeScoped(actor)) return;
  if (!actor.officeId) {
    throw new functions.https.HttpsError("failed-precondition", "Office-scoped account has no office assignment.");
  }
  if (targetOfficeId && targetOfficeId !== actor.officeId) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Office-scoped staff can only modify records for their assigned office."
    );
  }
}

async function getAllowedPublicHearingOffices(): Promise<string[]> {
  const defaults = new Set(DEFAULT_PUBLIC_HEARING_OFFICES);
  const configSnap = await db.collection("system_config").doc("rbac").get();
  if (configSnap.exists) {
    const values = configSnap.data()?.publicHearingOffices;
    if (Array.isArray(values)) {
      values.forEach((entry) => {
        const officeId = coerceString(entry);
        if (officeId) defaults.add(officeId);
      });
    }
  }
  return Array.from(defaults);
}

async function resolvePublicDocOfficeId(docType: PublicDocType, requestedOfficeId: string | null): Promise<string> {
  if (docType === "public_hearing") {
    const officeId = requestedOfficeId ?? DEFAULT_PUBLIC_HEARING_OFFICES[0];
    const allowed = await getAllowedPublicHearingOffices();
    if (!allowed.includes(officeId)) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "public_hearing documents must target an allowed office."
      );
    }
    return officeId;
  }

  return PUBLIC_DOC_FIXED_OFFICE_BY_TYPE[docType];
}

function assertStringLength(value: string | null, fieldName: string, minLen: number, maxLen: number): string {
  const normalized = coerceString(value);
  if (!normalized || normalized.length < minLen || normalized.length > maxLen) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      `${fieldName} must be between ${minLen} and ${maxLen} characters.`
    );
  }
  return normalized;
}

type PublicReportLane = "issue" | "emergency" | "feedback";
type PublicReportKind = "report" | "feedback";
type PublicReportServiceKey = "public_issue" | "public_emergency" | "citizen_feedback";
type PublicReportStatus =
  "submitted" |
  "acknowledged" |
  "in_review" |
  "assigned" |
  "in_progress" |
  "resolved" |
  "closed" |
  "rejected";
type PublicReportPriority = "low" | "medium" | "high" | "critical";
type EmergencyTypeKey =
  "road_accident" |
  "medical" |
  "fire" |
  "crime" |
  "other";

type PublicReportGeo = {
  lat: number | null;
  lng: number | null;
  geohash?: string;
};

type PublicReportAttachment = {
  url: string;
  contentType: string;
  name: string;
  path: string;
};

type PublicReportWriteInput = {
  reportId?: string;
  lane: PublicReportLane;
  reportKind: PublicReportKind;
  serviceKey: PublicReportServiceKey;
  title: string;
  subject: string;
  category: string;
  emergencyType: string | null;
  barangay: string;
  landmark: string;
  description: string;
  message: string;
  reporterName: string;
  reporterContact: string;
  reporterEmail?: string | null;
  preferredDepartment?: string | null;
  source: "website" | "app";
  geo: PublicReportGeo;
  officeId: string;
  officeName: string;
  priority: PublicReportPriority;
  trackingNumber: string;
  attachments: PublicReportAttachment[];
  duplicateOf: string | null;
  duplicateWarning: string | null;
  sla: {
    acknowledgeBy: Date;
    verifyBy: Date;
    assignBy: Date;
  };
};

const PUBLIC_REPORT_DEFAULT_ALLOWED_ORIGINS = [
  "http://localhost:5173",
  "http://127.0.0.1:5173",
  "http://localhost:4173",
  "http://127.0.0.1:4173",
] as const;

const EMERGENCY_ROUTING_RULES: Record<EmergencyTypeKey, {officeId: string; officeName: string}> = {
  // TODO: Replace these defaults with the actual LGU office routing table when stable office IDs are finalized.
  road_accident: {officeId: "MDRRMO", officeName: "Municipal Disaster Risk Reduction and Management Office"},
  medical: {officeId: "MDRRMO", officeName: "Municipal Disaster Risk Reduction and Management Office"},
  fire: {officeId: "MDRRMO", officeName: "Municipal Disaster Risk Reduction and Management Office"},
  crime: {officeId: "MDRRMO", officeName: "Municipal Disaster Risk Reduction and Management Office"},
  other: {officeId: "MDRRMO", officeName: "Municipal Disaster Risk Reduction and Management Office"},
};
const FEEDBACK_ROUTING_RULE = {
  officeId: "OFFICE_OF_THE_MAYOR",
  officeName: "Office of the Mayor",
};

/*
 * CORS is fail-closed outside emulator by default.
 * - Emulator/local integration can run with open mode for faster iteration.
 * - Deployed environments should provide explicit allowlists.
 * Override via CORS_MODE=open|strict when needed for controlled rollouts.
 */
function strictCorsEnabled(): boolean {
  if (CORS_MODE === "open") return false;
  if (CORS_MODE === "strict") return true;
  return !FUNCTIONS_EMULATOR_ENABLED;
}

function allowOriginWithoutAllowlist(): boolean {
  return !strictCorsEnabled();
}

function getPublicReportAllowedOrigins(): string[] {
  if (PUBLIC_REPORT_ALLOWED_ORIGINS.length > 0) {
    return PUBLIC_REPORT_ALLOWED_ORIGINS;
  }
  return Array.from(PUBLIC_REPORT_DEFAULT_ALLOWED_ORIGINS);
}

function isLoopbackOrigin(origin: string): boolean {
  try {
    const parsed = new URL(origin);
    return ["localhost", "127.0.0.1", "::1", "[::1]"].includes(parsed.hostname);
  } catch {
    return false;
  }
}

function isAllowedPublicReportCorsOrigin(origin: string): boolean {
  if (isLoopbackOrigin(origin)) return true;
  const allowedOrigins = getPublicReportAllowedOrigins();
  if (allowedOrigins.length === 0) return allowOriginWithoutAllowlist();
  return allowedOrigins.includes(origin);
}

function applyJsonEndpointSecurityHeaders(
  res: functions.Response<unknown>
): void {
  // JSON API responses should never be cached by browsers/proxies.
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
  res.set("Pragma", "no-cache");
  // Harden response parsing and referrer leakage.
  res.set("X-Content-Type-Options", "nosniff");
  res.set("Referrer-Policy", "no-referrer");
}

function applyPublicReportCors(
  req: functions.https.Request,
  res: functions.Response<unknown>
): boolean {
  applyJsonEndpointSecurityHeaders(res);
  const origin = String(req.headers.origin ?? "").trim();
  if (!origin) {
    // Non-browser clients (for example future mobile apps) may omit Origin.
    // Only emit wildcard in non-strict CORS mode.
    if (allowOriginWithoutAllowlist()) {
      res.set("Access-Control-Allow-Origin", "*");
    }
  } else if (isAllowedPublicReportCorsOrigin(origin)) {
    res.set("Access-Control-Allow-Origin", origin);
    res.set("Vary", "Origin");
  } else {
    return false;
  }
  res.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.set("Access-Control-Allow-Methods", "POST, OPTIONS");
  // Explicitly keep credentialed browser cookies off public endpoints.
  res.set("Access-Control-Allow-Credentials", "false");
  res.set("Access-Control-Max-Age", "600");
  return true;
}

function normalizePublicTicketNumber(payload: Record<string, unknown>): string {
  const rawTicket =
    payload.ticketNumber ??
    payload.ticket_number ??
    payload.trackingNumber ??
    payload.trackingNo ??
    payload.reference ??
    payload.referenceNo;
  const trackingNo = normalizeTrackingNo(rawTicket);
  if (!trackingNo) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "ticketNumber/trackingNumber is required."
    );
  }
  if (!TRACKING_NO_REGEX.test(trackingNo)) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Invalid ticket number format."
    );
  }
  return trackingNo;
}

async function enforcePublicReportLookupRateLimit(
  req: functions.https.Request,
  ticketNumber: string
): Promise<void> {
  const ipHash = sha256(getRequestIp(req)).substring(0, 32);
  const ticketHash = sha256(ticketNumber).substring(0, 16);
  const docId = `lookup_${ticketHash}_${ipHash}`;
  const rateRef = db.collection("public_report_lookup_rate_limits").doc(docId);
  const windowStart = Date.now() - PUBLIC_REPORT_LOOKUP_RATE_LIMIT_WINDOW_MS;

  await db.runTransaction(async (tx) => {
    const snap = await tx.get(rateRef);
    const data = snap.exists ? snap.data() ?? {} : {};
    const lastAttemptMs = parseEpochMs(data.lastAttemptAt);
    const currentCount =
      lastAttemptMs >= windowStart ?
        Math.max(0, Number(data.count ?? 0)) :
        0;

    if (currentCount >= PUBLIC_REPORT_LOOKUP_RATE_LIMIT_MAX_REQUESTS) {
      throw new functions.https.HttpsError(
        "resource-exhausted",
        "Too many tracking lookups from this connection. Please wait a few minutes before trying again."
      );
    }

    tx.set(rateRef, {
      ticketNumber,
      count: currentCount + 1,
      ipHash,
      lastAttemptAt: admin.firestore.FieldValue.serverTimestamp(),
      expiresAt: admin.firestore.Timestamp.fromMillis(
        Date.now() + PUBLIC_REPORT_LOOKUP_RATE_LIMIT_WINDOW_MS
      ),
    }, {merge: true});
  });
}

function sanitizePublicReportAttachment(
  attachment: Record<string, unknown>
): Record<string, unknown> {
  const name =
    coerceString(attachment.name) ??
    coerceString(attachment.fileName) ??
    coerceString(attachment.file_name) ??
    "Attachment";
  const path =
    coerceString(attachment.path) ??
    coerceString(attachment.filePath) ??
    coerceString(attachment.file_path) ??
    "";
  const url = coerceString(attachment.url) ?? "";
  const contentType =
    coerceString(attachment.contentType) ??
    coerceString(attachment.content_type) ??
    "";
  return {
    id: path || name,
    url,
    path,
    file_path: path,
    content_type: contentType,
    name,
    file_name: name,
  };
}

function sanitizePublicReportTimelineEntry(
  row: Record<string, unknown>
): Record<string, unknown> {
  const action = coerceString(row.type) ?? "UPDATE";
  const timestamp = toIsoString(row.createdAt ?? row.timestamp);
  const notes =
    coerceString(row.notes) ??
    coerceString(row.message) ??
    "";
  const officeName =
    coerceString(row.officeName) ??
    coerceString(row.assignedOfficeName) ??
    coerceString(row.currentOfficeName) ??
    coerceString(row.officeId) ??
    coerceString(row.assignedOfficeId) ??
    null;
  const nextStatus = coerceString(row.toStatus) ?? coerceString(row.status) ?? action;
  return {
    id: coerceString(row.id) ?? "",
    timestamp,
    updated_at: timestamp,
    action,
    actor_role:
      coerceString(row.actorRole) ??
      coerceString(row.byRole) ??
      coerceString(row.lastActionByRole) ??
      null,
    office_name: officeName,
    notes,
    admin_response: notes,
    note_public: notes,
    assigned_to: officeName,
    assigned_office: officeName,
    from_status: coerceString(row.fromStatus),
    to_status: nextStatus,
    status: nextStatus,
    attachment_path: null,
  };
}

async function loadPublicReportTimeline(
  docRef: admin.firestore.DocumentReference,
  limitRows = 20
): Promise<Record<string, unknown>[]> {
  const timelineSnap = await docRef
    .collection("timeline")
    .orderBy("createdAt", "desc")
    .limit(Math.max(1, Math.min(50, limitRows)))
    .get();
  return timelineSnap.docs.map((item) => sanitizePublicReportTimelineEntry(item.data() ?? {}));
}

function sanitizePublicReportTicket(
  row: Record<string, unknown>
): Record<string, unknown> {
  const ticketNumber =
    coerceString(row.ticketNumber) ??
    coerceString(row.trackingNumber) ??
    coerceString(row.referenceNo) ??
    coerceString(row.reference) ??
    "";
  const subject =
    coerceString(row.subject) ??
    coerceString(row.title) ??
    "";
  const message =
    coerceString(row.message) ??
    coerceString(row.description) ??
    "";
  const assignedOfficeName =
    coerceString(row.assignedOfficeName) ??
    coerceString(row.officeName);
  const latestStatus = coerceString(row.status) ?? "submitted";
  const attachments = Array.isArray(row.attachments)
    ? row.attachments
      .map((item) => (item && typeof item === "object" ? sanitizePublicReportAttachment(item as Record<string, unknown>) : null))
      .filter((item): item is Record<string, unknown> => item != null)
    : [];

  return {
    id: ticketNumber || coerceString(row.id),
    lane: getPublicReportLane(row),
    report_kind:
      coerceString(row.reportKind) ??
      (getPublicReportLane(row) === "feedback" ? "feedback" : "report"),
    service_key:
      coerceString(row.serviceKey) ??
      (getPublicReportLane(row) === "feedback" ? "citizen_feedback" : "public_issue"),
    ticket_number: ticketNumber,
    reference: ticketNumber,
    trackingNumber: ticketNumber,
    referenceNo: ticketNumber,
    category: coerceString(row.category) ?? "",
    subject,
    message,
    latest_status: latestStatus,
    status: latestStatus,
    assigned_to: assignedOfficeName ?? "",
    assigned_office: assignedOfficeName ?? "",
    created_at: toIsoString(row.createdAt),
    updated_at: toIsoString(row.updatedAt),
    attachments,
  };
}

function getPublicReportLane(row: Record<string, unknown>): PublicReportLane {
  const lane = (coerceString(row.lane) ?? "").toLowerCase();
  const serviceKey = (coerceString(row.serviceKey) ?? "").toLowerCase();
  const reportKind = (coerceString(row.reportKind) ?? "").toLowerCase();
  if (lane === "feedback" || serviceKey === "citizen_feedback" || reportKind === "feedback") {
    return "feedback";
  }
  if (lane === "emergency" || !!coerceString(row.emergencyType)) {
    return "emergency";
  }
  return "issue";
}

function normalizeRequestedPublicReportLane(raw: unknown): PublicReportLane | null {
  const value = String(raw ?? "")
    .trim()
    .toLowerCase();
  if (value === "feedback") {
    return "feedback";
  }
  if (value === "emergency") {
    return "emergency";
  }
  if (value === "issue" || value === "report" || value === "reports") {
    return "issue";
  }
  return null;
}

function featureKeyForPublicReportLane(lane: PublicReportLane): SystemFeatureKey {
  return lane === "feedback" ? "feedback" : "reports";
}

async function requirePublicReportLaneAvailability(
  lane: PublicReportLane,
  options: {write?: boolean} = {}
): Promise<void> {
  const settingsSnap = await db.collection("system").doc("settings").get();
  const raw = settingsSnap.exists ? settingsSnap.data() ?? {} : {};
  const normalized = normalizeStoredSystemSettings(raw, true);
  const rawFeatures =
    raw.features && typeof raw.features === "object"
      ? (raw.features as Record<string, unknown>)
      : {};
  const emergencyReportsEnabled = rawFeatures.emergencyReports == null ?
    true :
    Boolean(rawFeatures.emergencyReports);
  const featureKey = featureKeyForPublicReportLane(lane);

  if (!normalized.features[featureKey]) {
    throw new functions.https.HttpsError(
      "permission-denied",
      `${featureKey} feature is currently disabled by Command Center.`
    );
  }
  if (lane === "emergency" && !emergencyReportsEnabled) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "emergencyReports feature is currently disabled by Command Center."
    );
  }
  if (options.write && normalized.readOnly) {
    throw new functions.https.HttpsError(
      "failed-precondition",
      "System is in read-only mode. Public report intake is temporarily blocked."
    );
  }
}

function publicReportHttpStatus(error: unknown): {
  code: string;
  message: string;
  statusCode: number;
} {
  const httpsError = error as functions.https.HttpsError;
  const code = String(httpsError?.code ?? "internal");
  const message = String(httpsError?.message ?? "Public report submission failed.");
  const statusCode =
    code === "invalid-argument" ? 400 :
    code === "resource-exhausted" ? 429 :
    code === "permission-denied" ? 503 :
    code === "failed-precondition" ? 503 :
    code === "not-found" ? 404 : 500;
  return {code, message, statusCode};
}

function getRequestIp(req: functions.https.Request): string {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.trim()) {
    return forwarded.split(",")[0].trim();
  }
  if (Array.isArray(forwarded) && forwarded[0]) {
    return String(forwarded[0]).split(",")[0].trim();
  }
  return String(req.ip ?? "unknown");
}

async function enforcePublicReportRateLimit(
  req: functions.https.Request,
  lane: string
): Promise<void> {
  // This is intentionally lightweight. Production should add App Check, reCAPTCHA,
  // and a stronger central limiter, but this closes the obvious abuse gap now.
  const ipHash = sha256(getRequestIp(req)).substring(0, 32);
  const docId = `${lane}_${ipHash}`;
  const rateRef = db.collection("public_report_rate_limits").doc(docId);
  const windowStart = Date.now() - PUBLIC_REPORT_RATE_LIMIT_WINDOW_MS;

  await db.runTransaction(async (tx) => {
    const snap = await tx.get(rateRef);
    const data = snap.exists ? snap.data() ?? {} : {};
    const lastAttemptMs = parseEpochMs(data.lastAttemptAt);
    const currentCount =
      lastAttemptMs >= windowStart ?
        Math.max(0, Number(data.count ?? 0)) :
        0;

    if (currentCount >= PUBLIC_REPORT_RATE_LIMIT_MAX_REQUESTS) {
      throw new functions.https.HttpsError(
        "resource-exhausted",
        "Too many submissions from this connection. Please wait a few minutes before trying again."
      );
    }

    tx.set(rateRef, {
      lane,
      count: currentCount + 1,
      ipHash,
      lastAttemptAt: admin.firestore.FieldValue.serverTimestamp(),
      expiresAt: admin.firestore.Timestamp.fromMillis(
        Date.now() + PUBLIC_REPORT_RATE_LIMIT_WINDOW_MS
      ),
    }, {merge: true});
  });
}

function requiredPublicField(value: unknown, label: string, max = 160): string {
  const text = String(value ?? "").trim();
  if (!text) {
    throw new functions.https.HttpsError("invalid-argument", `${label} is required.`);
  }
  if (text.length > max) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      `${label} must be ${max} characters or fewer.`
    );
  }
  return text;
}

function optionalPublicField(value: unknown, max = 2000): string {
  const text = String(value ?? "").trim();
  if (!text) return "";
  if (text.length > max) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      `Field must be ${max} characters or fewer.`
    );
  }
  return text;
}

function normalizePublicSource(value: unknown): "website" | "app" {
  const source = String(value ?? "").trim().toLowerCase();
  return source === "app" ? "app" : "website";
}

function normalizeEmergencyType(raw: unknown): EmergencyTypeKey {
  const value = String(raw ?? "").trim().toLowerCase().replace(/[\s-]+/g, "_");
  if (value === "road" || value === "road_accident" || value === "roadincident") {
    return "road_accident";
  }
  if (value === "medical" || value === "medical_emergency") {
    return "medical";
  }
  if (value === "fire") {
    return "fire";
  }
  if (value === "crime" || value === "crime_security") {
    return "crime";
  }
  return "other";
}

function emergencyTypeLabel(type: EmergencyTypeKey): string {
  if (type === "road_accident") return "Road Accident";
  if (type === "medical") return "Medical Emergency";
  if (type === "fire") return "Fire Incident";
  if (type === "crime") return "Crime / Security";
  return "Other Emergency";
}

function deriveEmergencyPriority(type: EmergencyTypeKey): PublicReportPriority {
  if (type === "fire") return "critical";
  if (type === "medical" || type === "road_accident" || type === "crime") {
    return "high";
  }
  return "medium";
}

function deriveIssuePriority(category: string): PublicReportPriority {
  const normalized = String(category).trim().toLowerCase();
  if (normalized === "public_safety" || normalized === "road_traffic") {
    return "high";
  }
  if (normalized === "solid_waste" || normalized === "environment") {
    return "medium";
  }
  return "low";
}

function normalizeGeoInput(raw: unknown): PublicReportGeo {
  const source = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  const latValue = Number(source.lat);
  const lngValue = Number(source.lng);
  if (!Number.isFinite(latValue) || !Number.isFinite(lngValue)) {
    return {lat: null, lng: null};
  }
  if (latValue < -90 || latValue > 90 || lngValue < -180 || lngValue > 180) {
    throw new functions.https.HttpsError("invalid-argument", "Invalid map coordinates.");
  }
  return {
    lat: Number(latValue.toFixed(6)),
    lng: Number(lngValue.toFixed(6)),
  };
}

function haversineDistanceMeters(a: PublicReportGeo, b: PublicReportGeo): number {
  if (a.lat == null || a.lng == null || b.lat == null || b.lng == null) {
    return Number.POSITIVE_INFINITY;
  }
  const toRad = (value: number) => (value * Math.PI) / 180;
  const earthRadiusMeters = 6371000;
  const dLat = toRad(b.lat - a.lat);
  const dLng = toRad(b.lng - a.lng);
  const lat1 = toRad(a.lat);
  const lat2 = toRad(b.lat);
  const arc = Math.sin(dLat / 2) ** 2 +
    Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLng / 2) ** 2;
  return 2 * earthRadiusMeters * Math.asin(Math.sqrt(arc));
}

async function detectEmergencyDuplicate(
  emergencyType: EmergencyTypeKey,
  barangay: string,
  geo: PublicReportGeo
): Promise<{duplicateOf: string | null; duplicateWarning: string | null}> {
  const thresholdDate = new Date(Date.now() - EMERGENCY_DUPLICATE_WINDOW_MS);
  const recentSnap = await db
    .collection("reports")
    .where("createdAt", ">=", admin.firestore.Timestamp.fromDate(thresholdDate))
    .orderBy("createdAt", "desc")
    .limit(50)
    .get();

  for (const doc of recentSnap.docs) {
    const row = doc.data() ?? {};
    if (String(row.lane ?? "") !== "emergency") {
      continue;
    }
    if (String(row.emergencyType ?? "") !== emergencyType) {
      continue;
    }
    if (String(row.barangay ?? "").trim().toLowerCase() !== barangay.toLowerCase()) {
      continue;
    }
    const rowGeo = normalizeGeoInput(row.geo);
    const distance = haversineDistanceMeters(geo, rowGeo);
    if (distance <= EMERGENCY_DUPLICATE_DISTANCE_METERS) {
      return {
        duplicateOf: doc.id,
        duplicateWarning:
          "A similar emergency report was submitted nearby recently. The report was accepted and flagged for staff review.",
      };
    }
  }

  return {duplicateOf: null, duplicateWarning: null};
}

function buildEmergencySla(now: Date): {
  acknowledgeBy: Date;
  verifyBy: Date;
  assignBy: Date;
} {
  // LGU can tune these targets later through a config-backed policy if needed.
  return {
    acknowledgeBy: new Date(now.getTime() + (60 * 60 * 1000)),
    verifyBy: new Date(now.getTime() + (6 * 60 * 60 * 1000)),
    assignBy: new Date(now.getTime() + (12 * 60 * 60 * 1000)),
  };
}

function generatePublicTrackingNumber(prefix: string): string {
  const year = new Date().getFullYear();
  const suffix = crypto.randomInt(0, 1000000).toString().padStart(6, "0");
  return `${prefix}-${year}-${suffix}`;
}

async function uploadPublicReportAttachment(
  reportId: string,
  fileBaseName: string,
  dataUrl: string,
  options: {
    allowedContentTypes?: Array<string | RegExp>;
    maxBytes?: number;
  } = {}
): Promise<PublicReportAttachment | null> {
  const trimmed = String(dataUrl ?? "").trim();
  if (!trimmed) return null;
  const match = trimmed.match(/^data:([^;]+);base64,(.+)$/);
  if (!match) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Attachment must be a valid data URL."
    );
  }
  const contentType = match[1].trim().toLowerCase();
  const allowedContentTypes = Array.isArray(options.allowedContentTypes) && options.allowedContentTypes.length > 0 ?
    options.allowedContentTypes :
    [/^image\//];
  const contentTypeAllowed = allowedContentTypes.some((allowed) => {
    if (allowed instanceof RegExp) {
      return allowed.test(contentType);
    }
    return String(allowed).trim().toLowerCase() === contentType;
  });
  if (!contentTypeAllowed) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Attachment type is not allowed for this public report."
    );
  }
  const buffer = Buffer.from(match[2], "base64");
  const maxBytes = Number(options.maxBytes) > 0 ? Number(options.maxBytes) : (3 * 1024 * 1024);
  if (buffer.length > maxBytes) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Attachment is too large."
    );
  }

  const extension = contentType.split("/")[1] || "jpg";
  const safeName = fileBaseName.replace(/[^a-z0-9_-]/gi, "_").toLowerCase();
  const storagePath = `reports_public/${reportId}/${safeName}.${extension}`;
  const bucket = admin.storage().bucket();
  const file = bucket.file(storagePath);
  await file.save(buffer, {
    resumable: false,
    metadata: {
      contentType,
      cacheControl: "public,max-age=3600",
    },
  });
  const [url] = await file.getSignedUrl({
    action: "read",
    expires: "2100-01-01",
  });
  return {
    url,
    contentType,
    name: `${safeName}.${extension}`,
    path: storagePath,
  };
}

async function createPublicReportDocument(
  input: PublicReportWriteInput
): Promise<{reportId: string; trackingNumber: string}> {
  const reportRef = input.reportId ?
    db.collection("reports").doc(input.reportId) :
    db.collection("reports").doc();
  const locationAddress = `${input.landmark}, ${input.barangay}`.trim();
  const now = admin.firestore.FieldValue.serverTimestamp();

  // `officeId` and `currentOfficeId` are written on create so staff scoping works
  // immediately for queues, dashboards, and the active map.
  await reportRef.set({
    lane: input.lane,
    reportKind: input.reportKind,
    serviceKey: input.serviceKey,
    emergencyType: input.emergencyType,
    category: input.category,
    title: input.title,
    subject: input.subject,
    barangay: input.barangay,
    landmark: input.landmark,
    location: {
      address: locationAddress,
      barangay: input.barangay,
      landmark: input.landmark,
    },
    geo: input.geo,
    status: "submitted" as PublicReportStatus,
    priority: input.priority,
    officeId: input.officeId,
    officeName: input.officeName,
    currentOfficeId: input.officeId,
    assignedOfficeId: null,
    assignedToUid: null,
    assignedToName: null,
    createdByUid: null,
    createdByName: input.reporterName,
    createdByEmail: input.reporterEmail ?? null,
    source: input.source,
    reporter: {
      name: input.reporterName,
      contact: input.reporterContact,
      email: input.reporterEmail ?? null,
      preferredDepartment: input.preferredDepartment ?? null,
    },
    name: input.reporterName,
    email: input.reporterEmail ?? null,
    contact: input.reporterContact,
    contactNumber: input.reporterContact,
    preferredDepartment: input.preferredDepartment ?? null,
    description: input.description,
    message: input.message,
    attachments: input.attachments,
    ticketNumber: input.trackingNumber,
    trackingNumber: input.trackingNumber,
    referenceNo: input.trackingNumber,
    reference: input.trackingNumber,
    duplicateOf: input.duplicateOf,
    duplicateWarning: input.duplicateWarning,
    sla: {
      acknowledgeBy: admin.firestore.Timestamp.fromDate(input.sla.acknowledgeBy),
      verifyBy: admin.firestore.Timestamp.fromDate(input.sla.verifyBy),
      assignBy: admin.firestore.Timestamp.fromDate(input.sla.assignBy),
    },
    lastActionByUid: null,
    lastActionByName: PUBLIC_REPORT_WRITE_SERVICE,
    lastActionByEmail: null,
    lastActionByRole: "public",
    lastActionAt: now,
    createdAt: now,
    updatedAt: now,
  });

  return {
    reportId: reportRef.id,
    trackingNumber: input.trackingNumber,
  };
}

function overdueReportSlaStage(
  row: Record<string, unknown>,
  nowMsValue = Date.now()
): "acknowledge" | "verify" | "assign" | null {
  let status = "submitted";
  try {
    status = normalizeReportStatusInput(row.status ?? "submitted");
  } catch {
    status = "submitted";
  }
  const assignedToUid = coerceString(row.assignedToUid);
  const acknowledgeBy = parseEpochMs((row.sla as Record<string, unknown> | undefined)?.acknowledgeBy);
  const verifyBy = parseEpochMs((row.sla as Record<string, unknown> | undefined)?.verifyBy);
  const assignBy = parseEpochMs((row.sla as Record<string, unknown> | undefined)?.assignBy);

  if (status === "submitted" && acknowledgeBy > 0 && nowMsValue >= acknowledgeBy) {
    return "acknowledge";
  }
  if (
    (status === "submitted" || status === "acknowledged") &&
    verifyBy > 0 &&
    nowMsValue >= verifyBy
  ) {
    return "verify";
  }
  if (
    !assignedToUid &&
    (status === "submitted" || status === "acknowledged" || status === "in_review") &&
    assignBy > 0 &&
    nowMsValue >= assignBy
  ) {
    return "assign";
  }
  return null;
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

function randomTrackingNo(): string {
  const year = new Date().getFullYear();
  const token = crypto.randomBytes(4).toString("hex").toUpperCase();
  return `DTS-${year}-${token}`;
}

function randomTrackingPin(): string {
  return String(Math.floor(100000 + Math.random() * 900000));
}

async function generateUniqueTrackingNo(maxAttempts = 8): Promise<string> {
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const candidate = randomTrackingNo();
    const duplicate = await db
      .collection("dts_documents")
      .where("trackingNo", "==", candidate)
      .limit(1)
      .get();
    if (duplicate.empty) {
      return candidate;
    }
  }
  throw new functions.https.HttpsError(
    "aborted",
    "Unable to generate a unique tracking number. Retry."
  );
}

function sanitizePdfFileName(input: string | null, fallback = "document.pdf"): string {
  const base = (input ?? fallback)
    .trim()
    .replace(/[^a-zA-Z0-9._-]+/g, "_")
    .replace(/^_+|_+$/g, "");
  const normalized = base.length > 0 ? base : fallback;
  if (normalized.toLowerCase().endsWith(".pdf")) {
    return normalized;
  }
  return `${normalized}.pdf`;
}

function decodePdfBase64(input: unknown): Buffer {
  const text = coerceString(input);
  if (!text) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "fileBase64 is required."
    );
  }
  const normalized = text.includes(",") ? text.split(",").pop() ?? "" : text;
  let bytes: Buffer;
  try {
    bytes = Buffer.from(normalized, "base64");
  } catch (_error) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "fileBase64 must be a valid base64-encoded PDF."
    );
  }
  if (bytes.length === 0) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Decoded PDF is empty."
    );
  }
  if (bytes.length > DTS_INTERNAL_PDF_MAX_BYTES) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "PDF exceeds the 12 MB upload limit."
    );
  }
  const header = bytes.subarray(0, 5).toString("utf8");
  if (!header.startsWith("%PDF-")) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Only PDF files are accepted."
    );
  }
  return bytes;
}

async function buildStorageTokenUrl(filePath: string): Promise<string> {
  const bucket = admin.storage().bucket();
  const file = bucket.file(filePath);
  try {
    const [signed] = await file.getSignedUrl({
      action: "read",
      expires: Date.now() + 1000 * 60 * 60,
    });
    return signed;
  } catch (_error) {
    const [metadata] = await file.getMetadata();
    const custom = metadata.metadata ?? {};
    let token = coerceString(custom.firebaseStorageDownloadTokens);
    if (token && token.includes(",")) {
      token = token.split(",")[0].trim();
    }
    if (!token) {
      token = crypto.randomUUID();
      await file.setMetadata({
        metadata: {
          ...custom,
          firebaseStorageDownloadTokens: token,
        },
      });
    }
    return `https://firebasestorage.googleapis.com/v0/b/${bucket.name}/o/` +
      `${encodeURIComponent(filePath)}?alt=media&token=${token}`;
  }
}

async function buildStorageSignedReadUrl(
  filePath: string,
  expiresAtMs: number
): Promise<string> {
  const bucket = admin.storage().bucket();
  const file = bucket.file(filePath);
  const [signed] = await file.getSignedUrl({
    action: "read",
    expires: expiresAtMs,
  });
  return signed;
}

function normalizeGeneratedPdfPath(
  docId: string,
  value: unknown
): string | null {
  const candidate = coerceString(value);
  if (!candidate) return null;
  const normalized = candidate.replace(/\\/g, "/").replace(/^\/+/, "");
  if (!normalized.toLowerCase().endsWith(".pdf")) return null;
  const requiredPrefix = `dts_documents/${docId}/generated/`;
  if (!normalized.startsWith(requiredPrefix)) return null;
  return normalized;
}

async function stampInternalPdfDocument(
  sourcePdf: Buffer,
  trackingNo: string,
  qrCode: string
): Promise<Buffer> {
  const pdf = await PDFDocument.load(sourcePdf, {ignoreEncryption: true});
  if (pdf.getPageCount() === 0) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "PDF must contain at least one page."
    );
  }
  const qrPng = await createQrPng(qrCode);
  const qrImage = await pdf.embedPng(qrPng);
  const font = await pdf.embedFont(StandardFonts.HelveticaBold);

  // Use first-page stamp block only, placed in lower-right with <=0.5in margin.
  const page = pdf.getPages()[0];
  if (page) {
    const {width, height} = page.getSize();
    const rightMargin = Math.min(24, Math.max(12, width * 0.02));
    const bottomMargin = Math.min(24, Math.max(10, height * 0.018));
    const qrSize = 40;
    const boxPadding = 2;
    const boxWidth = qrSize + (boxPadding * 2);
    const textSize = 4.3;
    const textGap = 1.2;
    const maxTextWidth = boxWidth - 4;
    const fitLineToBox = (value: string): string => {
      let out = value.trim();
      while (
        out.length > 4 &&
        font.widthOfTextAtSize(out, textSize) > maxTextWidth
      ) {
        out = out.slice(0, -1);
      }
      return out;
    };
    const compactTracking = (value: string): string => {
      const normalized = value.trim();
      if (normalized.length <= 18) {
        return normalized;
      }
      return `${normalized.slice(0, 10)}...${normalized.slice(-5)}`;
    };
    const line = fitLineToBox(compactTracking(trackingNo));
    const captionHeight =
      (line.length > 0 ? textSize + textGap : 0) +
      2;
    const boxHeight = qrSize + captionHeight + (boxPadding * 2) + 1;

    const x = Math.max(8, width - rightMargin - boxWidth);
    const y = Math.max(8, bottomMargin);
    const qrX = x + ((boxWidth - qrSize) / 2);
    const qrY = y + captionHeight + boxPadding + 1;

    page.drawRectangle({
      x,
      y,
      width: boxWidth,
      height: boxHeight,
      color: rgb(1, 1, 1),
      borderColor: rgb(0.86, 0.89, 0.94),
      borderWidth: 0.8,
      opacity: 0.97,
    });
    page.drawImage(qrImage, {
      x: qrX,
      y: qrY,
      width: qrSize,
      height: qrSize,
    });
    if (line.length > 0) {
      const lineWidth = font.widthOfTextAtSize(line, textSize);
      page.drawText(line, {
        x: x + ((boxWidth - lineWidth) / 2),
        y: y + 2.2 + textSize + textGap,
        size: textSize,
        font,
        color: rgb(0.06, 0.1, 0.18),
      });
    }
  }

  return Buffer.from(await pdf.save());
}

function dtsInstructions(status: string) {
  const normalized = status.toUpperCase();
  switch (normalized) {
    case "DRAFT":
      return "Your document is being prepared for final issuance.";
    case "CREATED":
      return "Your document was created and is ready for routing.";
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
    case "VOIDED":
      return "This document was voided and replaced by records policy.";
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

type CallableContextLike = {
  auth?: {
    uid: string;
    token: Record<string, unknown>;
  } | null;
  rawRequest?: {
    ip?: string | null;
    headers?: Record<string, unknown> | null;
  } | null;
};

const DTS_STATUSES = new Set([
  "DRAFT",
  "CREATED",
  "RECEIVED",
  "IN_TRANSIT",
  "WITH_OFFICE",
  "IN_PROCESS",
  "FOR_APPROVAL",
  "RELEASED",
  "ARCHIVED",
  "VOIDED",
  "PULLED_OUT",
]);

const DTS_PIN_MAX_ATTEMPTS = 10;
const DTS_PIN_LOCK_MINUTES = 15;
const DTS_RECEIPT_VERIFY_MAX_ATTEMPTS = 6;
const DTS_RECEIPT_VERIFY_LOCK_MINUTES = 10;
const DTS_RECEIPT_QR_SUFFIX_LENGTH = 6;
const DTS_QR_RESERVATION_TTL_MINUTES = 15;
const DTS_QR_RESERVATION_SWEEP_LIMIT = 500;
const DTS_OVERDUE_ALERT_SWEEP_LIMIT = 300;
const DTS_OVERDUE_ALERT_RENOTIFY_HOURS = 6;
const DTS_TRACK_SESSION_TTL_HOURS = 12;
const DTS_TRACK_SESSION_ROTATION_BYTES = 24;
const DTS_PIN_BCRYPT_ROUNDS = 12;
const DTS_INTERNAL_PDF_MAX_BYTES = 12 * 1024 * 1024;
const DTS_TEMPLATE_FILE_MAX_BYTES = 12 * 1024 * 1024;
const DTS_TEMPLATE_DEFAULT_QR_POSITION = "BOTTOM_RIGHT";
const DTS_TEMPLATE_DEFAULT_QR_SIZE = 96;
const DTS_MAX_SLA_HOURS = 720;
const DTS_PRIORITY_LEVELS = new Set(["LOW", "NORMAL", "HIGH", "URGENT"]);
const DTS_RECEIPT_VERIFICATION_METHODS = new Set(["MANUAL_INPUT", "SCAN"]);
const DTS_DISTRIBUTION_MODES = new Set(["SINGLE", "MULTI"]);
const DTS_DESTINATION_STATUSES = new Set([
  "PENDING",
  "IN_TRANSIT",
  "RECEIVED",
  "REJECTED",
  "CANCELLED",
]);
const DTS_TEMPLATE_ALLOWED_QR_POSITIONS = new Set([
  "BOTTOM_RIGHT",
  "BOTTOM_LEFT",
  "TOP_RIGHT",
  "TOP_LEFT",
]);
const FUNCTIONS_BUILD_VERSION = "2026.02.20.1";

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

function normalizeDtsPriorityLevel(raw: unknown, fallback = "NORMAL"): string {
  const normalized = String(raw ?? "")
    .trim()
    .toUpperCase()
    .replace(/\s+/g, "_");
  if (DTS_PRIORITY_LEVELS.has(normalized)) {
    return normalized;
  }
  return fallback;
}

function normalizeDtsDistributionMode(raw: unknown, fallback = "SINGLE"): string {
  const normalized = String(raw ?? "")
    .trim()
    .toUpperCase()
    .replace(/\s+/g, "_");
  if (DTS_DISTRIBUTION_MODES.has(normalized)) {
    return normalized;
  }
  return fallback;
}

function normalizeDtsDestinationStatus(raw: unknown, fallback = "PENDING"): string {
  const normalized = String(raw ?? "")
    .trim()
    .toUpperCase()
    .replace(/\s+/g, "_");
  if (DTS_DESTINATION_STATUSES.has(normalized)) {
    return normalized;
  }
  return fallback;
}

function parseDtsDueAt(raw: unknown): Date | null {
  if (raw instanceof Date && Number.isFinite(raw.getTime())) {
    return raw;
  }
  if (typeof raw === "number" && Number.isFinite(raw)) {
    const fromEpoch = new Date(raw);
    return Number.isFinite(fromEpoch.getTime()) ? fromEpoch : null;
  }
  if (typeof raw === "string" && raw.trim().length > 0) {
    const parsed = new Date(raw.trim());
    return Number.isFinite(parsed.getTime()) ? parsed : null;
  }
  return null;
}

const DTS_OVERDUE_TRACKED_STATUSES = new Set([
  "CREATED",
  "RECEIVED",
  "WITH_OFFICE",
  "IN_PROCESS",
  "FOR_APPROVAL",
  "IN_TRANSIT",
  "PULLED_OUT",
]);

function dtsOverdueSeverity(hoursOverdue: number): "WARNING" | "HIGH" | "CRITICAL" {
  if (hoursOverdue >= 72) {
    return "CRITICAL";
  }
  if (hoursOverdue >= 24) {
    return "HIGH";
  }
  return "WARNING";
}

function normalizeDtsVerificationValue(raw: unknown): string {
  return String(raw ?? "").trim().toUpperCase();
}

function normalizeDtsVerificationMethod(raw: unknown): string {
  const normalized = String(raw ?? "")
    .trim()
    .toUpperCase()
    .replace(/\s+/g, "_");
  if (DTS_RECEIPT_VERIFICATION_METHODS.has(normalized)) {
    return normalized;
  }
  return "MANUAL_INPUT";
}

function matchesDtsTrackingOrQr(
  verificationValue: string,
  trackingNo: string,
  qrCode: string | null
): boolean {
  if (!verificationValue) {
    return false;
  }
  if (verificationValue === trackingNo.trim().toUpperCase()) {
    return true;
  }
  if (qrCode && verificationValue === qrCode.trim().toUpperCase()) {
    return true;
  }
  return false;
}

function dtsQrSuffix(qrCode: string | null): string | null {
  const normalized = normalizeDtsVerificationValue(qrCode);
  if (!normalized) {
    return null;
  }
  if (normalized.length <= DTS_RECEIPT_QR_SUFFIX_LENGTH) {
    return normalized;
  }
  return normalized.slice(-DTS_RECEIPT_QR_SUFFIX_LENGTH);
}

function receiptAttemptScopeId(scope: string): string {
  return scope
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9_-]+/g, "_")
    .replace(/_+/g, "_")
    .slice(0, 96);
}

function receiptAttemptDocId(scope: string, dimension: string, value: string): string {
  const safeDimension = dimension
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9_-]+/g, "_");
  const safeValue = value
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9_-]+/g, "_")
    .slice(0, 64);
  return `${receiptAttemptScopeId(scope)}__${safeDimension}__${safeValue || "UNKNOWN"}`;
}

function receiptAttemptContextIpHash(context: CallableContextLike): string {
  const rawIp = context.rawRequest?.ip ?? "unknown";
  return sha256(String(rawIp)).slice(0, 16).toUpperCase();
}

function buildReceiptAttemptRefs(
  scope: string,
  actorUid: string,
  context: CallableContextLike
): admin.firestore.DocumentReference[] {
  const uid = actorUid.trim() || "unknown";
  const ipHash = receiptAttemptContextIpHash(context);
  return [
    db.collection("dts_receipt_attempts").doc(receiptAttemptDocId(scope, "UID", uid)),
    db.collection("dts_receipt_attempts").doc(receiptAttemptDocId(scope, "IP", ipHash)),
  ];
}

async function assertReceiptVerificationNotLocked(
  scope: string,
  actorUid: string,
  context: CallableContextLike
): Promise<void> {
  const refs = buildReceiptAttemptRefs(scope, actorUid, context);
  const snaps = await Promise.all(refs.map((ref) => ref.get()));
  const now = Date.now();
  for (const snap of snaps) {
    const row = (snap.data() ?? {}) as Record<string, unknown>;
    const lockUntil = parseLockUntil(row);
    if (lockUntil && lockUntil.getTime() > now) {
      throw new functions.https.HttpsError(
        "resource-exhausted",
        "Too many invalid verification attempts. Please wait before trying again."
      );
    }
  }
}

async function clearReceiptVerificationAttempts(
  scope: string,
  actorUid: string,
  context: CallableContextLike
): Promise<void> {
  const refs = buildReceiptAttemptRefs(scope, actorUid, context);
  const batch = db.batch();
  for (const ref of refs) {
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
}

async function registerReceiptVerificationFailure(
  scope: string,
  actorUid: string,
  context: CallableContextLike
): Promise<boolean> {
  const refs = buildReceiptAttemptRefs(scope, actorUid, context);
  const snaps = await Promise.all(refs.map((ref) => ref.get()));
  const now = Date.now();
  const lockUntil = new Date(now + DTS_RECEIPT_VERIFY_LOCK_MINUTES * 60 * 1000);
  let locked = false;
  const batch = db.batch();
  for (const [index, ref] of refs.entries()) {
    const row = (snaps[index].data() ?? {}) as Record<string, unknown>;
    const previousFails = parseFailCount(row);
    const nextFails = previousFails + 1;
    const shouldLock = nextFails >= DTS_RECEIPT_VERIFY_MAX_ATTEMPTS;
    locked = locked || shouldLock;
    batch.set(
      ref,
      {
        failCount: shouldLock ? 0 : nextFails,
        lockUntil: shouldLock
          ? admin.firestore.Timestamp.fromDate(lockUntil)
          : admin.firestore.FieldValue.delete(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      {merge: true}
    );
  }
  await batch.commit();
  return locked;
}

const DTS_ALLOWED_TRANSITIONS: Record<string, Set<string>> = {
  DRAFT: new Set(["CREATED", "VOIDED"]),
  CREATED: new Set(["IN_TRANSIT", "WITH_OFFICE", "IN_PROCESS", "FOR_APPROVAL", "VOIDED"]),
  RECEIVED: new Set(["WITH_OFFICE", "IN_PROCESS", "FOR_APPROVAL", "IN_TRANSIT", "ARCHIVED", "VOIDED"]),
  WITH_OFFICE: new Set(["IN_PROCESS", "FOR_APPROVAL", "IN_TRANSIT", "RELEASED", "ARCHIVED", "PULLED_OUT", "VOIDED"]),
  IN_PROCESS: new Set(["WITH_OFFICE", "FOR_APPROVAL", "IN_TRANSIT", "RELEASED", "ARCHIVED", "VOIDED"]),
  FOR_APPROVAL: new Set(["WITH_OFFICE", "IN_PROCESS", "IN_TRANSIT", "RELEASED", "ARCHIVED", "VOIDED"]),
  RELEASED: new Set(["ARCHIVED", "PULLED_OUT"]),
  ARCHIVED: new Set(["PULLED_OUT"]),
  VOIDED: new Set([]),
  PULLED_OUT: new Set(["WITH_OFFICE", "IN_PROCESS", "FOR_APPROVAL", "RELEASED", "ARCHIVED", "VOIDED"]),
  IN_TRANSIT: new Set(["WITH_OFFICE"]),
};

function canTransitionDtsStatus(fromStatus: string, toStatus: string): boolean {
  if (fromStatus === toStatus) return true;
  const allowed = DTS_ALLOWED_TRANSITIONS[fromStatus];
  if (!allowed) return false;
  return allowed.has(toStatus);
}

async function requireStaffContext(
  context: CallableContextLike
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
  if (!(role === "super_admin" || role === "admin" || role === "office_admin" || role === "moderator")) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Staff access required."
    );
  }
  if (roleRequiresOffice(role) && !officeId) {
    throw new functions.https.HttpsError(
      "failed-precondition",
      "Office-scoped staff accounts must have an office assignment."
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

async function requireSuperAdminContext(
  context: CallableContextLike
): Promise<StaffContext> {
  const actor = await requireStaffContext(context);
  if (actor.role !== "super_admin") {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Only super_admin can manage staff users."
    );
  }
  return actor;
}

async function resolveManagedOffice(
  role: NormalizedRole,
  requestedOfficeId: string | null,
  requestedOfficeName: string | null,
  fallbackOfficeId: string | null,
  fallbackOfficeName: string | null
): Promise<{ officeId: string | null; officeName: string | null }> {
  if (!roleRequiresOffice(role)) {
    return {
      officeId: null,
      officeName: null,
    };
  }

  const officeId = requestedOfficeId ?? fallbackOfficeId;
  let officeName = requestedOfficeName ?? fallbackOfficeName;
  if (!officeId) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "officeId is required for office_admin or moderator."
      );
  }

  if (!officeName) {
    const officeSnap = await db.collection("offices").doc(officeId).get();
    officeName = coerceString(officeSnap.data()?.name);
  }

  return {
    officeId,
    officeName,
  };
}

function dtsPendingTransfer(data: Record<string, unknown>) {
  const pending = data.pendingTransfer;
  if (!pending || typeof pending !== "object") return null;
  return pending as Record<string, unknown>;
}

type DtsDestinationRecord = {
  id: string;
  docId: string;
  toOfficeId: string | null;
  toOfficeName: string | null;
  toUid: string | null;
  sourceOfficeId: string | null;
  sourceOfficeName: string | null;
  status: string;
  previousStatus: string | null;
  createdByUid: string | null;
  createdByName: string | null;
  createdAt: FirebaseFirestore.Timestamp | null;
  dispatchedAt: FirebaseFirestore.Timestamp | null;
  receivedAt: FirebaseFirestore.Timestamp | null;
  rejectedAt: FirebaseFirestore.Timestamp | null;
  cancelledAt: FirebaseFirestore.Timestamp | null;
  reason: string | null;
};

type DtsDestinationSummary = {
  total: number;
  pending: number;
  inTransit: number;
  received: number;
  rejected: number;
  cancelled: number;
  activeOfficeIds: string[];
  allOfficeIds: string[];
};

type ApplyDestinationSummaryOptions = {
  forceStatus?: string | null;
  parentPatch?: Record<string, unknown>;
};

function uniqueSortedStrings(values: Array<string | null | undefined>): string[] {
  const unique = new Set<string>();
  for (const raw of values) {
    const value = coerceString(raw);
    if (value) {
      unique.add(value);
    }
  }
  return Array.from(unique).sort((left, right) => left.localeCompare(right));
}

function mapDtsDestinationRecord(
  docId: string,
  id: string,
  row: Record<string, unknown>
): DtsDestinationRecord {
  return {
    id,
    docId,
    toOfficeId: coerceString(row.toOfficeId),
    toOfficeName: coerceString(row.toOfficeName),
    toUid: coerceString(row.toUid),
    sourceOfficeId: coerceString(row.sourceOfficeId),
    sourceOfficeName: coerceString(row.sourceOfficeName),
    status: normalizeDtsDestinationStatus(row.status),
    previousStatus: coerceString(row.previousStatus),
    createdByUid: coerceString(row.createdByUid),
    createdByName: coerceString(row.createdByName),
    createdAt: coerceTimestamp(row.createdAt),
    dispatchedAt: coerceTimestamp(row.dispatchedAt),
    receivedAt: coerceTimestamp(row.receivedAt),
    rejectedAt: coerceTimestamp(row.rejectedAt),
    cancelledAt: coerceTimestamp(row.cancelledAt),
    reason: coerceString(row.reason),
  };
}

function coerceTimestamp(value: unknown): FirebaseFirestore.Timestamp | null {
  if (value instanceof admin.firestore.Timestamp) {
    return value;
  }
  if (value instanceof Date) {
    return admin.firestore.Timestamp.fromDate(value);
  }
  return null;
}

async function loadDtsDestinationRecords(
  tx: FirebaseFirestore.Transaction,
  docRef: FirebaseFirestore.DocumentReference
): Promise<DtsDestinationRecord[]> {
  const destinationSnap = await tx.get(docRef.collection("destinations"));
  return destinationSnap.docs
    .map((row) => mapDtsDestinationRecord(docRef.id, row.id, row.data() ?? {}))
    .sort((left, right) => left.id.localeCompare(right.id));
}

function summarizeDtsDestinationRecords(
  destinations: DtsDestinationRecord[]
): DtsDestinationSummary {
  let pending = 0;
  let inTransit = 0;
  let received = 0;
  let rejected = 0;
  let cancelled = 0;
  for (const destination of destinations) {
    switch (destination.status) {
    case "PENDING":
      pending += 1;
      break;
    case "IN_TRANSIT":
      inTransit += 1;
      break;
    case "RECEIVED":
      received += 1;
      break;
    case "REJECTED":
      rejected += 1;
      break;
    case "CANCELLED":
      cancelled += 1;
      break;
    default:
      break;
    }
  }

  const activeOfficeIds = uniqueSortedStrings(
    destinations
      .filter((destination) =>
        destination.status === "PENDING" || destination.status === "IN_TRANSIT")
      .map((destination) => destination.toOfficeId)
  );
  const allOfficeIds = uniqueSortedStrings(
    destinations.map((destination) => destination.toOfficeId)
  );

  return {
    total: destinations.length,
    pending,
    inTransit,
    received,
    rejected,
    cancelled,
    activeOfficeIds,
    allOfficeIds,
  };
}

function destinationToLegacyPendingTransfer(
  destination: DtsDestinationRecord
): Record<string, unknown> {
  return {
    fromOfficeId: destination.sourceOfficeId,
    fromUid: destination.createdByUid,
    toOfficeId: destination.toOfficeId,
    toOfficeName: destination.toOfficeName,
    toUid: destination.toUid,
    previousStatus: normalizeDtsStatus(destination.previousStatus, "WITH_OFFICE"),
    initiatedAt: destination.dispatchedAt ?? destination.createdAt ?? admin.firestore.FieldValue.serverTimestamp(),
    destinationId: destination.id,
  };
}

function buildLegacyPendingTransferFromDestinations(
  destinations: DtsDestinationRecord[]
): Record<string, unknown> | null {
  const active = destinations.filter((row) => row.status === "IN_TRANSIT");
  if (active.length !== 1) {
    return null;
  }
  return destinationToLegacyPendingTransfer(active[0]);
}

function isDestinationReceiver(
  actor: StaffContext,
  destination: DtsDestinationRecord
): boolean {
  if (actor.role === "super_admin") {
    return true;
  }
  if (destination.toUid && destination.toUid === actor.uid) {
    return true;
  }
  if (actor.officeId && destination.toOfficeId && actor.officeId === destination.toOfficeId) {
    return true;
  }
  return sameNormalizedName(actor.officeName, destination.toOfficeName);
}

function isDestinationSource(
  actor: StaffContext,
  destination: DtsDestinationRecord,
  parentRow: Record<string, unknown>
): boolean {
  if (actor.role === "super_admin") {
    return true;
  }
  if (destination.createdByUid && destination.createdByUid === actor.uid) {
    return true;
  }
  if (actor.officeId && destination.sourceOfficeId && actor.officeId === destination.sourceOfficeId) {
    return true;
  }
  if (sameNormalizedName(actor.officeName, destination.sourceOfficeName)) {
    return true;
  }
  if (actor.officeId && coerceString(parentRow.currentOfficeId) === actor.officeId) {
    return true;
  }
  return sameNormalizedName(actor.officeName, coerceString(parentRow.currentOfficeName));
}

function applyDtsDestinationSummaryToParent(
  tx: FirebaseFirestore.Transaction,
  docRef: FirebaseFirestore.DocumentReference,
  parentRow: Record<string, unknown>,
  destinations: DtsDestinationRecord[],
  options: ApplyDestinationSummaryOptions = {}
): {summary: DtsDestinationSummary; status: string} {
  const summary = summarizeDtsDestinationRecords(destinations);
  const currentStatus = normalizeDtsStatus(parentRow.status, "WITH_OFFICE");
  const baseStatus = normalizeDtsStatus(
    parentRow.distributionBaseStatus,
    currentStatus === "IN_TRANSIT" ? "WITH_OFFICE" : currentStatus
  );
  let nextStatus = options.forceStatus == null
    ? currentStatus
    : normalizeDtsStatus(options.forceStatus, currentStatus);
  const payload: Record<string, unknown> = {
    distributionMode: summary.total > 1 ? "MULTI" : "SINGLE",
    destTotal: summary.total,
    destPending: summary.pending,
    destInTransit: summary.inTransit,
    destReceived: summary.received,
    destRejected: summary.rejected,
    destCancelled: summary.cancelled,
    activeDestinationOfficeIds: summary.activeOfficeIds,
    destinationOfficeIds: summary.allOfficeIds,
    pendingTransfer: buildLegacyPendingTransferFromDestinations(destinations),
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
  };
  if (summary.inTransit > 0 && options.forceStatus == null) {
    if (currentStatus !== "IN_TRANSIT") {
      payload.distributionBaseStatus = currentStatus;
    }
    nextStatus = "IN_TRANSIT";
    payload.currentCustodianUid = null;
  } else if (summary.inTransit === 0 && currentStatus === "IN_TRANSIT" && options.forceStatus == null) {
    nextStatus = baseStatus;
  }
  payload.status = nextStatus;
  if (options.parentPatch) {
    Object.assign(payload, options.parentPatch);
  }
  tx.set(docRef, payload, {merge: true});
  return {summary, status: nextStatus};
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

function findDestinationById(
  destinations: DtsDestinationRecord[],
  destinationId: string | null
): DtsDestinationRecord | null {
  if (!destinationId) {
    return null;
  }
  return destinations.find((row) => row.id === destinationId) ?? null;
}

function findReceivingDestinationForActor(
  destinations: DtsDestinationRecord[],
  actor: StaffContext
): DtsDestinationRecord | null {
  const candidates = destinations.filter((row) =>
    row.status === "IN_TRANSIT" && isDestinationReceiver(actor, row));
  if (candidates.length === 1) {
    return candidates[0];
  }
  return null;
}

function findSourceDestinationForActor(
  destinations: DtsDestinationRecord[],
  actor: StaffContext,
  parentRow: Record<string, unknown>
): DtsDestinationRecord | null {
  const candidates = destinations.filter((row) =>
    (row.status === "IN_TRANSIT" || row.status === "PENDING") &&
      isDestinationSource(actor, row, parentRow));
  if (candidates.length === 1) {
    return candidates[0];
  }
  return null;
}

function actorDisplayName(actor: StaffContext): string {
  return (
    coerceString(actor.profileData.displayName) ??
    coerceString(actor.profileData.email) ??
    actor.uid
  );
}

type DtsTemplateRecord = {
  id: string;
  name: string;
  officeId: string | null;
  officeName: string | null;
  fileUrl: string | null;
  qrPosition: string;
  qrSize: number;
  version: number;
  isActive: boolean;
  fileBytes: number | null;
  createdByUid: string | null;
  updatedAt: Date | null;
};

function normalizeTemplateVersion(raw: unknown, fallback = 1): number {
  if (typeof raw === "number" && Number.isFinite(raw)) {
    return Math.max(1, Math.floor(raw));
  }
  if (typeof raw === "string") {
    const parsed = Number.parseInt(raw.trim(), 10);
    if (Number.isFinite(parsed)) {
      return Math.max(1, parsed);
    }
  }
  return fallback;
}

function normalizeTemplateQrPosition(raw: unknown): string {
  const candidate = String(raw ?? "")
    .trim()
    .toUpperCase()
    .replace(/[^A-Z_]/g, "_");
  if (DTS_TEMPLATE_ALLOWED_QR_POSITIONS.has(candidate)) {
    return candidate;
  }
  return DTS_TEMPLATE_DEFAULT_QR_POSITION;
}

function normalizeTemplateQrSize(raw: unknown): number {
  if (typeof raw === "number" && Number.isFinite(raw)) {
    return Math.max(48, Math.min(220, Math.floor(raw)));
  }
  if (typeof raw === "string") {
    const parsed = Number.parseInt(raw.trim(), 10);
    if (Number.isFinite(parsed)) {
      return Math.max(48, Math.min(220, parsed));
    }
  }
  return DTS_TEMPLATE_DEFAULT_QR_SIZE;
}

function normalizeTemplateFileBytes(raw: unknown): number | null {
  if (typeof raw === "number" && Number.isFinite(raw) && raw >= 0) {
    return Math.floor(raw);
  }
  if (typeof raw === "string") {
    const parsed = Number.parseInt(raw.trim(), 10);
    if (Number.isFinite(parsed) && parsed >= 0) {
      return parsed;
    }
  }
  return null;
}

function sanitizeTemplateFileUrl(value: unknown): string {
  const text = coerceString(value);
  if (!text) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Template fileUrl is required."
    );
  }
  if (text.length > 2000) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Template fileUrl is too long."
    );
  }
  if (!text.startsWith("https://") && !text.startsWith("gs://")) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Template fileUrl must be an HTTPS or gs:// URL."
    );
  }
  const lower = text.toLowerCase();
  if (!lower.includes(".pdf")) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Template fileUrl must point to a PDF file."
    );
  }
  return text;
}

function mapDtsTemplateRecord(
  templateId: string,
  row: Record<string, unknown>
): DtsTemplateRecord {
  const updatedAtEpoch = parseEpochMs(row.updatedAt ?? row.createdAt);
  return {
    id: templateId,
    name: coerceString(row.name) ?? templateId,
    officeId: coerceString(row.officeId),
    officeName: coerceString(row.officeName),
    fileUrl: coerceString(row.fileUrl),
    qrPosition: normalizeTemplateQrPosition(row.qrPosition),
    qrSize: normalizeTemplateQrSize(row.qrSize),
    version: normalizeTemplateVersion(row.version, 1),
    isActive: row.isActive !== false,
    fileBytes: normalizeTemplateFileBytes(row.fileBytes),
    createdByUid: coerceString(row.createdByUid),
    updatedAt: updatedAtEpoch > 0 ? new Date(updatedAtEpoch) : null,
  };
}

function canManageDtsTemplate(
  actor: StaffContext,
  template: DtsTemplateRecord
): boolean {
  if (actor.role === "super_admin" || actor.role === "admin") {
    return true;
  }
  if (actor.role !== "office_admin") {
    return false;
  }
  if (!actor.officeId || !template.officeId) {
    return false;
  }
  return actor.officeId === template.officeId;
}

function assertDtsTemplateManager(actor: StaffContext): void {
  if (
    actor.role !== "super_admin" &&
    actor.role !== "admin" &&
    actor.role !== "office_admin"
  ) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Only admin, super_admin, or office_admin can manage templates."
    );
  }
}

function toCallableContextFromV2(
  request: CallableRequest<unknown>
): CallableContextLike {
  return {
    auth: request.auth
      ? {
          uid: request.auth.uid,
          token: (request.auth.token ?? {}) as Record<string, unknown>,
        }
      : null,
    rawRequest: {
      ip: request.rawRequest?.ip ?? null,
      headers: (request.rawRequest?.headers ?? null) as Record<string, unknown> | null,
    },
  };
}

const CALLABLE_ERROR_CODES = new Set([
  "cancelled",
  "unknown",
  "invalid-argument",
  "deadline-exceeded",
  "not-found",
  "already-exists",
  "permission-denied",
  "resource-exhausted",
  "failed-precondition",
  "aborted",
  "out-of-range",
  "unimplemented",
  "internal",
  "unavailable",
  "data-loss",
  "unauthenticated",
]);

function normalizeCallableErrorForV2(error: unknown): HttpsErrorV2 {
  if (error instanceof HttpsErrorV2) return error;
  const candidate = error as { code?: unknown; message?: unknown; details?: unknown };
  const rawCode = String(candidate.code ?? "").toLowerCase();
  const safeCode = CALLABLE_ERROR_CODES.has(rawCode) ? rawCode : "internal";
  type HttpsErrorCode = ConstructorParameters<typeof HttpsErrorV2>[0];
  const message = String(candidate.message ?? "Request failed.");
  return new HttpsErrorV2(safeCode as HttpsErrorCode, message, candidate.details);
}

function sanitizeDtsAttachments(raw: unknown): Array<Record<string, unknown>> {
  if (!Array.isArray(raw)) return [];
  const output: Array<Record<string, unknown>> = [];
  for (const entry of raw) {
    if (!entry || typeof entry !== "object") continue;
    const src = entry as Record<string, unknown>;
    const clean: Record<string, unknown> = {};
    const name = coerceString(src.name);
    const path = normalizeDtsAttachmentPath(src.path);
    const url = normalizeDtsAttachmentUrl(src.url);
    const contentType = coerceString(src.contentType);
    const uploadedAt = normalizeDtsAttachmentUploadedAt(src.uploadedAt);

    if (name && name.length <= 160) clean.name = name;
    if (path) clean.path = path;
    if (url) clean.url = url;
    if (contentType && contentType.length <= 120) clean.contentType = contentType;
    if (uploadedAt) clean.uploadedAt = uploadedAt;

    if (!clean.path && !clean.url) continue;
    output.push(clean);
    if (output.length >= 10) break;
  }
  return output;
}

type TrackingLookupContext = {
  auth?: { uid?: string } | null;
  rawRequest?: { ip?: string | null } | null;
};

function normalizeTrackingNo(raw: unknown): string {
  return String(raw ?? "").trim().toUpperCase();
}

function normalizeTrackingPin(raw: unknown): string {
  return String(raw ?? "").trim();
}

function invalidTrackingCredentialsError(): functions.https.HttpsError {
  return new functions.https.HttpsError(
    "permission-denied",
    INVALID_TRACKING_CREDENTIALS_MESSAGE
  );
}

function validateTrackingLookupInput(
  trackingNoRaw: unknown,
  pinRaw: unknown
): {trackingNo: string; pin: string} {
  const trackingNo = normalizeTrackingNo(trackingNoRaw);
  const pin = normalizeTrackingPin(pinRaw);
  if (!trackingNo || !pin) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "trackingNo and pin are required."
    );
  }
  if (!TRACKING_NO_REGEX.test(trackingNo)) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Invalid tracking number format."
    );
  }
  if (!TRACKING_PIN_REGEX.test(pin)) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Invalid PIN format."
    );
  }
  return {trackingNo, pin};
}

function isAllowedCorsOrigin(origin: string): boolean {
  if (isLoopbackOrigin(origin)) return true;
  if (TRACK_LOOKUP_ALLOWED_ORIGINS.length === 0) return allowOriginWithoutAllowlist();
  return TRACK_LOOKUP_ALLOWED_ORIGINS.includes(origin);
}

function applyTrackLookupCors(
  req: functions.https.Request,
  res: functions.Response<unknown>
): boolean {
  applyJsonEndpointSecurityHeaders(res);
  const origin = String(req.headers.origin ?? "").trim();
  if (!origin) {
    if (allowOriginWithoutAllowlist()) {
      res.set("Access-Control-Allow-Origin", "*");
    }
  } else if (isAllowedCorsOrigin(origin)) {
    res.set("Access-Control-Allow-Origin", origin);
    res.set("Vary", "Origin");
  } else {
    return false;
  }
  res.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.set("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.set("Access-Control-Allow-Credentials", "false");
  res.set("Access-Control-Max-Age", "600");
  return true;
}

function legacyPinHashFromDoc(pin: string, data: Record<string, unknown>): string {
  const salt = coerceString(data.publicPinSalt);
  return salt ? sha256(`${pin}:${salt}`) : sha256(pin);
}

function normalizeDtsAttachmentPath(value: unknown): string | null {
  const text = coerceString(value);
  if (!text) return null;
  const normalized = text.replace(/^\/+/, "");
  return DTS_ATTACHMENT_PATH_PATTERN.test(normalized) ? normalized : null;
}

function normalizeDtsAttachmentUrl(value: unknown): string | null {
  const text = coerceString(value);
  if (!text) return null;
  try {
    const parsed = new URL(text);
    if (parsed.protocol !== "https:") return null;

    let bucket: string | null = null;
    let objectPath: string | null = null;
    if (parsed.hostname === "firebasestorage.googleapis.com") {
      const match = parsed.pathname.match(/^\/v0\/b\/([^/]+)\/o\/(.+)$/);
      if (!match) return null;
      bucket = decodeURIComponent(match[1] ?? "");
      objectPath = decodeURIComponent(match[2] ?? "");
    } else if (parsed.hostname === "storage.googleapis.com") {
      const parts = parsed.pathname.split("/").filter(Boolean);
      if (parts.length < 2) return null;
      bucket = decodeURIComponent(parts[0] ?? "");
      objectPath = decodeURIComponent(parts.slice(1).join("/"));
    } else {
      return null;
    }

    if (!bucket || !DTS_ATTACHMENT_BUCKET_PATTERN.test(bucket)) return null;
    if (!objectPath || !DTS_ATTACHMENT_PATH_PATTERN.test(objectPath)) return null;
    return parsed.toString();
  } catch (_error) {
    return null;
  }
}

function normalizeDtsAttachmentUploadedAt(value: unknown): string | null {
  if (!value) return null;
  if (value instanceof admin.firestore.Timestamp) {
    return value.toDate().toISOString();
  }
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value.toISOString();
  }
  const parsed = new Date(String(value));
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

function isBcryptHash(hash: string): boolean {
  return /^\$2[aby]\$\d{2}\$/.test(hash);
}

async function hashTrackingPin(pin: string): Promise<string> {
  return bcrypt.hash(pin, DTS_PIN_BCRYPT_ROUNDS);
}

async function verifyTrackingPin(pin: string, data: Record<string, unknown>): Promise<boolean> {
  const hash = coerceString(data.pinHash) ?? coerceString(data.publicPinHash) ?? "";
  if (!hash) return false;
  if (isBcryptHash(hash)) {
    return bcrypt.compare(pin, hash);
  }
  return legacyPinHashFromDoc(pin, data) === hash;
}

function trackingAttemptDocId(trackingNo: string): string {
  return trackingNo.toUpperCase().replace(/[^A-Z0-9_-]/g, "_");
}

function contextUid(context: TrackingLookupContext): string {
  return context.auth?.uid?.trim() || "anon";
}

function contextIpHash(context: TrackingLookupContext): string {
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
  context: TrackingLookupContext
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
  context: TrackingLookupContext
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
  context: TrackingLookupContext
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

  let createdAt: number | null = null;
  if (dataRow.createdAt instanceof admin.firestore.Timestamp) {
    createdAt = dataRow.createdAt.toMillis();
  }

  let updatedAt: number | null = null;
  if (dataRow.updatedAt instanceof admin.firestore.Timestamp) {
    updatedAt = dataRow.updatedAt.toMillis();
  } else if (dataRow.createdAt instanceof admin.firestore.Timestamp) {
    updatedAt = dataRow.createdAt.toMillis();
  }

  const status = (dataRow.status ?? "RECEIVED").toString();
  return {
    trackingNo,
    trackingNumber: trackingNo,
    title,
    status,
    createdAt,
    updatedAt,
    lastUpdated: updatedAt,
    currentOfficeName,
    instructions: dtsInstructions(status),
  };
}

function sanitizeTrackingTimelineEntry(
  row: Record<string, unknown>
): Record<string, unknown> | null {
  const notePublic = coerceString(row.notePublic);
  if (!notePublic) return null;
  const actionType = coerceString(row.actionType) ?? dtsEventLabel(coerceString(row.type) ?? "UPDATE");
  const officeName =
    coerceString(row.officeName) ??
    coerceString(row.toOfficeName) ??
    coerceString(row.toOfficeId) ??
    coerceString(row.fromOfficeName) ??
    coerceString(row.fromOfficeId) ??
    "";
  const timestamp = row.createdAt instanceof admin.firestore.Timestamp
    ? row.createdAt.toMillis()
    : (row.timestamp instanceof admin.firestore.Timestamp
      ? row.timestamp.toMillis()
      : null);

  return {
    timestamp,
    actionType,
    officeName,
    notePublic,
  };
}

async function loadPublicTrackingTimeline(
  docRef: admin.firestore.DocumentReference,
  limitRows = 20
): Promise<Record<string, unknown>[]> {
  const timelineSnap = await docRef
    .collection("timeline")
    .orderBy("createdAt", "desc")
    .limit(Math.max(1, Math.min(50, limitRows)))
    .get();
  return timelineSnap.docs
    .map((item) => sanitizeTrackingTimelineEntry(item.data() ?? {}))
    .filter((item): item is Record<string, unknown> => item != null);
}

async function verifyPinWithRateLimit(
  trackingNo: string,
  pin: string,
  data: Record<string, unknown>,
  context: TrackingLookupContext
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

  const valid = await verifyTrackingPin(pin, data);
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

  throw invalidTrackingCredentialsError();
}

function dtsEventLabel(type: string): string {
  switch ((type || "").toUpperCase()) {
    case "CREATED":
      return "Created";
    case "DOCUMENT_INTAKE":
      return "Document intake";
    case "DOCUMENT_CREATED":
      return "Document created";
    case "DOCUMENT_FINALIZED":
      return "Document finalized";
    case "DOCUMENT_ROUTED":
      return "Routed";
    case "TRANSFER_INITIATED":
      return "Transfer initiated";
    case "TRANSFER_CONFIRMED":
      return "Transfer confirmed";
    case "TRANSFER_CANCELLED":
      return "Transfer cancelled";
    case "TRANSFER_REJECTED":
      return "Transfer rejected";
    case "DOCUMENT_RECEIVED":
      return "Received";
    case "STATUS_CHANGED":
      return "Status changed";
    case "DOCUMENT_GENERATED":
      return "Generated";
    case "DOCUMENT_REGENERATED":
      return "Regenerated";
    case "DOCUMENT_REPRINTED":
      return "Reprinted";
    case "RETURNED":
      return "Transfer returned";
    case "RELEASED":
      return "Released";
    case "ARCHIVED":
      return "Archived";
    case "DOCUMENT_VOIDED":
    case "VOIDED":
      return "Voided";
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

  const ref = db.collection("users").doc(uid);
  const snapshot = await ref.get();
  if (snapshot.exists && snapshot.data()?.role) {
    // avoid overwriting role/office when already provisioned via admin flow
    return;
  }

  await ref.set(
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
export const getMyClaims = protectedCallableFunctions.https.onCall(async (_data, context) => {
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
export const getServerTime = protectedCallableFunctions.https.onCall(async (_data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "Auth required.");
  }
  const now = new Date();
  return {
    epochMs: now.getTime(),
    iso: now.toISOString(),
  };
});

async function queryCount(queryRef: FirebaseFirestore.Query): Promise<number> {
  const snap = await queryRef.count().get();
  return Number(snap.data().count ?? 0);
}

async function unionCount(candidates: FirebaseFirestore.Query[]): Promise<number> {
  if (candidates.length === 0) {
    return 0;
  }

  const ids = new Set<string>();
  for (const queryRef of candidates) {
    const snapshot = await queryRef.get();
    snapshot.docs.forEach((docSnapshot) => {
      ids.add(docSnapshot.id);
    });
  }
  return ids.size;
}

async function collectQueryRows(
  candidates: FirebaseFirestore.Query[]
): Promise<Map<string, FirebaseFirestore.DocumentData>> {
  const rows = new Map<string, FirebaseFirestore.DocumentData>();
  for (const queryRef of candidates) {
    const snapshot = await queryRef.get();
    snapshot.docs.forEach((docSnapshot) => {
      if (!rows.has(docSnapshot.id)) {
        rows.set(docSnapshot.id, docSnapshot.data() ?? {});
      }
    });
  }
  return rows;
}

const ACTIVE_DASHBOARD_STATUSES = new Set([
  "submitted",
  "acknowledged",
  "in_review",
  "assigned",
  "in_progress",
]);

function toReportStatus(value: unknown): string {
  const raw = (coerceString(value) ?? "").toLowerCase().replace(/\s+/g, "_");
  return raw || "submitted";
}

function sortReportRowsByActionTime(
  rows: Array<Record<string, unknown>>
): Array<Record<string, unknown>> {
  return [...rows].sort((a, b) => {
    const aTime = parseEpochMs(a.lastActionAt ?? a.updatedAt ?? a.createdAt);
    const bTime = parseEpochMs(b.lastActionAt ?? b.updatedAt ?? b.createdAt);
    return bTime - aTime;
  });
}

function buildDashboardActivityFromReports(
  rows: Array<Record<string, unknown>>,
  limitCount = 8
): Array<Record<string, unknown>> {
  return sortReportRowsByActionTime(rows)
    .slice(0, limitCount)
    .map((row) => {
      const status = toReportStatus(row.status);
      const latestTimeline =
        row.latestTimelineEvent && typeof row.latestTimelineEvent === "object"
          ? (row.latestTimelineEvent as Record<string, unknown>)
          : null;
      const timelineType = coerceString(latestTimeline?.type);
      const timelineNotes = coerceString(latestTimeline?.notes);
      const toStatus = coerceString(latestTimeline?.toStatus) ?? status;
      const actionDisplay = timelineNotes
        ?? (timelineType
          ? timelineType.replace(/_/g, " ").trim()
          : `Status: ${toStatus.replace(/_/g, " ").trim()}`);
      const timestamp = toIsoString(
        latestTimeline?.createdAt ??
        row.lastActionAt ??
        row.updatedAt ??
        row.createdAt
      );

      return {
        id: `${coerceString(row.id) ?? ""}:${timestamp ?? "0"}`,
        timestamp,
        actorDisplay:
          coerceString(latestTimeline?.actorName) ??
          coerceString(row.lastActionByName) ??
          coerceString(latestTimeline?.actorRole) ??
          coerceString(row.lastActionByRole) ??
          "system",
        actionDisplay,
        entityDisplay:
          coerceString(row.referenceNo) ??
          coerceString(row.trackingNumber) ??
          coerceString(row.title) ??
          coerceString(row.id) ??
          "report",
        status,
        officeId:
          coerceString(row.officeId) ??
          coerceString(row.currentOfficeId) ??
          coerceString(row.assignedOfficeId),
      };
    });
}

function buildWorkQueuePreviewFromReports(
  rows: Array<Record<string, unknown>>,
  limitCount = 6
): Array<Record<string, unknown>> {
  return sortReportRowsByActionTime(rows)
    .slice(0, limitCount)
    .map((row) => ({
      id: coerceString(row.id) ?? "",
      title:
        coerceString(row.title) ??
        coerceString(row.subject) ??
        coerceString(row.concern) ??
        "Untitled report",
      referenceNo:
        coerceString(row.referenceNo) ??
        coerceString(row.trackingNumber) ??
        coerceString(row.id) ??
        "",
      status: toReportStatus(row.status),
      lane: getPublicReportLane(row),
      officeId:
        coerceString(row.officeId) ??
        coerceString(row.currentOfficeId) ??
        coerceString(row.assignedOfficeId),
      assignedToUid: coerceString(row.assignedToUid),
      updatedAt: toIsoString(row.updatedAt ?? row.createdAt),
      latestTimelineEvent:
        row.latestTimelineEvent && typeof row.latestTimelineEvent === "object"
          ? {
              ...(row.latestTimelineEvent as Record<string, unknown>),
              createdAt: toIsoString(
                (row.latestTimelineEvent as Record<string, unknown>).createdAt
              ),
            }
          : null,
    }));
}

/**
 * =========================
 * ADMIN DASHBOARD SUMMARY
 * =========================
 * Server-side scoped counts so admin UI does not depend on client-side
 * Firestore aggregation permissions.
 */
export const adminDashboardSummary = protectedCallableFunctions.https.onCall(async (_data, context) => {
  const actor = await requireStaffContext(context);

  const reportsRef = db.collection("reports");
  const dtsRef = db.collection("dts_documents");
  const usersRef = db.collection("users");

  const isSuperAdmin = actor.role === "super_admin";
  const hasMunicipalAdminAccess = isMunicipalAdminRole(actor.role);
  const scopedOfficeId = coerceString(actor.officeId);

  let announcementsCount = 0;
  for (const collectionName of POST_COLLECTIONS) {
    const postsRef = db.collection(collectionName);
    if (hasMunicipalAdminAccess) {
      announcementsCount += await queryCount(postsRef);
      continue;
    }

    const postCandidates: FirebaseFirestore.Query[] = [];
    if (scopedOfficeId) {
      postCandidates.push(postsRef.where("officeId", "==", scopedOfficeId));
    }
    postCandidates.push(postsRef.where("createdByUid", "==", actor.uid));
    for (const statusValue of PUBLISHED_STATUS_VARIANTS) {
      postCandidates.push(postsRef.where("status", "==", statusValue));
    }
    announcementsCount += await unionCount(postCandidates);
  }

  let reportsCount = 0;
  let reportRows = new Map<string, FirebaseFirestore.DocumentData>();
  if (hasMunicipalAdminAccess) {
    reportRows = await collectQueryRows([reportsRef]);
    reportsCount = reportRows.size;
  } else {
    const reportCandidates: FirebaseFirestore.Query[] = [];
    if (scopedOfficeId) {
      reportCandidates.push(reportsRef.where("officeId", "==", scopedOfficeId));
      reportCandidates.push(reportsRef.where("assignedOfficeId", "==", scopedOfficeId));
      reportCandidates.push(reportsRef.where("currentOfficeId", "==", scopedOfficeId));
    }
    reportCandidates.push(reportsRef.where("assignedToUid", "==", actor.uid));
    reportCandidates.push(reportsRef.where("createdByUid", "==", actor.uid));
    reportRows = await collectQueryRows(reportCandidates);
    reportsCount = reportRows.size;
  }

  let dtsCount = 0;
  if (hasMunicipalAdminAccess) {
    dtsCount = await queryCount(dtsRef);
  } else {
    const dtsCandidates: FirebaseFirestore.Query[] = [];
    if (scopedOfficeId) {
      dtsCandidates.push(dtsRef.where("currentOfficeId", "==", scopedOfficeId));
    }
    dtsCandidates.push(dtsRef.where("currentCustodianUid", "==", actor.uid));
    dtsCandidates.push(dtsRef.where("createdByUid", "==", actor.uid));
    dtsCount = await unionCount(dtsCandidates);
  }

  let usersCount: number | null = null;
  if (isSuperAdmin) {
    usersCount = await queryCount(usersRef);
  }

  const reportValues = Array.from(reportRows.entries()).map(([id, row]) => ({
    id,
    ...(row ?? {}),
  })) as Array<Record<string, unknown>>;
  const visibleActiveReports = reportValues.filter((rawRow) => {
    const status = toReportStatus(rawRow.status);
    return ACTIVE_DASHBOARD_STATUSES.has(status);
  });
  const myActiveCount = visibleActiveReports.filter(
    (row) => coerceString((row ?? {}).assignedToUid) === actor.uid
  ).length;
  const officeUnassignedCount = scopedOfficeId
    ? visibleActiveReports.filter((rawRow) => {
      const row = (rawRow ?? {}) as Record<string, unknown>;
      const rowOfficeId = coerceString(row.officeId);
      const rowCurrentOfficeId = coerceString(row.currentOfficeId);
      const rowAssignedOfficeId = coerceString(row.assignedOfficeId);
      const inOfficeScope = rowOfficeId === scopedOfficeId
        || rowCurrentOfficeId === scopedOfficeId
        || rowAssignedOfficeId === scopedOfficeId;
      return inOfficeScope && !coerceString(row.assignedToUid);
    }).length
    : 0;
  const emergencyActiveCount = visibleActiveReports.filter((rawRow) => {
    const lane = (coerceString(rawRow.lane) ?? "").toLowerCase();
    return lane === "emergency" || !!coerceString(rawRow.emergencyType);
  }).length;
  const activity = buildDashboardActivityFromReports(reportValues, 8);
  const workQueuePreview = buildWorkQueuePreviewFromReports(visibleActiveReports, 6);

  return {
    role: actor.role,
    officeId: scopedOfficeId,
    counts: {
      announcements: announcementsCount,
      reports: reportsCount,
      dtsDocuments: dtsCount,
      users: usersCount,
    },
    workload: {
      myActiveCount,
      officeUnassignedCount,
      visibleBacklogCount: visibleActiveReports.length,
      emergencyActiveCount,
    },
    activity,
    workQueuePreview,
    notes: {
      announcementsSource: POST_COLLECTIONS.join("+"),
    },
  };
});

type ReportsCursor = {
  cursorUpdatedAt: string;
  cursorId: string;
};

function normalizeReportsCursorInput(
  payload: Record<string, unknown>
): ReportsCursor | null {
  const cursorUpdatedAt = coerceString(payload.cursorUpdatedAt);
  const cursorId = coerceString(payload.cursorId);
  if (!cursorUpdatedAt || !cursorId) {
    return null;
  }
  const cursorEpoch = parseEpochMs(cursorUpdatedAt);
  if (!cursorEpoch) {
    return null;
  }
  return {
    cursorUpdatedAt: new Date(cursorEpoch).toISOString(),
    cursorId,
  };
}

function toCursorEpoch(cursor: ReportsCursor | null): number {
  return cursor ? parseEpochMs(cursor.cursorUpdatedAt) : 0;
}

async function collectScopedReportRowsForActor(
  actor: StaffContext
): Promise<Array<Record<string, unknown>>> {
  const reportsRef = db.collection("reports");
  const rows = new Map<string, FirebaseFirestore.DocumentData>();
  const queries: FirebaseFirestore.Query[] = [];

  if (isMunicipalAdminRole(actor.role)) {
    const snapshot = await reportsRef.get();
    snapshot.docs.forEach((doc) => rows.set(doc.id, doc.data() ?? {}));
  } else {
    if (actor.officeId) {
      queries.push(reportsRef.where("officeId", "==", actor.officeId));
      queries.push(reportsRef.where("assignedOfficeId", "==", actor.officeId));
      queries.push(reportsRef.where("currentOfficeId", "==", actor.officeId));
    }
    queries.push(reportsRef.where("assignedToUid", "==", actor.uid));
    queries.push(reportsRef.where("createdByUid", "==", actor.uid));

    for (const queryRef of queries) {
      const snapshot = await queryRef.get();
      snapshot.docs.forEach((doc) => {
        if (!rows.has(doc.id)) {
          rows.set(doc.id, doc.data() ?? {});
        }
      });
    }
  }

  return Array.from(rows.entries())
    .map(([id, row]) => serializeReportRow(id, row))
    .sort((a, b) => {
      const aTime = parseEpochMs((a.updatedAt as unknown) ?? a.createdAt);
      const bTime = parseEpochMs((b.updatedAt as unknown) ?? b.createdAt);
      if (bTime !== aTime) {
        return bTime - aTime;
      }
      return String(b.id).localeCompare(String(a.id));
    });
}

function pageScopedReportRows(
  sortedRows: Array<Record<string, unknown>>,
  listLimit: number,
  cursor: ReportsCursor | null
): {
  items: Array<Record<string, unknown>>;
  nextCursor: ReportsCursor | null;
} {
  const cursorEpoch = toCursorEpoch(cursor);
  const cursorId = cursor?.cursorId ?? "";
  const filteredRows = cursorEpoch > 0 && cursorId
    ? sortedRows.filter((row) => {
      const rowEpoch = parseEpochMs((row.updatedAt as unknown) ?? row.createdAt);
      if (rowEpoch < cursorEpoch) {
        return true;
      }
      if (rowEpoch > cursorEpoch) {
        return false;
      }
      return String(row.id).localeCompare(cursorId) < 0;
    })
    : sortedRows;

  const hasMore = filteredRows.length > listLimit;
  const items = filteredRows.slice(0, listLimit);
  const lastRow = items.length > 0 ? items[items.length - 1] : null;
  const nextCursor = hasMore && lastRow
    ? {
        cursorUpdatedAt:
          String((lastRow.updatedAt as string) || (lastRow.createdAt as string) || new Date().toISOString()),
        cursorId: String(lastRow.id),
      }
    : null;
  return {items, nextCursor};
}

async function loadScopedReportsForActor(
  actor: StaffContext,
  rawLimit: number,
  options: {
    cursor?: ReportsCursor | null;
  } = {}
): Promise<{
  items: Array<Record<string, unknown>>;
  scope: { role: NormalizedRole; officeId: string | null };
  nextCursor: ReportsCursor | null;
  generatedAt: string;
}> {
  const listLimit = Math.max(20, Math.min(500, rawLimit));
  const reportsRef = db.collection("reports");
  const cursor = options.cursor ?? null;
  const cursorEpoch = toCursorEpoch(cursor);
  const cursorId = cursor?.cursorId ?? "";

  if (isMunicipalAdminRole(actor.role)) {
    try {
      let municipalQuery = reportsRef
        .orderBy("updatedAt", "desc")
        .orderBy(admin.firestore.FieldPath.documentId(), "desc");
      if (cursorEpoch > 0 && cursorId) {
        municipalQuery = municipalQuery.startAfter(
          admin.firestore.Timestamp.fromMillis(cursorEpoch),
          cursorId
        );
      }
      const snapshot = await municipalQuery.limit(listLimit + 1).get();
      const rows = snapshot.docs.map((doc) =>
        serializeReportRow(doc.id, doc.data() ?? {})
      );
      const hasMore = rows.length > listLimit;
      const items = rows.slice(0, listLimit);
      const lastRow = items.length > 0 ? items[items.length - 1] : null;
      return {
        items,
        scope: {
          role: actor.role,
          officeId: actor.officeId ?? null,
        },
        nextCursor:
          hasMore && lastRow
            ? {
                cursorUpdatedAt:
                  String(
                    (lastRow.updatedAt as string) ||
                      (lastRow.createdAt as string) ||
                      new Date().toISOString()
                  ),
                cursorId: String(lastRow.id),
              }
            : null,
        generatedAt: new Date().toISOString(),
      };
    } catch (error) {
      const code = String((error as { code?: unknown })?.code ?? "").toLowerCase();
      if (code.includes("failed-precondition")) {
        throw new functions.https.HttpsError(
          "failed-precondition",
          "Required reports index is missing. Deploy Firestore indexes before using adminReportsBootstrap."
        );
      }
      throw error;
    }
  }

  /*
   * Office-scoped report reads intentionally union all scope branches before
   * cursor slicing so pagination remains complete and no branch gets dropped by
   * a branch-local limit cap.
   */
  const sortedRows = await collectScopedReportRowsForActor(actor);
  const {items, nextCursor} = pageScopedReportRows(sortedRows, listLimit, cursor);

  return {
    items,
    scope: {
      role: actor.role,
      officeId: actor.officeId ?? null,
    },
    nextCursor,
    generatedAt: new Date().toISOString(),
  };
}

function dtsSavedDocumentSortTimestamp(
  dataRow: Record<string, unknown>
): number {
  if (dataRow.updatedAt instanceof admin.firestore.Timestamp) {
    return dataRow.updatedAt.toMillis();
  }
  if (dataRow.createdAt instanceof admin.firestore.Timestamp) {
    return dataRow.createdAt.toMillis();
  }
  return 0;
}

function buildSanitizedSavedDocumentSummary(
  docId: string,
  dataRow: Record<string, unknown>
): Record<string, unknown> {
  const trackingNo = coerceString(dataRow.trackingNo) ?? docId;
  const sanitized = buildSanitizedTrackingResult(trackingNo, dataRow);
  return {
    docId,
    ...sanitized,
  };
}

async function loadScopedReportViewCountsForActor(
  actor: StaffContext
): Promise<Record<string, number>> {
  const rows = await collectScopedReportRowsForActor(actor);
  return buildScopedReportViewCounts(rows, actor);
}

async function loadScopedReportAssigneesForActor(
  actor: StaffContext
): Promise<{
  items: Array<{
    uid: string;
    displayName: string;
    email: string;
    role: NormalizedRole;
    officeId: string;
    isActive: boolean;
  }>;
  scope: { role: NormalizedRole; officeId: string | null };
}> {
  const usersRef = db.collection("users");
  let usersQuery: FirebaseFirestore.Query;
  if (isMunicipalAdminRole(actor.role)) {
    usersQuery = usersRef
      .where("role", "in", ["super_admin", "admin", "office_admin", "moderator"])
      .limit(300);
  } else if (actor.officeId) {
    usersQuery = usersRef
      .where("officeId", "==", actor.officeId)
      .where("role", "in", ["admin", "office_admin", "moderator"])
      .limit(300);
  } else {
    usersQuery = usersRef
      .where(admin.firestore.FieldPath.documentId(), "==", actor.uid)
      .limit(1);
  }

  const snapshot = await usersQuery.get();
  const items = snapshot.docs
    .map((doc) => {
      const row = doc.data() ?? {};
      return {
        uid: doc.id,
        displayName:
          coerceString(row.displayName) ??
          coerceString(row.name) ??
          coerceString(row.email) ??
          doc.id,
        email: coerceString(row.email) ?? "",
        role: normalizeRole(row.role),
        officeId: coerceString(row.officeId) ?? "",
        isActive: coerceBool(row.isActive, true),
      };
    })
    .filter((row) => row.isActive)
    .sort((a, b) => a.displayName.localeCompare(b.displayName));

  return {
    items,
    scope: {
      role: actor.role,
      officeId: actor.officeId ?? null,
    },
  };
}

function buildScopedReportViewCounts(
  rows: Array<Record<string, unknown>>,
  actor: StaffContext
): Record<string, number> {
  const activeStatuses = ACTIVE_DASHBOARD_STATUSES;
  const archiveStatuses = new Set(["resolved", "closed", "rejected"]);
  const active = rows.filter((row) => activeStatuses.has(toReportStatus(row.status)));
  const archive = rows.filter((row) => archiveStatuses.has(toReportStatus(row.status)));
  const myQueue = active.filter((row) => coerceString(row.assignedToUid) === actor.uid);
  const officeQueue = active.filter((row) => !coerceString(row.assignedToUid));
  const emergencyInbox = active.filter((row) => {
    const lane = (coerceString(row.lane) ?? "").toLowerCase();
    return lane === "emergency" || !!coerceString(row.emergencyType);
  });
  const overdue = emergencyInbox.filter((row) => {
    const deadline = parseEpochMs(
      (row.sla as Record<string, unknown> | undefined)?.assignBy ??
      (row.sla as Record<string, unknown> | undefined)?.acknowledgeBy
    );
    return deadline > 0 && deadline < Date.now();
  });

  return {
    allReports: rows.length,
    allActive: active.length,
    archive: archive.length,
    myQueue: myQueue.length,
    myActive: myQueue.length,
    officeQueue: officeQueue.length,
    emergencyInbox: emergencyInbox.length,
    overdue: overdue.length,
  };
}

async function adminListReportsScopedHandler(
  data: unknown,
  context: CallableContextLike
) {
  const actor = await requireStaffContext(context);
  const payload = (data && typeof data === "object")
    ? (data as Record<string, unknown>)
    : {};
  const requestedLane = normalizeRequestedPublicReportLane(payload.lane);
  await requireFeatureEnabled(requestedLane === "feedback" ? "feedback" : "reports");
  const rawLimit = typeof payload.limit === "number" ? Math.floor(payload.limit) : 120;
  const cursor = normalizeReportsCursorInput(payload);
  const response = await loadScopedReportsForActor(actor, rawLimit, {cursor});
  if (!requestedLane || !Array.isArray(response?.items)) {
    return response;
  }
  return {
    ...response,
    items: response.items.filter((item) => getPublicReportLane(
      (item && typeof item === "object") ? (item as Record<string, unknown>) : {}
    ) === requestedLane),
  };
}

export const adminListReportsScoped = protectedCallableFunctions.https.onCall(async (data, context) =>
  adminListReportsScopedHandler(data, context)
);

export const adminListReportAssignees = protectedCallableFunctions.https.onCall(async (data, context) => {
  const actor = await requireStaffContext(context);
  const payload = (data && typeof data === "object")
    ? (data as Record<string, unknown>)
    : {};
  const requestedLane = normalizeRequestedPublicReportLane(payload.lane);
  await requireFeatureEnabled(requestedLane === "feedback" ? "feedback" : "reports");
  return loadScopedReportAssigneesForActor(actor);
});

/**
 * Reports bootstrap bundles scoped tickets + assignees + counters in one
 * callable so the workspace can load in a single round-trip.
 */
async function adminReportsBootstrapHandler(
  data: unknown,
  context: CallableContextLike
) {
  const actor = await requireStaffContext(context);
  await requireFeatureEnabled("reports");
  const payload = (data && typeof data === "object")
    ? (data as Record<string, unknown>)
    : {};
  const rawLimit = typeof payload.limit === "number" ? Math.floor(payload.limit) : 120;
  const listLimit = Math.max(20, Math.min(500, rawLimit));
  const cursor = normalizeReportsCursorInput(payload);

  const [reportsPayload, assigneesPayload, viewCounts] = await Promise.all([
    loadScopedReportsForActor(actor, listLimit, {cursor}),
    canAssignReportsRole(actor.role)
      ? loadScopedReportAssigneesForActor(actor)
      : Promise.resolve({
          items: [],
          scope: {
            role: actor.role,
            officeId: actor.officeId ?? null,
          },
        }),
    loadScopedReportViewCountsForActor(actor),
  ]);

  return {
    reports: reportsPayload.items,
    items: reportsPayload.items,
    assignees: assigneesPayload.items,
    viewCounts,
    scope: reportsPayload.scope,
    nextCursor: reportsPayload.nextCursor,
    generatedAt: reportsPayload.generatedAt,
  };
}

export const adminReportsBootstrap = protectedCallableFunctions.https.onCall(async (data, context) =>
  adminReportsBootstrapHandler(data, context)
);

type StaffThreadMember = {
  uid: string;
  displayName: string;
  role: NormalizedRole;
  officeId: string | null;
  officeName: string | null;
  presence: Record<string, unknown>;
};

function buildStaffThreadMember(
  uid: string,
  profileData: Record<string, unknown>,
  fallbackRole?: NormalizedRole,
  fallbackOfficeId?: string | null,
  fallbackOfficeName?: string | null
): StaffThreadMember {
  return {
    uid,
    displayName:
      coerceString(profileData.displayName) ??
      coerceString(profileData.name) ??
      coerceString(profileData.email) ??
      uid,
    role: fallbackRole ?? normalizeRole(profileData.role),
    officeId: fallbackOfficeId ?? coerceString(profileData.officeId),
    officeName: fallbackOfficeName ?? coerceString(profileData.officeName),
    presence: serializeStaffPresence(profileData),
  };
}

function staffThreadIdFor(uidA: string, uidB: string): string {
  const [first, second] = [uidA, uidB].map((value) => value.trim()).sort();
  return `dm_${sha256(`${first}:${second}`).slice(0, 24)}`;
}

function canActorDirectMessageTarget(
  actor: StaffContext,
  target: StaffThreadMember
): boolean {
  if (actor.uid === target.uid) {
    return false;
  }

  if (!isStaffRole(target.role)) {
    return false;
  }

  if (actor.role === "super_admin" || actor.role === "admin") {
    return true;
  }

  if (target.role === "super_admin" || target.role === "admin") {
    return true;
  }

  return actor.officeId != null && target.officeId != null && actor.officeId === target.officeId;
}

function threadReadMap(
  row: Record<string, unknown>
): Record<string, unknown> {
  const raw = row.lastReadAtByUid;
  return raw && typeof raw === "object"
    ? (raw as Record<string, unknown>)
    : {};
}

function threadDeliveredMap(
  row: Record<string, unknown>
): Record<string, unknown> {
  const raw = row.lastDeliveredAtByUid;
  return raw && typeof raw === "object"
    ? (raw as Record<string, unknown>)
    : {};
}

function threadUnreadCountMap(
  row: Record<string, unknown>
): Record<string, unknown> {
  const raw = row.unreadCountByUid;
  return raw && typeof raw === "object"
    ? (raw as Record<string, unknown>)
    : {};
}

function threadTypingMap(
  row: Record<string, unknown>
): Record<string, unknown> {
  const raw = row.typingByUid;
  return raw && typeof raw === "object"
    ? (raw as Record<string, unknown>)
    : {};
}

function unreadCountForUid(
  row: Record<string, unknown>,
  uid: string
): number {
  const raw = threadUnreadCountMap(row)[uid];
  const value = Number(raw ?? 0);
  if (!Number.isFinite(value) || value <= 0) {
    return 0;
  }
  return Math.floor(value);
}

function serializeThreadPeerTyping(
  actorUid: string,
  peerUid: string,
  row: Record<string, unknown>
): Record<string, unknown> {
  if (!peerUid || peerUid === actorUid) {
    return {isTyping: false, updatedAt: null};
  }
  const raw = threadTypingMap(row)[peerUid];
  const typingData = raw && typeof raw === "object"
    ? (raw as Record<string, unknown>)
    : {};
  const updatedAtMs = parseEpochMs(typingData.updatedAt);
  const isTyping =
    coerceBool(typingData.isTyping, false) &&
    updatedAtMs > 0 &&
    (Date.now() - updatedAtMs) <= 10000;
  return {
    isTyping,
    updatedAt: isTyping ? toIsoString(typingData.updatedAt) : null,
  };
}

function serializeStaffPresence(
  profileData: Record<string, unknown>
): Record<string, unknown> {
  const state = coerceString(profileData.staffPresenceState) ?? "offline";
  const lastSeenAt = toIsoString(profileData.staffPresenceLastSeenAt);
  const lastSeenMs = parseEpochMs(profileData.staffPresenceLastSeenAt);
  const isOnline =
    state === "online" &&
    lastSeenMs > 0 &&
    (Date.now() - lastSeenMs) <= (2 * 60 * 1000);

  return {
    state,
    isOnline,
    lastSeenAt,
  };
}

async function uploadStaffMessageAttachment(
  threadId: string,
  senderUid: string,
  dataUrl: string,
  fileBaseName: string
): Promise<Record<string, unknown> | null> {
  const trimmed = String(dataUrl ?? "").trim();
  if (!trimmed) return null;
  const match = trimmed.match(/^data:([^;]+);base64,(.+)$/);
  if (!match) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Attachment must be a valid data URL."
    );
  }
  const contentType = match[1].trim().toLowerCase();
  // Voice-note uploads reuse the same attachment pipeline to keep the UI simple.
  const allowedTypes = ["image/", "application/pdf", "audio/"];
  if (!allowedTypes.some((allowed) => contentType.startsWith(allowed))) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Only image, PDF, and audio attachments are supported."
    );
  }
  const buffer = Buffer.from(match[2], "base64");
  if (buffer.length > (5 * 1024 * 1024)) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Attachment is too large."
    );
  }

  const safeName = (fileBaseName || "attachment")
    .replace(/[^a-z0-9._-]/gi, "_")
    .toLowerCase();
  const extension = contentType === "application/pdf"
    ? "pdf"
    : (contentType.split("/")[1] || "bin");
  const storagePath = `staff_threads/${threadId}/${senderUid}_${Date.now()}_${safeName}.${extension}`;
  const bucket = admin.storage().bucket();
  const file = bucket.file(storagePath);
  await file.save(buffer, {
    resumable: false,
    metadata: {
      contentType,
      cacheControl: "private,max-age=3600",
    },
  });
  const [url] = await file.getSignedUrl({
    action: "read",
    expires: "2100-01-01",
  });
  return {
    name: `${safeName}.${extension}`,
    url,
    path: storagePath,
    contentType,
    size: buffer.length,
  };
}

function serializeStaffThreadForActor(
  actorUid: string,
  threadId: string,
  row: Record<string, unknown>
): Record<string, unknown> {
  const memberIds = Array.isArray(row.memberIds)
    ? row.memberIds.map((value) => String(value || "").trim()).filter((value) => value.length > 0)
    : [];
  const profileMap = row.memberProfiles && typeof row.memberProfiles === "object"
    ? (row.memberProfiles as Record<string, unknown>)
    : {};
  const peerUid = memberIds.find((value) => value !== actorUid) ?? actorUid;
  const peerRaw = profileMap[peerUid];
  const peerData = peerRaw && typeof peerRaw === "object"
    ? (peerRaw as Record<string, unknown>)
    : {};
  const unreadCount = unreadCountForUid(row, actorUid);

  return {
    threadId,
    targetUid: peerUid,
    targetName: coerceString(peerData.displayName) ?? coerceString(peerData.name) ?? peerUid,
    targetRole: normalizeRole(peerData.role),
    targetOfficeId: coerceString(peerData.officeId),
    targetOfficeName: coerceString(peerData.officeName),
    lastMessageText: coerceString(row.lastMessageText) ?? "",
    lastMessageAt: toIsoString(row.lastMessageAt),
    updatedAt: toIsoString(row.updatedAt),
    hasUnread: unreadCount > 0,
    unreadCount,
    peerTyping: serializeThreadPeerTyping(actorUid, peerUid, row),
    targetPresence: serializeStaffPresence(peerData),
  };
}

async function staffListDirectContactsHandler(
  _data: unknown,
  context: CallableContextLike
) {
  const actor = await requireStaffContext(context);
  await requireFeatureEnabled("messages");

  const usersRef = db.collection("users");
  const rows = new Map<string, StaffThreadMember>();

  async function collectSnapshot(snapshot: FirebaseFirestore.QuerySnapshot) {
    snapshot.docs.forEach((doc) => {
      const data = (doc.data() ?? {}) as Record<string, unknown>;
      const member = buildStaffThreadMember(doc.id, data);
      if (!coerceBool(data.isActive, true)) {
        return;
      }
      if (!canActorDirectMessageTarget(actor, member)) {
        return;
      }
      rows.set(doc.id, member);
    });
  }

  if (isMunicipalAdminRole(actor.role)) {
    const snapshot = await usersRef.limit(400).get();
    await collectSnapshot(snapshot);
  } else if (actor.officeId) {
    const [sameOffice, municipalStaff] = await Promise.all([
      usersRef.where("officeId", "==", actor.officeId).limit(300).get(),
      usersRef.where("role", "in", ["super_admin", "admin"]).limit(50).get(),
    ]);
    await collectSnapshot(sameOffice);
    await collectSnapshot(municipalStaff);
  }

  return {
    items: Array.from(rows.values())
      .sort((left, right) => left.displayName.localeCompare(right.displayName)),
  };
}

export const staffListDirectContacts = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await staffListDirectContactsHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

async function staffListDirectThreadsHandler(
  _data: unknown,
  context: CallableContextLike
) {
  const actor = await requireStaffContext(context);
  await requireFeatureEnabled("messages");

  const snapshot = await db
    .collection("staff_threads")
    .where("memberIds", "array-contains", actor.uid)
    .limit(80)
    .get();

  const now = admin.firestore.Timestamp.now();
  const deliverableRows = snapshot.docs
    .map((doc) => ({
      doc,
      row: (doc.data() ?? {}) as Record<string, unknown>,
    }))
    .filter(({row}) => {
      if (coerceString(row.lastSenderUid) === actor.uid) {
        return false;
      }
      const lastMessageAtMs = parseEpochMs(row.lastMessageAt);
      const deliveredAtMs = parseEpochMs(threadDeliveredMap(row)[actor.uid]);
      return lastMessageAtMs > 0 && lastMessageAtMs > deliveredAtMs;
    });

  if (deliverableRows.length > 0) {
    const batch = db.batch();
    deliverableRows.forEach(({doc, row}) => {
      batch.set(doc.ref, {
        lastDeliveredAtByUid: {
          ...threadDeliveredMap(row),
          [actor.uid]: admin.firestore.FieldValue.serverTimestamp(),
        },
      }, {merge: true});
    });
    await batch.commit();
  }

  const refreshedRows = new Map<string, Record<string, unknown>>();
  deliverableRows.forEach(({doc, row}) => {
    refreshedRows.set(doc.id, {
      ...row,
      lastDeliveredAtByUid: {
        ...threadDeliveredMap(row),
        [actor.uid]: now,
      },
    });
  });

  const items = snapshot.docs
    .map((doc) => serializeStaffThreadForActor(
      actor.uid,
      doc.id,
      refreshedRows.get(doc.id) ?? ((doc.data() ?? {}) as Record<string, unknown>)
    ))
    .sort((left, right) => parseEpochMs(right.lastMessageAt) - parseEpochMs(left.lastMessageAt));

  return {items};
}

export const staffListDirectThreads = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await staffListDirectThreadsHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

async function staffListDirectMessagesHandler(
  data: unknown,
  context: CallableContextLike
) {
  const actor = await requireStaffContext(context);
  await requireFeatureEnabled("messages");

  const payload = (data && typeof data === "object")
    ? (data as Record<string, unknown>)
    : {};
  const threadId = coerceString(payload.threadId);
  if (!threadId) {
    throw new functions.https.HttpsError("invalid-argument", "threadId is required.");
  }

  const threadRef = db.collection("staff_threads").doc(threadId);
  const threadSnap = await threadRef.get();
  if (!threadSnap.exists) {
    return {items: []};
  }
  const threadData = (threadSnap.data() ?? {}) as Record<string, unknown>;
  const memberIds = Array.isArray(threadData.memberIds)
    ? threadData.memberIds.map((value) => String(value || "").trim())
    : [];
  if (!memberIds.includes(actor.uid)) {
    throw new functions.https.HttpsError("permission-denied", "You cannot open this conversation.");
  }

  const messagesSnap = await threadRef
    .collection("messages")
    .orderBy("createdAt", "desc")
    .limit(80)
    .get();

  const now = admin.firestore.Timestamp.now();
  const nextReadMap = {
    ...threadReadMap(threadData),
    [actor.uid]: now,
  };
  const nextDeliveredMap = {
    ...threadDeliveredMap(threadData),
    [actor.uid]: now,
  };
  const nextUnreadMap = {
    ...threadUnreadCountMap(threadData),
    [actor.uid]: 0,
  };

  await threadRef.set({
    lastReadAtByUid: {
      ...threadReadMap(threadData),
      [actor.uid]: admin.firestore.FieldValue.serverTimestamp(),
    },
    lastDeliveredAtByUid: {
      ...threadDeliveredMap(threadData),
      [actor.uid]: admin.firestore.FieldValue.serverTimestamp(),
    },
    unreadCountByUid: {
      ...threadUnreadCountMap(threadData),
      [actor.uid]: 0,
    },
  }, {merge: true});

  const messageBatch = db.batch();
  let hasMessageReceiptUpdates = false;
  messagesSnap.docs.forEach((doc) => {
    const row = (doc.data() ?? {}) as Record<string, unknown>;
    if (coerceString(row.senderUid) === actor.uid) {
      return;
    }
    const deliveredMap = row.deliveredAtByUid && typeof row.deliveredAtByUid === "object"
      ? (row.deliveredAtByUid as Record<string, unknown>)
      : {};
    const readMap = row.readAtByUid && typeof row.readAtByUid === "object"
      ? (row.readAtByUid as Record<string, unknown>)
      : {};
    const needsDelivered = parseEpochMs(deliveredMap[actor.uid]) <= 0;
    const needsRead = parseEpochMs(readMap[actor.uid]) <= 0;
    if (!needsDelivered && !needsRead) {
      return;
    }
    const patch: Record<string, unknown> = {};
    if (needsDelivered) {
      patch[`deliveredAtByUid.${actor.uid}`] = admin.firestore.FieldValue.serverTimestamp();
    }
    if (needsRead) {
      patch[`readAtByUid.${actor.uid}`] = admin.firestore.FieldValue.serverTimestamp();
    }
    messageBatch.set(doc.ref, patch, {merge: true});
    hasMessageReceiptUpdates = true;
  });

  if (hasMessageReceiptUpdates) {
    await messageBatch.commit();
  }

  const peerUid = memberIds.find((value) => value !== actor.uid) ?? "";
  const peerDeliveredAt = peerUid ? nextDeliveredMap[peerUid] : null;
  const peerReadAt = peerUid ? nextReadMap[peerUid] : null;
  const peerDeliveredAtMs = parseEpochMs(peerDeliveredAt);
  const peerReadAtMs = parseEpochMs(peerReadAt);

  const items = messagesSnap.docs
    .map((doc) => {
      const row = (doc.data() ?? {}) as Record<string, unknown>;
      const senderUid = coerceString(row.senderUid) ?? "";
      const createdAtMs = parseEpochMs(row.createdAt);
      const isOwn = senderUid === actor.uid;
      const deliveredAt = isOwn && createdAtMs > 0 && peerDeliveredAtMs > 0 && createdAtMs <= peerDeliveredAtMs
        ? toIsoString(peerDeliveredAt)
        : null;
      const readAt = isOwn && createdAtMs > 0 && peerReadAtMs > 0 && createdAtMs <= peerReadAtMs
        ? toIsoString(peerReadAt)
        : null;
      return {
        id: doc.id,
        text: coerceString(row.text) ?? "",
        senderUid,
        senderRole: normalizeRole(row.senderRole),
        senderName: coerceString(row.senderName) ?? "Staff User",
        createdAt: toIsoString(row.createdAt),
        deliveredAt,
        readAt,
        attachments: Array.isArray(row.attachments)
          ? row.attachments.map((item) => {
              const attachment = item && typeof item === "object"
                ? (item as Record<string, unknown>)
                : {};
              return {
                name: coerceString(attachment.name) ?? "Attachment",
                url: coerceString(attachment.url) ?? "",
                contentType: coerceString(attachment.contentType) ?? "",
              };
            }).filter((item) => item.url)
          : [],
        replyTo: row.replyTo && typeof row.replyTo === "object"
          ? {
              id: coerceString((row.replyTo as Record<string, unknown>).id) ?? "",
              senderUid: coerceString((row.replyTo as Record<string, unknown>).senderUid) ?? "",
              senderName: coerceString((row.replyTo as Record<string, unknown>).senderName) ?? "Staff User",
              text: coerceString((row.replyTo as Record<string, unknown>).text) ?? "",
              createdAt: toIsoString((row.replyTo as Record<string, unknown>).createdAt),
            }
          : null,
      };
    })
    .reverse();

  const nextThreadData = {
    ...threadData,
    lastReadAtByUid: nextReadMap,
    lastDeliveredAtByUid: nextDeliveredMap,
    unreadCountByUid: nextUnreadMap,
  };

  return {
    items,
    thread: serializeStaffThreadForActor(actor.uid, threadId, nextThreadData),
  };
}

export const staffListDirectMessages = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await staffListDirectMessagesHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

async function staffSendDirectMessageHandler(
  data: unknown,
  context: CallableContextLike
) {
  const actor = await requireStaffContext(context);
  await requireFeatureWritable("messages");

  const payload = (data && typeof data === "object")
    ? (data as Record<string, unknown>)
    : {};
  const targetUid = coerceString(payload.targetUid);
  const text = coerceString(payload.text);
  const attachmentDataUrl = coerceString(payload.attachmentDataUrl);
  const attachmentName = coerceString(payload.attachmentName) ?? "attachment";
  const rawReplyTo = payload.replyTo && typeof payload.replyTo === "object"
    ? (payload.replyTo as Record<string, unknown>)
    : null;
  const replyTo = rawReplyTo && coerceString(rawReplyTo.id)
    ? {
        id: coerceString(rawReplyTo.id) ?? "",
        senderUid: coerceString(rawReplyTo.senderUid) ?? "",
        senderName: coerceString(rawReplyTo.senderName) ?? "Staff User",
        text: (coerceString(rawReplyTo.text) ?? "").slice(0, 240),
        createdAt: coerceString(rawReplyTo.createdAt) ?? null,
      }
    : null;
  if (!targetUid) {
    throw new functions.https.HttpsError("invalid-argument", "targetUid is required.");
  }
  if (!text && !attachmentDataUrl) {
    throw new functions.https.HttpsError("invalid-argument", "Message text or attachment is required.");
  }
  if (text && text.length > 1000) {
    throw new functions.https.HttpsError("invalid-argument", "Message must be 1000 characters or fewer.");
  }

  const targetProfile = await getUserProfile(targetUid);
  if (!targetProfile.isActive) {
    throw new functions.https.HttpsError("failed-precondition", "The recipient account is inactive.");
  }

  const targetMember = buildStaffThreadMember(
    targetUid,
    targetProfile.data as Record<string, unknown>,
    targetProfile.role,
    targetProfile.officeId,
    targetProfile.officeName
  );

  if (!canActorDirectMessageTarget(actor, targetMember)) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "You are not allowed to message this staff member."
    );
  }

  const actorMember = buildStaffThreadMember(
    actor.uid,
    actor.profileData,
    actor.role,
    actor.officeId,
    actor.officeName
  );
  const threadId = staffThreadIdFor(actor.uid, targetUid);
  const threadRef = db.collection("staff_threads").doc(threadId);
  const messageRef = threadRef.collection("messages").doc();
  const attachment = attachmentDataUrl
    ? await uploadStaffMessageAttachment(threadId, actor.uid, attachmentDataUrl, attachmentName)
    : null;
  const previewText = text ?? (attachment
    ? (coerceString(attachment.contentType)?.startsWith("audio/") ? "Voice note" : `Attachment: ${attachment.name}`)
    : "");

  await db.runTransaction(async (tx) => {
    const threadSnap = await tx.get(threadRef);
    const existing = threadSnap.exists
      ? ((threadSnap.data() ?? {}) as Record<string, unknown>)
      : {};
    const existingUnreadMap = threadUnreadCountMap(existing);
    const targetUnreadCount = unreadCountForUid(existing, targetUid) + 1;
    tx.set(threadRef, {
      memberIds: [actor.uid, targetUid].sort(),
      memberProfiles: {
        [actor.uid]: actorMember,
        [targetUid]: targetMember,
      },
      lastMessageText: previewText,
      lastMessageAt: admin.firestore.FieldValue.serverTimestamp(),
      lastSenderUid: actor.uid,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      lastReadAtByUid: {
        ...threadReadMap(existing),
        [actor.uid]: admin.firestore.FieldValue.serverTimestamp(),
      },
      lastDeliveredAtByUid: {
        ...threadDeliveredMap(existing),
        [actor.uid]: admin.firestore.FieldValue.serverTimestamp(),
      },
      unreadCountByUid: {
        ...existingUnreadMap,
        [actor.uid]: 0,
        [targetUid]: targetUnreadCount,
      },
      typingByUid: {
        ...threadTypingMap(existing),
        [actor.uid]: {
          isTyping: false,
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        },
      },
      ...(threadSnap.exists ? {} : {createdAt: admin.firestore.FieldValue.serverTimestamp()}),
    }, {merge: true});

    tx.set(messageRef, {
      text: text ?? "",
      senderUid: actor.uid,
      senderRole: actor.role,
      senderName: actorMember.displayName,
      attachments: attachment ? [attachment] : [],
      replyTo,
      deliveredAtByUid: {
        [actor.uid]: admin.firestore.FieldValue.serverTimestamp(),
      },
      readAtByUid: {
        [actor.uid]: admin.firestore.FieldValue.serverTimestamp(),
      },
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  });

  await notifyUsers([targetUid], {
    title: "New staff message",
    body: `${actorMember.displayName} sent you a message.`,
    type: "staff_message",
  });

  await db.collection("users").doc(actor.uid).set({
    staffPresenceState: "online",
    staffPresenceLastSeenAt: admin.firestore.FieldValue.serverTimestamp(),
  }, {merge: true});

  return {
    success: true,
    threadId,
  };
}

export const staffSendDirectMessage = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await staffSendDirectMessageHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

async function staffSetTypingStateHandler(
  data: unknown,
  context: CallableContextLike
) {
  const actor = await requireStaffContext(context);
  await requireFeatureEnabled("messages");

  const payload = (data && typeof data === "object")
    ? (data as Record<string, unknown>)
    : {};
  const threadId = coerceString(payload.threadId);
  const isTyping = coerceBool(payload.isTyping, false);
  if (!threadId) {
    return {success: true, isTyping: false};
  }

  const threadRef = db.collection("staff_threads").doc(threadId);
  const threadSnap = await threadRef.get();
  if (!threadSnap.exists) {
    return {success: true, isTyping: false};
  }
  const threadData = (threadSnap.data() ?? {}) as Record<string, unknown>;
  const memberIds = Array.isArray(threadData.memberIds)
    ? threadData.memberIds.map((value) => String(value || "").trim())
    : [];
  if (!memberIds.includes(actor.uid)) {
    throw new functions.https.HttpsError("permission-denied", "You cannot update typing for this conversation.");
  }

  await threadRef.set({
    typingByUid: {
      ...threadTypingMap(threadData),
      [actor.uid]: {
        isTyping,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
    },
  }, {merge: true});

  return {success: true, isTyping};
}

export const staffSetTypingState = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await staffSetTypingStateHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

async function staffPingPresenceHandler(
  data: unknown,
  context: CallableContextLike
) {
  const actor = await requireStaffContext(context);
  await requireFeatureEnabled("messages");
  const payload = (data && typeof data === "object")
    ? (data as Record<string, unknown>)
    : {};
  const requestedState = coerceString(payload.state) ?? "online";
  const nextState = requestedState === "away" ? "away" : "online";

  await db.collection("users").doc(actor.uid).set({
    staffPresenceState: nextState,
    staffPresenceLastSeenAt: admin.firestore.FieldValue.serverTimestamp(),
  }, {merge: true});

  const threadSnapshot = await db
    .collection("staff_threads")
    .where("memberIds", "array-contains", actor.uid)
    .limit(80)
    .get();

  if (!threadSnapshot.empty) {
    const batch = db.batch();
    threadSnapshot.docs.forEach((doc) => {
      batch.set(doc.ref, {
        [`memberProfiles.${actor.uid}.presence`]: {
          state: nextState,
          isOnline: nextState === "online",
          lastSeenAt: admin.firestore.FieldValue.serverTimestamp(),
        },
      }, {merge: true});
    });
    await batch.commit();
  }

  return {success: true, state: nextState};
}

export const staffPingPresence = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await staffPingPresenceHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

function reportInActorScope(actor: StaffContext, row: Record<string, unknown>): boolean {
  // Super Admin and municipal Admin are municipal-wide for reports.
  if (actor.role === "super_admin" || actor.role === "admin") return true;
  // Moderator must claim or own the report before updating status.
  if (actor.role === "moderator") {
    return coerceString(row.assignedToUid) === actor.uid;
  }
  const actorOfficeId = coerceString(actor.officeId);
  if (coerceString(row.assignedToUid) === actor.uid) return true;
  if (coerceString(row.createdByUid) === actor.uid) return true;
  if (!actorOfficeId) return false;
  return [
    coerceString(row.officeId),
    coerceString(row.assignedOfficeId),
    coerceString(row.currentOfficeId),
  ].some((value) => value != null && value === actorOfficeId);
}

function reportActorMeta(actor: StaffContext, context: CallableContextLike) {
  return {
    lastActionByUid: actor.uid,
    lastActionByName: actorDisplayName(actor),
    lastActionByEmail:
      coerceString(actor.profileData.email) ??
      coerceString(context.auth?.token.email) ??
      "",
    lastActionByRole: actor.role,
    lastActionAt: admin.firestore.FieldValue.serverTimestamp(),
  };
}

function normalizeReportStatusInput(raw: unknown): string {
  const normalized = String(raw ?? "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "_");
  const allowed = new Set([
    "submitted",
    "acknowledged",
    "in_review",
    "assigned",
    "in_progress",
    "resolved",
    "closed",
    "rejected",
  ]);
  if (!allowed.has(normalized)) {
    throw new functions.https.HttpsError("invalid-argument", "Invalid report status.");
  }
  return normalized;
}

function isQueueEligibleReport(row: Record<string, unknown>): boolean {
  const assignedToUid = coerceString(row.assignedToUid);
  if (assignedToUid) {
    return false;
  }
  let status = "submitted";
  try {
    status = normalizeReportStatusInput(row.status ?? "submitted");
  } catch {
    return false;
  }
  return status === "submitted" || status === "acknowledged" || status === "in_review";
}

const CIVIL_REGISTRY_DEFAULT_OFFICE_ID = "OFFICE_OF_THE_CIVIL_REGISTRAR";
const CIVIL_REGISTRY_ALLOWED_OFFICE_IDS = [
  CIVIL_REGISTRY_DEFAULT_OFFICE_ID,
  "MUNICIPAL_LOCAL_CIVIL_REGISTRY_OFFICE",
  "MUNICIPAL_CIVIL_REGISTRY_OFFICE",
  "CIVIL_REGISTRY_OFFICE",
  "MLCRO",
] as const;
const CIVIL_REGISTRY_REQUEST_TYPES = [
  "Birth Certificate",
  "Marriage Certificate",
  "Death Certificate",
] as const;
const CIVIL_REGISTRY_STATUSES = [
  "Submitted",
  "Under Review",
  "For Compliance",
  "For Manual Verification",
  "Approved for Payment",
  "Paid",
  "For Processing / Printing",
  "Ready for Pickup",
  "Released",
  "Rejected / No Record Found",
  "Cancelled",
] as const;

const CIVIL_REGISTRY_REMARKS_REQUIRED = new Set([
  "For Compliance",
  "For Manual Verification",
  "Rejected / No Record Found",
  "Cancelled",
]);

const CIVIL_REGISTRY_ALLOWED_TRANSITIONS: Record<string, Set<string>> = {
  Submitted: new Set(["Under Review", "Cancelled"]),
  "Under Review": new Set([
    "For Compliance",
    "For Manual Verification",
    "Approved for Payment",
    "Rejected / No Record Found",
    "Cancelled",
  ]),
  "For Compliance": new Set(["Under Review", "Cancelled"]),
  "For Manual Verification": new Set([
    "Approved for Payment",
    "Rejected / No Record Found",
    "Cancelled",
  ]),
  "Approved for Payment": new Set(["Paid", "Cancelled"]),
  Paid: new Set(["For Processing / Printing"]),
  "For Processing / Printing": new Set(["Ready for Pickup"]),
  "Ready for Pickup": new Set(["Released"]),
  Released: new Set([]),
  "Rejected / No Record Found": new Set([]),
  Cancelled: new Set([]),
};

const CIVIL_REGISTRY_PUBLIC_KEYS = [
  "refNo",
  "requestType",
  "status",
  "submissionMode",
  "purpose",
  "submittedAt",
  "updatedAt",
  "estimatedReleaseDate",
] as const;

function normalizeOfficeScopeKey(value: unknown): string {
  return String(value ?? "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
}

const CIVIL_REGISTRY_ALLOWED_OFFICE_KEYS = new Set(
  CIVIL_REGISTRY_ALLOWED_OFFICE_IDS.map((value) => normalizeOfficeScopeKey(value))
);

function isCivilRegistryOfficeTagged(officeId: unknown, officeName: unknown): boolean {
  const officeIdKey = normalizeOfficeScopeKey(officeId);
  if (officeIdKey && CIVIL_REGISTRY_ALLOWED_OFFICE_KEYS.has(officeIdKey)) {
    return true;
  }

  const officeNameKey = normalizeOfficeScopeKey(officeName);
  if (!officeNameKey) {
    return false;
  }

  return (
    officeNameKey.includes("civilregistry") ||
    officeNameKey.includes("civilregistrar") ||
    officeNameKey.includes("mlcro")
  );
}

async function requireCivilRegistryStaffContext(
  context: CallableContextLike
): Promise<StaffContext> {
  const actor = await requireStaffContext(context);
  // Municipal Admin is municipal-wide and should be able to access Civil Registry tools without a Civil Registry office assignment.
  if (actor.role === "super_admin" || actor.role === "admin") {
    return actor;
  }

  const officeNameFromProfile = coerceString((actor.profileData as Record<string, unknown>)?.officeName);
  if (!isCivilRegistryOfficeTagged(actor.officeId, actor.officeName ?? officeNameFromProfile)) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Civil Registry access is limited to assigned Civil Registry moderators or office admins, municipal admins, and super admins."
    );
  }

  return actor;
}

function normalizeCivilRegistryRequestType(raw: unknown): string {
  const value = String(raw ?? "").trim().toLowerCase();
  if (value === "birth_certificate" || value === "birth certificate" || value === "birth") {
    return "Birth Certificate";
  }
  if (value === "marriage_certificate" || value === "marriage certificate" || value === "marriage") {
    return "Marriage Certificate";
  }
  if (value === "death_certificate" || value === "death certificate" || value === "death") {
    return "Death Certificate";
  }
  throw new functions.https.HttpsError("invalid-argument", "Invalid civil registry request type.");
}

function normalizeCivilRegistryStatus(raw: unknown): string {
  const value = String(raw ?? "").trim().toLowerCase().replace(/\s+/g, " ");
  for (const status of CIVIL_REGISTRY_STATUSES) {
    if (status.toLowerCase() === value) {
      return status;
    }
  }
  if (value === "rejected/no record found" || value === "rejected / no record found") {
    return "Rejected / No Record Found";
  }
  if (value === "for processing/printing" || value === "for processing / printing") {
    return "For Processing / Printing";
  }
  throw new functions.https.HttpsError("invalid-argument", "Invalid civil registry status.");
}

function normalizeCivilRegistrySubmissionMode(raw: unknown): "online" | "walk-in" {
  const value = String(raw ?? "").trim().toLowerCase();
  if (value === "walkin" || value === "walk-in" || value === "walk_in") {
    return "walk-in";
  }
  return "online";
}

function toLowerTrimmed(value: unknown): string {
  return String(value ?? "").trim().toLowerCase();
}

function requiredStringField(value: unknown, label: string): string {
  const text = String(value ?? "").trim();
  if (!text) {
    throw new functions.https.HttpsError("invalid-argument", `${label} is required.`);
  }
  return text;
}

function optionalStringField(value: unknown, max = 500): string | null {
  const text = String(value ?? "").trim();
  if (!text) return null;
  if (text.length > max) {
    throw new functions.https.HttpsError("invalid-argument", `Field exceeds ${max} characters.`);
  }
  return text;
}

function normalizeVerifierLastName(value: unknown): string {
  const text = String(value ?? "").trim().toLowerCase();
  if (text.length < 2) {
    throw new functions.https.HttpsError("invalid-argument", "Verifier last name is required.");
  }
  if (text.length > 120) {
    throw new functions.https.HttpsError("invalid-argument", "Verifier last name is too long.");
  }
  return text;
}

function validateCivilRegistryTransition(fromStatus: string, toStatus: string): void {
  if (fromStatus === toStatus) return;
  const allowed = CIVIL_REGISTRY_ALLOWED_TRANSITIONS[fromStatus];
  if (!allowed || !allowed.has(toStatus)) {
    throw new functions.https.HttpsError(
      "failed-precondition",
      `Invalid civil registry transition: ${fromStatus} -> ${toStatus}.`
    );
  }
}

function remarksRequiredForCivilRegistryStatus(status: string): boolean {
  return CIVIL_REGISTRY_REMARKS_REQUIRED.has(status);
}

function civilRegistryActorMeta(actor: StaffContext, context: CallableContextLike) {
  return {
    lastActionByUid: actor.uid,
    lastActionByName: actorDisplayName(actor),
    lastActionByEmail:
      coerceString(actor.profileData.email) ??
      coerceString(context.auth?.token.email) ??
      "",
    lastActionByRole: actor.role,
    lastActionAt: admin.firestore.FieldValue.serverTimestamp(),
  };
}

function civilRegistryHistoryRef(requestId: string): FirebaseFirestore.CollectionReference {
  return db.collection("civil_registry_requests").doc(requestId).collection("history");
}

function sanitizeCivilRegistryPublic(
  row: Record<string, unknown>
): Record<string, unknown> {
  const safe: Record<string, unknown> = {};
  for (const key of CIVIL_REGISTRY_PUBLIC_KEYS) {
    safe[key] = row[key] ?? null;
  }
  return safe;
}

function normalizeCivilRegistryDate(value: unknown): string | null {
  if (!value) return null;
  const text = String(value).trim();
  if (!text) return null;
  const date = new Date(text);
  if (Number.isNaN(date.getTime())) {
    throw new functions.https.HttpsError("invalid-argument", "Invalid date value.");
  }
  return date.toISOString();
}

function normalizeCivilRegistryPayload(
  payload: Record<string, unknown>,
  submissionMode: "online" | "walk-in"
): Record<string, unknown> {
  const normalizedSubmissionMode = normalizeCivilRegistrySubmissionMode(submissionMode);
  const requestType = normalizeCivilRegistryRequestType(payload.requestType);
  const purpose = requiredStringField(payload.purpose, "Purpose");
  const claimantTypeRaw = String(payload.claimantType ?? "").trim().toLowerCase();
  const claimantType = claimantTypeRaw === "representative" ? "representative" : "self";

  const requesterName = requiredStringField(payload.requesterName, "Requester name");
  const contactNo = requiredStringField(payload.contactNo, "Contact number");
  const email = optionalStringField(payload.email, 150);
  const relationshipToOwner = optionalStringField(payload.relationshipToOwner, 120);
  const verifierLastName = normalizeVerifierLastName(payload.verifierLastName);

  const details = payload.details && typeof payload.details === "object"
    ? (payload.details as Record<string, unknown>)
    : {};

  const birthDetails = {
    childName: optionalStringField(details.childName, 150),
    dateOfBirth: normalizeCivilRegistryDate(details.dateOfBirth),
    placeOfBirth: optionalStringField(details.placeOfBirth, 150),
    fatherName: optionalStringField(details.fatherName, 150),
    motherMaidenName: optionalStringField(details.motherMaidenName, 150),
  };
  const marriageDetails = {
    husbandName: optionalStringField(details.husbandName, 150),
    wifeMaidenName: optionalStringField(details.wifeMaidenName, 150),
    dateOfMarriage: normalizeCivilRegistryDate(details.dateOfMarriage),
    placeOfMarriage: optionalStringField(details.placeOfMarriage, 150),
  };
  const deathDetails = {
    deceasedName: optionalStringField(details.deceasedName, 150),
    dateOfDeath: normalizeCivilRegistryDate(details.dateOfDeath),
    placeOfDeath: optionalStringField(details.placeOfDeath, 150),
    relatedPersonName: optionalStringField(details.relatedPersonName, 150),
  };

  if (requestType === "Birth Certificate") {
    requiredStringField(birthDetails.childName, "Child name");
    requiredStringField(birthDetails.dateOfBirth, "Date of birth");
    requiredStringField(birthDetails.placeOfBirth, "Place of birth");
    requiredStringField(birthDetails.fatherName, "Father name");
    requiredStringField(birthDetails.motherMaidenName, "Mother maiden name");
  } else if (requestType === "Marriage Certificate") {
    requiredStringField(marriageDetails.husbandName, "Husband name");
    requiredStringField(marriageDetails.wifeMaidenName, "Wife maiden name");
    requiredStringField(marriageDetails.dateOfMarriage, "Date of marriage");
    requiredStringField(marriageDetails.placeOfMarriage, "Place of marriage");
  } else {
    requiredStringField(deathDetails.deceasedName, "Deceased name");
    requiredStringField(deathDetails.dateOfDeath, "Date of death");
    requiredStringField(deathDetails.placeOfDeath, "Place of death");
  }

  const representativeRaw = payload.representative && typeof payload.representative === "object"
    ? (payload.representative as Record<string, unknown>)
    : {};
  const representative = {
    representativeName: optionalStringField(representativeRaw.representativeName, 150),
    representativeRelationship: optionalStringField(representativeRaw.representativeRelationship, 120),
    authorizationLetterFlag: Boolean(representativeRaw.authorizationLetterFlag),
    ownerIdCopyFlag: Boolean(representativeRaw.ownerIdCopyFlag),
  };
  if (claimantType === "representative") {
    requiredStringField(representative.representativeName, "Representative name");
    requiredStringField(representative.representativeRelationship, "Representative relationship");
  }

  return {
    submissionMode: normalizedSubmissionMode,
    requestType,
    purpose,
    claimantType,
    requester: {
      name: requesterName,
      lastNameVerifier: verifierLastName,
      contactNo,
      email,
      relationshipToOwner,
      claimantType,
    },
    details: {
      birth: birthDetails,
      marriage: marriageDetails,
      death: deathDetails,
    },
    representative,
    verifierLastNameNormalized: verifierLastName,
  };
}

async function nextCivilRegistryRefNo(tx: FirebaseFirestore.Transaction): Promise<string> {
  const year = new Date().getFullYear();
  const counterRef = db.collection("civil_registry_counters").doc(String(year));
  const counterSnap = await tx.get(counterRef);
  const currentSeq = Number(counterSnap.data()?.seq ?? 0);
  const nextSeq = currentSeq + 1;
  tx.set(counterRef, {
    seq: nextSeq,
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
  }, {merge: true});
  return `CR-${year}-${String(nextSeq).padStart(6, "0")}`;
}

function civilRegistryRequestListItem(id: string, row: Record<string, unknown>) {
  return {
    id,
    refNo: coerceString(row.refNo) ?? id,
    requestType: coerceString(row.requestType) ?? "",
    submissionMode: coerceString(row.submissionMode) ?? "online",
    status: coerceString(row.status) ?? "Submitted",
    purpose: coerceString(row.purpose) ?? "",
    submittedAt: toIsoString(row.submittedAt),
    updatedAt: toIsoString(row.updatedAt),
    requesterName: coerceString((row.requester as Record<string, unknown> | undefined)?.name) ?? "",
    contactNo: coerceString((row.requester as Record<string, unknown> | undefined)?.contactNo) ?? "",
  };
}

async function adminWriteAuditLogHandler(
  data: unknown,
  context: CallableContextLike
) {
  const payload = (data && typeof data === "object")
    ? (data as Record<string, unknown>)
    : {};
  const actor = await requireStaffContext(context);
  const action = coerceString(payload.action);
  const entityType = coerceString(payload.entityType);
  const entityId = coerceString(payload.entityId);
  if (!action || !entityType || !entityId) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "action, entityType, and entityId are required."
    );
  }
  const officeId = coerceString(payload.officeId) ?? actor.officeId ?? null;
  const before = payload.before && typeof payload.before === "object" ? payload.before : null;
  const after = payload.after && typeof payload.after === "object" ? payload.after : null;
  await addAuditLog({
    action,
    entityType,
    entityId,
    officeId,
    before,
    after,
    actorUid: actor.uid,
    actorName: actorDisplayName(actor),
    actorRole: actor.role,
    actorOfficeId: actor.officeId ?? null,
    actorEmail:
      coerceString(actor.profileData.email) ??
      coerceString(context.auth?.token.email) ??
      null,
    ip: context.rawRequest?.ip ?? null,
    userAgent: context.rawRequest?.headers?.["user-agent"] ?? null,
    timestamp: admin.firestore.FieldValue.serverTimestamp(),
  });
  return {success: true};
}

export const adminWriteAuditLog = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await adminWriteAuditLogHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

async function adminUpdateSettingsHandler(
  data: unknown,
  context: CallableContextLike
) {
  const actor = await requireSuperAdminContext(context);
  const payload = data && typeof data === "object"
    ? (data as Record<string, unknown>)
    : {};
  const patch = payload.settings && typeof payload.settings === "object"
    ? payload.settings
    : payload;

  const reason = coerceString(payload.reason);
  if (reason && reason.length > 500) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "reason must be 500 characters or fewer."
    );
  }

  const settingsRef = db.collection("system").doc("settings");
  const actorName = actorDisplayName(actor);
  const actorEmail =
    coerceString(actor.profileData.email) ??
    coerceString(context.auth?.token.email) ??
    null;

  let beforeState = normalizeStoredSystemSettings(null, true);
  let afterState = beforeState;

  await db.runTransaction(async (tx) => {
    const currentSnapshot = await tx.get(settingsRef);
    beforeState = currentSnapshot.exists
      ? normalizeStoredSystemSettings(currentSnapshot.data(), true)
      : normalizeStoredSystemSettings(null, true);
    afterState = systemSettingsMergePatch(beforeState, patch);

    tx.set(
      settingsRef,
      {
        maintenance: afterState.maintenance,
        readOnly: afterState.readOnly,
        features: afterState.features,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedBy: {
          uid: actor.uid,
          role: actor.role,
          name: actorName,
          email: actorEmail,
        },
      },
      {merge: true}
    );
  });

  const responseUpdatedAt = new Date().toISOString();
  const responseSettings = {
    ...afterState,
    updatedAt: responseUpdatedAt,
    updatedBy: {
      uid: actor.uid,
      role: actor.role,
      name: actorName,
      email: actorEmail,
    },
  };

  await addDualSettingsAuditLog({
    action: "system_settings_updated",
    entityType: "system",
    entityId: "settings",
    path: "system/settings",
    officeId: actor.officeId ?? null,
    actorUid: actor.uid,
    actorRole: actor.role,
    actorOfficeId: actor.officeId ?? null,
    actorOfficeName: actor.officeName ?? null,
    actorName,
    actorEmail,
    reason: reason ?? null,
    before: beforeState,
    after: responseSettings,
    message: "System settings updated from Command Center.",
    timestamp: admin.firestore.FieldValue.serverTimestamp(),
  });

  return {
    success: true,
    settings: responseSettings,
    updatedAt: responseUpdatedAt,
  };
}

export const adminUpdateSettings = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await adminUpdateSettingsHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

function serializeFeatureSuggestionRow(
  id: string,
  row: FirebaseFirestore.DocumentData
): Record<string, unknown> {
  const data = row ?? {};
  return {
    id,
    selectedFeatures: normalizeFeatureSuggestionList(data.selectedFeatures, 12, 120),
    note: coerceString(data.note) ?? "",
    page: coerceString(data.page) ?? "/services",
    source: coerceString(data.source) ?? null,
    status: coerceString(data.status) ?? "submitted",
    visibility: coerceString(data.visibility) ?? "super_admin_only",
    createdAt: toIsoString(data.createdAt) ?? coerceString(data.createdAtIso),
  };
}

async function adminListFeatureSuggestionsHandler(
  data: unknown,
  context: CallableContextLike
) {
  await requireSuperAdminContext(context);
  const payload = data && typeof data === "object" ?
    (data as Record<string, unknown>) :
    {};
  const rawLimit = Number(payload.limit ?? 25);
  const requestedLimit = Number.isFinite(rawLimit) ?
    Math.min(100, Math.max(1, rawLimit)) :
    25;
  const snapshot = await db.collection("feature_suggestions")
    .orderBy("createdAt", "desc")
    .limit(requestedLimit)
    .get();

  return {
    success: true,
    items: snapshot.docs.map((doc) => serializeFeatureSuggestionRow(doc.id, doc.data() ?? {})),
    generatedAt: new Date().toISOString(),
  };
}

export const adminListFeatureSuggestions = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await adminListFeatureSuggestionsHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

function normalizePostCollectionNameServer(raw?: unknown): "posts" {
  void raw;
  return "posts";
}

function assertKnownLifecycleStatus(raw: unknown): LifecycleStatus {
  const value = String(raw ?? "")
    .trim()
    .toLowerCase();
  if (!LIFECYCLE_STATUSES.includes(value as LifecycleStatus)) {
    throw new functions.https.HttpsError("invalid-argument", "Invalid lifecycle status.");
  }
  return value as LifecycleStatus;
}

function canEditScopedRecord(
  actor: StaffContext,
  row: Record<string, unknown>
): boolean {
  if (actor.role === "super_admin" || actor.role === "admin") {
    return true;
  }
  const rowOfficeId = coerceString(row.officeId);
  const rowCreatorUid = coerceString(row.createdByUid);
  if (rowCreatorUid && rowCreatorUid === actor.uid) {
    return true;
  }
  if (actor.officeId && rowOfficeId && actor.officeId === rowOfficeId) {
    return true;
  }
  return false;
}

function mapAttachmentList(raw: unknown): Array<Record<string, unknown>> {
  if (!Array.isArray(raw)) return [];
  const mapped: Array<Record<string, unknown>> = [];
  for (const entry of raw) {
    if (!entry || typeof entry !== "object") continue;
    const item = entry as Record<string, unknown>;
    const url = coerceString(item.url);
    if (!url) continue;
    mapped.push({
      name: coerceString(item.name) ?? "Attachment",
      url,
      path: coerceString(item.path),
      contentType: coerceString(item.contentType),
      size: typeof item.size === "number" ? item.size : null,
      uploadedAt: coerceString(item.uploadedAt),
    });
    if (mapped.length >= 20) break;
  }
  return mapped;
}

async function adminSavePostDraftHandler(
  data: unknown,
  context: CallableContextLike
) {
  const actor = await requireStaffContext(context);
  if (!isContentDraftRole(actor.role)) {
    throw new functions.https.HttpsError("permission-denied", "Staff draft access is required.");
  }

  const payload = (data && typeof data === "object")
    ? (data as Record<string, unknown>)
    : {};
  const id = coerceString(payload.id);
  const type = String(payload.type ?? "announcement")
    .trim()
    .toLowerCase();
  if (type !== "announcement" && type !== "news") {
    throw new functions.https.HttpsError("invalid-argument", "type must be announcement or news.");
  }
  await requireFeatureWritable(type === "news" ? "news" : "announcements");

  const status = normalizeLifecycleStatus(payload.status, "draft");
  if (status !== "draft" && !isContentPublishRole(actor.role)) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Only admin or super_admin can publish/archive posts."
    );
  }

  const title = assertStringLength(coerceString(payload.title), "title", 1, 120);
  const body = assertStringLength(coerceString(payload.body), "body", 1, 5000);
  const category = coerceString(payload.category) ?? "Announcement";
  const officeId = coerceString(payload.officeId);
  ensureActorOfficeScope(actor, officeId);

  const tags = parseStringList(payload.tags, {maxItems: 20, maxLen: 32});
  const publishAt = parseDateField(payload.publishAt);
  const coverImageUrl = coerceString(payload.coverImageUrl);
  const coverImagePath = coerceString(payload.coverImagePath);
  const coverImageName = coerceString(payload.coverImageName);
  const coverImageContentType = coerceString(payload.coverImageContentType);
  const sourceCollection = normalizePostCollectionNameServer(payload.sourceCollection);
  const targetRef = id
    ? db.collection(sourceCollection).doc(id)
    : db.collection(sourceCollection).doc();

  if (id) {
    const existing = await targetRef.get();
    if (!existing.exists) {
      throw new functions.https.HttpsError("not-found", "Post not found.");
    }
    const row = (existing.data() ?? {}) as Record<string, unknown>;
    if (!canEditScopedRecord(actor, row)) {
      throw new functions.https.HttpsError("permission-denied", "Not allowed to edit this post.");
    }
  }

  const actorName = actorDisplayName(actor);
  const actorEmail =
    coerceString(actor.profileData.email) ??
    coerceString(context.auth?.token.email) ??
    null;
  const now = admin.firestore.FieldValue.serverTimestamp();
  const media = coverImageUrl ? {
    type: "image",
    url: coverImageUrl,
    path: coverImagePath,
    name: coverImageName,
    contentType: coverImageContentType,
  } : null;

  const payloadData: Record<string, unknown> = {
    type,
    category,
    title,
    body,
    officeId: officeId ?? null,
    publishAt,
    media,
    coverImageUrl: coverImageUrl ?? null,
    tags,
    status,
    searchKeywords: normalizeKeywordTokens(title, body, category, tags.join(" ")),
    updatedAt: now,
    updatedByUid: actor.uid,
    updatedByName: actorName,
    updatedByEmail: actorEmail,
  };

  if (status === "published") {
    payloadData.publishedAt = now;
    payloadData.publishedByUid = actor.uid;
    payloadData.publishedByName = actorName;
  }
  if (status === "archived") {
    payloadData.archivedAt = now;
    payloadData.archivedByUid = actor.uid;
    payloadData.archivedByName = actorName;
  }

  if (!id) {
    payloadData.createdAt = now;
    payloadData.createdByUid = actor.uid;
    payloadData.createdByName = actorName;
    payloadData.createdByEmail = actorEmail;
    payloadData.views = 0;
  }

  await targetRef.set(payloadData, {merge: true});
  await addAuditLog({
    action: id ? "post_draft_updated" : "post_draft_created",
    entityType: "posts",
    entityId: targetRef.id,
    officeId: officeId ?? actor.officeId ?? null,
    actorUid: actor.uid,
    actorRole: actor.role,
    actorName,
    actorEmail,
    after: {
      status,
      type,
      category,
      title,
      sourceCollection,
    },
  });

  return {
    success: true,
    id: targetRef.id,
    sourceCollection,
    status,
  };
}

export const adminSavePostDraft = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await adminSavePostDraftHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

async function adminSavePublicDocDraftHandler(
  data: unknown,
  context: CallableContextLike
) {
  const actor = await requireStaffContext(context);
  if (!isContentDraftRole(actor.role)) {
    throw new functions.https.HttpsError("permission-denied", "Staff draft access is required.");
  }
  await requireFeatureWritable("publicDocs");

  const payload = (data && typeof data === "object")
    ? (data as Record<string, unknown>)
    : {};
  const id = coerceString(payload.id);
  const rawDocType = String(payload.docType ?? "")
    .trim()
    .toLowerCase();
  if (!PUBLIC_DOC_TYPES.includes(rawDocType as PublicDocType)) {
    throw new functions.https.HttpsError("invalid-argument", "Unsupported document type.");
  }
  const docType = rawDocType as PublicDocType;
  const status = normalizeLifecycleStatus(payload.status, "draft");
  if (status !== "draft" && !isContentPublishRole(actor.role)) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Only admin or super_admin can publish/archive public documents."
    );
  }

  const docNo = assertStringLength(coerceString(payload.docNo), "docNo", 1, 40);
  const title = assertStringLength(coerceString(payload.title), "title", 1, 120);
  const summary = assertStringLength(coerceString(payload.summary), "summary", 1, 500);
  const requestedOfficeId = coerceString(payload.officeId);
  const officeId = await resolvePublicDocOfficeId(docType, requestedOfficeId);
  ensureActorOfficeScope(actor, officeId);

  const tags = parseStringList(payload.tags, {maxItems: 20, maxLen: 32});
  const attachments = mapAttachmentList(payload.attachments);
  const dateIssued = parseDateField(payload.dateIssued);
  const dateApproved = parseDateField(payload.dateApproved);
  const pdfUrl = coerceString(payload.pdfUrl);

  const targetRef = id
    ? db.collection("public_docs").doc(id)
    : db.collection("public_docs").doc();
  if (id) {
    const existing = await targetRef.get();
    if (!existing.exists) {
      throw new functions.https.HttpsError("not-found", "Public document not found.");
    }
    const row = (existing.data() ?? {}) as Record<string, unknown>;
    if (!canEditScopedRecord(actor, row)) {
      throw new functions.https.HttpsError("permission-denied", "Not allowed to edit this document.");
    }
  }

  const actorName = actorDisplayName(actor);
  const actorEmail =
    coerceString(actor.profileData.email) ??
    coerceString(context.auth?.token.email) ??
    null;
  const now = admin.firestore.FieldValue.serverTimestamp();
  const payloadData: Record<string, unknown> = {
    docType,
    docNo,
    title,
    summary,
    officeId,
    pdfUrl: pdfUrl ?? null,
    attachments,
    status,
    tags,
    dateIssued,
    dateApproved,
    searchKeywords: normalizeKeywordTokens(docNo, title, summary, tags.join(" ")),
    updatedAt: now,
    updatedByUid: actor.uid,
    updatedByName: actorName,
    updatedByEmail: actorEmail,
  };
  if (status === "published") {
    payloadData.publishedAt = now;
    payloadData.publishedByUid = actor.uid;
    payloadData.publishedByName = actorName;
  }
  if (status === "archived") {
    payloadData.archivedAt = now;
    payloadData.archivedByUid = actor.uid;
    payloadData.archivedByName = actorName;
  }
  if (!id) {
    payloadData.createdAt = now;
    payloadData.createdByUid = actor.uid;
    payloadData.createdByName = actorName;
  }

  await targetRef.set(payloadData, {merge: true});
  await addAuditLog({
    action: id ? "public_doc_updated" : "public_doc_created",
    entityType: "public_docs",
    entityId: targetRef.id,
    officeId,
    actorUid: actor.uid,
    actorRole: actor.role,
    actorName,
    actorEmail,
    after: {
      status,
      docType,
      docNo,
      title,
    },
  });

  return {
    success: true,
    id: targetRef.id,
    status,
  };
}

export const adminSavePublicDocDraft = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await adminSavePublicDocDraftHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

async function adminSaveJobDraftHandler(
  data: unknown,
  context: CallableContextLike
) {
  const actor = await requireStaffContext(context);
  await requireFeatureWritable("jobs");
  if (!isJobsManageRole(actor.role)) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Only admin or super_admin can manage job postings."
    );
  }

  const payload = (data && typeof data === "object")
    ? (data as Record<string, unknown>)
    : {};
  const id = coerceString(payload.id);
  const status = normalizeLifecycleStatus(payload.status, "draft");
  if (status !== "draft" && !isContentPublishRole(actor.role)) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Only admin or super_admin can publish/archive jobs."
    );
  }

  const title = assertStringLength(coerceString(payload.title), "title", 1, 120);
  const officeId = assertStringLength(coerceString(payload.officeId), "officeId", 1, 120);
  const employmentType = assertStringLength(coerceString(payload.employmentType), "employmentType", 1, 60);
  const description = assertStringLength(coerceString(payload.description), "description", 1, 5000);
  const salaryRange = coerceString(payload.salaryRange);
  const location = coerceString(payload.location);
  const qualifications = coerceString(payload.qualifications);
  const applicationLink = coerceString(payload.applicationLink);
  const applicationEmail = coerceString(payload.applicationEmail);
  const deadline = parseDateField(payload.deadline);
  const requirements = parseStringList(payload.requirements, {maxItems: 30, maxLen: 250});
  const tags = parseStringList(payload.tags, {maxItems: 20, maxLen: 32});

  const targetRef = id
    ? db.collection("jobs").doc(id)
    : db.collection("jobs").doc();
  if (id) {
    const existing = await targetRef.get();
    if (!existing.exists) {
      throw new functions.https.HttpsError("not-found", "Job posting not found.");
    }
  }

  const actorName = actorDisplayName(actor);
  const actorEmail =
    coerceString(actor.profileData.email) ??
    coerceString(context.auth?.token.email) ??
    null;
  const now = admin.firestore.FieldValue.serverTimestamp();
  const payloadData: Record<string, unknown> = {
    title,
    officeId,
    employmentType,
    plantilla: Boolean(payload.plantilla),
    salaryRange: salaryRange ?? null,
    location: location ?? null,
    description,
    qualifications: qualifications ?? null,
    requirements,
    applicationLink: applicationLink ?? null,
    applicationEmail: applicationEmail ?? null,
    deadline,
    status,
    tags,
    searchKeywords: normalizeKeywordTokens(
      title,
      description,
      qualifications ?? "",
      requirements.join(" "),
      tags.join(" ")
    ),
    updatedAt: now,
    updatedByUid: actor.uid,
    updatedByName: actorName,
    updatedByEmail: actorEmail,
  };
  if (status === "published") {
    payloadData.publishedAt = now;
    payloadData.publishedByUid = actor.uid;
    payloadData.publishedByName = actorName;
  }
  if (status === "archived") {
    payloadData.archivedAt = now;
    payloadData.archivedByUid = actor.uid;
    payloadData.archivedByName = actorName;
  }
  if (!id) {
    payloadData.createdAt = now;
    payloadData.createdByUid = actor.uid;
    payloadData.createdByName = actorName;
  }

  await targetRef.set(payloadData, {merge: true});
  await addAuditLog({
    action: id ? "job_updated" : "job_created",
    entityType: "jobs",
    entityId: targetRef.id,
    officeId,
    actorUid: actor.uid,
    actorRole: actor.role,
    actorName,
    actorEmail,
    after: {
      status,
      title,
      officeId,
    },
  });

  return {
    success: true,
    id: targetRef.id,
    status,
  };
}

export const adminSaveJobDraft = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await adminSaveJobDraftHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

async function adminSaveDirectoryEntryHandler(
  data: unknown,
  context: CallableContextLike
) {
  const actor = await requireStaffContext(context);
  await requireSystemWritable();
  if (!isDirectoryManageRole(actor.role)) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Only admin or super_admin can manage municipal directory entries."
    );
  }

  const payload = (data && typeof data === "object")
    ? (data as Record<string, unknown>)
    : {};
  const id = coerceString(payload.id);
  const status = normalizeLifecycleStatus(payload.status, "draft");
  if (status !== "draft" && !isContentPublishRole(actor.role)) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Only admin or super_admin can publish or archive municipal directory entries."
    );
  }

  const officeId = coerceString(payload.officeId);
  const officeName = assertStringLength(
    coerceString(payload.officeName),
    "officeName",
    1,
    160
  );
  const contactName = assertStringLength(
    coerceString(payload.contactName),
    "contactName",
    1,
    120
  );
  const position = assertStringLength(
    coerceString(payload.position),
    "position",
    1,
    120
  );
  const phone = assertStringLength(
    coerceString(payload.phone),
    "phone",
    1,
    80
  );
  const email = assertOptionalStringLength(coerceString(payload.email), "email", 160);
  const facebook = assertOptionalStringLength(coerceString(payload.facebook), "facebook", 300);
  const address = assertOptionalStringLength(coerceString(payload.address), "address", 240);
  const officeHours = assertOptionalStringLength(coerceString(payload.officeHours), "officeHours", 120);
  const source = assertOptionalStringLength(coerceString(payload.source), "source", 40) ?? "manual";
  const importBatchId = assertOptionalStringLength(coerceString(payload.importBatchId), "importBatchId", 80);
  const lastVerifiedAt = parseDateField(payload.lastVerifiedAt);
  const sortOrder = normalizeSortOrder(payload.sortOrder);

  ensureActorOfficeScope(actor, officeId);

  const targetRef = id
    ? db.collection("directory_entries").doc(id)
    : db.collection("directory_entries").doc();

  if (id) {
    const existing = await targetRef.get();
    if (!existing.exists) {
      throw new functions.https.HttpsError("not-found", "Directory entry not found.");
    }
  }

  const actorName = actorDisplayName(actor);
  const actorEmail =
    coerceString(actor.profileData.email) ??
    coerceString(context.auth?.token.email) ??
    null;
  const now = admin.firestore.FieldValue.serverTimestamp();
  const payloadData: Record<string, unknown> = {
    officeId: officeId ?? null,
    officeName,
    contactName,
    position,
    phone,
    email: email ?? null,
    facebook: facebook ?? null,
    address: address ?? null,
    officeHours: officeHours ?? null,
    source,
    importBatchId: importBatchId ?? null,
    status,
    isPublic: status === "published",
    sortOrder,
    lastVerifiedAt,
    lastVerifiedByUid: actor.uid,
    lastVerifiedByName: actorName,
    searchKeywords: buildDirectorySearchKeywords(
      officeName,
      contactName,
      position,
      phone,
      email,
      facebook,
      address
    ),
    updatedAt: now,
    updatedByUid: actor.uid,
    updatedByName: actorName,
    updatedByEmail: actorEmail,
  };

  if (status === "published") {
    payloadData.publishedAt = now;
    payloadData.publishedByUid = actor.uid;
    payloadData.publishedByName = actorName;
  }
  if (status === "archived") {
    payloadData.archivedAt = now;
    payloadData.archivedByUid = actor.uid;
    payloadData.archivedByName = actorName;
    payloadData.isPublic = false;
  }
  if (!id) {
    payloadData.createdAt = now;
    payloadData.createdByUid = actor.uid;
    payloadData.createdByName = actorName;
    payloadData.createdByEmail = actorEmail;
  }

  await targetRef.set(payloadData, {merge: true});
  await addAuditLog({
    action: id ? "directory_entry_updated" : "directory_entry_created",
    entityType: "directory_entries",
    entityId: targetRef.id,
    officeId: officeId ?? actor.officeId ?? null,
    actorUid: actor.uid,
    actorRole: actor.role,
    actorName,
    actorEmail,
    after: {
      status,
      officeId: officeId ?? null,
      officeName,
      contactName,
    },
  });

  return {
    success: true,
    id: targetRef.id,
    status,
  };
}

export const adminSaveDirectoryEntry = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await adminSaveDirectoryEntryHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

async function adminImportDirectoryEntriesHandler(
  data: unknown,
  context: CallableContextLike
) {
  const actor = await requireStaffContext(context);
  await requireSystemWritable();
  if (!isDirectoryManageRole(actor.role)) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Only admin or super_admin can import municipal directory entries."
    );
  }

  const payload = (data && typeof data === "object")
    ? (data as Record<string, unknown>)
    : {};
  const rows = Array.isArray(payload.rows) ? payload.rows : null;
  if (!rows || rows.length === 0) {
    throw new functions.https.HttpsError("invalid-argument", "rows is required.");
  }
  if (rows.length > 500) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "You can import up to 500 directory rows per batch."
    );
  }

  const importBatchId =
    assertOptionalStringLength(coerceString(payload.importBatchId), "importBatchId", 80) ??
    `DIRIMP-${Date.now()}-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;
  const actorName = actorDisplayName(actor);
  const actorEmail =
    coerceString(actor.profileData.email) ??
    coerceString(context.auth?.token.email) ??
    null;

  let batch = db.batch();
  let batchSize = 0;
  let createdCount = 0;

  async function commitBatch() {
    if (batchSize === 0) return;
    await batch.commit();
    batch = db.batch();
    batchSize = 0;
  }

  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index];
    if (!row || typeof row !== "object") {
      throw new functions.https.HttpsError(
        "invalid-argument",
        `Row ${index + 1} is not a valid object.`
      );
    }
    const item = row as Record<string, unknown>;
    const officeId = coerceString(item.officeId);
    const officeName = assertStringLength(
      coerceString(item.officeName),
      `rows[${index}].officeName`,
      1,
      160
    );
    const contactName = assertStringLength(
      coerceString(item.contactName),
      `rows[${index}].contactName`,
      1,
      120
    );
    const position = assertStringLength(
      coerceString(item.position),
      `rows[${index}].position`,
      1,
      120
    );
    const phone = assertStringLength(
      coerceString(item.phone),
      `rows[${index}].phone`,
      1,
      80
    );
    const email = assertOptionalStringLength(coerceString(item.email), `rows[${index}].email`, 160);
    const facebook = assertOptionalStringLength(coerceString(item.facebook), `rows[${index}].facebook`, 300);
    const address = assertOptionalStringLength(coerceString(item.address), `rows[${index}].address`, 240);
    const officeHours = assertOptionalStringLength(coerceString(item.officeHours), `rows[${index}].officeHours`, 120);
    const sortOrder = normalizeSortOrder(item.sortOrder, index);

    ensureActorOfficeScope(actor, officeId);

    const ref = db.collection("directory_entries").doc();
    batch.set(ref, {
      officeId: officeId ?? null,
      officeName,
      contactName,
      position,
      phone,
      email: email ?? null,
      facebook: facebook ?? null,
      address: address ?? null,
      officeHours: officeHours ?? null,
      source: "excel_import",
      importBatchId,
      status: "draft",
      isPublic: false,
      sortOrder,
      searchKeywords: buildDirectorySearchKeywords(
        officeName,
        contactName,
        position,
        phone,
        email,
        facebook,
        address
      ),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      createdByUid: actor.uid,
      createdByName: actorName,
      createdByEmail: actorEmail,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedByUid: actor.uid,
      updatedByName: actorName,
      updatedByEmail: actorEmail,
    });
    batchSize += 1;
    createdCount += 1;

    if (batchSize >= 400) {
      await commitBatch();
    }
  }

  await commitBatch();
  await addAuditLog({
    action: "directory_entries_imported",
    entityType: "directory_entries",
    entityId: importBatchId,
    officeId: actor.officeId ?? null,
    actorUid: actor.uid,
    actorRole: actor.role,
    actorName,
    actorEmail,
    after: {
      importBatchId,
      createdCount,
    },
  });

  return {
    success: true,
    importBatchId,
    createdCount,
  };
}

export const adminImportDirectoryEntries = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await adminImportDirectoryEntriesHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

async function adminSaveEmergencyHotlineHandler(
  data: unknown,
  context: CallableContextLike
) {
  const actor = await requireStaffContext(context);
  await requireSystemWritable();
  if (!isEmergencyHotlinesManageRole(actor.role)) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Only super_admin can manage emergency hotline records."
    );
  }

  const payload = (data && typeof data === "object")
    ? (data as Record<string, unknown>)
    : {};
  const id = coerceString(payload.id);
  const status = normalizeLifecycleStatus(payload.status, "draft");
  const label = assertStringLength(coerceString(payload.label), "label", 1, 120);
  const group = assertStringLength(coerceString(payload.group), "group", 1, 80);
  const description = assertOptionalStringLength(coerceString(payload.description), "description", 240);
  const officeId = coerceString(payload.officeId);
  const availabilityLabel = assertOptionalStringLength(coerceString(payload.availabilityLabel), "availabilityLabel", 120);
  const notes = assertOptionalStringLength(coerceString(payload.notes), "notes", 240);
  const contactNumbers = parsePhoneList(payload.contactNumbers, {maxItems: 8, maxLen: 80});
  if (contactNumbers.length === 0) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "At least one contact number is required."
    );
  }
  const sortOrder = normalizeSortOrder(payload.sortOrder);
  const lastVerifiedAt = parseDateField(payload.lastVerifiedAt);
  const showOnHomepage = Boolean(payload.showOnHomepage);

  const targetRef = id
    ? db.collection("emergency_hotlines").doc(id)
    : db.collection("emergency_hotlines").doc();

  if (id) {
    const existing = await targetRef.get();
    if (!existing.exists) {
      throw new functions.https.HttpsError("not-found", "Emergency hotline record not found.");
    }
  }

  const actorName = actorDisplayName(actor);
  const actorEmail =
    coerceString(actor.profileData.email) ??
    coerceString(context.auth?.token.email) ??
    null;
  const now = admin.firestore.FieldValue.serverTimestamp();
  const payloadData: Record<string, unknown> = {
    label,
    group,
    description: description ?? null,
    officeId: officeId ?? null,
    availabilityLabel: availabilityLabel ?? null,
    notes: notes ?? null,
    contactNumbers,
    showOnHomepage,
    status,
    isPublic: status === "published",
    sortOrder,
    lastVerifiedAt,
    lastVerifiedByUid: actor.uid,
    lastVerifiedByName: actorName,
    searchKeywords: buildEmergencyHotlineSearchKeywords(
      label,
      group,
      description,
      contactNumbers,
      notes
    ),
    updatedAt: now,
    updatedByUid: actor.uid,
    updatedByName: actorName,
    updatedByEmail: actorEmail,
  };

  if (status === "published") {
    payloadData.publishedAt = now;
    payloadData.publishedByUid = actor.uid;
    payloadData.publishedByName = actorName;
  }
  if (status === "archived") {
    payloadData.archivedAt = now;
    payloadData.archivedByUid = actor.uid;
    payloadData.archivedByName = actorName;
    payloadData.isPublic = false;
  }
  if (!id) {
    payloadData.createdAt = now;
    payloadData.createdByUid = actor.uid;
    payloadData.createdByName = actorName;
    payloadData.createdByEmail = actorEmail;
  }

  await targetRef.set(payloadData, {merge: true});
  await addAuditLog({
    action: id ? "emergency_hotline_updated" : "emergency_hotline_created",
    entityType: "emergency_hotlines",
    entityId: targetRef.id,
    officeId: officeId ?? null,
    actorUid: actor.uid,
    actorRole: actor.role,
    actorName,
    actorEmail,
    after: {
      status,
      label,
      group,
      showOnHomepage,
    },
  });

  return {
    success: true,
    id: targetRef.id,
    status,
  };
}

export const adminSaveEmergencyHotline = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await adminSaveEmergencyHotlineHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

async function adminSetEntityStatusHandler(
  data: unknown,
  context: CallableContextLike
) {
  const actor = await requireStaffContext(context);
  if (!isContentPublishRole(actor.role)) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Only admin or super_admin can update lifecycle status."
    );
  }
  const payload = (data && typeof data === "object")
    ? (data as Record<string, unknown>)
    : {};
  const entityType = coerceString(payload.entityType);
  const entityId = coerceString(payload.entityId);
  if (!entityType || !entityId) {
    throw new functions.https.HttpsError("invalid-argument", "entityType and entityId are required.");
  }
  const status = assertKnownLifecycleStatus(payload.status);

  const actorName = actorDisplayName(actor);
  const actorEmail =
    coerceString(actor.profileData.email) ??
    coerceString(context.auth?.token.email) ??
    null;
  const now = admin.firestore.FieldValue.serverTimestamp();
  const basePatch: Record<string, unknown> = {
    status,
    updatedAt: now,
    updatedByUid: actor.uid,
    updatedByName: actorName,
    updatedByEmail: actorEmail,
  };
  if (status === "published") {
    basePatch.publishedAt = now;
    basePatch.publishedByUid = actor.uid;
    basePatch.publishedByName = actorName;
  }
  if (status === "archived") {
    basePatch.archivedAt = now;
    basePatch.archivedByUid = actor.uid;
    basePatch.archivedByName = actorName;
  }

  let targetRef: FirebaseFirestore.DocumentReference;
  const auditEntityType = entityType;
  if (entityType === "posts") {
    const sourceCollection = normalizePostCollectionNameServer(payload.sourceCollection);
    targetRef = db.collection(sourceCollection).doc(entityId);
    const sourceSnap = await targetRef.get();
    if (!sourceSnap.exists) {
      throw new functions.https.HttpsError("not-found", "Post not found.");
    }
    const sourceRow = (sourceSnap.data() ?? {}) as Record<string, unknown>;
    const sourceType = String(sourceRow.type ?? "")
      .trim()
      .toLowerCase();
    await requireFeatureWritable(sourceType === "news" ? "news" : "announcements");
  } else if (entityType === "public_docs") {
    await requireFeatureWritable("publicDocs");
    targetRef = db.collection("public_docs").doc(entityId);
    const sourceSnap = await targetRef.get();
    if (!sourceSnap.exists) {
      throw new functions.https.HttpsError("not-found", "Public document not found.");
    }
  } else if (entityType === "jobs") {
    await requireFeatureWritable("jobs");
    targetRef = db.collection("jobs").doc(entityId);
    const sourceSnap = await targetRef.get();
    if (!sourceSnap.exists) {
      throw new functions.https.HttpsError("not-found", "Job posting not found.");
    }
  } else if (entityType === "directory_entries") {
    await requireSystemWritable();
    targetRef = db.collection("directory_entries").doc(entityId);
    const sourceSnap = await targetRef.get();
    if (!sourceSnap.exists) {
      throw new functions.https.HttpsError("not-found", "Directory entry not found.");
    }
  } else if (entityType === "emergency_hotlines") {
    await requireSystemWritable();
    if (!isEmergencyHotlinesManageRole(actor.role)) {
      throw new functions.https.HttpsError(
        "permission-denied",
        "Only super_admin can publish or archive emergency hotline records."
      );
    }
    targetRef = db.collection("emergency_hotlines").doc(entityId);
    const sourceSnap = await targetRef.get();
    if (!sourceSnap.exists) {
      throw new functions.https.HttpsError("not-found", "Emergency hotline record not found.");
    }
  } else {
    throw new functions.https.HttpsError("invalid-argument", "Unsupported entity type.");
  }

  if (entityType === "directory_entries" || entityType === "emergency_hotlines") {
    basePatch.isPublic = status === "published";
  }
  await targetRef.set(basePatch, {merge: true});
  await addAuditLog({
    action: `${auditEntityType}_${status}`,
    entityType: auditEntityType,
    entityId,
    officeId: coerceString(payload.officeId) ?? actor.officeId ?? null,
    actorUid: actor.uid,
    actorRole: actor.role,
    actorName,
    actorEmail,
    after: {status},
  });

  return {
    success: true,
    entityType: auditEntityType,
    entityId,
    status,
  };
}

export const adminSetEntityStatus = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await adminSetEntityStatusHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

async function adminUpdateReportStatusHandler(
  data: unknown,
  context: CallableContextLike
) {
  const payload = (data && typeof data === "object")
    ? (data as Record<string, unknown>)
    : {};
  const actor = await requireStaffContext(context);
  const reportId = coerceString(payload.reportId);
  if (!reportId) {
    throw new functions.https.HttpsError("invalid-argument", "reportId is required.");
  }
  const nextStatus = normalizeReportStatusInput(payload.status);
  const notes = coerceString(payload.notes);
  if (notes && notes.length > 1000) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "notes must be 1000 characters or fewer."
    );
  }

  const reportRef = db.collection("reports").doc(reportId);
  const actorMeta = reportActorMeta(actor, context);
  let previousStatus = "submitted";
  let timelineNote = "";

  await db.runTransaction(async (tx) => {
    const snap = await tx.get(reportRef);
    if (!snap.exists) {
      throw new functions.https.HttpsError("not-found", "Report not found.");
    }
    const row = (snap.data() ?? {}) as Record<string, unknown>;
    await requireFeatureWritable(featureKeyForPublicReportLane(getPublicReportLane(row)));
    previousStatus = normalizeReportStatusInput(row.status ?? "submitted");

    const canUpdate =
      actor.role === "super_admin" ||
      actor.role === "admin" ||
      (actor.role === "office_admin" && reportInActorScope(actor, row)) ||
      (actor.role === "moderator" && coerceString(row.assignedToUid) === actor.uid);
    if (!canUpdate) {
      throw new functions.https.HttpsError(
        "permission-denied",
        "You are not allowed to update this report."
      );
    }
    // Server-side status transitions keep the SOP order enforceable even if the
    // client UI is bypassed or stale.
    if (!canTransitionReportStatus(previousStatus, nextStatus)) {
      throw new functions.https.HttpsError(
        "failed-precondition",
        `Invalid status transition from ${previousStatus} to ${nextStatus}.`
      );
    }
    if (
      previousStatus !== nextStatus &&
      statusRequiresResidentNote(nextStatus) &&
      !notes
    ) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        `A resident-visible note is required when marking feedback as ${nextStatus}.`
      );
    }

    tx.set(
      reportRef,
      {
        status: nextStatus,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        ...actorMeta,
      },
      {merge: true}
    );
    tx.set(reportRef.collection("history").doc(), {
      type: "status_updated",
      fromStatus: previousStatus,
      toStatus: nextStatus,
      message: `Status changed from ${previousStatus} to ${nextStatus}.`,
      byUid: actor.uid,
      byName: actorMeta.lastActionByName,
      byRole: actor.role,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  });

  await addAuditLog({
    action: "report_status_updated",
    entityType: "report",
    entityId: reportId,
    reportId,
    officeId: actor.officeId ?? null,
    actorUid: actor.uid,
    actorRole: actor.role,
    actorOfficeId: actor.officeId ?? null,
    actorName: actorMeta.lastActionByName,
    before: {status: previousStatus},
    after: {status: nextStatus},
    message: `Status changed from ${previousStatus} to ${nextStatus}.`,
  });

  timelineNote =
    notes ||
    `Status changed from ${prettyStatus(previousStatus)} to ${prettyStatus(nextStatus)}.`;
  const latestTimelineEvent = await addReportTimeline(reportId, {
    type: "STATUS_CHANGED",
    actorUid: actor.uid,
    actorRole: actor.role,
    actorName: actorMeta.lastActionByName,
    notes: timelineNote,
    fromStatus: previousStatus,
    toStatus: nextStatus,
  });
  const updatedReportSnapshot = await reportRef.get();
  await sendFeedbackEmailNotification({
    id: reportId,
    ...(updatedReportSnapshot.data() ?? {}),
  }, {
    status: nextStatus,
    note: timelineNote,
    updatedAt: latestTimelineEvent.createdAt,
  });

  return {
    success: true,
    reportId,
    status: nextStatus,
    latestTimelineEvent,
  };
}

export const adminUpdateReportStatus = onCallV2(
  protectedCallableV2FeedbackOptions,
  async (request) => {
    try {
      return await adminUpdateReportStatusHandler(request.data, toCallableContextFromV2(request));
    } catch (error) {
      throw normalizeCallableErrorForV2(error);
    }
  }
);

async function staffClaimReportHandler(
  data: unknown,
  context: CallableContextLike
) {
  const payload = (data && typeof data === "object")
    ? (data as Record<string, unknown>)
    : {};
  const actor = await requireStaffContext(context);
  await requireFeatureWritable("reports");

  const reportId = coerceString(payload.reportId);
  if (!reportId) {
    throw new functions.https.HttpsError("invalid-argument", "reportId is required.");
  }

  const reportRef = db.collection("reports").doc(reportId);
  const actorMeta = reportActorMeta(actor, context);
  let previousStatus = "submitted";
  let claimedStatus = "assigned";
  let officeId: string | null = null;

  await db.runTransaction(async (tx) => {
    const snap = await tx.get(reportRef);
    if (!snap.exists) {
      throw new functions.https.HttpsError("not-found", "Report not found.");
    }
    const row = (snap.data() ?? {}) as Record<string, unknown>;
    if (!canClaimReportInActorScope(actor, row)) {
      throw new functions.https.HttpsError(
        "permission-denied",
        "You are not allowed to claim this report."
      );
    }

    const currentAssignee = coerceString(row.assignedToUid);
    if (currentAssignee && currentAssignee !== actor.uid) {
      throw new functions.https.HttpsError(
        "failed-precondition",
        "This report is already assigned to another staff member."
      );
    }

    previousStatus = normalizeReportStatusInput(row.status ?? "submitted");
    officeId = coerceString(row.officeId) ?? coerceString(row.currentOfficeId);
    const nextStatus =
      previousStatus === "submitted" ||
      previousStatus === "acknowledged" ||
      previousStatus === "in_review"
        ? "assigned"
        : previousStatus;
    claimedStatus = nextStatus;

    tx.set(
      reportRef,
      {
        assignedToUid: actor.uid,
        assignedToName: actorDisplayName(actor),
        assignedOfficeId: actor.officeId ?? coerceString(row.officeId) ?? coerceString(row.currentOfficeId) ?? null,
        status: nextStatus,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        ...actorMeta,
      },
      {merge: true}
    );
  });

  await addAuditLog({
    action: "report_claimed",
    entityType: "report",
    entityId: reportId,
    reportId,
    officeId,
    actorUid: actor.uid,
    actorRole: actor.role,
    actorOfficeId: actor.officeId ?? null,
    actorName: actorMeta.lastActionByName,
    before: {status: previousStatus},
    after: {status: previousStatus === "submitted" || previousStatus === "acknowledged" || previousStatus === "in_review" ? "assigned" : previousStatus, assignedToUid: actor.uid},
    message: "Claimed to self.",
  });

  const latestTimelineEvent = await addReportTimeline(reportId, {
    type: "CLAIMED",
    actorUid: actor.uid,
    actorRole: actor.role,
    actorName: actorMeta.lastActionByName,
    notes: "Claimed to self.",
    fromStatus: previousStatus,
    toStatus: claimedStatus,
  });
  if (claimedStatus !== previousStatus) {
    const updatedReportSnapshot = await reportRef.get();
    await sendFeedbackEmailNotification({
      id: reportId,
      ...(updatedReportSnapshot.data() ?? {}),
    }, {
      status: claimedStatus,
      note: latestTimelineEvent.notes,
      updatedAt: latestTimelineEvent.createdAt,
    });
  }

  return {
    success: true,
    reportId,
    assignedToUid: actor.uid,
    assignedToName: actorDisplayName(actor),
    status: claimedStatus,
    latestTimelineEvent,
  };
}

export const staffClaimReport = onCallV2(
  protectedCallableV2FeedbackOptions,
  async (request) => {
    try {
      return await staffClaimReportHandler(request.data, toCallableContextFromV2(request));
    } catch (error) {
      throw normalizeCallableErrorForV2(error);
    }
  }
);

async function adminAssignReportHandler(
  data: unknown,
  context: CallableContextLike
) {
  const payload = (data && typeof data === "object")
    ? (data as Record<string, unknown>)
    : {};
  const actor = await requireStaffContext(context);
  if (!canAssignReportsRole(actor.role)) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Only office_admin, admin, and super_admin can assign reports."
    );
  }
  const reportId = coerceString(payload.reportId);
  if (!reportId) {
    throw new functions.https.HttpsError("invalid-argument", "reportId is required.");
  }
  const assigneeUid = coerceString(payload.assigneeUid);
  const requestedStatusRaw = coerceString(payload.status);
  const requestedStatus = requestedStatusRaw ? normalizeReportStatusInput(requestedStatusRaw) : null;
  const notes = coerceString(payload.notes);
  if (notes && notes.length > 1000) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "notes must be 1000 characters or fewer."
    );
  }
  const reportRef = db.collection("reports").doc(reportId);
  const actorMeta = reportActorMeta(actor, context);

  let beforeAssignedUid: string | null = null;
  let beforeStatus = "submitted";
  let afterStatus = "submitted";
  let assignedToName: string | null = null;
  let assignedOfficeId: string | null = null;
  let timelineNote = "";
  let actionMessage = "";

  if (assigneeUid) {
    const targetProfile = await getUserProfile(assigneeUid);
    if (targetProfile.role === "resident") {
      throw new functions.https.HttpsError("invalid-argument", "Assignee must be a staff account.");
    }
    if (!targetProfile.isActive) {
      throw new functions.https.HttpsError("failed-precondition", "Assignee account is inactive.");
    }
    // Office Admin can assign only inside the same office; municipal Admin can assign cross-office.
    if (actor.role === "office_admin" && actor.officeId && targetProfile.officeId !== actor.officeId) {
      throw new functions.https.HttpsError(
        "permission-denied",
        "Office Admin can only assign staff within the same office."
      );
    }
    assignedOfficeId = targetProfile.officeId ?? null;
    assignedToName =
      coerceString(targetProfile.data.displayName) ??
      coerceString(targetProfile.data.email) ??
      assigneeUid;
  }

  await db.runTransaction(async (tx) => {
    const snap = await tx.get(reportRef);
    if (!snap.exists) {
      throw new functions.https.HttpsError("not-found", "Report not found.");
    }
    const row = (snap.data() ?? {}) as Record<string, unknown>;
    await requireFeatureWritable(featureKeyForPublicReportLane(getPublicReportLane(row)));
    if (!reportInActorScope(actor, row)) {
      throw new functions.https.HttpsError(
        "permission-denied",
        "You are not allowed to assign this report."
      );
    }
    beforeAssignedUid = coerceString(row.assignedToUid);
    beforeStatus = normalizeReportStatusInput(row.status ?? "submitted");
    const shouldAutoAssignStatus = Boolean(assigneeUid) &&
      (beforeStatus === "submitted" || beforeStatus === "acknowledged" || beforeStatus === "in_review");
    const shouldReturnToQueue = !assigneeUid && beforeStatus === "assigned";
    const defaultStatus = shouldAutoAssignStatus ? "assigned" : (shouldReturnToQueue ? "in_review" : beforeStatus);
    afterStatus = requestedStatus ?? defaultStatus;
    if (!canTransitionReportStatus(beforeStatus, afterStatus)) {
      throw new functions.https.HttpsError(
        "failed-precondition",
        `Invalid status transition from ${beforeStatus} to ${afterStatus}.`
      );
    }
    if (
      beforeStatus !== afterStatus &&
      statusRequiresResidentNote(afterStatus) &&
      !notes
    ) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        `A resident-visible note is required when marking feedback as ${afterStatus}.`
      );
    }
    actionMessage =
      buildReportWorkflowSummary({
        beforeStatus,
        afterStatus,
        beforeAssignedUid,
        afterAssignedUid: assigneeUid ?? null,
        assignedToName,
      }) ||
      (assigneeUid ? `Assigned to ${assignedToName}.` : "Removed assignee and returned to queue.");
    timelineNote = notes || actionMessage;

    tx.set(
      reportRef,
      {
        assignedToUid: assigneeUid ?? null,
        assignedToName: assigneeUid ? assignedToName : null,
        assignedOfficeId: assigneeUid ? assignedOfficeId : null,
        status: afterStatus,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        ...actorMeta,
      },
      {merge: true}
    );
    tx.set(reportRef.collection("history").doc(), {
      type:
        (beforeAssignedUid !== (assigneeUid ?? null) && afterStatus !== beforeStatus)
          ? "workflow_updated"
          : (assigneeUid ? "assigned" : "unassigned"),
      assignedToUid: assigneeUid ?? null,
      assignedToName: assigneeUid ? assignedToName : null,
      fromStatus: beforeStatus,
      toStatus: afterStatus,
      message: actionMessage,
      byUid: actor.uid,
      byName: actorMeta.lastActionByName,
      byRole: actor.role,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  });

  await addAuditLog({
    action:
      (beforeAssignedUid !== (assigneeUid ?? null) && afterStatus !== beforeStatus)
        ? "report_workflow_updated"
        : (assigneeUid ? "report_assigned" : "report_unassigned"),
    entityType: "report",
    entityId: reportId,
    reportId,
    officeId: actor.officeId ?? null,
    actorUid: actor.uid,
    actorRole: actor.role,
    actorOfficeId: actor.officeId ?? null,
    actorName: actorMeta.lastActionByName,
    before: {assignedToUid: beforeAssignedUid, status: beforeStatus},
    after: {assignedToUid: assigneeUid ?? null, status: afterStatus},
    message: actionMessage,
  });

  const latestTimelineEvent = await addReportTimeline(reportId, {
    type:
      (beforeAssignedUid !== (assigneeUid ?? null) && afterStatus !== beforeStatus)
        ? "WORKFLOW_UPDATED"
        : (assigneeUid ? (beforeAssignedUid ? "REASSIGNED" : "ASSIGNED") : "UNASSIGNED"),
    actorUid: actor.uid,
    actorRole: actor.role,
    actorName: actorMeta.lastActionByName,
    notes: timelineNote,
    fromStatus: beforeStatus,
    toStatus: afterStatus,
  });
  if (afterStatus !== beforeStatus) {
    const updatedReportSnapshot = await reportRef.get();
    await sendFeedbackEmailNotification({
      id: reportId,
      ...(updatedReportSnapshot.data() ?? {}),
    }, {
      status: afterStatus,
      note: latestTimelineEvent.notes,
      updatedAt: latestTimelineEvent.createdAt,
    });
  }

  return {
    success: true,
    reportId,
    assignedToUid: assigneeUid ?? null,
    assignedToName: assigneeUid ? assignedToName : null,
    status: afterStatus,
    latestTimelineEvent,
  };
}

export const adminAssignReport = onCallV2(
  protectedCallableV2FeedbackOptions,
  async (request) => {
    try {
      return await adminAssignReportHandler(request.data, toCallableContextFromV2(request));
    } catch (error) {
      throw normalizeCallableErrorForV2(error);
    }
  }
);

async function adminClaimNextReportHandler(
  data: unknown,
  context: CallableContextLike
) {
  const payload = (data && typeof data === "object")
    ? (data as Record<string, unknown>)
    : {};
  const actor = await requireStaffContext(context);
  await requireFeatureWritable("reports");
  if (actor.role === "resident") {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Only staff can claim reports from queue."
    );
  }

  const requestedOfficeId = coerceString(payload.officeId);
  const scopeOfficeId = isMunicipalAdminRole(actor.role) ? requestedOfficeId : actor.officeId;
  if (!isMunicipalAdminRole(actor.role) && !scopeOfficeId) {
    throw new functions.https.HttpsError(
      "failed-precondition",
      "Office-scoped report managers must have an office assignment."
    );
  }

  const queueStatuses = ["submitted", "acknowledged", "in_review"];
  let claimQuery: FirebaseFirestore.Query = db
    .collection("reports")
    .where("assignedToUid", "==", null)
    .where("status", "in", queueStatuses);

  if (scopeOfficeId) {
    claimQuery = claimQuery.where("officeId", "==", scopeOfficeId);
  }
  claimQuery = claimQuery.orderBy("createdAt", "asc").limit(10);

  const candidates = await claimQuery.get();
  if (candidates.empty) {
    throw new functions.https.HttpsError("not-found", "No available reports in queue.");
  }

  const actorMeta = reportActorMeta(actor, context);
  for (const candidate of candidates.docs) {
    const claimResult = await db.runTransaction(async (tx) => {
      const reportRef = db.collection("reports").doc(candidate.id);
      const snap = await tx.get(reportRef);
      if (!snap.exists) {
        return null;
      }

      const row = (snap.data() ?? {}) as Record<string, unknown>;
      if (!isQueueEligibleReport(row)) {
        return null;
      }
      if (scopeOfficeId && coerceString(row.officeId) !== scopeOfficeId) {
        return null;
      }
      if (!canClaimReportInActorScope(actor, row)) {
        return null;
      }

      const previousStatus = normalizeReportStatusInput(row.status ?? "submitted");
      const beforeAssignedToUid = coerceString(row.assignedToUid);
      const assignedName = actorDisplayName(actor);
      const resolvedAssignedOfficeId = actor.officeId ?? coerceString(row.officeId) ?? null;

      tx.set(
        reportRef,
        {
          assignedToUid: actor.uid,
          assignedToName: assignedName,
          assignedOfficeId: resolvedAssignedOfficeId,
          status: "assigned",
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          ...actorMeta,
        },
        {merge: true}
      );
      tx.set(reportRef.collection("history").doc(), {
        type: "assigned",
        fromStatus: previousStatus,
        toStatus: "assigned",
        assignedToUid: actor.uid,
        assignedToName: assignedName,
        message: "Claimed from queue",
        byUid: actor.uid,
        byName: actorMeta.lastActionByName,
        byRole: actor.role,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      return {
        reportId: reportRef.id,
        officeId: coerceString(row.officeId) ?? null,
        beforeAssignedToUid,
        beforeStatus: previousStatus,
      };
    });

    if (claimResult) {
      await addAuditLog({
        action: "report_claimed_from_queue",
        entityType: "report",
        entityId: claimResult.reportId,
        reportId: claimResult.reportId,
        officeId: claimResult.officeId,
        actorUid: actor.uid,
        actorRole: actor.role,
        actorOfficeId: actor.officeId ?? null,
        actorName: actorMeta.lastActionByName,
        before: {
          assignedToUid: claimResult.beforeAssignedToUid,
          status: claimResult.beforeStatus,
        },
        after: {
          assignedToUid: actor.uid,
          status: "assigned",
        },
        message: "Claimed from queue",
      });

      const latestTimelineEvent = await addReportTimeline(claimResult.reportId, {
        type: "CLAIMED",
        actorUid: actor.uid,
        actorRole: actor.role,
        actorName: actorMeta.lastActionByName,
        notes: "Claimed from queue.",
        fromStatus: claimResult.beforeStatus,
        toStatus: "assigned",
      });
      const updatedReportSnapshot = await db.collection("reports").doc(claimResult.reportId).get();
      await sendFeedbackEmailNotification({
        id: claimResult.reportId,
        ...(updatedReportSnapshot.data() ?? {}),
      }, {
        status: "assigned",
        note: latestTimelineEvent.notes,
        updatedAt: latestTimelineEvent.createdAt,
      });

      return {
        success: true,
        reportId: claimResult.reportId,
        assignedToUid: actor.uid,
        status: "assigned",
        officeId: claimResult.officeId,
        latestTimelineEvent,
      };
    }
  }

  throw new functions.https.HttpsError("not-found", "No available reports in queue.");
}

export const adminClaimNextReport = onCallV2(
  protectedCallableV2FeedbackOptions,
  async (request) => {
    try {
      return await adminClaimNextReportHandler(request.data, toCallableContextFromV2(request));
    } catch (error) {
      throw normalizeCallableErrorForV2(error);
    }
  }
);

async function adminRequeueReportHandler(
  data: unknown,
  context: CallableContextLike
) {
  const payload = (data && typeof data === "object")
    ? (data as Record<string, unknown>)
    : {};
  const actor = await requireStaffContext(context);
  await requireFeatureWritable("reports");
  if (!canAssignReportsRole(actor.role)) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Only office_admin, admin, and super_admin can requeue reports."
    );
  }

  const reportId = coerceString(payload.reportId);
  if (!reportId) {
    throw new functions.https.HttpsError("invalid-argument", "reportId is required.");
  }
  const reason = coerceString(payload.reason);
  const reportRef = db.collection("reports").doc(reportId);
  const actorMeta = reportActorMeta(actor, context);

  const result = await db.runTransaction(async (tx) => {
    const snap = await tx.get(reportRef);
    if (!snap.exists) {
      throw new functions.https.HttpsError("not-found", "Report not found.");
    }
    const row = (snap.data() ?? {}) as Record<string, unknown>;
    if (!reportInActorScope(actor, row)) {
      throw new functions.https.HttpsError(
        "permission-denied",
        "You are not allowed to manage this report."
      );
    }

    const previousStatus = normalizeReportStatusInput(row.status ?? "submitted");
    const nextStatus = previousStatus === "assigned" ? "in_review" : previousStatus;
    const beforeAssignedToUid = coerceString(row.assignedToUid);
    const beforeAssignedToName = coerceString(row.assignedToName);
    const beforeAssignedOfficeId = coerceString(row.assignedOfficeId);

    tx.set(
      reportRef,
      {
        assignedToUid: null,
        assignedToName: null,
        assignedOfficeId: null,
        status: nextStatus,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        ...actorMeta,
      },
      {merge: true}
    );
    tx.set(reportRef.collection("history").doc(), {
      type: "requeued",
      fromStatus: previousStatus,
      toStatus: nextStatus,
      message: reason ? `Requeued to queue: ${reason}` : "Requeued to queue",
      byUid: actor.uid,
      byName: actorMeta.lastActionByName,
      byRole: actor.role,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return {
      reportId,
      officeId: coerceString(row.officeId) ?? null,
      previousStatus,
      nextStatus,
      beforeAssignedToUid,
      beforeAssignedToName,
      beforeAssignedOfficeId,
    };
  });

  await addAuditLog({
    action: "report_requeued",
    entityType: "report",
    entityId: result.reportId,
    reportId: result.reportId,
    officeId: result.officeId,
    actorUid: actor.uid,
    actorRole: actor.role,
    actorOfficeId: actor.officeId ?? null,
    actorName: actorMeta.lastActionByName,
    before: {
      assignedToUid: result.beforeAssignedToUid,
      assignedToName: result.beforeAssignedToName,
      assignedOfficeId: result.beforeAssignedOfficeId,
      status: result.previousStatus,
    },
    after: {
      assignedToUid: null,
      assignedToName: null,
      assignedOfficeId: null,
      status: result.nextStatus,
    },
    message: reason ? `Requeued report. Reason: ${reason}` : "Requeued report.",
  });

  const latestTimelineEvent = await addReportTimeline(result.reportId, {
    type: "REQUEUED",
    actorUid: actor.uid,
    actorRole: actor.role,
    actorName: actorMeta.lastActionByName,
    notes: reason ? `Requeued to queue: ${reason}` : "Requeued to queue.",
    fromStatus: result.previousStatus,
    toStatus: result.nextStatus,
  });
  if (result.nextStatus !== result.previousStatus) {
    const updatedReportSnapshot = await reportRef.get();
    await sendFeedbackEmailNotification({
      id: result.reportId,
      ...(updatedReportSnapshot.data() ?? {}),
    }, {
      status: result.nextStatus,
      note: latestTimelineEvent.notes,
      updatedAt: latestTimelineEvent.createdAt,
    });
  }

  return {
    success: true,
    reportId: result.reportId,
    assignedToUid: null,
    status: result.nextStatus,
    latestTimelineEvent,
  };
}

export const adminRequeueReport = onCallV2(
  protectedCallableV2FeedbackOptions,
  async (request) => {
    try {
      return await adminRequeueReportHandler(request.data, toCallableContextFromV2(request));
    } catch (error) {
      throw normalizeCallableErrorForV2(error);
    }
  }
);

function normalizePublicIssuePayload(
  payload: Record<string, unknown>
): Omit<PublicReportWriteInput, "trackingNumber" | "officeId" | "officeName" | "priority" | "sla" | "duplicateOf" | "duplicateWarning" | "attachments"> {
  const category = requiredPublicField(payload.category || "general", "Category", 80)
    .toLowerCase()
    .replace(/\s+/g, "_");
  const title = requiredPublicField(payload.title, "Issue title", 120);
  const description = optionalPublicField(payload.description, 2000);
  if (!description) {
    throw new functions.https.HttpsError("invalid-argument", "Description is required.");
  }
  const barangay = requiredPublicField(payload.barangay || "Unspecified", "Barangay", 120);
  const rawLocation = requiredPublicField(payload.location, "Location", 200);
  const reporterName = optionalPublicField(payload.name, 120) || "Anonymous";
  const reporterContact = optionalPublicField(payload.contact, 120) || "Not provided";

  return {
    lane: "issue",
    reportKind: "report",
    serviceKey: "public_issue",
    title,
    subject: title,
    category,
    emergencyType: null,
    barangay,
    landmark: rawLocation,
    description,
    message: description,
    reporterName,
    reporterContact,
    source: normalizePublicSource(payload.source),
    geo: normalizeGeoInput(payload.geo),
  };
}

function normalizeEmergencyPayload(
  payload: Record<string, unknown>
): Omit<PublicReportWriteInput, "trackingNumber" | "officeId" | "officeName" | "priority" | "sla" | "duplicateOf" | "duplicateWarning" | "attachments"> & {
  emergencyTypeKey: EmergencyTypeKey;
  photoDataUrl: string;
} {
  const emergencyTypeKey = normalizeEmergencyType(payload.emergencyType);
  const barangay = requiredPublicField(payload.barangay, "Barangay", 120);
  const landmark = requiredPublicField(payload.landmark, "Purok / street / landmark", 200);
  const reporterName = requiredPublicField(payload.reporterName, "Reporter name", 120);
  const reporterContact = requiredPublicField(payload.contactNumber, "Contact number", 120);
  const description = optionalPublicField(payload.description, 2000);
  const privacyAccepted = payload.privacyAccepted === true;
  if (!privacyAccepted) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Privacy notice acknowledgement is required."
    );
  }

  return {
    lane: "emergency",
    reportKind: "report",
    serviceKey: "public_emergency",
    title: `${emergencyTypeLabel(emergencyTypeKey)} - ${barangay}`,
    subject: `${emergencyTypeLabel(emergencyTypeKey)} - ${barangay}`,
    category: emergencyTypeKey,
    emergencyType: emergencyTypeKey,
    emergencyTypeKey,
    barangay,
    landmark,
    description,
    message: description,
    reporterName,
    reporterContact,
    source: normalizePublicSource(payload.source),
    geo: normalizeGeoInput(payload.geo),
    photoDataUrl: optionalPublicField(payload.photoDataUrl, 4 * 1024 * 1024),
  };
}

function normalizePublicFeedbackPayload(
  payload: Record<string, unknown>
): Omit<PublicReportWriteInput, "trackingNumber" | "officeId" | "officeName" | "priority" | "sla" | "duplicateOf" | "duplicateWarning" | "attachments"> & {
  attachmentDataUrl: string;
} {
  const privacyAccepted =
    payload.privacyAccepted === true ||
    String(payload.privacyAccepted ?? "").trim().toLowerCase() === "true";
  if (!privacyAccepted) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Privacy notice acknowledgement is required."
    );
  }
  const category = requiredPublicField(payload.category || "general feedback", "Category", 80)
    .toLowerCase()
    .replace(/\s+/g, "_");
  const subject = requiredPublicField(payload.subject ?? payload.title, "Subject", 120);
  const message = requiredPublicField(payload.message ?? payload.description, "Message", 2000);
  const reporterEmail = requiredPublicField(payload.email, "Email address", 160);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(reporterEmail)) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Email address is invalid."
    );
  }
  const reporterName = optionalPublicField(payload.name, 120) || "Anonymous";
  const reporterContact = optionalPublicField(payload.contact, 120) || "Not provided";
  const barangay = optionalPublicField(payload.barangay, 120) || "Unspecified";
  const landmark = optionalPublicField(payload.location, 200) || "N/A";
  const preferredDepartment = optionalPublicField(payload.department, 120) || null;

  return {
    lane: "feedback",
    reportKind: "feedback",
    serviceKey: "citizen_feedback",
    title: subject,
    subject,
    category,
    emergencyType: null,
    barangay,
    landmark,
    description: message,
    message,
    reporterName,
    reporterContact,
    reporterEmail,
    preferredDepartment,
    source: normalizePublicSource(payload.source),
    geo: normalizeGeoInput(payload.geo),
    attachmentDataUrl: optionalPublicField(
      payload.attachmentDataUrl ?? payload.photoDataUrl,
      7 * 1024 * 1024
    ),
  };
}

function normalizeFeatureSuggestionList(
  raw: unknown,
  maxItems = 8,
  maxLength = 120
): string[] {
  if (!Array.isArray(raw)) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const entry of raw) {
    const text = optionalPublicField(entry, maxLength);
    if (!text || seen.has(text)) continue;
    seen.add(text);
    out.push(text);
    if (out.length >= maxItems) break;
  }
  return out;
}

function normalizePublicFeatureSuggestionPayload(
  payload: Record<string, unknown>
): {
  selectedFeatures: string[];
  note: string | null;
  page: string;
  source: string | null;
  deviceId: string | null;
} {
  const rawSelectedFeatures = Array.isArray(payload.selectedFeatures) ?
    payload.selectedFeatures :
    (Array.isArray(payload.features) ? payload.features : []);
  const selectedFeatures = normalizeFeatureSuggestionList(rawSelectedFeatures);
  const note = optionalPublicField(
    payload.note ?? payload.message ?? payload.details,
    1500
  );
  if (selectedFeatures.length === 0 && !note) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Select at least one feature or add a short suggestion."
    );
  }
  const page = optionalPublicField(payload.page ?? payload.sourcePage, 160) || "/services";
  const deviceId = optionalPublicField(payload.deviceId, 160);

  return {
    selectedFeatures,
    note,
    page,
    source: normalizePublicSource(payload.source),
    deviceId,
  };
}

async function enforceFeatureSuggestionDailyLimit(
  req: functions.https.Request,
  deviceId: string | null
): Promise<{ipHash: string; deviceHash: string | null}> {
  const ipHash = sha256(getRequestIp(req)).substring(0, 32);
  const deviceHash = deviceId ? sha256(deviceId).substring(0, 32) : null;
  const ipRef = db.collection("feature_suggestion_rate_limits").doc(`ip_${ipHash}`);
  const deviceRef = deviceHash ?
    db.collection("feature_suggestion_rate_limits").doc(`device_${deviceHash}`) :
    null;
  const windowStart = Date.now() - FEATURE_SUGGESTION_COOLDOWN_MS;

  await db.runTransaction(async (tx) => {
    const refs = deviceRef ? [ipRef, deviceRef] : [ipRef];
    const snaps = await Promise.all(refs.map((ref) => tx.get(ref)));

    for (const snap of snaps) {
      const data = snap.exists ? snap.data() ?? {} : {};
      const lastAttemptMs = parseEpochMs(data.lastSubmittedAt);
      if (lastAttemptMs >= windowStart) {
        throw new functions.https.HttpsError(
          "resource-exhausted",
          "Only one must-have feature suggestion per device or connection is allowed every 24 hours."
        );
      }
    }

    tx.set(ipRef, {
      scope: "ip",
      hash: ipHash,
      lastSubmittedAt: admin.firestore.FieldValue.serverTimestamp(),
      expiresAt: admin.firestore.Timestamp.fromMillis(Date.now() + FEATURE_SUGGESTION_COOLDOWN_MS),
    }, {merge: true});

    if (deviceRef && deviceHash) {
      tx.set(deviceRef, {
        scope: "device",
        hash: deviceHash,
        lastSubmittedAt: admin.firestore.FieldValue.serverTimestamp(),
        expiresAt: admin.firestore.Timestamp.fromMillis(Date.now() + FEATURE_SUGGESTION_COOLDOWN_MS),
      }, {merge: true});
    }
  });

  return {
    ipHash,
    deviceHash,
  };
}

async function handleSubmitPublicIssueHttpRequest(
  req: functions.https.Request,
  res: functions.Response<unknown>
) {
  const corsAllowed = applyPublicReportCors(req, res);
  if (!corsAllowed) {
    res.status(403).json({error: "Origin not allowed.", code: "permission-denied"});
    return;
  }
  if (req.method === "OPTIONS") {
    res.status(204).send("");
    return;
  }
  if (req.method !== "POST") {
    res.status(405).json({error: "Method not allowed.", code: "method-not-allowed"});
    return;
  }

  try {
    await requirePublicReportLaneAvailability("issue", {write: true});
    await enforcePublicReportRateLimit(req, "issue");
    const payload = req.body && typeof req.body === "object" ?
      (req.body as Record<string, unknown>) :
      {};
    const normalized = normalizePublicIssuePayload(payload);
    const trackingNumber = generatePublicTrackingNumber("RPT");
    const routedOffice = {
      // TODO: Replace this safe default with a category-based office router once official office IDs are finalized.
      officeId: "MDRRMO",
      officeName: "Municipal Disaster Risk Reduction and Management Office",
    };
    const now = new Date();
    const result = await createPublicReportDocument({
      ...normalized,
      trackingNumber,
      officeId: routedOffice.officeId,
      officeName: routedOffice.officeName,
      priority: deriveIssuePriority(normalized.category),
      attachments: [],
      duplicateOf: null,
      duplicateWarning: null,
      sla: buildEmergencySla(now),
    });

    res.status(200).json({
      success: true,
      trackingNumber: result.trackingNumber,
      lane: "issue",
    });
  } catch (error) {
    const {code, message, statusCode} = publicReportHttpStatus(error);
    functions.logger.warn("submitPublicReport request failed.", {
      code,
      statusCode,
      ipHash: sha256(getRequestIp(req)).substring(0, 16),
      region: REGION,
    });
    res.status(statusCode).json({error: message, code});
  }
}

export const submitPublicReport = onRequestV2(
  {region: REGION},
  handleSubmitPublicIssueHttpRequest
);

async function handleSubmitEmergencyReportHttpRequest(
  req: functions.https.Request,
  res: functions.Response<unknown>
) {
  const corsAllowed = applyPublicReportCors(req, res);
  if (!corsAllowed) {
    res.status(403).json({error: "Origin not allowed.", code: "permission-denied"});
    return;
  }
  if (req.method === "OPTIONS") {
    res.status(204).send("");
    return;
  }
  if (req.method !== "POST") {
    res.status(405).json({error: "Method not allowed.", code: "method-not-allowed"});
    return;
  }

  try {
    await requirePublicReportLaneAvailability("emergency", {write: true});
    await enforcePublicReportRateLimit(req, "emergency");
    const payload = req.body && typeof req.body === "object" ?
      (req.body as Record<string, unknown>) :
      {};
    const normalized = normalizeEmergencyPayload(payload);
    const routingRule = EMERGENCY_ROUTING_RULES[normalized.emergencyTypeKey];
    const duplicate = await detectEmergencyDuplicate(
      normalized.emergencyTypeKey,
      normalized.barangay,
      normalized.geo
    );
    const trackingNumber = generatePublicTrackingNumber("EMR");
    const now = new Date();
    const provisionalReportId = db.collection("reports").doc().id;
    const photoAttachment = normalized.photoDataUrl ?
      await uploadPublicReportAttachment(
        provisionalReportId,
        "incident_photo",
        normalized.photoDataUrl
      ) :
      null;
    const attachments = photoAttachment ? [photoAttachment] : [];

    // The report write uses a deterministic document id when an attachment exists
    // so the uploaded path and report document stay in sync.
    const result = await createPublicReportDocument({
      ...normalized,
      reportId: provisionalReportId,
      emergencyType: normalized.emergencyTypeKey,
      trackingNumber,
      officeId: routingRule.officeId,
      officeName: routingRule.officeName,
      priority: deriveEmergencyPriority(normalized.emergencyTypeKey),
      attachments,
      duplicateOf: duplicate.duplicateOf,
      duplicateWarning: duplicate.duplicateWarning,
      sla: buildEmergencySla(now),
    });

    // Emergency intake is escalated immediately to the routed office queue and
    // municipal admins so the 1-hour acknowledgement target is visible from the
    // moment the ticket lands.
    await recordReportEscalation(result.reportId, {
      ...normalized,
      officeId: routingRule.officeId,
      currentOfficeId: routingRule.officeId,
      assignedToUid: null,
      status: "submitted",
      title: normalized.title,
    }, "emergency", "Emergency lane reported. Immediate dispatch review required.");

    res.status(200).json({
      success: true,
      trackingNumber: result.trackingNumber,
      duplicateWarning: duplicate.duplicateWarning,
      lane: "emergency",
    });
  } catch (error) {
    const {code, message, statusCode} = publicReportHttpStatus(error);
    functions.logger.warn("submitEmergencyReport request failed.", {
      code,
      statusCode,
      ipHash: sha256(getRequestIp(req)).substring(0, 16),
      region: REGION,
    });
    res.status(statusCode).json({error: message, code});
  }
}

export const submitEmergencyReport = onRequestV2(
  {region: REGION},
  handleSubmitEmergencyReportHttpRequest
);

async function handleSubmitPublicFeedbackHttpRequest(
  req: functions.https.Request,
  res: functions.Response<unknown>
) {
  const corsAllowed = applyPublicReportCors(req, res);
  if (!corsAllowed) {
    res.status(403).json({error: "Origin not allowed.", code: "permission-denied"});
    return;
  }
  if (req.method === "OPTIONS") {
    res.status(204).send("");
    return;
  }
  if (req.method !== "POST") {
    res.status(405).json({error: "Method not allowed.", code: "method-not-allowed"});
    return;
  }

  try {
    await requirePublicReportLaneAvailability("feedback", {write: true});
    await enforcePublicReportRateLimit(req, "feedback");
    const payload = req.body && typeof req.body === "object" ?
      (req.body as Record<string, unknown>) :
      {};
    const normalized = normalizePublicFeedbackPayload(payload);
    const now = new Date();
    const trackingNumber = generatePublicTrackingNumber("FBK");
    const reportId = db.collection("reports").doc().id;
    const {attachmentDataUrl, ...reportInput} = normalized;
    const attachment = attachmentDataUrl ?
      await uploadPublicReportAttachment(reportId, "feedback_attachment", attachmentDataUrl, {
        allowedContentTypes: [
          /^image\//,
          "application/pdf",
          "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ],
        maxBytes: 5 * 1024 * 1024,
      }) :
      null;
    const attachments = attachment ? [attachment] : [];

    await createPublicReportDocument({
      ...reportInput,
      reportId,
      trackingNumber,
      officeId: FEEDBACK_ROUTING_RULE.officeId,
      officeName: FEEDBACK_ROUTING_RULE.officeName,
      priority: "low",
      attachments,
      duplicateOf: null,
      duplicateWarning: null,
      sla: buildEmergencySla(now),
    });

    const ticketSnap = await db.collection("reports").doc(reportId).get();
    const ticketRow = {
      id: reportId,
      ...(ticketSnap.data() ?? {}),
    };
    const publicTicket = sanitizePublicReportTicket(ticketRow);
    await sendFeedbackEmailNotification(ticketRow, {
      status: "submitted",
      updatedAt: now.toISOString(),
    });

    res.status(200).json({
      success: true,
      lane: "feedback",
      ...publicTicket,
      latest_status: "submitted",
      status: "submitted",
      created_at: now.toISOString(),
      updated_at: now.toISOString(),
      updates: [],
      timeline: [],
    });
  } catch (error) {
    const {code, message, statusCode} = publicReportHttpStatus(error);
    functions.logger.warn("submitPublicFeedback request failed.", {
      code,
      statusCode,
      ipHash: sha256(getRequestIp(req)).substring(0, 16),
      region: REGION,
    });
    res.status(statusCode).json({error: message, code});
  }
}

export const submitPublicFeedback = onRequestV2(
  {region: REGION, secrets: FEEDBACK_EMAIL_FUNCTION_SECRETS},
  handleSubmitPublicFeedbackHttpRequest
);

async function handleTrackPublicFeedbackHttpRequest(
  req: functions.https.Request,
  res: functions.Response<unknown>
) {
  const corsAllowed = applyPublicReportCors(req, res);
  if (!corsAllowed) {
    res.status(403).json({error: "Origin not allowed.", code: "permission-denied"});
    return;
  }
  if (req.method === "OPTIONS") {
    res.status(204).send("");
    return;
  }
  if (req.method !== "POST") {
    res.status(405).json({error: "Method not allowed.", code: "method-not-allowed"});
    return;
  }

  try {
    await requirePublicReportLaneAvailability("feedback");
    const payload = req.body && typeof req.body === "object" ?
      (req.body as Record<string, unknown>) :
      {};
    const ticketNumber = normalizePublicTicketNumber(payload);
    await enforcePublicReportLookupRateLimit(req, ticketNumber);

    const snap = await db.collection("reports")
      .where("trackingNumber", "==", ticketNumber)
      .limit(1)
      .get();

    if (snap.empty) {
      throw new functions.https.HttpsError("not-found", "Ticket not found.");
    }

    const doc = snap.docs[0];
    const row = (doc.data() ?? {}) as Record<string, unknown>;
    if (getPublicReportLane(row) !== "feedback") {
      throw new functions.https.HttpsError("not-found", "Ticket not found.");
    }

    const ticket = sanitizePublicReportTicket({
      id: doc.id,
      ...row,
    });
    const timeline = await loadPublicReportTimeline(doc.ref);

    res.status(200).json({
      success: true,
      ...ticket,
      latest_status: coerceString(row.status) ?? "submitted",
      status: coerceString(row.status) ?? "submitted",
      updates: timeline,
      timeline,
    });
  } catch (error) {
    const httpsError = error as functions.https.HttpsError;
    const code = String(httpsError?.code ?? "internal");
    const message = String(httpsError?.message ?? "Feedback tracking lookup failed.");
    const statusCode =
      code === "invalid-argument" ? 400 :
      code === "not-found" ? 404 :
      code === "resource-exhausted" ? 429 :
      code === "permission-denied" ? 403 : 500;
    functions.logger.warn("trackPublicFeedback request failed.", {
      code,
      statusCode,
      ipHash: sha256(getRequestIp(req)).substring(0, 16),
      region: REGION,
    });
    res.status(statusCode).json({error: message, code});
  }
}

export const trackPublicFeedback = onRequestV2(
  {region: REGION},
  handleTrackPublicFeedbackHttpRequest
);

async function handleSubmitFeatureSuggestionHttpRequest(
  req: functions.https.Request,
  res: functions.Response<unknown>
) {
  const corsAllowed = applyPublicReportCors(req, res);
  if (!corsAllowed) {
    res.status(403).json({error: "Origin not allowed.", code: "permission-denied"});
    return;
  }
  if (req.method === "OPTIONS") {
    res.status(204).send("");
    return;
  }
  if (req.method !== "POST") {
    res.status(405).json({error: "Method not allowed.", code: "method-not-allowed"});
    return;
  }

  try {
    const settings = await getEffectiveSystemSettings();
    if (settings.readOnly) {
      throw new functions.https.HttpsError(
        "failed-precondition",
        "System is in read-only mode. Suggestions are temporarily paused."
      );
    }
    await enforcePublicReportRateLimit(req, "feature_suggestion");
    const payload = req.body && typeof req.body === "object" ?
      (req.body as Record<string, unknown>) :
      {};
    const normalized = normalizePublicFeatureSuggestionPayload(payload);
    const {ipHash, deviceHash} = await enforceFeatureSuggestionDailyLimit(req, normalized.deviceId);
    const createdAt = admin.firestore.Timestamp.now();
    const suggestionRef = db.collection("feature_suggestions").doc();

    await suggestionRef.set({
      selectedFeatures: normalized.selectedFeatures,
      note: normalized.note ?? null,
      page: normalized.page,
      source: normalized.source ?? "web",
      status: "submitted",
      visibility: "super_admin_only",
      ipHash,
      deviceHash,
      origin: coerceString(req.headers.origin),
      userAgent: coerceString(req.headers["user-agent"]),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      createdAtIso: createdAt.toDate().toISOString(),
    });

    res.status(200).json({
      success: true,
      suggestionId: suggestionRef.id,
      createdAt: createdAt.toDate().toISOString(),
    });
  } catch (error) {
    const {code, message, statusCode} = publicReportHttpStatus(error);
    functions.logger.warn("submitFeatureSuggestion request failed.", {
      code,
      statusCode,
      ipHash: sha256(getRequestIp(req)).substring(0, 16),
      region: REGION,
    });
    res.status(statusCode).json({error: message, code});
  }
}

export const submitFeatureSuggestion = onRequestV2(
  {region: REGION},
  handleSubmitFeatureSuggestionHttpRequest
);

async function civilRegistrySubmitHandler(
  data: unknown
) {
  await requireFeatureWritable("civilRegistry");
  const payload = data && typeof data === "object"
    ? (data as Record<string, unknown>)
    : {};
  const normalized = normalizeCivilRegistryPayload(payload, "online");
  const requestRef = db.collection("civil_registry_requests").doc();
  let refNo = "";

  await db.runTransaction(async (tx) => {
    refNo = await nextCivilRegistryRefNo(tx);
    tx.set(requestRef, {
      refNo,
      status: "Submitted",
      requestType: normalized.requestType,
      submissionMode: "online",
      purpose: normalized.purpose,
      requester: normalized.requester,
      details: normalized.details,
      representative: normalized.representative,
      verifierLastNameNormalized: normalized.verifierLastNameNormalized,
      officeId: CIVIL_REGISTRY_DEFAULT_OFFICE_ID,
      submittedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      onsitePaymentOnly: true,
      noOnlinePayment: true,
    });
    tx.set(civilRegistryHistoryRef(requestRef.id).doc(), {
      oldStatus: null,
      newStatus: "Submitted",
      remarks: "Request submitted online.",
      changedByUid: null,
      changedByName: "Public Intake",
      changedByRole: "public",
      actionType: "submit",
      changedAt: admin.firestore.FieldValue.serverTimestamp(),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  });

  await addAuditLog({
    action: "civil_registry_request_submitted",
    entityType: "civil_registry_request",
    entityId: requestRef.id,
    refNo,
    officeId: CIVIL_REGISTRY_DEFAULT_OFFICE_ID,
    actorUid: null,
    actorRole: "public",
    actorName: "Public Intake",
    before: null,
    after: {status: "Submitted", requestType: normalized.requestType},
    message: "Civil registry request submitted via online intake.",
    timestamp: admin.firestore.FieldValue.serverTimestamp(),
  });

  return {
    success: true,
    requestId: requestRef.id,
    refNo,
    status: "Submitted",
    onsitePaymentOnly: true,
  };
}

export const civilRegistrySubmit = onCallV2({region: REGION}, async (request) => {
  try {
    return await civilRegistrySubmitHandler(request.data);
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

async function civilRegistryCheckStatusHandler(
  data: unknown
) {
  await requireFeatureEnabled("civilRegistry");
  const payload = data && typeof data === "object"
    ? (data as Record<string, unknown>)
    : {};

  const refNo = requiredStringField(payload.refNo, "Reference number").toUpperCase();
  const verifierLastName = normalizeVerifierLastName(payload.verifierLastName);
  const snapshot = await db
    .collection("civil_registry_requests")
    .where("refNo", "==", refNo)
    .limit(1)
    .get();

  if (snapshot.empty) {
    throw new functions.https.HttpsError("not-found", "Request not found.");
  }

  const rowDoc = snapshot.docs[0];
  const row = (rowDoc.data() ?? {}) as Record<string, unknown>;
  if (toLowerTrimmed(row.verifierLastNameNormalized) !== verifierLastName) {
    throw new functions.https.HttpsError("not-found", "Request not found.");
  }

  const historySnapshot = await civilRegistryHistoryRef(rowDoc.id)
    .orderBy("changedAt", "desc")
    .limit(25)
    .get();
  const timeline = historySnapshot.docs.map((entry) => {
    const dataRow = (entry.data() ?? {}) as Record<string, unknown>;
    return {
      id: entry.id,
      oldStatus: coerceString(dataRow.oldStatus),
      newStatus: coerceString(dataRow.newStatus) ?? "",
      remarks: coerceString(dataRow.remarks),
      changedAt: toIsoString(dataRow.changedAt),
      actionType: coerceString(dataRow.actionType) ?? "status",
    };
  });

  return {
    success: true,
    request: sanitizeCivilRegistryPublic({
      ...row,
      refNo,
    }),
    timeline,
    notices: [
      "Online intake only: no online payment.",
      "Pay onsite at Municipal Cashier/Treasurer after status is Approved for Payment.",
      "Release requires valid Official Receipt (OR).",
    ],
  };
}

export const civilRegistryCheckStatus = onCallV2({region: REGION}, async (request) => {
  try {
    return await civilRegistryCheckStatusHandler(request.data);
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

async function adminListCivilRegistryRequestsHandler(
  data: unknown,
  context: CallableContextLike
) {
  await requireFeatureEnabled("civilRegistry");
  await requireCivilRegistryStaffContext(context);
  const payload = data && typeof data === "object"
    ? (data as Record<string, unknown>)
    : {};
  const statusFilter = coerceString(payload.status);
  const typeFilter = coerceString(payload.requestType);
  const modeFilter = coerceString(payload.submissionMode);
  const fromDate = payload.fromDate ? new Date(String(payload.fromDate)) : null;
  const toDate = payload.toDate ? new Date(String(payload.toDate)) : null;
  const rawLimit = typeof payload.limit === "number" ? Math.floor(payload.limit) : 250;
  const listLimit = Math.max(20, Math.min(500, rawLimit));

  const snapshot = await db
    .collection("civil_registry_requests")
    .orderBy("submittedAt", "desc")
    .limit(listLimit)
    .get();

  let items = snapshot.docs.map((doc) => civilRegistryRequestListItem(doc.id, doc.data() ?? {}));
  if (statusFilter) {
    items = items.filter((item) => item.status === statusFilter);
  }
  if (typeFilter) {
    items = items.filter((item) => item.requestType === typeFilter);
  }
  if (modeFilter) {
    items = items.filter((item) => item.submissionMode === modeFilter);
  }
  if (fromDate && !Number.isNaN(fromDate.getTime())) {
    const fromTime = fromDate.getTime();
    items = items.filter((item) => parseEpochMs(item.submittedAt) >= fromTime);
  }
  if (toDate && !Number.isNaN(toDate.getTime())) {
    const toTime = toDate.getTime() + (24 * 60 * 60 * 1000) - 1;
    items = items.filter((item) => parseEpochMs(item.submittedAt) <= toTime);
  }

  return {
    items,
    statuses: CIVIL_REGISTRY_STATUSES,
    requestTypes: CIVIL_REGISTRY_REQUEST_TYPES,
  };
}

export const adminListCivilRegistryRequests = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await adminListCivilRegistryRequestsHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

async function adminGetCivilRegistryRequestHandler(
  data: unknown,
  context: CallableContextLike
) {
  await requireFeatureEnabled("civilRegistry");
  await requireCivilRegistryStaffContext(context);
  const payload = data && typeof data === "object"
    ? (data as Record<string, unknown>)
    : {};
  const requestId = coerceString(payload.requestId);
  if (!requestId) {
    throw new functions.https.HttpsError("invalid-argument", "requestId is required.");
  }

  const requestSnap = await db.collection("civil_registry_requests").doc(requestId).get();
  if (!requestSnap.exists) {
    throw new functions.https.HttpsError("not-found", "Civil registry request not found.");
  }
  const row = (requestSnap.data() ?? {}) as Record<string, unknown>;
  const historySnap = await civilRegistryHistoryRef(requestId)
    .orderBy("changedAt", "desc")
    .limit(120)
    .get();
  const history = historySnap.docs.map((entry) => {
    const dataRow = (entry.data() ?? {}) as Record<string, unknown>;
    return {
      id: entry.id,
      oldStatus: coerceString(dataRow.oldStatus),
      newStatus: coerceString(dataRow.newStatus) ?? "",
      remarks: coerceString(dataRow.remarks),
      changedByUid: coerceString(dataRow.changedByUid),
      changedByName: coerceString(dataRow.changedByName),
      changedByRole: coerceString(dataRow.changedByRole),
      changedAt: toIsoString(dataRow.changedAt),
      actionType: coerceString(dataRow.actionType) ?? "status",
    };
  });

  return {
    request: {
      id: requestSnap.id,
      ...row,
      submittedAt: toIsoString(row.submittedAt),
      updatedAt: toIsoString(row.updatedAt),
    },
    history,
  };
}

export const adminGetCivilRegistryRequest = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await adminGetCivilRegistryRequestHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

async function adminCreateCivilRegistryWalkInHandler(
  data: unknown,
  context: CallableContextLike
) {
  const actor = await requireCivilRegistryStaffContext(context);
  await requireFeatureWritable("civilRegistry");
  const payload = data && typeof data === "object"
    ? (data as Record<string, unknown>)
    : {};
  const normalized = normalizeCivilRegistryPayload(payload, "walk-in");
  const requestRef = db.collection("civil_registry_requests").doc();
  let refNo = "";
  const actorMeta = civilRegistryActorMeta(actor, context);

  await db.runTransaction(async (tx) => {
    refNo = await nextCivilRegistryRefNo(tx);
    tx.set(requestRef, {
      refNo,
      status: "Submitted",
      requestType: normalized.requestType,
      submissionMode: "walk-in",
      purpose: normalized.purpose,
      requester: normalized.requester,
      details: normalized.details,
      representative: normalized.representative,
      verifierLastNameNormalized: normalized.verifierLastNameNormalized,
      officeId: actor.officeId ?? CIVIL_REGISTRY_DEFAULT_OFFICE_ID,
      createdByUid: actor.uid,
      createdByName: actorMeta.lastActionByName,
      submittedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      onsitePaymentOnly: true,
      noOnlinePayment: true,
      ...actorMeta,
    });
    tx.set(civilRegistryHistoryRef(requestRef.id).doc(), {
      oldStatus: null,
      newStatus: "Submitted",
      remarks: "Walk-in request encoded by staff.",
      changedByUid: actor.uid,
      changedByName: actorMeta.lastActionByName,
      changedByRole: actor.role,
      actionType: "walk-in-encode",
      changedAt: admin.firestore.FieldValue.serverTimestamp(),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  });

  await addAuditLog({
    action: "civil_registry_walkin_encoded",
    entityType: "civil_registry_request",
    entityId: requestRef.id,
    refNo,
    officeId: actor.officeId ?? CIVIL_REGISTRY_DEFAULT_OFFICE_ID,
    actorUid: actor.uid,
    actorRole: actor.role,
    actorName: actorMeta.lastActionByName,
    before: null,
    after: {status: "Submitted", requestType: normalized.requestType, submissionMode: "walk-in"},
    message: "Walk-in civil registry request encoded.",
    timestamp: admin.firestore.FieldValue.serverTimestamp(),
  });

  return {
    success: true,
    requestId: requestRef.id,
    refNo,
    status: "Submitted",
  };
}

export const adminCreateCivilRegistryWalkIn = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await adminCreateCivilRegistryWalkInHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

async function adminUpdateCivilRegistryStatusHandler(
  data: unknown,
  context: CallableContextLike
) {
  const actor = await requireCivilRegistryStaffContext(context);
  await requireFeatureWritable("civilRegistry");
  const payload = data && typeof data === "object"
    ? (data as Record<string, unknown>)
    : {};
  const requestId = coerceString(payload.requestId);
  const nextStatus = normalizeCivilRegistryStatus(payload.status);
  const remarks = coerceString(payload.remarks);
  if (!requestId) {
    throw new functions.https.HttpsError("invalid-argument", "requestId is required.");
  }
  const restrictedStatuses = new Set(["Paid", "Released"]);
  if (restrictedStatuses.has(nextStatus)) {
    throw new functions.https.HttpsError(
      "failed-precondition",
      `Use dedicated workflow action for status ${nextStatus}.`
    );
  }
  if (remarksRequiredForCivilRegistryStatus(nextStatus) && !remarks) {
    throw new functions.https.HttpsError("invalid-argument", `Remarks are required for status "${nextStatus}".`);
  }

  const actorMeta = civilRegistryActorMeta(actor, context);
  const requestRef = db.collection("civil_registry_requests").doc(requestId);
  let previousStatus = "Submitted";

  await db.runTransaction(async (tx) => {
    const snap = await tx.get(requestRef);
    if (!snap.exists) {
      throw new functions.https.HttpsError("not-found", "Civil registry request not found.");
    }
    const row = (snap.data() ?? {}) as Record<string, unknown>;
    previousStatus = normalizeCivilRegistryStatus(row.status ?? "Submitted");
    validateCivilRegistryTransition(previousStatus, nextStatus);
    if (nextStatus === "Ready for Pickup" && !coerceString((row.payment as Record<string, unknown> | undefined)?.orNo)) {
      throw new functions.https.HttpsError("failed-precondition", "Cannot mark ready for pickup without OR/payment record.");
    }

    const updateData: Record<string, unknown> = {
      status: nextStatus,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      ...actorMeta,
    };
    if (nextStatus === "Ready for Pickup") {
      updateData.release = {
        ...(row.release && typeof row.release === "object" ? row.release as Record<string, unknown> : {}),
        dateReadyForPickup: admin.firestore.FieldValue.serverTimestamp(),
      };
    }
    tx.set(requestRef, updateData, {merge: true});
    tx.set(civilRegistryHistoryRef(requestId).doc(), {
      oldStatus: previousStatus,
      newStatus: nextStatus,
      remarks: remarks ?? null,
      changedByUid: actor.uid,
      changedByName: actorMeta.lastActionByName,
      changedByRole: actor.role,
      actionType: "status-update",
      changedAt: admin.firestore.FieldValue.serverTimestamp(),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  });

  await addAuditLog({
    action: "civil_registry_status_updated",
    entityType: "civil_registry_request",
    entityId: requestId,
    officeId: actor.officeId ?? CIVIL_REGISTRY_DEFAULT_OFFICE_ID,
    actorUid: actor.uid,
    actorRole: actor.role,
    actorName: actorMeta.lastActionByName,
    before: {status: previousStatus},
    after: {status: nextStatus},
    message: remarks ?? `Status changed from ${previousStatus} to ${nextStatus}.`,
    timestamp: admin.firestore.FieldValue.serverTimestamp(),
  });

  return {success: true, requestId, status: nextStatus};
}

export const adminUpdateCivilRegistryStatus = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await adminUpdateCivilRegistryStatusHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

async function adminRecordCivilRegistryPaymentHandler(
  data: unknown,
  context: CallableContextLike
) {
  const actor = await requireCivilRegistryStaffContext(context);
  await requireFeatureWritable("civilRegistry");
  if (!(actor.role === "super_admin" || actor.role === "admin")) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Only super admin or municipal admin can record payment."
    );
  }
  const payload = data && typeof data === "object"
    ? (data as Record<string, unknown>)
    : {};
  const requestId = requiredStringField(payload.requestId, "requestId");
  const orNo = requiredStringField(payload.orNo, "OR number");
  const amount = Number(payload.amount);
  if (!Number.isFinite(amount) || amount <= 0) {
    throw new functions.https.HttpsError("invalid-argument", "Valid amount is required.");
  }
  const datePaidIso = normalizeCivilRegistryDate(payload.datePaid) ?? new Date().toISOString();
  const cashierName = coerceString(payload.cashierName) ?? actorDisplayName(actor);
  const actorMeta = civilRegistryActorMeta(actor, context);
  const requestRef = db.collection("civil_registry_requests").doc(requestId);
  let previousStatus = "Submitted";

  await db.runTransaction(async (tx) => {
    const snap = await tx.get(requestRef);
    if (!snap.exists) {
      throw new functions.https.HttpsError("not-found", "Civil registry request not found.");
    }
    const row = (snap.data() ?? {}) as Record<string, unknown>;
    previousStatus = normalizeCivilRegistryStatus(row.status ?? "Submitted");
    validateCivilRegistryTransition(previousStatus, "Paid");

    tx.set(requestRef, {
      status: "Paid",
      payment: {
        orNo,
        amount,
        datePaid: datePaidIso,
        cashierUid: actor.uid,
        cashierName,
        recordedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      ...actorMeta,
    }, {merge: true});
    tx.set(civilRegistryHistoryRef(requestId).doc(), {
      oldStatus: previousStatus,
      newStatus: "Paid",
      remarks: `Payment recorded. OR: ${orNo}`,
      changedByUid: actor.uid,
      changedByName: cashierName,
      changedByRole: actor.role,
      actionType: "payment-recorded",
      changedAt: admin.firestore.FieldValue.serverTimestamp(),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  });

  await addAuditLog({
    action: "civil_registry_payment_recorded",
    entityType: "civil_registry_request",
    entityId: requestId,
    officeId: actor.officeId ?? "MUNICIPAL_CASHIER",
    actorUid: actor.uid,
    actorRole: actor.role,
    actorName: cashierName,
    before: {status: previousStatus},
    after: {status: "Paid", orNo, amount},
    message: `Payment recorded with OR ${orNo}.`,
    timestamp: admin.firestore.FieldValue.serverTimestamp(),
  });

  return {success: true, requestId, status: "Paid"};
}

export const adminRecordCivilRegistryPayment = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await adminRecordCivilRegistryPaymentHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

async function adminRecordCivilRegistryReleaseHandler(
  data: unknown,
  context: CallableContextLike
) {
  const actor = await requireCivilRegistryStaffContext(context);
  await requireFeatureWritable("civilRegistry");
  const payload = data && typeof data === "object"
    ? (data as Record<string, unknown>)
    : {};
  const requestId = requiredStringField(payload.requestId, "requestId");
  const claimantName = requiredStringField(payload.claimantName, "Claimant name");
  const claimantIdPresented = requiredStringField(payload.claimantIdPresented, "ID presented");
  const releasedByName = coerceString(payload.releasedByName) ?? actorDisplayName(actor);
  const releaseDateIso = normalizeCivilRegistryDate(payload.dateReleased) ?? new Date().toISOString();
  const actorMeta = civilRegistryActorMeta(actor, context);
  const requestRef = db.collection("civil_registry_requests").doc(requestId);
  let previousStatus = "Submitted";
  let orNo = "";

  await db.runTransaction(async (tx) => {
    const snap = await tx.get(requestRef);
    if (!snap.exists) {
      throw new functions.https.HttpsError("not-found", "Civil registry request not found.");
    }
    const row = (snap.data() ?? {}) as Record<string, unknown>;
    previousStatus = normalizeCivilRegistryStatus(row.status ?? "Submitted");
    validateCivilRegistryTransition(previousStatus, "Released");
    const payment = row.payment && typeof row.payment === "object"
      ? (row.payment as Record<string, unknown>)
      : {};
    orNo = coerceString(payment.orNo) ?? "";
    if (!orNo) {
      throw new functions.https.HttpsError(
        "failed-precondition",
        "Cannot release request without Official Receipt (OR)."
      );
    }

    const existingRelease = row.release && typeof row.release === "object"
      ? (row.release as Record<string, unknown>)
      : {};
    tx.set(requestRef, {
      status: "Released",
      release: {
        ...existingRelease,
        dateReadyForPickup: existingRelease.dateReadyForPickup ?? null,
        dateReleased: releaseDateIso,
        claimantName,
        claimantIdPresented,
        releasedByUid: actor.uid,
        releasedByName,
        releasedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      ...actorMeta,
    }, {merge: true});
    tx.set(civilRegistryHistoryRef(requestId).doc(), {
      oldStatus: previousStatus,
      newStatus: "Released",
      remarks: `Released to ${claimantName}.`,
      changedByUid: actor.uid,
      changedByName: releasedByName,
      changedByRole: actor.role,
      actionType: "release-recorded",
      changedAt: admin.firestore.FieldValue.serverTimestamp(),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  });

  await addAuditLog({
    action: "civil_registry_released",
    entityType: "civil_registry_request",
    entityId: requestId,
    officeId: actor.officeId ?? CIVIL_REGISTRY_DEFAULT_OFFICE_ID,
    actorUid: actor.uid,
    actorRole: actor.role,
    actorName: releasedByName,
    before: {status: previousStatus},
    after: {status: "Released", claimantName, claimantIdPresented, orNo},
    message: `Civil registry request released to ${claimantName}.`,
    timestamp: admin.firestore.FieldValue.serverTimestamp(),
  });

  return {success: true, requestId, status: "Released"};
}

export const adminRecordCivilRegistryRelease = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await adminRecordCivilRegistryReleaseHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

async function adminCivilRegistrySummaryHandler(
  _data: unknown,
  context: CallableContextLike
) {
  await requireFeatureEnabled("civilRegistry");
  await requireCivilRegistryStaffContext(context);
  const source = db.collection("civil_registry_requests");
  const now = new Date();
  const dayStart = new Date(now);
  dayStart.setHours(0, 0, 0, 0);

  const totalSubmittedToday = await queryCount(
    source.where("submittedAt", ">=", admin.firestore.Timestamp.fromDate(dayStart))
  );
  const birthCount = await queryCount(source.where("requestType", "==", "Birth Certificate"));
  const marriageCount = await queryCount(source.where("requestType", "==", "Marriage Certificate"));
  const deathCount = await queryCount(source.where("requestType", "==", "Death Certificate"));
  const approvedForPayment = await queryCount(source.where("status", "==", "Approved for Payment"));
  const paid = await queryCount(source.where("status", "==", "Paid"));
  const readyForPickup = await queryCount(source.where("status", "==", "Ready for Pickup"));
  const released = await queryCount(source.where("status", "==", "Released"));
  const pending = await queryCount(
    source.where("status", "in", ["Submitted", "Under Review", "For Compliance", "For Manual Verification"])
  );

  return {
    totalSubmittedToday,
    byType: {
      birth: birthCount,
      marriage: marriageCount,
      death: deathCount,
    },
    approvedForPayment,
    paid,
    readyForPickup,
    released,
    pendingComplianceManual: pending,
  };
}

export const adminCivilRegistrySummary = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await adminCivilRegistrySummaryHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

/**
 * =========================
 * OPS RUNTIME HEALTH
 * =========================
 * Lightweight runtime/version signal for admin operational checks.
 */
export const opsRuntimeHealth = protectedCallableFunctions.https.onCall(async (data, context) => {
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
    "adminUpdateSettings",
    "adminListFeatureSuggestions",
    "adminUpdateReportStatus",
    "staffClaimReport",
    "adminAssignReport",
    "adminClaimNextReport",
    "adminRequeueReport",
    "adminWriteAuditLog",
    "adminSavePostDraft",
    "adminSavePublicDocDraft",
    "adminSaveJobDraft",
    "adminSetEntityStatus",
    "civilRegistrySubmit",
    "civilRegistryCheckStatus",
    "adminListCivilRegistryRequests",
    "adminGetCivilRegistryRequest",
    "adminUpdateCivilRegistryStatus",
    "adminRecordCivilRegistryPayment",
    "adminRecordCivilRegistryRelease",
    "adminCreateCivilRegistryWalkIn",
    "adminCivilRegistrySummary",
    "dtsCreateTrackingRecord",
    "dtsCreateDestinations",
    "dtsDispatchDestinations",
    "dtsInitiateTransfer",
    "dtsConfirmDestinationReceipt",
    "dtsRejectDestination",
    "dtsCancelDestination",
    "dtsConfirmReceipt",
    "dtsRejectTransfer",
    "dtsUpdateStatus",
    "setTrackingPin",
    "dtsTrackByTrackingNo",
    "dtsTrackByQrAndPin",
    "dtsTrackByToken",
    "dtsSaveTrackedDocument",
    "dtsOpenSavedDocument",
    "dtsUnsaveTrackedDocument",
    "dtsListMyDocuments",
    "dtsListQrBatches",
    "generateDtsQrCodes",
    "dtsResolveQrForStaff",
    "exportDtsQrZip",
    "dtsGetGeneratedPdfAccess",
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
export const setUserRole = protectedCallableFunctions.https.onCall(async (data, context) => {
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

  // Only office-scoped roles require office metadata during direct role updates.
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
  await admin.auth().revokeRefreshTokens(uid);

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
 * USER MANAGEMENT (super_admin only)
 * =========================
 */
export const adminListUsers = protectedCallableFunctions.https.onCall(async (data, context) => {
  const actor = await requireSuperAdminContext(context);
  const includeResidents = coerceBool(data?.includeResidents, false);
  const rawLimit = typeof data?.limit === "number" ? Math.floor(data.limit) : 200;
  const listLimit = Math.max(20, Math.min(500, rawLimit));

  const source = db.collection("users");
  const usersQuery = includeResidents
    ? source.limit(listLimit)
    : source
      .where("role", "in", ["super_admin", "admin", "office_admin", "moderator"])
      .limit(listLimit);

  const usersSnapshot = await usersQuery.get();
  const userDocs = usersSnapshot.docs.filter((item) => {
    const row = item.data() ?? {};
    return !coerceBool(row.isDeleted, false);
  });

  const authLookups = await Promise.all(
    userDocs.map(async (item) => {
      try {
        const authUser = await admin.auth().getUser(item.id);
        return { uid: item.id, authUser };
      } catch (error) {
        if (isAuthUserNotFound(error)) {
          return { uid: item.id, authUser: null };
        }
        throw error;
      }
    })
  );
  const authByUid = new Map<string, admin.auth.UserRecord | null>(
    authLookups.map((row) => [row.uid, row.authUser])
  );

  const rolePriority: Record<NormalizedRole, number> = {
    super_admin: 100,
    admin: 80,
    office_admin: 70,
    moderator: 60,
    resident: 10,
  };

  const items = userDocs
    .map((item) => {
      const row = item.data() ?? {};
      const role = normalizeRole(row.role);
      const authUser = authByUid.get(item.id);
      const email = coerceString(row.email) ?? coerceString(authUser?.email) ?? "";
      const displayName =
        coerceString(row.displayName) ??
        coerceString(authUser?.displayName) ??
        coerceString(authUser?.email) ??
        item.id;
      const isActive = coerceBool(
        row.isActive,
        authUser ? !authUser.disabled : true
      );
      const disabled = authUser ? authUser.disabled : !isActive;

      return {
        uid: item.id,
        email,
        displayName,
        role,
        roleLabel: roleDisplayLabel(role),
        officeId: coerceString(row.officeId),
        officeName: coerceString(row.officeName),
        isActive,
        disabled,
        createdAt:
          toIsoString(row.createdAt) ??
          toIsoString(authUser?.metadata.creationTime),
        updatedAt: toIsoString(row.updatedAt),
        lastSignInAt:
          toIsoString(authUser?.metadata.lastSignInTime) ??
          toIsoString(row.lastLoginAt),
        providerIds: authUser?.providerData?.map((provider) => provider.providerId) ?? [],
      };
    })
    .sort((a, b) => {
      const left = rolePriority[a.role] ?? 0;
      const right = rolePriority[b.role] ?? 0;
      if (left !== right) return right - left;
      return a.email.localeCompare(b.email);
    });

  const roles = USER_MANAGEMENT_ROLES.map((role) => ({
    value: role,
    label: roleDisplayLabel(role),
  }));

  return {
    success: true,
    currentUid: actor.uid,
    minimumPasswordLength: USER_MIN_PASSWORD_LENGTH,
    roles,
    items,
  };
});

export const adminCreateUser = protectedCallableFunctions.https.onCall(async (data, context) => {
  const actor = await requireSuperAdminContext(context);
  const actorName = actorDisplayName(actor);
  const email = coerceString(data?.email);
  const password = coerceString(data?.password);
  const displayName = coerceString(data?.displayName);
  const role = normalizeRole(data?.role);
  const isActive =
    typeof data?.isActive === "boolean" ? data.isActive : true;

  if (!email || !password) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "email and password are required."
    );
  }
  if (password.length < USER_MIN_PASSWORD_LENGTH) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      `Password must be at least ${USER_MIN_PASSWORD_LENGTH} characters.`
    );
  }
  if (!USER_MANAGEMENT_ROLES.includes(role)) {
    throw new functions.https.HttpsError("invalid-argument", "Invalid role.");
  }

  const office = await resolveManagedOffice(
    role,
    coerceString(data?.officeId),
    coerceString(data?.officeName),
    null,
    null
  );

  const created = await admin.auth().createUser({
    email,
    password,
    displayName: displayName ?? undefined,
    disabled: !isActive,
  });

  await admin.auth().setCustomUserClaims(created.uid, {
    role,
    officeId: office.officeId,
    officeName: office.officeName,
    isActive,
  });
  await admin.auth().revokeRefreshTokens(created.uid);

  await db.collection("users").doc(created.uid).set(
    {
      uid: created.uid,
      email,
      displayName: displayName ?? email,
      role,
      officeId: office.officeId,
      officeName: office.officeName,
      isActive,
      isDeleted: false,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    },
    { merge: true }
  );

  await addAuditLog({
    action: "user_created",
    actorUid: actor.uid,
    actorRole: actor.role,
    actorOfficeId: actor.officeId ?? null,
    actorName,
    entityType: "user",
    entityId: created.uid,
    targetUid: created.uid,
    targetEmail: email,
    targetRole: role,
    officeId: office.officeId,
    message: `User ${email} created as ${roleDisplayLabel(role)}.`,
  });

  return { success: true, uid: created.uid };
});

export const adminUpdateUser = protectedCallableFunctions.https.onCall(async (data, context) => {
  const actor = await requireSuperAdminContext(context);
  const actorName = actorDisplayName(actor);
  const uid = coerceString(data?.uid);
  if (!uid) {
    throw new functions.https.HttpsError("invalid-argument", "uid is required.");
  }

  const targetProfile = await getUserProfile(uid);
  const targetData = targetProfile.data as Record<string, unknown>;
  const role = data?.role != null ? normalizeRole(data.role) : targetProfile.role;
  const requestedOfficeId = Object.prototype.hasOwnProperty.call(data ?? {}, "officeId")
    ? coerceString(data?.officeId)
    : targetProfile.officeId;
  const requestedOfficeName = Object.prototype.hasOwnProperty.call(data ?? {}, "officeName")
    ? coerceString(data?.officeName)
    : targetProfile.officeName;
  const office = await resolveManagedOffice(
    role,
    requestedOfficeId,
    requestedOfficeName,
    targetProfile.officeId,
    targetProfile.officeName
  );
  const isActive =
    typeof data?.isActive === "boolean" ? data.isActive : targetProfile.isActive;

  if (uid === actor.uid && role !== "super_admin") {
    throw new functions.https.HttpsError(
      "failed-precondition",
      "You cannot downgrade your own super_admin role."
    );
  }
  if (uid === actor.uid && !isActive) {
    throw new functions.https.HttpsError(
      "failed-precondition",
      "You cannot suspend your own account."
    );
  }

  const displayName =
    coerceString(data?.displayName) ??
    coerceString(targetData.displayName);
  const email =
    coerceString(data?.email) ??
    coerceString(targetData.email);

  await admin.auth().updateUser(uid, {
    displayName: displayName ?? undefined,
    email: email ?? undefined,
    disabled: !isActive,
  });

  await admin.auth().setCustomUserClaims(uid, {
    role,
    officeId: office.officeId,
    officeName: office.officeName,
    isActive,
  });
  await admin.auth().revokeRefreshTokens(uid);

  await db.collection("users").doc(uid).set(
    {
      email: email ?? targetData.email ?? null,
      displayName: displayName ?? targetData.displayName ?? null,
      role,
      officeId: office.officeId,
      officeName: office.officeName,
      isActive,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    },
    { merge: true }
  );

  await addAuditLog({
    action: "user_updated",
    actorUid: actor.uid,
    actorRole: actor.role,
    actorOfficeId: actor.officeId ?? null,
    actorName,
    entityType: "user",
    entityId: uid,
    targetUid: uid,
    targetRole: role,
    officeId: office.officeId,
    message: `User ${uid} updated as ${roleDisplayLabel(role)}.`,
  });

  return { success: true };
});

export const adminSetUserSuspension = protectedCallableFunctions.https.onCall(async (data, context) => {
  const actor = await requireSuperAdminContext(context);
  const actorName = actorDisplayName(actor);
  const uid = coerceString(data?.uid);
  if (!uid || typeof data?.suspended !== "boolean") {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "uid and suspended are required."
    );
  }
  if (uid === actor.uid && data.suspended) {
    throw new functions.https.HttpsError(
      "failed-precondition",
      "You cannot suspend your own account."
    );
  }

  const targetProfile = await getUserProfile(uid);
  const isActive = !data.suspended;

  await admin.auth().updateUser(uid, { disabled: data.suspended });
  await admin.auth().setCustomUserClaims(uid, {
    role: targetProfile.role,
    officeId: targetProfile.officeId,
    officeName: targetProfile.officeName,
    isActive,
  });
  await admin.auth().revokeRefreshTokens(uid);

  await db.collection("users").doc(uid).set(
    {
      isActive,
      suspendedAt: data.suspended
        ? admin.firestore.FieldValue.serverTimestamp()
        : null,
      suspendedByUid: data.suspended ? actor.uid : null,
      suspendedByName: data.suspended ? actorName : null,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    },
    { merge: true }
  );

  await addAuditLog({
    action: data.suspended ? "user_suspended" : "user_reactivated",
    actorUid: actor.uid,
    actorRole: actor.role,
    actorOfficeId: actor.officeId ?? null,
    actorName,
    entityType: "user",
    entityId: uid,
    targetUid: uid,
    message: data.suspended
      ? `User ${uid} suspended.`
      : `User ${uid} reactivated.`,
  });

  return { success: true };
});

export const adminResetUserPassword = protectedCallableFunctions.https.onCall(async (data, context) => {
  const actor = await requireSuperAdminContext(context);
  const actorName = actorDisplayName(actor);
  const uid = coerceString(data?.uid);
  const newPassword = coerceString(data?.newPassword);
  if (!uid || !newPassword) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "uid and newPassword are required."
    );
  }
  if (newPassword.length < USER_MIN_PASSWORD_LENGTH) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      `Password must be at least ${USER_MIN_PASSWORD_LENGTH} characters.`
    );
  }

  await admin.auth().updateUser(uid, { password: newPassword });
  await admin.auth().revokeRefreshTokens(uid);

  await db.collection("users").doc(uid).set(
    {
      passwordResetAt: admin.firestore.FieldValue.serverTimestamp(),
      passwordResetByUid: actor.uid,
      passwordResetByName: actorName,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    },
    { merge: true }
  );

  await addAuditLog({
    action: "user_password_reset",
    actorUid: actor.uid,
    actorRole: actor.role,
    actorOfficeId: actor.officeId ?? null,
    actorName,
    entityType: "user",
    entityId: uid,
    targetUid: uid,
    message: `Password reset for user ${uid}.`,
  });

  return { success: true };
});

export const adminDeleteUser = protectedCallableFunctions.https.onCall(async (data, context) => {
  const actor = await requireSuperAdminContext(context);
  const actorName = actorDisplayName(actor);
  const uid = coerceString(data?.uid);
  if (!uid) {
    throw new functions.https.HttpsError("invalid-argument", "uid is required.");
  }
  if (uid === actor.uid) {
    throw new functions.https.HttpsError(
      "failed-precondition",
      "You cannot delete your own account."
    );
  }

  try {
    await admin.auth().deleteUser(uid);
  } catch (error) {
    if (!isAuthUserNotFound(error)) {
      throw error;
    }
  }

  await db.collection("users").doc(uid).set(
    {
      isDeleted: true,
      isActive: false,
      deletedAt: admin.firestore.FieldValue.serverTimestamp(),
      deletedByUid: actor.uid,
      deletedByName: actorName,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    },
    { merge: true }
  );

  await addAuditLog({
    action: "user_deleted",
    actorUid: actor.uid,
    actorRole: actor.role,
    actorOfficeId: actor.officeId ?? null,
    actorName,
    entityType: "user",
    entityId: uid,
    targetUid: uid,
    message: `User ${uid} deleted.`,
  });

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
      await admin.auth().revokeRefreshTokens(uid).catch((error) => {
        console.warn("onUserWrite: revokeRefreshTokens failed", error);
      });
      return;
    }

    const beforeData = change.before.exists ? (change.before.data() ?? {}) : null;
    const data = change.after.data() ?? {};
    const role = normalizeRole(data.role);
    let officeId = coerceString(data.officeId);
    let officeName = coerceString(data.officeName);
    const isActive = coerceBool(data.isActive, true);

    if (role === "super_admin" || role === "resident") {
      officeId = null;
      officeName = null;
    }

    // Only sync/revoke when claim-affecting fields change. This avoids
    // invalidating sessions for unrelated profile writes (for example staff
    // presence heartbeats from the messaging module).
    const beforeRole = normalizeRole(beforeData?.role);
    let beforeOfficeId = coerceString(beforeData?.officeId);
    let beforeOfficeName = coerceString(beforeData?.officeName);
    const beforeIsActive = coerceBool(beforeData?.isActive, true);
    if (beforeRole === "super_admin" || beforeRole === "resident") {
      beforeOfficeId = null;
      beforeOfficeName = null;
    }
    const claimsChanged =
      !beforeData ||
      beforeRole !== role ||
      beforeOfficeId !== officeId ||
      beforeOfficeName !== officeName ||
      beforeIsActive !== isActive;

    if (claimsChanged) {
      await admin.auth().setCustomUserClaims(uid, {
        role,
        officeId,
        officeName,
        isActive,
      });
      await admin.auth().revokeRefreshTokens(uid);
    }

    const storedRoleRaw = coerceString(data.role);
    if (storedRoleRaw && normalizeRole(storedRoleRaw) !== storedRoleRaw) {
      await change.after.ref.set(
        {
          role,
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
  .onWrite(async (change) => {
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
          .where("role", "in", ["admin", "office_admin"])
          .where("officeId", "==", reportOfficeId)
          .get();
        officeAdminUids = officeSnap.docs.map((d) => d.id);
      } else {
        const officeSnap = await db
          .collection("users")
          .where("role", "in", ["admin", "office_admin"])
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
      await addReportTimeline(reportId, {
        type: "CREATED",
        actorUid: createdByUid || null,
        actorRole: createdByUid ? "resident" : "public",
        notes: "Report created.",
        fromStatus: null,
        toStatus: status,
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
        actorRole: createdByUid ? "resident" : "public",
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
    const workflowArtifactsHandledByCaller = Boolean(actorUid || actorName || actorRole);
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

      const assignmentTimelineType = afterAssigned
        ? (
          beforeAssigned
            ? "REASSIGNED"
            : (actorUid && actorUid === afterAssigned ? "CLAIMED" : "ASSIGNED")
        )
        : "UNASSIGNED";
      const assignmentMessage = afterAssigned
        ? (
          beforeAssigned
            ? "Report reassigned."
            : (actorUid && actorUid === afterAssigned ? "Report claimed." : "Report assigned.")
        )
        : "Report unassigned.";

      if (!workflowArtifactsHandledByCaller) {
        await addHistory(reportId, {
          type: "assignment_changed",
          fromAssignedUid: beforeAssigned ?? null,
          toAssignedUid: afterAssigned ?? null,
          status: afterStatus,
          message: assignmentMessage,
        });
        await addReportTimeline(reportId, {
          type: assignmentTimelineType,
          actorUid: actorUid || null,
          actorRole: actorRole || null,
          notes: assignmentMessage,
          fromStatus: beforeStatus,
          toStatus: afterStatus,
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
          message: assignmentMessage,
        });
      }
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
      if (!workflowArtifactsHandledByCaller) {
        await addHistory(reportId, {
          type: "status_changed",
          fromStatus: beforeStatus,
          toStatus: afterStatus,
          assignedToUid: afterAssigned ?? null,
          message: `Status changed from ${prettyStatus(beforeStatus)} to ${prettyStatus(
            afterStatus
          )}.`,
        });
        await addReportTimeline(reportId, {
          type: "STATUS_CHANGED",
          actorUid: actorUid || null,
          actorRole: actorRole || null,
          notes: `Status changed from ${prettyStatus(beforeStatus)} to ${prettyStatus(
            afterStatus
          )}.`,
          fromStatus: beforeStatus,
          toStatus: afterStatus,
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
    }

    if (archivedChanged) {
      const msg = afterArchived ? "Report archived." : "Report restored.";
      if (!workflowArtifactsHandledByCaller) {
        await addHistory(reportId, {
          type: afterArchived ? "archived" : "restored",
          status: afterStatus,
          assignedToUid: afterAssigned ?? null,
          message: msg,
        });
        await addReportTimeline(reportId, {
          type: afterArchived ? "ARCHIVED" : "RESTORED",
          actorUid: actorUid || null,
          actorRole: actorRole || null,
          notes: msg,
          fromStatus: beforeStatus,
          toStatus: afterStatus,
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
    }
  });

/**
 * =========================
 * ANNOUNCEMENT NOTIFICATIONS
 * =========================
 * Notify residents when an announcement is published.
 */
export const onAnnouncementNotify = functions.firestore
  .document("posts/{postId}")
  .onWrite(async (change, context) => {
    const before = change.before.exists ? change.before.data() : null;
    const after = change.after.exists ? change.after.data() : null;
    if (!after) return;
    const postType = String(after.type ?? "announcement").trim().toLowerCase();
    if (postType !== "announcement") return;
    const legacySourceCollection = String(after.legacySourceCollection ?? "").trim().toLowerCase();
    if (!before && legacySourceCollection === "announcements") return;

    const beforeStatus = (before?.status ?? null) as string | null;
    const afterStatus = (after.status ?? "draft") as string;
    const newlyPublished = afterStatus === "published" && beforeStatus !== "published";
    if (!newlyPublished) return;

    const title = (after.title ?? "Announcement") as string;
    const category = (after.category ?? "") as string;
    const postId = context.params.postId as string;

    const body = category ? `${title} - ${category}` : title;
    const residentUids = await getResidentUids();

    await notifyUsers(residentUids, {
      title: "New announcement",
      body,
      type: "announcement_published",
      announcementId: postId,
    });
  });

/**
 * =========================
 * ANNOUNCEMENT AUDIT LOGS
 * =========================
 */
export const onAnnouncementAudit = functions.firestore
  .document("posts/{postId}")
  .onWrite(async (change, context) => {
    const before = change.before.exists ? change.before.data() : null;
    const after = change.after.exists ? change.after.data() : null;
    const postId = context.params.postId as string;
    const typeSource = (after ?? before ?? {}) as Record<string, unknown>;
    const postType = String(typeSource.type ?? "announcement").trim().toLowerCase();
    if (postType !== "announcement") return;
    const legacySourceCollection = String(typeSource.legacySourceCollection ?? "").trim().toLowerCase();

    if (!before && after) {
      if (legacySourceCollection === "announcements") {
        return;
      }
      const title = (after.title ?? "Announcement") as string;
      const category = (after.category ?? "") as string;
      const status = (after.status ?? "draft") as string;
      const actor = announcementActor(after as Record<string, unknown>);
      const officeId = coerceString((after as Record<string, unknown>).officeId);

      await addAuditLog({
        action: "announcement_created",
        announcementId: postId,
        postId,
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
        announcementId: postId,
        postId,
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
        announcementId: postId,
        postId,
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
        announcementId: postId,
        postId,
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
      announcementId: postId,
      postId,
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
  .document("posts/{postId}/views/{uid}")
  .onCreate(async (_snap, context) => {
    const postId = context.params.postId as string;
    await db.doc(`posts/${postId}`).set(
      {
        views: admin.firestore.FieldValue.increment(1),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );
  });

/**
 * =========================
 * REPORT SLA ESCALATION SWEEP
 * =========================
 * Periodically checks open reports against the SOP deadlines. Server-side
 * escalation keeps overdue tickets visible even if no admin screen is open.
 */
export const escalateOverdueReports = functions.pubsub
  .schedule("every 15 minutes")
  .timeZone("Asia/Manila")
  .onRun(async () => {
    const now = Date.now();
    const activeStatuses = Array.from(OPEN_STATUSES);
    let escalated = 0;
    // Keep the sweep bounded per invocation. This avoids an unbounded scan while
    // still catching overdue tickets during routine operations.
    const snapshot = await db
      .collection("reports")
      .where("status", "in", activeStatuses)
      .limit(100)
      .get();

    for (const doc of snapshot.docs) {
      const row = (doc.data() ?? {}) as Record<string, unknown>;
      const stage = overdueReportSlaStage(row, now);
      if (!stage) {
        continue;
      }

      const lastStage = coerceString((row.slaEscalation as Record<string, unknown> | undefined)?.stage);
      if (lastStage === stage) {
        continue;
      }

      await recordReportEscalation(
        doc.id,
        row,
        stage,
        `SLA target missed for ${stage}. Immediate staff action is required.`
      );
      escalated += 1;
    }

    functions.logger.info("escalateOverdueReports completed", {escalated});
    return null;
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
    let hasMore = true;
    while (hasMore) {
      const snap = await db
        .collectionGroup("notifications")
        .where("read", "==", true)
        .where("createdAt", "<", cutoff)
        .limit(400)
        .get();
      if (snap.empty) {
        hasMore = false;
        continue;
      }

      const batch = db.batch();
      for (const doc of snap.docs) {
        batch.delete(doc.ref);
      }
      await batch.commit();
      deleted += snap.size;
      hasMore = snap.size === 400;
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
    let hasMore = true;
    while (hasMore) {
      const snap = await db
        .collection("dts_track_sessions")
        .where("expiresAt", "<=", now)
        .limit(400)
        .get();
      if (snap.empty) {
        hasMore = false;
        continue;
      }
      const batch = db.batch();
      for (const doc of snap.docs) {
        batch.delete(doc.ref);
      }
      await batch.commit();
      deleted += snap.size;
      hasMore = snap.size === 400;
    }
    console.log(`cleanupExpiredDtsTrackSessions deleted ${deleted} docs`);
    return null;
  });

/**
 * =========================
 * DTS QR RESERVATION CLEANUP
 * =========================
 * Releases stale reserved QR stickers back to inventory so abandoned scans
 * do not permanently brick physical sticker stock.
 */
export const cleanupExpiredDtsQrReservations = functions.pubsub
  .schedule("every 15 minutes")
  .timeZone("Asia/Manila")
  .onRun(async () => {
    const nowMs = Date.now();
    const reservedSnap = await db
      .collection("dts_qr_codes")
      .where("status", "==", "reserved")
      .limit(DTS_QR_RESERVATION_SWEEP_LIMIT)
      .get();

    if (reservedSnap.empty) {
      functions.logger.info("cleanupExpiredDtsQrReservations completed", {
        scanned: 0,
        released: 0,
      });
      return null;
    }

    let releasedCount = 0;
    let releasedToUnused = 0;
    let releasedToUsed = 0;
    let activeReservations = 0;
    const touchedBatchIds = new Set<string>();
    const setWrites: Array<{
      ref: FirebaseFirestore.DocumentReference<FirebaseFirestore.DocumentData>;
      data: Record<string, unknown>;
      merge?: boolean;
    }> = [];

    for (const snap of reservedSnap.docs) {
      const row = (snap.data() ?? {}) as Record<string, unknown>;
      if (!isDtsQrReservationExpired(row, nowMs)) {
        activeReservations += 1;
        continue;
      }
      const patch = buildDtsQrReservationReleasePatch(row);
      const nextStatus = normalizeDtsQrCodeStatus(patch.status);
      if (nextStatus === "used") {
        releasedToUsed += 1;
      } else {
        releasedToUnused += 1;
      }
      setWrites.push({
        ref: snap.ref,
        data: patch,
        merge: true,
      });
      releasedCount += 1;
      const batchId = coerceString(row.batchId);
      if (batchId) {
        touchedBatchIds.add(batchId);
      }
    }

    if (setWrites.length > 0) {
      await commitDtsQrReconcileWrites(setWrites, []);
      for (const batchId of touchedBatchIds) {
        try {
          await reconcileDtsQrBatch(batchId, {
            repairQrRows: true,
            syncBatchCounters: true,
          });
        } catch (error) {
          functions.logger.warn("cleanupExpiredDtsQrReservations reconcile failed", {
            batchId,
            error,
          });
        }
      }
    }

    functions.logger.info("cleanupExpiredDtsQrReservations completed", {
      scanned: reservedSnap.size,
      activeReservations,
      released: releasedCount,
      releasedToUnused,
      releasedToUsed,
      touchedBatches: touchedBatchIds.size,
      hitQueryLimit: reservedSnap.size === DTS_QR_RESERVATION_SWEEP_LIMIT,
    });
    return null;
  });

/**
 * =========================
 * DTS OVERDUE ESCALATION SWEEP
 * =========================
 * Periodically writes overdue alert records for DTS documents with due dates.
 * This keeps overdue visibility available in dashboard alerts even if no user
 * is actively browsing queue screens.
 */
export const escalateOverdueDtsDocuments = functions.pubsub
  .schedule("every 15 minutes")
  .timeZone("Asia/Manila")
  .onRun(async () => {
    const now = Date.now();
    const nowTs = admin.firestore.Timestamp.fromMillis(now);
    const trackedStatuses = Array.from(DTS_OVERDUE_TRACKED_STATUSES);
    const snapshot = await db
      .collection("dts_documents")
      .where("status", "in", trackedStatuses)
      .where("dueAt", "<=", nowTs)
      .limit(DTS_OVERDUE_ALERT_SWEEP_LIMIT)
      .get();

    if (snapshot.empty) {
      functions.logger.info("escalateOverdueDtsDocuments completed", {
        scanned: 0,
        alertsUpserted: 0,
      });
      return null;
    }

    let alertsUpserted = 0;
    const minRenotifyMillis = DTS_OVERDUE_ALERT_RENOTIFY_HOURS * 60 * 60 * 1000;

    for (const doc of snapshot.docs) {
      const row = (doc.data() ?? {}) as Record<string, unknown>;
      const dueAt = parseDtsDueAt(row.dueAt);
      if (!dueAt) {
        continue;
      }
      const status = normalizeDtsStatus(row.status, "RECEIVED");
      if (!DTS_OVERDUE_TRACKED_STATUSES.has(status)) {
        continue;
      }

      const overdueMillis = now - dueAt.getTime();
      if (!Number.isFinite(overdueMillis) || overdueMillis <= 0) {
        continue;
      }

      const hoursOverdue = Math.max(1, Math.floor(overdueMillis / (60 * 60 * 1000)));
      const severity = dtsOverdueSeverity(hoursOverdue);
      const alertRef = db.collection("dts_alerts").doc(`OVERDUE_${doc.id}`);
      const existing = await alertRef.get();
      const existingRow = (existing.data() ?? {}) as Record<string, unknown>;
      const existingStatus = normalizeDtsStatus(existingRow.status, "");
      const existingHoursRaw = Number(existingRow.hoursOverdue);
      const existingHours = Number.isFinite(existingHoursRaw)
        ? Math.max(0, Math.floor(existingHoursRaw))
        : 0;
      const lastNotifiedAt =
        existingRow.lastNotifiedAt instanceof admin.firestore.Timestamp
          ? existingRow.lastNotifiedAt.toDate()
          : null;
      const shouldRenotify =
        !lastNotifiedAt ||
        now - lastNotifiedAt.getTime() >= minRenotifyMillis ||
        existingStatus !== status ||
        hoursOverdue - existingHours >= 6;

      if (!shouldRenotify && existing.exists) {
        continue;
      }

      await alertRef.set(
        {
          alertType: "DTS_OVERDUE",
          status: status,
          severity: severity,
          docId: doc.id,
          trackingNo: coerceString(row.trackingNo) ?? doc.id,
          title: coerceString(row.title) ?? null,
          currentOfficeId: coerceString(row.currentOfficeId) ?? null,
          currentOfficeName: coerceString(row.currentOfficeName) ?? null,
          dueAt: admin.firestore.Timestamp.fromDate(dueAt),
          hoursOverdue: hoursOverdue,
          createdAt: existingRow.createdAt instanceof admin.firestore.Timestamp
            ? existingRow.createdAt
            : admin.firestore.FieldValue.serverTimestamp(),
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          lastNotifiedAt: admin.firestore.FieldValue.serverTimestamp(),
          resolved: false,
        },
        { merge: true }
      );
      alertsUpserted += 1;
    }

    functions.logger.info("escalateOverdueDtsDocuments completed", {
      scanned: snapshot.size,
      alertsUpserted,
    });
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
      "DOCUMENT_INTAKE",
      "DOCUMENT_CREATED",
      "DOCUMENT_FINALIZED",
      "DOCUMENT_GENERATED",
      "DOCUMENT_ROUTED",
      "DOCUMENT_RECEIVED",
      "TRANSFER_INITIATED",
      "TRANSFER_CANCELLED",
      "TRANSFER_REJECTED",
      "TRANSFER_CONFIRMED",
      "STATUS_CHANGED",
      "DOCUMENT_REGENERATED",
      "DOCUMENT_REPRINTED",
      "RETURNED",
      "RELEASED",
      "ARCHIVED",
      "DOCUMENT_VOIDED",
      "PULLED_OUT",
    ]);
    if (!notifiableTypes.has(eventType.toUpperCase())) return;
    const actorUid = coerceString(event.byUid);

    let actorName = "Staff";
    let actorEmail: string | null = null;
    let actorRole: string | null = null;
    let actorOfficeId: string | null = null;
    let actorOfficeName: string | null = null;
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
      actorOfficeName = coerceString(actor.officeName);
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
      actorOfficeName: actorOfficeName ?? null,
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
          if (role === "admin" || role === "moderator") {
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
async function dtsCreateTrackingRecordHandler(
  data: unknown,
  context: CallableContextLike
) {
  const payload = (data && typeof data === "object")
    ? (data as Record<string, unknown>)
    : {};
  const actor = await requireStaffContext(context);
  await requireFeatureWritable("documentTracking");
  const title = coerceString(payload.title) ?? "";
  const description = coerceString(payload.description) ?? "";
  const docType = coerceString(payload.docType) ?? "GENERAL";
  const originType = (coerceString(payload.originType) ?? "EXTERNAL")
    .trim()
    .toUpperCase() === "INTERNAL"
    ? "INTERNAL"
    : "EXTERNAL";
  const shouldAutoIssueTracking =
    originType === "INTERNAL" &&
    coerceBool(payload.autoIssueTracking, true);
  const trackingInput = payload.trackingNo ?? payload.trackingNumber;
  const pinInput = payload.pin;
  let trackingNo = "";
  let pin = "";
  if (shouldAutoIssueTracking) {
    trackingNo = await generateUniqueTrackingNo();
    pin = randomTrackingPin();
  } else {
    const validatedLookup = validateTrackingLookupInput(trackingInput, pinInput);
    trackingNo = validatedLookup.trackingNo;
    pin = validatedLookup.pin;
  }
  const requestedOriginOfficeId = coerceString(payload.originOfficeId);
  const sourceName = coerceString(payload.sourceName);
  const documentMode = (coerceString(payload.documentMode) ??
    (originType === "INTERNAL" ? "QR_EMBEDDED" : "QR_STICKER"))
    .trim()
    .toUpperCase() === "QR_EMBEDDED"
    ? "QR_EMBEDDED"
    : "QR_STICKER";
  const generatedFileUrl = coerceString(payload.generatedFileUrl);
  const activeGeneratedVersionRaw = payload.activeGeneratedVersion;
  const activeGeneratedVersion = typeof activeGeneratedVersionRaw === "number" &&
    Number.isFinite(activeGeneratedVersionRaw)
    ? Math.max(1, Math.floor(activeGeneratedVersionRaw))
    : (typeof activeGeneratedVersionRaw === "string" &&
      Number.isFinite(Number.parseInt(activeGeneratedVersionRaw, 10))
      ? Math.max(1, Number.parseInt(activeGeneratedVersionRaw, 10))
      : null);
  const requestedOfficeId = coerceString(payload.officeId);
  const requestedOfficeName = coerceString(payload.officeName);
  const intendedOfficeId = coerceString(payload.intendedOfficeId);
  const intendedOfficeName = coerceString(payload.intendedOfficeName);
  const intakeNote = coerceString(payload.intakeNote) ?? "";
  const isFastTrack = coerceBool(payload.isFastTrack, false);
  const requestedPriority = normalizeDtsPriorityLevel(payload.priorityLevel);
  let priorityLevel = isFastTrack ? requestedPriority : "NORMAL";
  if (!DTS_PRIORITY_LEVELS.has(priorityLevel)) {
    priorityLevel = "NORMAL";
  }
  const rawSlaHours = payload.slaHours;
  let slaHours: number | null = null;
  if (rawSlaHours != null && String(rawSlaHours).trim() !== "") {
    const parsedSla = Number.parseInt(String(rawSlaHours).trim(), 10);
    if (!Number.isFinite(parsedSla) || parsedSla < 1 || parsedSla > DTS_MAX_SLA_HOURS) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        `slaHours must be an integer between 1 and ${DTS_MAX_SLA_HOURS}.`
      );
    }
    slaHours = parsedSla;
  }
  let dueAt = parseDtsDueAt(payload.dueAt);
  if (isFastTrack && !dueAt && slaHours != null) {
    dueAt = new Date(Date.now() + (slaHours * 60 * 60 * 1000));
  }
  if (!isFastTrack) {
    dueAt = null;
    slaHours = null;
  }
  if (isFastTrack && !dueAt) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Fast-track records require a due date or SLA hours."
    );
  }
  if (dueAt && dueAt.getTime() <= Date.now()) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "dueAt must be set in the future."
    );
  }
  const verificationValue = normalizeDtsVerificationValue(payload.verificationValue);
  const verificationMethod = normalizeDtsVerificationMethod(payload.verificationMethod);
  const confirmPhysicalReceipt = coerceBool(payload.confirmPhysicalReceipt, false);
  let requestedQrCode = coerceString(payload.qrCode)?.trim().toUpperCase() ?? null;
  const receiptAttemptScope = `INTAKE_${trackingNo}`;

  const resolvedOriginOfficeId = originType === "INTERNAL"
    ? (actor.role === "super_admin"
      ? (requestedOriginOfficeId ?? actor.officeId ?? requestedOfficeId)
      : (actor.officeId ?? requestedOriginOfficeId ?? requestedOfficeId))
    : null;
  const officeId = originType === "INTERNAL"
    ? resolvedOriginOfficeId
    : (actor.role === "super_admin"
      ? requestedOfficeId
      : (actor.officeId ?? requestedOfficeId));
  if (!officeId) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "officeId is required to create tracking records."
    );
  }
  if (originType === "INTERNAL" && documentMode !== "QR_EMBEDDED") {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Internal documents must use QR_EMBEDDED mode."
    );
  }
  if (originType === "EXTERNAL" && documentMode !== "QR_STICKER") {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "External intake documents must use QR_STICKER mode."
    );
  }
  if (originType === "EXTERNAL") {
    await assertReceiptVerificationNotLocked(receiptAttemptScope, actor.uid, context);
    if (!confirmPhysicalReceipt) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "Physical receipt confirmation is required."
      );
    }
    if (!verificationValue) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "Enter tracking number or QR code for receipt verification."
      );
    }
    if (!requestedQrCode && verificationValue !== trackingNo) {
      requestedQrCode = verificationValue;
    }
    if (!matchesDtsTrackingOrQr(verificationValue, trackingNo, requestedQrCode)) {
      const locked = await registerReceiptVerificationFailure(
        receiptAttemptScope,
        actor.uid,
        context
      );
      if (locked) {
        throw new functions.https.HttpsError(
          "resource-exhausted",
          "Too many invalid verification attempts. Please wait before trying again."
        );
      }
      throw new functions.https.HttpsError(
        "invalid-argument",
        "Invalid tracking number or QR code."
      );
    }
  }
  if (originType === "EXTERNAL" && !requestedQrCode) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "qrCode is required for external intake records."
    );
  }
  if (originType === "EXTERNAL" && sourceName && sourceName.length > 160) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "sourceName is too long."
    );
  }
  const initialStatus = originType === "INTERNAL" ? "CREATED" : "RECEIVED";
  const officeName =
    requestedOfficeName ??
    actor.officeName ??
    coerceString((await db.collection("offices").doc(officeId).get()).data()?.name) ??
    officeId;

  const duplicateSnap = await db
    .collection("dts_documents")
    .where("trackingNo", "==", trackingNo)
    .limit(1)
    .get();
  if (!duplicateSnap.empty) {
    throw new functions.https.HttpsError(
      "already-exists",
      "Tracking number already exists."
    );
  }

  const pinHash = await hashTrackingPin(pin);
  const actorName = actorDisplayName(actor);
  const docRef = db.collection("dts_documents").doc();
  const qrRef = requestedQrCode
    ? db.collection("dts_qr_codes").doc(requestedQrCode)
    : null;
  let resolvedQrCode: string | null = null;
  let resolvedBatchId: string | null = null;
  let resolvedQrIndexRef:
    FirebaseFirestore.DocumentReference<FirebaseFirestore.DocumentData> | null = null;
  let resolvedQrIndexExists = false;

  try {
    await db.runTransaction(async (tx) => {
      let qrRow: Record<string, unknown> | null = null;
      if (qrRef) {
        const qrSnap = await tx.get(qrRef);
        if (!qrSnap.exists) {
          throw new functions.https.HttpsError(
            "not-found",
            "Requested QR code does not exist."
          );
        }
        qrRow = qrSnap.data() ?? {};
        const qrStatus = normalizeDtsQrCodeStatus(qrRow.status) || "unused";
        if (qrStatus === "voided") {
          throw new functions.https.HttpsError(
            "failed-precondition",
            "Requested QR code has been voided."
          );
        }
        if (qrStatus === "used") {
          throw new functions.https.HttpsError(
            "failed-precondition",
            "Requested QR code is not available."
          );
        }
        if (qrStatus === "reserved") {
          const reservedByUid = coerceString(qrRow.reservedByUid);
          if (!isDtsQrReservationExpired(qrRow) &&
              reservedByUid &&
              reservedByUid !== actor.uid) {
            throw new functions.https.HttpsError(
              "failed-precondition",
              "Requested QR code is currently reserved by another staff member."
            );
          }
        }
        if (qrStatus !== "unused" && qrStatus !== "reserved") {
          throw new functions.https.HttpsError(
            "failed-precondition",
            "Requested QR code is not available."
          );
        }
        resolvedQrCode = requestedQrCode;
        resolvedBatchId = coerceString(qrRow.batchId);
      } else if (originType === "INTERNAL" && documentMode === "QR_EMBEDDED") {
        const unusedQrSnap = await tx.get(
          db.collection("dts_qr_codes")
            .where("status", "==", "unused")
            .limit(1)
        );
        if (unusedQrSnap.empty) {
          throw new functions.https.HttpsError(
            "failed-precondition",
            "No unused QR code is available for internal finalize."
          );
        }
        const picked = unusedQrSnap.docs[0];
        qrRow = picked.data() ?? {};
        if (coerceString(qrRow.status) !== "unused") {
          throw new functions.https.HttpsError(
            "failed-precondition",
            "Unable to reserve an unused QR code."
          );
        }
        resolvedQrCode = picked.id;
        resolvedBatchId = coerceString(qrRow.batchId);
      }

      if (resolvedQrCode) {
        resolvedQrIndexRef = db.collection("dts_qr_index").doc(resolvedQrCode);
        const qrIndexSnap = await tx.get(resolvedQrIndexRef);
        resolvedQrIndexExists = qrIndexSnap.exists;
        const indexedDocId = coerceString(qrIndexSnap.data()?.docId);
        if (indexedDocId) {
          throw new functions.https.HttpsError(
            "failed-precondition",
            "Requested QR code is already linked to a document."
          );
        }

        const linkedDocSnap = await tx.get(
          db.collection("dts_documents")
            .where("qrCode", "==", resolvedQrCode)
            .limit(1)
        );
        if (!linkedDocSnap.empty) {
          throw new functions.https.HttpsError(
            "failed-precondition",
            "Requested QR code is already associated with another tracking record."
          );
        }
      }

      tx.set(docRef, {
        qrCode: resolvedQrCode ?? null,
        trackingNo,
        title,
        description,
        docType,
        status: initialStatus,
        isFastTrack,
        priorityLevel,
        dueAt: dueAt ? admin.firestore.Timestamp.fromDate(dueAt) : null,
        slaHours: slaHours ?? null,
        originType,
        originOfficeId: resolvedOriginOfficeId ?? null,
        sourceName: originType === "EXTERNAL" ? (sourceName ?? null) : null,
        documentMode,
        generatedFileUrl: generatedFileUrl ?? null,
        activeGeneratedVersion: activeGeneratedVersion ?? null,
        currentOfficeId: officeId,
        currentOfficeName: officeName,
        currentCustodianUid: actor.uid,
        intendedOfficeId: intendedOfficeId ?? null,
        intendedOfficeName: intendedOfficeName ?? null,
        distributionMode: "SINGLE",
        destTotal: 0,
        destPending: 0,
        destInTransit: 0,
        destReceived: 0,
        destRejected: 0,
        destCancelled: 0,
        activeDestinationOfficeIds: [],
        destinationOfficeIds: [],
        pendingTransfer: null,
        pinHash,
        publicPinHash: pinHash,
        pinHashAlgo: "bcrypt",
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        createdByUid: actor.uid,
        createdByName: actorName,
        submittedByUid: null,
        saveToResidentAccount: false,
      });

      tx.set(docRef.collection("timeline").doc(), {
        type: originType === "INTERNAL" ? "DOCUMENT_FINALIZED" : "DOCUMENT_INTAKE",
        actionType: originType === "INTERNAL" ? "DOCUMENT_FINALIZED" : "DOCUMENT_INTAKE",
        action: originType === "INTERNAL" ? "DOCUMENT_FINALIZED" : "DOCUMENT_INTAKE",
        method: originType === "EXTERNAL" ? verificationMethod : null,
        verificationMethod: originType === "EXTERNAL" ? verificationMethod : null,
        byUid: actor.uid,
        byName: actorName,
        byOfficeId: actor.officeId ?? officeId,
        byOfficeName: actor.officeName ?? officeName,
        officeId,
        status: initialStatus,
        notePublic: originType === "INTERNAL"
          ? "Document finalized."
          : "Document received.",
        notes: originType === "INTERNAL"
          ? `Document finalized by ${actorName}.`
          : `Document logged as received by ${actorName} (${verificationMethod}).`,
        officeName,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      if (isFastTrack) {
        tx.set(docRef.collection("timeline").doc(), {
          type: "PRIORITY_SET",
          actionType: "DOCUMENT_PRIORITY_SET",
          action: "DOCUMENT_PRIORITY_SET",
          byUid: actor.uid,
          byName: actorName,
          byOfficeId: actor.officeId ?? officeId,
          byOfficeName: actor.officeName ?? officeName,
          officeId,
          status: initialStatus,
          notePublic: "This document is prioritized for expedited handling.",
          notes: dueAt
            ? `Fast-track set to ${priorityLevel}. Due ${dueAt.toISOString()}${slaHours ? ` (SLA ${slaHours}h).` : "."}`
            : `Fast-track set to ${priorityLevel}.`,
          officeName,
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });
      }

      if (intakeNote) {
        tx.set(docRef.collection("timeline").doc(), {
          type: "NOTE",
          actionType: "NOTE_ADDED",
          action: "NOTE_ADDED",
          byUid: actor.uid,
          byName: actorName,
          byOfficeId: actor.officeId ?? officeId,
          byOfficeName: actor.officeName ?? officeName,
          officeId,
          status: initialStatus,
          notePublic: null,
          notes: intakeNote,
          officeName,
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });
      }

      if (resolvedQrCode) {
        const qrIndexRef = resolvedQrIndexRef ??
          db.collection("dts_qr_index").doc(resolvedQrCode);
        if (resolvedQrIndexExists) {
          tx.set(qrIndexRef, {
            docId: docRef.id,
            trackingNo,
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          }, {merge: true});
        } else {
          tx.create(qrIndexRef, {
            docId: docRef.id,
            trackingNo,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          });
        }
        tx.set(
          db.collection("dts_qr_codes").doc(resolvedQrCode),
          {
            status: "used",
            docId: docRef.id,
            usedAt: admin.firestore.FieldValue.serverTimestamp(),
            usedByUid: actor.uid,
            reservedAt: admin.firestore.FieldValue.delete(),
            reservedByUid: admin.firestore.FieldValue.delete(),
            reservationExpiresAt: admin.firestore.FieldValue.delete(),
          },
          {merge: true}
        );
        if (resolvedBatchId) {
          tx.set(
            db.collection("dts_qr_batches").doc(resolvedBatchId),
            {
              unusedCount: admin.firestore.FieldValue.increment(-1),
              usedCount: admin.firestore.FieldValue.increment(1),
              updatedAt: admin.firestore.FieldValue.serverTimestamp(),
            },
            {merge: true}
          );
        }
      }
    });
  } catch (error) {
    if (originType === "EXTERNAL") {
      const code = (error as {code?: string})?.code ?? "";
      const message = (error as {message?: string})?.message ?? "";
      const isVerificationFailure =
        code === "not-found" ||
        code === "failed-precondition" ||
        (code === "invalid-argument" && /tracking number|qr/i.test(message));
      if (isVerificationFailure) {
        const locked = await registerReceiptVerificationFailure(
          receiptAttemptScope,
          actor.uid,
          context
        );
        if (locked) {
          throw new functions.https.HttpsError(
            "resource-exhausted",
            "Too many invalid verification attempts. Please wait before trying again."
          );
        }
        throw new functions.https.HttpsError(
          "invalid-argument",
          "Invalid tracking number or QR code."
        );
      }
    }
    throw error;
  }

  if (originType === "EXTERNAL") {
    await clearReceiptVerificationAttempts(receiptAttemptScope, actor.uid, context);
  }

  await addAuditLog({
    action: "tracking_created",
    entityType: "dts_documents",
    entityId: docRef.id,
    dtsDocId: docRef.id,
    dtsTrackingNo: trackingNo,
    officeId,
    actorUid: actor.uid,
    actorRole: actor.role,
    actorOfficeId: actor.officeId ?? null,
    actorOfficeName: actor.officeName ?? null,
    actorName,
    message: `Tracking record created (${originType.toLowerCase()}).`,
  });

  return {
    success: true,
    id: docRef.id,
    trackingNo,
    pin,
    status: initialStatus,
    originType,
    documentMode,
    qrCode: resolvedQrCode,
    isFastTrack,
    priorityLevel,
    dueAt: dueAt ? dueAt.toISOString() : null,
    slaHours,
  };
}

export const dtsCreateTrackingRecord = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await dtsCreateTrackingRecordHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

export const dtsReserveAndCreateTrackingRecord = onCallV2(
  protectedCallableV2Options,
  async (request) => {
    try {
      // Atomic entrypoint for intake: reserve/validate QR and create record
      // inside the same server transaction path.
      return await dtsCreateTrackingRecordHandler(
        request.data,
        toCallableContextFromV2(request)
      );
    } catch (error) {
      throw normalizeCallableErrorForV2(error);
    }
  }
);

async function dtsListTemplatesHandler(
  data: unknown,
  context: CallableContextLike
) {
  const payload = (data && typeof data === "object") ?
    (data as Record<string, unknown>) :
    {};
  const actor = await requireStaffContext(context);
  await requireFeatureWritable("documentTracking");
  const includeInactive = coerceBool(payload.includeInactive, false);
  const requestedOfficeId = coerceString(payload.officeId);
  const requestedLimit = normalizeTemplateVersion(payload.limit, 60);
  const limitRows = Math.max(1, Math.min(240, requestedLimit));

  const officeScope = (actor.role === "super_admin" || actor.role === "admin") ?
    requestedOfficeId :
    (actor.officeId ?? requestedOfficeId);

  let query: FirebaseFirestore.Query<FirebaseFirestore.DocumentData> = db
    .collection("dts_templates")
    .limit(limitRows);
  if (officeScope) {
    query = query.where("officeId", "==", officeScope);
  }
  if (!includeInactive) {
    query = query.where("isActive", "==", true);
  }

  const snap = await query.get();
  const items = snap.docs
    .map((row) => mapDtsTemplateRecord(row.id, row.data() ?? {}))
    .filter((row) => {
      if (actor.role === "super_admin" || actor.role === "admin") {
        return true;
      }
      if (!actor.officeId) return false;
      return row.officeId === actor.officeId;
    })
    .sort((left, right) => {
      const leftTs = left.updatedAt?.getTime() ?? 0;
      const rightTs = right.updatedAt?.getTime() ?? 0;
      if (leftTs !== rightTs) return rightTs - leftTs;
      return left.name.toLowerCase().localeCompare(right.name.toLowerCase());
    })
    .map((row) => ({
      id: row.id,
      name: row.name,
      officeId: row.officeId,
      officeName: row.officeName,
      fileUrl: row.fileUrl,
      qrPosition: row.qrPosition,
      qrSize: row.qrSize,
      version: row.version,
      isActive: row.isActive,
      fileBytes: row.fileBytes,
      updatedAt: row.updatedAt ? row.updatedAt.toISOString() : null,
    }));

  return {
    success: true,
    items,
  };
}

export const dtsListTemplates = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await dtsListTemplatesHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

async function dtsCreateTemplateHandler(
  data: unknown,
  context: CallableContextLike
) {
  const payload = (data && typeof data === "object") ?
    (data as Record<string, unknown>) :
    {};
  const actor = await requireStaffContext(context);
  assertDtsTemplateManager(actor);
  await requireFeatureWritable("documentTracking");

  const name = coerceString(payload.name);
  if (!name || name.length > 120) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Template name is required and must be 120 chars or less."
    );
  }
  const fileUrl = sanitizeTemplateFileUrl(payload.fileUrl);
  const fileBytes = normalizeTemplateFileBytes(payload.fileBytes);
  if (fileBytes != null && fileBytes > DTS_TEMPLATE_FILE_MAX_BYTES) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Template file exceeds the 12 MB upload limit."
    );
  }
  const requestedOfficeId = coerceString(payload.officeId);
  const requestedOfficeName = coerceString(payload.officeName);
  let officeId = actor.officeId ?? null;
  if (actor.role === "super_admin" || actor.role === "admin") {
    officeId = requestedOfficeId ?? officeId;
  } else if (requestedOfficeId && requestedOfficeId !== actor.officeId) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "You cannot create templates outside your office."
    );
  }
  if (!officeId) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "officeId is required for template creation."
    );
  }

  const officeName = requestedOfficeName ??
    actor.officeName ??
    coerceString((await db.collection("offices").doc(officeId).get()).data()?.name) ??
    officeId;
  const qrPosition = normalizeTemplateQrPosition(payload.qrPosition);
  const qrSize = normalizeTemplateQrSize(payload.qrSize);
  const templateRef = db.collection("dts_templates").doc();
  const actorName = actorDisplayName(actor);

  await templateRef.set({
    name,
    officeId,
    officeName,
    fileUrl,
    fileBytes: fileBytes ?? null,
    qrPosition,
    qrSize,
    version: 1,
    isActive: true,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    createdByUid: actor.uid,
    createdByName: actorName,
    updatedByUid: actor.uid,
    updatedByName: actorName,
  });

  await addAuditLog({
    action: "dts_template_created",
    entityType: "dts_templates",
    entityId: templateRef.id,
    officeId,
    actorUid: actor.uid,
    actorRole: actor.role,
    actorOfficeId: actor.officeId ?? null,
    actorOfficeName: actor.officeName ?? null,
    actorName,
    message: `Template created: ${name}.`,
  });

  return {
    success: true,
    item: {
      id: templateRef.id,
      name,
      officeId,
      officeName,
      fileUrl,
      fileBytes: fileBytes ?? null,
      qrPosition,
      qrSize,
      version: 1,
      isActive: true,
    },
  };
}

export const dtsCreateTemplate = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await dtsCreateTemplateHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

async function dtsUpdateTemplateHandler(
  data: unknown,
  context: CallableContextLike
) {
  const payload = (data && typeof data === "object") ?
    (data as Record<string, unknown>) :
    {};
  const actor = await requireStaffContext(context);
  assertDtsTemplateManager(actor);
  await requireFeatureWritable("documentTracking");

  const templateId = coerceString(payload.templateId);
  if (!templateId) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "templateId is required."
    );
  }
  const templateRef = db.collection("dts_templates").doc(templateId);
  const templateSnap = await templateRef.get();
  if (!templateSnap.exists) {
    throw new functions.https.HttpsError("not-found", "Template not found.");
  }
  const current = mapDtsTemplateRecord(templateSnap.id, templateSnap.data() ?? {});
  if (!canManageDtsTemplate(actor, current)) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "You cannot update this template."
    );
  }

  const requestedOfficeId = coerceString(payload.officeId);
  if (requestedOfficeId && requestedOfficeId !== current.officeId) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Template office scope cannot be changed."
    );
  }

  const updates: Record<string, unknown> = {};
  const nextName = coerceString(payload.name);
  if (nextName != null) {
    if (nextName.length > 120) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "Template name must be 120 chars or less."
      );
    }
    updates.name = nextName;
  }

  const nextFileUrlRaw = payload.fileUrl;
  const hasFileUrlUpdate = nextFileUrlRaw != null;
  const nextFileUrl = hasFileUrlUpdate ?
    sanitizeTemplateFileUrl(nextFileUrlRaw) :
    current.fileUrl;
  if (hasFileUrlUpdate) {
    updates.fileUrl = nextFileUrl;
  }

  const nextQrPositionRaw = payload.qrPosition;
  const hasQrPositionUpdate = nextQrPositionRaw != null;
  const nextQrPosition = hasQrPositionUpdate ?
    normalizeTemplateQrPosition(nextQrPositionRaw) :
    current.qrPosition;
  if (hasQrPositionUpdate) {
    updates.qrPosition = nextQrPosition;
  }

  const nextQrSizeRaw = payload.qrSize;
  const hasQrSizeUpdate = nextQrSizeRaw != null;
  const nextQrSize = hasQrSizeUpdate ?
    normalizeTemplateQrSize(nextQrSizeRaw) :
    current.qrSize;
  if (hasQrSizeUpdate) {
    updates.qrSize = nextQrSize;
  }

  const fileBytes = normalizeTemplateFileBytes(payload.fileBytes);
  if (fileBytes != null) {
    if (fileBytes > DTS_TEMPLATE_FILE_MAX_BYTES) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "Template file exceeds the 12 MB upload limit."
      );
    }
    updates.fileBytes = fileBytes;
  }

  const layoutChanged = hasFileUrlUpdate || hasQrPositionUpdate || hasQrSizeUpdate;
  const nextVersion = layoutChanged ? current.version + 1 : current.version;
  if (layoutChanged) {
    updates.version = nextVersion;
  }
  updates.updatedAt = admin.firestore.FieldValue.serverTimestamp();
  updates.updatedByUid = actor.uid;
  updates.updatedByName = actorDisplayName(actor);

  await templateRef.set(updates, {merge: true});

  await addAuditLog({
    action: "dts_template_updated",
    entityType: "dts_templates",
    entityId: templateId,
    officeId: current.officeId ?? actor.officeId ?? null,
    actorUid: actor.uid,
    actorRole: actor.role,
    actorOfficeId: actor.officeId ?? null,
    actorOfficeName: actor.officeName ?? null,
    actorName: actorDisplayName(actor),
    message: layoutChanged ?
      `Template updated with version bump to v${nextVersion}.` :
      "Template metadata updated.",
  });

  const merged = {
    id: templateId,
    name: (updates.name as string | undefined) ?? current.name,
    officeId: current.officeId,
    officeName: current.officeName,
    fileUrl: (updates.fileUrl as string | undefined) ?? current.fileUrl,
    fileBytes: (updates.fileBytes as number | undefined) ?? current.fileBytes,
    qrPosition: (updates.qrPosition as string | undefined) ?? current.qrPosition,
    qrSize: (updates.qrSize as number | undefined) ?? current.qrSize,
    version: nextVersion,
    isActive: current.isActive,
  };

  return {
    success: true,
    item: merged,
  };
}

export const dtsUpdateTemplate = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await dtsUpdateTemplateHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

async function dtsDeactivateTemplateHandler(
  data: unknown,
  context: CallableContextLike
) {
  const payload = (data && typeof data === "object") ?
    (data as Record<string, unknown>) :
    {};
  const actor = await requireStaffContext(context);
  assertDtsTemplateManager(actor);
  await requireFeatureWritable("documentTracking");

  const templateId = coerceString(payload.templateId);
  if (!templateId) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "templateId is required."
    );
  }

  const templateRef = db.collection("dts_templates").doc(templateId);
  const templateSnap = await templateRef.get();
  if (!templateSnap.exists) {
    throw new functions.https.HttpsError("not-found", "Template not found.");
  }
  const current = mapDtsTemplateRecord(templateSnap.id, templateSnap.data() ?? {});
  if (!canManageDtsTemplate(actor, current)) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "You cannot deactivate this template."
    );
  }

  await templateRef.set({
    isActive: false,
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    updatedByUid: actor.uid,
    updatedByName: actorDisplayName(actor),
  }, {merge: true});

  await addAuditLog({
    action: "dts_template_deactivated",
    entityType: "dts_templates",
    entityId: templateId,
    officeId: current.officeId ?? actor.officeId ?? null,
    actorUid: actor.uid,
    actorRole: actor.role,
    actorOfficeId: actor.officeId ?? null,
    actorOfficeName: actor.officeName ?? null,
    actorName: actorDisplayName(actor),
    message: `Template deactivated: ${current.name}.`,
  });

  return {
    success: true,
    templateId,
    isActive: false,
  };
}

export const dtsDeactivateTemplate = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await dtsDeactivateTemplateHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

async function dtsPreviewInternalPdfHandler(
  data: unknown,
  context: CallableContextLike
) {
  const payload = (data && typeof data === "object") ?
    (data as Record<string, unknown>) :
    {};
  const actor = await requireStaffContext(context);
  await requireFeatureWritable("documentTracking");

  const requestedOfficeId = coerceString(payload.officeId);
  const officeId = (actor.role === "super_admin" || actor.role === "admin") ?
    (requestedOfficeId ?? actor.officeId) :
    (actor.officeId ?? requestedOfficeId);
  if (!officeId) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "officeId is required for internal preview."
    );
  }

  const sourcePdf = decodePdfBase64(payload.fileBase64);
  const fileName = sanitizePdfFileName(coerceString(payload.fileName));
  const previewTrackingNo = coerceString(payload.trackingNo) ??
    `PREVIEW-${Date.now().toString().slice(-8)}`;
  const previewQrCode = coerceString(payload.qrCode) ??
    `PREVIEW-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;
  const parsed = await PDFDocument.load(sourcePdf, {ignoreEncryption: true});
  const pageCount = parsed.getPageCount();
  if (pageCount <= 0) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "PDF must contain at least one page."
    );
  }
  const stamped = await stampInternalPdfDocument(
    sourcePdf,
    previewTrackingNo,
    previewQrCode
  );
  const previewPath = `dts_previews/${actor.uid}/${Date.now()}-${crypto.randomBytes(3).toString("hex")}-${fileName}`;
  const bucket = admin.storage().bucket();
  const previewFile = bucket.file(previewPath);
  await previewFile.save(stamped, {
    metadata: {
      contentType: "application/pdf",
      cacheControl: "private, max-age=300",
    },
  });

  const expiresAtMs = Date.now() + 1000 * 60 * 15;
  let previewDownloadUrl: string | null = null;
  try {
    previewDownloadUrl = await buildStorageSignedReadUrl(previewPath, expiresAtMs);
  } catch (error) {
    console.warn("dtsPreviewInternalPdf: signed URL generation failed; using token URL fallback", {
      error,
    });
    previewDownloadUrl = await buildStorageTokenUrl(previewPath);
  }

  return {
    success: true,
    fileName,
    pageCount,
    originalBytes: sourcePdf.length,
    stampedBytes: stamped.length,
    trackingNoPreview: previewTrackingNo,
    qrCodePreview: previewQrCode,
    previewFilePath: previewPath,
    previewDownloadUrl,
    previewExpiresAt: new Date(expiresAtMs).toISOString(),
  };
}

export const dtsPreviewInternalPdf = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await dtsPreviewInternalPdfHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

async function dtsStampInternalPdfHandler(
  data: unknown,
  context: CallableContextLike
) {
  const payload = (data && typeof data === "object") ?
    (data as Record<string, unknown>) :
    {};
  const actor = await requireStaffContext(context);
  await requireFeatureWritable("documentTracking");

  const docId = coerceString(payload.docId);
  if (!docId) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "docId is required."
    );
  }
  const docRef = db.collection("dts_documents").doc(docId);
  const docSnap = await docRef.get();
  if (!docSnap.exists) {
    throw new functions.https.HttpsError("not-found", "Document not found.");
  }
  const docRow = docSnap.data() ?? {};
  if (!canOperateOnDtsDoc(actor, docRow)) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "You cannot stamp this document."
    );
  }
  const originType = (coerceString(docRow.originType) ?? "EXTERNAL")
    .trim()
    .toUpperCase();
  if (originType !== "INTERNAL") {
    throw new functions.https.HttpsError(
      "failed-precondition",
      "PDF stamping is available only for internal documents."
    );
  }
  const status = normalizeDtsStatus(docRow.status, "CREATED");
  if (status === "ARCHIVED" || status === "VOIDED") {
    throw new functions.https.HttpsError(
      "failed-precondition",
      "Archived or voided records cannot be restamped."
    );
  }
  const trackingNo = coerceString(docRow.trackingNo);
  const qrCode = coerceString(docRow.qrCode);
  if (!trackingNo || !qrCode) {
    throw new functions.https.HttpsError(
      "failed-precondition",
      "Document is missing tracking number or QR assignment."
    );
  }

  const idempotencyKey = coerceString(payload.idempotencyKey);
  const requestRef = idempotencyKey ?
    docRef.collection("generation_requests").doc(sha256(idempotencyKey).slice(0, 40)) :
    null;
  if (requestRef) {
    try {
      await requestRef.create({
        status: "processing",
        createdByUid: actor.uid,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    } catch (_error) {
      const existing = await requestRef.get();
      const row = existing.data() ?? {};
      if (coerceString(row.status) === "completed" && row.result) {
        return row.result;
      }
      throw new functions.https.HttpsError(
        "aborted",
        "A finalize request is already in progress for this action."
      );
    }
  }

  try {
    const sourcePdf = decodePdfBase64(payload.fileBase64);
    const safeFileName = sanitizePdfFileName(coerceString(payload.fileName));
    const stampedPdf = await stampInternalPdfDocument(sourcePdf, trackingNo, qrCode);
    const currentVersion = Number.isFinite(Number(docRow.activeGeneratedVersion)) ?
      Math.max(0, Number(docRow.activeGeneratedVersion)) :
      0;
    const nextVersion = currentVersion + 1;
    const bucket = admin.storage().bucket();
    const versionPath = `dts_documents/${docId}/generated/v${nextVersion}`;
    const originalPath = `${versionPath}/original_${safeFileName}`;
    const stampedPath = `${versionPath}/stamped_${safeFileName}`;
    await bucket.file(originalPath).save(sourcePdf, {
      metadata: {
        contentType: "application/pdf",
        metadata: {
          dtsDocId: docId,
          trackingNo,
          generatedVersion: String(nextVersion),
          source: "internal_pdf_original",
        },
      },
    });
    await bucket.file(stampedPath).save(stampedPdf, {
      metadata: {
        contentType: "application/pdf",
        metadata: {
          dtsDocId: docId,
          trackingNo,
          qrCode,
          generatedVersion: String(nextVersion),
          source: "internal_pdf_stamped",
        },
      },
    });
    let generatedFileUrl: string | null = null;
    try {
      generatedFileUrl = await buildStorageSignedReadUrl(
        stampedPath,
        Date.now() + 1000 * 60 * 15
      );
    } catch (error) {
      if (FUNCTIONS_EMULATOR_ENABLED) {
        generatedFileUrl = await buildStorageTokenUrl(stampedPath);
      } else {
        console.warn("dtsStampInternalPdf: signed URL generation failed", {
          docId,
          stampedPath,
          error,
        });
      }
    }

    const timelineAttachments: Array<Record<string, unknown>> = [
      {
        name: `Stamped ${safeFileName}`,
        path: stampedPath,
        contentType: "application/pdf",
        uploadedAt: new Date().toISOString(),
      },
      {
        name: `Original ${safeFileName}`,
        path: originalPath,
        contentType: "application/pdf",
        uploadedAt: new Date().toISOString(),
      },
    ];
    const generatedAtIso = new Date().toISOString();
    const generatedFileEntry: Record<string, unknown> = {
      version: nextVersion,
      fileName: safeFileName,
      stampedPath,
      stampedUrl: generatedFileUrl,
      originalPath,
      generatedAt: generatedAtIso,
      generatedByUid: actor.uid,
      generatedByName: actorDisplayName(actor),
    };

    await db.runTransaction(async (tx) => {
      const currentSnap = await tx.get(docRef);
      if (!currentSnap.exists) {
        throw new functions.https.HttpsError("not-found", "Document not found.");
      }
      const currentRow = currentSnap.data() ?? {};
      if (coerceString(currentRow.qrCode) !== qrCode) {
        throw new functions.https.HttpsError(
          "failed-precondition",
          "QR assignment changed. Retry stamping."
        );
      }
      const existingGeneratedFiles = Array.isArray(currentRow.generatedFiles) ?
        currentRow.generatedFiles
          .filter((item: unknown) => Boolean(item) && typeof item === "object")
          .map((item: unknown) => ({...(item as Record<string, unknown>)})) :
        [];
      const nextGeneratedFiles = [...existingGeneratedFiles, generatedFileEntry]
        .filter((item) => {
          const stamped = coerceString(item.stampedPath);
          const original = coerceString(item.originalPath);
          return Boolean(stamped || original);
        })
        .sort((left, right) => {
          const leftVersion = Number.isFinite(Number(left.version)) ?
            Number(left.version) :
            0;
          const rightVersion = Number.isFinite(Number(right.version)) ?
            Number(right.version) :
            0;
          if (leftVersion !== rightVersion) {
            return rightVersion - leftVersion;
          }
          const leftGeneratedAt = Date.parse(coerceString(left.generatedAt) ?? "");
          const rightGeneratedAt = Date.parse(coerceString(right.generatedAt) ?? "");
          return (Number.isFinite(rightGeneratedAt) ? rightGeneratedAt : 0) -
            (Number.isFinite(leftGeneratedAt) ? leftGeneratedAt : 0);
        })
        .slice(0, 32);
      tx.set(docRef, {
        generatedFilePath: stampedPath,
        originalUploadPath: originalPath,
        generatedFileUrl,
        activeGeneratedVersion: nextVersion,
        generatedFiles: nextGeneratedFiles,
        generatedAt: admin.firestore.FieldValue.serverTimestamp(),
        generatedByUid: actor.uid,
        generatedByName: actorDisplayName(actor),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      }, {merge: true});
      tx.set(docRef.collection("timeline").doc(), {
        type: nextVersion > 1 ? "DOCUMENT_REGENERATED" : "DOCUMENT_GENERATED",
        actionType: nextVersion > 1 ? "DOCUMENT_REGENERATED" : "DOCUMENT_GENERATED",
        action: nextVersion > 1 ? "DOCUMENT_REGENERATED" : "DOCUMENT_GENERATED",
        byUid: actor.uid,
        byName: actorDisplayName(actor),
        byOfficeId: actor.officeId ?? coerceString(currentRow.currentOfficeId) ?? null,
        byOfficeName: actor.officeName ?? coerceString(currentRow.currentOfficeName) ?? null,
        officeId: coerceString(currentRow.currentOfficeId) ?? actor.officeId ?? null,
        status: normalizeDtsStatus(currentRow.status, "CREATED"),
        notePublic: "Document print copy prepared.",
        notes: nextVersion > 1
          ? `Regenerated stamped PDF version ${nextVersion}.`
          : `Generated stamped PDF version ${nextVersion}.`,
        officeName: coerceString(currentRow.currentOfficeName) ?? actor.officeName ?? null,
        generatedVersion: nextVersion,
        attachments: timelineAttachments,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    });

    await addAuditLog({
      action: "dts_internal_pdf_stamped",
      entityType: "dts_documents",
      entityId: docId,
      dtsDocId: docId,
      dtsTrackingNo: trackingNo,
      officeId: actor.officeId ?? coerceString(docRow.currentOfficeId) ?? null,
      actorUid: actor.uid,
      actorRole: actor.role,
      actorOfficeId: actor.officeId ?? null,
      actorOfficeName: actor.officeName ?? null,
      actorName: actorDisplayName(actor),
      message: `Generated stamped PDF version ${nextVersion}.`,
    });

    const response = {
      success: true,
      docId,
      trackingNo,
      qrCode,
      activeGeneratedVersion: nextVersion,
      generatedFilePath: stampedPath,
      generatedFileUrl,
      originalUploadPath: originalPath,
      fileName: safeFileName,
    };
    if (requestRef) {
      await requestRef.set({
        status: "completed",
        result: response,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      }, {merge: true});
    }
    return response;
  } catch (error) {
    if (requestRef) {
      await requestRef.set({
        status: "failed",
        error: error instanceof Error ? error.message : String(error),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      }, {merge: true});
    }
    throw error;
  }
}

export const dtsStampInternalPdf = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await dtsStampInternalPdfHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

async function dtsGetGeneratedPdfAccessHandler(
  data: unknown,
  context: CallableContextLike
) {
  const payload = (data && typeof data === "object") ?
    (data as Record<string, unknown>) :
    {};
  const actor = await requireStaffContext(context);
  await requireFeatureWritable("documentTracking");
  const docId = coerceString(payload.docId) ?? coerceString(payload.trackingId);
  const action = (coerceString(payload.action) ?? "open").toLowerCase();
  if (!docId) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "docId is required."
    );
  }
  if (!["open", "preview", "download"].includes(action)) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "action must be open, preview, or download."
    );
  }

  const docRef = db.collection("dts_documents").doc(docId);
  const docSnap = await docRef.get();
  if (!docSnap.exists) {
    throw new functions.https.HttpsError("not-found", "Document not found.");
  }
  const docRow = docSnap.data() ?? {};
  if (actor.role !== "super_admin" && !canOperateOnDtsDoc(actor, docRow)) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "You cannot access generated files for this document."
    );
  }

  const fallbackPathFromUrl = (() => {
    const urlText = coerceString(docRow.generatedFileUrl);
    if (!urlText) return null;
    try {
      const parsed = new URL(urlText);
      const marker = "/o/";
      const idx = parsed.pathname.indexOf(marker);
      if (idx < 0) return null;
      const encodedPath = parsed.pathname.slice(idx + marker.length);
      if (!encodedPath) return null;
      return decodeURIComponent(encodedPath);
    } catch (_error) {
      return null;
    }
  })();

  const requestedPathInput = coerceString(payload.path);
  const requestedPath = requestedPathInput ?
    normalizeGeneratedPdfPath(docId, requestedPathInput) :
    null;
  if (requestedPathInput && !requestedPath) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "path must point to a generated PDF under this document."
    );
  }
  const generatedFilePath = normalizeGeneratedPdfPath(
    docId,
    requestedPath ?? (docRow.generatedFilePath ?? fallbackPathFromUrl)
  );
  if (!generatedFilePath) {
    throw new functions.https.HttpsError(
      "failed-precondition",
      "No generated PDF is available for this record."
    );
  }

  const bucket = admin.storage().bucket();
  const file = bucket.file(generatedFilePath);
  const [exists] = await file.exists();
  if (!exists) {
    throw new functions.https.HttpsError(
      "not-found",
      "Generated PDF file not found in storage."
    );
  }

  const expiresAtMs = Date.now() + 1000 * 60 * 15;
  let downloadUrl: string | null = null;
  try {
    downloadUrl = await buildStorageSignedReadUrl(generatedFilePath, expiresAtMs);
  } catch (error) {
    console.warn("dtsGetGeneratedPdfAccess: signed URL generation failed; using token URL fallback", {
      error,
    });
    downloadUrl = await buildStorageTokenUrl(generatedFilePath);
  }

  await addAuditLog({
    action: "dts_generated_pdf_access",
    entityType: "dts_documents",
    entityId: docId,
    dtsDocId: docId,
    dtsTrackingNo: coerceString(docRow.trackingNo),
    officeId: coerceString(docRow.currentOfficeId),
    actorUid: actor.uid,
    actorRole: actor.role,
    actorOfficeId: actor.officeId ?? null,
    actorOfficeName: actor.officeName ?? null,
    actorName: actorDisplayName(actor),
    message: `Generated PDF ${action} access issued.`,
  });

  if (action !== "preview") {
    const resolvedOfficeId = coerceString(docRow.currentOfficeId) ?? actor.officeId ?? null;
    const resolvedOfficeName = coerceString(docRow.currentOfficeName) ?? actor.officeName ?? null;
    await docRef.collection("timeline").add({
      type: "DOCUMENT_REPRINTED",
      actionType: "DOCUMENT_REPRINTED",
      action: "DOCUMENT_REPRINTED",
      byUid: actor.uid,
      byName: actorDisplayName(actor),
      byOfficeId: actor.officeId ?? resolvedOfficeId,
      byOfficeName: actor.officeName ?? resolvedOfficeName,
      officeId: resolvedOfficeId,
      officeName: resolvedOfficeName,
      status: normalizeDtsStatus(docRow.status, "CREATED"),
      generatedFilePath,
      notePublic: "Generated PDF opened for printing.",
      notes: `Generated PDF ${action} access issued.`,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  }

  return {
    success: true,
    docId,
    action,
    generatedFilePath,
    downloadUrl,
    expiresAt: new Date(expiresAtMs).toISOString(),
  };
}

export const dtsGetGeneratedPdfAccess = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await dtsGetGeneratedPdfAccessHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

export const dtsResolveQrForStaff = protectedCallableFunctions.https.onCall(
  async (data, context) => {
    const actor = await requireStaffContext(context);
    await requireFeatureWritable("documentTracking");
    const qrCode = coerceString(data?.qrCode);
    if (!qrCode) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "qrCode is required."
      );
    }

    const qrRef = db.collection("dts_qr_codes").doc(qrCode);
    const qrSnap = await qrRef.get();
    if (!qrSnap.exists) {
      throw new functions.https.HttpsError("not-found", "QR code not found.");
    }

    const qrRow = qrSnap.data() ?? {};
    const status = normalizeDtsQrCodeStatus(qrRow.status) || "unused";
    const batchId = coerceString(qrRow.batchId);
    if (status === "voided") {
      throw new functions.https.HttpsError(
        "failed-precondition",
        "This QR code has been voided."
      );
    }
    const qrIndexSnap = await db.collection("dts_qr_index").doc(qrCode).get();
    const docIdFromCode = coerceString(qrRow.docId);
    const docIdFromIndex = coerceString(qrIndexSnap.data()?.docId);
    let docId = docIdFromCode ?? docIdFromIndex;
    if (!docId) {
      const linkedDocSnap = await db
        .collection("dts_documents")
        .where("qrCode", "==", qrCode)
        .limit(1)
        .get();
      if (!linkedDocSnap.empty) {
        docId = linkedDocSnap.docs[0].id;
      }
    }

    if (!docId && (status === "used" || qrIndexSnap.exists || docIdFromCode)) {
      const cleanupBatch = db.batch();
      cleanupBatch.set(qrSnap.ref, {
        status: "unused",
        docId: admin.firestore.FieldValue.delete(),
        usedAt: admin.firestore.FieldValue.delete(),
        usedByUid: admin.firestore.FieldValue.delete(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      }, {merge: true});
      if (qrIndexSnap.exists) {
        cleanupBatch.delete(qrIndexSnap.ref);
      }
      await cleanupBatch.commit();
      if (batchId) {
        await reconcileDtsQrBatch(batchId, {
          repairQrRows: true,
          syncBatchCounters: true,
        });
      }
    }

    if (!docId) {
      const reserved = await reserveDtsQrForIntake(qrCode, actor.uid);
      if (reserved.status === "used") {
        throw new functions.https.HttpsError(
          "failed-precondition",
          "Requested QR code is already associated with another tracking record."
        );
      }
      return {
        qrCode,
        status: "reserved",
        batchId: reserved.batchId,
        imagePath: reserved.imagePath,
        reservedByUid: actor.uid,
        reservationExpiresAt: reserved.reservationExpiresAt,
      };
    }

    const docSnap = await db.collection("dts_documents").doc(docId).get();
    if (!docSnap.exists) {
      const cleanupBatch = db.batch();
      cleanupBatch.set(qrSnap.ref, {
        status: "unused",
        docId: admin.firestore.FieldValue.delete(),
        usedAt: admin.firestore.FieldValue.delete(),
        usedByUid: admin.firestore.FieldValue.delete(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      }, {merge: true});
      if (qrIndexSnap.exists) {
        cleanupBatch.delete(qrIndexSnap.ref);
      }
      await cleanupBatch.commit();
      if (batchId) {
        await reconcileDtsQrBatch(batchId, {
          repairQrRows: true,
          syncBatchCounters: true,
        });
      }
      return {
        qrCode,
        status: "unused",
        batchId,
        imagePath: coerceString(qrRow.imagePath),
      };
    }
    const docRow = docSnap.data() ?? {};
    if (actor.role !== "super_admin" && !canOperateOnDtsDoc(actor, docRow)) {
      throw new functions.https.HttpsError(
        "permission-denied",
        "You cannot access this document."
      );
    }

    const canonicalTrackingNo = coerceString(docRow.trackingNo) ?? "";
    const needsQrPatch =
      status !== "used" ||
      docIdFromCode !== docId;
    const needsIndexPatch =
      !qrIndexSnap.exists ||
      docIdFromIndex !== docId ||
      coerceString(qrIndexSnap.data()?.trackingNo) !== canonicalTrackingNo;
    if (needsQrPatch || needsIndexPatch) {
      const patchBatch = db.batch();
      if (needsQrPatch) {
        patchBatch.set(qrSnap.ref, {
          status: "used",
          docId,
          usedAt: qrRow.usedAt ?? admin.firestore.FieldValue.serverTimestamp(),
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        }, {merge: true});
      }
      if (needsIndexPatch) {
        patchBatch.set(qrIndexSnap.ref, {
          docId,
          trackingNo: canonicalTrackingNo,
          createdAt: qrIndexSnap.exists ?
            (qrIndexSnap.data()?.createdAt ?? admin.firestore.FieldValue.serverTimestamp()) :
            admin.firestore.FieldValue.serverTimestamp(),
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        }, {merge: true});
      }
      await patchBatch.commit();
      if (batchId) {
        await reconcileDtsQrBatch(batchId, {
          repairQrRows: true,
          syncBatchCounters: true,
        });
      }
    }

    return {
      qrCode,
      status: "used",
      docId,
      trackingNo: canonicalTrackingNo,
      title: coerceString(docRow.title) ?? "",
      currentOfficeId: coerceString(docRow.currentOfficeId),
      currentOfficeName: coerceString(docRow.currentOfficeName),
    };
  }
);

type DtsRequestedDestination = {
  toOfficeId: string;
  toOfficeName: string | null;
  toUid: string | null;
};

function parseRequestedDestinations(
  raw: unknown,
  fallback: DtsRequestedDestination | null = null
): DtsRequestedDestination[] {
  const source = Array.isArray(raw) ? raw : (fallback ? [fallback] : []);
  const dedupe = new Set<string>();
  const rows: DtsRequestedDestination[] = [];
  for (const item of source) {
    const map = (item && typeof item === "object") ?
      (item as Record<string, unknown>) :
      {};
    const toOfficeId = coerceString(map.toOfficeId);
    if (!toOfficeId) {
      continue;
    }
    const key = `${toOfficeId}::${coerceString(map.toUid) ?? ""}`;
    if (dedupe.has(key)) {
      continue;
    }
    dedupe.add(key);
    rows.push({
      toOfficeId,
      toOfficeName: coerceString(map.toOfficeName),
      toUid: coerceString(map.toUid),
    });
    if (rows.length >= 40) {
      break;
    }
  }
  return rows;
}

async function hydrateDestinationOfficeNames(
  destinations: DtsRequestedDestination[]
): Promise<DtsRequestedDestination[]> {
  const officeCache = new Map<string, string>();
  return Promise.all(
    destinations.map(async (destination) => {
      const cachedName = officeCache.get(destination.toOfficeId);
      const knownName = destination.toOfficeName ?? cachedName ?? null;
      if (knownName) {
        return {
          ...destination,
          toOfficeName: knownName,
        };
      }
      const officeSnap = await db.collection("offices").doc(destination.toOfficeId).get();
      const resolvedName = coerceString(officeSnap.data()?.name) ?? destination.toOfficeId;
      officeCache.set(destination.toOfficeId, resolvedName);
      return {
        ...destination,
        toOfficeName: resolvedName,
      };
    })
  );
}

function assertDtsSourceOfficeForDistribution(
  actor: StaffContext,
  row: Record<string, unknown>
): void {
  if (actor.role === "super_admin" || actor.role === "admin") {
    return;
  }
  const currentOfficeId = coerceString(row.currentOfficeId);
  const currentOfficeName = coerceString(row.currentOfficeName);
  if (actor.officeId && currentOfficeId && actor.officeId === currentOfficeId) {
    return;
  }
  if (sameNormalizedName(actor.officeName, currentOfficeName)) {
    return;
  }
  throw new functions.https.HttpsError(
    "permission-denied",
    "Only the source office can manage destinations."
  );
}

async function dtsCreateDestinationsHandler(
  data: unknown,
  context: CallableContextLike
) {
  const payload = (data && typeof data === "object") ?
    (data as Record<string, unknown>) :
    {};
  const actor = await requireStaffContext(context);
  await requireFeatureWritable("documentTracking");
  const docId = coerceString(payload.docId);
  const fallbackDestination = coerceString(payload.toOfficeId)
    ? {
        toOfficeId: coerceString(payload.toOfficeId) as string,
        toOfficeName: coerceString(payload.toOfficeName),
        toUid: coerceString(payload.toUid),
      }
    : null;
  const requestedDestinations = parseRequestedDestinations(
    payload.destinations,
    fallbackDestination
  );
  if (!docId || requestedDestinations.length === 0) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "docId and at least one destination are required."
    );
  }

  const hydratedDestinations =
    await hydrateDestinationOfficeNames(requestedDestinations);
  const actorName = actorDisplayName(actor);
  const docRef = db.collection("dts_documents").doc(docId);
  const createdRows: Array<Record<string, unknown>> = [];
  let summaryResult: DtsDestinationSummary = {
    total: 0,
    pending: 0,
    inTransit: 0,
    received: 0,
    rejected: 0,
    cancelled: 0,
    activeOfficeIds: [],
    allOfficeIds: [],
  };

  await db.runTransaction(async (tx) => {
    const docSnap = await tx.get(docRef);
    if (!docSnap.exists) {
      throw new functions.https.HttpsError("not-found", "Document not found.");
    }
    const row = docSnap.data() ?? {};
    assertDtsSourceOfficeForDistribution(actor, row);
    const currentStatus = normalizeDtsStatus(row.status, "WITH_OFFICE");
    if (currentStatus === "RELEASED" ||
      currentStatus === "ARCHIVED" ||
      currentStatus === "VOIDED") {
      throw new functions.https.HttpsError(
        "failed-precondition",
        "Destinations cannot be modified for released, archived, or voided documents."
      );
    }

    const existingRows = await loadDtsDestinationRecords(tx, docRef);
    const existingKeys = new Map<string, DtsDestinationRecord>();
    for (const destination of existingRows) {
      const key = `${destination.toOfficeId ?? ""}::${destination.toUid ?? ""}`;
      if (!existingKeys.has(key)) {
        existingKeys.set(key, destination);
      }
    }

    for (const destination of hydratedDestinations) {
      const key = `${destination.toOfficeId}::${destination.toUid ?? ""}`;
      const existing = existingKeys.get(key);
      if (existing &&
        existing.status !== "CANCELLED" &&
        existing.status !== "REJECTED") {
        throw new functions.https.HttpsError(
          "already-exists",
          `Destination already exists for ${destination.toOfficeName ?? destination.toOfficeId}.`
        );
      }
      const destinationRef = docRef.collection("destinations").doc();
      tx.set(destinationRef, {
        docId: docRef.id,
        trackingNo: coerceString(row.trackingNo),
        toOfficeId: destination.toOfficeId,
        toOfficeName: destination.toOfficeName ?? destination.toOfficeId,
        toUid: destination.toUid,
        sourceOfficeId: coerceString(row.currentOfficeId),
        sourceOfficeName: coerceString(row.currentOfficeName),
        status: "PENDING",
        previousStatus: normalizeDtsStatus(row.status, "WITH_OFFICE"),
        createdByUid: actor.uid,
        createdByName: actorName,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      }, {merge: true});
      existingRows.push({
        id: destinationRef.id,
        docId: docRef.id,
        toOfficeId: destination.toOfficeId,
        toOfficeName: destination.toOfficeName ?? destination.toOfficeId,
        toUid: destination.toUid,
        sourceOfficeId: coerceString(row.currentOfficeId),
        sourceOfficeName: coerceString(row.currentOfficeName),
        status: "PENDING",
        previousStatus: normalizeDtsStatus(row.status, "WITH_OFFICE"),
        createdByUid: actor.uid,
        createdByName: actorName,
        createdAt: null,
        dispatchedAt: null,
        receivedAt: null,
        rejectedAt: null,
        cancelledAt: null,
        reason: null,
      });
      createdRows.push({
        id: destinationRef.id,
        toOfficeId: destination.toOfficeId,
        toOfficeName: destination.toOfficeName ?? destination.toOfficeId,
        status: "PENDING",
      });
    }

    const applied = applyDtsDestinationSummaryToParent(tx, docRef, row, existingRows, {
      parentPatch: {
        distributionMode: existingRows.length > 1 ? "MULTI" : "SINGLE",
      },
    });
    summaryResult = applied.summary;

    tx.set(docRef.collection("timeline").doc(), {
      type: "DESTINATIONS_UPDATED",
      actionType: "DESTINATIONS_UPDATED",
      action: "DESTINATIONS_UPDATED",
      byUid: actor.uid,
      byName: actorName,
      byOfficeId: actor.officeId ?? coerceString(row.currentOfficeId) ?? null,
      byOfficeName: actor.officeName ?? coerceString(row.currentOfficeName) ?? null,
      officeId: coerceString(row.currentOfficeId) ?? actor.officeId ?? null,
      officeName: coerceString(row.currentOfficeName) ?? actor.officeName ?? null,
      status: applied.status,
      notePublic: `Destination set updated (${createdRows.length} added).`,
      notes: `Added ${createdRows.length} destination${createdRows.length === 1 ? "" : "s"} for distributed routing.`,
      destinationCount: existingRows.length,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  });

  await addAuditLog({
    action: "dts_destinations_created",
    entityType: "dts_documents",
    entityId: docId,
    dtsDocId: docId,
    actorUid: actor.uid,
    actorRole: actor.role,
    actorOfficeId: actor.officeId ?? null,
    actorOfficeName: actor.officeName ?? null,
    actorName,
    message: `Added ${createdRows.length} destination${createdRows.length === 1 ? "" : "s"} to document.`,
  });

  return {
    success: true,
    created: createdRows,
    summary: {
      total: summaryResult.total,
      pending: summaryResult.pending,
      inTransit: summaryResult.inTransit,
      received: summaryResult.received,
      rejected: summaryResult.rejected,
      cancelled: summaryResult.cancelled,
    },
  };
}

async function dtsDispatchDestinationsHandler(
  data: unknown,
  context: CallableContextLike
) {
  const payload = (data && typeof data === "object") ?
    (data as Record<string, unknown>) :
    {};
  const actor = await requireStaffContext(context);
  await requireFeatureWritable("documentTracking");
  const docId = coerceString(payload.docId);
  const destinationIds = parseStringList(payload.destinationIds, {
    maxItems: 60,
    maxLen: 120,
  });
  if (!docId) {
    throw new functions.https.HttpsError("invalid-argument", "docId is required.");
  }

  const actorName = actorDisplayName(actor);
  const docRef = db.collection("dts_documents").doc(docId);
  let dispatchedCount = 0;

  await db.runTransaction(async (tx) => {
    const docSnap = await tx.get(docRef);
    if (!docSnap.exists) {
      throw new functions.https.HttpsError("not-found", "Document not found.");
    }
    const row = docSnap.data() ?? {};
    assertDtsSourceOfficeForDistribution(actor, row);
    const currentStatus = normalizeDtsStatus(row.status, "WITH_OFFICE");
    if (currentStatus === "RELEASED" ||
      currentStatus === "ARCHIVED" ||
      currentStatus === "VOIDED") {
      throw new functions.https.HttpsError(
        "failed-precondition",
        "Released, archived, or voided documents cannot be dispatched."
      );
    }

    const existingRows = await loadDtsDestinationRecords(tx, docRef);
    if (existingRows.length === 0) {
      throw new functions.https.HttpsError(
        "failed-precondition",
        "Create at least one destination before dispatch."
      );
    }
    const selectedRows = destinationIds.length === 0 ?
      existingRows.filter((rowItem) => rowItem.status === "PENDING") :
      existingRows.filter((rowItem) => destinationIds.includes(rowItem.id));
    if (selectedRows.length === 0) {
      throw new functions.https.HttpsError(
        "failed-precondition",
        "No pending destinations are available for dispatch."
      );
    }

    const nextRows = existingRows.map((destination) => {
      const shouldDispatch = selectedRows.some((selected) => selected.id === destination.id);
      if (!shouldDispatch) {
        return destination;
      }
      if (destination.status !== "PENDING") {
        throw new functions.https.HttpsError(
          "failed-precondition",
          "Only pending destinations can be dispatched."
        );
      }
      if (!isDestinationSource(actor, destination, row)) {
        throw new functions.https.HttpsError(
          "permission-denied",
          "Only the source office can dispatch this destination."
        );
      }
      const destinationRef = docRef.collection("destinations").doc(destination.id);
      tx.set(destinationRef, {
        status: "IN_TRANSIT",
        previousStatus:
          destination.previousStatus ?? normalizeDtsStatus(row.status, "WITH_OFFICE"),
        dispatchedAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        lastActionByUid: actor.uid,
        lastActionByName: actorName,
        lastActionOfficeId: actor.officeId ?? coerceString(row.currentOfficeId) ?? null,
        lastActionOfficeName: actor.officeName ?? coerceString(row.currentOfficeName) ?? null,
      }, {merge: true});
      dispatchedCount += 1;
      return {
        ...destination,
        status: "IN_TRANSIT",
        previousStatus:
          destination.previousStatus ?? normalizeDtsStatus(row.status, "WITH_OFFICE"),
      };
    });

    const applied = applyDtsDestinationSummaryToParent(tx, docRef, row, nextRows, {
      parentPatch: {
        distributionMode: nextRows.length > 1 ? "MULTI" : "SINGLE",
      },
    });

    tx.set(docRef.collection("timeline").doc(), {
      type: "DOCUMENT_ROUTED",
      actionType: "DOCUMENT_ROUTED",
      action: "DOCUMENT_ROUTED",
      byUid: actor.uid,
      byName: actorName,
      byOfficeId: actor.officeId ?? coerceString(row.currentOfficeId) ?? null,
      byOfficeName: actor.officeName ?? coerceString(row.currentOfficeName) ?? null,
      officeId: coerceString(row.currentOfficeId) ?? actor.officeId ?? null,
      officeName: coerceString(row.currentOfficeName) ?? actor.officeName ?? null,
      status: applied.status,
      fromStatus: normalizeDtsStatus(row.status, "WITH_OFFICE"),
      toStatus: applied.status,
      destinationCount: dispatchedCount,
      notePublic: dispatchedCount === 1 ?
        "Document transfer started." :
        `Document dispatched to ${dispatchedCount} destinations.`,
      notes: dispatchedCount === 1 ?
        "Destination dispatched." :
        `${dispatchedCount} destinations were dispatched.`,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  });

  await addAuditLog({
    action: "dts_destinations_dispatched",
    entityType: "dts_documents",
    entityId: docId,
    dtsDocId: docId,
    actorUid: actor.uid,
    actorRole: actor.role,
    actorOfficeId: actor.officeId ?? null,
    actorOfficeName: actor.officeName ?? null,
    actorName,
    message: `Dispatched ${dispatchedCount} destination${dispatchedCount === 1 ? "" : "s"}.`,
  });

  return {
    success: true,
    dispatchedCount,
  };
}

async function dtsConfirmDestinationReceiptHandler(
  data: unknown,
  context: CallableContextLike
) {
  const payload = (data && typeof data === "object") ?
    (data as Record<string, unknown>) :
    {};
  const actor = await requireStaffContext(context);
  await requireFeatureWritable("documentTracking");
  const docId = coerceString(payload.docId);
  const destinationId = coerceString(payload.destinationId);
  const verificationValue = normalizeDtsVerificationValue(payload.verificationValue);
  const verificationMethod = normalizeDtsVerificationMethod(payload.verificationMethod);
  const confirmPhysicalReceipt = coerceBool(payload.confirmPhysicalReceipt, false);
  if (!docId) {
    throw new functions.https.HttpsError("invalid-argument", "docId is required.");
  }
  if (!confirmPhysicalReceipt) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Physical receipt confirmation is required."
    );
  }
  if (!verificationValue) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Invalid tracking number or QR code."
    );
  }

  const attemptScope = `DEST_RECEIVE_${docId}_${destinationId ?? "AUTO"}`;
  await assertReceiptVerificationNotLocked(attemptScope, actor.uid, context);
  const actorName = actorDisplayName(actor);
  const docRef = db.collection("dts_documents").doc(docId);
  let resolvedDestinationId: string | null = null;

  try {
    await db.runTransaction(async (tx) => {
      const docSnap = await tx.get(docRef);
      if (!docSnap.exists) {
        throw new functions.https.HttpsError("not-found", "Document not found.");
      }
      const row = docSnap.data() ?? {};
      const existingRows = await loadDtsDestinationRecords(tx, docRef);
      if (existingRows.length === 0) {
        throw new functions.https.HttpsError(
          "failed-precondition",
          "No destination transfer found for this document."
        );
      }
      const chosen = destinationId ?
        findDestinationById(existingRows, destinationId) :
        findReceivingDestinationForActor(existingRows, actor);
      if (!chosen) {
        throw new functions.https.HttpsError(
          "failed-precondition",
          destinationId ?
            "Destination transfer not found." :
            "Select a destination transfer before confirming receipt."
        );
      }
      resolvedDestinationId = chosen.id;
      if (!isDestinationReceiver(actor, chosen)) {
        throw new functions.https.HttpsError(
          "permission-denied",
          "You are not authorized to receive this destination."
        );
      }
      if (chosen.status === "RECEIVED") {
        throw new functions.https.HttpsError(
          "failed-precondition",
          "Destination already received."
        );
      }
      if (chosen.status !== "IN_TRANSIT") {
        throw new functions.https.HttpsError(
          "failed-precondition",
          "Destination is not in transit."
        );
      }

      const trackingNo = coerceString(row.trackingNo) ?? "";
      const qrCode = coerceString(row.qrCode);
      const expectedQrSuffix = dtsQrSuffix(qrCode);
      if (expectedQrSuffix) {
        if (verificationValue !== expectedQrSuffix) {
          throw new functions.https.HttpsError(
            "invalid-argument",
            "Invalid tracking number or QR code."
          );
        }
      } else if (!matchesDtsTrackingOrQr(verificationValue, trackingNo, qrCode)) {
        throw new functions.https.HttpsError(
          "invalid-argument",
          "Invalid tracking number or QR code."
        );
      }

      const destinationRef = docRef.collection("destinations").doc(chosen.id);
      tx.set(destinationRef, {
        status: "RECEIVED",
        receivedAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        reason: admin.firestore.FieldValue.delete(),
        verificationMethod,
        verifiedByUid: actor.uid,
        verifiedByName: actorName,
        lastActionByUid: actor.uid,
        lastActionByName: actorName,
        lastActionOfficeId: actor.officeId ?? chosen.toOfficeId ?? null,
        lastActionOfficeName: actor.officeName ?? chosen.toOfficeName ?? null,
      }, {merge: true});

      const nextRows = existingRows.map((destination) =>
        destination.id === chosen.id ?
          {
            ...destination,
            status: "RECEIVED",
          } :
          destination
      );
      const singleDestinationFlow =
        normalizeDtsDistributionMode(row.distributionMode) === "SINGLE" ||
        nextRows.length <= 1;
      const applied = applyDtsDestinationSummaryToParent(tx, docRef, row, nextRows, {
        forceStatus: singleDestinationFlow ? "WITH_OFFICE" : null,
        parentPatch: singleDestinationFlow ?
          {
            currentOfficeId: chosen.toOfficeId,
            currentOfficeName: chosen.toOfficeName,
            currentCustodianUid: actor.uid,
            pendingTransfer: null,
          } :
          undefined,
      });

      tx.set(docRef.collection("timeline").doc(), {
        type: "DOCUMENT_RECEIVED",
        actionType: "DOCUMENT_RECEIVED",
        action: "DOCUMENT_RECEIVED",
        destinationId: chosen.id,
        method: verificationMethod,
        verificationMethod,
        byUid: actor.uid,
        byName: actorName,
        byOfficeId: actor.officeId ?? chosen.toOfficeId ?? null,
        byOfficeName: actor.officeName ?? chosen.toOfficeName ?? null,
        toOfficeId: chosen.toOfficeId,
        toOfficeName: chosen.toOfficeName,
        officeId: chosen.toOfficeId,
        officeName: chosen.toOfficeName,
        fromStatus: "IN_TRANSIT",
        toStatus: singleDestinationFlow ? "WITH_OFFICE" : applied.status,
        status: singleDestinationFlow ? "WITH_OFFICE" : applied.status,
        notePublic: chosen.toOfficeName ?
          `Document received by ${chosen.toOfficeName}.` :
          "Document received by destination office.",
        notes: `Destination receipt confirmed by ${actorName} (${verificationMethod}).`,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    });
  } catch (error) {
    const code = (error as {code?: string})?.code ?? "";
    if (code === "invalid-argument") {
      const locked = await registerReceiptVerificationFailure(
        attemptScope,
        actor.uid,
        context
      );
      if (locked) {
        throw new functions.https.HttpsError(
          "resource-exhausted",
          "Too many invalid verification attempts. Please wait before trying again."
        );
      }
      throw new functions.https.HttpsError(
        "invalid-argument",
        "Invalid tracking number or QR code."
      );
    }
    throw error;
  }

  await clearReceiptVerificationAttempts(attemptScope, actor.uid, context);

  await addAuditLog({
    action: "dts_destination_received",
    entityType: "dts_documents",
    entityId: docId,
    dtsDocId: docId,
    actorUid: actor.uid,
    actorRole: actor.role,
    actorOfficeId: actor.officeId ?? null,
    actorOfficeName: actor.officeName ?? null,
    actorName,
    message: `Destination receipt confirmed${resolvedDestinationId ? ` (${resolvedDestinationId})` : ""}.`,
  });

  return {
    success: true,
    destinationId: resolvedDestinationId,
  };
}

async function dtsRejectDestinationHandler(
  data: unknown,
  context: CallableContextLike
) {
  const payload = (data && typeof data === "object") ?
    (data as Record<string, unknown>) :
    {};
  const actor = await requireStaffContext(context);
  await requireFeatureWritable("documentTracking");
  const docId = coerceString(payload.docId);
  const destinationId = coerceString(payload.destinationId);
  const reason = coerceString(payload.reason);
  if (!docId || !reason) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "docId and reason are required."
    );
  }

  const actorName = actorDisplayName(actor);
  const docRef = db.collection("dts_documents").doc(docId);
  let resolvedDestinationId: string | null = null;

  await db.runTransaction(async (tx) => {
    const docSnap = await tx.get(docRef);
    if (!docSnap.exists) {
      throw new functions.https.HttpsError("not-found", "Document not found.");
    }
    const row = docSnap.data() ?? {};
    const existingRows = await loadDtsDestinationRecords(tx, docRef);
    if (existingRows.length === 0) {
      throw new functions.https.HttpsError(
        "failed-precondition",
        "No destination transfer found for this document."
      );
    }
    const chosen = destinationId ?
      findDestinationById(existingRows, destinationId) :
      findReceivingDestinationForActor(existingRows, actor);
    if (!chosen) {
      throw new functions.https.HttpsError(
        "failed-precondition",
        destinationId ?
          "Destination transfer not found." :
          "Select a destination transfer before rejecting."
      );
    }
    resolvedDestinationId = chosen.id;
    if (!isDestinationReceiver(actor, chosen)) {
      throw new functions.https.HttpsError(
        "permission-denied",
        "You are not the receiving office for this transfer."
      );
    }
    if (chosen.status !== "IN_TRANSIT") {
      throw new functions.https.HttpsError(
        "failed-precondition",
        "Destination is not currently in transit."
      );
    }

    const destinationRef = docRef.collection("destinations").doc(chosen.id);
    tx.set(destinationRef, {
      status: "REJECTED",
      reason,
      rejectedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      lastActionByUid: actor.uid,
      lastActionByName: actorName,
      lastActionOfficeId: actor.officeId ?? chosen.toOfficeId ?? null,
      lastActionOfficeName: actor.officeName ?? chosen.toOfficeName ?? null,
    }, {merge: true});

    const nextRows = existingRows.map((destination) =>
      destination.id === chosen.id ?
        {
          ...destination,
          status: "REJECTED",
          reason,
        } :
        destination
    );
    const singleDestinationFlow =
      normalizeDtsDistributionMode(row.distributionMode) === "SINGLE" ||
      nextRows.length <= 1;
    const applied = applyDtsDestinationSummaryToParent(tx, docRef, row, nextRows, {
      forceStatus: singleDestinationFlow ?
        normalizeDtsStatus(chosen.previousStatus, "WITH_OFFICE") :
        null,
      parentPatch: singleDestinationFlow ?
        {
          currentOfficeId: chosen.sourceOfficeId ?? coerceString(row.currentOfficeId),
          currentOfficeName: chosen.sourceOfficeName ?? coerceString(row.currentOfficeName),
          pendingTransfer: null,
        } :
        undefined,
    });

    tx.set(docRef.collection("timeline").doc(), {
      type: "TRANSFER_REJECTED",
      actionType: "TRANSFER_REJECTED",
      action: "TRANSFER_REJECTED",
      destinationId: chosen.id,
      byUid: actor.uid,
      byName: actorName,
      byOfficeId: actor.officeId ?? chosen.toOfficeId ?? null,
      byOfficeName: actor.officeName ?? chosen.toOfficeName ?? null,
      fromOfficeId: chosen.toOfficeId,
      toOfficeId: chosen.sourceOfficeId,
      reason,
      fromStatus: "IN_TRANSIT",
      toStatus: applied.status,
      officeId: chosen.sourceOfficeId ?? coerceString(row.currentOfficeId) ?? null,
      officeName: chosen.sourceOfficeName ?? coerceString(row.currentOfficeName) ?? null,
      status: applied.status,
      notePublic: "Receiving office rejected the transfer destination.",
      notes: `Transfer rejected: ${reason}`,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  });

  await addAuditLog({
    action: "dts_destination_rejected",
    entityType: "dts_documents",
    entityId: docId,
    dtsDocId: docId,
    actorUid: actor.uid,
    actorRole: actor.role,
    actorOfficeId: actor.officeId ?? null,
    actorOfficeName: actor.officeName ?? null,
    actorName,
    message: `Destination rejected${resolvedDestinationId ? ` (${resolvedDestinationId})` : ""}.`,
  });

  return {
    success: true,
    destinationId: resolvedDestinationId,
  };
}

async function dtsCancelDestinationHandler(
  data: unknown,
  context: CallableContextLike
) {
  const payload = (data && typeof data === "object") ?
    (data as Record<string, unknown>) :
    {};
  const actor = await requireStaffContext(context);
  await requireFeatureWritable("documentTracking");
  const docId = coerceString(payload.docId);
  const destinationId = coerceString(payload.destinationId);
  const reason = coerceString(payload.reason);
  if (!docId || !reason) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "docId and reason are required."
    );
  }

  const actorName = actorDisplayName(actor);
  const docRef = db.collection("dts_documents").doc(docId);
  let resolvedDestinationId: string | null = null;

  await db.runTransaction(async (tx) => {
    const docSnap = await tx.get(docRef);
    if (!docSnap.exists) {
      throw new functions.https.HttpsError("not-found", "Document not found.");
    }
    const row = docSnap.data() ?? {};
    const existingRows = await loadDtsDestinationRecords(tx, docRef);
    if (existingRows.length === 0) {
      throw new functions.https.HttpsError(
        "failed-precondition",
        "No destination transfer found for this document."
      );
    }
    const chosen = destinationId ?
      findDestinationById(existingRows, destinationId) :
      findSourceDestinationForActor(existingRows, actor, row);
    if (!chosen) {
      throw new functions.https.HttpsError(
        "failed-precondition",
        destinationId ?
          "Destination transfer not found." :
          "Select a destination transfer before cancelling."
      );
    }
    resolvedDestinationId = chosen.id;
    if (!isDestinationSource(actor, chosen, row)) {
      throw new functions.https.HttpsError(
        "permission-denied",
        "Only the source office can cancel this destination."
      );
    }
    if (chosen.status !== "IN_TRANSIT" && chosen.status !== "PENDING") {
      throw new functions.https.HttpsError(
        "failed-precondition",
        "Only pending or in-transit destinations can be cancelled."
      );
    }

    const destinationRef = docRef.collection("destinations").doc(chosen.id);
    tx.set(destinationRef, {
      status: "CANCELLED",
      reason,
      cancelledAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      lastActionByUid: actor.uid,
      lastActionByName: actorName,
      lastActionOfficeId: actor.officeId ?? chosen.sourceOfficeId ?? null,
      lastActionOfficeName: actor.officeName ?? chosen.sourceOfficeName ?? null,
    }, {merge: true});

    const nextRows = existingRows.map((destination) =>
      destination.id === chosen.id ?
        {
          ...destination,
          status: "CANCELLED",
          reason,
        } :
        destination
    );
    const singleDestinationFlow =
      normalizeDtsDistributionMode(row.distributionMode) === "SINGLE" ||
      nextRows.length <= 1;
    const applied = applyDtsDestinationSummaryToParent(tx, docRef, row, nextRows, {
      forceStatus: singleDestinationFlow ?
        normalizeDtsStatus(chosen.previousStatus, "WITH_OFFICE") :
        null,
      parentPatch: singleDestinationFlow ?
        {
          pendingTransfer: null,
          currentCustodianUid: actor.uid,
        } :
        undefined,
    });

    tx.set(docRef.collection("timeline").doc(), {
      type: "TRANSFER_CANCELLED",
      actionType: "TRANSFER_CANCELLED",
      action: "TRANSFER_CANCELLED",
      destinationId: chosen.id,
      byUid: actor.uid,
      byName: actorName,
      byOfficeId: actor.officeId ?? chosen.sourceOfficeId ?? null,
      byOfficeName: actor.officeName ?? chosen.sourceOfficeName ?? null,
      fromOfficeId: chosen.sourceOfficeId,
      toOfficeId: chosen.toOfficeId,
      reason,
      fromStatus: chosen.status,
      toStatus: applied.status,
      officeId: chosen.sourceOfficeId ?? coerceString(row.currentOfficeId) ?? null,
      officeName: chosen.sourceOfficeName ?? coerceString(row.currentOfficeName) ?? null,
      status: applied.status,
      notePublic: "Destination transfer cancelled.",
      notes: `Transfer cancelled: ${reason}`,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  });

  await addAuditLog({
    action: "dts_destination_cancelled",
    entityType: "dts_documents",
    entityId: docId,
    dtsDocId: docId,
    actorUid: actor.uid,
    actorRole: actor.role,
    actorOfficeId: actor.officeId ?? null,
    actorOfficeName: actor.officeName ?? null,
    actorName,
    message: `Destination cancelled${resolvedDestinationId ? ` (${resolvedDestinationId})` : ""}.`,
  });

  return {
    success: true,
    destinationId: resolvedDestinationId,
  };
}

export const dtsCreateDestinations = protectedCallableFunctions.https.onCall(
  async (data, context) => dtsCreateDestinationsHandler(data, context)
);

export const dtsDispatchDestinations = protectedCallableFunctions.https.onCall(
  async (data, context) => dtsDispatchDestinationsHandler(data, context)
);

export const dtsConfirmDestinationReceipt = protectedCallableFunctions.https.onCall(
  async (data, context) => dtsConfirmDestinationReceiptHandler(data, context)
);

export const dtsRejectDestination = protectedCallableFunctions.https.onCall(
  async (data, context) => dtsRejectDestinationHandler(data, context)
);

export const dtsCancelDestination = protectedCallableFunctions.https.onCall(
  async (data, context) => dtsCancelDestinationHandler(data, context)
);

export const dtsInitiateTransfer = protectedCallableFunctions.https.onCall(
  async (data, context) => {
    const docId = coerceString(data?.docId);
    const toOfficeId = coerceString(data?.toOfficeId);
    if (!docId || !toOfficeId) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "docId and toOfficeId are required."
      );
    }
    const toOfficeName = coerceString(data?.toOfficeName);
    const toUid = coerceString(data?.toUid);

    await dtsCreateDestinationsHandler(
      {
        docId,
        destinations: [
          {
            toOfficeId,
            toOfficeName,
            toUid,
          },
        ],
      },
      context
    );
    await dtsDispatchDestinationsHandler(
      {
        docId,
        destinationIds: [],
      },
      context
    );

    return {success: true};
  }
);

export const dtsCancelTransfer = protectedCallableFunctions.https.onCall(
  async (data, context) => {
    const actor = await requireStaffContext(context);
    await requireFeatureWritable("documentTracking");
    const docId = coerceString(data?.docId);
    const destinationId = coerceString(data?.destinationId);
    const reason = coerceString(data?.reason);
    if (!docId || !reason) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "docId and reason are required."
      );
    }
    if (destinationId) {
      return dtsCancelDestinationHandler(
        {docId, destinationId, reason},
        context
      );
    }
    const destinationProbe = await db
      .collection("dts_documents")
      .doc(docId)
      .collection("destinations")
      .limit(1)
      .get();
    if (!destinationProbe.empty) {
      return dtsCancelDestinationHandler(
        {docId, reason},
        context
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
        type: "TRANSFER_CANCELLED",
        actionType: "TRANSFER_CANCELLED",
        action: "TRANSFER_CANCELLED",
        byUid: actor.uid,
        byName: actorName,
        byOfficeId: actor.officeId ?? fromOfficeId,
        byOfficeName: actor.officeName ?? coerceString(row.currentOfficeName) ?? null,
        fromOfficeId: coerceString(pending.fromOfficeId),
        toOfficeId: coerceString(pending.toOfficeId),
        reason,
        fromStatus: "IN_TRANSIT",
        toStatus: previousStatus,
        officeId: fromOfficeId,
        officeName: coerceString(row.currentOfficeName) ?? actor.officeName ?? null,
        status: previousStatus,
        notePublic: "Transfer cancelled. Document returned to the source office.",
        notes: `Transfer cancelled while in transit: ${reason}`,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    });

    return {success: true};
  }
);

export const dtsRejectTransfer = protectedCallableFunctions.https.onCall(
  async (data, context) => {
    const actor = await requireStaffContext(context);
    await requireFeatureWritable("documentTracking");
    const docId = coerceString(data?.docId);
    const destinationId = coerceString(data?.destinationId);
    const reason = coerceString(data?.reason);
    const attachments = sanitizeDtsAttachments(data?.attachments);

    if (!docId || !reason) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "docId and reason are required."
      );
    }
    if (destinationId) {
      return dtsRejectDestinationHandler(
        {docId, destinationId, reason},
        context
      );
    }
    const destinationProbe = await db
      .collection("dts_documents")
      .doc(docId)
      .collection("destinations")
      .limit(1)
      .get();
    if (!destinationProbe.empty) {
      return dtsRejectDestinationHandler(
        {docId, reason},
        context
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
        type: "TRANSFER_REJECTED",
        actionType: "TRANSFER_REJECTED",
        action: "TRANSFER_REJECTED",
        byUid: actor.uid,
        byName: actorName,
        byOfficeId: actor.officeId ?? coerceString(pending.toOfficeId) ?? null,
        byOfficeName: actor.officeName ?? coerceString(pending.toOfficeName) ?? null,
        fromOfficeId: coerceString(pending.toOfficeId),
        toOfficeId: coerceString(pending.fromOfficeId),
        reason,
        fromStatus: "IN_TRANSIT",
        toStatus: previousStatus,
        officeId: fromOfficeId,
        officeName: coerceString(row.currentOfficeName) ?? actor.officeName ?? null,
        status: previousStatus,
        notePublic: "Receiving office rejected the transfer. Document returned to the source office.",
        notes: `Transfer rejected: ${reason}`,
        attachments,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    });

    return {success: true};
  }
);

export const dtsConfirmReceipt = protectedCallableFunctions.https.onCall(
  async (data, context) => {
    const actor = await requireStaffContext(context);
    await requireFeatureWritable("documentTracking");
    const docId = coerceString(data?.docId);
    const destinationId = coerceString(data?.destinationId);
    const verificationValue = normalizeDtsVerificationValue(data?.verificationValue);
    const verificationMethod = normalizeDtsVerificationMethod(data?.verificationMethod);
    const confirmPhysicalReceipt = coerceBool(data?.confirmPhysicalReceipt, false);
    if (!docId) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "docId is required."
      );
    }
    if (!confirmPhysicalReceipt) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "Physical receipt confirmation is required."
      );
    }
    if (!verificationValue) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "Invalid tracking number or QR code."
      );
    }
    if (destinationId) {
      return dtsConfirmDestinationReceiptHandler(
        {
          docId,
          destinationId,
          verificationValue,
          verificationMethod,
          confirmPhysicalReceipt,
        },
        context
      );
    }
    const destinationProbe = await db
      .collection("dts_documents")
      .doc(docId)
      .collection("destinations")
      .limit(1)
      .get();
    if (!destinationProbe.empty) {
      return dtsConfirmDestinationReceiptHandler(
        {
          docId,
          verificationValue,
          verificationMethod,
          confirmPhysicalReceipt,
        },
        context
      );
    }

    const receiptAttemptScope = `TRANSFER_${docId}`;
    await assertReceiptVerificationNotLocked(receiptAttemptScope, actor.uid, context);
    const docRef = db.collection("dts_documents").doc(docId);
    const actorName = actorDisplayName(actor);

    try {
      await db.runTransaction(async (tx) => {
        const snap = await tx.get(docRef);
        if (!snap.exists) {
          throw new functions.https.HttpsError("not-found", "Document not found.");
        }

        const row = snap.data() ?? {};
        const currentStatus = normalizeDtsStatus(row.status, "RECEIVED");
        if (currentStatus === "WITH_OFFICE") {
          throw new functions.https.HttpsError(
            "failed-precondition",
            "Document already received."
          );
        }
        if (currentStatus !== "IN_TRANSIT") {
          throw new functions.https.HttpsError(
            "failed-precondition",
            "Document not in transit."
          );
        }

        const pending = dtsPendingTransfer(row);
        if (!pending) {
          throw new functions.https.HttpsError(
            "failed-precondition",
            "Document not in transit."
          );
        }

        if (actor.role !== "super_admin" && !isIntendedDtsReceiver(actor, pending)) {
          throw new functions.https.HttpsError(
            "permission-denied",
            "You are not authorized to receive this document."
          );
        }

        const trackingNo = coerceString(row.trackingNo) ?? "";
        const qrCode = coerceString(row.qrCode);
        const expectedQrSuffix = dtsQrSuffix(qrCode);
        if (expectedQrSuffix) {
          if (verificationValue !== expectedQrSuffix) {
            throw new functions.https.HttpsError(
              "invalid-argument",
              `Invalid QR suffix. Enter the last ${DTS_RECEIPT_QR_SUFFIX_LENGTH} characters of the printed QR code.`
            );
          }
        } else if (!matchesDtsTrackingOrQr(verificationValue, trackingNo, qrCode)) {
          throw new functions.https.HttpsError(
            "invalid-argument",
            "Invalid tracking number or QR code."
          );
        }

        const toOfficeId = coerceString(pending.toOfficeId);
        if (!toOfficeId) {
          throw new functions.https.HttpsError(
            "failed-precondition",
            "Document not in transit."
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
          type: "DOCUMENT_RECEIVED",
          actionType: "DOCUMENT_RECEIVED",
          action: "DOCUMENT_RECEIVED",
          method: verificationMethod,
          verificationMethod,
          byUid: actor.uid,
          byName: actorName,
          byOfficeId: actor.officeId ?? toOfficeId,
          byOfficeName: actor.officeName ?? toOfficeName,
          toOfficeId,
          toOfficeName,
          officeId: toOfficeId,
          officeName: toOfficeName,
          fromStatus: "IN_TRANSIT",
          toStatus: "WITH_OFFICE",
          status: "WITH_OFFICE",
          notePublic: `Document received by ${toOfficeName}.`,
          notes: `Receipt confirmed by ${actorName} (${verificationMethod}).`,
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });
      });
    } catch (error) {
      const code = (error as {code?: string})?.code ?? "";
      const message = (error as {message?: string})?.message ?? "";
      const shouldCountFailure =
        code === "invalid-argument" &&
        /tracking number|qr code/i.test(message);
      if (shouldCountFailure) {
        const locked = await registerReceiptVerificationFailure(
          receiptAttemptScope,
          actor.uid,
          context
        );
        if (locked) {
          throw new functions.https.HttpsError(
            "resource-exhausted",
            "Too many invalid verification attempts. Please wait before trying again."
          );
        }
        throw new functions.https.HttpsError(
          "invalid-argument",
          "Invalid tracking number or QR code."
        );
      }
      throw error;
    }

    await clearReceiptVerificationAttempts(receiptAttemptScope, actor.uid, context);

    return {success: true};
  }
);

export const dtsUpdateStatus = protectedCallableFunctions.https.onCall(
  async (data, context) => {
    const actor = await requireStaffContext(context);
    await requireFeatureWritable("documentTracking");
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
    const reason = coerceString(data?.reason);
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
      if (
        status === "VOIDED" &&
        currentStatus !== "DRAFT" &&
        currentStatus !== "CREATED" &&
        actor.role !== "super_admin" &&
        actor.role !== "admin"
      ) {
        throw new functions.https.HttpsError(
          "permission-denied",
          "Voiding after routing/processing requires admin authorization."
        );
      }
      if (status === "VOIDED") {
        if (!reason) {
          throw new functions.https.HttpsError(
            "invalid-argument",
            "Void reason is required."
          );
        }
        if (reason.length < 6) {
          throw new functions.https.HttpsError(
            "invalid-argument",
            "Void reason must be at least 6 characters."
          );
        }
      }
      if (reason && reason.length > 500) {
        throw new functions.https.HttpsError(
          "invalid-argument",
          "reason must be 500 characters or fewer."
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
      const eventType = status === "VOIDED" ? "DOCUMENT_VOIDED" : "STATUS_CHANGED";
      const resolvedOfficeId = coerceString(row.currentOfficeId) ?? actor.officeId ?? null;
      const resolvedOfficeName = coerceString(row.currentOfficeName) ?? actor.officeName ?? null;
      tx.set(timelineRef, {
        type: eventType,
        actionType: eventType,
        action: eventType,
        byUid: actor.uid,
        byName: actorName,
        byOfficeId: actor.officeId ?? resolvedOfficeId,
        byOfficeName: actor.officeName ?? resolvedOfficeName,
        officeId: resolvedOfficeId,
        officeName: resolvedOfficeName,
        reason: reason ?? null,
        fromStatus: currentStatus,
        toStatus: status,
        status,
        notePublic: `Status updated to ${prettyDtsStatus(status)}.`,
        notes: reason
          ? `Status updated to ${prettyDtsStatus(status)} by ${actorName}. Reason: ${reason}`
          : `Status updated to ${prettyDtsStatus(status)} by ${actorName}.`,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    });

    return {success: true, status};
  }
);

export const dtsAddNote = protectedCallableFunctions.https.onCall(
  async (data, context) => {
    const actor = await requireStaffContext(context);
    await requireFeatureWritable("documentTracking");
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
      const resolvedOfficeId = coerceString(row.currentOfficeId) ?? actor.officeId ?? null;
      const resolvedOfficeName = coerceString(row.currentOfficeName) ?? actor.officeName ?? null;
      tx.set(timelineRef, {
        type: "NOTE",
        actionType: "NOTE_ADDED",
        action: "NOTE_ADDED",
        byUid: actor.uid,
        byName: actorName,
        byOfficeId: actor.officeId ?? resolvedOfficeId,
        byOfficeName: actor.officeName ?? resolvedOfficeName,
        officeId: resolvedOfficeId,
        officeName: resolvedOfficeName,
        status: normalizeDtsStatus(row.status, "RECEIVED"),
        notes,
        attachments,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    });

    return {success: true};
  }
);

export const dtsSetCoverPhoto = protectedCallableFunctions.https.onCall(
  async (data, context) => {
    const actor = await requireStaffContext(context);
    await requireFeatureWritable("documentTracking");
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
        type: "FILE_ATTACHED",
        actionType: "FILE_ATTACHED",
        action: "FILE_ATTACHED",
        byUid: actor.uid,
        byName: actorName,
        byOfficeId: actor.officeId ?? coerceString(row.currentOfficeId) ?? null,
        byOfficeName: actor.officeName ?? coerceString(row.currentOfficeName) ?? null,
        officeId: coerceString(row.currentOfficeId) ?? actor.officeId ?? null,
        officeName: coerceString(row.currentOfficeName) ?? actor.officeName ?? null,
        status: normalizeDtsStatus(row.status, "RECEIVED"),
        notePublic: "Cover photo uploaded.",
        notes: "Cover photo uploaded.",
        attachments: [coverPhoto],
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    });

    return {success: true};
  }
);

export const dtsAuditAttachmentAccess = protectedCallableFunctions.https.onCall(
  async (data, context) => {
    const actor = await requireStaffContext(context);
    await requireFeatureWritable("documentTracking");
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
 * DTS TRACKING PIN RESET
 * =========================
 * Server-side reset so PIN is never stored in plaintext and audit is guaranteed.
 */
async function setTrackingPinHandler(
  data: unknown,
  context: CallableContextLike
) {
  const payload = (data && typeof data === "object")
    ? (data as Record<string, unknown>)
    : {};
  const actor = await requireStaffContext(context);
  await requireFeatureWritable("documentTracking");
  if (!(actor.role === "super_admin" || actor.role === "admin")) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Only admin and super admin can reset tracking PIN."
    );
  }

  const trackingId = coerceString(payload.trackingId) ?? coerceString(payload.docId);
  const newPin = coerceString(payload.newPin);
  if (!trackingId || !newPin) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "trackingId and newPin are required."
    );
  }
  if (newPin.length < 4) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "PIN must be at least 4 characters."
    );
  }

  const docRef = db.collection("dts_documents").doc(trackingId);
  const docSnap = await docRef.get();
  if (!docSnap.exists) {
    throw new functions.https.HttpsError("not-found", "Document not found.");
  }
  const row = docSnap.data() ?? {};
  if (actor.role !== "super_admin" && !canOperateOnDtsDoc(actor, row)) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "You cannot reset PIN for this document."
    );
  }

  const pinHash = await hashTrackingPin(newPin);
  await docRef.set(
    {
      pinHash,
      publicPinHash: pinHash,
      pinHashAlgo: "bcrypt",
      publicPinSalt: admin.firestore.FieldValue.delete(),
      pinUpdatedAt: admin.firestore.FieldValue.serverTimestamp(),
      pinUpdatedByUid: actor.uid,
      pinUpdatedByName: actorDisplayName(actor),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    },
    {merge: true}
  );

  await addAuditLog({
    action: "tracking_pin_reset",
    entityType: "dts_documents",
    entityId: trackingId,
    dtsDocId: trackingId,
    actorUid: actor.uid,
    actorRole: actor.role,
    actorOfficeId: actor.officeId ?? null,
    actorOfficeName: actor.officeName ?? null,
    actorName: actorDisplayName(actor),
    message: "Tracking PIN reset.",
  });

  return {success: true};
}

export const setTrackingPin = onCallV2(protectedCallableV2Options, async (request) => {
  try {
    return await setTrackingPinHandler(request.data, toCallableContextFromV2(request));
  } catch (error) {
    throw normalizeCallableErrorForV2(error);
  }
});

/**
 * =========================
 * DTS TRACKING LOOKUP
 * =========================
 * Lookup by trackingNo + PIN and return a sanitized payload.
 */
async function lookupDtsByTrackingNo(
  trackingNo: string,
  pin: string,
  context: TrackingLookupContext
): Promise<Record<string, unknown>> {
  await requireFeatureEnabled("documentTracking");
  const snap = await db
    .collection("dts_documents")
    .where("trackingNo", "==", trackingNo)
    .limit(1)
    .get();

  if (snap.empty) {
    throw invalidTrackingCredentialsError();
  }

  const doc = snap.docs[0];
  const dataRow = doc.data() ?? {};
  await verifyPinWithRateLimit(trackingNo, pin, dataRow, context);
  const session = await issueTrackingSession(doc.id, trackingNo, context);
  const sanitized = buildSanitizedTrackingResult(trackingNo, dataRow);
  const timeline = await loadPublicTrackingTimeline(doc.ref);
  return {
    ...sanitized,
    timeline,
    sessionToken: session.token,
    sessionExpiresAt: session.expiresAtMs,
  };
}

export const dtsTrackByTrackingNo = regionalFunctions.https.onCall(
  async (data, context) => {
    const {trackingNo, pin} = validateTrackingLookupInput(
      (data as Record<string, unknown> | undefined)?.trackingNo ??
      (data as Record<string, unknown> | undefined)?.trackingNumber,
      (data as Record<string, unknown> | undefined)?.pin
    );
    return lookupDtsByTrackingNo(trackingNo, pin, context);
  }
);

async function handleTrackLookupHttpRequest(
  req: functions.https.Request,
  res: functions.Response<unknown>
) {
  const corsAllowed = applyTrackLookupCors(req, res);
  if (!corsAllowed) {
    functions.logger.warn("trackLookup blocked by CORS policy.", {
      code: "cors-blocked",
      origin: String(req.headers.origin ?? ""),
      ipHash: contextIpHash({rawRequest: req}),
      region: REGION,
    });
    res.status(403).json({error: "Origin not allowed.", code: "permission-denied"});
    return;
  }

  if (req.method === "OPTIONS") {
    res.status(204).send("");
    return;
  }
  if (req.method !== "POST") {
    res.status(405).json({ error: "Method not allowed." });
    return;
  }

  try {
    await requireFeatureEnabled("documentTracking");
    const {trackingNo, pin} = validateTrackingLookupInput(
      req.body?.trackingNumber ?? req.body?.trackingNo,
      req.body?.pin
    );
    const payload = await lookupDtsByTrackingNo(trackingNo, pin, {
      auth: null,
      rawRequest: req,
    });
    res.status(200).json(payload);
  } catch (error) {
    const httpsError = error as functions.https.HttpsError;
    const code = String(httpsError?.code ?? "internal");
    const message = String(httpsError?.message ?? "Tracking lookup failed.");
    const statusCode =
      code === "invalid-argument" ? 400 :
      code === "not-found" ? 404 :
      code === "resource-exhausted" ? 429 :
      code === "permission-denied" ? 403 : 500;
    functions.logger.warn("trackLookup request failed.", {
      code,
      statusCode,
      ipHash: contextIpHash({rawRequest: req}),
      region: REGION,
    });
    res.status(statusCode).json({ error: message, code });
  }
}

export const trackLookup = onRequestV2({region: REGION}, handleTrackLookupHttpRequest);

/**
 * =========================
 * DTS TRACKING LOOKUP (QR + PIN)
 * =========================
 * Allows public tracking using the QR sticker value, still requiring PIN.
 */
export const dtsTrackByQrAndPin = functions.https.onCall(
  async (data, context) => {
    await requireFeatureEnabled("documentTracking");
    const qrCode = coerceString(data?.qrCode);
    const pin = normalizeTrackingPin(data?.pin);
    if (!qrCode || !pin) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "qrCode and pin are required."
      );
    }
    if (!TRACKING_PIN_REGEX.test(pin)) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "Invalid PIN format."
      );
    }

    const qrSnap = await db.collection("dts_qr_index").doc(qrCode).get();
    if (!qrSnap.exists) {
      throw invalidTrackingCredentialsError();
    }
    const docId = coerceString(qrSnap.data()?.docId);
    if (!docId) {
      throw invalidTrackingCredentialsError();
    }

    const docSnap = await db.collection("dts_documents").doc(docId).get();
    if (!docSnap.exists) {
      throw invalidTrackingCredentialsError();
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
    const timeline = await loadPublicTrackingTimeline(docSnap.ref);
    return {
      ...sanitized,
      timeline,
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
    await requireFeatureEnabled("documentTracking");
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
    const timeline = await loadPublicTrackingTimeline(docSnap.ref);
    return {
      ...sanitized,
      timeline,
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
    await requireFeatureWritable("documentTracking");
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
    const createdByUid = coerceString(dataRow.createdByUid);
    let allowResidentRelink = false;
    if (existingOwner && existingOwner !== context.auth.uid) {
      if (dataRow.saveToResidentAccount !== true && createdByUid && existingOwner === createdByUid) {
        const ownerProfile = await getUserProfile(existingOwner);
        allowResidentRelink = isStaffRole(ownerProfile.role);
      }
      if (!allowResidentRelink) {
        throw new functions.https.HttpsError(
          "failed-precondition",
          "This document is already linked to another account."
        );
      }
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
 * DTS LIST MY DOCUMENTS
 * =========================
 * Returns resident-safe summaries for account-linked DTS records.
 */
export const dtsListMyDocuments = functions.https.onCall(
  async (_data, context) => {
    await requireFeatureEnabled("documentTracking");
    if (!context.auth) {
      throw new functions.https.HttpsError("unauthenticated", "Auth required.");
    }

    const snap = await db
      .collection("dts_documents")
      .where("submittedByUid", "==", context.auth.uid)
      .limit(100)
      .get();

    const normalizedDocuments = snap.docs
      .map((doc) => {
        const row = doc.data() ?? {};
        if (row.saveToResidentAccount != true) {
          return null;
        }
        return {
          sortTs: dtsSavedDocumentSortTimestamp(row),
          payload: buildSanitizedSavedDocumentSummary(doc.id, row),
        };
      })
      .filter((item): item is {sortTs: number; payload: Record<string, unknown>} => item != null);

    normalizedDocuments.sort((left, right) => right.sortTs - left.sortTs);

    return {
      documents: normalizedDocuments.map((item) => item.payload),
    };
  }
);

/**
 * =========================
 * DTS OPEN SAVED DOC
 * =========================
 * Reopens a resident-linked DTS record without re-entering the PIN.
 */
export const dtsOpenSavedDocument = functions.https.onCall(
  async (data, context) => {
    await requireFeatureEnabled("documentTracking");
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
    if (row.saveToResidentAccount !== true || ownerUid !== context.auth.uid) {
      throw new functions.https.HttpsError(
        "permission-denied",
        "This saved document is not linked to your account."
      );
    }

    const trackingNo = coerceString(row.trackingNo) ?? docId;
    const sanitized = buildSanitizedTrackingResult(trackingNo, row);
    const timeline = await loadPublicTrackingTimeline(docRef);
    return {
      ...sanitized,
      timeline,
      savedDocId: docId,
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
    await requireFeatureWritable("documentTracking");
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
 * DTS QR BATCH LIST
 * =========================
 * Lists recent QR sticker batches for Super Admin management.
 */
type DtsQrBatchReconcileSummary = {
  batchId: string;
  totalCount: number;
  unusedCount: number;
  usedCount: number;
  voidedCount: number;
  patchedQrCodes: number;
  patchedIndexRows: number;
  deletedIndexRows: number;
};

function normalizeDtsQrCodeStatus(value: unknown): string {
  return (coerceString(value) ?? "").trim().toLowerCase();
}

function resolveDtsQrReservationExpiryMs(row: Record<string, unknown>): number {
  const explicitExpiryMs = parseEpochMs(row.reservationExpiresAt);
  if (explicitExpiryMs > 0) {
    return explicitExpiryMs;
  }
  const reservedAtMs = parseEpochMs(row.reservedAt);
  if (reservedAtMs > 0) {
    return reservedAtMs + (DTS_QR_RESERVATION_TTL_MINUTES * 60 * 1000);
  }
  // Missing metadata is treated as stale so old reserved rows are auto-released.
  return 0;
}

function isDtsQrReservationExpired(
  row: Record<string, unknown>,
  nowMs = Date.now()
): boolean {
  const expiresAtMs = resolveDtsQrReservationExpiryMs(row);
  return expiresAtMs <= 0 || expiresAtMs <= nowMs;
}

function buildDtsQrReservationReleasePatch(
  row: Record<string, unknown>
): Record<string, unknown> {
  const linkedDocId = coerceString(row.docId);
  const patch: Record<string, unknown> = {
    status: linkedDocId ? "used" : "unused",
    reservedAt: admin.firestore.FieldValue.delete(),
    reservedByUid: admin.firestore.FieldValue.delete(),
    reservationExpiresAt: admin.firestore.FieldValue.delete(),
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
  };
  if (linkedDocId) {
    if (!row.usedAt) {
      patch.usedAt = admin.firestore.FieldValue.serverTimestamp();
    }
  } else {
    patch.docId = admin.firestore.FieldValue.delete();
    patch.usedAt = admin.firestore.FieldValue.delete();
    patch.usedByUid = admin.firestore.FieldValue.delete();
  }
  return patch;
}

type DtsQrReservationResult = {
  status: "reserved" | "used";
  batchId: string | null;
  imagePath: string | null;
  reservationExpiresAt: string | null;
};

async function reserveDtsQrForIntake(
  qrCode: string,
  actorUid: string
): Promise<DtsQrReservationResult> {
  const qrRef = db.collection("dts_qr_codes").doc(qrCode);
  const nowMs = Date.now();
  const reservationExpiresAtTs = admin.firestore.Timestamp.fromMillis(
    nowMs + (DTS_QR_RESERVATION_TTL_MINUTES * 60 * 1000)
  );

  return db.runTransaction(async (tx) => {
    const qrSnap = await tx.get(qrRef);
    if (!qrSnap.exists) {
      throw new functions.https.HttpsError("not-found", "QR code not found.");
    }
    const row = (qrSnap.data() ?? {}) as Record<string, unknown>;
    const status = normalizeDtsQrCodeStatus(row.status) || "unused";
    const batchId = coerceString(row.batchId);
    const imagePath = coerceString(row.imagePath);

    if (status === "voided") {
      throw new functions.https.HttpsError(
        "failed-precondition",
        "This QR code has been voided."
      );
    }
    if (status === "used") {
      return {
        status: "used",
        batchId,
        imagePath,
        reservationExpiresAt: null,
      };
    }

    if (status === "reserved") {
      const reservedByUid = coerceString(row.reservedByUid);
      if (!isDtsQrReservationExpired(row, nowMs) &&
          reservedByUid &&
          reservedByUid !== actorUid) {
        throw new functions.https.HttpsError(
          "failed-precondition",
          "This QR code is currently reserved."
        );
      }
    }

    tx.set(
      qrRef,
      {
        status: "reserved",
        reservedAt: admin.firestore.FieldValue.serverTimestamp(),
        reservedByUid: actorUid,
        reservationExpiresAt: reservationExpiresAtTs,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        docId: admin.firestore.FieldValue.delete(),
        usedAt: admin.firestore.FieldValue.delete(),
        usedByUid: admin.firestore.FieldValue.delete(),
      },
      {merge: true}
    );

    return {
      status: "reserved",
      batchId,
      imagePath,
      reservationExpiresAt: reservationExpiresAtTs.toDate().toISOString(),
    };
  });
}

type DtsQrLinkEvidence = {
  docId: string | null;
  trackingNo: string | null;
  hasIndexRow: boolean;
};

async function loadDtsQrLinkEvidence(
  qrCodes: string[]
): Promise<Map<string, DtsQrLinkEvidence>> {
  const evidence = new Map<string, DtsQrLinkEvidence>();
  if (qrCodes.length === 0) {
    return evidence;
  }

  const indexSnapshots = await Promise.all(
    qrCodes.map((qrCode) => db.collection("dts_qr_index").doc(qrCode).get())
  );
  for (let i = 0; i < qrCodes.length; i += 1) {
    const qrCode = qrCodes[i];
    const snap = indexSnapshots[i];
    const row = snap.data() ?? {};
    evidence.set(qrCode, {
      docId: coerceString(row.docId),
      trackingNo: coerceString(row.trackingNo),
      hasIndexRow: snap.exists,
    });
  }

  for (const codeChunk of chunk(qrCodes, 30)) {
    if (codeChunk.length === 0) continue;
    const docsByQr = await db
      .collection("dts_documents")
      .where("qrCode", "in", codeChunk)
      .get();
    docsByQr.forEach((docSnap) => {
      const row = docSnap.data() ?? {};
      const qrCode = coerceString(row.qrCode);
      if (!qrCode) return;
      const current = evidence.get(qrCode) ?? {
        docId: null,
        trackingNo: null,
        hasIndexRow: false,
      };
      evidence.set(qrCode, {
        docId: current.docId ?? docSnap.id,
        trackingNo: current.trackingNo ?? coerceString(row.trackingNo),
        hasIndexRow: current.hasIndexRow,
      });
    });
  }

  return evidence;
}

async function commitDtsQrReconcileWrites(
  setWrites: Array<{
    ref: FirebaseFirestore.DocumentReference<FirebaseFirestore.DocumentData>;
    data: Record<string, unknown>;
    merge?: boolean;
  }>,
  deleteWrites: Array<
    FirebaseFirestore.DocumentReference<FirebaseFirestore.DocumentData>
  >
): Promise<void> {
  if (setWrites.length === 0 && deleteWrites.length === 0) {
    return;
  }
  let setCursor = 0;
  let deleteCursor = 0;
  while (setCursor < setWrites.length || deleteCursor < deleteWrites.length) {
    const batch = db.batch();
    let opCount = 0;
    while (opCount < 400 && setCursor < setWrites.length) {
      const write = setWrites[setCursor];
      if (write.merge) {
        batch.set(write.ref, write.data, {merge: true});
      } else {
        batch.set(write.ref, write.data);
      }
      setCursor += 1;
      opCount += 1;
    }
    while (opCount < 400 && deleteCursor < deleteWrites.length) {
      batch.delete(deleteWrites[deleteCursor]);
      deleteCursor += 1;
      opCount += 1;
    }
    await batch.commit();
  }
}

async function reconcileDtsQrBatch(
  batchId: string,
  options?: {
    repairQrRows?: boolean;
    syncBatchCounters?: boolean;
  }
): Promise<DtsQrBatchReconcileSummary> {
  const repairQrRows = coerceBool(options?.repairQrRows, false);
  const syncBatchCounters = coerceBool(options?.syncBatchCounters, true);
  const codesSnapshot = await db
    .collection("dts_qr_codes")
    .where("batchId", "==", batchId)
    .get();
  const codeIds = codesSnapshot.docs.map((doc) => doc.id);
  const evidenceByCode = await loadDtsQrLinkEvidence(codeIds);

  let totalCount = 0;
  let usedCount = 0;
  let unusedCount = 0;
  let voidedCount = 0;
  let patchedQrCodes = 0;
  let patchedIndexRows = 0;
  let deletedIndexRows = 0;

  const setWrites: Array<{
    ref: FirebaseFirestore.DocumentReference<FirebaseFirestore.DocumentData>;
    data: Record<string, unknown>;
    merge?: boolean;
  }> = [];
  const deleteWrites: Array<
    FirebaseFirestore.DocumentReference<FirebaseFirestore.DocumentData>
  > = [];

  for (const codeDoc of codesSnapshot.docs) {
    totalCount += 1;
    const qrCode = codeDoc.id;
    const row = codeDoc.data() ?? {};
    const status = normalizeDtsQrCodeStatus(row.status);
    const existingDocId = coerceString(row.docId);
    const existingUsedAt = Boolean(row.usedAt);
    const evidence = evidenceByCode.get(qrCode) ?? {
      docId: null,
      trackingNo: null,
      hasIndexRow: false,
    };
    const linkedDocId = existingDocId ?? evidence.docId;
    const linkedTrackingNo = evidence.trackingNo;
    const targetStatus = status === "voided" && !linkedDocId ?
      "voided" :
      (linkedDocId ? "used" : "unused");

    if (targetStatus === "voided") {
      voidedCount += 1;
    } else if (targetStatus === "used") {
      usedCount += 1;
    } else {
      unusedCount += 1;
    }

    if (repairQrRows) {
      const qrPatch: Record<string, unknown> = {};
      if (status !== targetStatus) {
        qrPatch.status = targetStatus;
      }
      if (targetStatus === "used") {
        if (linkedDocId && existingDocId !== linkedDocId) {
          qrPatch.docId = linkedDocId;
        }
        if (!existingUsedAt) {
          qrPatch.usedAt = admin.firestore.FieldValue.serverTimestamp();
        }
      } else {
        if (existingDocId) {
          qrPatch.docId = admin.firestore.FieldValue.delete();
        }
        if (existingUsedAt) {
          qrPatch.usedAt = admin.firestore.FieldValue.delete();
        }
      }
      if (Object.keys(qrPatch).length > 0) {
        qrPatch.updatedAt = admin.firestore.FieldValue.serverTimestamp();
        setWrites.push({
          ref: codeDoc.ref,
          data: qrPatch,
          merge: true,
        });
        patchedQrCodes += 1;
      }

      const indexRef = db.collection("dts_qr_index").doc(qrCode);
      if (targetStatus === "used" && linkedDocId) {
        if (
          !evidence.hasIndexRow ||
          evidence.docId !== linkedDocId ||
          coerceString(evidence.trackingNo) !== coerceString(linkedTrackingNo)
        ) {
          setWrites.push({
            ref: indexRef,
            data: {
              docId: linkedDocId,
              trackingNo: linkedTrackingNo ?? null,
              updatedAt: admin.firestore.FieldValue.serverTimestamp(),
              ...(evidence.hasIndexRow ?
                {} :
                {createdAt: admin.firestore.FieldValue.serverTimestamp()}),
            },
            merge: true,
          });
          patchedIndexRows += 1;
        }
      } else if (evidence.hasIndexRow) {
        deleteWrites.push(indexRef);
        deletedIndexRows += 1;
      }
    }
  }

  if (syncBatchCounters) {
    setWrites.push({
      ref: db.collection("dts_qr_batches").doc(batchId),
      data: {
        totalCount,
        unusedCount,
        usedCount,
        voidedCount,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      merge: true,
    });
  }

  if (repairQrRows) {
    await commitDtsQrReconcileWrites(setWrites, deleteWrites);
  } else if (syncBatchCounters) {
    await db.collection("dts_qr_batches").doc(batchId).set({
      totalCount,
      unusedCount,
      usedCount,
      voidedCount,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    }, {merge: true});
  }

  return {
    batchId,
    totalCount,
    unusedCount,
    usedCount,
    voidedCount,
    patchedQrCodes,
    patchedIndexRows,
    deletedIndexRows,
  };
}

export const dtsListQrBatches = protectedCallableFunctions.https.onCall(
  async (data, context) => {
    await requireFeatureWritable("documentTracking");
    await requireSuperAdminContext(context);

    const limitRaw = typeof data?.limit === "number" ? data.limit : 24;
    const limit = Math.max(1, Math.min(100, Math.floor(limitRaw)));
    const repair = coerceBool(data?.repair, true);
    const snapshot = await db
      .collection("dts_qr_batches")
      .orderBy("createdAt", "desc")
      .limit(limit)
      .get();

    const items = await Promise.all(
      snapshot.docs.map(async (doc) => {
        const row = doc.data() ?? {};
        const existingTotal = Number.isFinite(Number(row.totalCount)) ? Number(row.totalCount) : 0;
        const existingUnused = Number.isFinite(Number(row.unusedCount)) ? Number(row.unusedCount) : 0;
        const existingUsed = Number.isFinite(Number(row.usedCount)) ? Number(row.usedCount) : 0;
        const existingVoided = Number.isFinite(Number(row.voidedCount)) ? Number(row.voidedCount) : 0;
        let summary: DtsQrBatchReconcileSummary = {
          batchId: doc.id,
          totalCount: existingTotal,
          unusedCount: existingUnused,
          usedCount: existingUsed,
          voidedCount: existingVoided,
          patchedQrCodes: 0,
          patchedIndexRows: 0,
          deletedIndexRows: 0,
        };
        try {
          summary = await reconcileDtsQrBatch(doc.id, {
            repairQrRows: repair,
            syncBatchCounters: true,
          });
        } catch (error) {
          console.warn("dtsListQrBatches: count reconciliation failed", {
            batchId: doc.id,
            error,
          });
        }
        return {
          id: doc.id,
          ...row,
          totalCount: summary.totalCount,
          unusedCount: summary.unusedCount,
          usedCount: summary.usedCount,
          voidedCount: summary.voidedCount,
        };
      })
    );

    return {items};
  }
);

/**
 * =========================
 * DTS QR INVENTORY RECONCILE
 * =========================
 * Repairs QR status/index drift and refreshes batch counters.
 */
export const dtsReconcileQrBatches = protectedCallableFunctions.https.onCall(
  async (data, context) => {
    await requireFeatureWritable("documentTracking");
    await requireSuperAdminContext(context);

    const batchId = coerceString(data?.batchId);
    const apply = coerceBool(data?.apply, true);
    const limitRaw = typeof data?.limit === "number" ? data.limit : 24;
    const limit = Math.max(1, Math.min(100, Math.floor(limitRaw)));

    let batchIds: string[] = [];
    if (batchId) {
      batchIds = [batchId];
    } else {
      const snapshot = await db
        .collection("dts_qr_batches")
        .orderBy("createdAt", "desc")
        .limit(limit)
        .get();
      batchIds = snapshot.docs.map((doc) => doc.id);
    }

    const rows: DtsQrBatchReconcileSummary[] = [];
    for (const rowBatchId of batchIds) {
      const summary = await reconcileDtsQrBatch(rowBatchId, {
        repairQrRows: apply,
        syncBatchCounters: true,
      });
      rows.push(summary);
    }

    return {
      success: true,
      apply,
      processed: rows.length,
      patchedQrCodes: rows.reduce((sum, row) => sum + row.patchedQrCodes, 0),
      patchedIndexRows: rows.reduce((sum, row) => sum + row.patchedIndexRows, 0),
      deletedIndexRows: rows.reduce((sum, row) => sum + row.deletedIndexRows, 0),
      items: rows.map((row) => ({
        batchId: row.batchId,
        totalCount: row.totalCount,
        unusedCount: row.unusedCount,
        usedCount: row.usedCount,
        voidedCount: row.voidedCount,
        patchedQrCodes: row.patchedQrCodes,
        patchedIndexRows: row.patchedIndexRows,
        deletedIndexRows: row.deletedIndexRows,
      })),
    };
  }
);

/**
 * =========================
 * DTS QR GENERATION
 * =========================
 * Generates QR codes and stores them in Firestore + Storage.
 */
export const generateDtsQrCodes = protectedCallableFunctions.https.onCall(
  async (data, context) => {
    await requireFeatureWritable("documentTracking");
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
    const profile = await getUserProfile(context.auth.uid);
    const actorName =
      coerceString(profile.data.displayName) ??
      coerceString(profile.data.email) ??
      context.auth.uid;

    const countRaw = typeof data?.count === "number" ? data.count : 50;
    const prefix = coerceString(data?.prefix) ?? "DTS-QR";
    const requestedBatchLabel = coerceString(data?.batchLabel);
    const count = Math.max(1, Math.min(200, Math.floor(countRaw)));
    const batchRef = db.collection("dts_qr_batches").doc();
    const batchId = batchRef.id;
    const batchLabel =
      requestedBatchLabel ??
      `QR Batch ${new Date().toISOString().slice(0, 10)} ${batchId.slice(0, 6).toUpperCase()}`;

    const created: Array<{ code: string; path: string }> = [];
    const seenCodes = new Set<string>();
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
      if (seenCodes.has(code)) {
        continue;
      }
      const ref = db.collection("dts_qr_codes").doc(code);
      const snap = await ref.get();
      if (snap.exists) {
        continue;
      }
      seenCodes.add(code);

      const path = `dts_qr_codes/${code}.png`;
      const png = await createQrPng(code);
      await bucket.file(path).save(png, {
        metadata: {
          contentType: "image/png",
        },
      });

      batch.set(ref, {
        qrCode: code,
        batchId,
        batchLabel,
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
    await batchRef.set({
      batchId,
      batchLabel,
      prefix,
      totalCount: created.length,
      unusedCount: created.length,
      usedCount: 0,
      voidedCount: 0,
      exportCount: 0,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      createdByUid: context.auth.uid,
      status: "active",
    });

    await addAuditLog({
      action: "dts_qr_batch_generated",
      entityType: "dts_qr_batches",
      entityId: batchId,
      actorUid: context.auth.uid,
      actorRole: callerRole,
      actorOfficeId: null,
      actorOfficeName: null,
      actorName,
      message: `Generated ${created.length} DTS QR codes.`,
    });

    return {
      batchId,
      batchLabel,
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
export const exportDtsQrZip = protectedCallableFunctions.https.onCall(
  async (data, context) => {
    await requireFeatureWritable("documentTracking");
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
    const profile = await getUserProfile(context.auth.uid);
    const actorName =
      coerceString(profile.data.displayName) ??
      coerceString(profile.data.email) ??
      context.auth.uid;

    const bucket = admin.storage().bucket();
    let codes: string[] = [];
    const batchId = coerceString(data?.batchId);
    const exportUnusedOnly =
      coerceBool(data?.unusedOnly, true) &&
      coerceBool(data?.includeUsed, false) === false;
    if (Array.isArray(data?.codes)) {
      codes = data.codes
        .map((c: unknown) => (c ? String(c).trim() : ""))
        .filter((c: string) => c.length > 0);
    }

    if (codes.length === 0) {
      if (batchId) {
        const batchSnap = await db
          .collection("dts_qr_codes")
          .where("batchId", "==", batchId)
          .limit(400)
          .get();
        let batchRows = batchSnap.docs;
        if (exportUnusedOnly) {
          const candidateCodeIds = batchRows.map((doc) => doc.id);
          const usedByIndex = new Set<string>();
          const usedByDocuments = new Set<string>();

          if (candidateCodeIds.length > 0) {
            const indexSnapshots = await Promise.all(
              candidateCodeIds.map((qrCode) =>
                db.collection("dts_qr_index").doc(qrCode).get()
              )
            );
            for (let i = 0; i < indexSnapshots.length; i += 1) {
              const snap = indexSnapshots[i];
              const qrCode = candidateCodeIds[i];
              const docId = coerceString(snap.data()?.docId);
              if (snap.exists && docId) {
                usedByIndex.add(qrCode);
              }
            }
            for (let i = 0; i < candidateCodeIds.length; i += 30) {
              const chunk = candidateCodeIds.slice(i, i + 30);
              const docsByQr = await db
                .collection("dts_documents")
                .where("qrCode", "in", chunk)
                .get();
              docsByQr.forEach((docSnap) => {
                const qrCode = coerceString(docSnap.data()?.qrCode);
                if (qrCode) {
                  usedByDocuments.add(qrCode);
                }
              });
            }
          }

          batchRows = batchRows.filter((docSnap) => {
            const codeRow = docSnap.data() ?? {};
            const status = (coerceString(codeRow.status) ?? "")
              .toLowerCase()
              .trim();
            if (status !== "unused") {
              return false;
            }
            if (coerceString(codeRow.docId)) {
              return false;
            }
            if (codeRow.usedAt) {
              return false;
            }
            if (usedByIndex.has(docSnap.id) || usedByDocuments.has(docSnap.id)) {
              return false;
            }
            return true;
          });
        }
        codes = batchRows.map((d) => d.id);
      } else {
        const query = db
          .collection("dts_qr_codes")
          .orderBy("createdAt", "desc");
        const snap = await (exportUnusedOnly ?
          query.where("status", "==", "unused").limit(50).get() :
          query.limit(10).get());
        codes = snap.docs.map((d) => d.id);
      }
    }

    codes = codes.slice(0, batchId ? 200 : 10);
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
    const exportFile = bucket.file(exportPath);
    await exportFile.save(zipBuffer, {
      metadata: { contentType: "application/zip" },
    });

    if (batchId) {
      await db.collection("dts_qr_batches").doc(batchId).set({
        lastExportedAt: admin.firestore.FieldValue.serverTimestamp(),
        lastExportPath: exportPath,
        exportCount: admin.firestore.FieldValue.increment(1),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      }, {merge: true});
    }

    await addAuditLog({
      action: "dts_qr_batch_exported",
      entityType: "dts_qr_batches",
      entityId: batchId ?? exportPath,
      actorUid: context.auth.uid,
      actorRole: callerRole,
      actorOfficeId: null,
      actorOfficeName: null,
      actorName,
      message: `Exported ${exportedCodes.length} DTS QR codes for printing.`,
    });

    let downloadUrl: string | null = null;
    try {
      const result = await exportFile.getSignedUrl({
        action: "read",
        expires: Date.now() + 1000 * 60 * 60,
      });
      downloadUrl = result[0];
    } catch (error) {
      console.warn("exportDtsQrZip: signed URL generation failed", error);
    }

    if (!downloadUrl) {
      try {
        const [metadata] = await exportFile.getMetadata();
        const customMetadata = metadata.metadata ?? {};
        let token = coerceString(customMetadata.firebaseStorageDownloadTokens);
        if (token && token.includes(",")) {
          token = token.split(",")[0].trim();
        }
        if (!token) {
          token = crypto.randomUUID();
          await exportFile.setMetadata({
            metadata: {
              ...customMetadata,
              firebaseStorageDownloadTokens: token,
            },
          });
        }
        downloadUrl = `https://firebasestorage.googleapis.com/v0/b/${bucket.name}/o/` +
          `${encodeURIComponent(exportPath)}?alt=media&token=${token}`;
      } catch (fallbackError) {
        console.warn("exportDtsQrZip: token URL fallback failed", fallbackError);
      }
    }

    return {
      batchId,
      count: exportedCodes.length,
      path: exportPath,
      downloadUrl,
      codes: exportedCodes,
      unusedOnly: exportUnusedOnly,
    };
  }
);

/*
 * Test-only exports for emulator integration tests.
 * These are not deployed callable endpoints; they only expose internal handlers
 * to keep privileged behavior verifiable in CI.
 */
export const __testing = {
  adminListReportsScopedHandler,
  adminReportsBootstrapHandler,
  loadScopedReportsForActor,
  loadScopedReportViewCountsForActor,
  buildScopedReportViewCounts,
  dtsCreateDestinationsHandler,
  dtsDispatchDestinationsHandler,
  dtsConfirmDestinationReceiptHandler,
  dtsRejectDestinationHandler,
  dtsCancelDestinationHandler,
  strictCorsEnabled,
  isAllowedCorsOrigin,
  isAllowedPublicReportCorsOrigin,
};
