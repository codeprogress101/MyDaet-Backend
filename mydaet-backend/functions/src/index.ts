import * as functions from "firebase-functions/v1";
import * as admin from "firebase-admin";

admin.initializeApp();
const db = admin.firestore();

/**
 * Role definitions
 */
type Role = "resident" | "moderator" | "admin" | "super_admin";
const ALLOWED_ROLES: Role[] = ["resident", "moderator", "admin", "super_admin"];

const OPEN_STATUSES = ["submitted", "in_review", "assigned", "in_progress"] as const;

function isOpenStatus(s: string): boolean {
  return (OPEN_STATUSES as readonly string[]).includes(s);
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
  return context.auth.token;
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

  const callerRole = (context.auth.token.role as Role | undefined) ?? "resident";
  if (callerRole !== "super_admin") {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Only super_admin can change roles."
    );
  }

  const uid = data?.uid;
  const role = data?.role as Role;

  if (typeof uid !== "string" || !ALLOWED_ROLES.includes(role)) {
    throw new functions.https.HttpsError("invalid-argument", "Invalid uid or role.");
  }

  await admin.auth().setCustomUserClaims(uid, { role });

  // keep Firestore display role in-sync (critical for dropdowns / UI)
  await db.collection("users").doc(uid).set(
    {
      role,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    },
    { merge: true }
  );

  return { success: true };
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

      const adminSnap = await db
        .collection("users")
        .where("role", "in", ["admin", "super_admin"])
        .get();
      const adminUids = adminSnap.docs.map((d) => d.id);

      await notifyUsers(adminUids, {
        title: "New report submitted",
        body: `${title} • ${category}`,
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
          body: `${title} • ${category}`,
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
        body: `${title} • ${detail}`,
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

    const body = category ? `${title} • ${category}` : title;
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

      await addAuditLog({
        action: "announcement_created",
        announcementId,
        announcementTitle: title,
        announcementCategory: category,
        status,
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

      await addAuditLog({
        action: "announcement_deleted",
        announcementId,
        announcementTitle: title,
        announcementCategory: category,
        status,
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

    if (statusChanged && afterStatus === "published") {
      await addAuditLog({
        action: "announcement_published",
        announcementId,
        announcementTitle: title,
        announcementCategory: category,
        status: afterStatus,
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
