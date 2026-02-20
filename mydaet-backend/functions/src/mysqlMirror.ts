import * as admin from "firebase-admin";
import mysql from "mysql2/promise";

type MirrorDocTarget = "posts" | "public_docs" | "jobs" | "doc_tracking";
type JobKind = "doc" | "timeline";

type SyncQueueJob = {
  kind: JobKind;
  target?: MirrorDocTarget;
  id?: string;
  trackingId?: string;
  entryId?: string;
  before?: Record<string, unknown> | null;
  after?: Record<string, unknown> | null;
};

let pool: mysql.Pool | null = null;

function env(name: string): string {
  return String(process.env[name] ?? "").trim();
}

function mysqlEnabled(): boolean {
  return Boolean(env("MYSQL_HOST") && env("MYSQL_USER") && env("MYSQL_PASSWORD") && env("MYSQL_DATABASE"));
}

function mysqlPort(): number {
  const parsed = Number.parseInt(env("MYSQL_PORT") || "3306", 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 3306;
}

function getPool(): mysql.Pool {
  if (!mysqlEnabled()) {
    throw new Error("MySQL mirror is not configured. Set MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE.");
  }
  if (pool) return pool;
  pool = mysql.createPool({
    host: env("MYSQL_HOST"),
    port: mysqlPort(),
    user: env("MYSQL_USER"),
    password: env("MYSQL_PASSWORD"),
    database: env("MYSQL_DATABASE"),
    waitForConnections: true,
    connectionLimit: 5,
    enableKeepAlive: true,
    ssl: env("MYSQL_SSL") === "true" ? { rejectUnauthorized: false } : undefined,
  });
  return pool;
}

function asString(value: unknown): string | null {
  if (value == null) return null;
  const text = String(value).trim();
  return text.length > 0 ? text : null;
}

function toIso(value: unknown): string | null {
  if (value == null) return null;
  if (value instanceof admin.firestore.Timestamp) return value.toDate().toISOString();
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value.toISOString();
  const parsed = new Date(String(value));
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

function resolveDocType(target: MirrorDocTarget, row: Record<string, unknown>): string | null {
  if (target === "public_docs") return asString(row.docType);
  if (target === "posts") return asString(row.type);
  if (target === "doc_tracking") return asString(row.docType);
  return null;
}

function resolveCategory(target: MirrorDocTarget, row: Record<string, unknown>): string | null {
  if (target === "posts") return asString(row.category);
  return null;
}

function resolveStatus(target: MirrorDocTarget, row: Record<string, unknown>): string | null {
  if (target === "doc_tracking") return asString(row.status);
  return asString(row.status);
}

function resolveOfficeId(target: MirrorDocTarget, row: Record<string, unknown>): string | null {
  if (target === "doc_tracking") {
    return asString(row.currentOfficeId) ?? asString(row.officeId);
  }
  return asString(row.officeId);
}

function safeTable(target: MirrorDocTarget): string {
  if (target === "posts") return "posts";
  if (target === "public_docs") return "public_docs";
  if (target === "jobs") return "jobs";
  return "doc_tracking";
}

export async function mirrorDocChange(
  target: MirrorDocTarget,
  id: string,
  before: Record<string, unknown> | null,
  after: Record<string, unknown> | null
): Promise<void> {
  if (!mysqlEnabled()) return;
  const table = safeTable(target);
  const mysqlPool = getPool();

  if (!after) {
    await mysqlPool.query(`DELETE FROM ${table} WHERE id = ?`, [id]);
    return;
  }

  const row = after;
  const type = resolveDocType(target, row);
  const category = resolveCategory(target, row);
  const docType = resolveDocType(target, row);
  const title = asString(row.title);
  const status = resolveStatus(target, row);
  const officeId = resolveOfficeId(target, row);
  const updatedAt = toIso(row.updatedAt) ?? toIso(row.publishedAt) ?? toIso(row.createdAt);
  const createdAt = toIso(row.createdAt);
  const jsonPayload = JSON.stringify({
    id,
    before: before ?? null,
    after,
  });

  await mysqlPool.query(
    `INSERT INTO ${table}
      (id, type, category, doc_type, title, status, office_id, json_payload, updated_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE
      type = VALUES(type),
      category = VALUES(category),
      doc_type = VALUES(doc_type),
      title = VALUES(title),
      status = VALUES(status),
      office_id = VALUES(office_id),
      json_payload = VALUES(json_payload),
      updated_at = VALUES(updated_at),
      created_at = VALUES(created_at)`,
    [id, type, category, docType, title, status, officeId, jsonPayload, updatedAt, createdAt]
  );
}

export async function mirrorTrackingTimelineChange(
  trackingId: string,
  entryId: string,
  before: Record<string, unknown> | null,
  after: Record<string, unknown> | null
): Promise<void> {
  if (!mysqlEnabled()) return;
  const mysqlPool = getPool();
  if (!after) {
    await mysqlPool.query(
      "DELETE FROM doc_tracking_timeline WHERE tracking_id = ? AND entry_id = ?",
      [trackingId, entryId]
    );
    return;
  }

  const timestamp = toIso(after.createdAt) ?? toIso(after.timestamp);
  const actionType = asString(after.actionType) ?? asString(after.type);
  const officeId = asString(after.toOfficeId) ?? asString(after.fromOfficeId);
  const publicNote = asString(after.notePublic) ?? asString(after.notes);
  const payload = JSON.stringify({
    trackingId,
    entryId,
    before: before ?? null,
    after,
  });

  await mysqlPool.query(
    `INSERT INTO doc_tracking_timeline
      (tracking_id, entry_id, timestamp, action_type, office_id, public_note, json_payload)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE
      timestamp = VALUES(timestamp),
      action_type = VALUES(action_type),
      office_id = VALUES(office_id),
      public_note = VALUES(public_note),
      json_payload = VALUES(json_payload)`,
    [trackingId, entryId, timestamp, actionType, officeId, publicNote, payload]
  );
}

export async function enqueueMirrorFailure(
  eventId: string | null,
  job: SyncQueueJob,
  error: unknown
): Promise<void> {
  const db = admin.firestore();
  const ref = eventId
    ? db.collection("sync_queue").doc(eventId)
    : db.collection("sync_queue").doc();
  await ref.set(
    {
      kind: job.kind,
      target: job.target ?? null,
      id: job.id ?? null,
      trackingId: job.trackingId ?? null,
      entryId: job.entryId ?? null,
      before: job.before ?? null,
      after: job.after ?? null,
      attempts: admin.firestore.FieldValue.increment(1),
      lastError: String((error as { message?: unknown })?.message ?? error ?? "unknown"),
      nextRetryAt: admin.firestore.Timestamp.fromMillis(Date.now() + 5 * 60 * 1000),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    },
    {merge: true}
  );
}

async function processJob(job: SyncQueueJob): Promise<void> {
  if (job.kind === "timeline") {
    if (!job.trackingId || !job.entryId) {
      throw new Error("Invalid timeline sync job.");
    }
    await mirrorTrackingTimelineChange(
      job.trackingId,
      job.entryId,
      (job.before ?? null) as Record<string, unknown> | null,
      (job.after ?? null) as Record<string, unknown> | null
    );
    return;
  }
  if (!job.target || !job.id) {
    throw new Error("Invalid document sync job.");
  }
  await mirrorDocChange(
    job.target,
    job.id,
    (job.before ?? null) as Record<string, unknown> | null,
    (job.after ?? null) as Record<string, unknown> | null
  );
}

export async function retryQueuedMirrorJobs(limitRows = 100): Promise<{ processed: number; failed: number }> {
  const db = admin.firestore();
  const now = admin.firestore.Timestamp.now();
  const snapshot = await db
    .collection("sync_queue")
    .where("nextRetryAt", "<=", now)
    .orderBy("nextRetryAt", "asc")
    .limit(Math.max(1, Math.min(500, limitRows)))
    .get();

  let processed = 0;
  let failed = 0;
  for (const item of snapshot.docs) {
    const data = item.data() as SyncQueueJob & { attempts?: number };
    try {
      await processJob(data);
      await item.ref.delete();
      processed += 1;
    } catch (error) {
      failed += 1;
      await item.ref.set(
        {
          attempts: admin.firestore.FieldValue.increment(1),
          lastError: String((error as { message?: unknown })?.message ?? error ?? "unknown"),
          nextRetryAt: admin.firestore.Timestamp.fromMillis(Date.now() + 5 * 60 * 1000),
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        {merge: true}
      );
    }
  }

  return {processed, failed};
}
