# Implementation Notes (Backend)

## Scan findings
- `functions/src/index.ts` already contains report workflow callables: `adminListReportsScoped`, `adminUpdateReportStatus`, `adminAssignReport`, `adminClaimNextReport`, and `adminRequeueReport`.
- Existing report history is stored in `reports/{reportId}/history` through `addHistory(...)`, while report reads are serialized through `serializeReportRow(...)`.
- There is no `submitPublicReport` HTTP endpoint in the current backend, even though the website expects one.
- Feature gating is enforced through `requireFeatureEnabled(...)` and `requireFeatureWritable(...)` against `system/settings`.
- Audit logging already uses `addAuditLog(...)`, and report notifications/history are centralized in the `onReportNotify` trigger.
- Firestore rules for `/reports/{reportId}` and `/history/{historyId}` are already present in `firestore.rules`; `storage.rules` exists and can be tightened for backend-only emergency uploads.

## Planned touchpoints
- Add HTTP endpoints for public report submission, including the new emergency lane.
- Standardize report writes so issue and emergency submissions share the fields needed by admin scoping and the active map.
- Add an append-only `timeline` subcollection for report audit flow while keeping existing `history` for compatibility.
- Keep report feature gating and read-only enforcement intact.

## Manual test checklist
- Public HTTP submission rejects when `reports` is disabled or the system is read-only.
- Emergency submissions write normalized report documents, duplicate warnings, and timeline entries.
- Admin report list continues to return the fields required for queue and map rendering.
- Firestore and Storage rules do not allow clients to bypass backend validation for public emergency uploads.
