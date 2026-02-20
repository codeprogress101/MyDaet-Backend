## Firebase Support Request: Clear Stuck Cloud Functions Gen1 Operations

### Project
- Project ID: `mydaet`
- Project number: `622631828696`
- Region: `us-central1`
- Date observed: `February 20, 2026`

### Incident Summary
Cloud Functions Gen1 deployment/deletion operations are stuck or failing in control plane state.

- Deployments partially succeed, then many Gen1 functions remain `OFFLINE`.
- Multiple delete operations remain stuck in `done:false`.
- Re-deploy and delete attempts repeatedly fail.
- This is blocking production rollout of staff/admin and document-tracking functionality.

### Current Pending Operations (`done:false`)
1. `projects/mydaet/locations/us-central1/operations/operation-1771573381056-64b3c92124999-9844348b-9d12b3ef`
   - verb: `delete`
   - target: `projects/mydaet/locations/us-central1/functions/trackLookup`
   - createTime: `2026-02-20T07:43:01.087346756Z`
2. `projects/mydaet/locations/us-central1/operations/operation-1771571891669-64b3c394c08b6-0de4f44e-e75f161e`
   - verb: `delete`
   - target: `projects/mydaet/locations/us-central1/functions/mirrorPostsToMysql`
   - createTime: `2026-02-20T07:18:11.711647556Z`
3. `projects/mydaet/locations/us-central1/operations/operation-1771572490952-64b3c5d046048-d7b57f63-c306adcd`
   - verb: `delete`
   - target: `projects/mydaet/locations/us-central1/functions/pingTemp`
   - createTime: `2026-02-20T07:28:10.993463705Z`

### Related Completed-But-Failed Operation
- `projects/mydaet/locations/us-central1/operations/operation-1771571542625-64b3c247e0d4f-00e9f54a-225b6b57`
  - done: `true`
  - error code: `10`
  - error: `Gen1 operation for function projects/mydaet/locations/us-central1/functions/trackLookup failed: Operation interrupted..`

### Functions Not Active (from v1 functions list)
`DELETE_IN_PROGRESS`
- `mirrorPostsToMysql`
- `pingTemp`
- `trackLookup`

`OFFLINE`
- `adminAssignReport`
- `adminUpdateReportStatus`
- `adminWriteAuditLog`
- `dtsCreateTrackingRecord`
- `mirrorDocTrackingTimelineToMysql`
- `mirrorDocTrackingToMysql`
- `mirrorJobsToMysql`
- `mirrorPublicDocsToMysql`
- `retryMysqlMirrorQueue`
- `setTrackingPin`

### Repro / Error Evidence
- `firebase-tools` delete calls return:
  - `Failed to delete 1st Gen function ...`
  - `FAILED_PRECONDITION: An operation on function ... is already in progress. Please try again later.`
- Direct operation cancel attempts on these operation IDs return HTTP `404`.

### Requested Action
Please clear/unblock the stuck Gen1 control-plane operations in `us-central1`, and repair the Gen1 function state for this project so function delete/deploy can proceed normally.

Specifically requested:
1. Force-complete or purge the stuck operation records listed above.
2. Clear any backend lock on affected functions (`trackLookup`, `mirrorPostsToMysql`, `pingTemp`).
3. Restore deployability/operability of affected Gen1 functions now in `OFFLINE`.
4. Confirm if there is a known regional/project-level incident for Gen1 in `us-central1`.

### Business Impact
- Staff admin features and public document tracking are blocked.
- Security/audit workflow functions are offline.
- Planned Firestore primary + MySQL mirror rollout cannot be completed.

