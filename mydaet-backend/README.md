# MyDaet Backend

Firestore is the source of truth for app + website.  
MySQL mirror is disabled for now (Firestore-only mode).

## Environment Variables

Set in Cloud Functions runtime:

- Firebase default runtime variables only.

MySQL-related variables are not required while mirror mode is disabled.

## Deploy

```bash
cd C:\Users\ADMIN\MyDaet-Backend\mydaet-backend\functions
npm install
npm run build
cd ..
firebase deploy --only functions,firestore:rules,storage
```

## Office Constants

- `SANGGUNIANG_BAYAN`
- `OFFICE_OF_THE_MAYOR`
- Plus office IDs defined in `offices/{officeId}`

## Role Matrix

- `resident`: public/report submitter; no staff admin actions
- `moderator`: draft/edit scoped records, report status updates when assigned, DTS operations in scope
- `admin`: office-scoped publishing, assignment, tracking PIN reset, audit visibility in-office
- `super_admin`: global access including user management

Legacy `office_admin` is normalized to `admin` server-side.

## Tracking SOP (Public vs Internal)

Public tracking output only includes:

- `trackingNumber`
- `title` (suppressed for confidential records)
- `status`
- `currentOfficeName`
- `updatedAt`
- timeline: `timestamp`, `actionType`, `officeName`, `notePublic`

Never exposed:

- `pinHash` / `publicPinHash`
- internal notes
- actor emails
- submitter PII (unless explicitly approved)

## MySQL Mirror

Mirror jobs are currently disabled by request.  
No Firestore->MySQL sync triggers are active in the deployed source.

## Tests

```bash
cd C:\Users\ADMIN\MyDaet-Backend\mydaet-backend\functions
npm run test:rules
```

Coverage includes:

- report read access by role
- audit log write denial from client
- user self-update constraints
