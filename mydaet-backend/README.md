# MyDaet Backend (Firestore Primary)

Firebase project: `mydaet`  
Primary region: `us-central1`

Firestore is the source of truth for web + app.  
MySQL mirror has been removed.

## Setup

1. Install dependencies:

```bash
cd C:\Users\ADMIN\MyDaet-Backend\mydaet-backend\functions
npm install
```

2. Build functions:

```bash
npm run build
```

3. Select Firebase project:

```bash
cd ..
firebase use mydaet
```

## Deploy

Deploy rules first, then functions:

```bash
firebase deploy --only firestore:rules,storage
firebase deploy --only functions
```

One-shot deploy (optional):

```bash
firebase deploy --only functions,firestore:rules,storage
```

## Runtime Environment

No secrets are stored in source control.

Optional runtime config:

- `TRACK_LOOKUP_ALLOWED_ORIGINS`  
  Comma-separated allowlist for HTTP `trackLookup` CORS.  
  If empty, the endpoint allows all origins.

## Role + Claims Model

Custom claims and `users/{uid}` profile must stay aligned.

Roles:

- `resident`
- `moderator`
- `admin`
- `super_admin`

Legacy `office_admin` is normalized as `admin`.

## Command Center Settings

Global settings document:

- `system/settings`

Shape:

- `maintenance.enabled` (boolean)
- `maintenance.message` (string)
- `readOnly` (boolean)
- `features` map:
  - `tourism`
  - `announcements`
  - `news`
  - `jobs`
  - `directory`
  - `documentTracking`
  - `reports`
  - `transparency`
- `updatedAt` (timestamp)
- `updatedBy` object (`uid`, `role`, `name`, `email`)

Behavior defaults:

- If `system/settings` does not exist yet, feature access is treated as enabled (open-until-configured).
- If `readOnly=true`, writes to feature collections are blocked by rules.
- Only `super_admin` can update `system/settings`.

Callable:

- `adminUpdateSettings` (Gen2)

The callable writes settings and creates audit entries in both:

- `auditLogs`
- `audit_logs` (legacy compatibility)

After changing role/office claims:

1. Update claims (Admin SDK / staff tools).
2. Re-save matching profile fields in `users/{uid}`.
3. User must sign out/sign in to refresh ID token claims.

### Set Super Admin Claim

Use the helper script in repo root:

```bash
cd C:\Users\ADMIN\MyDaet-Backend\mydaet-backend
node set-super-admin.js
```

The script updates both:

- Firebase custom claims (`role=super_admin`, `isActive=true`)
- `users/{uid}` profile role fields

## Access Matrix (Summary)

- Public:
  - Read only published `posts`, `public_docs`, `jobs`
  - No write access
- Staff (`moderator`, `admin`, `super_admin`):
  - Office-scoped writes based on rules + callable checks
- Residents:
  - No direct read access to DTS tracking documents
  - Tracking lookup only through server function + PIN

## Tracking SOP (Public vs Internal)

Public tracking response fields:

- `trackingNumber`
- `title` (may be suppressed for confidential docs)
- `status`
- `currentOfficeName`
- `updatedAt`
- `timeline[]` with:
  - `timestamp`
  - `actionType`
  - `officeName`
  - `notePublic`

Never exposed by public lookup:

- `pinHash` / `publicPinHash`
- internal notes
- actor emails
- submitter PII

## Troubleshooting

### Permission denied

Check all of the following:

1. User has correct claim role and active status.
2. User profile in `users/{uid}` has matching `role`, `officeId`, `officeName`.
3. User has refreshed token after claim changes (re-login).
4. Action is office-scoped correctly (docs/jobs/posts/report workflows).

### Wrong region / callable not found

Use `us-central1` in all clients:

- React `VITE_FIREBASE_FUNCTIONS_REGION=us-central1`
- Direct function URLs should include `/us-central1/`

### Command Center updates fail

Check:

1. Caller has `super_admin` claim and active profile.
2. Callable deploy includes `adminUpdateSettings`.
3. Firestore rules deploy includes `/system/settings` write allowance for `super_admin`.

### Missing env (web)

If web shows Firebase config missing:

1. Fill required `VITE_FIREBASE_*` values.
2. Restart local dev server after `.env` changes.

## Emulator / Rules Checks

Rules compile test:

```bash
cd C:\Users\ADMIN\MyDaet-Backend\mydaet-backend\functions
npm run test:rules
```

Functions build test:

```bash
npm run build
```
