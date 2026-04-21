# MyDaet Backend (Shared Firebase)

Primary Firebase aliases:
- `dev` -> `mydaet-staging` (local development uses staging backend)
- `staging` -> `mydaet-staging`
- `prod` -> `mydaet`

This repo is the source of truth for:
- Firestore rules and indexes
- Storage rules
- Cloud Functions

## Setup

1. Install Functions dependencies:

```bash
cd C:\Users\ADMIN\MyDaet-Backend\mydaet-backend\functions
npm install
```

2. Build functions:

```bash
npm run build
```

3. Select environment alias:

```bash
cd ..
firebase use dev
```

## Deploy

Use environment-specific scripts from repo root:

- Dev: `./scripts/deploy-dev.ps1`
- Staging: `./scripts/deploy-staging.ps1 -AcknowledgeManualChecks`
- Prod: `./scripts/deploy-prod.ps1 -Force -AcknowledgeManualChecks`

Default deploy scope is backend-only (`functions`, `firestore:rules`, `firestore:indexes`, `storage`).
Firebase Hosting is not part of the default backend deploy workflow.

Boundary checks are enforced before deploy by `scripts/predeploy-boundary-check.ps1`.
Manual smoke-test acknowledgment is required for staging/prod.

Optional scoped deploys:

```powershell
./scripts/predeploy-boundary-check.ps1 -Environment dev
./scripts/predeploy-boundary-check.ps1 -Environment staging -AcknowledgeManualChecks
./scripts/deploy-dev.ps1 -Functions -Rules
./scripts/deploy-staging.ps1 -AcknowledgeManualChecks
./scripts/deploy-prod.ps1 -Rules -Indexes -Force -AcknowledgeManualChecks
```

`deploy-prod.ps1` blocks by default unless `-Force` is provided.

## Data Domain Boundaries

Shared collections:
- `users`
- `offices`
- `roles`
- `config`

DTS collections:
- `dts_documents`
- `dts_routes`
- `dts_audit_logs`
- `dts_templates`

Rules enforce role claim checks and office-scoped access for DTS.

## Notes

- Public report submission remains callable/HTTP-only.
- DTS lifecycle mutations remain callable-only.
- Do not deploy backend rules/indexes from frontend repositories.
