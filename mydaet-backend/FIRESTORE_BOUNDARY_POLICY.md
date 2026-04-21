# Firestore Boundary Policy (Website + DTS)

## Scope

This policy applies to the active MyDaet surfaces:

- Website/Portal (`maogmangdaet-react-transition`)
- Daet DTS (`mydaet-dts-flutter`)

`mother` app is currently parked and out of active scope.

## Environment Model

Use this Firebase mapping:

- `dev` -> `mydaet-staging` (local app/testing shares staging backend)
- `staging` -> `mydaet-staging`
- `prod` -> `mydaet`

Within each environment, use one Firestore database: `(default)`.

## Collection Domains

## 1) Shared Domain (cross-surface)

Collections that may be used by both Website and DTS:

- `users`
- `offices`
- `roles`
- `system` / `config`
- `audit_logs` (platform-level)

Rules:

- Identity and role fields are backend authoritative.
- Client-side role checks are UX-only; server/rules checks are required.

## 2) Website Domain

Collections owned by Website workflows:

- `posts`
- `announcements`
- `public_docs`
- `jobs`
- `directory_entries`
- `reports`
- `emergency_hotlines`
- `civil_registry_requests`
- other non-`dts_*` public/admin portal collections

Rules:

- Public reads only for explicitly published/public records.
- Privileged writes should be callable-only wherever possible.

## 3) DTS Domain

Collections owned by DTS workflows:

- `dts_documents`
- `dts_routes`
- `dts_audit_logs`
- `dts_templates`
- `dts_qr_codes`
- `dts_qr_batches`
- `dts_qr_index`
- `dts_alerts`
- `dts_counters`
- any future DTS collection must use `dts_` prefix

Rules:

- DTS lifecycle state changes are callable-only.
- DTS reads are role-scoped and office-scoped.
- Direct client writes to DTS lifecycle collections are denied by default.

## Enforced Separation Rules

1. New DTS collections must use `dts_` prefix.
2. Website features must not write to DTS collections directly.
3. DTS feature code must not write Website-owned collections unless explicitly approved.
4. Shared collections must have explicit field ownership documented before mutation logic is added.
5. Any cross-domain write path must be function-mediated and audited.

## Storage Boundary Policy

- DTS assets must stay under DTS-prefixed paths (`/dts/...`, `/dts_qr_*`).
- Website assets must stay in Website-owned paths (`/posts/...`, `/public_docs/...`, etc.).
- DTS document attachments should stay office-scoped where implemented.

## Rules Checklist (Release Gate)

Run this checklist before staging/prod deploy:

1. `firestore.rules` has explicit `match` blocks for all new `dts_*` collections.
2. New `dts_*` blocks deny direct create/update/delete unless explicitly required.
3. Office scope checks exist for DTS staff reads.
4. Super admin bypass is explicit and minimal.
5. No broad wildcard rule grants write access unintentionally.
6. `storage.rules` paths follow Website vs DTS ownership boundaries.
7. `firestore.indexes.json` includes required indexes for new queries.
8. Callable functions enforce role + office checks before writes.
9. Audit events are written for privileged DTS actions.
10. Staging smoke test confirms:
   - Website cannot mutate DTS lifecycle data directly.
   - DTS users cannot access out-of-scope office records.
   - Public users cannot access restricted DTS internals.

## Automated Gate Script

Use `scripts/predeploy-boundary-check.ps1` before deploy.

Examples:

```powershell
./scripts/predeploy-boundary-check.ps1 -Environment dev
./scripts/predeploy-boundary-check.ps1 -Environment staging -AcknowledgeManualChecks
./scripts/predeploy-boundary-check.ps1 -Environment prod -AcknowledgeManualChecks
```

Deploy scripts call this checker by default.

## Change Control

For any boundary change:

1. Update this file.
2. Update `firestore.rules` / `storage.rules` / `firestore.indexes.json`.
3. Record the decision in `docs/agentic/decision-log.md`.
4. Record deploy and validation in `docs/agentic/work-log.md`.
