# Script Security Guardrails

## 1) Service-account JSON key usage is gated

The maintenance scripts below can still use a JSON key file, but only with explicit approval:

- `scripts/audit-user-office-consistency.js`
- `scripts/backfill-report-offices.js`

If `--key=<path>` or `GOOGLE_APPLICATION_CREDENTIALS` is set, you must also pass one of:

- `--allow-service-account-key`
- `ALLOW_SERVICE_ACCOUNT_KEY=true`

Without explicit approval, scripts abort.

## 2) User-managed key policy check

Run:

```bash
npm run security:sa-keys -- --project=mydaet
```

Behavior:
- exits `0` when no user-managed keys are found
- exits `2` when user-managed keys are found
- exits `1` for runtime/config errors
- requires `gcloud` CLI installed/authenticated

Optional:

```bash
npm run security:sa-keys -- --project=mydaet --allow-accounts=svc1@project.iam.gserviceaccount.com
npm run security:sa-keys -- --project=mydaet --warn-only
```

## 3) Local key-material scan

Run:

```bash
npm run security:local-keys
```

Behavior:
- scans the repository for service-account key filename patterns
- scans text-like files for private key markers
- exits `2` on findings and prints the matched file paths
