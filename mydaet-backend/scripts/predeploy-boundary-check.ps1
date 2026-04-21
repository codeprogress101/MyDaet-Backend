param(
  [ValidateSet("dev", "staging", "prod")]
  [string]$Environment = "dev",
  [switch]$AcknowledgeManualChecks
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Pass([string]$Message) {
  Write-Host "[PASS] $Message" -ForegroundColor Green
}

function Fail([string]$Message) {
  Write-Host "[FAIL] $Message" -ForegroundColor Red
  throw $Message
}

function Assert-FileExists([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) {
    Fail "Missing required file: $Path"
  }
  Pass "Found $Path"
}

function Assert-JsonParse([string]$Path) {
  try {
    Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json | Out-Null
    Pass "Valid JSON: $Path"
  } catch {
    Fail "Invalid JSON in $Path. $($_.Exception.Message)"
  }
}

function Assert-Pattern([string]$Path, [string]$Pattern, [string]$Label) {
  if (-not (Select-String -Path $Path -Pattern $Pattern -SimpleMatch -Quiet)) {
    Fail "$Label not found in $Path"
  }
  Pass $Label
}

function Assert-Regex([string]$Content, [string]$Pattern, [string]$Label) {
  if ($Content -notmatch $Pattern) {
    Fail "$Label check failed"
  }
  Pass $Label
}

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $repoRoot

Write-Host "Running predeploy boundary checks for '$Environment' in $repoRoot" -ForegroundColor Cyan

$firebaserc = Join-Path $repoRoot ".firebaserc"
$firebaseJson = Join-Path $repoRoot "firebase.json"
$firestoreRules = Join-Path $repoRoot "firestore.rules"
$firestoreIndexes = Join-Path $repoRoot "firestore.indexes.json"
$storageRules = Join-Path $repoRoot "storage.rules"
$functionsIndex = Join-Path $repoRoot "functions\src\index.ts"

Assert-FileExists $firebaserc
Assert-FileExists $firebaseJson
Assert-FileExists $firestoreRules
Assert-FileExists $firestoreIndexes
Assert-FileExists $storageRules
Assert-FileExists $functionsIndex

Assert-JsonParse $firebaserc
Assert-JsonParse $firebaseJson
Assert-JsonParse $firestoreIndexes

$rc = Get-Content -LiteralPath $firebaserc -Raw | ConvertFrom-Json
if (-not $rc.projects.PSObject.Properties.Name.Contains($Environment)) {
  Fail ".firebaserc missing projects.$Environment alias"
}
Pass ".firebaserc has projects.$Environment alias"

Assert-Pattern $firestoreRules "match /dts_documents/{docId}" "DTS documents rules block"
Assert-Pattern $firestoreRules "match /dts_routes/{routeId}" "DTS routes rules block"
Assert-Pattern $firestoreRules "match /dts_audit_logs/{auditId}" "DTS audit rules block"
Assert-Pattern $firestoreRules "match /dts_templates/{templateId}" "DTS templates rules block"
Assert-Pattern $firestoreRules "match /{document=**}" "Default deny wildcard block"
Assert-Pattern $firestoreRules "allow read, write: if false;" "Default deny read/write rule"

$rulesText = Get-Content -LiteralPath $firestoreRules -Raw
Assert-Regex $rulesText "(?s)match\s+/dts_documents/\{docId\}.*allow\s+create:\s+if\s+false;" "dts_documents direct create denied"
Assert-Regex $rulesText "(?s)match\s+/dts_documents/\{docId\}.*allow\s+update:\s+if\s+false;" "dts_documents direct update denied"
Assert-Regex $rulesText "(?s)function\s+dtsOfficeAllowed\s*\(" "DTS office scope helper exists"
Assert-Regex $rulesText "(?s)function\s+dtsCanRead\s*\(" "DTS read scope helper exists"

$indexesText = Get-Content -LiteralPath $firestoreIndexes -Raw
Assert-Regex $indexesText '"collectionGroup"\s*:\s*"dts_routes"' "dts_routes index entries present"
Assert-Regex $indexesText '"collectionGroup"\s*:\s*"dts_audit_logs"' "dts_audit_logs index entries present"

$storageText = Get-Content -LiteralPath $storageRules -Raw
Assert-Regex $storageText "match\s+/dts/\{docId\}/attachments/\{fileName\}" "DTS attachment path exists"
Assert-Regex $storageText "match\s+/dts/\{officePathId\}/\{docId\}/\{fileName\}" "DTS office-scoped attachment path exists"
Assert-Regex $storageText "match\s+/posts/\{postId\}/\{fileName\}" "Website posts storage path exists"
Assert-Regex $storageText "match\s+/public_docs/\{docType\}/pdf/\{filePath=\*\*\}" "Website public docs storage path exists"

$functionsText = Get-Content -LiteralPath $functionsIndex -Raw
Assert-Regex $functionsText "canOperateOnDtsDoc" "Functions contain DTS scope enforcement helper usage"
Assert-Regex $functionsText "writeDtsAuditLog|dts_audit|dtsAudit" "Functions contain DTS audit logging hooks"

if (($Environment -eq "staging" -or $Environment -eq "prod") -and -not $AcknowledgeManualChecks) {
  Fail "Manual smoke-test gate required for $Environment. Re-run with -AcknowledgeManualChecks after completing checklist item 10."
}

if ($AcknowledgeManualChecks) {
  Pass "Manual smoke-test gate acknowledged"
}

Write-Host "All predeploy boundary checks passed for '$Environment'." -ForegroundColor Green
