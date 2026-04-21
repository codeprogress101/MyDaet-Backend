param(
  [switch]$Functions,
  [switch]$Rules,
  [switch]$Indexes,
  [switch]$Storage,
  [switch]$AcknowledgeManualChecks,
  [switch]$SkipBoundaryCheck,
  [switch]$Force
)

$projectAlias = "prod"
$targets = @()

if ($Functions) { $targets += "functions" }
if ($Rules) { $targets += "firestore:rules" }
if ($Indexes) { $targets += "firestore:indexes" }
if ($Storage) { $targets += "storage" }

if ($targets.Count -eq 0) {
  $targets = @("functions", "firestore:rules", "firestore:indexes", "storage")
}

$only = [string]::Join(",", $targets)

if (-not $Force) {
  throw "Prod deploy blocked by default. Re-run with -Force after CI or release approval."
}

if (-not $SkipBoundaryCheck) {
  & "$PSScriptRoot\predeploy-boundary-check.ps1" -Environment prod -AcknowledgeManualChecks:$AcknowledgeManualChecks
}

Write-Host "Preparing deploy to Firebase alias '$projectAlias' with --only $only" -ForegroundColor Yellow
firebase use $projectAlias
if ($LASTEXITCODE -ne 0) {
  throw "Failed to switch Firebase alias to '$projectAlias'."
}

firebase deploy --project $projectAlias --only $only
if ($LASTEXITCODE -ne 0) {
  throw "Firebase deploy to '$projectAlias' failed."
}

Write-Host "Deploy to '$projectAlias' completed." -ForegroundColor Green
