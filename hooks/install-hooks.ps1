# MarketInk Quality Gate — one-time onboarding for a project (Windows).
#
# What it does (all inside the TARGET repo, nothing destructive):
#   1. Vendors the scanner into  <repo>/.quality-gate/  (scan.js, lib, rules,
#      baselines, prompts) and creates <repo>/.quality-gate.json from the
#      example if the project doesn't have one yet
#   2. Installs the hooks into    <repo>/.githooks/       (pre-commit, pre-push)
#   3. Points git at them:         git config core.hooksPath .githooks
#   4. Adds quality-reports/ to    <repo>/.gitignore
#
# After this, commit .githooks/ and .quality-gate/ so the setup travels with the
# repo. Teammates who clone/pull still run ONE command once (see the end).
#
# Usage:
#   .\install-hooks.ps1 -Repo C:\path\to\your-project
#   .\install-hooks.ps1 -Repo ..\my-service

param(
  [Parameter(Mandatory = $true)]
  [string]$Repo
)

$ErrorActionPreference = "Stop"
$toolDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)  # ..\quality-gate

$Repo = (Resolve-Path $Repo).Path
if (-not (Test-Path (Join-Path $Repo ".git"))) {
  Write-Error "Not a git repository: $Repo (run 'git init' there first)."
  exit 2
}

Write-Host "Onboarding Quality Gate into: $Repo" -ForegroundColor Cyan

# 1. Vendor the scanner ------------------------------------------------------
$vendor = Join-Path $Repo ".quality-gate"
New-Item -ItemType Directory -Force -Path $vendor | Out-Null
Copy-Item (Join-Path $toolDir "scan.js")                 (Join-Path $vendor "scan.js") -Force
foreach ($d in @("lib", "rules", "baselines")) {
  $dest = Join-Path $vendor $d
  if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
  Copy-Item (Join-Path $toolDir $d) $dest -Recurse -Force
}
if (Test-Path (Join-Path $toolDir ".quality")) {
  Copy-Item (Join-Path $toolDir ".quality") $vendor -Recurse -Force   # prompts for the AI review
}
Write-Host "  [ok] vendored scanner -> .quality-gate\" -ForegroundColor Green
$projCfg = Join-Path $Repo ".quality-gate.json"
if (-not (Test-Path $projCfg)) {
  Copy-Item (Join-Path $toolDir "examples\quality-gate.json") $projCfg
  Write-Host "  [ok] created .quality-gate.json (extends the org baseline - edit to taste)" -ForegroundColor Green
}

# 2. Install the hooks -------------------------------------------------------
$hooksDir = Join-Path $Repo ".githooks"
New-Item -ItemType Directory -Force -Path $hooksDir | Out-Null
Copy-Item (Join-Path $toolDir "hooks\pre-commit") (Join-Path $hooksDir "pre-commit") -Force
Copy-Item (Join-Path $toolDir "hooks\pre-push")   (Join-Path $hooksDir "pre-push")   -Force
Write-Host "  [ok] installed hooks -> .githooks\ (pre-commit, pre-push)" -ForegroundColor Green

# 3. Point git at the committed hooks ---------------------------------------
git -C $Repo config core.hooksPath .githooks
Write-Host "  [ok] git config core.hooksPath .githooks" -ForegroundColor Green

# 4. Ignore generated reports ------------------------------------------------
$gitignore = Join-Path $Repo ".gitignore"
$needed = @("quality-reports/", ".quality-gate/quality-reports/")
$existing = @()
if (Test-Path $gitignore) { $existing = Get-Content $gitignore }
$toAdd = $needed | Where-Object { $existing -notcontains $_ }
if ($toAdd.Count -gt 0) {
  Add-Content -Path $gitignore -Value ($toAdd -join "`n") -Encoding utf8
  Write-Host "  [ok] added report paths to .gitignore" -ForegroundColor Green
}

Write-Host ""
Write-Host "Done. The gate now runs automatically on commit and push in this repo." -ForegroundColor Cyan
Write-Host "Next:" -ForegroundColor Yellow
Write-Host "  1. Commit the setup so it travels with the repo:"
Write-Host "       git add .githooks .quality-gate .quality-gate.json .gitignore && git commit -m 'Add MarketInk Quality Gate hooks'"
Write-Host "  2. Every teammate runs this ONCE after cloning (git can't auto-enable hooks):"
Write-Host "       git config core.hooksPath .githooks"
Write-Host ""
Write-Host "Toggles (set as env vars): QG_BLOCK=1 to block on findings, QG_AI=1 to add the AI review on push."
