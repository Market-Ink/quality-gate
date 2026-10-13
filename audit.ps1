# Windows wrapper so you can run `./audit.ps1` instead of `node audit.js`.
# Passes every argument straight through. Whole-repo security audit — see audit.js.
$ErrorActionPreference = "Stop"
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Error "Node.js not found on PATH. Install Node 18+ (20+ recommended): https://nodejs.org"
    exit 2
}
& node "$dir\audit.js" @args
exit $LASTEXITCODE
