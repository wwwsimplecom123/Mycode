param(
    [string]$Deps
)

$ErrorActionPreference = "Stop"

if (-not $Deps) {
    $Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
    $Deps = Join-Path $Root ".deps"
}

if (-not (Test-Path -LiteralPath $Deps -PathType Container)) {
    throw "Project dependency directory was not found: $Deps"
}

$Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Write-Host "Repairing dependency permissions for $Identity ..." -ForegroundColor Yellow

& icacls.exe $Deps /inheritance:e /grant "${Identity}:(OI)(CI)RX" /T /C | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Could not grant read and execute permission on $Deps to $Identity. Run this script from an elevated PowerShell window."
}

Write-Host "Dependency permissions repaired." -ForegroundColor Green
