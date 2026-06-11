param(
    [string]$ListenAddress = "127.0.0.1",
    [int]$Port = 8000,
    [switch]$WithLlm
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Python = "C:\Users\huohuo\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
$Deps = Join-Path $Root ".deps"
$Data = Join-Path $Root "data"
$PidFile = Join-Path $Data "windows-services.json"
$DependencyProbes = @(
    (Join-Path $Deps "uvicorn\__init__.py"),
    (Join-Path $Deps "cryptography\__init__.py"),
    (Join-Path $Deps "_cffi_backend.cp312-win_amd64.pyd")
)
$PermissionRepair = Join-Path $Root "scripts\repair-windows-permissions.ps1"

if (-not (Test-Path $Python)) {
    throw "Codex Python was not found: $Python"
}
if (-not (Test-Path $Deps)) {
    throw "Project dependency directory .deps was not found."
}
if ($DependencyProbes | Where-Object { -not (Test-Path $_) }) {
    throw "Required packages were not found in .deps. Reinstall the project dependencies."
}

$PermissionDenied = $false
foreach ($DependencyProbe in $DependencyProbes) {
    try {
        $stream = [System.IO.File]::OpenRead($DependencyProbe)
        $stream.Dispose()
    } catch [System.UnauthorizedAccessException] {
        $PermissionDenied = $true
        break
    }
}
if ($PermissionDenied) {
    & $PermissionRepair -Deps $Deps
    foreach ($DependencyProbe in $DependencyProbes) {
        $stream = [System.IO.File]::OpenRead($DependencyProbe)
        $stream.Dispose()
    }
}

Push-Location $Root
try {
    $arguments = @("scripts\windows_launcher.py", "start", "--host", "$ListenAddress", "--port", "$Port")
    if ($WithLlm) { $arguments += "--with-llm" }
    & $Python $arguments
    if ($LASTEXITCODE -ne 0) {
        throw "ShieldDome launcher failed. See data\windows-api.err.log and data\windows-worker.err.log."
    }
    $health = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/v1/health"
    Write-Host ""
    Write-Host "ShieldDome Windows test environment started." -ForegroundColor Green
    Write-Host "Listening on: $ListenAddress`:$Port"
    Write-Host "Console on this computer: http://127.0.0.1:$Port"
    Write-Host "API docs: http://127.0.0.1:$Port/docs"
    if ($ListenAddress -eq "0.0.0.0") {
        Write-Host "Remote test mode enabled. Configure the browser plugin with this computer's LAN IP and allow TCP port $Port in Windows Firewall." -ForegroundColor Yellow
    }
    Write-Host "Login username: admin"
    Write-Host "Login password: ShieldDome-Local-Admin-2026"
    Write-Host "Service API admin token: shielddome-local-admin"
    Write-Host "EML ingestion token: shielddome-local-ingest"
    Write-Host "LLM configured: $($health.provider.configured)"
    Write-Host "Stop: powershell -ExecutionPolicy Bypass -File scripts\stop-windows.ps1"
} finally {
    Pop-Location
}
