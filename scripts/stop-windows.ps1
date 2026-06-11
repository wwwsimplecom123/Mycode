$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Python = "C:\Users\huohuo\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
Push-Location $Root
try {
    & $Python scripts\windows_launcher.py stop
} finally {
    Pop-Location
}
Write-Host "ShieldDome Windows test services stopped." -ForegroundColor Green
