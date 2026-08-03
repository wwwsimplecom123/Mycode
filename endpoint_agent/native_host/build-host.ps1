[CmdletBinding()]
param(
    [string]$PythonExecutable = "python"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$endpointRoot = Split-Path -Parent $PSScriptRoot
$sourceRoot = Join-Path $endpointRoot "src"
$entryPoint = Join-Path $endpointRoot "packaging\native_host_entry.py"
$workRoot = Join-Path $endpointRoot "build\native-host"
$distRoot = Join-Path $endpointRoot "dist\native-host"
$executablePath = Join-Path $distRoot "ShieldDomeEndpointHost.exe"
$metadataPath = Join-Path $distRoot "build-metadata.json"
$identityPath = Join-Path $PSScriptRoot "identity.json"

$ErrorActionPreference = "Continue"
$versionOutput = & $PythonExecutable -m PyInstaller --version 2>$null
$versionExitCode = $LASTEXITCODE
$ErrorActionPreference = "Stop"
if ($versionExitCode -ne 0) {
    throw "PyInstaller is unavailable. Install the pinned development dependency from an approved offline cache with: python -m pip install --no-index -r endpoint_agent\requirements-packaging.txt"
}
$pyInstallerVersion = ($versionOutput | Select-Object -Last 1).ToString().Trim()

New-Item -ItemType Directory -Force -Path $workRoot, $distRoot | Out-Null

# Reproducible invocation: python -m PyInstaller --noconfirm --clean --onefile --console --noupx
$arguments = @(
    "-m", "PyInstaller",
    "--noconfirm",
    "--clean",
    "--onefile",
    "--console",
    "--noupx",
    "--name", "ShieldDomeEndpointHost",
    "--paths", $sourceRoot,
    "--distpath", $distRoot,
    "--workpath", $workRoot,
    "--specpath", $workRoot,
    $entryPoint
)
& $PythonExecutable @arguments
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller failed with exit code $LASTEXITCODE."
}
if (-not (Test-Path -LiteralPath $executablePath -PathType Leaf)) {
    throw "PyInstaller did not produce the expected Host executable."
}

$identity = Get-Content -LiteralPath $identityPath -Raw -Encoding UTF8 | ConvertFrom-Json
$metadata = [ordered]@{
    schema_version = "1.0"
    host_name = [string]$identity.host_name
    extension_id = [string]$identity.extension_id
    extension_origin = [string]$identity.extension_origin
    executable_path = [System.IO.Path]::GetFullPath($executablePath)
    executable_sha256 = (Get-FileHash -LiteralPath $executablePath -Algorithm SHA256).Hash.ToLowerInvariant()
    build_tool = "PyInstaller"
    build_tool_version = $pyInstallerVersion
}
$metadata | ConvertTo-Json | Set-Content -LiteralPath $metadataPath -Encoding UTF8

Write-Host "Built Native Messaging Host: $executablePath"
Write-Host "Build metadata: $metadataPath"
