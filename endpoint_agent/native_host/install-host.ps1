[CmdletBinding()]
param(
    [string]$HostPath,
    [string]$BuildMetadataPath,
    [string]$ManifestRoot = (Join-Path $env:LOCALAPPDATA "ShieldDome\EndpointAgent\NativeMessagingHosts"),
    [string]$ChromeRegistryPath = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\cn.shielddome.endpoint_agent",
    [string]$EdgeRegistryPath = "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\cn.shielddome.endpoint_agent"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$endpointRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($HostPath)) {
    $HostPath = Join-Path $endpointRoot "dist\native-host\ShieldDomeEndpointHost.exe"
}
if ([string]::IsNullOrWhiteSpace($BuildMetadataPath)) {
    $BuildMetadataPath = Join-Path $endpointRoot "dist\native-host\build-metadata.json"
}
Import-Module (Join-Path $PSScriptRoot "NativeHostRegistration.psm1") -Force

Install-ShieldDomeNativeHost `
    -HostPath $HostPath `
    -BuildMetadataPath $BuildMetadataPath `
    -ManifestRoot $ManifestRoot `
    -ChromeRegistryPath $ChromeRegistryPath `
    -EdgeRegistryPath $EdgeRegistryPath | ConvertTo-Json -Depth 4
