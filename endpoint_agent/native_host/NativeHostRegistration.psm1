Set-StrictMode -Version Latest

$script:IdentityPath = Join-Path $PSScriptRoot "identity.json"
$script:ExtensionManifestPath = Join-Path (Split-Path -Parent $PSScriptRoot) "extension\manifest.json"

function Get-ShieldDomeExtensionId {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$PublicKey)

    try {
        $publicBytes = [Convert]::FromBase64String($PublicKey)
    } catch {
        throw "The extension public key is not valid Base64."
    }
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha256.ComputeHash($publicBytes)
    } finally {
        $sha256.Dispose()
    }
    $builder = New-Object System.Text.StringBuilder
    foreach ($byte in $digest[0..15]) {
        [void]$builder.Append([char]([int][char]'a' + ($byte -shr 4)))
        [void]$builder.Append([char]([int][char]'a' + ($byte -band 15)))
    }
    return $builder.ToString()
}

function Get-ShieldDomeIdentity {
    [CmdletBinding()]
    param()

    $identity = Get-Content -LiteralPath $script:IdentityPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $extensionManifest = Get-Content -LiteralPath $script:ExtensionManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $derivedId = Get-ShieldDomeExtensionId -PublicKey ([string]$extensionManifest.key)
    $derivedOrigin = "chrome-extension://$derivedId/"
    if ([string]$identity.identity_kind -ne "development_public_key" -or
        [string]$identity.extension_id -cne $derivedId -or
        [string]$identity.extension_origin -cne $derivedOrigin -or
        [string]$identity.host_name -cne "cn.shielddome.endpoint_agent") {
        throw "The extension manifest and Native Host identity are inconsistent."
    }
    return $identity
}

function Get-ShieldDomeFullPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return [System.IO.Path]::GetFullPath($Path)
}

function Test-ShieldDomeBuild {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$HostPath,
        [Parameter(Mandatory = $true)][string]$BuildMetadataPath
    )

    if (-not [System.IO.Path]::IsPathRooted($HostPath)) {
        throw "The Native Host path must be absolute."
    }
    if (-not (Test-Path -LiteralPath $HostPath -PathType Leaf)) {
        throw "The Native Host executable does not exist."
    }
    if ([System.IO.Path]::GetExtension($HostPath) -ine ".exe") {
        throw "The Native Host must be a Windows .exe file."
    }
    $hostBytes = [System.IO.File]::ReadAllBytes($HostPath)
    if ($hostBytes.Length -lt 2 -or $hostBytes[0] -ne 0x4d -or $hostBytes[1] -ne 0x5a) {
        throw "The Native Host does not have a Windows executable header."
    }
    if (-not (Test-Path -LiteralPath $BuildMetadataPath -PathType Leaf)) {
        throw "The Native Host build metadata does not exist."
    }

    $identity = Get-ShieldDomeIdentity
    $metadata = Get-Content -LiteralPath $BuildMetadataPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $requiredFields = @(
        "schema_version", "host_name", "extension_id", "extension_origin",
        "executable_path", "executable_sha256", "build_tool", "build_tool_version"
    )
    $actualFields = @($metadata.PSObject.Properties.Name)
    if (@($requiredFields | Where-Object { $_ -notin $actualFields }).Count -ne 0 -or
        @($actualFields | Where-Object { $_ -notin $requiredFields }).Count -ne 0) {
        throw "The Native Host build metadata fields are invalid."
    }

    $fullHostPath = (Resolve-Path -LiteralPath $HostPath).Path
    $metadataHostPath = Get-ShieldDomeFullPath -Path ([string]$metadata.executable_path)
    $actualHash = (Get-FileHash -LiteralPath $fullHostPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ([string]$metadata.schema_version -cne "1.0" -or
        [string]$metadata.host_name -cne [string]$identity.host_name -or
        [string]$metadata.extension_id -cne [string]$identity.extension_id -or
        [string]$metadata.extension_origin -cne [string]$identity.extension_origin -or
        $metadataHostPath -ine $fullHostPath -or
        [string]$metadata.executable_sha256 -cne $actualHash -or
        [string]$metadata.build_tool -cne "PyInstaller" -or
        [string]::IsNullOrWhiteSpace([string]$metadata.build_tool_version)) {
        throw "The Native Host build metadata does not match the executable and extension identity."
    }

    return [pscustomobject]@{
        identity = $identity
        host_path = $fullHostPath
        executable_sha256 = $actualHash
        build_tool_version = [string]$metadata.build_tool_version
    }
}

function New-ShieldDomeBrowserManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet("Chrome", "Edge")][string]$Browser,
        [Parameter(Mandatory = $true)][string]$ManifestRoot,
        [Parameter(Mandatory = $true)]$Build
    )

    $browserDirectory = Join-Path (Get-ShieldDomeFullPath -Path $ManifestRoot) $Browser
    New-Item -ItemType Directory -Force -Path $browserDirectory | Out-Null
    $manifestPath = Join-Path $browserDirectory ("{0}.json" -f $Build.identity.host_name)
    $manifest = [ordered]@{
        name = [string]$Build.identity.host_name
        description = "ShieldDome Endpoint Agent Native Host - DEVELOPMENT IDENTITY"
        path = [string]$Build.host_path
        type = "stdio"
        allowed_origins = @([string]$Build.identity.extension_origin)
    }
    $manifest | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    return $manifestPath
}

function Install-ShieldDomeNativeHost {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$HostPath,
        [Parameter(Mandatory = $true)][string]$BuildMetadataPath,
        [Parameter(Mandatory = $true)][string]$ManifestRoot,
        [Parameter(Mandatory = $true)][string]$ChromeRegistryPath,
        [Parameter(Mandatory = $true)][string]$EdgeRegistryPath
    )

    $build = Test-ShieldDomeBuild -HostPath $HostPath -BuildMetadataPath $BuildMetadataPath
    $registrations = @(
        [pscustomobject]@{ Browser = "Chrome"; RegistryPath = $ChromeRegistryPath },
        [pscustomobject]@{ Browser = "Edge"; RegistryPath = $EdgeRegistryPath }
    )
    foreach ($registration in $registrations) {
        $manifestPath = New-ShieldDomeBrowserManifest -Browser $registration.Browser -ManifestRoot $ManifestRoot -Build $build
        New-Item -Path $registration.RegistryPath -Force | Out-Null
        Set-Item -LiteralPath $registration.RegistryPath -Value $manifestPath
    }
    return Get-ShieldDomeNativeHostStatus @PSBoundParameters
}

function Get-ShieldDomeNativeHostStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$HostPath,
        [Parameter(Mandatory = $true)][string]$BuildMetadataPath,
        [Parameter(Mandatory = $true)][string]$ManifestRoot,
        [Parameter(Mandatory = $true)][string]$ChromeRegistryPath,
        [Parameter(Mandatory = $true)][string]$EdgeRegistryPath
    )

    $build = Test-ShieldDomeBuild -HostPath $HostPath -BuildMetadataPath $BuildMetadataPath
    $browsers = @()
    foreach ($registration in @(
        [pscustomobject]@{ Browser = "Chrome"; RegistryPath = $ChromeRegistryPath },
        [pscustomobject]@{ Browser = "Edge"; RegistryPath = $EdgeRegistryPath }
    )) {
        $manifestPath = Join-Path (Join-Path (Get-ShieldDomeFullPath -Path $ManifestRoot) $registration.Browser) ("{0}.json" -f $build.identity.host_name)
        if (-not (Test-Path -LiteralPath $registration.RegistryPath)) {
            throw "$($registration.Browser) Native Messaging registration is missing."
        }
        $registeredPath = [string](Get-Item -LiteralPath $registration.RegistryPath).GetValue("")
        if ((Get-ShieldDomeFullPath -Path $registeredPath) -ine (Get-ShieldDomeFullPath -Path $manifestPath)) {
            throw "$($registration.Browser) Native Messaging registration points to an unexpected manifest."
        }
        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
            throw "$($registration.Browser) Native Messaging manifest is missing."
        }
        $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ([string]$manifest.name -cne [string]$build.identity.host_name -or
            [string]$manifest.type -cne "stdio" -or
            [string]$manifest.path -ine [string]$build.host_path -or
            @($manifest.allowed_origins).Count -ne 1 -or
            [string]@($manifest.allowed_origins)[0] -cne [string]$build.identity.extension_origin) {
            throw "$($registration.Browser) Native Messaging manifest is inconsistent."
        }
        $browsers += $registration.Browser
    }
    return [pscustomobject]@{
        ready = $true
        host_name = [string]$build.identity.host_name
        extension_id = [string]$build.identity.extension_id
        extension_origin = [string]$build.identity.extension_origin
        host_path = [string]$build.host_path
        browsers = $browsers
    }
}

function Uninstall-ShieldDomeNativeHost {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ManifestRoot,
        [Parameter(Mandatory = $true)][string]$ChromeRegistryPath,
        [Parameter(Mandatory = $true)][string]$EdgeRegistryPath
    )

    $identity = Get-ShieldDomeIdentity
    $refusals = @()
    $removed = @()
    foreach ($registration in @(
        [pscustomobject]@{ Browser = "Chrome"; RegistryPath = $ChromeRegistryPath },
        [pscustomobject]@{ Browser = "Edge"; RegistryPath = $EdgeRegistryPath }
    )) {
        $browserDirectory = Join-Path (Get-ShieldDomeFullPath -Path $ManifestRoot) $registration.Browser
        $manifestPath = Join-Path $browserDirectory ("{0}.json" -f $identity.host_name)
        $registryExists = Test-Path -LiteralPath $registration.RegistryPath
        $manifestExists = Test-Path -LiteralPath $manifestPath -PathType Leaf
        $owned = $true
        if ($registryExists) {
            $registeredPath = [string](Get-Item -LiteralPath $registration.RegistryPath).GetValue("")
            if ([string]::IsNullOrWhiteSpace($registeredPath) -or
                (Get-ShieldDomeFullPath -Path $registeredPath) -ine (Get-ShieldDomeFullPath -Path $manifestPath)) {
                $owned = $false
            }
        }
        if ($manifestExists) {
            try {
                $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
                if ([string]$manifest.name -cne [string]$identity.host_name -or
                    [string]$manifest.type -cne "stdio" -or
                    @($manifest.allowed_origins).Count -ne 1 -or
                    [string]@($manifest.allowed_origins)[0] -cne [string]$identity.extension_origin) {
                    $owned = $false
                }
            } catch {
                $owned = $false
            }
        }
        if (-not $owned) {
            $refusals += $registration.Browser
            continue
        }
        $removedOwnedItem = $registryExists -or $manifestExists
        if ($registryExists) {
            Remove-Item -LiteralPath $registration.RegistryPath -Force
        }
        if ($manifestExists) {
            Remove-Item -LiteralPath $manifestPath -Force
        }
        if (Test-Path -LiteralPath $browserDirectory -PathType Container) {
            if (@(Get-ChildItem -LiteralPath $browserDirectory -Force).Count -eq 0) {
                Remove-Item -LiteralPath $browserDirectory -Force
            }
        }
        if ($removedOwnedItem) {
            $removed += $registration.Browser
        }
    }
    $fullManifestRoot = Get-ShieldDomeFullPath -Path $ManifestRoot
    if (Test-Path -LiteralPath $fullManifestRoot -PathType Container) {
        if (@(Get-ChildItem -LiteralPath $fullManifestRoot -Force).Count -eq 0) {
            Remove-Item -LiteralPath $fullManifestRoot -Force
        }
    }
    if ($refusals.Count -ne 0) {
        throw "Refused to remove unowned Native Messaging registration: $($refusals -join ', ')."
    }
    return [pscustomobject]@{ removed = $removed; refused = @() }
}

Export-ModuleMember -Function @(
    "Get-ShieldDomeExtensionId",
    "Get-ShieldDomeIdentity",
    "Test-ShieldDomeBuild",
    "New-ShieldDomeBrowserManifest",
    "Install-ShieldDomeNativeHost",
    "Get-ShieldDomeNativeHostStatus",
    "Uninstall-ShieldDomeNativeHost"
)
