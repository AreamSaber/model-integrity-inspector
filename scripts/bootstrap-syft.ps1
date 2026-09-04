param([switch]$Force)

$ErrorActionPreference = 'Stop'
$workspaceRoot = Split-Path -Parent $PSScriptRoot
$toolRoot = Join-Path $workspaceRoot '.tools'
$cacheRoot = Join-Path $toolRoot 'cache'
$syftRoot = Join-Path $toolRoot 'syft'
$syftExecutable = Join-Path $syftRoot 'syft.exe'
$archivePath = Join-Path $cacheRoot 'syft_1.51.1_windows_amd64.zip'
$downloadUrl = 'https://github.com/anchore/syft/releases/download/v1.51.1/syft_1.51.1_windows_amd64.zip'
$expectedHash = '5e4bc3e6b6344b4625de0f7aa5351aaa72856d11d78462972de0a101ee2c1c8f'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'This bootstrap script installs the pinned Windows amd64 Syft binary. CI uses the pinned SBOM action on Linux.'
}

function Assert-SyftVersion {
    $versionOutput = (& $syftExecutable version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $versionOutput -notmatch '(?m)^Version:\s*1\.51\.1\s*$') {
        throw "Unexpected Syft version output: $versionOutput"
    }
}

function Remove-CheckedPath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$AllowedRoot,
        [switch]$Recurse
    )
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $resolvedAllowedRoot = [IO.Path]::GetFullPath($AllowedRoot).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $resolvedPath = [IO.Path]::GetFullPath($Path)
    if (-not $resolvedPath.StartsWith($resolvedAllowedRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a path outside $AllowedRoot."
    }
    Remove-Item -LiteralPath $resolvedPath -Force -Recurse:$Recurse
}

function Receive-SyftArchive {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $archivePath
}

if ((Test-Path -LiteralPath $syftExecutable -PathType Leaf) -and -not $Force) {
    Assert-SyftVersion
    exit 0
}

New-Item -ItemType Directory -Force -Path $cacheRoot | Out-Null
if ($Force) {
    Remove-CheckedPath -Path $archivePath -AllowedRoot $cacheRoot
}
if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
    Receive-SyftArchive
}

$actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash.ToLowerInvariant()
if ($actualHash -ne $expectedHash) {
    Write-Warning "Cached Syft archive checksum mismatch ($actualHash); downloading a clean copy."
    Remove-CheckedPath -Path $archivePath -AllowedRoot $cacheRoot
    Receive-SyftArchive
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        Remove-CheckedPath -Path $archivePath -AllowedRoot $cacheRoot
        throw "Downloaded Syft archive checksum mismatch: $actualHash"
    }
}

Remove-CheckedPath -Path $syftRoot -AllowedRoot $toolRoot -Recurse
New-Item -ItemType Directory -Force -Path $syftRoot | Out-Null
Expand-Archive -LiteralPath $archivePath -DestinationPath $syftRoot -Force
Assert-SyftVersion
