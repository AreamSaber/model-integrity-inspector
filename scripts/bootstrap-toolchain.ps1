param([switch]$Force)

$ErrorActionPreference = 'Stop'
$workspaceRoot = Split-Path -Parent $PSScriptRoot
$toolRoot = Join-Path $workspaceRoot '.tools'
$goRoot = Join-Path $toolRoot 'go'
$goExecutable = Join-Path $goRoot 'bin\go.exe'
$cacheRoot = Join-Path $toolRoot 'cache'
$archivePath = Join-Path $cacheRoot 'go1.26.7.windows-amd64.zip'
$downloadUrl = 'https://go.dev/dl/go1.26.7.windows-amd64.zip'
$expectedHash = 'f4f534a486e4bc3387fa18f08208f2f854b7aaea8a08f2a2d829a914a05abb11'

function Remove-MIICachedArchive {
    if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
        return
    }

    $resolvedCacheRoot = [IO.Path]::GetFullPath($cacheRoot).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $resolvedArchivePath = [IO.Path]::GetFullPath($archivePath)
    if (-not $resolvedArchivePath.StartsWith($resolvedCacheRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing to remove an archive outside the workspace tool cache.'
    }
    Remove-Item -LiteralPath $resolvedArchivePath -Force
}

function Receive-MIIGoArchive {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $archivePath
}

if ((Test-Path -LiteralPath $goExecutable -PathType Leaf) -and -not $Force) {
    & $goExecutable version
    exit 0
}

New-Item -ItemType Directory -Force -Path $cacheRoot | Out-Null
if ($Force) {
    Remove-MIICachedArchive
}
if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
    Receive-MIIGoArchive
}

$actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash.ToLowerInvariant()
if ($actualHash -ne $expectedHash) {
    Write-Warning "Cached Go archive checksum mismatch ($actualHash); downloading a clean copy."
    Remove-MIICachedArchive
    Receive-MIIGoArchive
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        Remove-MIICachedArchive
        throw "Downloaded Go archive checksum mismatch: $actualHash"
    }
}

if (Test-Path -LiteralPath $goRoot) {
    $resolvedToolRoot = [IO.Path]::GetFullPath($toolRoot)
    $resolvedGoRoot = [IO.Path]::GetFullPath($goRoot)
    if (-not $resolvedGoRoot.StartsWith($resolvedToolRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing to replace Go outside the workspace tool directory.'
    }
    Remove-Item -LiteralPath $resolvedGoRoot -Recurse -Force
}

Expand-Archive -LiteralPath $archivePath -DestinationPath $toolRoot -Force
& $goExecutable version
