param([switch]$Force)

$ErrorActionPreference = 'Stop'
$workspaceRoot = Split-Path -Parent $PSScriptRoot
$toolRoot = Join-Path $workspaceRoot '.tools'
$cacheRoot = Join-Path $toolRoot 'cache'
$installRoot = Join-Path $toolRoot 'golangci-lint'
$isWindowsPlatform = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT

if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [Runtime.InteropServices.Architecture]::X64) {
    throw 'Pinned golangci-lint bootstrap currently supports amd64 runners only.'
}

if ($isWindowsPlatform) {
    $archiveName = 'golangci-lint-2.13.2-windows-amd64.zip'
    $expectedHash = '4735fdc8e84a0cfb7a15a1c364a650942f88215e0d36c674ebc4024f7b554524'
    $executableName = 'golangci-lint.exe'
} else {
    $archiveName = 'golangci-lint-2.13.2-linux-amd64.tar.gz'
    $expectedHash = '2277d43b98ec0054280f2ac26b53268bae97682444678a59a657dd565da021d6'
    $executableName = 'golangci-lint'
}

$archivePath = Join-Path $cacheRoot $archiveName
$downloadUrl = "https://github.com/golangci/golangci-lint/releases/download/v2.13.2/$archiveName"
$lintExecutable = Join-Path $installRoot $executableName

function Assert-GolangCILintVersion {
    $versionOutput = (& $lintExecutable version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $versionOutput -notmatch '^golangci-lint has version 2\.13\.2\s') {
        throw "Unexpected golangci-lint version output: $versionOutput"
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

function Receive-LintArchive {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $archivePath
}

if ((Test-Path -LiteralPath $lintExecutable -PathType Leaf) -and -not $Force) {
    Assert-GolangCILintVersion
    Write-Output $lintExecutable
    exit 0
}

New-Item -ItemType Directory -Force -Path $cacheRoot | Out-Null
if ($Force) {
    Remove-CheckedPath -Path $archivePath -AllowedRoot $cacheRoot
}
if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
    Receive-LintArchive
}

$actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash.ToLowerInvariant()
if ($actualHash -ne $expectedHash) {
    Write-Warning "Cached golangci-lint archive checksum mismatch ($actualHash); downloading a clean copy."
    Remove-CheckedPath -Path $archivePath -AllowedRoot $cacheRoot
    Receive-LintArchive
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        Remove-CheckedPath -Path $archivePath -AllowedRoot $cacheRoot
        throw "Downloaded golangci-lint archive checksum mismatch: $actualHash"
    }
}

Remove-CheckedPath -Path $installRoot -AllowedRoot $toolRoot -Recurse
New-Item -ItemType Directory -Force -Path $installRoot | Out-Null
if ($isWindowsPlatform) {
    Expand-Archive -LiteralPath $archivePath -DestinationPath $installRoot -Force
} else {
    & tar -xzf $archivePath --strip-components=1 -C $installRoot
    if ($LASTEXITCODE -ne 0) { throw 'Extracting golangci-lint failed.' }
}

if (-not (Test-Path -LiteralPath $lintExecutable -PathType Leaf)) {
    $nestedExecutable = Get-ChildItem -LiteralPath $installRoot -Recurse -File -Filter $executableName | Select-Object -First 1
    if (-not $nestedExecutable) { throw 'golangci-lint executable was not found in the verified archive.' }
    Copy-Item -LiteralPath $nestedExecutable.FullName -Destination $lintExecutable -Force
}
Assert-GolangCILintVersion
Write-Output $lintExecutable
