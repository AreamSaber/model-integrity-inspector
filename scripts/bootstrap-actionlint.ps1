param([switch]$Force)

$ErrorActionPreference = 'Stop'
$workspaceRoot = Split-Path -Parent $PSScriptRoot
$toolRoot = Join-Path $workspaceRoot '.tools'
$cacheRoot = Join-Path $toolRoot 'cache'
$installRoot = Join-Path $toolRoot 'actionlint'
$isWindowsPlatform = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT

if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [Runtime.InteropServices.Architecture]::X64) {
    throw 'Pinned actionlint bootstrap currently supports amd64 runners only.'
}

if ($isWindowsPlatform) {
    $archiveName = 'actionlint_1.7.12_windows_amd64.zip'
    $expectedHash = '6e7241b51e6817ea6a047693d8e6fed13b31819c9a0dd6c5a726e1592d22f6e9'
    $executableName = 'actionlint.exe'
} else {
    $archiveName = 'actionlint_1.7.12_linux_amd64.tar.gz'
    $expectedHash = '8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8'
    $executableName = 'actionlint'
}

$archivePath = Join-Path $cacheRoot $archiveName
$downloadUrl = "https://github.com/rhysd/actionlint/releases/download/v1.7.12/$archiveName"
$actionlintExecutable = Join-Path $installRoot $executableName

function Assert-ActionlintVersion {
    $versionOutput = (& $actionlintExecutable -version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $versionOutput -notmatch '^1\.7\.12\s') {
        throw "Unexpected actionlint version output: $versionOutput"
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

function Receive-ActionlintArchive {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $archivePath
}

if ((Test-Path -LiteralPath $actionlintExecutable -PathType Leaf) -and -not $Force) {
    Assert-ActionlintVersion
    Write-Output $actionlintExecutable
    exit 0
}

New-Item -ItemType Directory -Force -Path $cacheRoot | Out-Null
if ($Force) {
    Remove-CheckedPath -Path $archivePath -AllowedRoot $cacheRoot
}
if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
    Receive-ActionlintArchive
}

$actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash.ToLowerInvariant()
if ($actualHash -ne $expectedHash) {
    Write-Warning "Cached actionlint archive checksum mismatch ($actualHash); downloading a clean copy."
    Remove-CheckedPath -Path $archivePath -AllowedRoot $cacheRoot
    Receive-ActionlintArchive
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        Remove-CheckedPath -Path $archivePath -AllowedRoot $cacheRoot
        throw "Downloaded actionlint archive checksum mismatch: $actualHash"
    }
}

Remove-CheckedPath -Path $installRoot -AllowedRoot $toolRoot -Recurse
New-Item -ItemType Directory -Force -Path $installRoot | Out-Null
if ($isWindowsPlatform) {
    Expand-Archive -LiteralPath $archivePath -DestinationPath $installRoot -Force
} else {
    & tar -xzf $archivePath -C $installRoot
    if ($LASTEXITCODE -ne 0) { throw 'Extracting actionlint failed.' }
}

if (-not (Test-Path -LiteralPath $actionlintExecutable -PathType Leaf)) {
    $nestedExecutable = Get-ChildItem -LiteralPath $installRoot -Recurse -File -Filter $executableName | Select-Object -First 1
    if (-not $nestedExecutable) { throw 'actionlint executable was not found in the verified archive.' }
    Copy-Item -LiteralPath $nestedExecutable.FullName -Destination $actionlintExecutable -Force
}
Assert-ActionlintVersion
Write-Output $actionlintExecutable
