param([switch]$Force)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'toolchain.ps1')

$workspaceRoot = Split-Path -Parent $PSScriptRoot
$toolRoot = Join-Path $workspaceRoot '.tools'
$installRoot = Join-Path $toolRoot 'govulncheck'
$go = Resolve-MIIGo
$executableName = "govulncheck$(if ([IO.Path]::GetExtension($go) -eq '.exe') { '.exe' } else { '' })"
$govulncheckExecutable = Join-Path $installRoot $executableName

function Assert-GovulncheckVersion {
    $versionOutput = (& $govulncheckExecutable -version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $versionOutput -notmatch '(?m)^Scanner:\s*govulncheck@v1\.7\.0\s*$') {
        throw "Unexpected govulncheck version output: $versionOutput"
    }
}

if ((Test-Path -LiteralPath $govulncheckExecutable -PathType Leaf) -and -not $Force) {
    Assert-GovulncheckVersion
    Write-Output $govulncheckExecutable
    exit 0
}

if (Test-Path -LiteralPath $installRoot) {
    $resolvedToolRoot = [IO.Path]::GetFullPath($toolRoot).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $resolvedInstallRoot = [IO.Path]::GetFullPath($installRoot)
    if (-not $resolvedInstallRoot.StartsWith($resolvedToolRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing to replace govulncheck outside the workspace tool directory.'
    }
    Remove-Item -LiteralPath $resolvedInstallRoot -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $installRoot | Out-Null

$originalGoBin = $env:GOBIN
$originalPath = $env:PATH
$env:GOBIN = $installRoot
$env:PATH = "$(Split-Path -Parent $go)$([IO.Path]::PathSeparator)$originalPath"
try {
    & $go install golang.org/x/vuln/cmd/govulncheck@v1.7.0
    if ($LASTEXITCODE -ne 0) { throw 'Installing govulncheck v1.7.0 failed.' }
} finally {
    $env:GOBIN = $originalGoBin
    $env:PATH = $originalPath
}

Assert-GovulncheckVersion
Write-Output $govulncheckExecutable
