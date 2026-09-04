$ErrorActionPreference = 'Stop'

$MIIExpectedGoVersion = 'go1.26.7'
$MIIExpectedNodeVersion = 'v24.19.0'
$MIIExpectedPnpmVersion = '11.19.0'

function Assert-MIIExactVersion {
    param(
        [Parameter(Mandatory)][string]$Tool,
        [Parameter(Mandatory)][string]$Actual,
        [Parameter(Mandatory)][string]$Expected
    )

    if ($Actual.Trim() -ne $Expected) {
        throw "$Tool version mismatch: expected $Expected, found $($Actual.Trim())."
    }
}

function Assert-MIIGoVersion {
    param([Parameter(Mandatory)][string]$Executable)

    $versionOutput = (& $Executable version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read Go version from $Executable."
    }
    $match = [regex]::Match($versionOutput, '^go version (go\d+\.\d+\.\d+)\s')
    if (-not $match.Success) {
        throw "Unexpected Go version output: $versionOutput"
    }
    Assert-MIIExactVersion -Tool 'Go' -Actual $match.Groups[1].Value -Expected $MIIExpectedGoVersion
}

function Assert-MIINodeVersion {
    param([Parameter(Mandatory)][string]$Executable)

    $versionOutput = (& $Executable --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read Node.js version from $Executable."
    }
    Assert-MIIExactVersion -Tool 'Node.js' -Actual $versionOutput -Expected $MIIExpectedNodeVersion
}

function Assert-MIIPnpmVersion {
    param([Parameter(Mandatory)][string]$Executable)

    $versionOutput = (& $Executable --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read pnpm version from $Executable."
    }
    Assert-MIIExactVersion -Tool 'pnpm' -Actual $versionOutput -Expected $MIIExpectedPnpmVersion
}

function Resolve-MIIGo {
    $workspaceRoot = Split-Path -Parent $PSScriptRoot
    $privateGo = Join-Path $workspaceRoot '.tools\go\bin\go.exe'
    if (Test-Path -LiteralPath $privateGo -PathType Leaf) {
        Assert-MIIGoVersion -Executable $privateGo
        return $privateGo
    }

    $command = Get-Command go -ErrorAction SilentlyContinue
    if ($command) {
        Assert-MIIGoVersion -Executable $command.Source
        return $command.Source
    }

    throw 'Go was not found. Run .\scripts\bootstrap-toolchain.ps1 first.'
}

function Resolve-MIINode {
    $command = Get-Command node -ErrorAction SilentlyContinue
    if ($command) {
        Assert-MIINodeVersion -Executable $command.Source
        return $command.Source
    }

    throw "Node.js was not found. Install Node.js $($MIIExpectedNodeVersion.TrimStart('v'))."
}

function Resolve-MIIPnpm {
    if ($env:MII_PNPM -and (Test-Path -LiteralPath $env:MII_PNPM -PathType Leaf)) {
        Assert-MIIPnpmVersion -Executable $env:MII_PNPM
        return $env:MII_PNPM
    }

    $command = Get-Command pnpm -ErrorAction SilentlyContinue
    if ($command) {
        Assert-MIIPnpmVersion -Executable $command.Source
        return $command.Source
    }

    $codexPnpm = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\bin\fallback\pnpm.cmd'
    if (Test-Path -LiteralPath $codexPnpm -PathType Leaf) {
        Assert-MIIPnpmVersion -Executable $codexPnpm
        return $codexPnpm
    }

    throw 'pnpm was not found. Install pnpm 11.19.0 or set MII_PNPM.'
}
