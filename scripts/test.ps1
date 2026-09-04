$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'toolchain.ps1')

$workspaceRoot = Split-Path -Parent $PSScriptRoot
$go = Resolve-MIIGo
$node = Resolve-MIINode
$pnpm = Resolve-MIIPnpm
$webRoot = Join-Path $workspaceRoot 'web'

& $pnpm --dir $webRoot install --frozen-lockfile
if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
& $pnpm --dir $webRoot test
if ($LASTEXITCODE -ne 0) { throw 'Frontend tests failed.' }

Push-Location $workspaceRoot
try {
    & $go test ./...
    if ($LASTEXITCODE -ne 0) { throw 'Go tests failed.' }
} finally {
    Pop-Location
}
