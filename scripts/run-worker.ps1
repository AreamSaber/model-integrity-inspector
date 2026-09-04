$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'toolchain.ps1')

$workspaceRoot = Split-Path -Parent $PSScriptRoot
$go = Resolve-MIIGo
$env:APP_ROLE = 'worker'
Push-Location $workspaceRoot
try {
    & $go run ./cmd/mii
} finally {
    Pop-Location
}
