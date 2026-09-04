$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'toolchain.ps1')

$workspaceRoot = Split-Path -Parent $PSScriptRoot
$node = Resolve-MIINode
$pnpm = Resolve-MIIPnpm
$webRoot = Join-Path $workspaceRoot 'web'

& $pnpm --dir $webRoot install --frozen-lockfile
if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
& $pnpm --dir $webRoot dev
