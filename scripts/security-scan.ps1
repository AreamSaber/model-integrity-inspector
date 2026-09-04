$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'toolchain.ps1')

$workspaceRoot = Split-Path -Parent $PSScriptRoot
$go = Resolve-MIIGo
$null = Resolve-MIINode
$pnpm = Resolve-MIIPnpm
$webRoot = Join-Path $workspaceRoot 'web'
$govulncheck = Join-Path $workspaceRoot ".tools\govulncheck\govulncheck$(if ([IO.Path]::GetExtension($go) -eq '.exe') { '.exe' } else { '' })"
if (-not (Test-Path -LiteralPath $govulncheck -PathType Leaf)) {
    $bootstrapOutput = @(& (Join-Path $PSScriptRoot 'bootstrap-govulncheck.ps1'))
    if ($LASTEXITCODE -ne 0) { throw 'govulncheck bootstrap failed.' }
}

$originalPath = $env:PATH
$env:PATH = "$(Split-Path -Parent $go)$([IO.Path]::PathSeparator)$originalPath"
Push-Location $workspaceRoot
try {
    & $govulncheck -test ./...
    if ($LASTEXITCODE -ne 0) { throw 'govulncheck found a reachable vulnerability or failed.' }
} finally {
    Pop-Location
    $env:PATH = $originalPath
}

$originalNodeOptions = $env:NODE_OPTIONS
$env:NODE_OPTIONS = "$originalNodeOptions --dns-result-order=ipv4first".Trim()
try {
    & $pnpm --dir $webRoot audit --audit-level high
    if ($LASTEXITCODE -ne 0) { throw 'pnpm audit found a high or critical vulnerability or failed.' }
} finally {
    $env:NODE_OPTIONS = $originalNodeOptions
}

Write-Output 'Dependency vulnerability checks passed: govulncheck, pnpm audit.'
