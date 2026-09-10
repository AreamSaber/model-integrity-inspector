$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'toolchain.ps1')

$workspaceRoot = Split-Path -Parent $PSScriptRoot
$go = Resolve-MIIGo
$node = Resolve-MIINode
$pnpm = Resolve-MIIPnpm
$webRoot = Join-Path $workspaceRoot 'web'
$artifactRoot = Join-Path $workspaceRoot 'artifacts'

& $pnpm --dir $webRoot install --frozen-lockfile
if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
& $pnpm --dir $webRoot test
if ($LASTEXITCODE -ne 0) { throw 'Frontend tests failed.' }
& $pnpm --dir $webRoot build
if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }

Push-Location $workspaceRoot
try {
    # Independent database-heavy package binaries share the runner's disk.
    # Keep every test and its internal concurrency; schedule packages serially.
    & $go test -p 1 -count=1 ./...
    if ($LASTEXITCODE -ne 0) { throw 'Go tests failed.' }
    New-Item -ItemType Directory -Force -Path $artifactRoot | Out-Null
    & $go test -count=1 -tags webassets ./web ./internal/app
    if ($LASTEXITCODE -ne 0) { throw 'Embedded frontend integration tests failed.' }
    & $go build -tags webassets -trimpath -o (Join-Path $artifactRoot 'mii.exe') ./cmd/mii
    if ($LASTEXITCODE -ne 0) { throw 'Go build failed.' }
} finally {
    Pop-Location
}

Write-Output "Build completed: $(Join-Path $artifactRoot 'mii.exe')"
