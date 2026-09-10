$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'toolchain.ps1')

$workspaceRoot = Split-Path -Parent $PSScriptRoot
$go = Resolve-MIIGo
$null = Resolve-MIINode
$pnpm = Resolve-MIIPnpm
$webRoot = Join-Path $workspaceRoot 'web'
$golangCILint = Join-Path $workspaceRoot ".tools\golangci-lint\golangci-lint$(if ([IO.Path]::GetExtension($go) -eq '.exe') { '.exe' } else { '' })"
if (-not (Test-Path -LiteralPath $golangCILint -PathType Leaf)) {
    $bootstrapOutput = @(& (Join-Path $PSScriptRoot 'bootstrap-golangci-lint.ps1'))
    if ($LASTEXITCODE -ne 0) { throw 'golangci-lint bootstrap failed.' }
}
$actionlint = Join-Path $workspaceRoot ".tools\actionlint\actionlint$(if ([IO.Path]::GetExtension($go) -eq '.exe') { '.exe' } else { '' })"
if (-not (Test-Path -LiteralPath $actionlint -PathType Leaf)) {
    $bootstrapOutput = @(& (Join-Path $PSScriptRoot 'bootstrap-actionlint.ps1'))
    if ($LASTEXITCODE -ne 0) { throw 'actionlint bootstrap failed.' }
}

$goFormatExecutable = Join-Path (Split-Path -Parent $go) $(if ([IO.Path]::GetExtension($go) -eq '.exe') { 'gofmt.exe' } else { 'gofmt' })
$goFiles = @(Get-ChildItem -LiteralPath (Join-Path $workspaceRoot 'cmd'), (Join-Path $workspaceRoot 'internal') -Recurse -File -Filter '*.go' | Select-Object -ExpandProperty FullName)
$unformatted = @(& $goFormatExecutable -l $goFiles)
if ($LASTEXITCODE -ne 0) { throw 'gofmt check failed.' }
if ($unformatted.Count -gt 0) {
    throw "Go files require gofmt: $($unformatted -join ', ')"
}

$syntaxErrors = @()
foreach ($script in Get-ChildItem -LiteralPath $PSScriptRoot -Recurse -File -Filter '*.ps1') {
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($script.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    foreach ($parseError in $errors) {
        $syntaxErrors += "$($script.Name):$($parseError.Extent.StartLineNumber): $($parseError.Message)"
    }
}
if ($syntaxErrors.Count -gt 0) {
    throw "PowerShell syntax check failed:`n$($syntaxErrors -join "`n")"
}

& (Join-Path $PSScriptRoot 'tests/test-m0-04-policy.ps1')
& (Join-Path $PSScriptRoot 'tests/test-race-shards.ps1')
& (Join-Path $PSScriptRoot 'tests/test-build-test-scheduling.ps1')

& $actionlint (Join-Path $workspaceRoot '.github\workflows\ci.yml')
if ($LASTEXITCODE -ne 0) { throw 'GitHub Actions workflow lint failed.' }

$originalPath = $env:PATH
$env:PATH = "$(Split-Path -Parent $go)$([IO.Path]::PathSeparator)$originalPath"
Push-Location $workspaceRoot
try {
    & $go vet ./...
    if ($LASTEXITCODE -ne 0) { throw 'go vet failed.' }
    & $golangCILint run --config .golangci.yml ./...
    if ($LASTEXITCODE -ne 0) { throw 'golangci-lint failed.' }
} finally {
    Pop-Location
    $env:PATH = $originalPath
}

& $pnpm --dir $webRoot install --frozen-lockfile
if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
& $pnpm --dir $webRoot lint
if ($LASTEXITCODE -ne 0) { throw 'Frontend lint failed.' }

Write-Output 'Static checks passed: gofmt, go vet, golangci-lint, PowerShell parser, actionlint, Oxlint.'
