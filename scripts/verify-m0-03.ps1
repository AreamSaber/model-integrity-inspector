$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'toolchain.ps1')

$workspaceRoot = Split-Path -Parent $PSScriptRoot
$go = Resolve-MIIGo
$pnpm = Resolve-MIIPnpm
$node = Resolve-MIINode
$buildScript = Join-Path $PSScriptRoot 'build.ps1'

$requiredDirectories = @(
    'cmd\mii',
    'internal\integrity\api',
    'internal\integrity\domain',
    'internal\integrity\repository',
    'internal\integrity\secret',
    'internal\integrity\safehttp',
    'internal\integrity\adapter\openaichat',
    'internal\integrity\scheduler',
    'internal\integrity\worker',
    'internal\integrity\probe',
    'internal\integrity\tokenizer',
    'internal\integrity\feature',
    'internal\integrity\analyzer',
    'internal\integrity\scoring',
    'internal\integrity\baseline',
    'internal\integrity\report',
    'internal\integrity\audit',
    'internal\integrity\observability',
    'web\src\pages\Integrity',
    'web\src\components\Integrity',
    'migrations\sqlite',
    'migrations\postgresql',
    'rules\bundles',
    'tests\integration',
    'tests\mock-upstream',
    'tests\datasets',
    'deploy\standalone',
    'deploy\docker-compose'
)
foreach ($relativePath in $requiredDirectories) {
    $path = Join-Path $workspaceRoot $relativePath
    if (-not (Test-Path -LiteralPath $path -PathType Container)) {
        throw "Required directory is missing: $relativePath"
    }
}

$requiredFiles = @(
    '.gitignore',
    '.go-version',
    '.nvmrc',
    'VERSION',
    'README.md',
    'go.mod',
    'cmd\mii\main.go',
    'web\package.json',
    'web\pnpm-lock.yaml',
    'scripts\bootstrap-toolchain.ps1',
    'scripts\build.ps1',
    'scripts\test.ps1',
    'scripts\run-server.ps1',
    'scripts\run-worker.ps1',
    'scripts\run-web.ps1',
    'config\config.example.yaml',
    'docs\reviews\M0-03-review.md'
)
foreach ($relativePath in $requiredFiles) {
    $path = Join-Path $workspaceRoot $relativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required file is missing: $relativePath"
    }
    if ((Get-Item -LiteralPath $path).Length -eq 0) {
        throw "Required file is empty: $relativePath"
    }
}

Push-Location $workspaceRoot
try {
    $insideWorkTree = (& git rev-parse --is-inside-work-tree).Trim()
    if ($LASTEXITCODE -ne 0 -or $insideWorkTree -ne 'true') { throw 'Git repository is not initialized.' }
    $branch = (& git branch --show-current).Trim()
    if ($branch -ne 'main') { throw "Expected main branch, found $branch." }
    $head = (& git rev-parse --verify HEAD 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $head -notmatch '^[0-9a-f]{40,64}$') {
        throw 'Git repository has no valid baseline commit.'
    }
    foreach ($relativePath in $requiredFiles) {
        $gitPath = $relativePath -replace '\\', '/'
        & git ls-files --error-unmatch -- $gitPath *> $null
        if ($LASTEXITCODE -ne 0) {
            throw "Required file is not tracked by Git: $relativePath"
        }
    }

    $editorConfig = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $workspaceRoot '.editorconfig')
    if ($editorConfig -notmatch '(?ms)^\[\*\.ps1\]\s*\r?\n.*?^end_of_line\s*=\s*crlf\s*$') {
        throw 'EditorConfig must declare CRLF for PowerShell files.'
    }
    $gitAttributes = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $workspaceRoot '.gitattributes')
    if ($gitAttributes -notmatch '(?m)^\*\.ps1\s+text\s+eol=crlf\s*$') {
        throw 'Git attributes must declare CRLF for PowerShell files.'
    }

    $secretIgnoreCanaries = @(
        '.env',
        'sample.key',
        'sample.pem',
        'sample.p12',
        'sample.pfx',
        'sample.jks',
        'sample.keystore',
        'secrets/config.yaml',
        'secrets-production.yaml'
    )
    foreach ($secretPath in $secretIgnoreCanaries) {
        & git check-ignore -q -- $secretPath
        if ($LASTEXITCODE -ne 0) {
            throw "Secret path is not ignored by Git: $secretPath"
        }
    }

    $goModules = @(& $go list -m all)
    if ($LASTEXITCODE -ne 0) { throw 'go list -m all failed.' }
    if ($goModules.Count -ne 1 -or $goModules[0] -ne 'model-integrity-inspector.local/mii') {
        throw "Unexpected Go module dependency: $($goModules -join ', ')"
    }

    $packageJson = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $workspaceRoot 'web\package.json') | ConvertFrom-Json
    $expectedNodeEngine = $MIIExpectedNodeVersion.Substring(1)
    if ($packageJson.engines.node -ne $expectedNodeEngine) {
        throw "Frontend Node.js engine must be exactly $expectedNodeEngine."
    }
    if ($packageJson.engines.pnpm -ne $MIIExpectedPnpmVersion) {
        throw "Frontend pnpm engine must be exactly $MIIExpectedPnpmVersion."
    }
    if ($packageJson.packageManager -ne "pnpm@$MIIExpectedPnpmVersion") {
        throw "Frontend packageManager must be pnpm@$MIIExpectedPnpmVersion."
    }
    $directVersions = @($packageJson.dependencies.PSObject.Properties.Value) + @($packageJson.devDependencies.PSObject.Properties.Value)
    foreach ($version in $directVersions) {
        if ($version -notmatch '^\d+\.\d+\.\d+([+-][0-9A-Za-z.-]+)?$') {
            throw "Frontend dependency is not exact: $version"
        }
    }
    $lockfile = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $workspaceRoot 'web\pnpm-lock.yaml')
    if ($lockfile -match '(?m)^\s*(resolution: )?(file:|link:|workspace:|git\+)') {
        throw 'Frontend lockfile contains a local workspace or Git dependency.'
    }

    & $buildScript
    if ($LASTEXITCODE -ne 0) { throw 'One-command build failed.' }
    if (-not (Test-Path -LiteralPath (Join-Path $workspaceRoot 'artifacts\mii.exe') -PathType Leaf)) {
        throw 'Expected artifacts\mii.exe was not produced.'
    }
} finally {
    Pop-Location
}

$rootMarkdown = Get-ChildItem -LiteralPath $workspaceRoot -File -Filter '*.md'
$planPath = @($rootMarkdown | Where-Object {
    (Get-Content -Raw -Encoding UTF8 -LiteralPath $_.FullName) -match '(?m)^\| M0-01 \|'
})[0].FullName
$plan = Get-Content -Raw -Encoding UTF8 -LiteralPath $planPath
$passed = -join [char[]](0x5DF2, 0x901A, 0x8FC7)
$inProgress = -join [char[]](0x8FDB, 0x884C, 0x4E2D)
$pendingReview = -join [char[]](0x5F85, 0x5BA1, 0x6838)
$m001Row = [regex]::Match($plan, '(?m)^\| M0-01 \|.*$').Value
$m002Row = [regex]::Match($plan, '(?m)^\| M0-02 \|.*$').Value
$m003Row = [regex]::Match($plan, '(?m)^\| M0-03 \|.*$').Value
if (-not $m001Row.EndsWith("| $passed |")) { throw 'M0-01 must remain passed.' }
if (-not $m002Row.EndsWith("| $passed |")) { throw 'M0-02 must remain passed.' }

$m003State = $null
if ($m003Row.EndsWith("| $inProgress |")) {
    $m003State = 'in-progress'
} elseif ($m003Row.EndsWith("| $pendingReview |")) {
    $m003State = 'pending-review'
} elseif ($m003Row.EndsWith("| $passed |")) {
    $m003State = 'passed'
} else {
    throw 'M0-03 must be in progress, pending review, or passed.'
}

$goVersionOutput = (& $go version | Out-String).Trim()
$goVersionMatch = [regex]::Match($goVersionOutput, '^go version (go\d+\.\d+\.\d+)\s')
if (-not $goVersionMatch.Success) { throw "Unexpected Go version output: $goVersionOutput" }
Assert-MIIExactVersion -Tool 'Go' -Actual $goVersionMatch.Groups[1].Value -Expected $MIIExpectedGoVersion
$nodeVersion = (& $node --version | Out-String).Trim()
Assert-MIIExactVersion -Tool 'Node.js' -Actual $nodeVersion -Expected $MIIExpectedNodeVersion
$pnpmVersion = (& $pnpm --version | Out-String).Trim()
Assert-MIIExactVersion -Tool 'pnpm' -Actual $pnpmVersion -Expected $MIIExpectedPnpmVersion
$goVersion = $goVersionOutput -replace '^go version ', ''

Write-Output 'M0-03 verification passed.'
Write-Output "Repository: git=initialized, branch=$branch, head=present, required-files=tracked"
Write-Output "Structure: required-directories=$($requiredDirectories.Count), required-files=$($requiredFiles.Count)"
Write-Output "Toolchain: Go=$goVersion, Node=$nodeVersion, pnpm=$pnpmVersion"
Write-Output "Dependencies: Go modules=$($goModules.Count), frontend direct versions=exact, local business sources=none"
Write-Output "Repository policy: PowerShell=CRLF, secret-ignore-canaries=$($secretIgnoreCanaries.Count)"
Write-Output 'Build: frontend-test=passed, frontend-build=passed, go-test=passed, mii-binary=present'
Write-Output "Task status: M0-01=passed, M0-02=passed, M0-03=$m003State"
