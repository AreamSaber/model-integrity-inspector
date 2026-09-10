$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'toolchain.ps1')
. (Join-Path $PSScriptRoot 'ci-policy.ps1')

$workspaceRoot = Split-Path -Parent $PSScriptRoot
$go = Resolve-MIIGo
$null = Resolve-MIINode
$null = Resolve-MIIPnpm
$requiredFiles = @(
    '.dockerignore',
    '.github\workflows\ci.yml',
    '.github\branch-protection\main.json',
    '.github\dependabot.yml',
    '.golangci.yml',
    '.syft.yaml',
    'Dockerfile',
    'scripts\apply-branch-protection.ps1',
    'scripts\ci-policy.ps1',
    'scripts\tests\test-m0-04-policy.ps1',
    'scripts\bootstrap-actionlint.ps1',
    'scripts\bootstrap-golangci-lint.ps1',
    'scripts\bootstrap-govulncheck.ps1',
    'scripts\bootstrap-syft.ps1',
    'scripts\generate-sbom.ps1',
    'scripts\lint.ps1',
    'scripts\package.ps1',
    'scripts\security-scan.ps1',
    'docs\operations\M0-04-CI-AND-BRANCH-PROTECTION.md',
    'docs\reviews\M0-04-review.md'
)

foreach ($relativePath in $requiredFiles) {
    $path = Join-Path $workspaceRoot $relativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required M0-04 file is missing: $relativePath" }
    if ((Get-Item -LiteralPath $path).Length -eq 0) { throw "Required M0-04 file is empty: $relativePath" }
}

Push-Location $workspaceRoot
try {
    $head = (& git rev-parse --verify HEAD | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $head -notmatch '^[0-9a-f]{40,64}$') { throw 'A valid Git HEAD is required.' }
    $worktreeStatus = (& git status --porcelain --untracked-files=normal | Out-String).Trim()
    if (-not [string]::IsNullOrWhiteSpace($worktreeStatus)) { throw 'M0-04 verification requires a clean Git worktree.' }
    foreach ($relativePath in $requiredFiles) {
        $gitPath = $relativePath -replace '\\', '/'
        & git ls-files --error-unmatch -- $gitPath *> $null
        if ($LASTEXITCODE -ne 0) { throw "Required M0-04 file is not tracked by Git: $relativePath" }
    }

    $workflowPath = Join-Path $workspaceRoot '.github\workflows\ci.yml'
    $workflow = Get-Content -Raw -Encoding UTF8 -LiteralPath $workflowPath
    foreach ($marker in @('push:', 'pull_request:', 'quality:', 'dependency-scan:', 'package:', 'image:', 'required:', 'name: m0-04-required')) {
        if (-not $workflow.Contains($marker)) { throw "CI workflow marker is missing: $marker" }
    }
    if ($workflow -match '(?m)^\s*pull_request_target\s*:') { throw 'CI must not use pull_request_target.' }
    if ($workflow -match '\$\{\{\s*secrets\.') { throw 'M0-04 CI must not consume repository secrets.' }
    if ($workflow -notmatch '(?ms)^permissions:\s*\r?\n\s+contents:\s*read\s*$') { throw 'CI permissions must default to contents: read.' }
    $actionReferences = [regex]::Matches($workflow, '(?m)^\s*uses:\s*[^@\s]+@(?<ref>[^\s#]+)')
    if ($actionReferences.Count -eq 0) { throw 'CI workflow has no action references.' }
    foreach ($actionReference in $actionReferences) {
        if ($actionReference.Groups['ref'].Value -notmatch '^[0-9a-f]{40}$') {
            throw "Action is not pinned to a full commit SHA: $($actionReference.Value.Trim())"
        }
    }
    Assert-MIICIVersions -Sources (Get-MIICIVersionSources -WorkspaceRoot $workspaceRoot)

    $policy = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $workspaceRoot '.github\branch-protection\main.json') | ConvertFrom-Json
    Assert-MIIBranchPolicy -Policy $policy

    $dockerfile = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $workspaceRoot 'Dockerfile')
    if ([regex]::Matches($dockerfile, '(?m)^FROM\s+\S+@sha256:[0-9a-f]{64}').Count -lt 2) { throw 'Docker build stages must pin base image digests.' }
    foreach ($label in @('org.opencontainers.image.version', 'org.opencontainers.image.revision', 'org.opencontainers.image.created')) {
        if (-not $dockerfile.Contains($label)) { throw "OCI image label is missing: $label" }
    }

    & (Join-Path $PSScriptRoot 'lint.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'Static checks failed.' }
    & (Join-Path $PSScriptRoot 'security-scan.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'Dependency vulnerability scans failed.' }
    & (Join-Path $PSScriptRoot 'package.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'Versioned packaging failed.' }
    & (Join-Path $PSScriptRoot 'generate-sbom.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'Local SBOM generation failed.' }

    $version = (Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $workspaceRoot 'VERSION')).Trim()
    $shortCommit = $head.Substring(0, 12)
    $goos = (& $go env GOOS | Out-String).Trim()
    $goarch = (& $go env GOARCH | Out-String).Trim()
    $artifactStem = "mii_${version}_${shortCommit}_${goos}_${goarch}"
    $manifestPath = Join-Path $workspaceRoot "artifacts\package\$artifactStem.manifest.json"
    $checksumPath = Join-Path $workspaceRoot "artifacts\package\$artifactStem.SHA256SUMS"
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or -not (Test-Path -LiteralPath $checksumPath -PathType Leaf)) {
        throw 'Package manifest or SHA256SUMS is missing.'
    }
    $manifest = Get-Content -Raw -Encoding UTF8 -LiteralPath $manifestPath | ConvertFrom-Json
    if ($manifest.version -ne $version -or $manifest.commit -ne $head -or $manifest.goos -ne $goos -or $manifest.goarch -ne $goarch) {
        throw 'Package manifest identity does not match VERSION, HEAD, or platform.'
    }
    foreach ($artifact in $manifest.artifacts) {
        $artifactPath = Join-Path (Split-Path -Parent $manifestPath) $artifact.file
        if (-not (Test-Path -LiteralPath $artifactPath -PathType Leaf)) { throw "Manifest artifact is missing: $($artifact.file)" }
        $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $artifactPath).Hash.ToLowerInvariant()
        if ($actualHash -ne $artifact.sha256) { throw "Manifest hash mismatch: $($artifact.file)" }
    }

    $sbomPath = Join-Path $workspaceRoot "artifacts\sbom\mii_${version}_${shortCommit}_source.cdx.json"
    if (-not (Test-Path -LiteralPath $sbomPath -PathType Leaf)) { throw 'Versioned CycloneDX SBOM is missing.' }
    $sbom = Get-Content -Raw -Encoding UTF8 -LiteralPath $sbomPath | ConvertFrom-Json
    if ($sbom.bomFormat -ne 'CycloneDX') { throw 'SBOM format is not CycloneDX.' }

    $rootMarkdown = Get-ChildItem -LiteralPath $workspaceRoot -File -Filter '*.md'
    $planPath = @($rootMarkdown | Where-Object { (Get-Content -Raw -Encoding UTF8 -LiteralPath $_.FullName) -match '(?m)^\| M0-01 \|' })[0].FullName
    $plan = Get-Content -Raw -Encoding UTF8 -LiteralPath $planPath
    $passed = -join [char[]](0x5DF2, 0x901A, 0x8FC7)
    $pendingReview = -join [char[]](0x5F85, 0x5BA1, 0x6838)
    $inProgress = -join [char[]](0x8FDB, 0x884C, 0x4E2D)
    $m003Row = [regex]::Match($plan, '(?m)^\| M0-03 \|.*$').Value
    $m004Row = [regex]::Match($plan, '(?m)^\| M0-04 \|.*$').Value
    $m003State = if ($m003Row.EndsWith("| $passed |")) { 'passed' } elseif ($m003Row.EndsWith("| $pendingReview |")) { 'pending-review' } else { throw 'M0-03 must be pending review or passed.' }
    $m004State = if ($m004Row.EndsWith("| $inProgress |")) { 'in-progress' } elseif ($m004Row.EndsWith("| $pendingReview |")) { 'pending-review' } elseif ($m004Row.EndsWith("| $passed |")) { 'passed' } else { throw 'M0-04 must be in progress, pending review, or passed.' }

    $remoteNames = @(& git remote)
    if ($remoteNames -contains 'origin') {
        $origin = (& git remote get-url origin | Out-String).Trim()
        $originState = if (-not [string]::IsNullOrWhiteSpace($origin)) { 'configured' } else { 'missing' }
    } else {
        $originState = 'missing'
    }
    $dockerState = if (Get-Command docker -ErrorAction SilentlyContinue) { 'available' } else { 'missing' }
} finally {
    Pop-Location
}

Write-Output 'M0-04 local verification passed.'
Write-Output "CI: triggers=push+pull_request, actionlint=passed, actions=$($actionReferences.Count)-sha-pinned, gate=m0-04-required"
Write-Output 'Quality: gofmt=passed, go-vet=passed, golangci-lint=passed, powershell=passed, oxlint=passed, tests=passed'
Write-Output 'Security: govulncheck=passed, pnpm-audit=passed, trivy=ci-defined'
Write-Output "Artifacts: version=$version, commit=$shortCommit, manifest=verified, checksums=present, sbom=cyclonedx"
Write-Output "External: origin=$originState, docker=$dockerState, branch-protection=not-verified-locally"
Write-Output "Task status: M0-03=$m003State, M0-04=$m004State"
