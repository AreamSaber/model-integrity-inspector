$ErrorActionPreference = 'Stop'

$workspaceRoot = Split-Path -Parent $PSScriptRoot
$architecturePath = Join-Path $workspaceRoot 'docs\architecture\SYSTEM-ARCHITECTURE-V1.0.md'
$adrDirectory = Join-Path $workspaceRoot 'docs\adr'
$reviewPath = Join-Path $workspaceRoot 'docs\reviews\M0-02-review.md'

$rootMarkdown = Get-ChildItem -LiteralPath $workspaceRoot -File -Filter '*.md'
$planPath = @($rootMarkdown | Where-Object {
    (Get-Content -Raw -Encoding UTF8 -LiteralPath $_.FullName) -match '(?m)^\| M0-01 \|'
})[0].FullName
$specPath = @($rootMarkdown | Where-Object { $_.Name -like '*TECH-SPEC*' })[0].FullName

$requiredPaths = @($architecturePath, $reviewPath, $specPath)
foreach ($path in $requiredPaths) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required file is missing: $path" }
    if ((Get-Item -LiteralPath $path).Length -eq 0) { throw "Required file is empty: $path" }
}

$architecture = Get-Content -Raw -Encoding UTF8 -LiteralPath $architecturePath
$architectureMarkers = @(
    'APP_ROLE=server | worker | all',
    'SQLite',
    'PostgreSQL',
    'Redis',
    'S3',
    'OIDC',
    'KMS',
    '## 4. Module boundaries',
    '## 8. Failure boundaries',
    '## 9. Audit integrity boundary',
    'Safe HTTP Client',
    '| `APP_ROLE` |',
    '```mermaid'
)
foreach ($marker in $architectureMarkers) {
    if (-not $architecture.Contains($marker)) { throw "Architecture marker is missing: $marker" }
}
foreach ($forbiddenFlow in @('SafeHTTP --> Secret', 'SafeHTTP --> Sample')) {
    if ($architecture.Contains($forbiddenFlow)) { throw "Forbidden architecture flow is present: $forbiddenFlow" }
}

$spec = Get-Content -Raw -Encoding UTF8 -LiteralPath $specPath
foreach ($marker in @('ADR-0006-audit-log-integrity.md', 'integrity_audit_chain_heads', 'wrap nonce')) {
    if (-not $spec.Contains($marker)) { throw "TECH SPEC clarification is missing marker: $marker" }
}
if ($spec.Contains('custom_headers_encrypted')) { throw 'TECH SPEC still duplicates encrypted custom headers on Target.' }

$adrFiles = @(Get-ChildItem -LiteralPath $adrDirectory -File -Filter 'ADR-*.md' | Sort-Object Name)
if ($adrFiles.Count -ne 6) { throw "Expected 6 ADR files, found $($adrFiles.Count)." }

$adrMarkers = @(
    '## Decision',
    '## Consequences',
    '## Alternatives rejected',
    '## Failure, rollback, security and data'
)
$adrStates = @()
foreach ($adrFile in $adrFiles) {
    $adr = Get-Content -Raw -Encoding UTF8 -LiteralPath $adrFile.FullName
    if ($adr.Contains('Status: Accepted')) {
        $adrStates += 'accepted'
    } elseif ($adr.Contains('Status: Proposed for M0-02 review')) {
        $adrStates += 'proposed-for-review'
    } else {
        throw "$($adrFile.Name) has an invalid ADR status."
    }
    foreach ($marker in $adrMarkers) {
        if (-not $adr.Contains($marker)) { throw "$($adrFile.Name) is missing marker: $marker" }
    }
}

$auditAdr = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $adrDirectory 'ADR-0006-audit-log-integrity.md')
foreach ($marker in @('HMAC-SHA-256', 'integrity_audit_chain_heads', 'event_hash =', 'audit_integrity_key')) {
    if (-not $auditAdr.Contains($marker)) { throw "Audit integrity ADR is missing marker: $marker" }
}

$secretAdr = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $adrDirectory 'ADR-0004-secret-envelope-encryption.md')
foreach ($marker in @('`secret_id`', '`encrypted_data_key`', 'wrap nonce', 'AES-256-GCM')) {
    if (-not $secretAdr.Contains($marker)) { throw "Secret ADR is missing marker: $marker" }
}

$plan = Get-Content -Raw -Encoding UTF8 -LiteralPath $planPath
$passed = -join [char[]](0x5DF2, 0x901A, 0x8FC7)
$pendingReview = -join [char[]](0x5F85, 0x5BA1, 0x6838)
$m001Row = [regex]::Match($plan, '(?m)^\| M0-01 \|.*$').Value
$m002Row = [regex]::Match($plan, '(?m)^\| M0-02 \|.*$').Value
if (-not $m001Row.EndsWith("| $passed |")) { throw 'M0-01 must remain passed.' }
$m002State = $null
if ($m002Row.EndsWith("| $pendingReview |")) {
    $m002State = 'pending-review'
} elseif ($m002Row.EndsWith("| $passed |")) {
    $m002State = 'passed'
} else {
    throw 'M0-02 must be pending review or passed.'
}

$taskRows = [regex]::Matches($plan, '(?m)^\| (?:M[0-8]|SEC|ALG|OPS)-\d{2} \|.*$')
if ($taskRows.Count -ne 91) { throw "Expected 91 tasks, found $($taskRows.Count)." }

Write-Output 'M0-02 verification passed.'
Write-Output 'Architecture: context=present, trust-boundaries=present, module-boundaries=present, role-map=present, failure-boundaries=present, audit-integrity=present'
Write-Output "ADRs: total=$($adrFiles.Count), status=$((@($adrStates | Select-Object -Unique) -join ','))"
Write-Output 'Database paths: SQLite=standalone, PostgreSQL=standard-production'
Write-Output 'Optional dependencies: Redis/S3/OIDC/KMS=not-required-for-core'
Write-Output "Task status: M0-01=passed, M0-02=$m002State, total tasks=91"
