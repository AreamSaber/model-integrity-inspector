$ErrorActionPreference = 'Stop'

$workspaceRoot = Split-Path -Parent $PSScriptRoot
$rootMarkdown = Get-ChildItem -LiteralPath $workspaceRoot -File -Filter '*.md'
$prdPath = @($rootMarkdown | Where-Object { $_.Name -like '*PRD*' })[0].FullName
$specPath = @($rootMarkdown | Where-Object { $_.Name -like '*TECH-SPEC*' })[0].FullName
$planPath = @($rootMarkdown | Where-Object {
    (Get-Content -Raw -Encoding UTF8 -LiteralPath $_.FullName) -match '(?m)^\| M0-01 \|'
})[0].FullName

$takeoverPath = @(Get-ChildItem -LiteralPath (Join-Path $workspaceRoot 'docs\project') -File -Filter '*.md')[0].FullName
$decisionPath = @(Get-ChildItem -LiteralPath (Join-Path $workspaceRoot 'docs\decisions') -File -Filter '*.md')[0].FullName
$scopePath = @(Get-ChildItem -LiteralPath (Join-Path $workspaceRoot 'docs\baselines') -File -Filter '*.md')[0].FullName
$reviewPath = @(Get-ChildItem -LiteralPath (Join-Path $workspaceRoot 'docs\reviews') -File -Filter 'M0-01*.md')[0].FullName

$requiredPaths = @(
    $prdPath,
    $specPath,
    $planPath,
    $takeoverPath,
    $decisionPath,
    $scopePath,
    $reviewPath
)

foreach ($path in $requiredPaths) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required file is missing: $path"
    }
    if ((Get-Item -LiteralPath $path).Length -eq 0) {
        throw "Required file is empty: $path"
    }
}

$prd = Get-Content -Raw -Encoding UTF8 -LiteralPath $prdPath
$spec = Get-Content -Raw -Encoding UTF8 -LiteralPath $specPath
$plan = Get-Content -Raw -Encoding UTF8 -LiteralPath $planPath
$decision = Get-Content -Raw -Encoding UTF8 -LiteralPath $decisionPath
$scope = Get-Content -Raw -Encoding UTF8 -LiteralPath $scopePath

$requirementPattern = '(?m)^\| (SYS|TAR|RUN|PINJ|MTOK|RINT|BASE|REP|HIS|CFG)-\d{3} \|.*\| (P0|P1|P2) \|$'
$requirements = [regex]::Matches($prd, $requirementPattern)
$priorityCounts = @{}
foreach ($priority in @('P0', 'P1', 'P2')) {
    $priorityCounts[$priority] = @($requirements | Where-Object { $_.Groups[2].Value -eq $priority }).Count
}

if ($requirements.Count -ne 77) { throw "Expected 77 PRD requirements, found $($requirements.Count)." }
if ($priorityCounts['P0'] -ne 59) { throw "Expected 59 P0 requirements, found $($priorityCounts['P0'])." }
if ($priorityCounts['P1'] -ne 17) { throw "Expected 17 P1 requirements, found $($priorityCounts['P1'])." }
if ($priorityCounts['P2'] -ne 1) { throw "Expected 1 P2 requirement, found $($priorityCounts['P2'])." }

$milestoneTasks = [regex]::Matches($plan, '(?m)^\| M[0-8]-\d{2} \|')
$specialTasks = [regex]::Matches($plan, '(?m)^\| (SEC|ALG|OPS)-\d{2} \|')
if ($milestoneTasks.Count -ne 79) { throw "Expected 79 milestone tasks, found $($milestoneTasks.Count)." }
if ($specialTasks.Count -ne 12) { throw "Expected 12 special tasks, found $($specialTasks.Count)." }

if ($prd -notmatch '(?m)^## 19\.') { throw 'PRD frozen-decision section was not found.' }
if ($spec -notmatch '(?m)^## 24\.') { throw 'TECH SPEC frozen-decision section was not found.' }

$frozen = -join [char[]](0x51BB, 0x7ED3, 0x7248)
if (-not $prd.Substring(0, [Math]::Min(300, $prd.Length)).Contains("V1.0 $frozen")) { throw 'PRD is not frozen.' }
if (-not $spec.Substring(0, [Math]::Min(300, $spec.Length)).Contains("V1.0 $frozen")) { throw 'TECH SPEC is not frozen.' }

$approved = -join [char[]](0x5DF2, 0x6279, 0x51C6)
$decisionRows = [regex]::Matches($decision, '(?m)^\| DEC-\d{3} \|.*$')
$approvedDecisions = @($decisionRows | Where-Object { $_.Value.EndsWith("| $approved |") })
if ($decisionRows.Count -ne 16 -or $approvedDecisions.Count -ne 16) { throw 'All 16 decisions must be approved.' }

$frozenBaseline = -join [char[]](0x51BB, 0x7ED3, 0x57FA, 0x7EBF)
if (-not $scope.Substring(0, [Math]::Min(300, $scope.Length)).Contains("V1.0 $frozenBaseline")) { throw 'Scope baseline is not frozen.' }

$passed = -join [char[]](0x5DF2, 0x901A, 0x8FC7)
$m0Row = [regex]::Match($plan, '(?m)^\| M0-01 \|.*$').Value
if (-not $m0Row.EndsWith("| $passed |")) { throw 'M0-01 is not marked as passed.' }

$taskRows = [regex]::Matches($plan, '(?m)^\| (?:M[0-8]|SEC|ALG|OPS)-\d{2} \|.*$')
if ($taskRows.Count -ne 91) { throw "Expected 91 tasks, found $($taskRows.Count)." }

Write-Output 'M0-01 verification passed.'
Write-Output "PRD requirements: total=$($requirements.Count), P0=$($priorityCounts['P0']), P1=$($priorityCounts['P1']), P2=$($priorityCounts['P2'])"
Write-Output "Plan tasks: milestones=$($milestoneTasks.Count), specials=$($specialTasks.Count), total=$($milestoneTasks.Count + $specialTasks.Count)"
Write-Output 'Decisions: approved=16, PRD=V1.0 frozen, TECH-SPEC=V1.0 frozen, scope=V1.0 frozen'
Write-Output 'Task status: M0-01=passed, total tasks=91'
Write-Output "Verified files: $($requiredPaths.Count)"
