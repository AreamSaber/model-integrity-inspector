$ErrorActionPreference = 'Stop'
$scriptsRoot = Split-Path -Parent $PSScriptRoot
$workspaceRoot = Split-Path -Parent $scriptsRoot
. (Join-Path $scriptsRoot 'ci-policy.ps1')

$script:policyTestCount = 0
function Test-MIIPolicyCase {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][scriptblock]$Test, [switch]$MustFail, [string]$ErrorPattern)
    $caught = $null
    try { & $Test } catch { $caught = $_ }
    if ($MustFail -and $null -eq $caught) { throw "FAIL: $Name accepted an invalid configuration." }
    if ($MustFail -and $ErrorPattern -and $caught.Exception.Message -notmatch $ErrorPattern) { throw "FAIL: $Name failed for the wrong reason: $caught" }
    if (-not $MustFail -and $null -ne $caught) { throw "FAIL: $Name failed: $caught" }
    $script:policyTestCount++
}

$sources = Get-MIICIVersionSources -WorkspaceRoot $workspaceRoot
Test-MIIPolicyCase 'actual repository tool sources' { Assert-MIICIVersions -Sources $sources }
foreach ($case in @(
    @{ Name = 'missing required repository matrix dependency'; Old = 'needs: [quality, repository-race, worker-race, identity-postgres-race, dependency-scan, package, image]'; New = 'needs: [quality, worker-race, identity-postgres-race, dependency-scan, package, image]' },
    @{ Name = 'missing required Worker matrix dependency'; Old = 'needs: [quality, repository-race, worker-race, identity-postgres-race, dependency-scan, package, image]'; New = 'needs: [quality, repository-race, identity-postgres-race, dependency-scan, package, image]' },
    @{ Name = 'missing required PostgreSQL identity dependency'; Old = 'needs: [quality, repository-race, worker-race, identity-postgres-race, dependency-scan, package, image]'; New = 'needs: [quality, repository-race, worker-race, dependency-scan, package, image]' },
    @{ Name = 'one missing race matrix shard'; Old = 'shard: [0, 1, 2, 3, 4, 5]'; New = 'shard: [0, 1, 2, 3, 4]' },
    @{ Name = 'duplicate race matrix shard'; Old = 'shard: [0, 1, 2, 3, 4, 5]'; New = 'shard: [0, 1, 2, 3, 4, 4]' },
    @{ Name = 'race matrix cancels siblings on failure'; Old = "repository-race-`${{ matrix.shard }}`r`n    strategy:`r`n      fail-fast: false"; New = "repository-race-`${{ matrix.shard }}`r`n    strategy:`r`n      fail-fast: true" },
    @{ Name = 'race matrix can exclude shard'; Old = 'shard: [0, 1, 2, 3, 4, 5]'; New = "shard: [0, 1, 2, 3, 4, 5]`n        exclude: [{shard: 0}]" },
    @{ Name = 'quality omits remaining race packages'; Old = 'run: ./scripts/test-race.ps1 -Group Core'; New = 'run: echo omitted' },
    @{ Name = 'quality uses unknown race group'; Old = 'run: ./scripts/test-race.ps1 -Group Core'; New = 'run: ./scripts/test-race.ps1 -Group Unknown' },
    @{ Name = 'repository matrix always executes one shard'; Old = 'run: ./scripts/test-race.ps1 -Group Repository -Shard ${{ matrix.shard }}'; New = 'run: ./scripts/test-race.ps1 -Group Repository -Shard 0' },
    @{ Name = 'required gate may be skipped after failure'; Old = 'if: always()'; New = 'if: success()' },
    @{ Name = 'required gate ignores matrix result'; Old = '"$QUALITY" "$REPOSITORY_RACE" "$WORKER_RACE"'; New = '"$QUALITY" "$WORKER_RACE"' },
    @{ Name = 'required gate ignores Worker result'; Old = '"$REPOSITORY_RACE" "$WORKER_RACE" "$IDENTITY_POSTGRES_RACE"'; New = '"$REPOSITORY_RACE" "$IDENTITY_POSTGRES_RACE"' },
    @{ Name = 'required gate ignores PostgreSQL identity result'; Old = '"$WORKER_RACE" "$IDENTITY_POSTGRES_RACE" "$DEPENDENCY_SCAN"'; New = '"$WORKER_RACE" "$DEPENDENCY_SCAN"' },
    @{ Name = 'required gate ignores failed result'; Old = 'test "$result" = "success" || exit 1'; New = 'test "$result" = "success" || exit 0' },
    @{ Name = 'required gate bound to literal success'; Old = 'REPOSITORY_RACE: ${{ needs.repository-race.result }}'; New = 'REPOSITORY_RACE: success' },
    @{ Name = 'Worker result replaced by literal success'; Old = 'WORKER_RACE: ${{ needs.worker-race.result }}'; New = 'WORKER_RACE: success' },
    @{ Name = 'PostgreSQL identity result replaced by literal success'; Old = 'IDENTITY_POSTGRES_RACE: ${{ needs.identity-postgres-race.result }}'; New = 'IDENTITY_POSTGRES_RACE: success' },
    @{ Name = 'Worker always executes shard zero'; Old = 'run: ./scripts/test-race.ps1 -Group Worker -Shard ${{ matrix.shard }}'; New = 'run: ./scripts/test-race.ps1 -Group Worker -Shard 0' },
    @{ Name = 'PostgreSQL identity replaced by default Core'; Old = 'run: ./scripts/test-race.ps1 -Group IdentityPostgres'; New = 'run: ./scripts/test-race.ps1 -Group Core' },
    @{ Name = 'failed matrix is marked nonfatal'; Old = 'name: repository-race-${{ matrix.shard }}'; New = "name: repository-race-`${{ matrix.shard }}`n    continue-on-error: true" }
)) {
    $workflow = $sources['.github/workflows/ci.yml'] -replace '\r\n', "`n"
    $old = $case.Old -replace '\r\n', "`n"
    $offset = $workflow.IndexOf($old, [StringComparison]::Ordinal)
    if ($offset -lt 0) { throw "Mutation target missing: $($case.Name)" }
    $changedWorkflow = $workflow.Remove($offset, $old.Length).Insert($offset, ($case.New -replace '\r\n', "`n"))
    Test-MIIPolicyCase $case.Name -MustFail -ErrorPattern 'race|Race|Required|required|six|six|success|CI' {
        Assert-MIIRaceWorkflow -Workflow $changedWorkflow
    }
}

# Scope mutations to the actual Worker or identity job, so the already-present
# repository matrix cannot accidentally satisfy a new task's requirement.
foreach ($jobName in @('worker-race', 'identity-postgres-race')) {
    $workflow = $sources['.github/workflows/ci.yml'] -replace '\r\n', "`n"
    $body = Get-MIIExplicitWorkflowJob -Workflow $workflow -Name $jobName
    $mutations = @(
        @{ Name = 'job silently skipped'; Old = '    runs-on: ubuntu-24.04'; New = "    runs-on: ubuntu-24.04`n    if: false" },
        @{ Name = 'job limit raised'; Old = '    timeout-minutes: 25'; New = '    timeout-minutes: 30' },
        @{ Name = 'native race host changed'; Old = '    runs-on: ubuntu-24.04'; New = '    runs-on: windows-2025' },
        @{ Name = 'race step conditionally skipped'; Old = '        run: ./scripts/test-race.ps1'; New = "        if: false`n        run: ./scripts/test-race.ps1" },
        @{ Name = 'isolated service omitted'; Old = '    services:'; New = '    services-disabled:' }
    )
    if ($jobName -ceq 'worker-race') {
        $mutations += @(
            @{ Name = 'one Worker shard missing'; Old = 'shard: [0, 1, 2, 3, 4, 5]'; New = 'shard: [0, 1, 2, 3, 4]' },
            @{ Name = 'one Worker shard duplicated'; Old = 'shard: [0, 1, 2, 3, 4, 5]'; New = 'shard: [0, 1, 2, 3, 4, 4]' },
            @{ Name = 'Worker sibling cancelled'; Old = 'fail-fast: false'; New = 'fail-fast: true' },
            @{ Name = 'Worker matrix excludes parent'; Old = 'shard: [0, 1, 2, 3, 4, 5]'; New = "shard: [0, 1, 2, 3, 4, 5]`n        exclude: [{shard: 0}]" }
        )
    }
    foreach ($mutation in $mutations) {
        $offset = $body.IndexOf($mutation.Old, [StringComparison]::Ordinal)
        if ($offset -lt 0) { throw "Mutation target missing in ${jobName}: $($mutation.Name)" }
        $changedBody = $body.Remove($offset, $mutation.Old.Length).Insert($offset, $mutation.New)
        $changedWorkflow = $workflow.Replace($body, $changedBody)
        Test-MIIPolicyCase "$jobName $($mutation.Name)" -MustFail -ErrorPattern 'race|Race|Required|required|six|success|CI' {
            Assert-MIIRaceWorkflow -Workflow $changedWorkflow
        }
    }
}
Test-MIIPolicyCase 'verifier literals cannot replace tool sources' -MustFail {
    Assert-MIICIVersions -Sources @{ 'scripts/verify-m0-04.ps1' = Get-Content -Raw -LiteralPath (Join-Path $scriptsRoot 'verify-m0-04.ps1') }
}
foreach ($sourcePath in $sources.Keys) {
    Test-MIIPolicyCase "missing authoritative file $sourcePath" -MustFail {
        $changed = $sources.Clone()
        $changed.Remove($sourcePath)
        Assert-MIICIVersions -Sources $changed
    }
}

foreach ($case in @(
    @{ Name = 'Go CI version'; File = '.github/workflows/ci.yml'; Old = 'GO_VERSION: 1.26.7'; New = 'GO_VERSION: 1.26.8' },
    @{ Name = 'Node CI version'; File = '.github/workflows/ci.yml'; Old = 'NODE_VERSION: 24.19.0'; New = 'NODE_VERSION: 24.20.0' },
    @{ Name = 'pnpm CI version'; File = '.github/workflows/ci.yml'; Old = 'PNPM_VERSION: 11.19.0'; New = 'PNPM_VERSION: 11.20.0' },
    @{ Name = 'pnpm install ignores pinned environment'; File = '.github/workflows/ci.yml'; Old = 'run: npm install --global "pnpm@${PNPM_VERSION}"'; New = 'run: npm install --global "pnpm@latest"' },
    @{ Name = 'one of two Trivy actions'; File = '.github/workflows/ci.yml'; Old = 'version: v0.74.0'; New = 'version: v0.74.1' },
    @{ Name = 'one missing Syft action pin'; File = '.github/workflows/ci.yml'; Old = 'syft-version: v1.51.1'; New = '# syft-version: v1.51.1' },
    @{ Name = 'duplicate Trivy pin'; File = '.github/workflows/ci.yml'; Old = 'version: v0.74.0'; New = "version: v0.74.0`n          version: v0.74.1" },
    @{ Name = 'setup-go not using pinned environment'; File = '.github/workflows/ci.yml'; Old = 'go-version: ${{ env.GO_VERSION }}'; New = 'go-version: stable' },
    @{ Name = 'setup-node not using pinned environment'; File = '.github/workflows/ci.yml'; Old = 'node-version: ${{ env.NODE_VERSION }}'; New = 'node-version: latest' },
    @{ Name = 'Go local expected version'; File = 'scripts/toolchain.ps1'; Old = "`$MIIExpectedGoVersion = 'go1.26.7'"; New = "`$MIIExpectedGoVersion = 'go1.26.8'" },
    @{ Name = 'Node local expected version'; File = 'scripts/toolchain.ps1'; Old = "`$MIIExpectedNodeVersion = 'v24.19.0'"; New = "`$MIIExpectedNodeVersion = 'v24.20.0'" },
    @{ Name = 'pnpm local expected version'; File = 'scripts/toolchain.ps1'; Old = "`$MIIExpectedPnpmVersion = '11.19.0'"; New = "`$MIIExpectedPnpmVersion = '11.20.0'" },
    @{ Name = 'golangci-lint URL but old archive names remain'; File = 'scripts/bootstrap-golangci-lint.ps1'; Old = '/download/v2.13.2/'; New = '/download/v2.13.3/' },
    @{ Name = 'golangci-lint Windows archive'; File = 'scripts/bootstrap-golangci-lint.ps1'; Old = 'golangci-lint-2.13.2-windows-amd64.zip'; New = 'golangci-lint-2.13.3-windows-amd64.zip' },
    @{ Name = 'golangci-lint Linux archive'; File = 'scripts/bootstrap-golangci-lint.ps1'; Old = 'golangci-lint-2.13.2-linux-amd64.tar.gz'; New = 'golangci-lint-2.13.3-linux-amd64.tar.gz' },
    @{ Name = 'govulncheck install but old version assertion remains'; File = 'scripts/bootstrap-govulncheck.ps1'; Old = 'install golang.org/x/vuln/cmd/govulncheck@v1.7.0'; New = 'install golang.org/x/vuln/cmd/govulncheck@v1.8.0' },
    @{ Name = 'govulncheck removed install'; File = 'scripts/bootstrap-govulncheck.ps1'; Old = '& $go install golang.org/x/vuln/cmd/govulncheck@v1.7.0'; New = '# & $go install golang.org/x/vuln/cmd/govulncheck@v1.7.0' },
    @{ Name = 'actionlint actual URL'; File = 'scripts/bootstrap-actionlint.ps1'; Old = '/download/v1.7.12/'; New = '/download/v1.7.13/' },
    @{ Name = 'Syft actual URL'; File = 'scripts/bootstrap-syft.ps1'; Old = '/download/v1.51.1/'; New = '/download/v1.51.2/' }
)) {
    $offset = $sources[$case.File].IndexOf($case.Old, [StringComparison]::Ordinal)
    if ($offset -lt 0) { throw "Test mutation target not found: $($case.Name)" }
    Test-MIIPolicyCase $case.Name -MustFail {
        $changed = $sources.Clone()
        # Replace only one occurrence; old values elsewhere and in comments must not satisfy the guard.
        $changed[$case.File] = $changed[$case.File].Remove($offset, $case.Old.Length).Insert($offset, $case.New) + "`n# Previous setting: $($case.Old)`n"
        Assert-MIICIVersions -Sources $changed
    }
}

$policyJSON = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $workspaceRoot '.github/branch-protection/main.json')
Test-MIIPolicyCase 'actual request policy' { Assert-MIIBranchPolicy -Policy ($policyJSON | ConvertFrom-Json) }
# Sanitized shape of the real GitHub GET response, independently specified, not produced by the validator.
$appliedJSON = @'
{
  "required_status_checks": { "strict": true, "contexts": ["m0-04-required"], "checks": [{"context": "m0-04-required", "app_id": 15368}] },
  "required_pull_request_reviews": { "dismiss_stale_reviews": true, "require_code_owner_reviews": false, "require_last_push_approval": true, "required_approving_review_count": 1 },
  "enforce_admins": { "enabled": true },
  "required_linear_history": { "enabled": true },
  "allow_force_pushes": { "enabled": false },
  "allow_deletions": { "enabled": false },
  "block_creations": { "enabled": false },
  "required_conversation_resolution": { "enabled": true },
  "lock_branch": { "enabled": false },
  "allow_fork_syncing": { "enabled": false }
}
'@
Test-MIIPolicyCase 'real response shape without disabled restrictions' { Assert-MIIBranchPolicy -Policy ($appliedJSON | ConvertFrom-Json) -Applied }
Test-MIIPolicyCase 'response with explicit null restrictions' {
    $changed = $appliedJSON | ConvertFrom-Json
    $changed | Add-Member -NotePropertyName restrictions -NotePropertyValue $null
    Assert-MIIBranchPolicy -Policy $changed -Applied
}
Test-MIIPolicyCase 'legacy unsafe response still contains required context' -MustFail {
    Assert-MIIBranchPolicy -Applied -Policy ('{"required_status_checks":{"contexts":["m0-04-required"],"strict":false},"enforce_admins":{"enabled":false},"required_pull_request_reviews":{"required_approving_review_count":0},"allow_force_pushes":{"enabled":true},"allow_deletions":{"enabled":true}}' | ConvertFrom-Json)
}
foreach ($field in @('enforce_admins', 'required_linear_history', 'allow_force_pushes', 'allow_deletions',
    'block_creations', 'required_conversation_resolution', 'lock_branch', 'allow_fork_syncing')) {
    Test-MIIPolicyCase "changed remote $field" -MustFail {
        $changed = $appliedJSON | ConvertFrom-Json
        $changed.$field.enabled = -not $changed.$field.enabled
        Assert-MIIBranchPolicy -Policy $changed -Applied
    }
    Test-MIIPolicyCase "missing remote $field" -MustFail {
        $changed = $appliedJSON | ConvertFrom-Json
        $changed.PSObject.Properties.Remove($field)
        Assert-MIIBranchPolicy -Policy $changed -Applied
    }
    Test-MIIPolicyCase "missing remote $field.enabled" -MustFail {
        $changed = $appliedJSON | ConvertFrom-Json
        $changed.$field.PSObject.Properties.Remove('enabled')
        Assert-MIIBranchPolicy -Policy $changed -Applied
    }
    Test-MIIPolicyCase "changed local $field" -MustFail {
        $changed = $policyJSON | ConvertFrom-Json
        $changed.$field = -not $changed.$field
        Assert-MIIBranchPolicy -Policy $changed
    }
}
foreach ($field in @('dismiss_stale_reviews', 'require_last_push_approval', 'require_code_owner_reviews')) {
    Test-MIIPolicyCase "changed review $field" -MustFail {
        $changed = $appliedJSON | ConvertFrom-Json
        $changed.required_pull_request_reviews.$field = -not $changed.required_pull_request_reviews.$field
        Assert-MIIBranchPolicy -Policy $changed -Applied
    }
    Test-MIIPolicyCase "missing review $field" -MustFail {
        $changed = $appliedJSON | ConvertFrom-Json
        $changed.required_pull_request_reviews.PSObject.Properties.Remove($field)
        Assert-MIIBranchPolicy -Policy $changed -Applied
    }
}
foreach ($count in @(0, 2, '1', $null)) {
    Test-MIIPolicyCase "changed approval count [$count]" -MustFail {
        $changed = $appliedJSON | ConvertFrom-Json
        $changed.required_pull_request_reviews.required_approving_review_count = $count
        Assert-MIIBranchPolicy -Policy $changed -Applied
    }
}
foreach ($appID in @(-1, 999, '15368', $null)) {
    Test-MIIPolicyCase "wrong status check app [$appID]" -MustFail {
        $changed = $appliedJSON | ConvertFrom-Json
        $changed.required_status_checks.checks[0].app_id = $appID
        Assert-MIIBranchPolicy -Policy $changed -Applied
    }
}
foreach ($field in @('checks', 'contexts', 'strict')) {
    Test-MIIPolicyCase "missing required status $field" -MustFail {
        $changed = $appliedJSON | ConvertFrom-Json
        $changed.required_status_checks.PSObject.Properties.Remove($field)
        Assert-MIIBranchPolicy -Policy $changed -Applied
    }
}
foreach ($field in @('context', 'app_id')) {
    Test-MIIPolicyCase "missing bound check $field" -MustFail {
        $changed = $appliedJSON | ConvertFrom-Json
        $changed.required_status_checks.checks[0].PSObject.Properties.Remove($field)
        Assert-MIIBranchPolicy -Policy $changed -Applied
    }
}
Test-MIIPolicyCase 'missing approval count' -MustFail {
    $changed = $appliedJSON | ConvertFrom-Json
    $changed.required_pull_request_reviews.PSObject.Properties.Remove('required_approving_review_count')
    Assert-MIIBranchPolicy -Policy $changed -Applied
}
Test-MIIPolicyCase 'wrong required context' -MustFail {
    $changed = $appliedJSON | ConvertFrom-Json
    $changed.required_status_checks.contexts = @('m0-04-required-fake')
    Assert-MIIBranchPolicy -Policy $changed -Applied
}
Test-MIIPolicyCase 'check app bound to wrong context' -MustFail {
    $changed = $appliedJSON | ConvertFrom-Json
    $changed.required_status_checks.checks[0].context = 'm0-04-required-fake'
    Assert-MIIBranchPolicy -Policy $changed -Applied
}
Test-MIIPolicyCase 'disabled strict status' -MustFail {
    $changed = $appliedJSON | ConvertFrom-Json
    $changed.required_status_checks.strict = $false
    Assert-MIIBranchPolicy -Policy $changed -Applied
}
Test-MIIPolicyCase 'false string is not a JSON boolean' -MustFail {
    $changed = $appliedJSON | ConvertFrom-Json
    $changed.allow_force_pushes.enabled = 'false'
    Assert-MIIBranchPolicy -Policy $changed -Applied
}
Test-MIIPolicyCase 'unbound duplicate required check' -MustFail {
    $changed = $appliedJSON | ConvertFrom-Json
    $changed.required_status_checks.checks += [PSCustomObject]@{ context = 'm0-04-required'; app_id = -1 }
    Assert-MIIBranchPolicy -Policy $changed -Applied
}
Test-MIIPolicyCase 'PR bypass allowlist' -MustFail {
    $changed = $appliedJSON | ConvertFrom-Json
    $changed.required_pull_request_reviews | Add-Member -NotePropertyName bypass_pull_request_allowances -NotePropertyValue ([PSCustomObject]@{ users = @([PSCustomObject]@{ login = 'admin' }); teams = @(); apps = @() })
    Assert-MIIBranchPolicy -Policy $changed -Applied
}

function Invoke-MIIMockedProtectionApply {
    param([Parameter(Mandatory)][string]$Response)
    $mockState = @{ Response = $Response; Calls = [Collections.Generic.List[string]]::new() }
    $savedExitCode = $global:LASTEXITCODE
    $fakeGH = {
        $global:LASTEXITCODE = 0
        if ($args[0] -eq 'auth') { $mockState.Calls.Add('AUTH'); return }
        if ($args[0] -ne 'api') { throw 'Unexpected mock gh command.' }
        if ($args -contains 'PUT') { $mockState.Calls.Add('PUT'); return }
        $mockState.Calls.Add('GET')
        $mockState.Response
    }.GetNewClosure()
    # Function scope shadows command resolution only while the production script is called.
    # The mock never launches gh, so even the PUT branch has no external side effect.
    function Get-Command {
        param([string]$Name, [string]$ErrorAction)
        if ($Name -cne 'gh' -or $ErrorAction -cne 'SilentlyContinue') { throw 'Unexpected mock command lookup.' }
        [PSCustomObject]@{ Source = $fakeGH }
    }
    try {
        & (Join-Path $scriptsRoot 'apply-branch-protection.ps1') -Repository 'fixture/test'
    } finally {
        $global:LASTEXITCODE = $savedExitCode
        if (($mockState.Calls -join ',') -cne 'AUTH,PUT,GET') { throw 'Production script did not execute expected mock AUTH,PUT,GET sequence.' }
    }
}
Test-MIIPolicyCase 'actual apply entry point accepts secure readback' {
    $output = Invoke-MIIMockedProtectionApply -Response $appliedJSON
    if ($output -notcontains 'Branch protection applied and verified: fixture/test/main') { throw 'Success message is missing.' }
}
Test-MIIPolicyCase 'actual apply entry point rejects unsafe readback' -MustFail -ErrorPattern '^Policy mismatch at allow_force_pushes.enabled:' {
    $changed = $appliedJSON | ConvertFrom-Json
    $changed.allow_force_pushes.enabled = $true
    Invoke-MIIMockedProtectionApply -Response ($changed | ConvertTo-Json -Depth 10)
}
Test-MIIPolicyCase 'actual apply entry point rejects incomplete readback' -MustFail -ErrorPattern '^Required policy field is missing:' {
    Invoke-MIIMockedProtectionApply -Response '{"required_status_checks":{"contexts":["m0-04-required"]}}'
}
Test-MIIPolicyCase 'actual apply entry point rejects malformed JSON' -MustFail -ErrorPattern 'JSON' {
    Invoke-MIIMockedProtectionApply -Response 'not-json-m0-04-required'
}

# Verify production entry points are wired to the same tested helpers, without running network writes or builds.
foreach ($entry in @(
    @{ File = 'verify-m0-04.ps1'; Commands = @('Assert-MIICIVersions', 'Get-MIICIVersionSources', 'Assert-MIIBranchPolicy') },
    @{ File = 'apply-branch-protection.ps1'; Commands = @('Assert-MIIBranchPolicy', 'ConvertFrom-Json') }
)) {
    Test-MIIPolicyCase "production validator wiring $($entry.File)" {
        $ast = Get-MIIPolicyScriptAST -Source (Get-Content -Raw -LiteralPath (Join-Path $scriptsRoot $entry.File))
        $commands = @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() })
        foreach ($command in $entry.Commands) {
            if ($commands -notcontains $command) { throw "Production entry point does not call $command." }
        }
    }
}
Write-Output "M0-04 policy regression tests passed: $script:policyTestCount cases (offline, no remote mutations)."
