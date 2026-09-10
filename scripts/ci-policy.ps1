# Pure checks shared by local verification, branch-protection readback and offline tests.
function Get-MIIRequiredProperty {
    param([Parameter(Mandatory)]$Object, [Parameter(Mandatory)][string]$Path)
    $value = $Object
    foreach ($part in $Path.Split('.')) {
        if ($null -eq $value -or $null -eq $value.PSObject.Properties[$part]) {
            throw "Required policy field is missing: $Path"
        }
        $value = $value.$part
    }
    return ,$value
}

function Assert-MIIPolicyValue {
    param([Parameter(Mandatory)]$Object, [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Expected)
    $actual = Get-MIIRequiredProperty -Object $Object -Path $Path
    if ($null -eq $actual -or $actual.GetType() -ne $Expected.GetType() -or $actual -cne $Expected) {
        throw "Policy mismatch at ${Path}: expected $Expected, found $actual."
    }
}

function Assert-MIIBranchPolicy {
    param([Parameter(Mandatory)]$Policy, [switch]$Applied)
    $booleanRules = [ordered]@{
        enforce_admins = $true
        required_linear_history = $true
        allow_force_pushes = $false
        allow_deletions = $false
        block_creations = $false
        required_conversation_resolution = $true
        lock_branch = $false
        allow_fork_syncing = $false
    }
    foreach ($name in $booleanRules.Keys) {
        $path = if ($Applied) { "$name.enabled" } else { $name }
        Assert-MIIPolicyValue -Object $Policy -Path $path -Expected $booleanRules[$name]
    }
    Assert-MIIPolicyValue -Object $Policy -Path 'required_status_checks.strict' -Expected $true
    Assert-MIIPolicyValue -Object $Policy -Path 'required_pull_request_reviews.dismiss_stale_reviews' -Expected $true
    Assert-MIIPolicyValue -Object $Policy -Path 'required_pull_request_reviews.require_last_push_approval' -Expected $true
    Assert-MIIPolicyValue -Object $Policy -Path 'required_pull_request_reviews.require_code_owner_reviews' -Expected $false
    $reviewCount = Get-MIIRequiredProperty -Object $Policy -Path 'required_pull_request_reviews.required_approving_review_count'
    if ($reviewCount -isnot [long] -and $reviewCount -isnot [int]) { throw 'Approval count must be an integer.' }
    if ($reviewCount -ne 1) { throw 'Branch policy must require exactly one approval.' }

    $contexts = Get-MIIRequiredProperty -Object $Policy -Path 'required_status_checks.contexts'
    if ($contexts -isnot [array] -or $contexts.Count -ne 1 -or $contexts[0] -cne 'm0-04-required') {
        throw 'The required status contexts must be exactly [m0-04-required].'
    }
    $checks = Get-MIIRequiredProperty -Object $Policy -Path 'required_status_checks.checks'
    if ($checks -isnot [array] -or $checks.Count -ne 1) { throw 'Exactly one app-bound required status check is required.' }
    Assert-MIIPolicyValue -Object $checks[0] -Path 'context' -Expected 'm0-04-required'
    $appID = Get-MIIRequiredProperty -Object $checks[0] -Path 'app_id'
    if (($appID -isnot [long] -and $appID -isnot [int]) -or $appID -ne 15368) {
        throw 'm0-04-required must be bound to the GitHub Actions app (15368).'
    }

    # GitHub omits restrictions when PUT restrictions:null disables push restrictions.
    if (-not $Applied) { $null = Get-MIIRequiredProperty -Object $Policy -Path 'restrictions' }
    if ($null -ne $Policy.restrictions) { throw 'Unexpected push restrictions differ from the intended policy.' }
    # Omitted bypass allowances mean none; a non-empty allowlist must never pass.
    $bypass = $Policy.required_pull_request_reviews.bypass_pull_request_allowances
    if ($null -ne $bypass) {
        foreach ($kind in @('users', 'teams', 'apps')) {
            if (@($bypass.$kind).Where({ $null -ne $_ }).Count -gt 0) { throw "Unexpected PR bypass allowance: $kind" }
        }
    }
}

function Get-MIICIVersionSources {
    param([Parameter(Mandatory)][string]$WorkspaceRoot)
    $sources = @{}
    foreach ($path in @('.github/workflows/ci.yml', 'scripts/toolchain.ps1', 'scripts/bootstrap-golangci-lint.ps1',
        'scripts/bootstrap-govulncheck.ps1', 'scripts/bootstrap-actionlint.ps1', 'scripts/bootstrap-syft.ps1')) {
        $sources[$path] = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $WorkspaceRoot $path)
    }
    return $sources
}

function Get-MIIPolicyScriptAST {
    param([Parameter(Mandatory)][string]$Source)
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($Source, [ref]$null, [ref]$parseErrors)
    if ($parseErrors.Count -ne 0) { throw "Invalid PowerShell version source: $($parseErrors[0].Message)" }
    return $ast
}

function Assert-MIIScriptAssignment {
    param([Parameter(Mandatory)]$AST, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string[]]$Expected)
    $assignments = @($AST.FindAll({
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
        $node.Left.VariablePath.UserPath -ceq $Name
    }, $true))
    if ($assignments.Count -ne $Expected.Count) { throw "Version source must assign $Name exactly $($Expected.Count) time(s)." }
    $values = @($assignments | ForEach-Object {
        if ($_.Right -isnot [Management.Automation.Language.CommandExpressionAst] -or
            ($_.Right.Expression -isnot [Management.Automation.Language.StringConstantExpressionAst] -and
             $_.Right.Expression -isnot [Management.Automation.Language.ExpandableStringExpressionAst])) {
            throw "Version source $Name must use an explicit string value."
        }
        $_.Right.Expression.Value
    })
    for ($index = 0; $index -lt $Expected.Count; $index++) {
        if ($values[$index] -cne $Expected[$index]) { throw "Version source $Name mismatch: $($values[$index])" }
    }
}

function Get-MIIWorkflowActionInputs {
    param([Parameter(Mandatory)][string]$Workflow)
    # Deliberately accept only the repository's explicit block-style action inputs.
    # Anchored step/with boundaries prevent comments or another action's pin satisfying this check.
    $lines = $Workflow -split '\r?\n'
    for ($lineIndex = 0; $lineIndex -lt $lines.Count; $lineIndex++) {
        $match = [regex]::Match($lines[$lineIndex], '^(?<indent> +)(?:- )?uses:\s*(?<action>[^@\s]+)@[^\s#]+(?:\s+#.*)?$')
        if (-not $match.Success) { continue }
        $indent = $match.Groups['indent'].Length
        $inputs = @{}
        $withSeen = $false
        for ($next = $lineIndex + 1; $next -lt $lines.Count; $next++) {
            $line = $lines[$next]
            if ($line -match '^\s*(#.*)?$') { continue }
            $spaces = [regex]::Match($line, '^ *').Length
            if ($spaces -lt $indent -or ($spaces -eq $indent -and $line.TrimStart().StartsWith('- '))) { break }
            if ($spaces -eq $indent) {
                if ($line.Trim() -ceq 'with:') {
                    if ($withSeen) { throw 'Duplicate action with block.' }
                    $withSeen = $true
                } else { $withSeen = $false }
                continue
            }
            if ($withSeen) {
                $field = [regex]::Match($line, ('^ {' + ($indent + 2) + '}(?<key>[a-zA-Z0-9_-]+):\s*(?<value>[^#]*?)(?:\s+#.*)?$'))
                if (-not $field.Success) { throw "Unsupported action input syntax: $line" }
                $key = $field.Groups['key'].Value
                if ($inputs.ContainsKey($key)) { throw "Duplicate action input: $key" }
                $inputs[$key] = $field.Groups['value'].Value.Trim()
            }
        }
        [PSCustomObject]@{ Action = $match.Groups['action'].Value; Inputs = $inputs }
    }
}

function Assert-MIICIVersions {
    param([Parameter(Mandatory)][hashtable]$Sources)
    $workflow = $Sources['.github/workflows/ci.yml']
    if ([string]::IsNullOrWhiteSpace($workflow)) { throw 'CI workflow version source is missing.' }
    Assert-MIIRaceWorkflow -Workflow $workflow
    $environment = [regex]::Matches($workflow, '(?m)^env:\s*\r?\n(?<body>(?:^  [^\r\n]*\r?\n)+)')
    if ($environment.Count -ne 1) { throw 'CI must have one explicit root env block.' }
    foreach ($pin in @{ GO_VERSION = '1.26.7'; NODE_VERSION = '24.19.0'; PNPM_VERSION = '11.19.0' }.GetEnumerator()) {
        $values = [regex]::Matches($environment[0].Groups['body'].Value, ('(?m)^  ' + $pin.Key + ':\s*(?<value>[^\r\n#]+)'))
        if ($values.Count -ne 1 -or $values[0].Groups['value'].Value.Trim() -cne $pin.Value) { throw "CI env pin mismatch: $($pin.Key)" }
        if ([regex]::Matches($workflow, ('(?m)^\s*' + $pin.Key + ':')).Count -ne 1) { throw "CI must not override $($pin.Key)." }
    }
    $pnpmInstalls = [regex]::Matches($workflow, '(?m)^\s*run:\s*npm install --global (?<package>[^\r\n]+)$')
    if ($pnpmInstalls.Count -ne 3) { throw 'CI must explicitly install pinned pnpm in all three Node jobs.' }
    foreach ($install in $pnpmInstalls) {
        if ($install.Groups['package'].Value.Trim() -cne '"pnpm@${PNPM_VERSION}"') { throw 'CI pnpm installation must use PNPM_VERSION.' }
    }
    $actions = @(Get-MIIWorkflowActionInputs -Workflow $workflow)
    foreach ($pin in @(
        @{ Action = 'aquasecurity/trivy-action'; Input = 'version'; Version = 'v0.74.0'; Count = 2 },
        @{ Action = 'anchore/sbom-action'; Input = 'syft-version'; Version = 'v1.51.1'; Count = 2 },
        @{ Action = 'actions/setup-go'; Input = 'go-version'; Version = '${{ env.GO_VERSION }}'; Count = 8 },
        @{ Action = 'actions/setup-node'; Input = 'node-version'; Version = '${{ env.NODE_VERSION }}'; Count = 3 }
    )) {
        $matches = @($actions | Where-Object { $_.Action -ceq $pin.Action })
        if ($matches.Count -ne $pin.Count) { throw "CI action count mismatch: $($pin.Action)" }
        foreach ($action in $matches) {
            if ($action.Inputs[$pin.Input] -cne $pin.Version) { throw "CI $($pin.Action) $($pin.Input) must be $($pin.Version)." }
        }
    }

    $toolchain = Get-MIIPolicyScriptAST -Source $Sources['scripts/toolchain.ps1']
    Assert-MIIScriptAssignment -AST $toolchain -Name 'MIIExpectedGoVersion' -Expected 'go1.26.7'
    Assert-MIIScriptAssignment -AST $toolchain -Name 'MIIExpectedNodeVersion' -Expected 'v24.19.0'
    Assert-MIIScriptAssignment -AST $toolchain -Name 'MIIExpectedPnpmVersion' -Expected '11.19.0'
    foreach ($pin in @(
        @{ File = 'golangci-lint'; Archives = @('golangci-lint-2.13.2-windows-amd64.zip', 'golangci-lint-2.13.2-linux-amd64.tar.gz'); URL = 'https://github.com/golangci/golangci-lint/releases/download/v2.13.2/$archiveName' },
        @{ File = 'actionlint'; Archives = @('actionlint_1.7.12_windows_amd64.zip', 'actionlint_1.7.12_linux_amd64.tar.gz'); URL = 'https://github.com/rhysd/actionlint/releases/download/v1.7.12/$archiveName' },
        @{ File = 'syft'; URL = 'https://github.com/anchore/syft/releases/download/v1.51.1/syft_1.51.1_windows_amd64.zip' }
    )) {
        $ast = Get-MIIPolicyScriptAST -Source $Sources["scripts/bootstrap-$($pin.File).ps1"]
        Assert-MIIScriptAssignment -AST $ast -Name 'downloadUrl' -Expected $pin.URL
        if ($pin.Archives) { Assert-MIIScriptAssignment -AST $ast -Name 'archiveName' -Expected $pin.Archives }
    }
    $govulncheck = Get-MIIPolicyScriptAST -Source $Sources['scripts/bootstrap-govulncheck.ps1']
    $installCommands = @($govulncheck.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and $node.CommandElements.Count -ge 2 -and
        $node.CommandElements[0].Extent.Text -ceq '$go' -and $node.CommandElements[1].Extent.Text -ceq 'install'
    }, $true))
    if ($installCommands.Count -ne 1 -or $installCommands[0].CommandElements.Count -ne 3 -or
        $installCommands[0].CommandElements[2].Extent.Text -cne 'golang.org/x/vuln/cmd/govulncheck@v1.7.0') {
        throw 'govulncheck install command must pin golang.org/x/vuln/cmd/govulncheck@v1.7.0.'
    }
}

function Get-MIIExplicitWorkflowJob {
    param([Parameter(Mandatory)][string]$Workflow, [Parameter(Mandatory)][string]$Name)
    $matches = [regex]::Matches($Workflow, ('(?ms)^  ' + [regex]::Escape($Name) + ':\r?\n(?<body>.*?)(?=^  [a-zA-Z][a-zA-Z0-9_-]*:|\z)'))
    if ($matches.Count -ne 1) { throw "CI requires one explicit $Name job." }
    return $matches[0].Groups['body'].Value
}

function Assert-MIIRaceWorkflow {
    param([Parameter(Mandatory)][string]$Workflow)
    Assert-MIIPGBackupWorkflow -Workflow $Workflow
    $quality = Get-MIIExplicitWorkflowJob -Workflow $Workflow -Name 'quality'
    $core = Get-MIIExplicitWorkflowJob -Workflow $Workflow -Name 'core-race'
    $repository = Get-MIIExplicitWorkflowJob -Workflow $Workflow -Name 'repository-race'
    $worker = Get-MIIExplicitWorkflowJob -Workflow $Workflow -Name 'worker-race'
    $identity = Get-MIIExplicitWorkflowJob -Workflow $Workflow -Name 'identity-postgres-race'
    $required = Get-MIIExplicitWorkflowJob -Workflow $Workflow -Name 'required'
    if ($Workflow -match '(?m)^\s*continue-on-error:') { throw 'Required CI work must not ignore failures.' }
    Assert-MIICoreRaceWorkflow -Core $core -Quality $quality
    if ([regex]::Matches($identity, '(?m)^        run: \./scripts/test-race\.ps1 -Group IdentityPostgres\s*$').Count -ne 1) { throw 'CI must independently run explicit PostgreSQL identity/API race exactly once.' }
    foreach ($matrix in @(@{ Body = $repository; Name = 'repository-race'; Group = 'Repository' }, @{ Body = $worker; Name = 'worker-race'; Group = 'Worker' })) {
        if ($matrix.Body -cnotmatch ('(?m)^    name: ' + [regex]::Escape($matrix.Name) + '-\$\{\{ matrix\.shard \}\}\s*$') -or
            $matrix.Body -cnotmatch '(?m)^    strategy:\r?\n      fail-fast: false\r?\n      matrix:\r?\n        shard: \[0, 1, 2, 3, 4, 5\]\r?\n    runs-on: ubuntu-24\.04\s*$' -or
            $matrix.Body -match '(?m)^\s*(include|exclude):' -or
            [regex]::Matches($matrix.Body, ('(?m)^        run: \./scripts/test-race\.ps1 -Group ' + $matrix.Group + ' -Shard \$\{\{ matrix\.shard \}\}\s*$')).Count -ne 1) { throw 'All six repository/Worker race shards must be explicit and independently executed.' }
    }
    foreach ($job in @($core, $repository, $worker, $identity)) {
        if ([regex]::Matches($job, '(?m)^    timeout-minutes: 25\s*$').Count -ne 1 -or
            [regex]::Matches($job, '(?m)^    runs-on: ubuntu-24\.04\s*$').Count -ne 1 -or $job -match '(?m)^\s*if:') { throw 'Required race jobs must retain native Ubuntu, the 25-minute job limit and cannot conditionally skip work.' }
        if ($job -cnotmatch '(?m)^          MII_TEST_POSTGRES_DSN: postgres://[^\r\n]+$') { throw 'Every race job requires its real isolated PostgreSQL service.' }
        if ($job -cnotmatch '(?m)^    services:\r?\n      postgres:\r?\n        image: postgres:18\.6-bookworm@sha256:1c59e2c3c818eaa0f0628f695b36e7c9e362d6b219b36a54a32df645cbd7e1af\s*$' -or
            $job -cnotmatch '(?m)^          - 127\.0\.0\.1:15432:5432\s*$') { throw 'Every race job must own the pinned isolated PostgreSQL service.' }
    }
    if ($required -cnotmatch '(?m)^    name: m0-04-required\s*$' -or
        $required -cnotmatch '(?m)^    if: always\(\)\s*$' -or
        $required -cnotmatch '(?m)^    needs: \[quality, core-race, repository-race, worker-race, identity-postgres-race, dependency-scan, package, image, pg-backup-native\]\s*$') { throw 'The unchanged required gate must await every CI job, even on failure or cancellation.' }
    foreach ($binding in @(
        'QUALITY: ${{ needs.quality.result }}', 'CORE_RACE: ${{ needs.core-race.result }}', 'REPOSITORY_RACE: ${{ needs.repository-race.result }}',
        'WORKER_RACE: ${{ needs.worker-race.result }}', 'IDENTITY_POSTGRES_RACE: ${{ needs.identity-postgres-race.result }}',
        'DEPENDENCY_SCAN: ${{ needs.dependency-scan.result }}', 'PACKAGE: ${{ needs.package.result }}', 'IMAGE: ${{ needs.image.result }}',
        'PG_BACKUP_NATIVE: ${{ needs.pg-backup-native.result }}'
    )) {
        if ([regex]::Matches($required, ('(?m)^          ' + [regex]::Escape($binding) + '\s*$')).Count -ne 1) { throw 'Every required job result must be bound exactly once.' }
    }
    if ($required -cnotmatch '(?m)^          for result in "\$QUALITY" "\$CORE_RACE" "\$REPOSITORY_RACE" "\$WORKER_RACE" "\$IDENTITY_POSTGRES_RACE" "\$DEPENDENCY_SCAN" "\$PACKAGE" "\$IMAGE" "\$PG_BACKUP_NATIVE"; do\r?\n            test "\$result" = "success" \|\| exit 1\r?\n          done\s*$') { throw 'Required CI accepts only success; failure, skipped, cancelled or missing is not success.' }
}

function Assert-MIICoreRaceWorkflow {
    param([Parameter(Mandatory)][string]$Core, [Parameter(Mandatory)][string]$Quality)
    $coreBody = $Core -replace '\r\n', "`n"
    if ($coreBody -match '(?m)^\s*(if|needs|continue-on-error|GOFLAGS|MII_IDENTITY_TEST_DRIVER):' -or
        [regex]::Matches($coreBody, '(?m)^    name: core-race$').Count -ne 1 -or
        [regex]::Matches($coreBody, '(?m)^      - ').Count -ne 5) { throw 'Required Core race CI must be independent, unconditional and have exactly five explicit steps.' }
    foreach ($line in @(
        '          POSTGRES_DB: mii_ci', '          POSTGRES_USER: mii_test_owner',
        '          POSTGRES_PASSWORD: mii-ci-${{ github.run_id }}-${{ github.run_attempt }}',
        '          --health-cmd "pg_isready -U mii_test_owner -d mii_ci"',
        '          --health-interval 5s', '          --health-timeout 5s', '          --health-retries 10'
    )) {
        if ([regex]::Matches($coreBody, ('(?m)^' + [regex]::Escape($line) + '$')).Count -ne 1) { throw 'Required Core race CI must keep the pinned isolated service settings.' }
    }
    $expected = @'
    steps:
      - name: Checkout
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - name: Set up Go
        uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version: ${{ env.GO_VERSION }}
          cache: false
      - name: Download pinned Go dependencies
        run: go mod download
      - name: Verify required race coverage policy
        shell: pwsh
        run: |
          ./scripts/tests/test-m0-04-policy.ps1
          ./scripts/tests/test-race-shards.ps1
      - name: SQLite and PostgreSQL race regression
        env:
          MII_TEST_POSTGRES_DSN: postgres://mii_test_owner:mii-ci-${{ github.run_id }}-${{ github.run_attempt }}@127.0.0.1:15432/mii_ci?sslmode=disable
        shell: pwsh
        run: ./scripts/test-race.ps1 -Group Core
'@
    $steps = [regex]::Matches($coreBody, '(?ms)^    steps:\n.*\z')
    if ($steps.Count -ne 1 -or $steps[0].Value.TrimEnd() -cne $expected.Replace("`r`n", "`n").TrimEnd()) { throw 'Required Core race CI must run the original exact command, pinned setup and coverage checks.' }
    if ($Quality -match 'test-race\.ps1' -or $Quality -match '(?m)^\s*(if|needs|continue-on-error):' -or
        [regex]::Matches($Quality, '(?m)^    timeout-minutes: 25\s*$').Count -ne 1 -or
        [regex]::Matches($Quality, '(?m)^    runs-on: ubuntu-24\.04\s*$').Count -ne 1) { throw 'Quality CI must retain its independent native bounded build budget.' }
    foreach ($command in @('./scripts/lint.ps1', './scripts/build.ps1', './scripts/test-replay-netns.ps1')) {
        if ([regex]::Matches($Quality, ('(?m)^        run: ' + [regex]::Escape($command) + '\s*$')).Count -ne 1) { throw 'Quality CI must retain every static, build and offline isolation check.' }
    }
}

function Assert-MIIPGBackupWorkflow {
    param([Parameter(Mandatory)][string]$Workflow)
    $job = (Get-MIIExplicitWorkflowJob -Workflow $Workflow -Name 'pg-backup-native') -replace '\r\n', "`n"
    if ($job -match '(?m)^\s*(if|continue-on-error|ports|volumes):' -or
        [regex]::Matches($job, '(?m)^    name: pg-backup-native$').Count -ne 1 -or
        [regex]::Matches($job, '(?m)^    runs-on: ubuntu-24\.04$').Count -ne 1 -or
        [regex]::Matches($job, '(?m)^    timeout-minutes: 25$').Count -ne 1) {
        throw 'Required PG backup CI must remain unconditional, isolated, native Linux and bounded to 25 minutes.'
    }
    $image = 'postgres:18.6-bookworm@sha256:1c59e2c3c818eaa0f0628f695b36e7c9e362d6b219b36a54a32df645cbd7e1af'
    if ($job -cnotmatch ('(?m)^    container:\n      image: ' + [regex]::Escape($image) + '\n      options: --init$') -or
        $job -cnotmatch ('(?m)^    services:\n      postgres:\n        image: ' + [regex]::Escape($image) + '$') -or
        [regex]::Matches($job, '(?m)^      - name:').Count -ne 4 -or
        [regex]::Matches($job, '(?m)^      - ').Count -ne 4) {
        throw 'Required PG backup CI needs the pinned tool container with init, its own same-version service and exactly four explicit steps.'
    }
    foreach ($line in @(
        '          POSTGRES_DB: mii_ci', '          POSTGRES_USER: mii_test_owner',
        '          POSTGRES_PASSWORD: mii-ci-${{ github.run_id }}-${{ github.run_attempt }}',
        '          --health-cmd "pg_isready -U mii_test_owner -d mii_ci"',
        '          --health-interval 5s', '          --health-timeout 5s', '          --health-retries 10',
        '        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1',
        '        uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0',
        '          go-version: ${{ env.GO_VERSION }}', '          cache: false'
    )) {
        if ([regex]::Matches($job, ('(?m)^' + [regex]::Escape($line) + '$')).Count -ne 1) {
            throw 'Required PG backup CI service/actions must retain exact pinned inputs.'
        }
    }
    $install = @'
    steps:
      - name: Install container CI dependencies
        shell: bash
        run: |
          apt-get update
          apt-get install --no-install-recommends -y ca-certificates curl git gzip tar
      - name: Checkout
'@
    if (-not $job.Contains($install.Replace("`r`n", "`n"))) { throw 'Required PG backup CI dependencies must be installed only inside the container before checkout.' }
    # Compare the actual executable step, not a version literal/comment in some
    # other job. No skipped step, shell wrapper, extra command or GOFLAGS escape
    # can retain a decoy command and satisfy this deliberately explicit policy.
    $expected = @'
      - name: Native PostgreSQL backup and TLS regression
        env:
          MII_TEST_PG_DUMP: /usr/lib/postgresql/18/bin/pg_dump
          MII_TEST_PG_RESTORE: /usr/lib/postgresql/18/bin/pg_restore
          PGPASSWORD: mii-ci-${{ github.run_id }}-${{ github.run_attempt }}
          PGCONNECT_TIMEOUT: 10
        shell: bash
        run: |
          test "$(go env GOVERSION)" = "go1.26.7"
          test "$(go env GOOS)" = "linux"
          test -z "$(go env GOFLAGS)"
          test -x "$MII_TEST_PG_DUMP" && test -x "$MII_TEST_PG_RESTORE"
          case "$("$MII_TEST_PG_DUMP" --version)" in
            'pg_dump (PostgreSQL) 18.6'|'pg_dump (PostgreSQL) 18.6 ('*) ;;
            *) echo "PG_BACKUP_DUMP_VERSION_MISMATCH" >&2; exit 1 ;;
          esac
          case "$("$MII_TEST_PG_RESTORE" --version)" in
            'pg_restore (PostgreSQL) 18.6'|'pg_restore (PostgreSQL) 18.6 ('*) ;;
            *) echo "PG_BACKUP_RESTORE_VERSION_MISMATCH" >&2; exit 1 ;;
          esac
          export MII_TEST_PG_BACKUP_DSN="postgres://mii_test_owner:${PGPASSWORD}@postgres:5432/mii_ci?sslmode=disable"
          test "$(/usr/lib/postgresql/18/bin/psql -X -w -h postgres -p 5432 -U mii_test_owner -d mii_ci -Atc "SELECT current_setting('server_version_num')='180006' AND EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND rolcreatedb)" 2>/dev/null)" = "t"
          go test -p 1 -tags pgbackup_integration ./internal/integrity/pgbackup ./internal/integrity/repository -run '^(TestPostgresDump|TestPGBackupTLS|TestNativeProcess)' -count=1 -timeout=10m
'@
    $steps = [regex]::Matches($job, '(?ms)^      - name: Native PostgreSQL backup and TLS regression\n.*?(?=^      - name:|\z)')
    if ($steps.Count -ne 1 -or $steps[0].Value.TrimEnd() -cne $expected.Replace("`r`n", "`n").TrimEnd()) {
        throw 'Required PG backup CI must run its complete pinned native version/permission checks and tagged two-package regression exactly.'
    }
}
