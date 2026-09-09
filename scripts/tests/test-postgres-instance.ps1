$ErrorActionPreference = 'Stop'
$scriptsRoot = Split-Path -Parent $PSScriptRoot
$repositoryRoot = Split-Path -Parent $scriptsRoot
$runtimeScript = Join-Path $scriptsRoot 'test-postgres.ps1'
$tokens = $parseErrors = $null
$runtimeAST = [Management.Automation.Language.Parser]::ParseFile($runtimeScript, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'Managed PostgreSQL helper has a syntax error.' }

# Extract only three pure policy functions. Never dot-source the entry point:
# its default Action Test intentionally starts and later stops a real cluster.
$pureNames = @('Get-TestPostgresInstanceSettings', 'Assert-TestPostgresStateIdentity', 'Assert-TestPostgresPortPolicy')
foreach ($name in $pureNames) {
    $definitions = @($runtimeAST.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $false))
    if ($definitions.Count -ne 1) { throw 'Missing or duplicate instance policy function.' }
    . ([scriptblock]::Create($definitions[0].Extent.Text))
}
# The real parameter declaration is exercised without the script's action body.
$bindParameters = [scriptblock]::Create($runtimeAST.ParamBlock.Extent.Text + @'

[pscustomobject]@{ Action = $Action; Instance = $Instance; Port = $Port; Packages = $Packages; PortSpecified = $PSBoundParameters.ContainsKey('Port') }
'@)
$script:instanceCaseCount = 0
function Test-PostgresInstanceCase {
    param([string]$Name, [scriptblock]$Run, [string]$Reject)
    $caught = $null
    try { & $Run | Out-Null } catch { $caught = $_ }
    if ($Reject -and (-not $caught -or $caught.Exception.Message -notmatch $Reject)) { throw "FAIL ${Name}: expected $Reject; actual $caught" }
    if (-not $Reject -and $caught) { throw "FAIL ${Name}: $caught" }
    $script:instanceCaseCount++
}

function New-PostgresInstanceState {
    param([string]$ForInstance, [int]$ForPort)
    $runtimeName = if ($ForInstance -eq 'Backup') { 'test-postgres-backup' } else { 'test-postgres' }
    return [pscustomobject]@{
        marker = 'MII_DISPOSABLE_POSTGRES_V1'; version = '18.6'; instance = $ForInstance
        data_directory = Join-Path $repositoryRoot ".tools/$runtimeName/data"
        port = $ForPort; database = 'mii_test'; host = '127.0.0.1'
    }
}
$generalState = New-PostgresInstanceState -ForInstance General -ForPort 15432
$backupState = New-PostgresInstanceState -ForInstance Backup -ForPort 15433

Test-PostgresInstanceCase 'only closed existing parameters plus Instance' {
    $names = @($runtimeAST.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
    if (($names -join ',') -cne 'Action,Instance,Port,Packages') { throw 'Public parameters added a runtime path or changed the existing interface.' }
}
Test-PostgresInstanceCase 'General defaults retain Test, 15432 and repository tests' {
    $bound = & $bindParameters
    if ($bound.Instance -cne 'General' -or $bound.Action -cne 'Test' -or $bound.Port -ne 15432 -or $bound.PortSpecified -or
        ($bound.Packages -join ',') -cne './internal/integrity/repository') { throw 'General defaults changed.' }
    $settings = Get-TestPostgresInstanceSettings -SelectedInstance $bound.Instance -SelectedAction $bound.Action -SelectedPort $bound.Port -PortSpecified $bound.PortSpecified
    if ($settings.RuntimeName -cne 'test-postgres' -or $settings.PeerRuntimeName -cne 'test-postgres-backup' -or
        $settings.PeerInstance -cne 'Backup' -or $settings.DSNEnvironment -cne 'MII_TEST_POSTGRES_DSN') { throw 'General runtime or DSN changed.' }
}
foreach ($actionName in @('Start', 'Stop', 'Status')) {
    Test-PostgresInstanceCase "Backup $actionName uses only its fixed runtime and explicit port" {
        $bound = & $bindParameters -Action $actionName -Instance Backup -Port 15433
        $settings = Get-TestPostgresInstanceSettings -SelectedInstance $bound.Instance -SelectedAction $bound.Action -SelectedPort $bound.Port -PortSpecified $bound.PortSpecified
        if ($settings.RuntimeName -cne 'test-postgres-backup' -or $settings.PeerRuntimeName -cne 'test-postgres' -or
            $settings.PeerInstance -cne 'General' -or $settings.DSNEnvironment -cne 'MII_TEST_PG_BACKUP_DSN') { throw 'Backup runtime is not isolated.' }
    }
    Test-PostgresInstanceCase "Backup $actionName cannot silently inherit default port" -Reject 'requires an explicit -Port' {
        Get-TestPostgresInstanceSettings -SelectedInstance Backup -SelectedAction $actionName -SelectedPort 15432 -PortSpecified $false
    }
    Test-PostgresInstanceCase "Backup $actionName cannot use General default port" -Reject 'General default port 15432' {
        Get-TestPostgresInstanceSettings -SelectedInstance Backup -SelectedAction $actionName -SelectedPort 15432 -PortSpecified $true
    }
}
Test-PostgresInstanceCase 'Backup ordinary Test action fails before lifecycle' -Reject 'explicit pgbackup_integration tagged command' {
    Get-TestPostgresInstanceSettings -SelectedInstance Backup -SelectedAction Test -SelectedPort 15433 -PortSpecified $true
}
Test-PostgresInstanceCase 'General explicit original custom port remains supported' {
    $bound = & $bindParameters -Instance General -Action Start -Port 15440
    $settings = Get-TestPostgresInstanceSettings -SelectedInstance $bound.Instance -SelectedAction $bound.Action -SelectedPort $bound.Port -PortSpecified $bound.PortSpecified
    if ($settings.RuntimeName -cne 'test-postgres' -or $bound.Port -ne 15440) { throw 'General explicit port behavior changed.' }
}
foreach ($invalid in @('Custom', '../test-postgres', 'Backup/../../outside', 'D:\outside', '')) {
    Test-PostgresInstanceCase 'actual parameter set rejects arbitrary Instance' -Reject 'ValidateSet|validation|validate|验证|无效|有效' { & $bindParameters -Instance $invalid }
}
foreach ($invalid in @(0, 1023, 65536, -1)) {
    Test-PostgresInstanceCase 'actual port range rejects invalid values' -Reject 'ValidateRange|validation|validate|验证|范围' { & $bindParameters -Port $invalid }
}
Test-PostgresInstanceCase 'fixed settings close off custom runtime names' -Reject 'ValidateSet|validation|validate|验证|无效|有效' {
    Get-TestPostgresInstanceSettings -SelectedInstance '../outside' -SelectedAction Start -SelectedPort 15433 -PortSpecified $true
}

Test-PostgresInstanceCase 'legacy General state without instance remains valid' {
    $legacy = New-PostgresInstanceState -ForInstance General -ForPort 15432
    $legacy.PSObject.Properties.Remove('instance')
    Assert-TestPostgresStateIdentity -State $legacy -ExpectedDataRoot $generalState.data_directory -ExpectedPort 15432 -ExpectedInstance General
}
foreach ($state in @($generalState, $backupState)) {
    Test-PostgresInstanceCase 'new state matches its exact instance data and port' {
        Assert-TestPostgresStateIdentity -State $state -ExpectedDataRoot $state.data_directory -ExpectedPort $state.port -ExpectedInstance $state.instance
    }
}
foreach ($mutation in @('marker', 'directory', 'port', 'instance', 'missing_instance', 'missing_port', 'text_port', 'out_of_range')) {
    Test-PostgresInstanceCase "Backup rejects $mutation state mismatch" -Reject 'state mismatch' {
        $state = New-PostgresInstanceState -ForInstance Backup -ForPort 15433
        switch ($mutation) {
            marker { $state.marker = 'unowned' }
            directory { $state.data_directory = $generalState.data_directory }
            port { $state.port = 15434 }
            instance { $state.instance = 'General' }
            missing_instance { $state.PSObject.Properties.Remove('instance') }
            missing_port { $state.PSObject.Properties.Remove('port') }
            text_port { $state.port = 'not-a-port' }
            out_of_range { $state.port = 65536 }
        }
        Assert-TestPostgresStateIdentity -State $state -ExpectedDataRoot $backupState.data_directory -ExpectedPort 15433 -ExpectedInstance Backup
    }
}
Test-PostgresInstanceCase 'General rejects state copied from Backup' -Reject 'state mismatch' {
    Assert-TestPostgresStateIdentity -State $backupState -ExpectedDataRoot $generalState.data_directory -ExpectedPort 15433 -ExpectedInstance General
}
Test-PostgresInstanceCase 'absent other instance and unoccupied port permit startup policy' {
    Assert-TestPostgresPortPolicy -SelectedPort 15433 -PeerState $null -PeerDataRoot $generalState.data_directory -PeerInstance General -ListeningPorts @() -ManagedRunning $false
}
foreach ($state in @($generalState, $backupState)) {
    $otherPort = if ($state.instance -eq 'General') { 15433 } else { 15432 }
    Test-PostgresInstanceCase 'other managed instance can be listening on its distinct port' {
        Assert-TestPostgresPortPolicy -SelectedPort $otherPort -PeerState $state -PeerDataRoot $state.data_directory -PeerInstance $state.instance -ListeningPorts @($state.port) -ManagedRunning $false
    }
    foreach ($alreadyRunning in @($false, $true)) {
        Test-PostgresInstanceCase 'other instance retains its port even while stopped or selected instance running' -Reject 'reserved by the other managed PostgreSQL instance' {
            Assert-TestPostgresPortPolicy -SelectedPort $state.port -PeerState $state -PeerDataRoot $state.data_directory -PeerInstance $state.instance -ListeningPorts @() -ManagedRunning $alreadyRunning
        }
    }
}
Test-PostgresInstanceCase 'unrelated listener rejected before initialization' -Reject 'already listening outside' {
    Assert-TestPostgresPortPolicy -SelectedPort 15433 -PeerState $generalState -PeerDataRoot $generalState.data_directory -PeerInstance General -ListeningPorts @(15432, 15433) -ManagedRunning $false
}
Test-PostgresInstanceCase 'exact already-running instance may retain its own listener' {
    Assert-TestPostgresPortPolicy -SelectedPort 15433 -PeerState $generalState -PeerDataRoot $generalState.data_directory -PeerInstance General -ListeningPorts @(15432, 15433) -ManagedRunning $true
}
Test-PostgresInstanceCase 'peer state must belong to its fixed directory even at a different port' -Reject 'state mismatch' {
    Assert-TestPostgresPortPolicy -SelectedPort 15433 -PeerState $generalState -PeerDataRoot $backupState.data_directory -PeerInstance General -ListeningPorts @() -ManagedRunning $false
}
Test-PostgresInstanceCase 'malformed peer port cannot silently bypass reservation' -Reject 'invalid port' {
    $state = New-PostgresInstanceState -ForInstance General -ForPort 15432
    $state.port = 'invalid'
    Assert-TestPostgresPortPolicy -SelectedPort 15433 -PeerState $state -PeerDataRoot $generalState.data_directory -PeerInstance General -ListeningPorts @() -ManagedRunning $false
}

$source = $runtimeAST.Extent.Text
Test-PostgresInstanceCase 'all owned state and credentials resolve beneath selected fixed runtime' {
    foreach ($assignment in @(
        '$runtimeRoot = Join-Path $toolRoot $instanceSettings.RuntimeName',
        '$dataRoot = Join-Path $runtimeRoot ''data''',
        '$statePath = Join-Path $runtimeRoot ''runtime.json''',
        '$dsnPath = Join-Path $runtimeRoot ''dsn.txt''',
        '$passwordPath = Join-Path $runtimeRoot ''password.txt''',
        '$binRoot = Join-Path $toolRoot ''postgresql-18.6-3/pgsql/bin'''
    )) { if (-not $source.Contains($assignment)) { throw 'Fixed owned runtime path wiring changed.' } }
    foreach ($name in @('initdb.log', 'server.log', 'start.stdout.log', 'start.stderr.log', 'stop.stdout.log', 'stop.stderr.log')) {
        if (-not $source.Contains(('Join-Path $runtimeRoot ''{0}''' -f $name))) { throw 'An instance log left its selected runtime.' }
    }
}
$startDefinition = $runtimeAST.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Start-TestPostgres' }, $false)
Test-PostgresInstanceCase 'port and unknown Backup directory checks precede every startup write' {
    $body = $startDefinition.Body.Extent.Text
    $portCheck = $body.IndexOf('Assert-TestPostgresStartPort -ManagedRunning $managedRunning', [StringComparison]::Ordinal)
    $unknownCheck = $body.IndexOf('Unrecognized existing Backup runtime directory', [StringComparison]::Ordinal)
    if ($portCheck -lt 0 -or $unknownCheck -lt $portCheck) { throw 'Startup preflight checks missing.' }
    foreach ($write in @('bootstrap-test-postgres.ps1', 'New-Item', 'Protect-TestPostgresDirectory', '[IO.File]::WriteAllText', '& $initdb', 'Start-Process')) {
        if ($body.IndexOf($write, [StringComparison]::Ordinal) -le $unknownCheck) { throw 'Startup writes precede safe instance/port selection.' }
    }
}
Test-PostgresInstanceCase 'peer inspection has no command that can control or change a cluster' {
    $definition = $runtimeAST.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-TestPostgresStartPort' }, $false)
    $allowed = @('Join-Path', 'Assert-TestPostgresPath', 'Test-Path', 'Get-Content', 'ConvertFrom-Json', 'ForEach-Object', 'Assert-TestPostgresPortPolicy')
    foreach ($command in $definition.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $false)) {
        if ($command.GetCommandName() -notin $allowed) { throw 'Peer inspection acquired a non-read-only command.' }
    }
}
Test-PostgresInstanceCase 'existing process, reparse, environment and durability guards remain' {
    foreach ($guard in @(
        'Refusing test PostgreSQL in a production environment.',
        'Test PostgreSQL paths may not traverse symlinks or junctions.',
        'PID file points at an unrelated process; refusing to control it.',
        'Unrecognized nonempty PostgreSQL data directory; no data was removed.',
        'Managed test credentials are missing; do not replace or reset the cluster implicitly.',
        "'-m', 'fast', '-w', '-t', '30'", '-WindowStyle Hidden',
        '$null = & $pgControl status -D $dataRoot',
        'instance = $Instance'
    )) { if (-not $source.Contains($guard)) { throw 'Existing instance protection was removed.' } }
    if ($source -match 'fsync\s*=\s*off|full_page_writes\s*=\s*off|synchronous_commit\s*=\s*off|--no-sync|--force|pg_terminate_backend') {
        throw 'Instance separation weakened durability or gained force cleanup.'
    }
}

Write-Output "PostgreSQL instance policy passed: $script:instanceCaseCount cases; pure helpers and actual parameter/AST contracts only, no database or filesystem mutations."
