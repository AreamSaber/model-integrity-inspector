param(
    [ValidateSet('Start', 'Stop', 'Status', 'Test')][string]$Action = 'Test',
    [ValidateRange(1024, 65535)][int]$Port = 15432,
    [string[]]$Packages = @('./internal/integrity/repository')
)

# Local, disposable Windows PostgreSQL integration runtime. No system installer,
# Windows service, firewall change, production database, or real credential.
# Start returns only an ignored DSN FILE PATH, never its secret contents.
# Usage: ./scripts/test-postgres.ps1 -Action Start (then read dsn.txt without echo)
#        ./scripts/test-postgres.ps1 -Action Stop
#        ./scripts/test-postgres.ps1 -Action Test (repository tests; stops finally)
# Source: PostgreSQL 18 initdb/pg_ctl docs. Runtime TLS is disabled only on the
# explicitly disposable loopback database; do not reuse this for deployments.
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'This local test runtime is Windows only.' }
if ($env:APP_ENV -eq 'production' -or $env:MII_ENV -eq 'production') { throw 'Refusing test PostgreSQL in a production environment.' }
$workspaceRoot = Split-Path -Parent $PSScriptRoot
$toolRoot = Join-Path $workspaceRoot '.tools'
$runtimeRoot = Join-Path $toolRoot 'test-postgres'
$dataRoot = Join-Path $runtimeRoot 'data'
$binRoot = Join-Path $toolRoot 'postgresql-18.6-3/pgsql/bin'
$statePath = Join-Path $runtimeRoot 'runtime.json'
$dsnPath = Join-Path $runtimeRoot 'dsn.txt'
$passwordPath = Join-Path $runtimeRoot 'password.txt'
$pgControl = Join-Path $binRoot 'pg_ctl.exe'

function Assert-TestPostgresPath {
    param([string]$Path)
    $allowed = [IO.Path]::GetFullPath($toolRoot).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not $resolved.StartsWith($allowed, [StringComparison]::OrdinalIgnoreCase)) { throw 'Test PostgreSQL path is outside .tools.' }
    $ancestor = $resolved
    while ($ancestor -and $ancestor.Length -ge $allowed.TrimEnd('\', '/').Length) {
        if ((Test-Path -LiteralPath $ancestor) -and ((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Test PostgreSQL paths may not traverse symlinks or junctions.'
        }
        $ancestor = Split-Path -Parent $ancestor
    }
}

function Protect-TestPostgresDirectory {
    $acl = Get-Acl -LiteralPath $runtimeRoot
    $allowedSIDs = @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-18')
    $unexpectedRules = @($acl.Access | Where-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin $allowedSIDs -or $_.AccessControlType -ne 'Allow' })
    if ($acl.AreAccessRulesProtected -and $unexpectedRules.Count -eq 0 -and @($acl.Access).Count -eq 2) { return }
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($existingRule in @($acl.Access)) { $null = $acl.RemoveAccessRuleSpecific($existingRule) }
    foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    [IO.FileSystemAclExtensions]::SetAccessControl([IO.DirectoryInfo]::new($runtimeRoot), $acl)
}

function Get-TestPostgresState {
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) { return $null }
    $state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
    if ($state.marker -ne 'MII_DISPOSABLE_POSTGRES_V1' -or $state.data_directory -ne $dataRoot -or $state.port -ne $Port) {
        throw 'Managed PostgreSQL state mismatch. Use the original port; do not reuse arbitrary clusters.'
    }
    Assert-TestPostgresPath -Path $state.data_directory
    return $state
}

function Test-ManagedPostgresRunning {
    if (-not (Test-Path -LiteralPath (Join-Path $dataRoot 'postmaster.pid') -PathType Leaf)) { return $false }
    $pidLine = (Get-Content -LiteralPath (Join-Path $dataRoot 'postmaster.pid') -TotalCount 1).Trim()
    $managedPID = 0
    if (-not [int]::TryParse($pidLine, [ref]$managedPID)) { throw 'Invalid managed PostgreSQL PID file.' }
    $process = Get-Process -Id $managedPID -ErrorAction SilentlyContinue
    if (-not $process) { return $false }
    if ($process.Path -ne (Join-Path $binRoot 'postgres.exe')) { throw 'PID file points at an unrelated process; refusing to control it.' }
    $null = & $pgControl status -D $dataRoot 2>&1
    return $LASTEXITCODE -eq 0
}

function Stop-TestPostgres {
    if (-not (Get-TestPostgresState)) { Write-Output 'No managed PostgreSQL test cluster has been initialized.'; return }
    if (Test-ManagedPostgresRunning) {
        $control = Start-Process -FilePath $pgControl -ArgumentList @('stop', '-D', ('"{0}"' -f $dataRoot), '-m', 'fast', '-w', '-t', '30') -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $runtimeRoot 'stop.stdout.log') -RedirectStandardError (Join-Path $runtimeRoot 'stop.stderr.log')
        if (-not $control.WaitForExit(40000)) { throw 'Timed out waiting for PostgreSQL shutdown helper.' }
        if ($control.ExitCode -ne 0) { throw 'Managed PostgreSQL shutdown failed; inspect ignored local logs.' }
    }
    Write-Output 'Managed PostgreSQL is stopped. Disposable cluster files remain in ignored .tools/test-postgres.'
}

function Start-TestPostgres {
    if (-not (Test-Path -LiteralPath $pgControl -PathType Leaf)) { & (Join-Path $PSScriptRoot 'bootstrap-test-postgres.ps1') }
    New-Item -ItemType Directory -Force -Path $runtimeRoot | Out-Null
    Protect-TestPostgresDirectory
    $state = Get-TestPostgresState
    if (-not $state) {
        if ((Test-Path -LiteralPath $dataRoot) -and @(Get-ChildItem -LiteralPath $dataRoot -Force).Count -gt 0) {
            throw 'Unrecognized nonempty PostgreSQL data directory; no data was removed.'
        }
        $passwordBytes = [byte[]]::new(32)
        [Security.Cryptography.RandomNumberGenerator]::Fill($passwordBytes)
        $databasePassword = [Convert]::ToHexString($passwordBytes).ToLowerInvariant()
        [Array]::Clear($passwordBytes)
        [IO.File]::WriteAllText($passwordPath, $databasePassword, [Text.UTF8Encoding]::new($false))
        $initdb = Join-Path $binRoot 'initdb.exe'
        $initOutput = @(& $initdb -D $dataRoot --username=mii_test_owner --auth-host=scram-sha-256 --auth-local=scram-sha-256 "--pwfile=$passwordPath" --encoding=UTF8 --locale=C --no-instructions -c 'listen_addresses=127.0.0.1' -c "port=$Port" -c 'log_statement=none' -c 'log_min_error_statement=panic' -c 'log_parameter_max_length_on_error=0' 2>&1)
        if ($LASTEXITCODE -ne 0) { throw 'Disposable PostgreSQL initialization failed; no existing database was altered.' }
        [IO.File]::WriteAllText((Join-Path $runtimeRoot 'initdb.log'), (($initOutput | Out-String).Replace($databasePassword, '[REDACTED]')), [Text.UTF8Encoding]::new($false))
        $databaseDSN = "postgres://mii_test_owner:${databasePassword}@127.0.0.1:$Port/mii_test?sslmode=disable"
        [IO.File]::WriteAllText($dsnPath, $databaseDSN, [Text.UTF8Encoding]::new($false))
        $state = [ordered]@{ marker = 'MII_DISPOSABLE_POSTGRES_V1'; version = '18.6'; data_directory = $dataRoot; port = $Port; database = 'mii_test'; host = '127.0.0.1' }
        [IO.File]::WriteAllText($statePath, ($state | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
        $databasePassword = $null
        $databaseDSN = $null
    }
    if (-not (Test-Path -LiteralPath $dsnPath -PathType Leaf) -or -not (Test-Path -LiteralPath $passwordPath -PathType Leaf)) { throw 'Managed test credentials are missing; do not replace or reset the cluster implicitly.' }
    if (-not (Test-ManagedPostgresRunning)) {
        # Fixed command-line loopback/port overrides protect against accidental
        # edits to generated config. pg_ctl starts a normal process, not a service.
        $options = "-h 127.0.0.1 -p $Port -c log_statement=none -c log_min_error_statement=panic -c log_parameter_max_length_on_error=0"
        $control = Start-Process -FilePath $pgControl -ArgumentList @('start', '-D', ('"{0}"' -f $dataRoot), '-o', ('"{0}"' -f $options), '-l', ('"{0}"' -f (Join-Path $runtimeRoot 'server.log')), '-w', '-t', '30') -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $runtimeRoot 'start.stdout.log') -RedirectStandardError (Join-Path $runtimeRoot 'start.stderr.log')
        # Start-Process -Wait waits the full descendant tree on Windows. Only
        # wait for pg_ctl; the intentionally background server must stay alive.
        if (-not $control.WaitForExit(40000)) { throw 'Timed out waiting for PostgreSQL startup helper.' }
        if ($control.ExitCode -ne 0) { throw 'Managed PostgreSQL start failed; inspect ignored local logs.' }
    }
    $oldPassword = $env:PGPASSWORD
    $oldPassFile = $env:PGPASSFILE
    try {
        $env:PGPASSWORD = [IO.File]::ReadAllText($passwordPath).Trim()
        $env:PGPASSFILE = ''
        $psql = Join-Path $binRoot 'psql.exe'
        $existing = @(& $psql -X -w -h 127.0.0.1 -p $Port -U mii_test_owner -d postgres -Atc "SELECT 1 FROM pg_database WHERE datname = 'mii_test'" 2>&1)
        if ($LASTEXITCODE -ne 0) { throw 'Managed PostgreSQL authentication check failed.' }
        if (($existing -join '').Trim() -ne '1') {
            $null = & (Join-Path $binRoot 'createdb.exe') -w -h 127.0.0.1 -p $Port -U mii_test_owner mii_test 2>&1
            if ($LASTEXITCODE -ne 0) { throw 'Could not create the disposable mii_test database.' }
        }
        $settings = @(& $psql -X -w -h 127.0.0.1 -p $Port -U mii_test_owner -d mii_test -Atc "SELECT current_setting('listen_addresses'), current_setting('port'), current_setting('password_encryption')" 2>&1)
        if ($LASTEXITCODE -ne 0 -or ($settings -join '').Trim() -ne "127.0.0.1|$Port|scram-sha-256") { throw 'Managed PostgreSQL loopback/auth settings did not match.' }
    } finally {
        $env:PGPASSWORD = $oldPassword
        $env:PGPASSFILE = $oldPassFile
    }
    Write-Output "Managed PostgreSQL is ready on loopback port $Port. Read MII_TEST_POSTGRES_DSN from the ignored file: $dsnPath"
}

foreach ($path in @($runtimeRoot, $dataRoot, $binRoot, $statePath, $dsnPath, $passwordPath)) { Assert-TestPostgresPath -Path $path }
switch ($Action) {
    'Start' { Start-TestPostgres }
    'Stop' { Stop-TestPostgres }
    'Status' {
        if ((Get-TestPostgresState) -and (Test-ManagedPostgresRunning)) { Write-Output "Managed PostgreSQL is running on loopback port $Port." }
        else { Write-Output 'Managed PostgreSQL is stopped.' }
    }
    'Test' {
        $oldDSN = $env:MII_TEST_POSTGRES_DSN
        $oldPath = $env:PATH
        try {
            Start-TestPostgres
            $env:MII_TEST_POSTGRES_DSN = [IO.File]::ReadAllText($dsnPath).Trim()
            $databasePassword = [IO.File]::ReadAllText($passwordPath).Trim()
            $env:PATH = "$(Join-Path $toolRoot 'go/bin')$([IO.Path]::PathSeparator)$oldPath"
            Push-Location $workspaceRoot
            try {
                $testOutput = @(& (Join-Path $toolRoot 'go/bin/go.exe') test -count=1 -v @Packages 2>&1)
                $testExit = $LASTEXITCODE
                Write-Output (($testOutput | Out-String).Replace($env:MII_TEST_POSTGRES_DSN, '[REDACTED_DSN]').Replace($databasePassword, '[REDACTED]'))
                if ($testExit -ne 0) { throw 'PostgreSQL integration tests failed.' }
            } finally { Pop-Location }
        } finally {
            $env:MII_TEST_POSTGRES_DSN = $oldDSN
            $env:PATH = $oldPath
            $databasePassword = $null
            Stop-TestPostgres
        }
    }
}
