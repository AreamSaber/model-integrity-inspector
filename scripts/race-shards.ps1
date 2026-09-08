# Deterministic, ordinal top-level partitions. Each selected parent retains all
# nested subtests and fuzz seeds; benchmarks are not run by ordinary go test.
function Get-MIIRepositoryRacePackage { return 'model-integrity-inspector.local/mii/internal/integrity/repository' }
function Get-MIIWorkerRacePackage { return 'model-integrity-inspector.local/mii/internal/integrity/worker' }

function Get-MIIRaceTestNames {
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Lines, [Parameter(Mandatory)][string]$Package)
    $names = [Collections.Generic.List[string]]::new()
    $summarySeen = $false
    $summary = '^ok\s+' + [regex]::Escape($Package) + '\s+[0-9]+(?:\.[0-9]+)?s$'
    foreach ($line in $Lines) {
        if ($summarySeen) { throw 'Unexpected output after the race enumeration summary.' }
        if ($line -cmatch '^(?:Test|Example|Fuzz)[\p{L}\p{Nd}_]*$') { $names.Add($line); continue }
        if ($line -cmatch $summary) { $summarySeen = $true; continue }
        throw 'Unknown or malformed race enumeration output.'
    }
    if (-not $summarySeen -or $names.Count -eq 0) { throw 'Race enumeration requires tests and one successful package summary.' }
    return ,$names.ToArray()
}

function Get-MIIRacePattern {
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Names)
    if ($Names.Count -eq 0) { throw 'An empty race shard must never fall back to running every test.' }
    foreach ($name in $Names) {
        if ($name -cnotmatch '^(?:Test|Example|Fuzz)[\p{L}\p{Nd}_]*$') { throw 'Invalid top-level race test name.' }
    }
    return '^(' + (($Names | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')$'
}

function Assert-MIIRaceCoverage {
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Names, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Shards, [ValidateRange(1,32)][int]$ShardCount = 6)
    if ($Shards.Count -ne $ShardCount -or $Names.Count -lt $ShardCount) { throw 'Race shard count or enumeration size is invalid.' }
    $expected = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in $Names) {
        $null = Get-MIIRacePattern -Names @($name)
        if (-not $expected.Add($name)) { throw 'Duplicate enumerated race test.' }
    }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($shard in $Shards) {
        $pattern = Get-MIIRacePattern -Names $shard.Names
        foreach ($name in $shard.Names) {
            if (-not $expected.Contains($name) -or -not $seen.Add($name)) { throw 'Unknown or duplicate race shard member.' }
        }
        foreach ($name in $Names) {
            $matched = [regex]::IsMatch($name, $pattern, [Text.RegularExpressions.RegexOptions]::CultureInvariant)
            if ($matched -ne ($shard.Names -ccontains $name)) { throw 'Race selection pattern changed coverage.' }
        }
    }
    if (-not $seen.SetEquals($expected)) { throw 'Race shards omit one or more enumerated tests.' }
}

function New-MIIRacePlan {
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Names, [ValidateRange(1,32)][int]$ShardCount = 6)
    [string[]]$sorted = $Names.Clone()
    [Array]::Sort($sorted, [StringComparer]::Ordinal)
    $shards = @(for ($index = 0; $index -lt $ShardCount; $index++) {
        [PSCustomObject]@{ Names = @() }
    })
    for ($index = 0; $index -lt $sorted.Count; $index++) { $shards[$index % $ShardCount].Names += $sorted[$index] }
    Assert-MIIRaceCoverage -Names $sorted -Shards $shards -ShardCount $ShardCount
    return [PSCustomObject]@{ Names = $sorted; Shards = $shards }
}

function Get-MIINonRepositoryRacePackages {
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Packages)
    $repository = Get-MIIRepositoryRacePackage
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($package in $Packages) {
        if ($package -cnotmatch '^model-integrity-inspector\.local/mii(?:/[A-Za-z0-9_.-]+)+$' -or -not $seen.Add($package)) { throw 'Unknown or duplicate go list package output.' }
    }
    if (-not $seen.Contains($repository) -or $seen.Count -lt 2) { throw 'The complete package list must include repository and other packages.' }
    [string[]]$others = @($Packages | Where-Object { $_ -cne $repository })
    [Array]::Sort($others, [StringComparer]::Ordinal)
    if ($others.Count -ne $Packages.Count - 1) { throw 'Only the exact independently required repository package may be partitioned out.' }
    return ,$others
}

# Execute returns { ExitCode, Lines }; production invokes a native Go executable,
# tests inject an offline recorder to assert flags, quoting and failure handling.
function Invoke-MIICIRace {
    param([Parameter(Mandatory)][ValidateSet('Other','Repository','Core','Worker','IdentityPostgres')][string]$Group, [ValidateRange(0,5)][int]$Shard = 0, [Parameter(Mandatory)][scriptblock]$Execute)
    if ([string]::IsNullOrWhiteSpace($env:MII_TEST_POSTGRES_DSN)) { throw 'Race CI requires the isolated PostgreSQL test DSN.' }
    if (-not [string]::IsNullOrEmpty($env:GOFLAGS)) { throw 'Race CI does not accept implicit GOFLAGS that may change coverage.' }
    if (-not [string]::IsNullOrEmpty($env:MII_IDENTITY_TEST_DRIVER)) { throw 'Race CI must start with the default identity driver.' }
    if ($Group -eq 'Repository' -or $Group -eq 'Worker') {
        $package = if ($Group -eq 'Repository') { Get-MIIRepositoryRacePackage } else { Get-MIIWorkerRacePackage }
        $listed = & $Execute -GoArguments @('test','-race','-count=1','-timeout=10m','-list','^(Test|Example|Fuzz)',$package) -Capture $true
        if ($listed.ExitCode -ne 0) { throw 'Race test enumeration failed.' }
        $names = Get-MIIRaceTestNames -Lines $listed.Lines -Package $package
        $plan = New-MIIRacePlan -Names $names
        $pattern = Get-MIIRacePattern -Names $plan.Shards[$Shard].Names
        Write-Host "$Group race shard $Shard/6: $($plan.Shards[$Shard].Names.Count) of $($plan.Names.Count) top-level tests; exact coverage verified."
        $tested = & $Execute -GoArguments @('test','-race','-count=1','-timeout=10m','-run',$pattern,$package) -Capture $false
        if ($tested.ExitCode -ne 0) { throw "$Group race shard $Shard failed." }
        return
    }
    if ($Shard -ne 0) { throw 'Only repository and Worker support a shard index.' }
    if ($Group -eq 'IdentityPostgres') {
        Invoke-MIIIdentityPostgresRace -Execute $Execute
        return
    }
    $listed = & $Execute -GoArguments @('list','./...') -Capture $true
    if ($listed.ExitCode -ne 0) { throw 'Complete Go package enumeration failed.' }
    $packages = Get-MIINonRepositoryRacePackages -Packages $listed.Lines
    $worker = Get-MIIWorkerRacePackage
    if ($packages -cnotcontains $worker) { throw 'Complete race enumeration must contain the exact Worker package.' }
    [string[]]$others = @($packages | Where-Object { $_ -cne $worker })
    if ($others.Count -eq 0 -or $others.Count -ne $packages.Count - 1) { throw 'Only the exact Worker package may move to sequential complete partitions.' }
    $plan = $null
    if ($Group -eq 'Other') {
        $listedWorker = & $Execute -GoArguments @('test','-race','-count=1','-timeout=10m','-list','^(Test|Example|Fuzz)',$worker) -Capture $true
        if ($listedWorker.ExitCode -ne 0) { throw 'Worker race enumeration failed.' }
        $plan = New-MIIRacePlan -Names (Get-MIIRaceTestNames -Lines $listedWorker.Lines -Package $worker)
        Write-Host "Race testing $($others.Count) non-repository/non-Worker packages; all Worker parents follow in six exact sequential partitions."
    } else {
        Write-Host "Race testing $($others.Count) non-repository/non-Worker packages; CI separately requires all six Worker shards and PostgreSQL identity/API."
    }
    $tested = & $Execute -GoArguments (@('test','-race','-count=1','-timeout=10m') + $others) -Capture $false
    if ($tested.ExitCode -ne 0) { throw 'Non-repository race regression failed.' }
    if ($Group -eq 'Core') { return }
    # Worker has grown beyond one process's ten-minute total race budget. Keep
    # the original bound per process and every top-level test/subtest/fuzz seed.
    # Sequential execution also avoids migrations competing with other suites.
    foreach ($index in 0..5) {
        $pattern = Get-MIIRacePattern -Names $plan.Shards[$index].Names
        Write-Host "Worker race partition $index/6: $($plan.Shards[$index].Names.Count) of $($plan.Names.Count) top-level tests; exact coverage verified."
        $tested = & $Execute -GoArguments @('test','-race','-count=1','-timeout=10m','-run',$pattern,$worker) -Capture $false
        if ($tested.ExitCode -ne 0) { throw "Worker race partition $index failed." }
    }
    Invoke-MIIIdentityPostgresRace -Execute $Execute
}

function Invoke-MIIIdentityPostgresRace {
    param([Parameter(Mandatory)][scriptblock]$Execute)
    try {
        $env:MII_IDENTITY_TEST_DRIVER = 'postgres'
        $tested = & $Execute -GoArguments @('test','-race','-count=1','-timeout=10m','./internal/identity','./internal/integrity/api') -Capture $false
        if ($tested.ExitCode -ne 0) { throw 'PostgreSQL identity/API race regression failed.' }
    } finally { $env:MII_IDENTITY_TEST_DRIVER = $null }
}
