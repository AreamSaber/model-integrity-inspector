param([switch]$NativeGo)
$ErrorActionPreference = 'Stop'
$scriptsRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $scriptsRoot 'race-shards.ps1')
$script:raceCaseCount = 0
function Test-MIIRaceCase {
    param([string]$Name, [scriptblock]$Test, [switch]$MustFail, [string]$ErrorPattern)
    $caught = $null
    try { & $Test } catch { $caught = $_ }
    if ($MustFail -and $null -eq $caught) { throw "FAIL: $Name accepted an invalid race configuration." }
    if ($MustFail -and $ErrorPattern -and $caught.Exception.Message -notmatch $ErrorPattern) { throw "FAIL: $Name failed for the wrong reason: $caught" }
    if (-not $MustFail -and $null -ne $caught) { throw "FAIL: ${Name}: $caught" }
    $script:raceCaseCount++
}
$package = Get-MIIRepositoryRacePackage
$names = @('TestZulu','TestAlpha','TestAlphaMore','TestCase','Testcase','Example','Example_demo','FuzzDecode','FuzzDecodeMore','Test_I','Test_ı','Test_中')
$lines = $names + "ok  `t$package`t0.123s"
Test-MIIRaceCase 'actual list shape and all runnable kinds' {
    $parsed = Get-MIIRaceTestNames -Lines $lines -Package $package
    if (($parsed -join ',') -cne ($names -join ',')) { throw 'The listing lost a Test, Example or Fuzz name.' }
}
foreach ($bad in @(
    @(), @('TestOnly'), @("ok`t$package`t0.001s"), @('BenchmarkHidden',"ok`t$package`t0.001s"),
    @('Test/Subtest',"ok`t$package`t0.001s"), @('Test.*',"ok`t$package`t0.001s"),
    @('TestGood','unexpected initialization output',"ok`t$package`t0.001s"),
    @('TestGood',"ok`t$package`t0.001s",'TestAfter'), @('TestGood',"ok`t$package`t0.001s (cached)"),
    @('TestGood',"ok`twrong/package`t0.001s"), @('TestGood',"FAIL`t$package`t0.001s"), @('TestGood','')
)) { Test-MIIRaceCase 'malformed, unknown or incomplete list fails closed' -MustFail { Get-MIIRaceTestNames -Lines $bad -Package $package } }
Test-MIIRaceCase 'ordinal deterministic under Turkish locale and reversed input' {
    $savedCulture = [Threading.Thread]::CurrentThread.CurrentCulture
    try {
        [Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo('tr-TR')
        $plan = New-MIIRacePlan -Names $names
        [string[]]$reversed = $names.Clone(); [Array]::Reverse($reversed)
        $other = New-MIIRacePlan -Names $reversed
        if (($plan | ConvertTo-Json -Depth 5 -Compress) -cne ($other | ConvertTo-Json -Depth 5 -Compress)) { throw 'Partitions depend on locale or enumeration order.' }
        [string[]]$expected = $names.Clone(); [Array]::Sort($expected, [StringComparer]::Ordinal)
        if (($plan.Names -join ',') -cne ($expected -join ',')) { throw 'Non-ordinal ordering.' }
    } finally { [Threading.Thread]::CurrentThread.CurrentCulture = $savedCulture }
}
Test-MIIRaceCase 'every item exactly once and prefixes never accidentally match' {
    $plan = New-MIIRacePlan -Names $names
    foreach ($name in $names) {
        $hits = @($plan.Shards | Where-Object { [regex]::IsMatch($name, (Get-MIIRacePattern -Names $_.Names)) })
        if ($hits.Count -ne 1) { throw 'Missing or duplicate regex coverage.' }
    }
    if ([regex]::IsMatch('TestAlphaMore', (Get-MIIRacePattern -Names @('TestAlpha')))) { throw 'Unanchored regex selected a different parent.' }
}
foreach ($mutation in @('duplicate-input','omitted','duplicate-shard','unknown','empty','missing-shard')) {
    Test-MIIRaceCase "reject $mutation coverage" -MustFail {
        $plan = New-MIIRacePlan -Names $names
        switch ($mutation) {
            'duplicate-input' { $plan.Names += $plan.Names[0] }
            'omitted' { $plan.Shards[0].Names = @($plan.Shards[0].Names[0]) }
            'duplicate-shard' { $plan.Shards[1].Names += $plan.Shards[0].Names[0] }
            'unknown' { $plan.Shards[0].Names += 'TestUnknown' }
            'empty' { $plan.Shards[0].Names = @() }
            'missing-shard' { $plan.Shards = $plan.Shards[0..4] }
        }
        Assert-MIIRaceCoverage -Names $plan.Names -Shards $plan.Shards
    }
}
Test-MIIRaceCase 'too few items cannot create a silently empty shard' -MustFail { New-MIIRacePlan -Names @('TestOne') }
foreach ($index in @(-1,6)) { Test-MIIRaceCase 'out-of-range shard rejected before execution' -MustFail { Invoke-MIICIRace -Group Repository -Shard $index -Execute { throw 'Must not run' } } }
$packages = @('model-integrity-inspector.local/mii/internal/app', $package, "$package/extra", 'model-integrity-inspector.local/mii/scripts/tool')
Test-MIIRaceCase 'only exact repository package is partitioned out' {
    $rest = Get-MIINonRepositoryRacePackages -Packages $packages
    if ($rest.Count -ne 3 -or $rest -cnotcontains "$package/extra" -or $rest -ccontains $package) { throw 'A non-repository package was lost.' }
}
foreach ($bad in @(@(), @($package), @('model-integrity-inspector.local/mii/internal/app'), @($package,$package), @($package,'unexpected output'))) {
    Test-MIIRaceCase 'bad complete package enumeration rejected' -MustFail { Get-MIINonRepositoryRacePackages -Packages $bad }
}

$savedDSN = $env:MII_TEST_POSTGRES_DSN; $savedFlags = $env:GOFLAGS; $savedDriver = $env:MII_IDENTITY_TEST_DRIVER
try {
    # Non-network synthetic presence marker, never supplied to a database driver.
    $env:MII_TEST_POSTGRES_DSN = 'offline-test-presence'; $env:GOFLAGS = $null; $env:MII_IDENTITY_TEST_DRIVER = $null
    function Invoke-MIIMockedRace {
        param([string]$Group, [int]$Shard = 0, [int]$FailAt = -1)
        $state = @{ Calls = [Collections.Generic.List[object]]::new() }
        $mockLines = $lines; $mockPackages = $packages
        $execute = {
            param([string[]]$GoArguments, [bool]$Capture)
            $state.Calls.Add([PSCustomObject]@{ Arguments = $GoArguments; Capture = $Capture; Driver = $env:MII_IDENTITY_TEST_DRIVER })
            $output = if ($GoArguments[0] -ceq 'list') { $mockPackages } elseif ($GoArguments -ccontains '-list') { $mockLines } else { @() }
            [PSCustomObject]@{ ExitCode = $(if ($state.Calls.Count -eq $FailAt) { 1 } else { 0 }); Lines = $output }
        }.GetNewClosure()
        $caught = $null
        try { Invoke-MIICIRace -Group $Group -Shard $Shard -Execute $execute } catch { $caught = $_ }
        return [PSCustomObject]@{ Calls = $state.Calls; Failure = $caught }
    }
    foreach ($shard in 0..5) {
        Test-MIIRaceCase "native argument shape for shard $shard" {
            $result = Invoke-MIIMockedRace -Group Repository -Shard $shard
            if ($result.Failure -or $result.Calls.Count -ne 2) { throw "Unexpected execution or failure: $($result.Failure)" }
            $run = $result.Calls[1].Arguments
            if ($run.Count -ne 7 -or ($run[0..4] -join ',') -cne 'test,-race,-count=1,-timeout=10m,-run' -or $run[6] -cne $package) { throw 'Race, count, timeout or single-argument pattern changed.' }
            $plan = New-MIIRacePlan -Names $names
            if ($run[5] -cne (Get-MIIRacePattern -Names $plan.Shards[$shard].Names) -or $run[5].Contains('/')) { throw 'Quoting lost parents or filtered nested subtests.' }
            if (-not $result.Calls[0].Capture -or $result.Calls[1].Capture) { throw 'Wrong list/test output handling.' }
        }
    }
    Test-MIIRaceCase 'all non-repository packages and additional PostgreSQL identity/API pass' {
        $result = Invoke-MIIMockedRace -Group Other
        if ($result.Failure -or $result.Calls.Count -ne 3) { throw 'Complete regression did not run.' }
        $run = $result.Calls[1].Arguments
        if (($run[0..3] -join ',') -cne 'test,-race,-count=1,-timeout=10m' -or $run.Count -ne 7 -or $run -ccontains $package) { throw 'Non-repository coverage or flags changed.' }
        foreach ($item in (Get-MIINonRepositoryRacePackages -Packages $packages)) { if ($run -cnotcontains $item) { throw 'A package was omitted.' } }
        if (($result.Calls[2].Arguments -join ',') -cne 'test,-race,-count=1,-timeout=10m,./internal/identity,./internal/integrity/api' -or $result.Calls[2].Driver -cne 'postgres' -or $env:MII_IDENTITY_TEST_DRIVER) { throw 'PostgreSQL override or cleanup changed.' }
    }
    foreach ($group in @('Other','Repository')) {
        foreach ($step in 1..$(if ($group -ceq 'Other') { 3 } else { 2 })) {
            Test-MIIRaceCase "failure is fatal at $group step $step" {
                $result = Invoke-MIIMockedRace -Group $group -FailAt $step
                if (-not $result.Failure -or $result.Calls.Count -ne $step -or $env:MII_IDENTITY_TEST_DRIVER) { throw 'Failed execution was ignored, continued or leaked driver override.' }
            }
        }
    }
    Test-MIIRaceCase 'missing PostgreSQL cannot turn dual database regression into skipped tests' -MustFail -ErrorPattern 'isolated PostgreSQL test DSN' {
        try { $env:MII_TEST_POSTGRES_DSN = $null; Invoke-MIICIRace -Group Repository -Execute { throw 'Must not invoke' } }
        finally { $env:MII_TEST_POSTGRES_DSN = 'offline-test-presence' }
    }
    Test-MIIRaceCase 'implicit skip flags forbidden' -MustFail -ErrorPattern 'implicit GOFLAGS' {
        try { $env:GOFLAGS = '-skip=Test'; Invoke-MIICIRace -Group Repository -Execute { throw 'Must not invoke' } }
        finally { $env:GOFLAGS = $null }
    }
} finally { $env:MII_TEST_POSTGRES_DSN = $savedDSN; $env:GOFLAGS = $savedFlags; $env:MII_IDENTITY_TEST_DRIVER = $savedDriver }

if ($NativeGo) {
    . (Join-Path $scriptsRoot 'toolchain.ps1')
    $go = Resolve-MIIGo
    Push-Location (Split-Path -Parent $scriptsRoot)
    try {
        # Run the exact native Go RE2 selection on this OS through PowerShell's
        # argument-array path. No test bodies are run by -list.
        $actual = @(& $go test -race -count=1 -timeout=10m -list '^(Test|Example|Fuzz)' $package 2>&1)
        if ($LASTEXITCODE -ne 0) { throw 'Native race enumeration failed.' }
        $plan = New-MIIRacePlan -Names (Get-MIIRaceTestNames -Lines $actual -Package $package)
        foreach ($shard in $plan.Shards) {
            $pattern = Get-MIIRacePattern -Names $shard.Names
            $arguments = @('test','-race','-count=1','-timeout=10m','-list',$pattern,$package)
            $actual = @(& $go @arguments 2>&1)
            if ($LASTEXITCODE -ne 0) { throw 'Native shard selection failed.' }
            $selected = Get-MIIRaceTestNames -Lines $actual -Package $package
            [Array]::Sort($selected, [StringComparer]::Ordinal)
            if (($selected -join ',') -cne ($shard.Names -join ',')) { throw 'Go RE2/native PowerShell selection changed exact coverage.' }
        }
        Write-Output "Native Go race enumeration: all $($plan.Names.Count) items covered exactly once across six selections."
    } finally { Pop-Location }
}
Write-Output "Race shard regression tests passed: $script:raceCaseCount cases."
