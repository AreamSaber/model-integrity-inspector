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
$workerPackage = Get-MIIWorkerRacePackage
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
$packages = @('model-integrity-inspector.local/mii/internal/app', $package, "$package/extra", 'model-integrity-inspector.local/mii/scripts/tool', $workerPackage, "$workerPackage/extra")
Test-MIIRaceCase 'only exact repository package is partitioned out' {
    $rest = Get-MIINonRepositoryRacePackages -Packages $packages
    if ($rest.Count -ne 5 -or $rest -cnotcontains "$package/extra" -or $rest -ccontains $package) { throw 'A non-repository package was lost.' }
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
        $mockWorker = $workerPackage
        $mockWorkerLines = $names + "ok  `t$workerPackage`t0.123s"
        $execute = {
            param([string[]]$GoArguments, [bool]$Capture)
            $state.Calls.Add([PSCustomObject]@{ Arguments = $GoArguments; Capture = $Capture; Driver = $env:MII_IDENTITY_TEST_DRIVER })
            $output = if ($GoArguments[0] -ceq 'list') { $mockPackages } elseif ($GoArguments -ccontains '-list') { if ($GoArguments[-1] -ceq $mockWorker) { $mockWorkerLines } else { $mockLines } } else { @() }
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
        if ($result.Failure -or $result.Calls.Count -ne 10) { throw "Complete regression did not run: $($result.Failure)" }
        $run = $result.Calls[2].Arguments
        if (($run[0..3] -join ',') -cne 'test,-race,-count=1,-timeout=10m' -or $run.Count -ne 8 -or $run -ccontains $package -or $run -ccontains $workerPackage) { throw 'Non-repository coverage or flags changed.' }
        foreach ($item in (Get-MIINonRepositoryRacePackages -Packages $packages)) { if ($item -cne $workerPackage -and $run -cnotcontains $item) { throw 'A package was omitted.' } }
        if (($result.Calls[1].Arguments -join ',') -cne "test,-race,-count=1,-timeout=10m,-list,^(Test|Example|Fuzz),$workerPackage" -or -not $result.Calls[1].Capture) { throw 'Worker enumeration changed flags or runnable kinds.' }
        $plan = New-MIIRacePlan -Names $names
        foreach ($index in 0..5) {
            $part = $result.Calls[3 + $index]
            if ($part.Capture -or $part.Driver -or $part.Arguments.Count -ne 7 -or ($part.Arguments[0..4] -join ',') -cne 'test,-race,-count=1,-timeout=10m,-run' -or $part.Arguments[5] -cne (Get-MIIRacePattern -Names $plan.Shards[$index].Names) -or $part.Arguments[6] -cne $workerPackage) { throw 'Worker partition omitted a parent, widened timeout or changed database scope.' }
        }
        if (($result.Calls[9].Arguments -join ',') -cne 'test,-race,-count=1,-timeout=10m,./internal/identity,./internal/integrity/api' -or $result.Calls[9].Driver -cne 'postgres' -or $env:MII_IDENTITY_TEST_DRIVER) { throw 'PostgreSQL override or cleanup changed.' }
    }
    Test-MIIRaceCase 'Core retains every exact non-repository/non-Worker package' {
        $result = Invoke-MIIMockedRace -Group Core
        if ($result.Failure -or $result.Calls.Count -ne 2 -or -not $result.Calls[0].Capture -or $result.Calls[1].Capture) { throw 'Core must list packages then execute its one complete test process.' }
        $run = $result.Calls[1].Arguments
        if (($run[0..3] -join ',') -cne 'test,-race,-count=1,-timeout=10m' -or $run.Count -ne 8 -or $result.Calls[1].Driver) { throw 'Core flags or default database scope changed.' }
        $expected = @((Get-MIINonRepositoryRacePackages -Packages $packages) | Where-Object { $_ -cne $workerPackage })
        if (($run[4..($run.Count - 1)] -join ',') -cne ($expected -join ',')) { throw 'Core lost or duplicated packages, including similarly prefixed packages.' }
    }
    foreach ($shard in 0..5) {
        Test-MIIRaceCase "independent Worker shard $shard keeps exact complete parent selection" {
            $result = Invoke-MIIMockedRace -Group Worker -Shard $shard
            if ($result.Failure -or $result.Calls.Count -ne 2) { throw 'Worker shard must enumerate and execute once.' }
            if (($result.Calls[0].Arguments -join ',') -cne "test,-race,-count=1,-timeout=10m,-list,^(Test|Example|Fuzz),$workerPackage" -or -not $result.Calls[0].Capture) { throw 'Standalone Worker enumeration changed runnable kinds or flags.' }
            $plan = New-MIIRacePlan -Names $names
            $run = $result.Calls[1]
            if ($run.Capture -or $run.Driver -or $run.Arguments.Count -ne 7 -or ($run.Arguments[0..4] -join ',') -cne 'test,-race,-count=1,-timeout=10m,-run' -or $run.Arguments[5] -cne (Get-MIIRacePattern -Names $plan.Shards[$shard].Names) -or $run.Arguments[6] -cne $workerPackage) { throw 'Standalone Worker dropped a parent or changed its flags/database scope.' }
        }
    }
    Test-MIIRaceCase 'independent PostgreSQL identity/API scope and cleanup are unchanged' {
        $result = Invoke-MIIMockedRace -Group IdentityPostgres
        if ($result.Failure -or $result.Calls.Count -ne 1 -or $result.Calls[0].Capture -or ($result.Calls[0].Arguments -join ',') -cne 'test,-race,-count=1,-timeout=10m,./internal/identity,./internal/integrity/api' -or $result.Calls[0].Driver -cne 'postgres' -or $env:MII_IDENTITY_TEST_DRIVER) { throw 'Explicit PostgreSQL identity/API coverage, flags or environment cleanup changed.' }
    }
    Test-MIIRaceCase 'parallel CI delivery equals every local Other test invocation exactly once' {
        $local = Invoke-MIIMockedRace -Group Other
        $separate = @((Invoke-MIIMockedRace -Group Core))
        foreach ($shard in 0..5) { $separate += Invoke-MIIMockedRace -Group Worker -Shard $shard }
        $separate += Invoke-MIIMockedRace -Group IdentityPostgres
        if ($local.Failure -or @($separate | Where-Object { $_.Failure }).Count -ne 0) { throw 'A required group failed before coverage comparison.' }
        $projection = { param($call) [PSCustomObject]@{ Arguments = $call.Arguments; Driver = $call.Driver } }
        $expected = @($local.Calls | Where-Object { -not $_.Capture } | ForEach-Object { & $projection $_ })
        $actual = @($separate | ForEach-Object { $_.Calls } | Where-Object { -not $_.Capture } | ForEach-Object { & $projection $_ })
        if ($expected.Count -ne 8 -or ($actual | ConvertTo-Json -Depth 5 -Compress) -cne ($expected | ConvertTo-Json -Depth 5 -Compress)) { throw 'Split CI omitted, duplicated or changed one of the complete Other test invocations.' }
    }
    foreach ($group in @('Other','Repository','Core','Worker','IdentityPostgres')) {
        $steps = if ($group -ceq 'Other') { 10 } elseif ($group -ceq 'IdentityPostgres') { 1 } else { 2 }
        foreach ($step in 1..$steps) {
            Test-MIIRaceCase "failure is fatal at $group step $step" {
                $result = Invoke-MIIMockedRace -Group $group -FailAt $step
                if (-not $result.Failure -or $result.Calls.Count -ne $step -or $env:MII_IDENTITY_TEST_DRIVER) { throw 'Failed execution was ignored, continued or leaked driver override.' }
            }
        }
    }
    foreach ($group in @('Core','Other','IdentityPostgres')) {
        Test-MIIRaceCase "$group rejects an accidental shard index" -MustFail {
            Invoke-MIICIRace -Group $group -Shard 1 -Execute { throw 'Must not invoke' }
        }
    }
    Test-MIIRaceCase 'unknown group is rejected before native invocation' -MustFail -ErrorPattern 'ValidateSet|validation|validate|argument' {
        Invoke-MIICIRace -Group Unknown -Execute { throw 'Must not invoke' }
    }
    foreach ($mutation in @('missing-worker','prefix-only','unknown-list','empty-parent','duplicate-parent')) {
        Test-MIIRaceCase "Worker enumeration rejects $mutation before testing any body" -MustFail -ErrorPattern 'exact Worker package|Unknown or malformed race enumeration|Race enumeration requires tests|Duplicate enumerated race test' {
            $state = @{ Calls = 0 }
            $execute = {
                param([string[]]$GoArguments, [bool]$Capture)
                $state.Calls++
                if ($GoArguments[0] -ceq 'list') {
                    $output = if ($mutation -ceq 'missing-worker') { @($packages | Where-Object { $_ -cne $workerPackage -and $_ -cne "$workerPackage/extra" }) } elseif ($mutation -ceq 'prefix-only') { @($packages | Where-Object { $_ -cne $workerPackage }) } else { $packages }
                } elseif ($GoArguments -ccontains '-list') {
                    $output = switch ($mutation) {
                        'unknown-list' { @('unexpected-output', "ok`t$workerPackage`t0.1s") }
                        'empty-parent' { @("ok`t$workerPackage`t0.1s") }
                        'duplicate-parent' { $names + $names[0] + "ok`t$workerPackage`t0.1s" }
                    }
                } else { throw 'Must reject enumeration before any race body.' }
                [PSCustomObject]@{ ExitCode = 0; Lines = $output }
            }
            Invoke-MIICIRace -Group Other -Execute $execute
        }
    }
    foreach ($group in @('Other','Repository','Core','Worker','IdentityPostgres')) {
        Test-MIIRaceCase "$group missing PostgreSQL cannot silently skip database tests" -MustFail -ErrorPattern 'isolated PostgreSQL test DSN' {
            try { $env:MII_TEST_POSTGRES_DSN = $null; Invoke-MIICIRace -Group $group -Execute { throw 'Must not invoke' } }
            finally { $env:MII_TEST_POSTGRES_DSN = 'offline-test-presence' }
        }
        Test-MIIRaceCase "$group implicit skip flags forbidden" -MustFail -ErrorPattern 'implicit GOFLAGS' {
            try { $env:GOFLAGS = '-skip=Test'; Invoke-MIICIRace -Group $group -Execute { throw 'Must not invoke' } }
            finally { $env:GOFLAGS = $null }
        }
        Test-MIIRaceCase "$group rejects inherited identity driver override" -MustFail -ErrorPattern 'default identity driver' {
            try { $env:MII_IDENTITY_TEST_DRIVER = 'postgres'; Invoke-MIICIRace -Group $group -Execute { throw 'Must not invoke' } }
            finally { $env:MII_IDENTITY_TEST_DRIVER = $null }
        }
    }
} finally { $env:MII_TEST_POSTGRES_DSN = $savedDSN; $env:GOFLAGS = $savedFlags; $env:MII_IDENTITY_TEST_DRIVER = $savedDriver }

if ($NativeGo) {
    . (Join-Path $scriptsRoot 'toolchain.ps1')
    $go = Resolve-MIIGo
    Push-Location (Split-Path -Parent $scriptsRoot)
    try {
        # Run the exact native Go RE2 selection on this OS through PowerShell's
        # argument-array path. No test bodies are run by -list.
        foreach ($selectedPackage in @($package, $workerPackage)) {
            $actual = @(& $go test -race -count=1 -timeout=10m -list '^(Test|Example|Fuzz)' $selectedPackage 2>&1)
            if ($LASTEXITCODE -ne 0) { throw 'Native race enumeration failed.' }
            $plan = New-MIIRacePlan -Names (Get-MIIRaceTestNames -Lines $actual -Package $selectedPackage)
            foreach ($shard in $plan.Shards) {
                $pattern = Get-MIIRacePattern -Names $shard.Names
                $arguments = @('test','-race','-count=1','-timeout=10m','-list',$pattern,$selectedPackage)
                $actual = @(& $go @arguments 2>&1)
                if ($LASTEXITCODE -ne 0) { throw 'Native shard selection failed.' }
                $selected = Get-MIIRaceTestNames -Lines $actual -Package $selectedPackage
                [Array]::Sort($selected, [StringComparer]::Ordinal)
                if (($selected -join ',') -cne ($shard.Names -join ',')) { throw 'Go RE2/native PowerShell selection changed exact coverage.' }
            }
            Write-Output "Native Go race enumeration ($selectedPackage): all $($plan.Names.Count) items covered exactly once across six selections."
        }
    } finally { Pop-Location }
}
Write-Output "Race shard regression tests passed: $script:raceCaseCount cases."
