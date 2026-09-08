param([switch]$PolicyOnly)
$ErrorActionPreference = 'Stop'

# Pure framing validation is exercised locally and before every actual CI run.
# These in-memory checks are not an OS-isolation success receipt.
function Assert-MIIReplayNetnsResult {
    param([int]$ExitCode, [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Lines)
    if ($ExitCode -ne 0 -or $Lines.Count -eq 0 -or $Lines.Count -gt 2048) { throw 'MI_REPLAY_NETNS_RUN_FAILED' }
    $package = 'model-integrity-inspector.local/mii/tests/replay/cmd/replay'
    $test = 'TestOfflineReplayNetworkNamespace'
    $starts = 0; $runs = 0; $passes = 0; $summaries = 0
    $stageCounts = @{}
    foreach ($stage in @('IDENTITY_OK','TOPOLOGY_OK','LOOPBACK_BLOCKED','IP_EGRESS_BLOCKED','OFFLINE_EQUAL','NEGATIVES_OK','ATOMIC_OK','PARENT_UNCHANGED')) {
        $stageCounts['MI_REPLAY_NETNS_' + $stage] = 0
    }
    foreach ($line in $Lines) {
        if ($line.Length -gt 32768) { throw 'MI_REPLAY_NETNS_RESULT_INVALID' }
        try { $event = $line | ConvertFrom-Json -AsHashtable -Depth 12 -ErrorAction Stop }
        catch { throw 'MI_REPLAY_NETNS_RESULT_INVALID' }
        if ($event -isnot [hashtable] -or $event.Package -cne $package -or
            $event.Action -cnotin @('start','run','output','pass') -or $summaries -ne 0) {
            throw 'MI_REPLAY_NETNS_RESULT_INVALID'
        }
        if ($event.ContainsKey('Test') -and $event.Test -cne $test) { throw 'MI_REPLAY_NETNS_RESULT_INVALID' }
        switch -CaseSensitive ($event.Action) {
            'start' {
                if ($starts -ne 0 -or $runs -ne 0 -or $event.ContainsKey('Test')) { throw 'MI_REPLAY_NETNS_RESULT_INVALID' }
                $starts++
            }
            'run' {
                if ($starts -ne 1 -or $runs -ne 0 -or $event.Test -cne $test) { throw 'MI_REPLAY_NETNS_RESULT_INVALID' }
                $runs++
            }
            'pass' {
                if ($event.ContainsKey('Test')) {
                    if ($runs -ne 1 -or $passes -ne 0) { throw 'MI_REPLAY_NETNS_RESULT_INVALID' }
                    $passes++
                } else {
                    if ($starts -ne 1 -or $runs -ne 1 -or $passes -ne 1) { throw 'MI_REPLAY_NETNS_RESULT_INVALID' }
                    $summaries++
                }
            }
            'output' {
                if ($starts -ne 1) { throw 'MI_REPLAY_NETNS_RESULT_INVALID' }
                if ($event.Test -ceq $test -and $event.Output -is [string]) {
                    foreach ($label in @($stageCounts.Keys)) {
                        $stageCounts[$label] += [regex]::Matches($event.Output, [regex]::Escape($label) + '(?![A-Z_])').Count
                    }
                }
            }
        }
    }
    if ($starts -ne 1 -or $runs -ne 1 -or $passes -ne 1 -or $summaries -ne 1) { throw 'MI_REPLAY_NETNS_NOT_EXECUTED' }
    foreach ($count in $stageCounts.Values) { if ($count -ne 1) { throw 'MI_REPLAY_NETNS_PROOF_STAGE_MISSING' } }
}

function Get-MIIReplayNetnsProbeDiagnostics {
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Lines)
    # Only these literal classifications may leave the private subprocess output.
    # An unknown errno is OTHER; arbitrary error text, addresses and paths never
    # become a diagnostic label. None of these labels counts as a proof stage.
    $labels = @(
        foreach ($value in @('IPV4','IPV6','UNKNOWN')) { 'MI_REPLAY_NETNS_DIAG_FAMILY_' + $value }
        foreach ($value in @('ADDRESS','SOCKET','CONNECT','POLL','GETSOCKOPT','SO_ERROR','CLOSE','CONTEXT','UNKNOWN')) { 'MI_REPLAY_NETNS_DIAG_STAGE_' + $value }
        foreach ($value in @('NONE','ENETUNREACH','EHOSTUNREACH','EAFNOSUPPORT','ECONNREFUSED','EINPROGRESS','EPERM','EACCES','EADDRNOTAVAIL','ETIMEDOUT','EINTR','EINVAL','EBADF','CANCELED','DEADLINE','OTHER')) { 'MI_REPLAY_NETNS_DIAG_ERRNO_' + $value }
    )
    foreach ($label in $labels) {
        if (@($Lines | Where-Object { $_ -cmatch ('(?<![A-Z0-9_])' + [regex]::Escape($label) + '(?![A-Z0-9_])') }).Count -gt 0) { $label }
    }
}

function Test-MIIReplayNetnsPolicy {
    $package = 'model-integrity-inspector.local/mii/tests/replay/cmd/replay'
    $test = 'TestOfflineReplayNetworkNamespace'
    $events = @(
        @{ Action = 'start'; Package = $package },
        @{ Action = 'run'; Package = $package; Test = $test },
        @{ Action = 'pass'; Package = $package; Test = $test },
        @{ Action = 'pass'; Package = $package }
    )
    $base = @($events | ForEach-Object { $_ | ConvertTo-Json -Compress })
    $proof = @(foreach ($stage in @('IDENTITY_OK','TOPOLOGY_OK','LOOPBACK_BLOCKED','IP_EGRESS_BLOCKED','OFFLINE_EQUAL','NEGATIVES_OK','ATOMIC_OK','PARENT_UNCHANGED')) {
        @{ Action = 'output'; Package = $package; Test = $test; Output = ('MI_REPLAY_NETNS_' + $stage + "`n") } | ConvertTo-Json -Compress
    })
    $valid = @($base[0],$base[1]) + $proof + @($base[2],$base[3])
    Assert-MIIReplayNetnsResult -ExitCode 0 -Lines $valid
    $bad = @(
        @{ Code = 1; Lines = $valid },
        @{ Code = 0; Lines = @() },
        @{ Code = 0; Lines = $base },
        @{ Code = 0; Lines = @($base[0],$base[1]) + $proof[1..7] + @($base[2],$base[3]) },
        @{ Code = 0; Lines = @($base[0],$base[1]) + $proof + @($proof[0],$base[2],$base[3]) },
        @{ Code = 0; Lines = @($valid[0],$valid[3]) },
        @{ Code = 0; Lines = @($valid[0],$valid[1],$valid[3]) },
        @{ Code = 0; Lines = @($valid[0],$valid[1],$valid[2]) },
        @{ Code = 0; Lines = @($valid[0],$valid[1],$valid[1],$valid[2],$valid[3]) },
        @{ Code = 0; Lines = @($valid[0],$valid[2],$valid[1],$valid[3]) },
        @{ Code = 0; Lines = @($valid[0],$valid[1],$valid[2],$valid[3],$valid[3]) },
        @{ Code = 0; Lines = @($valid[0],'not-json',$valid[1],$valid[2],$valid[3]) },
        @{ Code = 0; Lines = @($valid -creplace '"pass"','"skip"') },
        @{ Code = 0; Lines = @($valid -creplace '"pass"','"fail"') },
        @{ Code = 0; Lines = @($valid -creplace 'TestOfflineReplayNetworkNamespace','TestOther') },
        @{ Code = 0; Lines = @($valid -creplace '/cmd/replay','/cmd/wrong') }
    )
    foreach ($case in $bad) {
        $rejected = $false
        try { Assert-MIIReplayNetnsResult -ExitCode $case.Code -Lines $case.Lines }
        catch { $rejected = $true }
        if (-not $rejected) { throw 'MI_REPLAY_NETNS_POLICY_REGRESSION' }
    }
    $diagnostics = @(Get-MIIReplayNetnsProbeDiagnostics -Lines @(
        'private-canary /private/path MI_REPLAY_NETNS_DIAG_FAMILY_IPV6 MI_REPLAY_NETNS_DIAG_STAGE_CONNECT MI_REPLAY_NETNS_DIAG_ERRNO_ENETUNREACH',
        'MI_REPLAY_NETNS_DIAG_ERRNO_ENETUNREACH_PRIVATE MI_REPLAY_NETNS_DIAG_STAGE_UNTRUSTED MI_REPLAY_NETNS_DIAG_ERRNO_PRIVATE',
        'MI_REPLAY_NETNS_DIAG_ERRNO_ENETUNREACH'
    ))
    if (($diagnostics -join ' ') -cne 'MI_REPLAY_NETNS_DIAG_FAMILY_IPV6 MI_REPLAY_NETNS_DIAG_STAGE_CONNECT MI_REPLAY_NETNS_DIAG_ERRNO_ENETUNREACH') {
        throw 'MI_REPLAY_NETNS_POLICY_REGRESSION'
    }
    if (@(Get-MIIReplayNetnsProbeDiagnostics -Lines @('MI_REPLAY_NETNS_DIAG_FAMILY_IPV4_PRIVATE','private-canary')).Count -ne 0) {
        throw 'MI_REPLAY_NETNS_POLICY_REGRESSION'
    }
}

Test-MIIReplayNetnsPolicy
if ($PolicyOnly) {
    Write-Output 'MI_REPLAY_NETNS_POLICY_TESTS_OK_NOT_OS_EVIDENCE'
    return
}
if (-not $IsLinux) { throw 'MI_REPLAY_NETNS_LINUX_REQUIRED' }
if (-not [string]::IsNullOrEmpty($env:GOFLAGS) -or
    -not [string]::IsNullOrEmpty($env:MII_REPLAY_NETNS_CHILD) -or
    -not [string]::IsNullOrEmpty($env:MII_REPLAY_NETNS_CONFIG)) { throw 'MI_REPLAY_NETNS_IMPLICIT_OVERRIDE_REJECTED' }
. (Join-Path $PSScriptRoot 'toolchain.ps1')
$miiNetnsGo = Resolve-MIIGo
$miiNetnsRoot = Split-Path -Parent $PSScriptRoot
$miiNetnsSaved = @{}
foreach ($name in @('CGO_ENABLED','GOPROXY','GOSUMDB','PATH')) {
    $miiNetnsSaved[$name] = [Environment]::GetEnvironmentVariable($name)
}
Push-Location $miiNetnsRoot
try {
    $env:CGO_ENABLED = '0'
    $env:GOPROXY = 'off'
    $env:GOSUMDB = 'off'
    $env:PATH = (Split-Path -Parent $miiNetnsGo) + [IO.Path]::PathSeparator + $env:PATH
    # All dependencies are prepared by the preceding required Test and build
    # step. A missing cache is a failure, never an excuse to enable network here.
    $arguments = @('test','-json','-tags=replay_netns','-count=1','-timeout=4m','-run','^TestOfflineReplayNetworkNamespace$','./tests/replay/cmd/replay')
    $lines = @(& $miiNetnsGo @arguments 2>&1)
    $code = $LASTEXITCODE
    # Raw compiler/sudo/subprocess diagnostics remain private to this call.
    # Emit only closed stage labels generated by the test, never DSN/key/body.
    $stages = @('IDENTITY_OK','TOPOLOGY_OK','LOOPBACK_BLOCKED','IP_EGRESS_BLOCKED','OFFLINE_EQUAL','NEGATIVES_OK','ATOMIC_OK','PARENT_UNCHANGED',
        'FAILED_PARENT_IDENTITY','FAILED_CONNECTED_BASELINE','FAILED_BASELINE_READ','FAILED_CHILD_CONFIG','FAILED_EXECUTABLE','FAILED_REQUIRED_TOOL',
        'FAILED_ISOLATED_PROCESS','FAILED_STAGE_MISSING','FAILED_CHILD_NOT_RUN','FAILED_PARENT_NAMESPACE_CHANGED','FAILED_PARENT_COMPARE',
        'FAILED_GO_TOOLCHAIN','FAILED_FILE_TEST_BUILD','FAILED_NAMESPACE','FAILED_CONTROL_LISTENER','FAILED_CONTROL_CLEANUP','FAILED_CONTROL_UNREACHABLE','FAILED_CONTROL_PAYLOAD',
        'FAILED_IDENTITY','FAILED_CAPABILITIES','FAILED_INHERITED_SOCKET','FAILED_INTERFACE','FAILED_ROUTE','FAILED_SOURCE_ADDRESS','FAILED_NETWORK_NOT_BLOCKED','FAILED_PROBE_POLICY','FAILED_REPLAY',
        'FAILED_OUTPUT_COMPARE','FAILED_NEGATIVE','FAILED_CANCEL','FAILED_ATOMIC_TESTS','FAILED_FILE_OWNER')
    foreach ($stage in $stages) {
        $label = 'MI_REPLAY_NETNS_' + $stage
        if (@($lines | Where-Object { $_ -cmatch [regex]::Escape($label) }).Count -gt 0) { Write-Output $label }
    }
    Get-MIIReplayNetnsProbeDiagnostics -Lines $lines
    Assert-MIIReplayNetnsResult -ExitCode $code -Lines $lines
    Write-Output 'MI_REPLAY_NETNS_OS_VALIDATED_DEVELOPMENT_ONLY'
} finally {
    Pop-Location
    foreach ($name in $miiNetnsSaved.Keys) { [Environment]::SetEnvironmentVariable($name,$miiNetnsSaved[$name]) }
}
