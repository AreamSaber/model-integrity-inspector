param([Parameter(Mandatory)][ValidateSet('Other','Repository','Core','Worker','Application','IdentityPostgres')][string]$Group, [ValidateRange(0,5)][int]$Shard = 0)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'toolchain.ps1')
. (Join-Path $PSScriptRoot 'race-shards.ps1')
$go = Resolve-MIIGo
$workspaceRoot = Split-Path -Parent $PSScriptRoot
$executeGo = {
    param([string[]]$GoArguments, [bool]$Capture)
    if ($Capture) {
        # Capture stderr too: unknown enumeration diagnostics cannot be silently
        # discarded. CI downloads pinned modules before entering enumeration.
        $lines = @(& $go @GoArguments 2>&1)
        return [PSCustomObject]@{ ExitCode = $LASTEXITCODE; Lines = $lines }
    }
    & $go @GoArguments | Out-Host
    return [PSCustomObject]@{ ExitCode = $LASTEXITCODE; Lines = @() }
}.GetNewClosure()
Push-Location $workspaceRoot
try { Invoke-MIICIRace -Group $Group -Shard $Shard -Execute $executeGo }
finally { Pop-Location }
