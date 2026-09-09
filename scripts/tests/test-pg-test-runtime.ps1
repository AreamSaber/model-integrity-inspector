param([Parameter(Mandatory)][string]$RuntimeLibrary)

$ErrorActionPreference = 'Stop'
$scriptsRoot = Split-Path -Parent $PSScriptRoot
$repositoryRoot = Split-Path -Parent $scriptsRoot
. (Join-Path $scriptsRoot 'prepare-pg-test-runtime.ps1') -RuntimeLibrary $RuntimeLibrary
$sourcePath = Get-MIIPGRuntimeAbsolutePath -Path $RuntimeLibrary
$sourceBytes = [IO.File]::ReadAllBytes($sourcePath)
$fixture = Join-Path $repositoryRoot ('.tools/pg-runtime-regression-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
$junctions = [Collections.Generic.List[string]]::new()
$script:runtimeCaseCount = 0

function Test-MIIPGRuntimeCase {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][scriptblock]$Run, [string]$Reject)
    $caught = $null
    try { & $Run | Out-Null } catch { $caught = $_ }
    if ($Reject -and (-not $caught -or $caught.Exception.Message -notmatch $Reject)) {
        throw "FAIL $Name : expected $Reject; actual $caught"
    }
    if (-not $Reject -and $caught) { throw "FAIL $Name : $caught" }
    $script:runtimeCaseCount++
}

function New-MIIPGRuntimeFixture {
    param([Parameter(Mandatory)][string]$Name, [byte[]]$Bytes = $sourceBytes, [string]$FileName = 'VCRUNTIME140.dll')
    $directory = Join-Path $fixture $Name
    New-Item -ItemType Directory -Path $directory | Out-Null
    $path = Join-Path $directory $FileName
    [IO.File]::WriteAllBytes($path, $Bytes)
    return $path
}

function Test-MIIPGRuntimeFixtureLibrary {
    param([Parameter(Mandatory)][string]$Path)
    $pins = $stream = $null
    try {
        $absolute = Get-MIIPGRuntimeAbsolutePath -Path $Path
        $pins = Open-MIIPGRuntimeAncestors -Directory (Split-Path -Parent $absolute)
        $stream = [MIIPGTestRuntime.Native]::OpenRegularRead($absolute)
        Assert-MIIPGRuntimeLibrary -Path $absolute -Stream $stream
    } finally {
        if ($stream) { $stream.Dispose() }
        if ($pins) { foreach ($handle in $pins) { $handle.Dispose() } }
    }
}

try {
    Test-MIIPGRuntimeCase 'actual Microsoft-signed pinned x64 source' {
        $identity = Test-MIIPGRuntimeFixtureLibrary -Path $sourcePath
        if ($identity.authenticode_status -cne 'Valid' -or $identity.version -cne '14.51.36247.0') {
            throw 'Actual signed source identity mismatch.'
        }
    }
    Test-MIIPGRuntimeCase 'relative source rejected' -Reject 'ABSOLUTE_PATH_REQUIRED' {
        Get-MIIPGRuntimeAbsolutePath -Path './VCRUNTIME140.dll'
    }
    Test-MIIPGRuntimeCase 'ADS source rejected' -Reject 'ABSOLUTE_PATH_REQUIRED' {
        Get-MIIPGRuntimeAbsolutePath -Path ($sourcePath + ':stream')
    }
    $wrongName = New-MIIPGRuntimeFixture -Name 'wrong-name' -FileName 'other.dll'
    Test-MIIPGRuntimeCase 'wrong filename rejected before deployment' -Reject 'WRONG_NAME' {
        Install-MIIPGTestRuntime -RuntimeLibrary $wrongName -RepositoryRoot $repositoryRoot
    }
    $oversized = New-MIIPGRuntimeFixture -Name 'oversized' -Bytes ([byte[]]::new(4MB + 1))
    Test-MIIPGRuntimeCase 'oversized file rejected' -Reject 'FILE_SIZE_INVALID' { Test-MIIPGRuntimeFixtureLibrary -Path $oversized }
    $peOffset = [BitConverter]::ToInt32($sourceBytes, 60)
    $x86Bytes = [byte[]]$sourceBytes.Clone()
    $x86Bytes[$peOffset + 4] = 0x4C; $x86Bytes[$peOffset + 5] = 0x01
    $x86 = New-MIIPGRuntimeFixture -Name 'wrong-architecture' -Bytes $x86Bytes
    Test-MIIPGRuntimeCase 'actual PE machine x86 rejected' -Reject 'ARCHITECTURE_NOT_X64' { Test-MIIPGRuntimeFixtureLibrary -Path $x86 }
    $unsignedBytes = [byte[]]$sourceBytes.Clone()
    # PE32+ optional header data directory index 4 is the certificate table.
    # Removing its offset/size leaves a real unsigned DLL, not a mocked status.
    $certificateDirectory = $peOffset + 24 + 112 + (4 * 8)
    [Array]::Clear($unsignedBytes, $certificateDirectory, 8)
    $unsigned = New-MIIPGRuntimeFixture -Name 'unsigned' -Bytes $unsignedBytes
    if ((Get-AuthenticodeSignature -LiteralPath $unsigned).Status -eq [Management.Automation.SignatureStatus]::Valid) {
        throw 'Unsigned fixture still has a valid native signature; test cannot proceed.'
    }
    Test-MIIPGRuntimeCase 'real unsigned DLL rejected' -Reject 'MICROSOFT_SIGNATURE_REQUIRED' { Test-MIIPGRuntimeFixtureLibrary -Path $unsigned }
    $corruptBytes = [byte[]]$sourceBytes.Clone()
    $corruptBytes[0] = 0
    $corrupt = New-MIIPGRuntimeFixture -Name 'invalid-pe' -Bytes $corruptBytes
    Test-MIIPGRuntimeCase 'invalid PE rejected' -Reject 'PE_INVALID' { Test-MIIPGRuntimeFixtureLibrary -Path $corrupt }
    $safeSource = New-MIIPGRuntimeFixture -Name 'real-source-copy'
    $alias = Join-Path $fixture 'source-junction'
    New-Item -ItemType Junction -Path $alias -Target (Split-Path -Parent $safeSource) | Out-Null
    $junctions.Add($alias)
    Test-MIIPGRuntimeCase 'source ancestor reparse rejected' -Reject 'DIRECTORY_UNSAFE' {
        Install-MIIPGTestRuntime -RuntimeLibrary (Join-Path $alias 'VCRUNTIME140.dll') -RepositoryRoot $repositoryRoot
    }
    $fakeRepository = Join-Path $fixture 'repository'
    $fakeTools = Join-Path $fakeRepository '.tools'
    $fakeBin = Join-Path $fakeTools 'postgresql-18.6-3/pgsql/bin'
    New-Item -ItemType Directory -Path $fakeBin -Force | Out-Null
    Test-MIIPGRuntimeCase 'outside exact target rejected' -Reject 'TARGET_OUTSIDE_FIXED_DIRECTORY' {
        Assert-MIIPGRuntimeTarget -Path (Join-Path $fixture 'outside/VCRUNTIME140.dll') -ToolsRoot $fakeTools
    }
    Test-MIIPGRuntimeCase 'prefix-lookalike target rejected' -Reject 'TARGET_OUTSIDE_FIXED_DIRECTORY' {
        Assert-MIIPGRuntimeTarget -Path (Join-Path $fakeRepository '.tools-evil/postgresql-18.6-3/pgsql/bin/VCRUNTIME140.dll') -ToolsRoot $fakeTools
    }
    $different = Join-Path $fakeBin 'VCRUNTIME140.dll'
    [IO.File]::WriteAllText($different, 'existing-target-must-not-be-overwritten')
    $beforeDifferent = (Get-FileHash -Algorithm SHA256 -LiteralPath $different).Hash
    Test-MIIPGRuntimeCase 'different existing target rejected' -Reject 'EXISTING_FILE_DIFFERS_NO_OVERWRITE' {
        Install-MIIPGTestRuntime -RuntimeLibrary $sourcePath -RepositoryRoot $fakeRepository
    }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $different).Hash -cne $beforeDifferent) {
        throw 'Different target bytes were overwritten.'
    }
    $reparseRepository = Join-Path $fixture 'reparse-repository'
    $outsideTools = Join-Path $fixture 'junction-physical-tools'
    New-Item -ItemType Directory -Path $reparseRepository | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $outsideTools 'postgresql-18.6-3/pgsql/bin') -Force | Out-Null
    $targetAlias = Join-Path $reparseRepository '.tools'
    New-Item -ItemType Junction -Path $targetAlias -Target $outsideTools | Out-Null
    $junctions.Add($targetAlias)
    Test-MIIPGRuntimeCase 'target ancestor reparse rejected' -Reject 'DIRECTORY_UNSAFE' {
        Install-MIIPGTestRuntime -RuntimeLibrary $sourcePath -RepositoryRoot $reparseRepository
    }
    if (Test-Path -LiteralPath (Join-Path $outsideTools 'postgresql-18.6-3/pgsql/bin/VCRUNTIME140.dll')) {
        throw 'Reparse rejection still wrote an outside DLL.'
    }
    Test-MIIPGRuntimeCase 'held ancestor cannot be renamed while verified' {
        $locked = Join-Path $fixture 'locked-directory'
        New-Item -ItemType Directory -Path $locked | Out-Null
        $pins = Open-MIIPGRuntimeAncestors -Directory $locked
        try {
            $renameFailed = $false
            try { Move-Item -LiteralPath $locked -Destination (Join-Path $fixture 'renamed-directory') }
            catch { $renameFailed = $true }
            if (-not $renameFailed -or -not (Test-Path -LiteralPath $locked)) { throw 'Directory pin did not prevent rename.' }
        } finally { foreach ($handle in $pins) { $handle.Dispose() } }
    }
    Test-MIIPGRuntimeCase 'real entry point reuses exact installed identity and probes both actual tools' {
        $installed = Join-Path $repositoryRoot '.tools/postgresql-18.6-3/pgsql/bin/VCRUNTIME140.dll'
        $before = Get-Item -LiteralPath $installed
        $hashBefore = (Get-FileHash -Algorithm SHA256 -LiteralPath $installed).Hash
        & (Join-Path $scriptsRoot 'prepare-pg-test-runtime.ps1') -RuntimeLibrary $sourcePath
        $after = Get-Item -LiteralPath $installed
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $installed).Hash -cne $hashBefore -or
            $after.CreationTimeUtc -ne $before.CreationTimeUtc -or $after.LastWriteTimeUtc -ne $before.LastWriteTimeUtc) {
            throw 'Idempotent reuse changed the installed DLL.'
        }
    }
    Write-Output "PG test runtime regression passed: $script:runtimeCaseCount cases; actual Authenticode and filesystem probes, no database operations."
} finally {
    # Remove each owned junction itself first; recursive cleanup never traverses it.
    foreach ($junction in $junctions) {
        if (Test-Path -LiteralPath $junction) { [IO.Directory]::Delete($junction) }
    }
    $resolvedFixture = [IO.Path]::GetFullPath($fixture)
    $expectedPrefix = [IO.Path]::GetFullPath((Join-Path $repositoryRoot '.tools')) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolvedFixture.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolvedFixture) -notmatch '^pg-runtime-regression-[0-9a-f]{32}$' -or
        ((Get-Item -LiteralPath $resolvedFixture).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Refusing regression cleanup outside its exact owned temporary directory.'
    }
    Remove-Item -LiteralPath $resolvedFixture -Recurse -Force
}
