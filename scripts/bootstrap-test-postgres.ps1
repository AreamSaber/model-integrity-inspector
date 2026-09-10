param([switch]$Force)

$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'This local test bootstrap is Windows x64 only; it never installs a system service.'
}
$workspaceRoot = Split-Path -Parent $PSScriptRoot
$toolRoot = Join-Path $workspaceRoot '.tools'
$cacheRoot = Join-Path $toolRoot 'cache'
$postgresRoot = Join-Path $toolRoot 'postgresql-18.6-3'
$archivePath = Join-Path $cacheRoot 'postgresql-18.6-3-windows-x64-binaries.zip'
$downloadUrl = 'https://get.enterprisedb.com/postgresql/postgresql-18.6-3-windows-x64-binaries.zip'
# This is a locally observed hash of the HTTPS download, NOT an independently
# published/signed vendor checksum. It pins future replays against byte drift.
# Provenance: postgresql.org/download/windows/ -> EDB binaries -> fileid=1260488.
$expectedHash = '59f8ce701c63c2ed623c665a5e51b3ef6f2e37ccf837b68ffeed0742d0ae6abd'

function Assert-PostgresLocalPath {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Within)
    $allowed = [IO.Path]::GetFullPath($Within).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not $resolved.StartsWith($allowed, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing a PostgreSQL test path outside the intended tool directory.'
    }
    $ancestor = $resolved
    while ($ancestor -and $ancestor.Length -ge $allowed.TrimEnd('\', '/').Length) {
        if (Test-Path -LiteralPath $ancestor) {
            if ((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'PostgreSQL test paths must not pass through symlinks or junctions.'
            }
        }
        $ancestor = Split-Path -Parent $ancestor
    }
}

Assert-PostgresLocalPath -Path $archivePath -Within $toolRoot
Assert-PostgresLocalPath -Path $postgresRoot -Within $toolRoot
New-Item -ItemType Directory -Force -Path $cacheRoot | Out-Null
if ($Force -and (Test-Path -LiteralPath $archivePath)) {
    Remove-Item -LiteralPath $archivePath -Force
}
for ($attempt = 0; $attempt -lt 2; $attempt++) {
    if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $archivePath
    }
    $archiveHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash.ToLowerInvariant()
    if ($archiveHash -eq $expectedHash) { break }
    Remove-Item -LiteralPath $archivePath -Force
    if ($attempt -eq 1) { throw 'PostgreSQL archive differs from the observed pinned hash; download removed.' }
    Write-Warning 'Cached PostgreSQL bytes differ from the pinned observation; downloading once more.'
}

$postgresExecutable = Join-Path $postgresRoot 'pgsql/bin/postgres.exe'
if ($Force -and (Test-Path -LiteralPath $postgresRoot)) {
    $running = @(Get-Process -Name postgres -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($postgresRoot, [StringComparison]::OrdinalIgnoreCase) })
    if ($running.Count -gt 0) { throw 'Stop the managed PostgreSQL test instance before forcing a binary refresh.' }
    Assert-PostgresLocalPath -Path $postgresRoot -Within $toolRoot
    Remove-Item -LiteralPath $postgresRoot -Recurse -Force
}

if (-not (Test-Path -LiteralPath $postgresExecutable -PathType Leaf)) {
    if (Test-Path -LiteralPath $postgresRoot) { throw 'Partial PostgreSQL extraction exists; use -Force after stopping the test runtime.' }
    New-Item -ItemType Directory -Path $postgresRoot | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
        foreach ($entry in $zip.Entries) {
            # Exclude pgAdmin, StackBuilder, documentation and other installers.
            if ($entry.FullName -notmatch '^pgsql/(bin|lib|share)/' -or $entry.FullName.EndsWith('/')) { continue }
            $destination = Join-Path $postgresRoot $entry.FullName
            Assert-PostgresLocalPath -Path $destination -Within $postgresRoot
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $destination, $false)
        }
    } finally {
        $zip.Dispose()
    }
}

$binaries = @()
Add-Type -AssemblyName System.IO.Compression.FileSystem
$verifiedArchive = [IO.Compression.ZipFile]::OpenRead($archivePath)
try {
foreach ($binary in @('postgres.exe', 'initdb.exe', 'pg_ctl.exe', 'psql.exe', 'createdb.exe', 'pg_isready.exe')) {
    $path = Join-Path $postgresRoot "pgsql/bin/$binary"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "PostgreSQL archive is missing $binary." }
    $installedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
    $archiveEntry = $verifiedArchive.GetEntry("pgsql/bin/$binary")
    if (-not $archiveEntry) { throw "Pinned archive is missing $binary." }
    $entryStream = $archiveEntry.Open()
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { $entryHash = [Convert]::ToHexString($hasher.ComputeHash($entryStream)).ToLowerInvariant() }
    finally { $entryStream.Dispose(); $hasher.Dispose() }
    if ($installedHash -ne $entryHash) { throw "Installed PostgreSQL binary differs from pinned archive: $binary. Use -Force only after stopping the test server." }
    $version = (& $path --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $version -notmatch '\(PostgreSQL\) 18\.6$') { throw "Unexpected PostgreSQL binary version: $binary" }
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    $binaries += [ordered]@{
        file = $binary
        version = $version
        sha256 = $installedHash
        authenticode_status = [string]$signature.Status
        signer = $(if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null })
    }
}
} finally { $verifiedArchive.Dispose() }
$provenance = [ordered]@{
    version = '18.6-3'
    source_page = 'https://www.postgresql.org/download/windows/'
    vendor_page = 'https://www.enterprisedb.com/download-postgresql-binaries'
    vendor_link = 'https://sbp.enterprisedb.com/getfile.jsp?fileid=1260488'
    download_url = $downloadUrl
    archive_sha256 = $archiveHash
    checksum_trust = 'Observed HTTPS-download hash; no independent vendor checksum located. Not a claim of archive authenticity.'
    binaries = $binaries
}
[IO.File]::WriteAllText((Join-Path $postgresRoot 'provenance.json'), ($provenance | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
Write-Warning 'PostgreSQL development archive is pinned to an observed HTTPS hash, not an independent vendor checksum. See ignored provenance.json for binary signature observations.'
Write-Output "PostgreSQL 18.6 test binaries are ready under $postgresRoot; no service, firewall, PATH or database changes were made."
