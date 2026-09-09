param([string]$RuntimeLibrary)

$ErrorActionPreference = 'Stop'

function Initialize-MIIPGRuntimeNative {
    if ('MIIPGTestRuntime.Native' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
namespace MIIPGTestRuntime {
    public static class Native {
        [StructLayout(LayoutKind.Sequential)]
        struct FileInfo {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security,
            uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfo info);
        public static SafeFileHandle PinDirectory(string path) {
            // LIST_DIRECTORY|READ_ATTRIBUTES, share READ|WRITE but not DELETE;
            // metadata-only access does not prevent rename on Windows. Opening the
            // reparse point itself prevents transparent junction traversal.
            var handle = CreateFileW(path, 0x81, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
            FileInfo info;
            if (handle.IsInvalid || !GetFileInformationByHandle(handle, out info) ||
                (info.Attributes & 0x400) != 0 || (info.Attributes & 0x10) == 0) {
                handle.Dispose(); throw new IOException("MI_PG_RUNTIME_DIRECTORY_UNSAFE");
            }
            return handle;
        }
        public static FileStream OpenRegularRead(string path) {
            var handle = CreateFileW(path, 0x80000000, 1, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero);
            FileInfo info;
            if (handle.IsInvalid || !GetFileInformationByHandle(handle, out info) ||
                (info.Attributes & 0x410) != 0 || info.Links != 1) {
                handle.Dispose(); throw new IOException("MI_PG_RUNTIME_FILE_UNSAFE");
            }
            return new FileStream(handle, FileAccess.Read);
        }
        static async Task<string> BoundedText(StreamReader stream) {
            var result = new StringBuilder();
            var buffer = new char[128];
            for (;;) {
                int count = await stream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                if (count == 0) return result.ToString();
                if (result.Length + count > 256) throw new IOException("MI_PG_RUNTIME_VERSION_OUTPUT_LIMIT");
                result.Append(buffer, 0, count);
            }
        }
        public static void VerifyVersion(string executable, string name, string systemRoot) {
            var info = new ProcessStartInfo(executable) {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true,
                WorkingDirectory = Path.GetDirectoryName(executable)
            };
            info.ArgumentList.Add("--version");
            info.Environment.Clear();
            info.Environment["LANG"] = "C";
            info.Environment["LC_ALL"] = "C";
            info.Environment["SystemRoot"] = systemRoot;
            using (var process = new Process { StartInfo = info }) {
                Task<string> stdout = null, stderr = null;
                try {
                    if (!process.Start()) throw new IOException("MI_PG_RUNTIME_VERSION_START");
                    process.StandardInput.Close();
                    stdout = BoundedText(process.StandardOutput);
                    stderr = BoundedText(process.StandardError);
                    var clock = Stopwatch.StartNew();
                    while (!process.WaitForExit(25)) {
                        if (clock.ElapsedMilliseconds >= 5000 || stdout.IsFaulted || stderr.IsFaulted)
                            throw new IOException("MI_PG_RUNTIME_VERSION_FAILED");
                    }
                    if (!Task.WaitAll(new Task[] { stdout, stderr }, 5000))
                        throw new IOException("MI_PG_RUNTIME_VERSION_DRAIN");
                    string expected = name + " (PostgreSQL) 18.6";
                    if (process.ExitCode != 0 || stderr.Result.Length != 0 ||
                        (stdout.Result != expected + "\r\n" && stdout.Result != expected + "\n"))
                        throw new IOException("MI_PG_RUNTIME_VERSION_MISMATCH");
                } catch {
                    // Fixed trusted --version probe only; this is not the
                    // product's arbitrary-duration native process executor.
                    try { if (!process.HasExited) { process.Kill(true); process.WaitForExit(5000); } } catch { }
                    try { process.StandardOutput.Dispose(); process.StandardError.Dispose(); } catch { }
                    throw new IOException("MI_PG_RUNTIME_VERSION_FAILED");
                }
            }
        }
    }
}
'@
}

function Get-MIIPGRuntimeAbsolutePath {
    param([Parameter(Mandatory)][string]$Path)
    if ($Path.Length -gt 4096 -or $Path -notmatch '^[A-Za-z]:[\\/]' -or
        $Path.Substring(2).Contains(':') -or $Path.IndexOfAny([char[]]"`0`r`n") -ge 0) {
        throw 'MI_PG_RUNTIME_ABSOLUTE_PATH_REQUIRED'
    }
    return [IO.Path]::GetFullPath($Path)
}

function Open-MIIPGRuntimeAncestors {
    param([Parameter(Mandatory)][string]$Directory)
    Initialize-MIIPGRuntimeNative
    $absolute = Get-MIIPGRuntimeAbsolutePath -Path $Directory
    $paths = [Collections.Generic.List[string]]::new()
    $cursor = $absolute
    while ($cursor) {
        $paths.Insert(0, $cursor)
        $parent = [IO.Directory]::GetParent($cursor)
        $cursor = if ($parent) { $parent.FullName } else { $null }
    }
    if ($paths.Count -gt 128) { throw 'MI_PG_RUNTIME_PATH_DEPTH_LIMIT' }
    $handles = [Collections.Generic.List[IDisposable]]::new()
    try {
        foreach ($path in $paths) { $handles.Add([MIIPGTestRuntime.Native]::PinDirectory($path)) }
        return ,$handles
    } catch {
        foreach ($handle in $handles) { $handle.Dispose() }
        throw
    }
}

function Assert-MIIPGRuntimeTarget {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ToolsRoot)
    $tools = Get-MIIPGRuntimeAbsolutePath -Path $ToolsRoot
    $target = Get-MIIPGRuntimeAbsolutePath -Path $Path
    $expected = [IO.Path]::GetFullPath((Join-Path $tools 'postgresql-18.6-3/pgsql/bin/VCRUNTIME140.dll'))
    if (-not $target.Equals($expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'MI_PG_RUNTIME_TARGET_OUTSIDE_FIXED_DIRECTORY'
    }
    $pins = Open-MIIPGRuntimeAncestors -Directory (Split-Path -Parent $target)
    return ,$pins
}

function Get-MIIPGRuntimeHash {
    param([Parameter(Mandatory)][IO.Stream]$Stream)
    $Stream.Position = 0
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return [Convert]::ToHexString($hash.ComputeHash($Stream)).ToLowerInvariant() }
    finally { $hash.Dispose(); $Stream.Position = 0 }
}

function Assert-MIIPGRuntimeLibrary {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][IO.Stream]$Stream)
    if ([IO.Path]::GetFileName($Path) -ine 'VCRUNTIME140.dll') { throw 'MI_PG_RUNTIME_WRONG_NAME' }
    if ($Stream.Length -lt 128 -or $Stream.Length -gt 4MB) { throw 'MI_PG_RUNTIME_FILE_SIZE_INVALID' }
    $reader = [IO.BinaryReader]::new($Stream, [Text.Encoding]::ASCII, $true)
    try {
        $Stream.Position = 0
        if ($reader.ReadUInt16() -ne 0x5A4D) { throw 'MI_PG_RUNTIME_PE_INVALID' }
        $Stream.Position = 60
        $peOffset = [int64]$reader.ReadUInt32()
        if ($peOffset -lt 64 -or $peOffset -gt $Stream.Length - 26) { throw 'MI_PG_RUNTIME_PE_INVALID' }
        $Stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x4550) { throw 'MI_PG_RUNTIME_PE_INVALID' }
        if ($reader.ReadUInt16() -ne 0x8664) { throw 'MI_PG_RUNTIME_ARCHITECTURE_NOT_X64' }
        $Stream.Position = $peOffset + 22
        if (($reader.ReadUInt16() -band 0x2000) -eq 0 -or $reader.ReadUInt16() -ne 0x20B) {
            throw 'MI_PG_RUNTIME_PE_NOT_X64_DLL'
        }
    } finally { $reader.Dispose(); $Stream.Position = 0 }
    $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
    $versionText = '{0}.{1}.{2}.{3}' -f $version.FileMajorPart, $version.FileMinorPart, $version.FileBuildPart, $version.FilePrivatePart
    if ($versionText -cne '14.51.36247.0') { throw 'MI_PG_RUNTIME_VERSION_NOT_PINNED' }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        -not $signature.SignerCertificate -or $signature.SignerCertificate.Subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)' -or
        $signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -notin
            @('Microsoft Windows Software Compatibility Publisher', 'Microsoft Corporation')) {
        throw 'MI_PG_RUNTIME_MICROSOFT_SIGNATURE_REQUIRED'
    }
    $sha256 = Get-MIIPGRuntimeHash -Stream $Stream
    # Locally observed bytes of an already installed Microsoft-signed runtime;
    # not an independently published vendor checksum or redistribution grant.
    if ($sha256 -cne 'd1f4225df2cd877dbf130d5668a021dce3f94118455ff5ec952061c30afc9ce7') {
        throw 'MI_PG_RUNTIME_BYTES_NOT_PINNED'
    }
    return [ordered]@{ sha256 = $sha256; version = $versionText; bytes = $Stream.Length;
        architecture = 'x64'; authenticode_status = [string]$signature.Status;
        signer = $signature.SignerCertificate.Subject; signer_thumbprint = $signature.SignerCertificate.Thumbprint }
}

function Install-MIIPGTestRuntime {
    param([Parameter(Mandatory)][string]$RuntimeLibrary, [Parameter(Mandatory)][string]$RepositoryRoot)
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess) {
        throw 'MI_PG_RUNTIME_REQUIRES_WINDOWS_X64'
    }
    $source = Get-MIIPGRuntimeAbsolutePath -Path $RuntimeLibrary
    if ([IO.Path]::GetFileName($source) -ine 'VCRUNTIME140.dll') { throw 'MI_PG_RUNTIME_WRONG_NAME' }
    $repository = Get-MIIPGRuntimeAbsolutePath -Path $RepositoryRoot
    $tools = Join-Path $repository '.tools'
    $target = Join-Path $tools 'postgresql-18.6-3/pgsql/bin/VCRUNTIME140.dll'
    $sourcePins = $targetPins = $sourceStream = $targetStream = $null
    try {
        $sourcePins = Open-MIIPGRuntimeAncestors -Directory (Split-Path -Parent $source)
        $sourceStream = [MIIPGTestRuntime.Native]::OpenRegularRead($source)
        $identity = Assert-MIIPGRuntimeLibrary -Path $source -Stream $sourceStream
        $targetPins = Assert-MIIPGRuntimeTarget -Path $target -ToolsRoot $tools
        $reused = Test-Path -LiteralPath $target
        if (-not $reused) {
            $copy = [IO.FileStream]::new($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
            try { $sourceStream.Position = 0; $sourceStream.CopyTo($copy, 65536); $copy.Flush($true) }
            finally { $copy.Dispose() }
        }
        $targetStream = [MIIPGTestRuntime.Native]::OpenRegularRead($target)
        if ((Get-MIIPGRuntimeHash -Stream $targetStream) -cne $identity.sha256) {
            throw 'MI_PG_RUNTIME_EXISTING_FILE_DIFFERS_NO_OVERWRITE'
        }
        $targetIdentity = Assert-MIIPGRuntimeLibrary -Path $target -Stream $targetStream
        $bin = Split-Path -Parent $target
        $systemRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
        foreach ($tool in @('pg_dump', 'pg_restore')) {
            $toolPath = Join-Path $bin "$tool.exe"
            $toolStream = [MIIPGTestRuntime.Native]::OpenRegularRead($toolPath)
            try { [MIIPGTestRuntime.Native]::VerifyVersion($toolPath, $tool, $systemRoot) }
            finally { $toolStream.Dispose() }
        }
        $record = [ordered]@{
            purpose = 'Local development/test prerequisite only; not a product redistribution authorization.'
            source = $source; target = $target; runtime = $targetIdentity
            postgres_tools = @('pg_dump (PostgreSQL) 18.6', 'pg_restore (PostgreSQL) 18.6')
            environment = @('LANG=C', 'LC_ALL=C', 'SystemRoot'); inherited_path = $false
            licensing_reference = 'https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files?view=msvc-170'
        }
        $recordPath = Join-Path (Split-Path -Parent (Split-Path -Parent $bin)) 'local-runtime-provenance.json'
        $json = ($record | ConvertTo-Json -Depth 6) + "`n"
        if (Test-Path -LiteralPath $recordPath) {
            $existing = [MIIPGTestRuntime.Native]::OpenRegularRead($recordPath)
            try {
                if ($existing.Length -gt 16384) { throw 'MI_PG_RUNTIME_PROVENANCE_DIFFERS' }
                $reader = [IO.StreamReader]::new($existing, [Text.UTF8Encoding]::new($false), $true, 4096, $true)
                try { if ($reader.ReadToEnd() -cne $json) { throw 'MI_PG_RUNTIME_PROVENANCE_DIFFERS' } }
                finally { $reader.Dispose() }
            } finally { $existing.Dispose() }
        } else {
            $recordStream = [IO.FileStream]::new($recordPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
            try { $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json); $recordStream.Write($bytes, 0, $bytes.Length); $recordStream.Flush($true) }
            finally { $recordStream.Dispose() }
        }
        Write-Output "PostgreSQL 18.6 local runtime verified (reused=$reused); no database, system directory, registry or PATH changes."
        Write-Warning 'The ignored runtime DLL is for this local test environment only. Production redistribution rights and official runtime prerequisites remain separate.'
    } finally {
        if ($targetStream) { $targetStream.Dispose() }
        if ($sourceStream) { $sourceStream.Dispose() }
        if ($targetPins) { foreach ($handle in $targetPins) { $handle.Dispose() } }
        if ($sourcePins) { foreach ($handle in $sourcePins) { $handle.Dispose() } }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    if (-not $RuntimeLibrary) { throw 'Explicit -RuntimeLibrary is required; no ambient DLL search is performed.' }
    Install-MIIPGTestRuntime -RuntimeLibrary $RuntimeLibrary -RepositoryRoot (Split-Path -Parent $PSScriptRoot)
}
