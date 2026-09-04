$ErrorActionPreference = 'Stop'

$workspaceRoot = Split-Path -Parent $PSScriptRoot
$syftExecutable = Join-Path $workspaceRoot '.tools\syft\syft.exe'
if (-not (Test-Path -LiteralPath $syftExecutable -PathType Leaf)) {
    & (Join-Path $PSScriptRoot 'bootstrap-syft.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'Syft bootstrap failed.' }
}

$version = (Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $workspaceRoot 'VERSION')).Trim()
Push-Location $workspaceRoot
try {
    $commit = (& git rev-parse --verify HEAD | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40,64}$') { throw 'A valid Git commit is required for SBOM generation.' }
    $worktreeStatus = (& git status --porcelain --untracked-files=normal | Out-String).Trim()
    if (-not [string]::IsNullOrWhiteSpace($worktreeStatus)) {
        throw 'Refusing to generate a release-style SBOM from a dirty Git worktree.'
    }
    $shortCommit = $commit.Substring(0, 12)
    $outputRoot = Join-Path $workspaceRoot 'artifacts\sbom'
    $outputPath = Join-Path $outputRoot "mii_${version}_${shortCommit}_source.cdx.json"
    New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null

    & $syftExecutable scan "dir:$workspaceRoot" --config (Join-Path $workspaceRoot '.syft.yaml') -o "cyclonedx-json=$outputPath"
    if ($LASTEXITCODE -ne 0) { throw 'Syft SBOM generation failed.' }

    $sbom = Get-Content -Raw -Encoding UTF8 -LiteralPath $outputPath | ConvertFrom-Json
    if ($sbom.bomFormat -ne 'CycloneDX' -or [string]::IsNullOrWhiteSpace($sbom.specVersion)) {
        throw 'Generated SBOM is not a valid CycloneDX JSON document.'
    }
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $outputPath).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText("$outputPath.sha256", "$hash  $(Split-Path -Leaf $outputPath)`n", [Text.UTF8Encoding]::new($false))
} finally {
    Pop-Location
}

Write-Output "SBOM completed: $outputPath"
Write-Output "SBOM SHA-256: $hash"
