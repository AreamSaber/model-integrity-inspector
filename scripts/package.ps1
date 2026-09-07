$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'toolchain.ps1')

$workspaceRoot = Split-Path -Parent $PSScriptRoot
$go = Resolve-MIIGo
$null = Resolve-MIINode
$pnpm = Resolve-MIIPnpm
$webRoot = Join-Path $workspaceRoot 'web'
$outputRoot = Join-Path $workspaceRoot 'artifacts\package'
$version = (Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $workspaceRoot 'VERSION')).Trim()

if ($version -notmatch '^[0-9A-Za-z][0-9A-Za-z._-]*$') {
    throw "VERSION contains unsafe artifact-name characters: $version"
}

Push-Location $workspaceRoot
try {
    $commit = (& git rev-parse --verify HEAD | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40,64}$') { throw 'A valid Git commit is required for packaging.' }
    $worktreeStatus = (& git status --porcelain --untracked-files=normal | Out-String).Trim()
    if (-not [string]::IsNullOrWhiteSpace($worktreeStatus)) {
        throw 'Refusing to create a release-style package from a dirty Git worktree.'
    }
    if (Test-Path -LiteralPath $outputRoot -PathType Container) {
        $resolvedArtifactRoot = [IO.Path]::GetFullPath((Join-Path $workspaceRoot 'artifacts')).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
        $resolvedOutputRoot = [IO.Path]::GetFullPath($outputRoot)
        if (-not $resolvedOutputRoot.StartsWith($resolvedArtifactRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to clean a package directory outside the workspace artifact root.'
        }
        foreach ($staleArtifact in Get-ChildItem -LiteralPath $resolvedOutputRoot -File | Where-Object Name -Like 'mii*') {
            Remove-Item -LiteralPath $staleArtifact.FullName -Force
        }
    }
    $builtAt = (& git show -s --format=%cI HEAD | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($builtAt)) { throw 'Unable to read the commit timestamp.' }
    $goos = (& $go env GOOS | Out-String).Trim()
    $goarch = (& $go env GOARCH | Out-String).Trim()

    & $pnpm --dir $webRoot install --frozen-lockfile
    if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
    & $pnpm --dir $webRoot test
    if ($LASTEXITCODE -ne 0) { throw 'Frontend tests failed.' }
    & $pnpm --dir $webRoot build
    if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
    & $go test ./...
    if ($LASTEXITCODE -ne 0) { throw 'Go tests failed.' }

    New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null
    $shortCommit = $commit.Substring(0, 12)
    $artifactStem = "mii_${version}_${shortCommit}_${goos}_${goarch}"
    $binaryExtension = if ($goos -eq 'windows') { '.exe' } else { '' }
    $binaryPath = Join-Path $outputRoot "$artifactStem$binaryExtension"
    $ldflags = "-s -w -X model-integrity-inspector.local/mii/internal/buildinfo.version=$version -X model-integrity-inspector.local/mii/internal/buildinfo.commit=$commit -X model-integrity-inspector.local/mii/internal/buildinfo.builtAt=$builtAt"
    & $go test -tags webassets ./web ./internal/app
    if ($LASTEXITCODE -ne 0) { throw 'Embedded frontend integration tests failed.' }
    & $go build -tags webassets -trimpath -buildvcs=true -ldflags $ldflags -o $binaryPath ./cmd/mii
    if ($LASTEXITCODE -ne 0) { throw 'Versioned Go build failed.' }

    $embeddedBuild = (& $binaryPath version | Out-String).Trim() | ConvertFrom-Json
    if ($embeddedBuild.version -ne $version -or $embeddedBuild.commit -ne $commit -or $embeddedBuild.built_at -ne $builtAt) {
        throw 'Packaged binary build metadata does not match VERSION and Git HEAD.'
    }

    $webArchive = Join-Path $outputRoot "mii-web_${version}_${shortCommit}.zip"
    Compress-Archive -Path (Join-Path $webRoot 'dist\*') -DestinationPath $webArchive -Force

    $noticePath = Join-Path $outputRoot "$artifactStem.THIRD_PARTY_NOTICES.md"
    Copy-Item -LiteralPath (Join-Path $workspaceRoot 'internal/integrity/tokenizer/THIRD_PARTY_NOTICES.md') -Destination $noticePath

    $artifacts = @($binaryPath, $webArchive, $noticePath) | ForEach-Object {
        [ordered]@{
            file = Split-Path -Leaf $_
            sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $_).Hash.ToLowerInvariant()
            bytes = (Get-Item -LiteralPath $_).Length
        }
    }
    $manifestPath = Join-Path $outputRoot "$artifactStem.manifest.json"
    $manifest = [ordered]@{
        schema_version = 1
        product = 'model-integrity-inspector'
        version = $version
        commit = $commit
        built_at = $builtAt
        goos = $goos
        goarch = $goarch
        artifacts = $artifacts
    }
    [IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))

    $checksumPath = Join-Path $outputRoot "$artifactStem.SHA256SUMS"
    $checksumTargets = @($binaryPath, $webArchive, $noticePath, $manifestPath)
    $checksumLines = @($checksumTargets | ForEach-Object {
        "$((Get-FileHash -Algorithm SHA256 -LiteralPath $_).Hash.ToLowerInvariant())  $(Split-Path -Leaf $_)"
    })
    [IO.File]::WriteAllLines($checksumPath, $checksumLines, [Text.UTF8Encoding]::new($false))
} finally {
    Pop-Location
}

Write-Output "Package completed: version=$version, commit=$commit, platform=$goos/$goarch"
Write-Output "Artifacts: $outputRoot"
