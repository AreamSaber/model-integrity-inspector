param(
    [string]$Repository,
    [string]$Branch = 'main',
    [switch]$Preview
)

$ErrorActionPreference = 'Stop'
$workspaceRoot = Split-Path -Parent $PSScriptRoot
$policyPath = Join-Path $workspaceRoot '.github\branch-protection\main.json'

if ([string]::IsNullOrWhiteSpace($Repository)) {
    Push-Location $workspaceRoot
    try {
        $remote = (& git remote get-url origin 2>$null | Out-String).Trim()
    } finally {
        Pop-Location
    }
    if ($remote -match 'github\.com[:/](?<repository>[^/]+/[^/]+?)(?:\.git)?$') {
        $Repository = $Matches.repository
    }
}
if ($Repository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') {
    throw 'Repository must be a GitHub owner/name value or resolvable from the origin remote.'
}
if ($Branch -notmatch '^[A-Za-z0-9._/-]+$') {
    throw 'Branch contains unsupported characters.'
}

$policy = Get-Content -Raw -Encoding UTF8 -LiteralPath $policyPath | ConvertFrom-Json
if ($policy.required_status_checks.contexts -notcontains 'm0-04-required') {
    throw 'Branch protection policy must require m0-04-required.'
}
if ($Preview) {
    Write-Output "Preview: PUT repos/$Repository/branches/$Branch/protection"
    $policy | ConvertTo-Json -Depth 8
    exit 0
}

$gh = Get-Command gh -ErrorAction SilentlyContinue
if (-not $gh) { throw 'GitHub CLI was not found. Install gh and authenticate before applying branch protection.' }
& $gh.Source auth status
if ($LASTEXITCODE -ne 0) { throw 'GitHub CLI is not authenticated.' }
& $gh.Source api --method PUT -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28' "repos/$Repository/branches/$Branch/protection" --input $policyPath
if ($LASTEXITCODE -ne 0) { throw 'Applying branch protection failed.' }

$applied = & $gh.Source api -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28' "repos/$Repository/branches/$Branch/protection"
if ($LASTEXITCODE -ne 0 -or $applied -notmatch 'm0-04-required') {
    throw 'Branch protection verification failed.'
}
Write-Output "Branch protection applied and verified: $Repository/$Branch"
