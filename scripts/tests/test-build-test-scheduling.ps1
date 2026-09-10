$ErrorActionPreference = 'Stop'
$scriptsRoot = Split-Path -Parent $PSScriptRoot

function Assert-MIIBuildTestScheduling {
    param([string]$Source)
    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($Source, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -ne 0) { throw 'Build script did not parse.' }
    $commands = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
        $node.CommandElements.Count -gt 1 -and
        $node.CommandElements[0] -is [Management.Automation.Language.VariableExpressionAst] -and
        $node.CommandElements[0].VariablePath.UserPath -ceq 'go' -and
        $node.CommandElements[1].Extent.Text -ceq 'test'
    }, $true))
    if ($commands.Count -ne 2) { throw 'Build must retain exactly the full and embedded frontend Go test commands.' }
    $expected = @('& $go test -p 1 -count=1 ./...', '& $go test -count=1 -tags webassets ./web ./internal/app')
    for ($index = 0; $index -lt $commands.Count; $index++) {
        $command = $commands[$index]
        if ($command.Extent.Text -cne $expected[$index]) { throw 'Go test scope, scheduling or fresh-run policy changed.' }
        # The test command must be an immediate try-block statement, not a
        # dormant function/conditional, a pipeline, or an ignored background job.
        $pipeline = $command.Parent
        if ($pipeline -isnot [Management.Automation.Language.PipelineAst] -or
            $pipeline.PipelineElements.Count -ne 1 -or $pipeline.Background -or
            $pipeline.Parent -isnot [Management.Automation.Language.StatementBlockAst] -or
            $pipeline.Parent.Parent -isnot [Management.Automation.Language.TryStatementAst] -or
            $pipeline.Parent.Parent.Body -ne $pipeline.Parent -or
            $pipeline.Parent.Parent.Parent -ne $ast.EndBlock) { throw 'Go tests must execute directly in the top-level build try block.' }
        $statements = @($pipeline.Parent.Statements)
        $position = [Array]::IndexOf($statements, $pipeline)
        $guard = if ($index -eq 0) { 'Go tests failed.' } else { 'Embedded frontend integration tests failed.' }
        $guardText = "if (`$LASTEXITCODE -ne 0) { throw '$guard' }"
        if ($position -lt 0 -or $position + 1 -ge $statements.Count -or
            $statements[$position + 1].Extent.Text -cne $guardText) { throw 'Every Go test command must fail the build immediately on error.' }
    }
}

$caseCount = 0
foreach ($script in @('build.ps1', 'package.ps1')) {
    $source = Get-Content -LiteralPath (Join-Path $scriptsRoot $script) -Raw
    Assert-MIIBuildTestScheduling -Source $source
    $caseCount++
    foreach ($replacement in @(
        '& $go test ./...', '& $go test -p 2 -count=1 ./...',
        '& $go test -p 1 ./...', '& $go test -p 1 -count=1 -short ./...',
        '& $go test -p 1 -count=1 -run TestSubset ./...',
        '& $go test -p 1 -count=1 ./internal/integrity/repository',
        '# & $go test -p 1 -count=1 ./...',
        'Write-Output ''& $go test -p 1 -count=1 ./...''',
        'if ($false) { & $go test -p 1 -count=1 ./... }',
        'function NeverCalled { & $go test -p 1 -count=1 ./... }',
        'function NeverCalled { try { & $go test -p 1 -count=1 ./... } finally {} }',
        '& $go test -p 1 -count=1 ./... | Out-Null',
        '& $go test -p 1 -count=1 ./... &'
    )) {
        $mutated = $source.Replace('& $go test -p 1 -count=1 ./...', $replacement)
        $rejected = $false
        try { Assert-MIIBuildTestScheduling -Source $mutated } catch { $rejected = $true }
        if (-not $rejected) { throw "Scheduling regression accepted in $script." }
        $caseCount++
    }
    foreach ($mutation in @(
        @('& $go test -count=1 -tags webassets ./web ./internal/app', '& $go test -tags webassets ./web ./internal/app'),
        @('if ($LASTEXITCODE -ne 0) { throw ''Go tests failed.'' }', '$LASTEXITCODE = 0'),
        @('if ($LASTEXITCODE -ne 0) { throw ''Embedded frontend integration tests failed.'' }', '# ignored embedded failure')
    )) {
        $mutated = $source.Replace($mutation[0], $mutation[1])
        $rejected = $false
        try { Assert-MIIBuildTestScheduling -Source $mutated } catch { $rejected = $true }
        if (-not $rejected) { throw "Execution failure regression accepted in $script." }
        $caseCount++
    }
}
Write-Output "Build test scheduling policy: $caseCount cases passed."
