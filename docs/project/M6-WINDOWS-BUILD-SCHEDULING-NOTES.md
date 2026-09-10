# Windows build test scheduling checkpoint

Date: 2026-09-10. This changes test-package scheduling, not application deadlines,
database durability, test selection, or formal approval. The new recipe still
requires an actual complete native run; policy tests alone are not CI success.

## Observed failure

GitHub run `34334609860`, commit `0268a09`, finished with 18 successful jobs and
two failures: `package-windows-2025` and its dependent `m0-04-required` gate.
Image, Linux package, quality, all repository/Worker race shards, identity PG,
dependency scan and native PG backup succeeded. This confirms the previous
Docker CSV input repair, but does not validate the Windows package.

The Windows job `102411006255` runs `scripts/package.ps1`. Its first ordinary
`go test ./...` pass failed before the embedded-assets pass and package output.
The actual log shows overlapping package lifetimes: repository approximately
09:30:17–09:40:17 UTC, Worker 09:30:48–09:40:40, and API 09:29:40–09:36:07.
Repository exhausted its existing ten-minute package timeout while a SQLite
fixture initialization was in Windows `FlushFileBuffers`/commit. This stack
does not prove that the currently running subtest was deadlocked.

The app reported Worker claim failure then `database_unavailable` exit; later
HTTP dial errors followed application shutdown. Worker and capture fixtures
also failed. The closed diagnostics do not reveal the original native database
error, so resource contention is a mitigation hypothesis, not a proved unique
root cause. A separate early-failure Runner cleanup issue is tracked in
`M6-WINDOWS-CI-20260910-NOTES.md` when that unit is finalized.

## Changes and invariant checks

Both build and package scripts now execute `go test -p 1 -count=1 ./...`.
Independent database-heavy package binaries no longer compete on one runner's
disk. Every package and test remains selected, intra-package concurrency is
unchanged, and no short mode, test filter, retry or timeout increase was added.
The separate embedded-frontend suite now also uses `-count=1`. Existing immediate
exit-code checks, clean-tree packaging guard and all independent race jobs remain.

`scripts/tests/test-build-test-scheduling.ps1` uses the PowerShell AST, not a
substring that can match comments, strings or an uncalled function. It verifies
the two exact live top-level try-block test commands and their following failure
guards. Mutations cover parallelism, caching, omitted tests, short/subset mode,
comment/string/dormant function lookalikes, pipelines/background execution and
ignored failures. The check is included in `scripts/lint.ps1`.

Root verification:

- Actual original recipes: new policy fails (exit 1, 0.382s).
- Updated recipes: 34 policy cases pass.
- Existing M0-04 policy: 165 cases pass; race coverage policy: 87 cases pass.
- Entire Go contracts package, three fresh rounds: PASS 1.164s.
- Full application/Worker/repository native run and new remote CI: pending.

This is not a performance/capacity acceptance, a complete Windows failure fix,
or V1.0 completion. The original 77 requirements and 91 tasks remain in scope.
