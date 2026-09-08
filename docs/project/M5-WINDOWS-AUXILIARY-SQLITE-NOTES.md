# Windows auxiliary SQLite connection diagnosis and test-only repair

## Original CI evidence

The Windows job for head `6fdfd6cbd08aab3b12cb88a02352823710ce779a`,
run `34187516642`, job `101938788963`, failed on 2026-09-08 during
`Build versioned package`:

- The first ordinary Go pass completed successfully, including Worker (184.921s).
- The later `go test -tags webassets ./web ./internal/app` failed in
  `TestApplicationEvidenceDisplayActualTLSMultiBlockAuthorization/sqlite/evidence.read`.
- The failure was `evidence_stream_pipeline_test.go:392: commit scoped permission
  revocation`; the permission subtest took 0.18s, its SQLite parent 14.29s, the
  whole parent 14.33s, and the app package 33.205s. The log was emitted at
  04:44:08 UTC; `package.ps1:55` then rejected embedded frontend integration tests.
- The bounded app diagnostic contained only the normal listener-start event, with
  `truncated=false`. No Worker/serve failure classification was emitted.

That error text comes from one of the two independent `DELETE` statements in
`pipelineRemoveDisplayPermission`, not an explicit `sql.Tx.Commit`. The old helper
did not disclose the role/member phase, driver code or context state, so the exact
CI SQL failure remains **unproven**. This was not evidence of the earlier renew,
HTTP polling or pure request-redaction failures. The quality job was still in its
race step at the last diagnostic query; its partial logs were unavailable. This
note makes no later CI success claim.

The relevant helper contents were also read from GitHub at `ref=6fdfd6c`, not
assumed from newer local changes. `configurePipelineRetention` used bare
`sql.Open("sqlite", cfg.DatabasePath)`. The production repository uses explicit
per-connection `busy_timeout(5000)`, `foreign_keys(1)`, `journal_mode(WAL)`,
`synchronous(FULL)`, `_txlock=immediate`, and a one-connection SQLite pool. The
modernc v1.58.0 source does not apply a busy timeout to a bare path by default.
There is no explicit deferred transaction around the auxiliary permission reads
and deletes, so this diagnosis must not be mislabeled as a proved BUSY_SNAPSHOT.

## Controlled evidence and red test

`TestPipelineAuxiliarySQLiteBareConnectionContendsWithWriter` retains the original
bare-connection behavior as a diagnostic control, using only a fresh temporary
SQLite file initialized by actual `repository.Open`. Two independent bare
connections both observe busy timeout 0, foreign keys 0, and persistent WAL mode.
One synchronously acquires `BEGIN IMMEDIATE`; the other's scoped DELETE then
returns exact modernc code 5 (`SQLITE_BUSY`) while its context is active, leaving
the row unchanged. After lock release, an independent unlocked positive-control
DELETE affects exactly one row. No scheduler guess, automatic retry, error
swallowing or original helper mutation is involved in this diagnostic.

That controlled result makes independent-connection writer contention a concrete
mechanism, but does not retrospectively identify the opaque CI error. It is not a
reproduction of the original CI timing.

After extracting the existing bare helper into `openPipelineDatabase` without
changing its behavior, the new safety-policy test ran red:

```
busy_ms=0 foreign_keys=0 synchronous=2 wal=false max_open=0
FAIL TestPipelineAuxiliarySQLiteOpenerUsesPerConnectionSafetyPolicy
```

The fresh file in this red case had not been initialized by production Open, so
its non-WAL state is consistent with the separate bare-on-production-WAL control.
The red package run took 0.102s.

## Minimal test-only repair

Owned files:

- `internal/app/pipeline_derived_test.go`: all existing pipeline auxiliary SQLite
  opens now use `openPipelineDatabase`, explicit production-equivalent safety DSN
  parameters and max-open/max-idle 1. Configuration paths remain literal paths.
  PostgreSQL DSNs/opening are unchanged. PRAGMAs are applied to **each physical
  connection**, not once on an arbitrarily selected pooled connection.
- `internal/app/evidence_service_pipeline_test.go`: scoped snapshot/revoke/restore
  failures print only a closed phase, class, safe driver-code projection and
  context class. No error text, SQL, DSN, table/message/detail or credentials are
  formatted. SQLite reports numeric codes and primary-class grouping; PostgreSQL
  reports only an explicit SQLSTATE allowlist, with other strings discarded.
- `internal/app/evidence_stream_pipeline_test.go`: the three permission-revocation
  modes must end with actual `repository.ErrManagementPermission`. The real
  permit checks its original context/deadline before querying the current grants;
  this cause therefore proves revocation completed before a still-live permit's
  next-block permission check. Source/context expiry errors cannot pass instead.
- `internal/app/pipeline_sqlite_connection_test.go`: diagnostic control, actual
  opener policy/replacement and short-writer positive control, plus safe error
  classification tests.

No production repository code, business/permit/HTTP deadline, queue behavior,
retry policy, thresholds or PostgreSQL configuration was changed.

## Verification and limitations

The actual-opener policy test checks 5000ms busy timeout, foreign keys enabled,
WAL, FULL synchronous and max-open 1, then explicitly retires the physical
connection with `driver.ErrBadConn` and checks its replacement. Thus a one-time
pool PRAGMA cannot satisfy the test.

The short-writer positive control uses two actual new openers. One begins an
immediate writer transaction before the other issues exactly one scoped DELETE.
It observes that operation borrowing the auxiliary pool's sole connection, keeps
the known writer barrier for a controlled 25ms, then releases it. The statement
must succeed once within its original 2-second test-operation budget, affect
exactly one scoped row and preserve another organization's row. There is no
retry loop. The 25ms is controlled lock duration, not an assumption that a worker
probably reached a desired stage.

The error tests use wrappers whose `Error()` panics, synthetic PostgreSQL private
fields and unknown SQLSTATE strings. Their exact expected outputs contain only
the allowlisted projection. The real SQLite BUSY result is also checked through
the new classifier.

Final independent command:

```
go test ./internal/app -run '^(TestPipelineAuxiliarySQLite|TestPipelineSQLDiagnostics)' -count=3 -v
```

Passed in 0.396s; the short-writer tests took about 0.06s each. The final repeat
without verbose output passed in 0.457s. Both final full app-package lint runs
returned `0 issues`. Earlier bare diagnostic-only three rounds passed in 0.180s.
All database files in these commands were new temporary SQLite files;
PostgreSQL was not touched.

The actual multiblock pipeline, whole app, webassets app, PostgreSQL and remote CI
were **not rerun by this unit** because the root task owns that integration test
window. The added permission-specific assertion still requires that integration
validation. The original CI cause remains non-unique until a matching classified
failure or controlled original-path evidence is obtained; this repair must not be
reported as remotely green based only on these small tests.

## Root integration verification

Root reviewed all five files and ran the auxiliary/diagnostic tests three times
(0.410s PASS), then the complete embedded-web/app suite three times with the real
PostgreSQL DSN enabled: `go test -tags webassets ./web ./internal/app -count=3
-timeout=5m`. The web package passed in 0.396s and app in 150.603s. This includes
the actual multi-block permission-specific assertions on SQLite/PostgreSQL, not
just the temporary lock comparator. The running script continues with separate
API/Worker regressions; their results are not included here. Remote Windows CI
for the repaired commit is still required.
