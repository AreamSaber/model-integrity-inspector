# Actual application CI failure diagnostics

## Scope and observed failure

This is an observability change, **not a fix or a claimed reproduction of the
Windows CI failure**. It changes no database, lease, HTTP, shutdown or test
deadline; adds no retry; and does not convert any failure to success.

The immutable evidence is commit
`01165e18e2d77a3f4bf3bad62f4e8f7ab450d34f`, Actions run `34185808446`, Windows
job `101933780172`:

- The first `go test ./...` passed: `internal/app` 21.140 seconds and
  `internal/integrity/worker` 121.153 seconds.
- The subsequent `go test -tags webassets ./web ./internal/app` failed in
  `TestApplicationActualTLSZeroDayRetentionThroughPublishedArtifacts/sqlite`.
  The child took 13.46 seconds; its parent took 13.68 seconds; the package took
  22.546 seconds.
- At 2026-09-08 04:13:24 UTC, `repeated_pipeline_test.go:33` reported only
  `app HTTP request failed`; `pipeline_test.go:196` then reported
  `application did not stop gracefully MI_STARTUP_FAILED`.
- The failing call was the second, nine-sample custom Run's status-poll GET,
  after estimate and confirmation. It was not the new response-body GET, the
  40-second convergence guard, or a whole-package Go test timeout.
- The default periodic consumer heartbeat and per-job renewal intervals are
  15 seconds, without an app override. Under ordinary Go timer semantics, the
  entire 13.46-second child cannot already have reached either first interval.
  This narrows the investigation, but does not identify which other queue,
  listener, HTTP, or shutdown operation failed.

The old source discarded all actual app Worker operation logs because its
`worker.Config.Logger` was nil. The first `workerDone` branch discarded the
returned error, and several exits became the same `ErrStartup`. The HTTP test
helper discarded the client's concrete error as well. Consequently, the old
log cannot establish a unique root cause. A successful retry cannot supply
that missing evidence.

## Diagnostic changes

`app.go` preserves `prepare` and `prepareWithNetwork` signatures and delegates
their implementation through the private `prepareWithNetworkAndLogger` entry.
Production `Run` and the actual TLS pipeline pass the same trusted logger into
the existing `worker.Config.Logger` field. No Worker setter, queue behavior,
public configuration, HTTP input, or SQL logging was added.

The existing Worker logger has only fixed messages and fields: queue operation
labels `consumer_heartbeat`, `maintenance`, `claim`, `fail_report`, `complete`,
`check_lease`, and `renew`, plus the fixed handler-failure code. No raw error
is passed by those log sites. Queue errors remain sanitized at the repository
boundary; these logs do **not** recover driver messages, SQL state, lock owner,
SQL text, DSN, or any private execution data.

The actual `serve` state machine emits `application component stopped` with:

- `phase`: `listener_exit`, `worker_exit`, `http_shutdown`, `worker_shutdown`,
  `worker_shutdown_deadline`, or `unknown`.
- `class`: a fixed errors.Is classification covering database unavailable,
  job/consumer fencing, active consumer, unresponsive/failed handler, cancelled
  or deadline context, invalid job/configuration, already-running Worker,
  closed listener, no error, or unknown.
- `caller_done`: whether the caller context has already completed, including
  cancellation or deadline. This does not override a reported fencing failure.

The original returns, select branches, 10-second shutdown deadline, server
close behavior, and Worker wait remain unchanged. Unknown phase input is
replaced with `unknown`; error strings are never formatted. A Worker exiting
with nil while the caller is live remains an unhealthy app exit and is visible
as `phase=worker_exit,class=none,caller_done=false`.

The pipeline HTTP helper reports only fixed error categories, separately from
the request-context class: `none`, `cancelled`, `deadline_exceeded`,
`unexpected_eof`, `eof`, `connection_closed`, `timeout`, `network_dial`,
`network_read`, `network_write`, `network_other`, or `unknown`. Network direction
is intentionally not an unverified errno classification: it does not claim to
distinguish connection refusal from reset without an appropriate typed signal.
Timeout discovery also checks up to 32 ordinary unwrap links because outer
`url.Error`/`net.OpError` can mask a deeper Timeout method through another wrapper.

HTTP request/read failures do not print method, path, URL, error text, response
body or keys. A status mismatch now prints only received/expected numeric HTTP
status, not the original path or an untrusted response error-code string.

The fixture's trusted JSON logger writes to a mutex-protected 32 KiB test-only
buffer. It preserves the producer's write-count semantics, drops excess bytes,
and records a truncation flag. Cleanup waits on the same original shutdown
path and emits the bounded snapshot only if the test failed. Background logger
goroutines never invoke `t.Log` after test cleanup. The original body-service
composition, retention checks and browser-hold code are preserved.

## Pure validation and limits

New `internal/app/diagnostics_test.go` covers:

- Direct, wrapped and joined fixed error classification, with fencing and an
  unresponsive handler still distinguished when cancellation is also present.
- Errors whose `Error()` method panics if consulted, plus protected URL/DSN/
  SQL/body/key canaries: only fixed phase/class/boolean fields reach logging.
- Safe HTTP categories, including deeply wrapped timeouts and unknown network
  operation labels that must not be copied into output.
- Concurrent bounded-buffer writes/snapshots and overflow semantics.
- The real `serve` state machine using a synthetic listener, no database and no
  network: listener failure remains `ErrStartup`; ordinary caller cancellation
  remains successful and does not become a failure log.
- AST verification that actual Worker construction receives the trusted logger.

Actual local results on Windows:

- `go test ./internal/app -run '^$'`: compilation PASS, no tests run.
- `go test ./internal/app -run '^TestApplicationDiagnostic' -count=3`: PASS,
  0.119 seconds after the final diagnostic field rename to `caller_done`.
- `go test -tags webassets ./internal/app -run '^TestApplicationDiagnostic'
  -count=3`: PASS, 0.114 seconds, including the final field name.
- `golangci-lint run ./internal/app`: 0 issues after final changes.

No database tests, network requests, Git operations, or real secret reads were
performed for this diagnostic unit. The parent independently reported a
webassets whole-app dual-database three-round PASS in 86.815 seconds, **compiled
before this diagnostic change**; it is not validation of the new wiring.
Root subsequently completed `go test -tags webassets ./web ./internal/app
-count=3 -timeout=8m` with the new diagnostics and actual multi-block TLS fixture:
SQLite/PostgreSQL full app PASS 138.674 seconds, web PASS 0.500 seconds (session26993).
Root also reran the tagged diagnostic pure tests three times (0.114 seconds) and
app/run/API/contracts lint (0 issues). These local results do not establish the
old Windows CI root cause or prove a Linux race execution; new CI remains required.
