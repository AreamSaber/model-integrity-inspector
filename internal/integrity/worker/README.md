# Database Worker and bounded target precheck

`New(Config{Store, Logger, Handlers})` registers typed handlers and returns a
`Runner`. `Run(ctx)` opens the real database consumer; `Ready()` becomes true only
after the initial consumer heartbeat succeeds. It becomes false on shutdown,
lost ownership/generation, or failed consumer renewal/database access. The
application combines it with schema, audit-tail and other readiness checks.

The default loop polls every second and renews both consumer and current Job
every 15 seconds against the existing 60-second lease. Cancellation checks run
every second, independently of lease renewal. Cancellation, target invalidation,
loss of lease and shutdown cancel the handler's HTTP context; an unresponsive
handler gets a bounded five-second shutdown grace, never a false completion.
Handler errors/panics are replaced by fixed codes, never logged verbatim.

## Precheck path

`target.Service.EnqueuePrecheck(ctx, org, targetID, version, requestKey)` freezes a
non-sensitive target snapshot and exact Secret version and atomically enqueues
`integrity.target.precheck`. It never performs synchronous network calls. Empty
request keys are generated; repeat keys with the same frozen configuration return
the same object/job, while conflicting use fails.

`NewPrecheckHandler(PrecheckConfig{Store, Secrets, URLPolicy})` implements the real
Worker handler. DNS resolver, validated-IP dialer and root-certificate inputs are
trusted infrastructure/test seams. They are never sourced from request DTOs. The
production defaults retain HTTPS, public-only DNS/address policy, TLS validation,
no redirects and no environment proxy inherited from Safe HTTP.

- One fixed minimal nonstream request and one stream request, each requesting at
  most 16 output tokens. Auto mapping may issue exactly one explicit
  unsupported-parameter fallback: maximum three requests, 48 requested output
  tokens, no network/rate-limit retry. Explicit parameter settings do not fall
  back. An adversarial provider's billing claim is not a guaranteed token meter.
- Total execution ceiling: 60 seconds, individual request ceiling: 20 seconds
  (or the tighter target setting). Queue snapshots expire after 15 minutes.
- Maximum 4 KiB outbound JSON and 64 KiB per response/event, including decompressed
  bytes. Infinite/slow streams are bounded by total and idle timeouts.
- Every actual HTTP `Do`, including fallback, first makes a durable request
  reservation inside `JobQueue.WithLease`. It verifies owner/generation/expiry,
  active organization/target and exact target/Secret versions before incrementing
  the persisted counter. Short target row locks protect reservation and final
  result transactions; no database transaction spans network I/O.
- Secret plaintext exists only inside the Worker's scoped callback. API and
  custom headers are cleared from controlled request maps when the call finishes.
  Body text, header values, reported model IDs and provider request IDs are not
  persisted in precheck state, logs, responses or audit records.
- SSE must genuinely terminate successfully. Partial EOF/malformed streams fail
  protocol compatibility; they never become a model-risk judgment.

Results contain only six fixed check names, fixed statuses and classified `MI_`
error codes. Nonstream/stream protocol failures, authentication, missing model,
rate limit, network failure, timeout, stale configuration and uncertainty remain
distinct. Result plus processed Job completion commit through `CompleteWith` in
one transaction with audit. A compatibility failure is a processed Job with a
**failed precheck**, never `passed` merely because work was claimed.

## Failure and recovery

If any request was reserved before a crash, recovery records
`MI_UNCERTAIN_ATTEMPT` without repeating it. Requests remain charged even when
their outcome is unknown. Queue reconciliation atomically synchronizes cancelled
or retry-exhausted jobs with failed precheck rows and audit, distinguishing
`MI_PRECHECK_CANCELLED`, `MI_UNCERTAIN_ATTEMPT` and
`MI_PRECHECK_ATTEMPTS_EXHAUSTED`. Audit failure rolls both records back.

Deleting a target refuses pending/running precheck jobs so it cannot destroy
credentials under active work. Disable/rotation cancels in-flight work at the
poll boundary, prevents a next request, and invalidates final success. Bytes
already received by an upstream cannot be recalled. A stale Worker cannot commit
business results or modify its replacement's lease.

The repository transaction capability is bound to Job ID and generation:
`BeginPrecheck`/`ReservePrecheckRequest` require a non-completing lease capability;
`FinishPrecheck` requires the `CompleteWith` capability. Ordinary transactions,
wrong-job capabilities and expired/closed capabilities are rejected.

## Tests

SQLite and actual PostgreSQL tests use isolated test-owned schemas. Local TLS
mock integration routes a validated public IP through an injected test dialer;
production loopback/metadata policies are never weakened. Tests cover both
protocols, parameter fallback, fixed budgets, sensitive canaries, partial SSE,
classification, cancellation/disable/rotation, lost generation, readiness,
uncertain recovery, capability misuse and atomic audit failure rollback.

```powershell
& ./.tools/go/bin/go.exe test ./internal/integrity/worker ./internal/integrity/repository ./internal/integrity/target
```

Set `MII_TEST_POSTGRES_DSN` securely to enable actual PostgreSQL cases; it is never
printed. This is local mock compatibility evidence, not paid-upstream validation.
