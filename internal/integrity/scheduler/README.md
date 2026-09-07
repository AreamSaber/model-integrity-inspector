# Execution checkpoint: repository and policy

This is the M2-07/08/09 **repository/policy stage**, not a completed live Run
Worker. It makes no network calls, reads no credentials, and performs no scoring.

## Contract

`scheduler.NewPolicy(adminLimits)` creates a private-field capability from
trusted server configuration. Never decode administrator limits from a Run HTTP
body. `Tenant.CreateRun(plan, policy, requestKey)` reapplies this policy and
freezes the complete neutral plan, target/Secret versions and limits together
with ProbeInstances, LogicalSamples and the typed plan Job. Creation and cancel
revalidate the actual persisted session and grants in their write transaction.
Cancel supports `run.cancel-own` and `run.cancel-any`, checking `created_by`
inside the same transaction for own-only callers.

Compiler-produced `Manifest` JSON is retained as S2 reproduction metadata. When
present it must be an object, compact with Go JSON escaping, and exactly match
`ManifestHash`; snapshot serialization may not alter those bytes. Only legacy
low-level fixtures may omit it. The public service must require verified
manifest compilation and must not accept an arbitrary Plan/Manifest from HTTP.

The intended handler calls are:

1. Plan Job: `Queue.CompleteWith(... tx.StartRun(runID))` atomically queues sample
   Jobs. A claimed Job is not evidence of successful execution.
2. Immediately before each actual request:
   `Queue.WithLease(... tx.ReserveAttempt(sampleID, adapterSnapshot))`.
3. After a response:
   `Queue.CompleteWith(... tx.FinishAttempt(sampleID, attemptID, outcome, jitter))`.
   A retry creates a new delayed typed Job for the same LogicalSample and frozen
   request/nonce; it never creates another independent statistical sample.
4. After reclaiming an interrupted request:
   `Queue.CompleteWith(... tx.RecoverInterruptedSample(sampleID))`.
   The old generation becomes UNCERTAIN; it is not silently reissued.
5. Proven cancellation/stale-target/budget stop before any request:
   `Queue.CompleteWith(... tx.FinishUnattemptedSample(sampleID))`.
   Concurrency and RPM contention must defer the Job, not fabricate a failed
   sample. Run cancel does not falsely mark an in-flight Job completed.

The last settled/skipped sample sets `execution_closed_at` before atomically
queuing analysis revision 1. Cancellation closes as CANCELLED and preserves
already-billed work. Analyzer/report lifecycle is a separate checkpoint.

## Accounting and authority

- Request count is durable dispatch intent immediately before Do. A crash in the
  commit-to-send gap cannot prove whether upstream billing occurred, so that
  request remains conservatively charged.
- Available token/money budget subtracts both settled counters and current
  reservations. Integer prices are micros per million tokens; each component is
  rounded up with overflow checks. Unknown price is represented by `CostKnown`
  false / nil pricing, never assumed free. A requested monetary cap with unknown
  price fails closed.
- Missing usage is estimated from frozen input/local output with a 1.25 factor;
  UNCERTAIN uses frozen input plus maximum output with the same factor. An actual
  upstream usage overrun is recorded rather than hidden and blocks later work.
  A local budget cannot guarantee an upstream provider honors token limits or
  removes already incurred charges.
- Short DB transactions serialize exact global, organization, target and run
  concurrency counts and target rolling-minute request counts. No network call
  occurs under the reservation lock. Live authority is the current Job owner,
  generation and DB-clock lease; expired generations cannot finish successfully.
- `Tenant.CheckExecution` is a separate Run/target/cancel liveness check used
  alongside `Queue.CheckLease`. Future Worker code must cancel outbound contexts
  on either failure; this repository alone cannot abort an already-open socket.
- `Queue.ReconcileExecution(ctx, orgID)` handles bounded terminal failed/cancelled
  plan/sample Jobs. An exhausted unstarted plan closes FAILED with the fixed
  `MI_EXECUTION_PLAN_FAILED` classification instead of remaining QUEUED forever.
  Recovery, budget settlement, final sample selection, close and
  audit are atomic; repeated reconciliation is idempotent.
- `execution_ordinal` and microsecond-spaced availability preserve plan queue
  priority. They do **not** promise request completion order under concurrent
  consumers; actual Attempt timestamps remain separate from planned order.
- Run/sample plans and wire snapshots are S2 data, excluded from default model
  JSON. The canonical snapshot must exactly match the frozen supported request
  fields; duplicate keys, injected credentials and changed seeds are rejected.

## Remaining integration

The next Worker stage must register real plan/sample handlers, apply in-flight
cancellation/lease heartbeats, map adapter errors to the closed classifications,
use the confirmed frozen output-token parameter (no hidden automatic fallback),
and schedule terminal reconciliation. Precheck has its existing independent
budget; no precheck or fallback call is implicitly added here. Any future
runtime parameter fallback must persist and charge a separate Attempt for every
real request. Evidence/response storage and analyzer callbacks are not yet wired.

Regression tests run against both SQLite and a real PostgreSQL DSN injected via
`MII_TEST_POSTGRES_DSN`; tests use synthetic data and no paid external upstream.
