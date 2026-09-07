# Target and credential services

`target.NewService(Config{Store, Secrets, URLPolicy})` provides `Create`, `Get`,
`List`, `Update`, `RotateSecret`, `Delete` and `Snapshot`. All operations require a
positive organization ID. Mutations require the trusted audit actor in context;
HTTP remains responsible for RBAC, CSRF, request-size/JSON-field checks and
converting internal positive `int64` IDs to decimal-string API IDs.

## Write and read boundaries

- `secret.Input` is write-only and refuses formatting/JSON serialization. API Key
  and all custom header values are encrypted as one envelope. The handler owns
  and discards/clears the original input; service-owned copies are zeroed.
- `secret.Service.PrepareCreate` / `PrepareReplacement` complete encryption
  before any persistence transaction. The repository atomically creates/updates
  Target, encrypted Secret and audit events. Audit failure rolls back all three.
- Target stores only the Secret ID, not a second ciphertext/header payload.
  Authentication type/header name are internal routing metadata. Public `View`
  omits them and exposes only Secret ID, version, mask and rotation timestamp.
- Full target configuration replacement is an optimistic CAS. The HTTP PATCH
  layer merges explicitly supplied fields with the current view and passes the
  client-supplied expected version; it must not silently substitute a newer one.
  Secret replacement compares both target and credential versions.
- URL validation is pure and does not issue DNS/network requests. Default HTTPS,
  permanent metadata/reserved-address exclusions and custom-header validation
  are shared with Safe HTTP. Administrator URL policy is copied at construction;
  it cannot be widened through target options. TLS verification cannot be disabled.

## Runtime and history

`Snapshot` is a detached value with non-sensitive complete configuration and
`secret_id + secret_version`. Changes/deletion do not mutate previously persisted
snapshots or historical reports. `Service.Snapshot` alone is **not** authority to
commit a Run: Run creation must call
`TenantTransaction.LockTargetForRun(id, expectedVersion)` in the same transaction
that persists the frozen Run and enqueues its first job. This serializes Run
creation with target edits, credential rotation and deletion.

Only the Worker calls `secret.Service.WithCredentialsForWorker` and wraps the
entire outbound adapter call inside its callback. The current target must remain
active and the exact credential version must exist. Missing, disabled, deleted,
corrupt or stale-version credentials fail closed; callback errors/panics are
replaced by stable, non-sensitive errors. No background module should bypass the
service and read the encrypted repository record directly.

Rotation replaces the encrypted active version. A Worker that already entered a
credential callback can finish its scoped call; future resolutions of an old
snapshot version fail rather than silently use the replacement. The Run/Worker
integration must classify that stale reference and implement any desired
explicit cancellation/rescheduling policy; history never retrieves old keys.

Delete is an optimistic soft deletion of the target with immediate clearing of
the active Secret ciphertext, wrapped DEK, nonce, fingerprint and mask columns,
plus two atomic audit events. It refuses unfinished Runs and pending/running
run-plan, run-analyze or sample-execute jobs, including jobs attached to a
prematurely closed Run. Report-only jobs may continue reading immutable history.
The coordinator must cancel/drain active work before retrying deletion; this
service does not pretend cancellation has completed. WAL, database backup and
physical-media retention are separate operational policies, not a claim of
instant forensic erasure. A retained Secret tombstone preserves historical FKs.

## Verification

Tests run against SQLite and real PostgreSQL when `MII_TEST_POSTGRES_DSN` is set;
each PostgreSQL case creates/drops a unique test-owned schema. DSNs are never
printed. Persistence tests cover tenant isolation, 8-way CAS across independent
connections, active-work deletion refusal, audit rollback, masking and active-row
destruction. Service tests additionally exercise the real encryption boundary,
borrowed-buffer zeroing, canary absence, safe snapshots, reserved headers,
administrator-only network policy and credential replacement.

```powershell
& ./.tools/go/bin/go.exe test ./internal/integrity/target ./internal/integrity/secret ./internal/integrity/repository
```

Connectivity precheck jobs and Run/Worker/HTTP wiring are follow-on integration;
this package never performs adapter calls synchronously from target CRUD.
