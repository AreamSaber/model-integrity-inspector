# Run workflow boundary

The target row mounts `RunWorkflow` under an organization-keyed authenticated
view. `runs-api.ts` calls the real same-origin API with cookies, organization IDs
as strings and session CSRF for writes. DTOs are closed and reject raw content,
invalid identifiers/counters, unexpected fields and inconsistent quote budgets.
Errors and warnings use fixed friendly text; unknown codes never reveal server
messages. Permissions come only from scoped `/auth/permissions`, not role catalogs
or `system_admin`, and are re-read before write operations.

`RunConfiguration` sends exact explicit options with server-aligned input maxima.
Custom stream modes are `[false]`, `[true]` or `[false,true]`; unsupported requests
must fail visibly rather than silently changing mode. Missing current-version
prechecks produce guidance, not an automatic possibly billed precheck. Estimates
are short-lived, non-outbound drafts, limited by the backend to 20 active drafts
per owner. Baseline and early-stop options are intentionally not exposed.

`RunQuote` displays the server-frozen hash, bundle versions, total input reserve,
total output budget, nullable money and coverage limitations. The user must accept
real charges before creating a Run. POST `/runs` uses exactly the estimate ID,
manifest hash and `confirm_cost:true`, without a random idempotency header. An
unknown result is retained for manual same-body recovery, never automatic replay
or replacement by a new draft. Before expiry recovery can perform the original
creation; after expiry only an existing Run can be recovered. Draft/recovery state
is in-memory, not browser storage; navigation warns that leaving does not cancel
an already submitted job, and a full reload cannot recover this UI state.

`RunProgress` reads one fixed ID every five seconds, for at most 600 reads before
manual continuation. It pins target, creator, package, manifest, version bundles
and planned sample count, rejects regressing record versions/sample completion,
and retains the last accepted record after a read error. Cancellation needs a
checkbox, fresh effective permission and the current record version. It is only
available for QUEUED/RUNNING with an open execution phase; unknown cancellation
results are reconciled by GET, never by automatic POST. Organization changes,
logout, session expiry, mandatory password changes and unmount abort local reads
and mutations, but do not claim to undo an accepted backend task.

The ANALYZING state does not mean completed analysis. Results/reports remain
disabled, the standalone Run list is not implemented, and unavailable backend
execution/analysis handlers fail visibly. Tests exercise the rendered UI through
the actual client and controlled fetch responses; no paid upstream calls are
performed, and this checkpoint does not claim real-browser integration, calibrated
analysis or a completed development milestone.
