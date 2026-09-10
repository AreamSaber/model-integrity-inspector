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

`RunProgress` uses `watchRun` to follow one fixed ID with bounded fetch SSE. An
initial exact-ID GET establishes the current record; disconnects and terminal
events require another authoritative GET. A terminal event alone cannot reveal a
final result link. Automatic tracking is limited to 12 connections or one hour
before manual continuation; it does not recreate or execute the Run. It pins
target, creator, package, manifest, version bundles and planned sample count,
rejects regressing record versions/sample completion, and retains the last
accepted record after ordinary read errors. Authentication/permission failure
removes the protected view; it is not presented as an empty or completed Run.
Cancellation needs a
checkbox, fresh effective permission and the current record version. It is only
available for QUEUED/RUNNING with an open execution phase; unknown cancellation
results are reconciled by GET, never by automatic POST. Organization changes,
logout, session expiry, mandatory password changes and unmount abort local reads
and mutations, but do not claim to undo an accepted backend task.

The ANALYZING state does not mean completed analysis. A terminal Run with read
permission offers an existing analysis revision 1 link; the server determines
whether a published result is actually available. Run history uses server-side
organization-scoped filters and cursors. The connected result views show immutable
summary, Token/behavior statistics and S1 samples/Attempt metadata, not response
bodies. Statistics and S1 details additionally require evidence permission; old
results cannot silently be replaced by changed content under the same revision.
Report generation/export remain unavailable. A history list is not the missing
organization overview/trend or two-Run comparison feature.

Tests exercise the rendered UI through the actual client and controlled fetch
responses, without paid upstream calls. The current integration ledger separately
records the real-Go/browser read-path check; it does not establish the full browser
configuration-to-Run/cancellation/SSE-failure workflow, calibrated analysis or a
completed development milestone.
