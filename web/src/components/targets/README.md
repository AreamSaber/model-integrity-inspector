# Target management boundary

`TargetsPage` is mounted under the authenticated session and keyed by organization
ID. It uses the real `/api/v1` API, with browser-managed cookies, session CSRF on
writes, and `X-Organization-ID` for all target/catalog requests.

Implemented: target list and server cursor navigation; GET-before-edit/rotate/delete/precheck;
create; non-secret PATCH with version; complete credential rotation with target
and secret versions; DELETE `{version}` after explicit name confirmation.
The rotation response is a complete sanitized Target, not a standalone Secret.
The server performs `q` search over name/model/channel, exact model/environment
filtering, and active/disabled filtering. Filters remain attached to signed-cursor
navigation; changing them resets paging. No current-page pseudo-search is used.

Provider and model options come from `/providers` and `/model-profiles`, with
explicit load-more controls. No mock catalog entries or client-side current-page
search are presented as full data. Catalog loading failure is explicit; creating
an unassociated target with a manually supplied model is permitted by the API.
Provider/model-profile CRUD is available in the separate supplier/model management
navigation entries; this target form only selects existing catalog records.

All IDs remain decimal strings. Versions are positive integers. The read DTO
rejects unexpected auth/header/ciphertext/fingerprint fields and validates the
server's masked secret metadata. Update requests project only configuration
fields, even if passed a read DTO. Editing never mounts credential inputs.

Create/rotate credential inputs are uncontrolled, never prefilled, persisted or
logged, and cleared after requests (including failure). Both names and values of
custom headers are treated as sensitive and cleared. JavaScript strings cannot
promise memory zeroization. No old credentials are retrieved or reused by UI.

URL validation is a usability check, not SSRF enforcement. TLS verification is
always enabled; authoritative URL/DNS/network restrictions remain on the server.
The target-row Run entry reads the current target version and opens the separate
configuration, estimate, cost-confirmation and progress workflow. It never
automatically prechecks, estimates or creates a Run. The standalone Run list and
result/report pages are not yet connected. See `../runs/README.md`.
Precheck is a real, potentially billed operation: it requires opening one target,
reading its current version, and
explicitly acknowledging the maximum three upstream requests. List rendering,
opening the panel, saving configuration and background reads never POST prechecks.

Each logical submission creates one cryptographically random `Idempotency-Key`
and POSTs only `{version}`. Uncertain network/response results never automatically
retry or allocate another key. Explicit retries use the original key and version;
while uncertain, latest-record lookup cannot substitute someone else's request
for the unknown submission. Keys are in-memory only; the page warns against
reopening/repeated submissions after an uncertain response.

Queued/running records are read by exact `/prechecks/{precheckId}` every three
seconds, with at most 300 reads before manual continuation. The target ID,
precheck ID, job ID and target-version snapshot stay pinned, and record versions
cannot move backward. Terminal status or read failure stops automatic polling;
manual retry reads the same ID, never POSTs. An explicit latest-record read is
labeled as not this user's submission and is then pinned to its returned ID too.
Different target versions are clearly marked. Closing/unmounting, organization
switches, logout, expiry and mandatory password changes abort pending reads and
timers, not the backend job. Read times are labeled browser-local timezone.

The precheck DTO is a closed vocabulary with bounded request count, six known
check names, classified status/error codes, string IDs, numeric versions and
timestamps. It rejects raw headers/bodies/credentials, mismatched identities and
structurally false success. Only fixed friendly failure messages are rendered.
Passing precheck proves neither model authenticity nor model integrity.

Concurrent updates do not silently overwrite local edits: version conflicts offer
explicit reload, which discards unsaved configuration and does not replay a write.
Failed refreshes retain clearly marked stale data and disable row mutations.
Organization switches abort scoped requests, unmount forms and discard stale
responses. Session expiry and forced-password responses delegate to the common
authenticated-session boundary.
Save/delete/return transitions restore keyboard focus and scroll to the list
heading rather than leaving focus at a removed form.

`src/targets.test.tsx` and `src/prechecks.test.tsx` exercise the rendered application through the actual fetch
client with controlled network responses. Real-Go/browser and deployment checks
are separate and must not be inferred from these component tests.
