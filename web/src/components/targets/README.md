# Target management boundary

`TargetsPage` is mounted under the authenticated session and keyed by organization
ID. It uses the real `/api/v1` API, with browser-managed cookies, session CSRF on
writes, and `X-Organization-ID` for all target/catalog requests.

Implemented: target list and server cursor navigation; GET-before-edit/rotate/delete;
create; non-secret PATCH with version; complete credential rotation with target
and secret versions; DELETE `{version}` after explicit name confirmation.
The rotation response is a complete sanitized Target, not a standalone Secret.

Provider and model options come from `/providers` and `/model-profiles`, with
explicit load-more controls. No mock catalog entries or client-side current-page
search are presented as full data. Catalog loading failure is explicit; creating
an unassociated target with a manually supplied model is permitted by the API.
Provider/model-profile CRUD is outside this page's implementation.

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
Precheck and Run buttons are disabled and labeled not connected; this page never
makes an upstream request or reports a simulated successful precheck.

Concurrent updates do not silently overwrite local edits: version conflicts offer
explicit reload, which discards unsaved configuration and does not replay a write.
Failed refreshes retain clearly marked stale data and disable row mutations.
Organization switches abort scoped requests, unmount forms and discard stale
responses. Session expiry and forced-password responses delegate to the common
authenticated-session boundary.

`src/targets.test.tsx` exercises the rendered application through the actual fetch
client with controlled network responses. Real-Go/browser and deployment checks
are separate and must not be inferred from these component tests.
