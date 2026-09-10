# Web application

React UI for the same-origin Go control API. This is not the design prototype.

## Build and test

Use the repository-pinned Node `24.19.0` and pnpm `11.19.0`:

```text
pnpm install --frozen-lockfile
pnpm typecheck
pnpm lint
pnpm test
pnpm build
```

The production `dist` contains external JavaScript and CSS, with no inline scripts,
styles, external fonts, analytics, or CDN assets. Serve it through the Go server's
frontend handler on the **same origin** as `/api/v1`. A standalone Vite server is
not an authentication backend; without an explicitly configured development
reverse proxy and matching backend public origin, API requests fail visibly.
Do not disable the server's Origin/CSRF checks to make development requests pass.

## Implemented boundary

- Initialization status, first organization/admin creation, optional in-memory
  `X-Setup-Token`, and separate login after successful initialization.
- Cookie session recovery, login, current-session logout, and password changes
  that invalidate all sessions. CSRF is only held in React memory. No credentials,
  CSRF, or setup tokens are written to URL or browser storage; password fields are
  cleared after requests. JavaScript strings cannot promise memory zeroization.
- Temporary-password sessions must contain the boolean `user.must_change_password`.
  When true, only the password-change form and logout are mounted; organization
  selectors, business navigation and role requests are blocked. A
  `MI_PASSWORD_CHANGE_REQUIRED` response immediately unmounts the business view and
  reads `/auth/me` once. The rejected operation is never retried automatically.
  Refresh failure or contradictory flags keep the gate closed, with explicit
  session-only retry/logout. A successful password change requires login again.
  User IDs remain strings; `user.version` is a positive safe-integer counter and
  `display_name` may be empty. A missing/non-boolean security flag fails validation.
- Session-derived organization selection, organization refresh, and scoped role
  catalog loading using string IDs and `X-Organization-ID`. Switching organizations
  unmounts/aborts the prior scoped view; stale responses cannot overwrite it.
- Error, permission-denied, loading, empty, retry, expired-session and concurrent
  initialization states; field labels and error associations, keyboard focus,
  duplicate-submit protection, responsive navigation and scrollable tables.
- Target list and server cursor pagination, GET-before-edit, create, non-secret
  configuration edit, complete credential rotation and versioned deletion with
  explicit name confirmation. Provider/model selections come from real catalog
  endpoints, with explicit load-more controls and no fabricated options.
  Target IDs remain strings; target/secret versions are positive integers.
  Credential inputs are never prefilled, persisted or logged, and are cleared
  after successful or failed requests. The target read DTO rejects credential,
  header, ciphertext and fingerprint fields; only masked metadata is displayed.
  Conflicts offer explicit reload rather than automatic overwrite or replay.
  Target search, exact model/environment and status filters use server queries,
  preserve filters across cursor paging, and reset the cursor on filter changes.
  Saving/deleting restores focus and scroll to the list heading.
  See `src/components/targets/README.md` for the target boundary details.
- Organization-scoped provider and model-profile management at `#/providers` and
  `#/model-profiles`: actual server `q` search/cursor paging, separate full detail
  reads, create, GET-before-edit/delete, versioned updates and name-confirmed
  deletion. Effective `catalog.write` is read on entry and before each mutation;
  missing/failed grants keep the page read-only. Associated-record protection is
  explained without pretending to know reference counts or cascading deletes.
  Model summaries never invent capability fields absent from the list response.
  Forms use real provider options with explicit paging/search and fetch the
  currently associated provider separately when needed. Capabilities, public
  limits and tokenizer quality are directory declarations, not trusted runtime
  artifacts. Prices use exact integer micro-dollar conversion, including the
  safe-integer maximum; null remains unknown and differs from a configured zero.
  Unknown write responses stop retries until the user returns to re-read the
  directory. See `src/components/catalog/README.md` for contract boundaries.
- Explicit target prechecks, with cost acknowledgement and a maximum three
  upstream requests. POST uses one in-memory cryptographic idempotency key per
  logical action; uncertain results offer manual same-key retry, never automatic
  new submissions. Polling follows one precise precheck/job/target-version ID
  tuple, stops on terminal/error/unmount and is bounded to 300 reads. Separate
  latest-record viewing is explicitly read-only and never substitutes another
  record for an uncertain submission. Only classified safe results are rendered;
  passing means capability checks, not model authenticity or integrity.
- Target-row Run configuration, estimate/explicit-cost confirmation and fixed-ID
  progress. Only opening Run configuration reads `/auth/permissions`; this is the
  actual current user/organization effective grant set, refreshed before each
  estimate, creation and cancellation. Missing/failed permissions disable writes;
  system-admin flags and role definitions never substitute for effective grants.
  Quick/standard/deep defaults and custom families, languages, repetitions, output
  tiers and stream modes are sent as configured. Non-custom requests never include
  custom-only options. Service hard maxima and high-cost/custom permissions are
  validated without silently removing choices; server limits remain authoritative.
  Estimates create only short-lived drafts and never implicitly precheck a target.
  Unknown prices stay unknown. Version/hash/budget/coverage warnings are displayed
  before the user explicitly accepts charges; public development templates and
  conservative missing model limits are not presented as approved vendor claims.
- Run creation uses one fixed estimate ID/hash body; uncertain POST results do not
  automatically retry or create another draft. Manual recovery uses the same body.
  Unused expired quotes require a new explicit estimate; an existing Run can still
  be recovered after expiry under the backend's one-draft/one-Run contract. Progress
  follows only that returned Run, verifies immutable identities and monotonic
  versions, and polls every five seconds for at most 600 reads before manual
  continuation. Cancellation requires confirmation and fresh cancel-own/any
  permission, posts the current version, and is disabled once execution closes.
  Unknown cancellation results trigger only a fixed-ID read. Leaving, switching
  organizations or losing the session aborts local reads, not the backend Run.
  `ANALYZING` is not completion; result/report buttons remain unavailable.
- System-user creation, display-name/status changes, login-lock reset and versioned
  temporary-password reset. New users are ordinary accounts; no system-admin
  promotion or user deletion is exposed. Temporary passwords are write-only,
  confirmation-checked and cleared after success, failure or local validation.
  Self-disable/reset controls are blocked; last-admin and self-lockout API errors
  are explained. Lock state is not exposed by the DTO and is never invented.
- Organization creation and settings changes, including timezone, active status
  and 0–180-day response retention. Edits GET the latest record, then bind the
  target organization ID in both URL and header, even when editing a different
  organization from the selected workspace. Creating an organization does not
  silently switch the workspace; disabling the selected one clears selection.
  Legacy organization refresh follows all pages with bounded/cycle-checked reads.
- Organization-scoped member listing, addition, roles/extra-grant updates and
  status-based revocation. Full role definitions are fetched before grant forms
  open. Existing users are selected by string ID supplied by a system admin;
  ordinary organization admins never query the global user directory. Extra
  grants are distinguished from inherited role permissions. Empty extra-grant
  arrays explicitly clear them; records always include optimistic versions.
- Management lists use actual server-side `q` search and signed-cursor pagination.
  Failed refreshes retain clearly marked stale data and disable row mutations.
  Conflicts offer an explicit discard-and-refresh step without replaying writes.
  Successful read DTOs reject credential fields, invalid flag/version types,
  and mismatched organization/user/member response identities.

The role endpoint returns **role definitions**, not the current user's memberships
or effective permissions. The UI never treats that catalog as authorization.
Server-side permissions remain authoritative. There is no client-side fallback
that invents session, organization, role, detection or report data.

## Deliberate limitations

Target CRUD has passed local type/build/lint checks and real-client interaction
tests against controlled network responses. Root's real-Go browser smoke verified
catalog options and a target configuration update. Precheck UI-to-real-worker
browser integration is still pending; the current tests use controlled network
responses and no real upstream calls. Run configuration/estimate/confirmation UI
is connected to real API routes, but the runtime may return
`MI_EXECUTION_NOT_READY` until its analysis worker is available. This is shown as
an error, never as an invented Run. Real-Go Run browser integration is pending.
Saving a target never makes an upstream call or reports simulated precheck success.

The standalone Run list, reports, baselines, rules, audit and system administration routes remain
explicitly marked “尚未接入”. Overview statistics are not implemented and are not
rendered as zero. Pagination on the legacy read-only role page is not yet
implemented in the UI (member grant forms do load the full role catalog).
Provider/model-profile management is implemented against the real API client;
its real-Go/browser mutation integration remains a separate pending check.
TLS verification cannot be disabled, and client URL
checks never substitute for server-side SSRF/DNS/network controls.
Logout ends the current session; password change invalidates every session.

Tests drive rendered forms/navigation through the actual API client and a
controlled `fetch` boundary. These tests are not production fake implementations
and do not replace real-browser, real-Go API, mobile visual or deployment smoke
tests. Tests do not make paid upstream calls; real precheck and Run execution can
incur upstream charges only after their explicit user confirmations. Run draft
and recovery state is in-memory and is not restored after a full page reload;
do not recreate an uncertain submission by opening another configuration.

The current checkpoint has 181 tests, including 30 catalog and 35 Run request/DTO cases,
24 management cases and 20 precheck/filter cases. Root's real-Go browser smoke
has also verified user/member reads; broader management mutation and Run browser
integration remain separate checks. Controlled-network tests do not replace them.
Vitest uses at most two thread
workers to avoid Windows fork-startup contention; this does not relax assertions.
