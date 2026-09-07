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
  See `src/components/targets/README.md` for the target boundary details.
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
tests against controlled network responses. Real-Go/catalog browser integration
is still pending. Precheck and Run controls are explicitly disabled; saving a
target does not make an upstream call or report simulated precheck success.

Runs, reports, baselines, rules, audit and system administration routes remain
explicitly marked “尚未接入”. Overview statistics are not implemented and are not
rendered as zero. Provider/model-profile CRUD and pagination on the legacy
read-only role page are not yet implemented in the UI (member grant forms do
load the full role catalog). Target search/filter controls are not yet wired to
the backend; a current-page filter is not presented as a full search.
TLS verification cannot be disabled, and client URL
checks never substitute for server-side SSRF/DNS/network controls.
Logout ends the current session; password change invalidates every session.

Tests drive rendered forms/navigation through the actual API client and a
controlled `fetch` boundary. These tests are not production fake implementations
and do not replace real-browser, real-Go API, mobile visual or deployment smoke
tests. No paid upstream calls are made by these pages or tests.

The management checkpoint has 96 tests, including 24 management request/DTO cases.
Management browser integration with the actual Go API is still pending; local
controlled-network tests are not a substitute for that integration check.
Vitest uses at most two thread
workers to avoid Windows fork-startup contention; this does not relax assertions.
