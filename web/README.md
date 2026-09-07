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
rendered as zero. Provider/model-profile CRUD, user/member/organization management
and role-catalog pagination are not yet implemented in the UI. Target searching
is not offered until server-side filtering exists; a current-page filter is not
presented as a full search. TLS verification cannot be disabled, and client URL
checks never substitute for server-side SSRF/DNS/network controls.
Logout ends the current session; password change invalidates every session.

Tests drive rendered forms/navigation through the actual API client and a
controlled `fetch` boundary. These tests are not production fake implementations
and do not replace real-browser, real-Go API, mobile visual or deployment smoke
tests. No paid upstream calls are made by these pages or tests.

The current local checkpoint has 72 passing tests. Vitest uses at most two thread
workers to avoid Windows fork-startup contention; this does not relax assertions.
