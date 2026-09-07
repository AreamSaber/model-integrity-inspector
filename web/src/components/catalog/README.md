# Provider and model-profile management boundary

`CatalogPage` is mounted at `#/providers` or `#/model-profiles`, keyed by both
organization and resource type. It uses the real same-origin `/api/v1` API,
browser-managed cookies, `X-Organization-ID` on reads/writes and session CSRF on
writes. Effective `catalog.write` is read through `/auth/permissions` and refreshed
before every mutation. The role catalog and system-admin flag do not grant access.
Read-only users may read lists and full details; failed or unknown grants disable
mutations. Session expiry, CSRF failure and mandatory password changes delegate
to the common authenticated boundary, without replaying the rejected operation.

Both lists use server-side `q`, `limit:25` and signed cursor pagination. Provider
search covers names; model search covers model identifiers/display names. The API
does not expose status or provider-ID filters, so there are no misleading
current-page substitutes. Failed refreshes retain marked stale data and disable
row writes. Model lists return summaries; full capabilities/tokenizer/limits are
only rendered after GET of the precise selected model ID.

Create projects only writable fields. Edit and delete first read the current
record and carry its optimistic version; updates require the returned version to
increment exactly once. Delete also requires typing the current name. The backend
uses the same conflict code for version changes and association protection; the
UI explains both, never claims a fabricated reference count, and never performs
cascading deletion or automatic conflict overwrite. Unknown network/5xx/response
outcomes disable repeat submissions and direct the user to read back the directory.
Abort on navigation only stops client processing, not an already accepted change.
Save/delete/return restores focus and scroll to the list heading.

Model forms obtain provider choices from actual paged API responses, support
server search, and separately GET the currently associated provider even if it
is absent from the first list page. Cyclic cursors fail visibly; additional option
loading is bounded to 100 pages, with explicit incomplete-list guidance. Creating
a model requires an active provider; activating an existing model also does.
`openai_chat` is the only implemented protocol. Stream/seed/reasoning flags are
explicit booleans. Optional output/context limits are range-checked, consistent,
and cleared using null; the read API omits unknown limits.

Prices are USD per million tokens, converted through BigInt to safe integer
micro-dollars without floating-point rounding (maximum 9007199254740991 micros).
Blank means null/unknown, while a typed zero remains zero. Price entry accepts at
most six decimal places. Declared tokenizer qualities require an ID except
`unavailable`, which explicitly clears it. These values do not install, download,
approve or replace runtime tokenizer/template bundles and never establish exact
counting, safety approval or supplier authenticity. Metadata forms must not be
used for credentials; there are no credential inputs or upstream-discovery calls.

`catalog-api.test.ts` and `catalog.test.tsx` exercise the actual client with
controlled network responses, including precision, CAS, association protection,
permission changes, stale reads, lifecycle cancellation and keyboard focus.
They make no paid upstream calls and do not replace real-Go/browser or deployment
validation. This bounded checkpoint does not claim M1/M6 Gate approval.
