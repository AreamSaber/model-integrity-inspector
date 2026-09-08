# Response retention observation contract

## Scope and recovery entry

This is the contract-only unit for the response cleanup work following `6fdfd6c`.
Its owned files are `docs/api/openapi-v1.json`,
`tests/contracts/response_retention_test.go`, the two deleted-status additions in
`tests/contracts/evidence_display_test.go`, and this note. It makes no backend,
frontend, global ledger, database, Git or deployment changes.

The implementation was checked in `api/response_retention.go`,
`run/response_retention.go`, `worker/response_retention.go`, the actual app worker
and maintenance wiring, and all production `repository/response_retention_cleanup*`
files. Repository cleanup tests were read for intended coverage but not run by
this unit. The body-display source/status code and shared HTTP/result read gates
were also checked; these are live implementation observations, not independent
database acceptance evidence.

## Implemented public contract

- `GET /runs/{id}/response-retention?analysis_revision=1` under `/api/v1` is a
  read-only observation for an authorized published Run at revision 1.
- Current `run.read` and `evidence.read` are required together. Neither
  `report.export` nor `evidence.body` is required. The repository read transaction
  rechecks the actual session, user, organization membership and two closed grants.
- Request IDs and all 12 `ResponseRetentionView` fields are mandatory. Run IDs
  stay canonical decimal int64 strings, including values beyond JavaScript's
  exact-number range. `last_deleted_at` is explicitly nullable, never omitted.
- Only literal query revision `1`, exactly once, is accepted. Body/transfer
  encoding, extra/duplicate query keys and malformed requests are rejected;
  the handler explicitly rejects HEAD with 405. The observation route does not
  implement the body-display route's Range/conditional-header rejection, so the
  new document does not invent those restrictions.
- The HTTP context is bounded by 2 seconds before authentication, with four
  per-control-handler nonblocking admission slots. Output uses that HTTP deadline
  when supported. The service also applies a nested 2-second timeout which cannot
  extend an earlier parent deadline. Responses have `Cache-Control: no-store`.
- The dedicated saturation code is 429 `MI_RETENTION_LIMIT`, `Retry-After: 2`.
  Explicit invalid retention sources/write-deadline setup failures map to 503
  `MI_RETENTION_SOURCE_INVALID`; the existing shared result/service error mappings
  remain. `targetError` maps its conflict to `MI_VERSION_CONFLICT`, not a guessed
  `MI_CONFLICT`. The document does not infer a corruption cause from a generic
  service error. The current read keeps `businessErr` so an explicit
  `ErrRetentionSource` survives shared repository normalization.

The view version is `mii.response-retention-summary.v1`. Policy days are the
implemented inclusive range 0–180, not an invented four-value enum; policy
version is positive with no newly invented upper bound. Attempt count is bounded
by 1536. Each count is at most attempt count. Display deleted, expired and retained
are mutually exclusive subsets whose sum is **at most**, not necessarily equal
to, attempt count. Raw deletion may overlap display categories. The latest deletion
time is null iff both deletion counts are zero, otherwise nonzero and no later
than the observation time.

Scalar JSON Schema checks cannot express all of those cross-field relationships.
They are documented as runtime invariants and tied to the actual view-validation
function by AST checks, rather than falsely claiming a standalone JSON Schema
validator enforces arithmetic between properties.

The summary describes live S1 response-storage metadata and verified deletion
receipts. Retained storage does not prove authenticated plaintext availability or
authorize its disclosure. The read does not mutate existing reports/hashes, run
deletion, expose a request-only reproduction API, or certify completion of M6 or
other retention classes. Repository cleanup only deletes the two response-copy
classes; its wider readiness is outside this contract unit.

## Deleted response-display status

The existing response-body GET now documents `unavailable_deleted` in its closed
unavailable union, always with `content: null`. Its existing permissions, private
disclosure codec, limits and all other compatibility constraints are unchanged.

The repository must verify the exact source/attempt deletion item, its batch
receipt hash, completed queue job and actual signed audit event. A missing row
alone does not prove deletion. A `BodyRecorded` attempt with an unexplained
missing display row remains `ErrDisplaySource`, mapped by the existing body API
to 503 `MI_EVIDENCE_UNAVAILABLE`. A zero-day policy reason has precedence when the
current policy is zero. There is no raw-response fallback.

The pre-existing actual wire/redaction/display-purpose AEAD contract test now
exercises the new unavailable status too: null is accepted with or without an
optional hash, non-null content is rejected, and unknown reasons remain rejected.
That pure fixture validates format and codec behavior, not an invented database
authorization grant. The additional AST contract separately binds the documented
deleted status to the real receipt/audit verification chain.

## Verification evidence (2026-09-08)

1. Added four dedicated contract tests before changing OpenAPI. The single-round
   run failed as expected: the first three had no path/schema object and the
   deleted-display test found no `unavailable_deleted` null branch (package
   0.119s). This was a real red contract run, not a backend failure.
2. After the scoped documentation/status additions, the retention/display
   dedicated tests passed (0.161s). Whole `tests/contracts -count=3` passed
   (0.597s) and its lint returned `0 issues`.
3. Strengthened middleware AST binding: the actual `isResponseRetentionRequest`
   conditional bodies must themselves apply the 2-second context and admission
   release/429/write-deadline checks. Matching another route's limits elsewhere
   in the middleware no longer suffices. Final whole-contract three-round run
   passed (0.556s). The immediately following lint attempt was correctly blocked
   by another agent's active global linter; no lock bypass was attempted.

Dedicated negative cases reject a missing/malformed mandatory `request_id`, bare
or extra envelope fields, omitted nullable field, numeric Run ID, unknown version,
wrong revision, out-of-range/negative counts and a body alias. Actual public DTO
JSON is checked in both null and non-null deletion-time cases. Reflection checks
all 12 real fields/types and absence of `omitempty`. AST checks tie the documented
route, source validation, permissions, bounds, success/error mapping, actual app
maintenance and fenced worker handler to production functions rather than comments.

No database, network, native Linux race or end-to-end cleanup test ran in this
unit. Passing this contract does not claim the ongoing repository/app cleanup
work is accepted or that CI is green.

Parent integration subsequently completed the whole contract package three times
(0.500s) and combined app/run/API/worker/contracts lint with zero issues. These
results supersede the earlier transient linter-lock observation; they do not
replace actual database, browser or remote CI evidence.

## Known shared edge outside this unit

The existing shared control middleware's exceptional `rand.Read` failure branch
still writes a legacy `{error:"MI_SERVICE_UNAVAILABLE"}` shape before a request ID
exists. This pre-existing branch was reported to the parent; it is not a reason
to weaken the standard mandatory-request-ID contract or edit backend files from
this documentation-only unit. Normal success/error envelopes remain strict.
