# Development report kernel

This is the bounded **M5-08 JSON/HTML/CSV generation kernel**, not a report
Job/API, publication store, independent audit, calibrated release or PDF
exporter. It performs no filesystem, database, network or secret access.

## Application boundary

```go
snapshot, err := report.NewDevelopmentSnapshot(scope, projection)
if err != nil {
    // Return a closed error; do not log the supplied projection.
    return err
}
artifacts, err := report.Generate(snapshot)
if err != nil {
    return err
}
jsonBytes := artifacts.JSON()
htmlBytes := artifacts.HTML()
contentHash := artifacts.ContentHash()
jsonFileHash := artifacts.JSONFileHash()
htmlFileHash := artifacts.HTMLFileHash()
```

`Scope` supplies `ReportID`, `OrganizationID`, `RunID`, analysis revision,
fixed `GeneratedAt`, and the exact frozen rule/template/scoring/tokenizer
versions. IDs are canonical positive signed-64-bit decimal **strings**, never
JSON numbers. Generation time is UTC-normalized and must be nonzero, within
2000–9999, and no earlier than the run finish. No wall clock is read.

The report-owned `Input` is an explicit S1 projection of the already validated
public `Run` / `ResultView` / `FindingView` / `SampleView` / `AttemptView`
read models. It deliberately does not import run/repository (avoids dependency
cycles) and has no endpoint, name/model free text, prompt/response body,
credentials, arbitrary title/summary/HTML, command, URL, or storage path.

The authorized repository/Worker adapter must:

- Revalidate the current user, organization membership and required report/S1
  evidence permissions; read the exact immutable published analysis revision.
  Read all logical samples and their attempt chains, not just one UI page.
- Bind all projections to the same organization/run/revision and frozen versions
  before calling the kernel. `ExpectedSamples` must equal supplied sample count
  and `ValidSamples` equals the number of `Included` logical samples, not retry
  count. Current supported development revision is **1**; other revisions or
  unrecognized release labels fail closed.
- Map `ResultSummary.RiskLevel/Completeness` (public `watch` / `full` etc.), not
  storage-only labels. Preserve null scores, local/remote counts and unknown
  prices. Copy costs as integer micros, without floating-point currency math.
- Map `TokenAnalysis` / `BehaviorAnalysis` to the report-owned statistics.
  Usage/stream median fields are nullable here: if the corresponding denominator
  is 0 map the source's absent measurement to **nil**, otherwise map its number.
- Copy only closed public codes. `SampleView.Limitations` already merges safe
  protocol warnings; arbitrary `MI_` prefixes are **not** accepted. A successful
  Attempt's missing/empty stored error must arrive as **nil**, not an empty
  string or fabricated execution error. Do not pass restricted storage rows.
- Allocate/freeze the report ID and generation timestamp once per logical report
  publication. Retrying generation must reuse this scope; no new timestamp.

`NewDevelopmentSnapshot` validates the supplied shape, bindings, enum/range
constraints, cross-references, chronology and resource bounds, then deep-copies
it. It **does not authenticate DB provenance, authorize a caller, verify a
signature, recompute a score, or independently verify a hash's preimage**.
Hash-shaped fields must come from the trusted read adapter, not a public request
body. A consistent forged input is not detected as a forgery by this renderer.
Do not expose this constructor by unmarshalling a caller's arbitrary JSON.

`Snapshot` and `Artifacts` have private state. Regeneration is deterministic and
safe for concurrent read-only use; byte getters return independent copies.
As with ordinary Go APIs, do not mutate input concurrently during construction.

## Content and validation

The standard JSON and standalone, script-free HTML contain scope/version/time,
four-dimensional and overall risks, confidence, grade, completeness, denominators,
findings, alternatives, rule statistics, token tiers/plateau intervals, behavioral
fingerprints/paired differences, logical sample references, attempt timeline,
limitations, fixed next-step guidance and the PRD disclaimer. No missing value
is converted to healthy/zero. Retries do not increase independent sample count.

The kernel accepts **C/D development evidence only**; uncalibrated confidence is
at most 74 (59 for partial/insufficient). Empty valid evidence must remain
insufficient / D / null overall risk. Summary risk labels must match frozen
scoring bands unless explicitly insufficient. It does not perform a new scoring
pass. All figures remain observations, not misconduct probabilities.

Every output fixes `observation_mode=blackbox`, `development=true`,
`calibrated=false`, `content_state=redacted`, `review=null`,
`review_state=not_included`. This means the report does not contain a frozen human
review, **not** that the Run has no historical reviews. Input has no
approval/calibration/gateway-evidence switch. Machine evaluation is distinct from
human review. Adding a future review
requires a **new report version**, never overwriting the existing snapshot.

Bounds include 512 samples, 256 findings, 3 attempts per sample, 512 tiers and
plateaus, 2048 patterns, 4 paired metrics, 128 codes per code set, 32 finding
statistics, 512 references per reference set, a conservative 4 MiB total input
preflight, and 16 MiB **per output artifact**. Illegal UTF-8, oversized values,
nonfinite/unsafe numbers, duplicate IDs/ordinals/refs/set keys, foreign sample
refs, unsupported revisions/versions, invalid enums and contradictory nullable
denominators fail closed with fixed errors. Resource accounting may reject an
input before its exact JSON encoding would reach 4 MiB.

HTML uses only `html/template` text-context escaping, no trusted HTML casts,
scripts, inline styles, forms, active links, or external assets. A restrictive
CSP and no-referrer meta are included. It renders readable statistics and also
includes an escaped copy of the final JSON file. The later download layer still
must supply correct MIME, attachment filename policy, CSP, permissions, bounded
storage and immutable publication; this package does not perform those duties.

## Canonical JSON and hashes

Schema: `mii.report.v1`. Canonicalization: `mii.report.canonical-json.v1`.
This is a **project profile, not RFC 8785/JCS**:

1. UTF-8 JSON, no whitespace or trailing newline, recursive lexicographic object
   key ordering by Go string byte order. All current schema keys are ASCII.
2. JSON strings use Go `encoding/json` escaping, including HTML escaping and
   `\u2028`/`\u2029`; there is no Unicode normalization or case folding.
3. Numbers are finite safe binary64 values; integers outside ±(2^53−1) are
   rejected. Numbers use Go `strconv.FormatFloat(n, 'g', -1, 64)` shortest
   round-trip representation; negative zero becomes `0`. This exponent spelling
   intentionally differs from JCS. IDs remain strings. Times are normalized to
   UTC RFC3339Nano (`Z`, fractional seconds only as needed).
4. Defined sets are normalized before encoding: findings by numeric ID,
   statistics by name, code/reference sets lexicographically, tiers by
   `(series_id, requested_max_tokens)`, plateaus by
   `(series_id, low_requested, high_requested)`, patterns by
   `(kind, fingerprint)`, and differences by metric. Duplicate set keys fail.
   Empty collections encode `[]`, not `null`.
5. Samples are ordered by their semantic **ordinal**, attempts by **attempt_no**;
   these values are not renumbered. Input slice permutation alone does not alter
   content; changing semantic ordinals does. Optional absent objects/measurements
   remain `null` rather than empty or zero.
6. Build the canonical content document with the **`content_hash` field absent**
   (not `null`, not an empty string). SHA-256 over these bytes is the content hash,
   represented as lowercase `sha256:<64 hex>`.
7. Add `content_hash` and canonicalize again to obtain the **final JSON file**.
   `JSONFileHash()` is SHA-256 of those exact bytes and is not the content hash.
   HTML cites the same content hash and embeds the final JSON; `HTMLFileHash()`
   independently hashes its exact bytes. File hashes are returned metadata, not
   self-referential fields inside their own files.

To check content, parse the JSON, remove `content_hash`, reapply this exact
profile and compare SHA-256. To check a downloaded file, hash the exact bytes
against the separately stored file hash. Hashes prove byte consistency only,
**not authenticity, independent approval, or a trusted calibration release**.

## Verification

`GenerateCSV(snapshot)` exports the same frozen logical document using the
`mii.report.csv.v1` four-column, full-node profile. `mii.report.v1` remains the
document schema. CSV is a separately generated immutable artifact, not a
conversion endpoint or replacement of an existing JSON/HTML report. Its exact
bytes have their own SHA-256; logical content retains the canonical content
hash. UTF-8, CRLF, quoted JSON scalar values, JSON Pointer paths and explicit
container nodes preserve nullable values, identifiers and empty structures.
The same S1 restrictions and 16 MiB per-file bound apply; CSV does not enable
restricted evidence, human-review snapshots or calibrated evidence grades.
See `docs/project/M5-CSV-REPORT-NOTES.md` and
`docs/project/M5-CSV-INTEGRATION-NOTES.md` for profile and integration evidence.

`go test ./internal/integrity/report -count=1 -cover` covers deterministic
regeneration, concurrent reads, deep ownership, cloned output, canonical golden
number/escaping profile, semantic-vs-set ordering, unknown/empty statistics,
large string IDs, scope/revision/version conflicts, duplicated references and
attempts, closed codes including protocol warnings, every string-leaf canary,
renderer XSS defense in depth, exact writer limits, and total input resource
bounds. The number fuzz target also runs as seed tests; no paid calls occur.

These checks are development verification, not completion of M5, formal review,
real statistical calibration, publication E2E, or security approval.
