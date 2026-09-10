# Behavioral feature kernel — development checkpoint

This package is a pure, bounded behavioral **feature extractor**, not a detector
verdict, score, content-safety approval, or a completed M4 milestone. It performs
no network calls and imports no repository, credential, or model-judging service.
General JSON/JSONL/sequence completeness and termination belong to the separate
`analysis/structure` package.

## API and provenance boundary

```go
catalog, err := behavior.VerifyCatalog(canonicalBundle, trustedReleaseHash)
engine, err := behavior.New(catalog)
features, err := engine.Analyze(sample)
batch, err := engine.AnalyzeBatch(samples)
difference, err := engine.PairedDifference(samples, behavior.ContractDeviation)
```

`VerifyCatalog` calls `probe/templates.Decode`, requires the exact canonical
bundle and trusted digest, copies metadata into private fields, and retains no
prompt. A digest supplied by the response under analysis is not trustworthy.
The caller must obtain the digest from its immutable published bundle record.
Passing `nil` to `New` permits descriptive per-sample format analysis, but not
aggregate support or neutral-language classification.

Only the exact current `templates.BuiltinHash` / `BuiltinVersion` entries
`neutral.en-us.1` and `neutral.zh-cn.1` can enter the narrow refusal/identity
classifier. Their exact contract must equal the uppercase of a declared
synthetic marker. A custom verified bundle, an unknown template reference, or a
caller flag cannot opt a task into this whitelist. These public builtin string
transformation templates are still development material, **not independently
content-safety reviewed or approved**. Other task classes require a future
versioned review and explicit whitelist update.

Integration must map immutable plan metadata to `Sample` and must not let an
upstream response supply its own template, expected result, validity, pair, or
final-attempt metadata. `Sample.ID` and `Attempt.ID` are positive repository IDs;
output sample IDs are decimal strings, including IDs greater than JavaScript's
safe-integer range. `FinalAttemptID` is the authoritative selected attempt;
there is no best-response selection or fallback from an invalid final attempt.
An earlier selected attempt is supported only when that is the explicit
repository decision; this package does not infer a terminal state from ordering.

## Implemented behavior

- Exact output uses byte equality. Legal JSON whitespace and escaped strings are
  accepted for a single-field JSON contract; extra fields, duplicate keys, key
  case changes, non-string/null values, and extra documents are deviations.
- Extra prefix/suffix evidence requires a unique expected marker or embedded
  single-field object. Repeated anchors remain ambiguous. Valid wrapper objects
  are not reinterpreted as prefixes around nested values. JSON anchor scanning
  stops after 64 opening braces rather than selecting from arbitrary structure.
- Fingerprints use version/domain-separated SHA-256, Unicode lowercase,
  whitespace folding, and replacement of **only declared planned markers**.
  Marker-only, punctuation-only, short text and a documented development list
  of common English/Chinese courtesies do not support repeated-text candidates.
  These suppressions do not erase a real exact-format deviation. They are not
  an exhaustive linguistic model or Unicode NFKC/semantic normalization.
- Narrow anchored English/Chinese first-person inability and self-identity
  phrases produce `refusal_like` / `self_identity_like`, never an injection or
  brand attribution. Quoted/narrative keyword mentions are not classified.
  Appropriate requested identity is not counted. Unknown wording can be missed;
  `no_cue` means no supported linguistic cue, not proof of no refusal.
- Explicit sensitive tasks are excluded, not counted as ordinary neutral
  refusals. Invalid/not-applicable final attempts are excluded. Self-report
  template metadata overrides any caller attempt to unset `AuxiliaryOnly`;
  `AnalyzeBatch` returns these records separately in `auxiliary_samples`, with
  no behavioral measurements, repeated support, or paired statistical weight.

## Repeat support and paired effects

`AnalyzeBatch` aggregates only registered, eligible logical samples, never retry
attempts. Builtin contract shape must additionally match its marker experiment.
The denominator includes eligible non-matching responses. A `cross_family_repeat`
requires at least 3 matching logical samples and an 80% repeat fraction **in each
of at least 2 families**, with at least 3 template references and 2 languages
among qualifying support. Smaller coverage remains `insufficient_coverage`.
All thresholds are fixed **uncalibrated development rules**, not risk cutoffs.
The result describes repeated text and retains ordinary model style/training
as alternatives. Common text not covered by the suppression list may still
repeat; repeat alone is never an anomaly or hidden-instruction claim.

`PairedDifference` accepts arms `A` / `B` grouped by `Pair.ID` (the generator's
96-bit hex pair IDs fit). `ComparableSHA256` must bind semantic task identity and
all fixed request conditions from the frozen plan, excluding only the planned
surface/language variable. Both arms must agree on this digest, contrast type,
family, bundle/version, expected contract, and marker set. Surface comparisons
must share language; language comparisons must differ in language. Incomplete,
duplicate-arm, invalid, auxiliary, and incomparable pairs are explicitly
excluded, not imputed as zero. Duplicate logical sample IDs reject the batch.

The effect is `(B positive − A positive) / complete pairs`. The exact two-sided
paired binary test conditions on discordant pairs only, using
`2 * P[Binomial(n, 0.5) <= min(A-only, B-only)]`, capped at 1. Ties contribute to
the rate denominator, not the binomial trial count. This is the small-sample
paired sign/McNemar construction described by [NIST's McNemar test reference](https://www.itl.nist.gov/div898/software/dataplot/refman1/auxillar/mcnemar.htm).
The test assumes independent experimental pairs; retries are not independent
pairs. The caller must not duplicate/relabel units or silently pool unrelated
experiments. Use separate preplanned contrasts when conditions are heterogeneous.

No complete pairs yields null effect and p-value. Fewer than 6 complete pairs
gets an explicit low-power development warning, even though the exact number is
computable. No discordance yields p=1 plus an uninformative-state warning, not
proof of equivalence. Language contrast output always lists language capability
as an alternative, even when an observed rate difference is large. The p-value
is exploratory and **not FDR-adjusted**; no significance/risk decision is made.
Confidence intervals, multiplicity families, calibrated scoring, baseline
trust, and powered/independently frozen benchmark evaluation remain later work.

## Bounded, content-free output

Limits are 64 KiB per attempt, 8 attempts per logical sample, 512 samples and
8 MiB total response/contract/marker material per batch. Contract expected text
is at most 1,024 bytes, JSON key 128 bytes, and up to 16 ASCII marker values of
8–128 characters are accepted. Invalid UTF-8 and unknown input enum values fail
with fixed `MI_BEHAVIOR_*` errors, without echoing data.

Outputs contain IDs, byte offsets `[start,end)`, classifications, hashes,
coverage counts and statistics—not response text, expected values, nonce,
brand names, or prompt text. Pair IDs are hashed in pair evidence. Ordinary
formatting and JSON serialization of whole `Sample`, `Attempt`, and `Contract`
inputs are redacted. This does not prevent a caller from directly logging an
exported string field; inputs remain ephemeral S2 material and must be handled
accordingly. Hashes support evidence indexing/equality, not encryption or a
claim of anonymity for low-entropy text. Any evidence body retrieval still
requires the separate S2 authorization/audit path.

## Verification and remaining boundaries

```powershell
.tools/go/bin/go.exe test -cover ./internal/integrity/analysis/behavior
.tools/go/bin/go.exe vet ./internal/integrity/analysis/behavior
.tools/go/bin/go.exe test ./internal/integrity/analysis/behavior -run '^$' -fuzz FuzzAnalyzeBoundedText -fuzztime 10s -parallel 2
```

Tests exercise synthetic positive fixtures and hard negatives: common courtesy,
marker replacement, sensitive-topic refusal exclusion, multilingual capability
differences, self-report exclusion despite a false caller flag, malformed JSON,
ambiguous anchors, invalid final attempts, incomplete/duplicate pairs, retry
deduplication, hand-computed exact probabilities, output redaction and resource
bounds. They demonstrate implementation invariants, not detection accuracy.
The public tests are development/regression inputs, never a frozen blind set.

The kernel is not yet wired to Run persistence/scoring/reporting. It does not
implement general brand recognition, embeddings, stylistic sentiment models,
cross-run causal analysis, FDR, private baseline admission, or final M4 approval.
The rest of the application must preserve the PRD/TECH restriction against
claiming a proven hidden prompt without direct gateway-side evidence.
