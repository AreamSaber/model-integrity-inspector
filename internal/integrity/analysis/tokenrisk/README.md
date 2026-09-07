# Token and response aggregate kernel — development only

`Analyze(Input) (Result, error)` is a bounded, offline feature consumer. It does
not execute requests, read credentials, accept response bodies, calculate an
A/B/C/D evidence grade, infer a provider's intentions, or claim calibration.
`Version` is `1.0.0-dev.1`; `Parameters()` and its canonical SHA-256
`RulesHash()` freeze this development parameter set, including weights,
thresholds, sample minima, bootstrap settings and strength caps.

## Trusted input and grouping

The composition service must obtain inputs from the authorized immutable run
manifest and final persisted attempts. Do not bind this type from HTTP.

- `ID` is the logical sample ID; `FinalAttemptID` selects its final outcome.
  Older attempts never enter statistics, pairs, families or network-error rate.
  Identical duplicate final rows are counted once; conflicting finals, conflicting
  final pointers, and one attempt assigned to two logical samples are rejected.
- `SeriesID` is a lower-case SHA-256 of the **fixed task and settings**: family,
  language, variant, template/version, input format, model, temperature and other
  invariant parameters. Exclude requested output tier and stream mode, and
  replace variable nonce/label values with their template semantics. Hashing the
  fully interpolated prompt would incorrectly make every repetition a new series.
  This kernel rejects reuse across family/language/variant/template metadata;
  the trusted caller remains responsible for including all fixed settings.
- `GroupID` identifies shared nonce/seed observations. The same group across
  tiers is one bootstrap block. Stream pairs require the same series, group,
  tier, seed and tokenizer artifact and exactly one observation per mode.
  Unmatched/ambiguous groups are reported, not silently paired.
- Only `VALID`/`VALID_WITH_WARNING` participate. `self_report` always has zero
  weight even if its auxiliary flag was omitted. Invalid final attempts still
  contribute to completion and network-diagnostic counts. Filter/refusal/client
  safety outcomes marked not applicable by structure analysis cannot become
  token platform or termination evidence.
- `Local` and `Usage` come from the frozen tokenizer; `Structure` comes from the
  bounded structure analyzer. `ProtocolChecked` and `SuffixChecked` distinguish
  missing features from checked negatives. A suffix is an unexpected suffix's
  controlled fingerprint, never raw response text. Setting a nonempty fingerprint
  or protocol anomaly without its checked flag is rejected.

No baseline input or self-declared trusted-baseline Boolean exists. Results
explicitly include `MI_BASELINE_UNAVAILABLE`. A future M5 resolver must verify
immutable organization/run/sample scope, approval/version/expiry, matched
parameters and authenticated snapshots before baseline features can enter this
kernel; the baseline path is intentionally absent from this checkpoint.

## Platform and statistical semantics

Comparable ladder series use sequence/JSONL only, separated by tokenizer ID and
version. For each tier the kernel exposes median, median absolute deviation,
`1.4826 * MAD / max(median, 1)`, raw hard-structure incompleteness rate, abnormal
support rate, natural-EOS rate, and quality limitations.

Main tier counts pool stream modes: the frozen minimum is **three samples per
tier and six across the two high tiers**, not three in each stream arm. Separate
mode diagnostics must show both modes at both tiers and median difference at
most 20% before a common platform can retain strong candidate strength. A
mode-specific truncation is not a common-mode platform.

Adjacent tier pairs require request ratio at least 1.5, output growth below 1.2,
combined robust CV below 0.10, plateau below 0.70 of the high requested value,
and actual abnormal structure/termination support. Normal `LENGTH` at the
requested budget is not contradictory metadata; raw incompleteness remains
visible separately. A missing SSE terminator remains anomalous even when the
visible output reached its requested budget.

Median-difference intervals use 1,024 deterministic SHA-256-counter resamples
of independent **groups**, paired when groups overlap. Shared group/seed arms
resample together. A partially paired design does not silently fall back to
unpaired rows. Without overlap, both arms resample independently. The reported
95% percentile interval is exploratory: fewer than two groups has no interval;
fewer than three groups explicitly limits confidence but does not mechanically
cap a standard package's otherwise strong platform at 39. An interval containing
the development normal-growth range (responsiveness at least 0.5) lowers a
candidate to 39. Median bootstrap intervals are described by the
[NIST handbook](https://www.itl.nist.gov/div898/handbook/eda/section3/bootplot.htm);
the [official R bootstrap documentation](https://search.r-project.org/CRAN/refmans/boot/html/boot.ci.html)
also explains that interval procedures have limitations. This implementation
does **not** claim BCa/studentized coverage or calibrated small-sample coverage.

Usage requires at least six same-direction mismatches with at least 80% of all
eligible observations in that direction, strictly above 15% relative error.
Opposite-direction or normal observations are not discarded from the denominator.
Heuristic estimates use 30% and a 39 ceiling. Unseparated hidden reasoning skips
total Usage comparison. Stream differences require matched pairs, an effect over
20%, consistent direction, a cluster interval beyond ±10%, two-tier coverage and
abnormal support; otherwise explicit weak/incomplete/alternative limits apply.

## Aggregation and missing evidence

Token weights stay `0.45 platform + 0.20 termination + 0.20 Usage + 0.15 stream`.
Termination's Token denominator is applicable ladder responses, **not** unrelated
short behavioral tasks. Response metadata consistency uses all applicable
response features. Response development weights are SSE 0.35, fixed suffix 0.25,
metadata 0.25 and protocol 0.15; these are versioned development parameters, not
a claim of calibrated thresholds prescribed by the specification.

Missing components have zero effective weight and remaining weights renormalize.
Checked normal components stay in the denominator. With no analyzable components
strength is `nil`, not a fabricated zero. Independent-family counts count actual
families, never probe rows. Only a single comparable tier, too few samples,
heuristic estimates, unseparated reasoning or predominant natural EOS constrain
Token strength to at most 39. Incomplete runs are marked partial and capped at
59. A declared model limit may only lower strength; it never establishes trust.
Network errors strictly above 20% halve the SSE attribution subcomponent.

The actual standard 60-request compiler schedule is exercised with real offline
tokenization and structure extraction against synthetic clipped responses:

Ladder responses follow the frozen nonce/numbered-unit contract. Non-ladder rows
use short completed-text controls for response metadata and denominator checks;
this test does not evaluate their format, label, style or refusal contracts.

- a fixed 256-token proxy produces two platform candidates at 256→512, each
  strength 80 with two nonce groups per family; weighted Token strength is **41**
  when Usage and stream/nonstream comparison are honestly normal;
- a healthy proxy produces zero Token/Response strength;
- stream-only clipping is reported as mode incomparability and does not produce
  a common platform candidate.

These are calculations, not acceptance claims. In particular, the fixed-256
example does **not** meet a risk≥60 release acceptance threshold. No thresholds
have been tuned to force it to pass. M5 must calibrate scoring/aggregation on a
separate development set, freeze the rule release, and perform independent
acceptance. Multiple comparisons remain marked exploratory; this checkpoint
does not implement FDR-adjusted significance, baseline paired inference, or
train/calibration/held-out dataset evaluation. Proportion features are descriptive
rates, not unimplemented Fisher tests masquerading as p-values.

## Bounds and verification

Hard bounds: 4,096 incoming attempt observations, 512 logical samples, 64 fixed
series, 128 tokenizer cohorts, bounded identifiers/warnings and tokenizer counts.
Bootstrap work is fixed at 1,024 replicates; no network, runtime artifact fetch,
mutable global RNG, arbitrary callbacks, or body logging occurs.

Run `go test ./internal/integrity/analysis/tokenrisk -count=3` and
`go vet ./internal/integrity/analysis/tokenrisk`. Tests include actual compiler
60-sample controls, deterministic paired/unpaired resampling, incomplete pairs,
retry deduplication, conflicting metadata, missing weights, natural EOS, reasoning,
heuristics, hidden stream confounding, healthy LENGTH, network threshold boundaries,
and resource rejection. All response strings in tests are synthetic and local.
