# Development rule runtime — A1

This checkpoint adds real parameterized offline computation, not rule
publication, a calibration certificate, an acceptance dataset, or production
Run version selection. Existing Worker/Run/HTTP wiring still uses the exact
frozen builtin `1.0.0-dev.1` and SHA-256. No network, paid request, database,
template upload or evaluator signing authority is added here.

## API and identity

- `DevelopmentArtifact(version)` creates a typed development candidate with a
  distinct `major.minor.patch-dev.positiveInteger` version. Its JSON is a closed
  `mii.rule-artifact.v1` envelope containing the implementation ID and typed
  `Manifest`; neither `trusted` nor `calibrated` is an accepted input field.
- `RuleArtifact.Canonical()` validates all semantics before returning exact
  canonical bytes and SHA-256. When token rules change, update the scoring
  `TokenRulesHash` to the value from `tokenrisk.NewDevelopment(rules).Hash()`.
- `DecodeRuleArtifact(bytes, expectedHash)` rejects unknown/duplicate/case-aliased
  fields, omitted fields, trailing data, noncanonical representations, invalid
  UTF-8, nonfinite/out-of-range values and payloads over 1 MiB. Supplying one's
  own matching hash does not establish provenance or release approval.
- `NewResolver().Resolve(bytes, expectedHash)` resolves only installed
  `mii.analyzer.development.v1`, the unchanged builtin, and admitted development
  parameters. Template/tokenizer bytes are verified when constructing the
  resolver; only current exact artifact references are supported. Unknown
  implementations or template/wordlist references fail closed.
- The returned `Runtime` has private fields. `Ref()` returns detached S1 identity
  data, never publication authority. `Analyze(*features.Batch)` cross-checks the
  builder-verified template/tokenizer hashes and executes the selected immutable
  token/scoring engines. It cannot expose raw feature inputs or response text.

One resolver retains at most 64 versions, including builtin. Identical replay is
idempotent; different canonical bytes under an already registered version fail.
This process-local guard is not a substitute for future tenant-scoped durable
immutability. The original builtin version cannot name alternate parameters or
the new candidate envelope even when its other fields use default values.

## Admitted development parameters

| Kernel | Parameter | Range |
|---|---|---|
| Token | `RobustCV` | 0.01–0.20 |
| Token/stream direction | `UsageDirectionFraction` | 0.80–1.00 |
| Token bootstrap | `BootstrapReplicates` | powers of two, 128–4096 |
| Scoring | `StableFraction` | 0.80–1.00 |
| Scoring confidence | `NoBaselineFactor` | 0.10–0.80 |
| Scoring confidence | `MissingDimensionFactor` | 0.10–0.75 |

All other parameters are equal to the frozen defaults, including weights,
minimum sample/family counts, risk bands, fixed effects/usage cutoffs,
exploratory alpha, pattern minima, hypothesis family and confidence/grade caps.
The last two knobs can only be more conservative than builtin. These ranges are
engineering bounds for development, not calibrated operating recommendations.
Changing an allowed knob changes the kernel hash and its corresponding actual
calculation. The PRNG domain remains the original implementation's version, so
renaming otherwise identical rules cannot select a different bootstrap interval.

Scoring checks the exact selected Token version/hash, not just its shape.
Every public constructor remains development-only; no caller can enable A/B or
manufacture baseline/gateway trust. Missing evidence stays missing. The separate
future release-admission capability remains private and currently unconstructible
through a production API.

## Verification and remaining work

Tests cover all six knobs affecting calculations, pre-change full-JSON builtin
golden hashes, old-vs-resolved complete Analyzer equality, a real frozen compiler
and feature builder with local synthetic responses, actual custom-template batch
rejection, malicious JSON/size boundaries, lifetime-limited opaque input access,
mixed-kernel rejection, concurrent version conflicts and bounded registries.
The standard 60-sample fixed-256 regression still computes Token **41**; it is not
retuned or presented as satisfying release thresholds.

Next checkpoints must bind exact candidate hashes to durable organization
versions, estimates/confirmed Runs, worker compatibility and closed result
readers. A real no-network replay capture runner, independently controlled
calibration/acceptance datasets, authenticated metric receipts, publication,
retirement and rollout remain separate work. This package does not complete
M5-06 or any human/algorithm release approval.
