# Unified features (development)

M5-01 pure builder: replay the organization-bound signed Manifest, verify frozen
template/tokenizer artifacts, validate every persisted sample and attempt, and
rebuild the exact adapter wire hash. Statistical input always uses the persisted
final attempt; neither completion order nor the best retry chooses evidence.

The Worker must load authoritative rows through its Run-analysis lease and
decrypt the final encrypted response under its exact organization/Run/sample/
attempt/request-hash AAD. This package cannot authenticate fabricated database
projections. Nonfinal attempts need metadata only. Missing/expired evidence,
unknown measurements, invalid protocol, safety limits and auxiliary self-report
remain explicit exclusions/limitations, never synthetic successful observations.

The default build includes this package (no WIP build flags). S1 results contain
closed classifications, identifiers, numeric features and hashes, not prompts,
response bodies, raw model echoes or private headers. Opaque kernel inputs
provide only pure analysis methods and expire on callback return. JSON, fmt and
slog tests cover sensitive wrapper redaction and detached feature projections.

Current resource ceilings are 150 generated samples, 1 MiB per normalized
response and 8 MiB combined manifest/wire/evidence batch. Exceeding a ceiling is
an explicit resource error, not a manufactured partial score. This is not yet
a streaming large-batch implementation. Built-in templates are public development
artifacts, not independently approved calibration or private acceptance data.

Verification: `go test ./internal/integrity/analysis/features -count=3 -cover`
(87.9% statement coverage at this checkpoint), plus repository/Worker integration
tests as the complete analysis chain is connected.
