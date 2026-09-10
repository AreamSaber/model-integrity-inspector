# Frozen final-attempt analysis composition

The Worker reads a closed Run through its real queue lease, replays its signed
Manifest, and decrypts final response records with exact persisted AAD scope.
Only then does it pass an opaque `features.Batch` to `Analyze`. No network,
credential, gateway-approval or baseline-trust flag exists in this package.

The S1 document includes numeric/closed-class features, token aggregates,
behavior patterns, all four fixed paired hypotheses with BH adjustment, and
development scores/confidence/limitations. Paired hypotheses that cannot be
tested remain in the family. This is an exploratory paired family only, not a
claim that all future rule/baseline hypotheses were calibrated or FDR-controlled.

Protocol observations distinguish normal, anomalous, missing, invalid and
unobserved fields. An HTTP error can contribute to protocol diagnostics without
its response entering token/behavior statistics. Normal `length` completion is
not itself an anomalous finish. Unknown/absent usage is not a numeric zero.

`repository.PublishRunAnalysis` accepts the authoritative source receipt only
inside exact fenced completion. Revision 1, aggregate findings, Run state, audit
and job completion share one transaction. Document scope and indexed scores
must agree. Expired evidence yields an explicitly insufficient/partial result;
authentication failure yields no score. Terminal failed analysis jobs transition
to visible `FAILED / MI_ANALYSIS_FAILED`, never stuck apparent progress or fake
success. Machine publication is unrelated to formal human approval.

The full document stores per-sample S1 features in the immutable result revision;
legacy unversioned sample `feature_json` is not overwritten. Reanalysis revisions,
fine-grained finding navigation, baseline/rule publication, result HTTP/UI and
report generation are still separate unfinished work. The public application
confirmation gate remains closed until runtime version admission is connected.

Evidence: real TLS mock calls, generated signed manifests, durable encrypted
evidence and both databases in `worker/analysis_test.go`; atomic/audit rollback,
stale receipt, concurrent completion and missing-data tests in repository. Mock
is limited to the controlled upstream, not substituted for product analysis.
