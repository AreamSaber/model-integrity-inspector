# Real Worker/TLS development capture tests

This directory is the separate **development controller**, not the offline
detector. All Go files here are `_test.go`; its mock controls, intervention
choice and generated credential material are absent from the replay core.
There is no official upstream, paid request, independent blind label, dataset
accuracy calculation, calibration claim or QA approval.

Each case allocates a fresh SQLite database or isolated PostgreSQL schema and
random synthetic keys. PostgreSQL runs when `MII_TEST_POSTGRES_DSN` is configured;
without that variable its tests explicitly skip, never count as passed. It runs
the actual identity initialization/login, persisted session authorization,
target service, TLS precheck, Run estimate/confirm, real ready Runner and queue
leases, sample execution, exact-AAD evidence, analysis and atomic publication.
The TLS client may dial only the controlled loopback server; it verifies TLS
using the fixture certificate. Nothing dials a paid/external model.

The two preselected controller cases are complete JSON/SSE and stream terminal
`[DONE]` omission with clean EOF. The model identifier is the frozen local
`gpt-4o` tokenizer mapping, **not a claim that the mock is OpenAI's model**.
The mock responder uses the fixed vocabulary's actual encoded pieces, checks
their count against the production local tokenizer, and only produces bounded
synthetic template responses. Sequence responses contain two complete nonce rows,
whose 54 ASCII bytes always fit the smallest 64-token fixture tier; this avoids
random nonce tokenization exceeding the request cap. The actual tokenizer count
check remains enforced. Protocol completion is not a claim that every probe
instruction is perfectly satisfied. Scenario names exist only in test names/control
configuration, not detector input.

Entity bytes are recorded from actual `ResponseWriter.Write` calls and matched
to the real Worker pre-auth request snapshot. An analysis handler wrapper uses
the genuine `LoadRunAnalysis.Use` source and exact AAD to assemble a pending
draft. Changed/missing/extra records, missing final pointers, corrupted evidence
and changed organization scope are rejected using detached test copies.

The test pauses after analysis computation but **before** `CompleteWith`:
sealing must fail and revision 1 must still be absent. Only after the original
completion commits, the Run is terminal, outstanding Run reservations are zero,
and the immutable publication and final Attempts match does `sealSettled` call
the explicit development serializer. Attempt reservation columns are historical
original amounts and are not incorrectly treated as outstanding balances.

A third test executes publication/audit writes and then deliberately returns an
error from the original completion transaction. It verifies rollback, no
published revision, no sealed bytes, no exported files and a valid audit chain.
The injected completion failure must make Runner exit with its sanitized storage
error while the parent context is still live. The test joins that failure before
canceling its context; racing cancellation against Runner's error normalization
would incorrectly sometimes demand a graceful `nil` from an intentional failure.
Ordinary successful-case shutdown still requires a clean `nil` result.

The PostgreSQL timing regression holds the isolated schema's reservation mutex,
then observes the actual `ReserveAttempt` waiter using `pg_blocking_pids` before
injecting a bounded 250ms lock delay. It performs unchanged real TLS/Worker work
and proves Adapter elapsed time can exceed the persisted Attempt interval:
Adapter timing begins before the blocked reservation establishes `started_at`.
Both complete and clean-EOF-partial SSE captures must still reproduce the actual
published analysis byte-for-byte. No production deadline or clock is modified;
the replay timing check preserves separate bounds and authenticated budgets.

After successful capture, the TLS server is actually closed. The core replays
the finite capture in memory, reparses every response, recounts tokens and
produces an analysis document byte-for-byte equal to the actual immutable
Worker publication. A repeated replay is byte-identical. Captured timings are
the signed original observations, not measurements of offline network latency.
The credential scan checks decoded Manifest, wire request, body and header values;
checking only outer JSON text would miss secrets hidden by []byte base64 encoding.
It covers this controller's known synthetic secrets, not every unknown encoding.

```powershell
$env:CGO_ENABLED='0'
.\.tools\go\bin\go.exe test ./tests/replay/capturefixture -count=3
```

## B1-5 controlled private-file export and actual CLI

The real compiler now uses a fresh independent `localfile.ManifestSigner`, not
the application's AES/Audit `KeyRing`. Its version is verified in the actual
frozen Manifest. The synthetic application master and Ed25519 capture **private**
key never leave memory; only the capture public verification key is exported.
The independent ProbeMAC key is intentionally exported in its dedicated private
development trust file, and nowhere inside the capture. Signer destruction runs
after the Worker has stopped. No public exporter capability is added: this entire
controller and its export helper remain `_test.go`, absent from production builds.

`settledExporter.write` calls the real settlement/publication checks itself and
verifies the audit chain. Before **any** file write it scans decoded Manifest,
request, response and headers, plus the trust/rule documents, for this test's
known application master, login password, upstream credential and capture private
key. Common raw/hex/base64 canaries are used; the separately generated Manifest
key is also excluded from captured fields. This finite canary check is not a
general unknown-secret detector. A decoded-body canary regression reaches the
same real settled-source boundary but rejects export; canceled, pre-commit and
rolled-back sources leave the output directory empty.

Only afterward does `localfile.WriteNew` create `capture-public-key.json`,
`manifest-key.json`, `rule.json`, then `capture.json` in a fresh private test-owned
directory. Windows uses owner+SYSTEM ACLs; Linux uses a 0700 directory and 0600
files. Each file is independently atomic/no-replace using the existing native
handle safeguards; the four-file set is **not** claimed to be a single atomic
transaction. A failure after an earlier file commit can leave private inputs,
but never causes a prevalidation failure to export anything. Files are temporary
test artifacts removed by `testing.TempDir` cleanup, not checked-in fixtures or
production evidence exports.

After closing the TLS server, the test builds and starts the actual standalone
CLI with those files. Build dependency downloads are disabled; CLI environment
contains only locale and necessary Windows system-root entries, not database,
GitHub or application credentials. Its full S1 prediction must match the in-memory
replay byte-for-byte, and its analysis must match the immutable database-published
document byte-for-byte. A second process cannot overwrite the first output; a
replacement independent Manifest key fails without creating a prediction.
These assertions run for both TLS cases on both databases and the PostgreSQL
reservation-delay regressions. Exact local tokenizer recounting and partial SSE
features remain checked, not taken from input quality/count claims.

Closing TLS is **not** OS network isolation evidence. B1-4's separately gated
Ubuntu namespace check currently uses synthetic CLI captures; these real-source
CLI tests do not claim to run in that namespace. They demonstrate controlled
development export and actual process replay, not calibration, blind acceptance,
release eligibility or production authorization. No production Worker,
repository, HTTP, replay core or CLI implementation is changed by B1-5.
