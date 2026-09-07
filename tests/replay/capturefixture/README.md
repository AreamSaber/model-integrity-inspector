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
published revision, no sealed bytes and a valid audit chain.

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

These tests currently retain generated capture bytes only in process memory;
they do not persist reusable fixtures or export synthetic Manifest keys.
The local-file CLI and explicitly controlled fixture export remain a separate
checkpoint. No production Worker/repository/HTTP code is changed. The B1-1 core
timing boundary is corrected for the distinct Adapter/reservation origins above.
