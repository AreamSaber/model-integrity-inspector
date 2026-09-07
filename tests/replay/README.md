# B1 development offline replay core

This checkpoint implements the strict capture codec, private verified source,
real offline HTTP/SSE parser, local tokenizer/features and selected A1 Runtime.
It **does not yet include** the actual Worker/TLS capture controller or CLI.
Unit fixtures are synthetic parser/kernel tests, not persisted Worker receipts,
calibration data, blind labels, accuracy measurements or release approval.

`New(Config).Replay(ctx, reader)` accepts only canonical signed
`mii.replay-capture.v1` bytes. The trusted local Config pins a development
capture public key, synthetic Manifest verifier and supported runtime. Inputs
cannot provide keys, download paths, normalized answers, local token counts,
tokenizer quality, labels, risks or approval flags. `CaptureDraft` is protected
from ordinary formatting/logging/JSON; `SealDevelopment` is its explicit S2
serialization path and authenticates only a development controller statement.

The next capture checkpoint must obtain actual source under
`LoadRunAnalysis.Use`, verify exact-AAD evidence, and **wait for successful
analysis publication and final settlement before sealing**. A controller
statement alone cannot prove these database facts to the offline process.

The core supports only one completed final Attempt per logical sample, HTTP
200 complete JSON, or complete/clean-EOF-partial SSE. It rejects unsupported
timeouts, retries, refusals, transport errors, missing/extra records, changed
request bindings and bytes after `[DONE]`. Header duplicates reach the actual
parser. A line-limited memory Body avoids reading past terminal SSE events.
There is no HTTP client, DNS, Dial, database or controller import in this core.

The actual parser must reproduce a digest of the original protocol projection.
Only then are signed capture-observed timing fields attached, with explicit
output limitations: offline elapsed time is not a new network measurement.
Tokenizer quality and counts come from locally recounting parsed Content;
reported Usage remains separate. The candidate runtime never rewrites the
source Manifest's builtin execution version. All outputs remain development,
uncalibrated, with C/D evidence only.

Bounds: capture JSON 24 MiB, Manifest 2 MiB, raw body 1 MiB / 8 MiB total,
wire request 1 MiB / 4 MiB total, at most 150 samples. The feature builder's
stricter **combined** 8 MiB budget for Manifest + requests + encoded evidence
also applies. Oversize or unsupported input fails closed, without printing
source text. No bounded input is silently truncated into a healthy result.

```powershell
$env:CGO_ENABLED='0'
.\.tools\go\bin\go.exe test ./tests/replay -count=3
.\.tools\go\bin\go.exe test ./tests/replay -run '^$' -fuzz FuzzCaptureEnvelope -fuzztime 10s
```

Tests cover real parser behavior, exact/compatible/heuristic recounts, Usage
separation, deterministic repeats, runtime parameter changes, capture timing,
strict JSON/UTF-8/signatures, source/settlement binding, resource limits,
unsupported scenarios, S2 logging and nonce-free predictions. Import checks
complement but do not replace running the future CLI in an actual denied-network
environment. See the project B1 design notes for the remaining controller/CLI
work and explicit non-goals.
