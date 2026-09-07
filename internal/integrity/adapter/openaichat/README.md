# Chat Completions adapter

This package implements the V1 text-only OpenAI-compatible Chat Completions protocol. It imports only neutral domain DTOs and the Safe HTTP error/policy boundary; it has no repository, Secret Service, classifier or scoring dependency.

## API and ownership

- `New(Config)` binds an endpoint and `Doer` (production: a dedicated `safehttp.Client`). The endpoint may be a base URL such as `https://provider.example.com/v1` or the full `/chat/completions` URL. URL policy must match the administrator-owned Safe HTTP policy.
- `BuildRequest(ctx, domain.NormalizedRequest)` returns an HTTP request and detached snapshot of canonical wire JSON. It maps exactly one output-budget parameter and never inserts authentication. Unknown extras, non-finite values, unsupported roles/formats and oversized requests are rejected.
- `Call(ctx, input, prepare, sink)` builds the request, invokes the trusted Worker-owned `PrepareRequest` callback, sends and parses. The callback may attach credentials to headers only; do not alter the URL, method or body. Invoke the whole call inside the Secret Service's short-lived outbound scope. The adapter does not retain the callback or credentials.
- `ParseNonStream(response)` and `ParseStream(ctx, response, sink)` can parse existing responses. Both close response bodies. `Call` is preferred because it also records network-inclusive first-byte/first-token timings.
- `Precheck(ctx, input, prepare)` performs an unscored, non-streaming call with at most 16 output tokens. Only a structured or strictly recognized `max_tokens` unsupported-parameter error permits one fallback attempt with `max_completion_tokens`. The successful mapping is cached per adapter; a failed fallback is not repeatedly attempted. A normal `Call` never performs capability fallback or automatic retries.
- `Capabilities()` describes the supported subset: streaming with usage, seed, `max_tokens`/`max_completion_tokens`, text/JSON-object response formats and bounded frequency/presence penalties. JSON Schema, tools, images, audio, `n>1` and arbitrary parameter forwarding are not silently claimed as supported.

The project-frozen default remains `max_tokens`; an explicit target configuration wins. A model capability resolver can supply the explicit parameter before construction. No mutable remote model-name heuristics are embedded here.

## Evidence and safety

Request snapshots contain only canonical JSON and its SHA-256, never URL queries or headers. Probe payloads and normalized model content remain sensitive/untrusted S2 data, not logging DTOs. Response error bodies and low-level parser/network diagnostics never enter returned errors or normalized content. The Worker/report retention layer remains responsible for encryption, redaction, storage limits and plain-text rendering.

Responses preserve model/usage/finish observations, including missing fields and contradictory non-negative totals. Missing usage is represented with `nil` pointers, not synthesized zeroes. Duplicate JSON keys, negative/fractional usage, invalid UTF-8, ambiguous choices, wrong content types and unsupported output structures are rejected. Finish-reason strings outside the protocol enum become an `unknown` value plus a warning, not an untrusted diagnostic string.

SSE accepts LF/CRLF/CR, arbitrary network splits across UTF-8, multiline data, comments, empty events, role/content/refusal deltas, usage-only chunks and `[DONE]`. Event summaries retain only sequence/type/byte count/timing: first eight and last eight events. No complete stream or event body is kept. A normal stream requires `[DONE]`; EOF after valid chunks is `partial` with warnings. Malformed/client-limit responses are `invalid`; network/timeout/cancel errors retain already valid partial content but are explicitly classified for sample validity, not risk scoring.

Limits are at most 1 MiB request JSON, 1 MiB per SSE event, 8 MiB aggregate response and 64 KiB error body. First effective event defaults to 60 s from call start, stream idle to 30 s and total request to 180 s. An initial role-only event or heartbeat does not satisfy the first effective event deadline. The Safe HTTP layer additionally enforces wire/decompressed limits, TLS and network policy. `Doer`, clocks and event sinks are trusted integration seams; sinks must be nonblocking.

## Verification and source

Tests include canonical mapping/no-auth snapshots, strict shape and usage validation, one-time capability fallback and negative cases, byte-at-a-time Unicode SSE, delimiter variants, multiline/empty events, incomplete EOF, malformed events, bounded summaries, size limits, first/idle/total/cancel deadlines, and sanitized failures. Integration tests actually exercise this repository's synthetic mock upstream through a Safe HTTP client with verified TLS and a test-only validated-IP dial seam. Test-controller labels are read only by test assertions, never by the adapter.

The independently authored reference-shape fixture and usage-only/termination handling were checked using **OpenAI Docs**: [Create chat completion and streaming schema](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create). These are local compatibility checks, not evidence of a successful paid or real provider request. Real model/provider compatibility remains a separately authorized external check.
