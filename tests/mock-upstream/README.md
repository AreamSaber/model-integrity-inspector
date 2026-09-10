# Mock upstream — M0-07

Development implementation, pending formal review. This is a bounded synthetic server, not an LLM, production gateway, detector, or an algorithm-accuracy claim. It makes no outbound requests and does not use real credentials.

## Run and embed

```powershell
.\.tools\go\bin\go.exe run ./cmd/mock-upstream -config ./tests/mock-upstream/scenarios/fixed-cap.json
.\.tools\go\bin\go.exe test ./tests/mock-upstream ./cmd/mock-upstream ./tests/datasets
```

The default listener is `127.0.0.1:8090`. The CLI rejects non-loopback listeners and `APP_ENV=production` / `MII_ENV=production`; it is deliberately not wired into `cmd/mii` or production deployment. Configure a **test-only** explicit Safe HTTP allowlist for loopback when exercising the real product; do not weaken the default SSRF policy. Stop with Ctrl+C.

Public protocol endpoints: `GET /health`, `GET /v1/models`, `POST /v1/chat/completions`. Only Chat Completions text JSON/SSE is supported. There is no HTTP configuration, oracle, labels, records, or control endpoint. Responses and request IDs contain no scenario identifiers.

Go API:

```go
handler, err := mockupstream.NewHandler(mockupstream.Config{
    Seed: 42, OverrideMaxTokens: 256, OverrideProbability: 1,
})
// Handle err, then use httptest.NewServer(handler).
// Only the trusted test controller may read handler.Records().
```

`Responder func(Request, int) (Generation, error)` supplies fixture-specific text/token pieces for exact format contracts, JSONL, numbered sequences, or tokenizer integration. The default responder emits `item000001 `, `item000002 `, etc., up to the requested budget. It does not understand arbitrary natural-language instructions. A synthetic token is **one generated piece**, not a real model-vocabulary token; default usage must not be labeled an exact production tokenizer count. The generation limit is 8,192 pieces / 1 MiB content. Input bodies are limited to 1 MiB and 256 messages. Record retention defaults to the newest 256 requests, configurable up to 10,000.

## Combinable controls

| Control | Values and behavior |
|---|---|
| `inject_system_instruction` | `fixed_prefix`, `forced_identity`, `neutral_refusal`; detects observable effects only, no real system prompt is extracted |
| `prefix`, `response_suffix` | Bounded synthetic prefix/suffix response modifications |
| `override_max_tokens`, `override_probability` | Cap only when lower than requested; explicitly set probability `1` for a fixed cap, `0` means disabled |
| `cap_steps` | Ordered `{min_requested,cap}` thresholds; last matching step wins; same probability gate |
| `usage_mode`, `usage_factor` | `honest`, `missing`, `inflated` (default ×1.3), `deflated` (default ×0.5) |
| `finish_reason_mode` | `honest`, `always_stop`, `always_length`, `missing` |
| `stream_mode` | `normal`, `truncate`, `omit_done`, `delay`, `malformed_event` |
| `stream_cutoff_tokens` | Visible generation cutoff only for stream requests; omit both final finish/usage and `[DONE]` |
| `stream_chunk_tokens` | Chunk-size hint (four Unicode code points per unit); does not assert TCP packet boundaries |
| `delay_milliseconds` | Context-cancellable delay, bounded at 10 seconds; delayed stream mode also delays each event |
| `model_alias` | Override reported model without changing requested model in the controller snapshot |
| `http_error_rate`, `http_error_status` | 400/401/404/429/5xx; 429/503 include bounded `Retry-After` |
| `network_error_rate` | Real HTTP/1 connection close before headers; in a recorder without Hijack returns explicit 503 fallback |
| `natural_early_eos`, `safety_refusal` | Hard-negative behavior without hidden-instruction configuration; these and instruction controls also apply to custom responders |
| `reasoning_tokens` | Separate reasoning detail and total completion budget for reasoning-model negative controls |

Network, HTTP, and cap probability draws use separate SHA-256-derived deterministic domains with `(config seed, request ordinal)`. Replaying the same sequential request sequence under the same config reproduces the draws. Under concurrency, retain controller ordinals/dispatch order; do not assume scheduler interleavings are reproducible. The request's model seed is preserved as a protocol parameter but does not control the server's fault RNG. Ordinary IDs and deterministic creation timestamps are the same across scenario types to avoid oracle leakage.

Honest Usage describes generated synthetic token pieces before gateway-style prefix/suffix rewriting. Consequently prefix/suffix scenarios can intentionally produce response/Usage disagreement; this is not an exact tokenizer experiment. `include_usage` is honored for normal SSE; JSON responses include usage unless missing mode is enabled. Stream faults leave non-streaming comparisons intact.

`Records()` returns a deep copy of the bounded controller-only history: actual JSON parameters, requested budget, applied cap, generated count, ordinal, status, and termination state. Authorization/cookie headers are never captured. Test requests must still be synthetic and non-sensitive: controller snapshots contain supplied messages. These are controlled experiment records, not automatically A-grade evidence or production audit logs. Evidence elevation requires the evaluator to intentionally attach and verify direct observations outside blind mode.

## Verification and limits

Tests cover both output aliases, request/configuration bounds, fixed/piecewise/probability caps, deterministic replay, response behavior, usage/finish/model overrides, normal and anomalous SSE, UTF-8, authentication non-disclosure, true transport EOF, cancellation, concurrency, bounded snapshots and absence of control endpoints. Public scenario files are development fixtures only. No live model accuracy, frozen calibration set, blind acceptance result, production networking, or independent approval is claimed.
