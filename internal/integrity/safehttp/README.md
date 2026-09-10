# Safe HTTP boundary

`safehttp` owns outbound URL, address, TLS, framing, header and byte/time limits. It does not fetch Secrets, accept `secret_id`, access a repository, log request/response data, parse model output or assign risk scores.

## Adapter use

```go
client, err := safehttp.NewClient(safehttp.Config{
    Endpoint: "https://provider.example.com/v1",
    // Set only after validating custom header names with ValidateCustomHeaders.
    AllowedRequestHeaders: []string{"X-Provider-Token"},
})
if err != nil { /* return the sanitized error code */ }
defer client.CloseIdleConnections()

// Obtain plaintext credentials only within the Worker's scoped Secret callback.
// Adapter builds a request with its context, JSON body, Authorization, Content-Type
// and Accept, then calls client.Do(request). Always close response.Body.
```

Create a distinct client per target/runtime configuration. The request must remain on the configured origin and within its base-path subtree. HTTP methods are limited to GET, HEAD and POST. Transport and TLS configuration are not exposed for mutation.

`ValidateEndpoint(raw, URLPolicy)` is pure: it checks URL syntax and IP literals, not live DNS. DNS is checked by the actual connection dial path, including each fresh connection after keep-alive expiry or failure. A complete answer set must pass before any address is dialed; the dialer receives only numeric validated IPs. TLS verifies the original hostname with system roots or an administrator-supplied trust pool (cloned at construction). HTTP/1.1 avoids multiplexing streams across a shared socket idle deadline.

## Administrator policy

- HTTPS is mandatory unless `URLPolicy.AllowHTTP` is explicitly enabled for development; this never disables address checks.
- `PrivateCIDRAllowlist` accepts only canonical subnets inside RFC1918 or IPv6 ULA. Loopback, link-local, multicast, unspecified, special-use, metadata and known platform addresses remain blocked even with an allowlist.
- `BlockedCIDRs` adds deployment-specific control-plane exclusions and takes precedence over private allowlists.
- All URL queries, userinfo, fragments, percent-encoded paths, dot segments, alternate numeric host forms and non-ASCII hostnames are rejected. V1 targets use ordinary OpenAI-compatible base URLs; query-dependent provider protocols require a separately reviewed adapter/policy extension.
- Environment proxies, redirects, cookie jars, insecure TLS, Unix sockets and request framing/routing overrides are unavailable.
- `Resolver`, `DialContext` and `RootCAs` are trusted infrastructure/test seams. They must never come from target/HTTP request data. Tests map a validated public IP to their own loopback server solely inside the injected dialer; production policy is unchanged.
- `ValidateCustomHeaders` rejects overrides of adapter-owned Authorization/Content-Type/Accept/User-Agent/Idempotency-Key as well as transport-reserved headers. The final outgoing adapter request may contain those normal adapter-owned headers. Additional custom outgoing header names require an explicit allowlist.

## Resource and error behavior

Defaults: 10 s connection/DNS, 10 s TLS, 30 s response headers, 30 s socket idle, 180 s total request; request/wire response/decompressed response each at most 8 MiB, error response at most 64 KiB, response headers at most 64 KiB. Configured byte limits may reduce, never raise, these ceilings. Total timeout includes response body reading; cancellation and limit violations close the body. The adapter separately applies the protocol's 1 MiB SSE-event and first-valid-event limits.

Oversized bodies produce `ErrSafetyLimit` (`CLIENT_SAFETY_LIMIT`) rather than successful truncated EOF. This is a client-safety termination, not evidence of upstream token manipulation. Both compressed wire bytes and decompressed gzip output are bounded; unsupported or ambiguous compression is rejected. Stable package errors discard underlying URL/header/DNS/TLS/body error text. Responses do not retain the authenticated request or cookies/auth headers; only the response-header whitelist survives. Body contents remain untrusted adapter input and must not be logged or rendered as HTML.

Safety tests include URL/header injection, reserved ranges, mixed DNS answers, rebinding, IPv4-mapped IPv6, administrator-private routing, origin/path/pool separation, original TLS SNI, CA/hostname failures, redirects, environment proxy isolation, compression bombs, exact-size EOF, request/error/response bounds, header/idle/total/cancel timeouts, sanitized errors and concurrent request isolation.

References: [Go net/http](https://pkg.go.dev/net/http), [IANA IPv4 special-purpose registry](https://www.iana.org/assignments/iana-ipv4-special-registry), [IANA IPv6 special-purpose registry](https://www.iana.org/assignments/iana-ipv6-special-registry).
