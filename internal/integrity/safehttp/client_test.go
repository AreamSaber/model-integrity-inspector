package safehttp

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type resolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (resolver resolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return resolver(ctx, network, host)
}

type harness struct {
	client *Client
	server *httptest.Server
	dials  atomic.Int32
	dns    atomic.Int32
	sni    chan string
}

func newHarness(t *testing.T, handler http.HandlerFunc, configure func(*Config)) *harness {
	t.Helper()
	h := &harness{sni: make(chan string, 32)}
	h.server = httptest.NewUnstartedServer(handler)
	h.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	h.server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		h.sni <- hello.ServerName
		return nil, nil
	}}
	h.server.StartTLS()
	t.Cleanup(h.server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(h.server.Certificate())
	config := Config{
		Endpoint: "https://upstream.example.com/v1", RootCAs: roots,
		Resolver: resolverFunc(func(_ context.Context, network, host string) ([]netip.Addr, error) {
			h.dns.Add(1)
			if network != "ip" || host != "upstream.example.com" {
				t.Error("resolver received unexpected network or hostname")
			}
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		}),
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			h.dials.Add(1)
			if network != "tcp" || address != "8.8.8.8:443" {
				t.Error("dial was not pinned to the validated numeric IP")
			}
			// Only the trusted test seam maps the checked public address to a
			// loopback test server; production policy is never relaxed.
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, h.server.Listener.Addr().String())
		},
	}
	if configure != nil {
		configure(&config)
	}
	var err error
	h.client, err = NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.client.CloseIdleConnections)
	return h
}

func request(t *testing.T, method, endpoint string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, endpoint, body)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func consume(t *testing.T, response *http.Response) ([]byte, error) {
	t.Helper()
	defer func() { _ = response.Body.Close() }()
	return io.ReadAll(response.Body)
}

func TestClientPinsIPPreservesTLSAndScrubsResponseMetadata(t *testing.T) {
	t.Parallel()
	h := newHarness(t, func(writer http.ResponseWriter, req *http.Request) {
		if req.Host != "upstream.example.com" || req.Header.Get("Authorization") != "Bearer CANARY_SECRET" || req.URL.Path != "/v1/chat/completions" {
			t.Error("adapter request was not preserved")
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Request-Id", "request-123")
		writer.Header().Set("Set-Cookie", "key=CANARY_SECRET")
		writer.Header().Set("Authorization", "Bearer CANARY_SECRET")
		writer.Header().Set("X-Api-Key", "CANARY_SECRET")
		_, _ = io.WriteString(writer, `{"ok":true}`)
	}, nil)
	req := request(t, http.MethodPost, "https://upstream.example.com/v1/chat/completions", strings.NewReader(`{"model":"test"}`))
	req.Header.Set("Authorization", "Bearer CANARY_SECRET")
	req.Header.Set("Content-Type", "application/json")
	response, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, err := consume(t, response)
	if err != nil || string(data) != `{"ok":true}` {
		t.Fatalf("unexpected response: %v", err)
	}
	if response.Request != nil || len(response.Header) != 2 || response.Header.Get("X-Request-Id") != "request-123" {
		t.Fatal("response metadata exposes the outbound request or unsafe headers")
	}
	if h.dials.Load() != 1 || h.dns.Load() != 1 || <-h.sni != "upstream.example.com" {
		t.Fatal("DNS/IP pinning or TLS SNI differs from target")
	}
}

func TestMixedDNSAnswersAreRejectedBeforeAnyDial(t *testing.T) {
	t.Parallel()
	for _, blocked := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "::ffff:127.0.0.1", "fd00:ec2::254", "168.63.129.16", "192.0.2.1"} {
		t.Run(blocked, func(t *testing.T) {
			var dials atomic.Int32
			client, err := NewClient(Config{
				Endpoint: "https://upstream.example.com/v1",
				Resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr(blocked)}, nil
				}),
				DialContext: func(context.Context, string, string) (net.Conn, error) {
					dials.Add(1)
					return nil, errors.New("CANARY_NETWORK_ERROR")
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			_, err = client.Do(request(t, http.MethodGet, "https://upstream.example.com/v1", nil))
			if !errors.Is(err, ErrBlockedAddress) || dials.Load() != 0 {
				t.Fatalf("mixed DNS set reached dialer: %v", err)
			}
		})
	}
}

func TestDNSRebindingIsCheckedAtEveryNewConnection(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	h := newHarness(t, func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Connection", "close")
		_, _ = io.WriteString(writer, "ok")
	}, func(config *Config) {
		config.Resolver = resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			if calls.Add(1) == 1 {
				return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
			}
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		})
	})
	response, err := h.client.Do(request(t, http.MethodGet, "https://upstream.example.com/v1", nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consume(t, response); err != nil {
		t.Fatal(err)
	}
	_, err = h.client.Do(request(t, http.MethodGet, "https://upstream.example.com/v1", nil))
	if !errors.Is(err, ErrBlockedAddress) || calls.Load() != 2 || h.dials.Load() != 1 {
		t.Fatalf("rebound address accepted: %v", err)
	}
}

func TestRedirectNeverMakesSecondRequestOrLeaksCredentials(t *testing.T) {
	t.Parallel()
	for _, location := range []string{"https://attacker.example.com/?key=CANARY_SECRET", "http://169.254.169.254/latest/meta-data", "/v1/elsewhere"} {
		t.Run(location, func(t *testing.T) {
			var calls atomic.Int32
			h := newHarness(t, func(writer http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				writer.Header().Set("Location", location)
				writer.WriteHeader(http.StatusTemporaryRedirect)
			}, nil)
			req := request(t, http.MethodPost, "https://upstream.example.com/v1", strings.NewReader("{}"))
			req.Header.Set("Authorization", "Bearer CANARY_SECRET")
			_, err := h.client.Do(req)
			if !errors.Is(err, ErrRedirect) || calls.Load() != 1 || h.dials.Load() != 1 || strings.Contains(err.Error(), "CANARY") {
				t.Fatalf("redirect policy failed: %v", err)
			}
		})
	}
}

func TestUnknownCAAndWrongTLSHostnameAreRejected(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"untrusted-ca", "wrong-name"} {
		t.Run(mode, func(t *testing.T) {
			var reached atomic.Bool
			h := newHarness(t, func(http.ResponseWriter, *http.Request) { reached.Store(true) }, func(config *Config) {
				if mode == "untrusted-ca" {
					config.RootCAs = x509.NewCertPool()
				} else {
					config.Endpoint = "https://other.example.net/v1"
					config.Resolver = resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
						return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
					})
				}
			})
			_, err := h.client.Do(request(t, http.MethodGet, h.client.endpoint.String(), nil))
			if !errors.Is(err, ErrTLS) || reached.Load() {
				t.Fatalf("TLS verification failed open: %v", err)
			}
		})
	}
}

func TestPerTargetOriginPathAndHeaderIsolation(t *testing.T) {
	t.Parallel()
	h := newHarness(t, func(writer http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(writer, "ok") }, nil)
	for _, endpoint := range []string{"https://elsewhere.example.com/v1", "https://upstream.example.com:8443/v1", "http://upstream.example.com/v1", "https://upstream.example.com/admin", "https://upstream.example.com/v11"} {
		if _, err := h.client.Do(request(t, http.MethodGet, endpoint, nil)); err == nil {
			t.Errorf("target boundary bypass accepted: %s", endpoint)
		}
	}
	for _, headers := range []http.Header{
		{"Host": {"attacker.example.com"}}, {"Proxy-Authorization": {"CANARY_SECRET"}}, {"X-Unapproved-Key": {"CANARY_SECRET"}},
		{"Authorization": {"Bearer CANARY_SECRET\r\nHost: 127.0.0.1"}}, {"Accept-Encoding": {"br"}},
	} {
		req := request(t, http.MethodGet, "https://upstream.example.com/v1", nil)
		req.Header = headers
		if _, err := h.client.Do(req); !errors.Is(err, ErrInvalidHeader) {
			t.Errorf("header boundary bypass accepted: %v", err)
		}
	}
	req := request(t, http.MethodGet, "https://upstream.example.com/v1", nil)
	req.Host = "169.254.169.254"
	if _, err := h.client.Do(req); !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("Request.Host override accepted: %v", err)
	}
	if h.dials.Load() != 0 {
		t.Fatal("rejected request performed network access")
	}
	other := newHarness(t, func(writer http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(writer, "ok") }, nil)
	if h.client.transport == other.client.transport {
		t.Fatal("targets share a transport/pool")
	}
}

func TestRequestAndResponseSizeLimits(t *testing.T) {
	t.Parallel()
	for _, bodySize := range []int{31, 32, 33} {
		t.Run(strconv.Itoa(bodySize), func(t *testing.T) {
			var calls atomic.Int32
			h := newHarness(t, func(writer http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				_, _ = io.WriteString(writer, "ok")
			}, func(config *Config) { config.MaxRequestBodyBytes = 32 })
			req := request(t, http.MethodPost, "https://upstream.example.com/v1", strings.NewReader(strings.Repeat("x", bodySize)))
			req.ContentLength = -1 // Unknown lengths must also be checked before network I/O.
			response, err := h.client.Do(req)
			if bodySize > 32 {
				if !errors.Is(err, ErrSafetyLimit) || calls.Load() != 0 {
					t.Fatalf("oversized request reached upstream: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := consume(t, response); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	for _, mode := range []string{"known-length", "chunked", "exact", "error-body"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, func(writer http.ResponseWriter, _ *http.Request) {
				count := 33
				if mode == "exact" {
					count = 32
				}
				if mode == "error-body" {
					writer.WriteHeader(http.StatusUnauthorized)
				}
				if mode == "chunked" || mode == "error-body" {
					writer.(http.Flusher).Flush()
				}
				_, _ = io.WriteString(writer, strings.Repeat("x", count))
			}, func(config *Config) { config.MaxResponseBodyBytes = 32; config.MaxErrorBodyBytes = 16 })
			response, err := h.client.Do(request(t, http.MethodGet, "https://upstream.example.com/v1", nil))
			var data []byte
			if err == nil {
				data, err = consume(t, response)
			}
			if mode == "exact" {
				if err != nil || len(data) != 32 {
					t.Fatalf("exact-size response rejected: %v", err)
				}
			} else if !errors.Is(err, ErrSafetyLimit) || len(data) > 32 {
				t.Fatalf("oversized response was silently accepted: %v", err)
			}
		})
	}
}

func TestDecompressedResponseLimitAndUnsupportedEncoding(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"small-gzip", "gzip-bomb", "unsupported", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Encoding", "gzip")
				if mode == "unsupported" {
					writer.Header().Set("Content-Encoding", "br")
				}
				if mode == "duplicate" {
					writer.Header().Add("Content-Encoding", "identity")
				}
				count := 100
				if mode == "gzip-bomb" {
					count = 10000
				}
				compressor := gzip.NewWriter(writer)
				_, _ = compressor.Write(bytes.Repeat([]byte{'x'}, count))
				_ = compressor.Close()
			}, func(config *Config) { config.MaxResponseBodyBytes = 128 })
			response, err := h.client.Do(request(t, http.MethodGet, "https://upstream.example.com/v1", nil))
			var data []byte
			if err == nil {
				data, err = consume(t, response)
			}
			switch mode {
			case "small-gzip":
				if err != nil || len(data) != 100 || !response.Uncompressed || response.Header.Get("Content-Encoding") != "" {
					t.Fatalf("valid compressed response failed: %v", err)
				}
			case "gzip-bomb":
				if !errors.Is(err, ErrSafetyLimit) || len(data) != 128 {
					t.Fatalf("decompression limit not enforced: %v", err)
				}
			default:
				if !errors.Is(err, ErrEncoding) {
					t.Fatalf("unsupported encoding accepted: %v", err)
				}
			}
		})
	}
}

func TestHeaderIdleTotalAndCancellationTimeouts(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"headers", "idle", "total", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, func(writer http.ResponseWriter, req *http.Request) {
				if mode == "headers" {
					<-req.Context().Done()
					return
				}
				writer.Header().Set("Content-Type", "text/event-stream")
				writer.(http.Flusher).Flush()
				if mode == "total" {
					ticker := time.NewTicker(5 * time.Millisecond)
					defer ticker.Stop()
					for {
						select {
						case <-req.Context().Done():
							return
						case <-ticker.C:
							_, _ = io.WriteString(writer, "x")
							writer.(http.Flusher).Flush()
						}
					}
				}
				<-req.Context().Done()
			}, func(config *Config) {
				config.RequestTotalTimeout = 500 * time.Millisecond
				config.StreamIdleTimeout = 300 * time.Millisecond
				if mode == "headers" {
					config.ResponseHeaderTimeout = 40 * time.Millisecond
				}
				if mode == "idle" {
					config.StreamIdleTimeout = 40 * time.Millisecond
				}
				if mode == "total" {
					config.RequestTotalTimeout = 80 * time.Millisecond
				}
			})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			req := request(t, http.MethodGet, "https://upstream.example.com/v1", nil).WithContext(ctx)
			started := time.Now()
			response, err := h.client.Do(req)
			if mode == "cancel" {
				cancel()
			}
			if err == nil {
				_, err = consume(t, response)
			}
			want := ErrTimeout
			if mode == "cancel" {
				want = ErrCanceled
			}
			if !errors.Is(err, want) || time.Since(started) > time.Second {
				t.Fatalf("timeout/cancellation not enforced promptly: %v", err)
			}
		})
	}
}

func TestProxyEnvironmentIsNeverUsed(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1/CANARY_PROXY_SECRET")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1/CANARY_PROXY_SECRET")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1/CANARY_PROXY_SECRET")
	h := newHarness(t, func(writer http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(writer, "ok") }, nil)
	response, err := h.client.Do(request(t, http.MethodGet, "https://upstream.example.com/v1", nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consume(t, response); err != nil {
		t.Fatal(err)
	}
	if h.client.transport.Proxy != nil || h.dials.Load() != 1 {
		t.Fatal("environment proxy affected transport")
	}
}

func TestNilRequestHeaderIsSafe(t *testing.T) {
	t.Parallel()
	h := newHarness(t, func(writer http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(writer, "ok") }, nil)
	req := request(t, http.MethodGet, "https://upstream.example.com/v1", nil)
	req.Header = nil
	response, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consume(t, response); err != nil {
		t.Fatal(err)
	}
}

func TestResolverDialErrorsAndContextAreSanitized(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"dns-error", "dns-empty", "dns-timeout", "dial-error", "dial-timeout"} {
		t.Run(mode, func(t *testing.T) {
			config := Config{Endpoint: "https://upstream.example.com/v1", ConnectTimeout: 30 * time.Millisecond}
			config.Resolver = resolverFunc(func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
				switch mode {
				case "dns-error":
					return nil, errors.New("CANARY_DNS_SECRET")
				case "dns-empty":
					return nil, nil
				case "dns-timeout":
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
			})
			config.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
				if mode == "dial-timeout" {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return nil, errors.New("CANARY_DIAL_SECRET")
			}
			client, err := NewClient(config)
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			_, err = client.Do(request(t, http.MethodGet, config.Endpoint, nil))
			if err == nil || strings.Contains(err.Error(), "CANARY") || strings.Contains(err.Error(), "upstream.example") {
				t.Fatalf("unsafe transport error: %v", err)
			}
			if strings.HasSuffix(mode, "timeout") && !errors.Is(err, ErrTimeout) {
				t.Fatalf("timeout not classified: %v", err)
			}
		})
	}
}

func TestConcurrentRequestsRemainIsolated(t *testing.T) {
	t.Parallel()
	h := newHarness(t, func(writer http.ResponseWriter, req *http.Request) {
		_, _ = io.WriteString(writer, html.EscapeString(req.Header.Get("X-Request-Id")))
	}, nil)
	var group sync.WaitGroup
	for index := 0; index < 12; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			id := strings.Repeat("x", index+1)
			req := request(t, http.MethodPost, "https://upstream.example.com/v1", strings.NewReader("{}"))
			req.Header.Set("X-Request-Id", id)
			response, err := h.client.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			data, err := consume(t, response)
			if err != nil || string(data) != id {
				t.Error("concurrent request/response contamination")
			}
		}()
	}
	group.Wait()
}
