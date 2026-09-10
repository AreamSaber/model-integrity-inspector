package openaichat

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/safehttp"
	mockupstream "model-integrity-inspector.local/mii/tests/mock-upstream"
)

type fixedResolver struct{}

func (fixedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

func mockAdapter(t *testing.T, config mockupstream.Config, adapterConfig func(*Config)) (*Adapter, *mockupstream.Handler) {
	t.Helper()
	upstream, err := mockupstream.NewHandler(config)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(upstream)
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, err := safehttp.NewClient(safehttp.Config{
		Endpoint: "https://upstream.example.com/v1", RootCAs: roots, Resolver: fixedResolver{},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "8.8.8.8:443" {
				t.Error("adapter bypassed validated-IP dial")
			}
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, server.Listener.Addr().String())
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	options := Config{Endpoint: "https://upstream.example.com/v1", Doer: client}
	if adapterConfig != nil {
		adapterConfig(&options)
	}
	adapter, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	return adapter, upstream
}

func TestActualMockUpstreamThroughSafeHTTPTLS(t *testing.T) {
	t.Parallel()
	for _, parameter := range []string{"max_tokens", "max_completion_tokens"} {
		for _, stream := range []bool{false, true} {
			t.Run(parameter+map[bool]string{false: "-json", true: "-sse"}[stream], func(t *testing.T) {
				testKey := "CANARY_" + t.Name()
				a, controller := mockAdapter(t, mockupstream.Config{RequiredAPIKey: testKey}, func(config *Config) { config.MaxOutputParameter = parameter })
				value := input()
				value.Stream = stream
				result, snapshot, err := a.Call(t.Context(), value, func(request *http.Request) error {
					request.Header.Set("Authorization", "Bearer "+testKey)
					return nil
				}, nil)
				if err != nil || result.ParseStatus != "valid" || result.Content == "" || result.CompletionTokens == nil || *result.CompletionTokens != 64 || result.FinishReason != "length" || result.StreamTerminated != stream {
					t.Fatalf("actual local compatibility failed: %v", err)
				}
				if snapshot.MaxOutputParameter != parameter || strings.Contains(string(snapshot.Payload), "CANARY") || result.HTTPStatus != 200 || result.ProviderRequestID == "" {
					t.Fatal("snapshot/response metadata incorrect")
				}
				// Ground truth stays in test-controller code, never production adapter input.
				deadline := time.Now().Add(time.Second)
				records := controller.Records()
				for len(records) == 0 && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
					records = controller.Records()
				}
				if len(records) != 1 || records[0].RequestedTokens != 64 || records[0].Request.Stream != stream {
					t.Fatal("mock observed a different request")
				}
				if _, exists := records[0].ReceivedParameters[parameter]; !exists {
					t.Fatal("expected budget parameter was not sent")
				}
			})
		}
	}
}

func TestActualMockFaultMatrix(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name         string
		config       mockupstream.Config
		stream       bool
		code, status string
		warning      string
	}{
		{"missing-usage", mockupstream.Config{UsageMode: "missing"}, false, "", "valid", "USAGE_MISSING"},
		{"missing-finish", mockupstream.Config{FinishReasonMode: "missing"}, true, "", "valid", "FINISH_REASON_MISSING"},
		{"omit-done", mockupstream.Config{StreamMode: "omit_done"}, true, "", "partial", "STREAM_EOF_BEFORE_DONE"},
		{"truncate", mockupstream.Config{StreamMode: "truncate", StreamCutoffTokens: 4}, true, "", "partial", "STREAM_EOF_BEFORE_DONE"},
		{"malformed", mockupstream.Config{StreamMode: "malformed_event"}, true, "MI_PROTOCOL_INVALID", "invalid", "STREAM_MALFORMED_EVENT"},
		{"rate-limit", mockupstream.Config{HTTPErrorRate: 1, HTTPErrorStatus: 429, RetryAfterSeconds: 3}, false, "MI_UPSTREAM_RATE_LIMITED", "invalid", ""},
		{"network", mockupstream.Config{NetworkErrorRate: 1}, false, "MI_HTTP_NETWORK_FAILED", "invalid", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, _ := mockAdapter(t, test.config, nil)
			value := input()
			value.Stream = test.stream
			result, _, err := a.Call(t.Context(), value, nil, nil)
			if errorCode(err) != test.code || result.ParseStatus != test.status {
				t.Fatalf("fault matrix classification failed: status=%s error=%v", result.ParseStatus, err)
			}
			if test.warning != "" && !hasWarning(result, test.warning) {
				t.Fatal("expected observability warning missing")
			}
			if test.name == "rate-limit" {
				var normalized *Error
				if !errors.As(err, &normalized) || normalized.RetryAfter != 3*time.Second || !normalized.Retryable {
					t.Fatal("retry metadata missing")
				}
			}
		})
	}
}

func TestControlledCapAndUsageForgeryAreObservedNotScored(t *testing.T) {
	t.Parallel()
	a, _ := mockAdapter(t, mockupstream.Config{OverrideMaxTokens: 16, OverrideProbability: 1, UsageMode: "inflated", UsageFactor: 2}, nil)
	result, _, err := a.Call(t.Context(), input(), nil, nil)
	if err != nil || result.CompletionTokens == nil || *result.CompletionTokens != 32 || len(strings.Fields(result.Content)) != 16 || result.ParseStatus != "valid" {
		t.Fatalf("controlled anomaly was not preserved for later analysis: %v", err)
	}
}

// This is an independently authored fixture following the official Chat
// Completions response schema, not evidence of a paid/real upstream call.
func TestOfficialChatCompletionSchemaFixture(t *testing.T) {
	t.Parallel()
	fixture := `{"id":"chatcmpl-reference-fixture","object":"chat.completion","created":0,"model":"fixture-model","choices":[{"index":0,"message":{"role":"assistant","content":"Synthetic compatibility response.","refusal":null,"annotations":[]},"logprobs":null,"finish_reason":"stop"}],"usage":{"prompt_tokens":7,"completion_tokens":9,"total_tokens":16,"prompt_tokens_details":{"cached_tokens":0},"completion_tokens_details":{"reasoning_tokens":2,"accepted_prediction_tokens":0,"rejected_prediction_tokens":0}},"service_tier":"default","system_fingerprint":"fixture-fingerprint"}`
	a := adapterForTest(t, nil)
	result, err := a.ParseNonStream(rawResponse(200, "application/json", fixture))
	if err != nil || result.ModelReported != "fixture-model" || result.ReasoningTokens == nil || *result.ReasoningTokens != 2 || result.ParseStatus != "valid" {
		t.Fatalf("reference shape rejected: %v", err)
	}
}

func TestRequestSnapshotUnaffectedByScopedCredentials(t *testing.T) {
	t.Parallel()
	testKey := "CANARY_" + t.Name()
	a, _ := mockAdapter(t, mockupstream.Config{RequiredAPIKey: testKey}, nil)
	prepare := func(req *http.Request) error { req.Header.Set("Authorization", "Bearer "+testKey); return nil }
	value := input()
	value.Messages = []domain.NormalizedMessage{{Role: "developer", Content: "Perform a neutral synthetic task."}, {Role: "user", Content: "Return a bounded list."}}
	_, before, err := a.BuildRequest(t.Context(), value)
	if err != nil {
		t.Fatal(err)
	}
	result, after, err := a.Call(t.Context(), value, prepare, nil)
	if err != nil {
		t.Fatal(err)
	}
	if before.RequestHash != after.RequestHash || !json.Valid(after.Payload) {
		t.Fatal("auth affected request hash")
	}
	encoded, _ := json.Marshal(struct {
		Snapshot domain.RequestSnapshot
		Response domain.NormalizedResponse
	}{after, result})
	if strings.Contains(string(encoded), testKey) || strings.Contains(string(encoded), "Authorization") {
		t.Fatal("credential leaked into durable DTO")
	}
}

func TestFirstEventBudgetIncludesHeaderDelay(t *testing.T) {
	t.Parallel()
	start := time.Now()
	a := adapterForTest(t, func(config *Config) {
		config.FirstEventTimeout = 30 * time.Millisecond
		config.Now = func() time.Time { return time.Now() }
		config.Doer = doerFunc(func(req *http.Request) (*http.Response, error) {
			_ = req.Body.Close()
			timer := time.NewTimer(50 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-timer.C:
			}
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(basicStream()))}, nil
		})
	})
	value := input()
	value.Stream = true
	_, _, err := a.Call(t.Context(), value, nil, nil)
	if errorCode(err) != "MI_HTTP_TIMEOUT" || time.Since(start) > time.Second {
		t.Fatalf("header delay reset the first-event budget: %v", err)
	}
}
