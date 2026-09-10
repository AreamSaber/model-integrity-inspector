package openaichat

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/safehttp"
)

type doerFunc func(*http.Request) (*http.Response, error)

func (doer doerFunc) Do(request *http.Request) (*http.Response, error) { return doer(request) }

func adapterForTest(t *testing.T, configure func(*Config)) *Adapter {
	t.Helper()
	config := Config{Endpoint: "https://upstream.example.com/v1", Doer: doerFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("CANARY_UNEXPECTED_NETWORK") })}
	if configure != nil {
		configure(&config)
	}
	adapter, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func input() domain.NormalizedRequest {
	return domain.NormalizedRequest{Model: "test-model", Messages: []domain.NormalizedMessage{{Role: "user", Content: "Return a synthetic sequence."}}, MaxOutputTokens: 64}
}
func float(value float64) *float64 { return &value }
func rawResponse(code int, contentType, body string) *http.Response {
	return &http.Response{StatusCode: code, Header: http.Header{"Content-Type": {contentType}}, Body: io.NopCloser(strings.NewReader(body))}
}
func errorCode(err error) string {
	var normalized *Error
	if errors.As(err, &normalized) {
		return normalized.Code
	}
	if err != nil {
		return "UNCLASSIFIED"
	}
	return ""
}

const goodNonStream = `{"id":"chatcmpl-fixture","object":"chat.completion","model":"test-model","choices":[{"index":0,"message":{"role":"assistant","content":"Hello 世界"},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":5,"completion_tokens_details":{"reasoning_tokens":0}}}`

func TestBuildRequestMappingCanonicalSnapshotAndNoCredentials(t *testing.T) {
	t.Parallel()
	for _, parameter := range []string{"max_tokens", "max_completion_tokens"} {
		t.Run(parameter, func(t *testing.T) {
			a := adapterForTest(t, func(config *Config) { config.MaxOutputParameter = parameter })
			value := input()
			value.Stream = true
			value.Temperature = float(0)
			value.TopP = float(1)
			value.Stop = []string{"END"}
			value.ResponseFormat = &domain.ResponseFormat{Type: "json_object"}
			value.ExtraAllowedParams = map[string]any{"frequency_penalty": 0.5}
			req, snapshot, err := a.BuildRequest(t.Context(), value)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatal(err)
			}
			_ = req.Body.Close()
			var payload map[string]any
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatal(err)
			}
			if req.URL.String() != "https://upstream.example.com/v1/chat/completions" || req.Header.Get("Accept") != "text/event-stream" || payload[parameter] != float64(64) || payload["stream_options"].(map[string]any)["include_usage"] != true {
				t.Fatal("request mapping failed")
			}
			other := "max_tokens"
			if parameter == other {
				other = "max_completion_tokens"
			}
			if _, found := payload[other]; found {
				t.Fatal("conflicting budget parameter emitted")
			}
			digest := sha256.Sum256(body)
			if snapshot.RequestHash != hex.EncodeToString(digest[:]) || !bytes.Equal(body, snapshot.Payload) {
				t.Fatal("snapshot is not the exact canonical wire JSON")
			}
			req.Header.Set("Authorization", "Bearer CANARY_CREDENTIAL")
			encoded, _ := json.Marshal(snapshot)
			if strings.Contains(string(encoded), "CANARY") || strings.Contains(string(encoded), "Authorization") {
				t.Fatal("snapshot retained credential headers")
			}
			value.Messages[0].Content = "changed"
			if strings.Contains(string(snapshot.Payload), "changed") {
				t.Fatal("snapshot aliases mutable input")
			}
		})
	}
}

func TestBuildRequestRejectsInvalidAndUnapprovedFields(t *testing.T) {
	t.Parallel()
	a := adapterForTest(t, nil)
	for name, mutate := range map[string]func(*domain.NormalizedRequest){
		"model":             func(value *domain.NormalizedRequest) { value.Model = "CANARY\r\n" },
		"no messages":       func(value *domain.NormalizedRequest) { value.Messages = nil },
		"bad role":          func(value *domain.NormalizedRequest) { value.Messages[0].Role = "tool" },
		"too many messages": func(value *domain.NormalizedRequest) { value.Messages = make([]domain.NormalizedMessage, 257) },
		"zero budget":       func(value *domain.NormalizedRequest) { value.MaxOutputTokens = 0 },
		"large budget":      func(value *domain.NormalizedRequest) { value.MaxOutputTokens = MaxOutputTokens + 1 },
		"NaN":               func(value *domain.NormalizedRequest) { value.Temperature = float(math.NaN()) },
		"Inf":               func(value *domain.NormalizedRequest) { value.TopP = float(math.Inf(1)) },
		"top_p":             func(value *domain.NormalizedRequest) { value.TopP = float(1.1) },
		"temperature":       func(value *domain.NormalizedRequest) { value.Temperature = float(-1) },
		"unknown extra":     func(value *domain.NormalizedRequest) { value.ExtraAllowedParams = map[string]any{"api_key": "CANARY"} },
		"reserved extra":    func(value *domain.NormalizedRequest) { value.ExtraAllowedParams = map[string]any{"messages": nil} },
		"bad extra type": func(value *domain.NormalizedRequest) {
			value.ExtraAllowedParams = map[string]any{"presence_penalty": "1"}
		},
		"extra range": func(value *domain.NormalizedRequest) {
			value.ExtraAllowedParams = map[string]any{"frequency_penalty": 3}
		},
		"extra nonfinite": func(value *domain.NormalizedRequest) {
			value.ExtraAllowedParams = map[string]any{"frequency_penalty": math.NaN()}
		},
		"invalid UTF8": func(value *domain.NormalizedRequest) { value.Messages[0].Content = string([]byte{0xff}) },
		"too much content": func(value *domain.NormalizedRequest) {
			value.Messages[0].Content = strings.Repeat("x", MaxRequestBytes+1)
		},
		"empty stop":         func(value *domain.NormalizedRequest) { value.Stop = []string{""} },
		"too many stops":     func(value *domain.NormalizedRequest) { value.Stop = []string{"a", "b", "c", "d", "e"} },
		"unsupported format": func(value *domain.NormalizedRequest) { value.ResponseFormat = &domain.ResponseFormat{Type: "audio"} },
	} {
		t.Run(name, func(t *testing.T) {
			value := input()
			mutate(&value)
			_, _, err := a.BuildRequest(t.Context(), value)
			if errorCode(err) != "MI_REQUEST_INVALID" || strings.Contains(err.Error(), "CANARY") {
				t.Fatalf("invalid input accepted or leaked: %v", err)
			}
		})
	}
}

func TestNonStreamStrictShapeAndUsage(t *testing.T) {
	t.Parallel()
	a := adapterForTest(t, nil)
	result, err := a.ParseNonStream(rawResponse(200, "application/json; charset=utf-8", goodNonStream))
	if err != nil || result.Content != "Hello 世界" || result.ParseStatus != "valid" || result.ChoiceCount != 1 || result.TotalTokens == nil || *result.TotalTokens != 5 || result.ReasoningTokens == nil || *result.ReasoningTokens != 0 {
		t.Fatalf("valid response failed: %v", err)
	}
	if result.RawResponseBytes != int64(len(goodNonStream)) || len(result.ResponseHash) != 64 {
		t.Fatal("response byte/hash metadata missing")
	}
	for _, body := range []string{
		`{"choices":[]}`, `{invalid CANARY_SECRET}`, goodNonStream + goodNonStream,
		strings.Replace(goodNonStream, `"index":0`, `"index":1`, 1), strings.Replace(goodNonStream, `"index":0,`, ``, 1),
		strings.Replace(goodNonStream, `"content":"Hello 世界"`, `"content":42`, 1),
		strings.Replace(goodNonStream, `"role":"assistant"`, `"role":"tool"`, 1),
		strings.Replace(goodNonStream, `"prompt_tokens":2`, `"prompt_tokens":-2`, 1),
		strings.Replace(goodNonStream, `"prompt_tokens":2`, `"prompt_tokens":1.2`, 1),
		strings.Replace(goodNonStream, `"prompt_tokens":2`, `"prompt_tokens":"2"`, 1),
		strings.Replace(goodNonStream, `"prompt_tokens":2`, `"prompt_tokens":2,"prompt_tokens":3`, 1),
		strings.Replace(goodNonStream, `"object":"chat.completion"`, `"object":"response"`, 1),
		strings.Replace(goodNonStream, `"Hello 世界"`, `"`+string([]byte{0xff})+`"`, 1),
	} {
		result, err := a.ParseNonStream(rawResponse(200, "application/json", body))
		if err == nil || result.ParseStatus != "invalid" || strings.Contains(err.Error(), "CANARY") {
			t.Fatalf("invalid protocol accepted/leaked: %v", err)
		}
	}
	for _, media := range []string{"text/html", "text/event-stream", "application/json; charset=latin1", "not a media type"} {
		if _, err := a.ParseNonStream(rawResponse(200, media, goodNonStream)); errorCode(err) != "MI_PROTOCOL_CONTENT_TYPE" {
			t.Errorf("wrong media type accepted: %v", err)
		}
	}
}

func TestMissingFinishUsageAndContradictionsRemainObservable(t *testing.T) {
	t.Parallel()
	a := adapterForTest(t, nil)
	missing := `{"model":"test-model","choices":[{"index":0,"message":{"role":"assistant","content":"bounded response"}}]}`
	result, err := a.ParseNonStream(rawResponse(200, "application/json", missing))
	if err != nil || result.CompletionTokens != nil || result.FinishReason != "" || !hasWarning(result, "USAGE_MISSING") || !hasWarning(result, "FINISH_REASON_MISSING") {
		t.Fatalf("missing evidence incorrectly synthesized or discarded: %v", err)
	}
	contradiction := strings.Replace(goodNonStream, `"total_tokens":5`, `"total_tokens":99`, 1)
	result, err = a.ParseNonStream(rawResponse(200, "application/json", contradiction))
	if err != nil || *result.TotalTokens != 99 || !hasWarning(result, "USAGE_TOTAL_MISMATCH") {
		t.Fatalf("usage contradiction lost: %v", err)
	}
	refusal := `{"model":"test-model","choices":[{"index":0,"message":{"role":"assistant","content":null,"refusal":"I cannot comply."},"finish_reason":"content_filter"}]}`
	result, err = a.ParseNonStream(rawResponse(200, "application/json", refusal))
	if err != nil || !result.Refusal || result.Content != "I cannot comply." || result.FinishReason != "content_filter" {
		t.Fatalf("refusal not normalized: %v", err)
	}
}

func hasWarning(result domain.NormalizedResponse, expected string) bool {
	for _, warning := range result.ParseWarnings {
		if warning == expected {
			return true
		}
	}
	return false
}

func TestHTTPStatusRetryAfterAndSensitiveErrors(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	a := adapterForTest(t, func(config *Config) { config.Now = func() time.Time { return now } })
	for _, test := range []struct {
		status    int
		code      string
		retryable bool
	}{
		{400, "MI_UPSTREAM_INVALID_PARAMETERS", false}, {401, "MI_UPSTREAM_AUTHENTICATION_FAILED", false}, {403, "MI_UPSTREAM_AUTHENTICATION_FAILED", false},
		{404, "MI_UPSTREAM_MODEL_NOT_FOUND", false}, {408, "MI_HTTP_TIMEOUT", true}, {409, "MI_UPSTREAM_CONFLICT", false}, {429, "MI_UPSTREAM_RATE_LIMITED", true},
		{500, "MI_UPSTREAM_UNAVAILABLE", true}, {502, "MI_UPSTREAM_UNAVAILABLE", true}, {503, "MI_UPSTREAM_UNAVAILABLE", true}, {504, "MI_UPSTREAM_UNAVAILABLE", true}, {501, "MI_UPSTREAM_HTTP_ERROR", false},
	} {
		t.Run(fmt.Sprint(test.status), func(t *testing.T) {
			response := rawResponse(test.status, "application/json", `{"error":{"message":"CANARY_SECRET Authorization: Bearer CANARY_SECRET https://example.com?key=CANARY_SECRET"}}`)
			response.Header.Set("Retry-After", "7")
			result, err := a.ParseNonStream(response)
			var normalized *Error
			if !errors.As(err, &normalized) || normalized.Code != test.code || normalized.Retryable != test.retryable || normalized.RetryAfter != 7*time.Second || result.Content != "" || result.ResponseHash != "" {
				t.Fatalf("HTTP failure normalization failed: %v", err)
			}
			encoded, _ := json.Marshal(result)
			if strings.Contains(string(encoded), "CANARY") || strings.Contains(fmt.Sprintf("%+v", err), "CANARY") {
				t.Fatal("upstream error body leaked")
			}
		})
	}
	for _, value := range []string{"-1", "999999999999999999999", "86401", "NaN", "7\r\nX-Key:CANARY", now.Add(-time.Second).Format(http.TimeFormat)} {
		if parseRetryAfter(value, now) != 0 {
			t.Errorf("unsafe retry-after accepted: %q", value)
		}
	}
	if parseRetryAfter(now.Add(30*time.Second).Format(http.TimeFormat), now) != 30*time.Second {
		t.Fatal("HTTP-date Retry-After failed")
	}
	if _, err := a.ParseNonStream(rawResponse(401, "application/json", strings.Repeat("x", 64*1024+1))); errorCode(err) != "CLIENT_SAFETY_LIMIT" {
		t.Fatal("error-body limit failed")
	}
}

func TestPrecheckOneExplicitFallbackAndSuccessfulCache(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var parameters []string
	a := adapterForTest(t, func(config *Config) {
		config.Doer = doerFunc(func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("Authorization") != "Bearer CANARY_KEY" {
				t.Error("scoped preparation did not run")
			}
			var body map[string]any
			_ = json.NewDecoder(req.Body).Decode(&body)
			_ = req.Body.Close()
			mu.Lock()
			defer mu.Unlock()
			if _, legacy := body["max_tokens"]; legacy {
				parameters = append(parameters, "max_tokens")
				return rawResponse(400, "application/json", `{"error":{"code":"unsupported_parameter","param":"max_tokens","message":"CANARY_KEY"}}`), nil
			}
			parameters = append(parameters, "max_completion_tokens")
			return rawResponse(200, "application/json", goodNonStream), nil
		})
	})
	prepare := func(req *http.Request) error { req.Header.Set("Authorization", "Bearer CANARY_KEY"); return nil }
	result, err := a.Precheck(t.Context(), input(), prepare)
	if err != nil || !result.Ready || result.Attempts != 2 || !result.FallbackUsed || result.MaxOutputParameter != "max_completion_tokens" {
		t.Fatalf("explicit fallback failed: %v", err)
	}
	_, snapshot, err := a.Call(t.Context(), input(), prepare, nil)
	if err != nil || snapshot.MaxOutputParameter != "max_completion_tokens" {
		t.Fatalf("successful capability result not cached: %v", err)
	}
	if strings.Join(parameters, ",") != "max_tokens,max_completion_tokens,max_completion_tokens" {
		t.Fatal("unexpected retry/mapping sequence")
	}
}

func TestPrecheckDoesNotRetryAuthGeneral400OrRepeatFailedFallback(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"auth", "general", "failed-fallback"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			a := adapterForTest(t, func(config *Config) {
				config.Doer = doerFunc(func(req *http.Request) (*http.Response, error) {
					_ = req.Body.Close()
					calls++
					switch mode {
					case "auth":
						return rawResponse(401, "application/json", `{"error":{"code":"unsupported_parameter","param":"max_tokens"}}`), nil
					case "general":
						return rawResponse(400, "application/json", `{"error":{"message":"CANARY unsupported"}}`), nil
					default:
						return rawResponse(400, "application/json", `{"error":{"code":"unsupported_parameter","param":"max_tokens"}}`), nil
					}
				})
			})
			_, _ = a.Precheck(t.Context(), input(), nil)
			_, _ = a.Precheck(t.Context(), input(), nil)
			want := 2
			if mode == "failed-fallback" {
				want = 3
			}
			if calls != want {
				t.Fatalf("unexpected precheck retries: %d", calls)
			}
		})
	}
}

func TestCallTransportAndCredentialPreparationErrorsAreNotRiskEvidence(t *testing.T) {
	t.Parallel()
	a := adapterForTest(t, func(config *Config) {
		config.Doer = doerFunc(func(req *http.Request) (*http.Response, error) {
			_ = req.Body.Close()
			return nil, safehttp.ErrBlockedAddress
		})
	})
	result, snapshot, err := a.Call(t.Context(), input(), nil, nil)
	if errorCode(err) != "MI_TARGET_BLOCKED_ADDRESS" || result.ParseStatus != "invalid" || result.EndCause != "blocked" || snapshot.RequestHash == "" {
		t.Fatalf("network policy failure misclassified: %v", err)
	}
	_, snapshot, err = a.Call(t.Context(), input(), func(*http.Request) error { return errors.New("CANARY_SECRET") }, nil)
	if errorCode(err) != "MI_AUTH_PREPARATION_FAILED" || strings.Contains(fmt.Sprintf("%+v", err), "CANARY") || strings.Contains(string(snapshot.Payload), "CANARY") {
		t.Fatal("credential callback error leaked")
	}
}

func TestAmbiguousErrorsNeverEnableCapabilityFallback(t *testing.T) {
	t.Parallel()
	for _, body := range []string{
		`{"error":{"code":"unsupported_parameter","param":"other","param":"max_tokens"}}`,
		`{"error":{"type":"invalid_request_error","message":"Unsupported unrelated parameter; max_tokens and max_completion_tokens are examples."}}`,
		`{"error":{"code":"unsupported_parameter","param":"max_completion_tokens"}}`,
	} {
		calls := 0
		a := adapterForTest(t, func(config *Config) {
			config.Doer = doerFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				_ = req.Body.Close()
				return rawResponse(400, "application/json", body), nil
			})
		})
		_, _ = a.Precheck(t.Context(), input(), nil)
		if calls != 1 {
			t.Fatal("ambiguous error enabled a billable fallback request")
		}
	}
}

func TestConcurrentPrechecksShareOneCapabilityFallback(t *testing.T) {
	t.Parallel()
	var legacyCalls, completionCalls atomic.Int32
	a := adapterForTest(t, func(config *Config) {
		config.Doer = doerFunc(func(req *http.Request) (*http.Response, error) {
			var body map[string]json.RawMessage
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				_ = req.Body.Close()
				return nil, err
			}
			_ = req.Body.Close()
			if _, exists := body["max_tokens"]; exists {
				legacyCalls.Add(1)
				return rawResponse(400, "application/json", `{"error":{"code":"unsupported_parameter","param":"max_tokens"}}`), nil
			}
			completionCalls.Add(1)
			return rawResponse(200, "application/json", goodNonStream), nil
		})
	})
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			result, err := a.Precheck(t.Context(), input(), nil)
			if err != nil || !result.Ready {
				t.Error("concurrent precheck failed")
			}
		}()
	}
	group.Wait()
	if legacyCalls.Load() != 1 || completionCalls.Load() != 8 {
		t.Fatal("concurrent prechecks duplicated the failed capability probe")
	}
}
