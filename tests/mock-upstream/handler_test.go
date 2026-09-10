package mockupstream

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type completion struct {
	Model   string `json:"model"`
	Choices []struct {
		Message Message `json:"message"`
		Finish  string  `json:"finish_reason"`
	} `json:"choices"`
	Usage *struct {
		Prompt     int `json:"prompt_tokens"`
		Completion int `json:"completion_tokens"`
		Total      int `json:"total_tokens"`
		Details    struct {
			Reasoning int `json:"reasoning_tokens"`
		} `json:"completion_tokens_details"`
	} `json:"usage"`
}

func mustHandler(t *testing.T, config Config) *Handler {
	t.Helper()
	handler, err := NewHandler(config)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func requestBody(tokens int, stream bool) []byte {
	encoded, _ := json.Marshal(map[string]any{
		"model": "test-model", "messages": []Message{{Role: "user", Content: "Generate a numbered sequence"}},
		"max_tokens": tokens, "stream": stream, "stream_options": map[string]bool{"include_usage": true},
	})
	return encoded
}

func call(handler http.Handler, body []byte) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/chat/completions", bytes.NewReader(body)))
	return response
}

func decodeCompletion(t *testing.T, response *httptest.ResponseRecorder) completion {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("status %d: %s", response.Code, response.Body.String())
	}
	var result completion
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestNormalAndCaps(t *testing.T) {
	for _, tc := range []struct {
		name         string
		config       Config
		budget, want int
		applied      bool
	}{
		{"normal", Config{}, 128, 128, false},
		{"fixed", Config{OverrideMaxTokens: 64, OverrideProbability: 1}, 256, 64, true},
		{"not_above_budget", Config{OverrideMaxTokens: 128, OverrideProbability: 1}, 64, 64, false},
		{"zero_probability", Config{OverrideMaxTokens: 64}, 256, 256, false},
		{"piecewise_low", Config{CapSteps: []CapStep{{128, 64}, {512, 256}}, OverrideProbability: 1}, 256, 64, true},
		{"piecewise_high", Config{CapSteps: []CapStep{{128, 64}, {512, 256}}, OverrideProbability: 1}, 1024, 256, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := mustHandler(t, tc.config)
			result := decodeCompletion(t, call(handler, requestBody(tc.budget, false)))
			if result.Usage.Completion != tc.want || len(strings.Fields(result.Choices[0].Message.Content)) != tc.want {
				t.Fatalf("unexpected output: %+v", result)
			}
			record := handler.Records()[0]
			if record.OverrideApplied != tc.applied || record.RequestedTokens != tc.budget || record.GeneratedTokens != tc.want {
				t.Fatalf("incorrect controller evidence: %+v", record)
			}
		})
	}
}

func TestProbabilityReplayAndBoundedRecords(t *testing.T) {
	config := Config{Seed: 901, OverrideMaxTokens: 16, OverrideProbability: 0.5, MaxRecords: 100}
	a, b := mustHandler(t, config), mustHandler(t, config)
	count := 0
	for range 100 {
		body := requestBody(64, false)
		if call(a, body).Body.String() != call(b, body).Body.String() {
			t.Fatal("same sequential seed/request replay drifted")
		}
	}
	for _, record := range a.Records() {
		if record.OverrideApplied {
			count++
		}
	}
	if count < 20 || count > 80 {
		t.Fatalf("probability did not generate both conditions: %d", count)
	}
	snapshot := a.Records()
	snapshot[0].Request.Messages[0].Content = "modified"
	snapshot[0].ReceivedParameters["model"] = json.RawMessage(`"changed"`)
	if reflect.DeepEqual(a.Records()[0], snapshot[0]) {
		t.Fatal("controller snapshots share mutable state")
	}
	call(a, requestBody(64, false))
	if records := a.Records(); len(records) != 100 || records[0].Ordinal != 2 || records[99].Ordinal != 101 {
		t.Fatal("record ring is not bounded")
	}
}

func TestBehaviorAndHardNegatives(t *testing.T) {
	for _, tc := range []struct {
		config   Config
		contains string
		finish   string
	}{
		{Config{InjectInstruction: "fixed_prefix", Prefix: "NOTICE ", Suffix: " FOOTER"}, "NOTICE item000001", "length"},
		{Config{InjectInstruction: "forced_identity"}, "As the Acme assistant", "length"},
		{Config{InjectInstruction: "neutral_refusal"}, "cannot help", "stop"},
		{Config{NaturalEarlyEOS: true}, "answer is four.", "stop"},
		{Config{SafetyRefusal: true}, "cannot help", "stop"},
	} {
		result := decodeCompletion(t, call(mustHandler(t, tc.config), requestBody(64, false)))
		if !strings.Contains(result.Choices[0].Message.Content, tc.contains) || result.Choices[0].Finish != tc.finish {
			t.Fatalf("unexpected behavior: %+v", result)
		}
	}
}

func TestUsageFinishAndAlias(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want int
	}{{"honest", 100}, {"inflated", 130}, {"deflated", 50}} {
		result := decodeCompletion(t, call(mustHandler(t, Config{UsageMode: tc.mode, FinishReasonMode: "always_stop", ModelAlias: "alias"}), requestBody(100, false)))
		if result.Usage.Completion != tc.want || result.Usage.Total != result.Usage.Prompt+tc.want || result.Choices[0].Finish != "stop" || result.Model != "alias" {
			t.Fatalf("unexpected usage/finish/model: %+v", result)
		}
	}
	missing := decodeCompletion(t, call(mustHandler(t, Config{UsageMode: "missing", FinishReasonMode: "missing"}), requestBody(64, false)))
	if missing.Usage != nil || missing.Choices[0].Finish != "" {
		t.Fatal("missing fields were populated")
	}
	reasoning := decodeCompletion(t, call(mustHandler(t, Config{ReasoningTokens: 20}), requestBody(64, false)))
	if reasoning.Usage.Completion != 84 || reasoning.Usage.Details.Reasoning != 20 {
		t.Fatal("reasoning token fixture missing")
	}
}

func TestSSEModes(t *testing.T) {
	for _, mode := range []string{"normal", "truncate", "omit_done", "malformed_event"} {
		t.Run(mode, func(t *testing.T) {
			handler := mustHandler(t, Config{StreamMode: mode, StreamCutoffTokens: 10})
			response := call(handler, requestBody(64, true))
			body := response.Body.String()
			if response.Header().Get("Content-Type") != "text/event-stream" {
				t.Fatal("wrong SSE content type")
			}
			if strings.Contains(body, "[DONE]") != (mode == "normal") {
				t.Fatal("incorrect termination marker")
			}
			if handler.Records()[0].StreamTerminated != (mode == "normal") {
				t.Fatal("incorrect controller termination")
			}
			if mode == "truncate" && (strings.Contains(body, `"finish_reason":"length"`) || strings.Contains(body, `"usage"`)) {
				t.Fatal("cutoff stream included final metadata")
			}
			if mode == "malformed_event" && !strings.Contains(body, "{invalid-json") {
				t.Fatal("malformed fixture absent")
			}
			if mode == "normal" && !strings.Contains(body, `"completion_tokens":64`) {
				t.Fatal("include_usage was ignored")
			}
			// Streaming-only faults must leave the non-streaming comparison intact.
			nonstream := decodeCompletion(t, call(handler, requestBody(64, false)))
			if nonstream.Usage.Completion != 64 {
				t.Fatal("stream-only fault affected JSON response")
			}
		})
	}
}

func TestCustomResponderUnicode(t *testing.T) {
	handler := mustHandler(t, Config{Responder: func(_ Request, _ int) (Generation, error) {
		return Generation{Tokens: []string{"你好", "🌍", "！"}, PromptTokens: 3, FinishReason: "stop"}, nil
	}})
	response := call(handler, requestBody(64, true))
	if !strings.Contains(response.Body.String(), "你好🌍！") {
		t.Fatal("UTF-8 fixture corrupted")
	}
}

func TestBehaviorControlsComposeWithCustomResponder(t *testing.T) {
	for _, tc := range []struct {
		config Config
		want   string
		tokens int
	}{
		{Config{InjectInstruction: "neutral_refusal"}, "I cannot help with that request.", 6},
		{Config{SafetyRefusal: true}, "I cannot help with that request.", 6},
		{Config{NaturalEarlyEOS: true}, "The answer is four.", 4},
	} {
		tc.config.Responder = func(_ Request, _ int) (Generation, error) {
			return Generation{Tokens: []string{"fixture would otherwise succeed"}, PromptTokens: 7, FinishReason: "length"}, nil
		}
		handler := mustHandler(t, tc.config)
		result := decodeCompletion(t, call(handler, requestBody(64, false)))
		if result.Choices[0].Message.Content != tc.want || result.Choices[0].Finish != "stop" || result.Usage.Completion != tc.tokens || result.Usage.Prompt != 7 {
			t.Fatalf("custom responder bypassed behavioral control: %+v", result)
		}
		stream := call(handler, requestBody(64, true))
		if strings.Contains(stream.Body.String(), "fixture would") || !strings.Contains(stream.Body.String(), "[DONE]") {
			t.Fatal("stream fixture bypassed behavioral control")
		}
	}
}

func TestHTTPAnomaliesAndAuthentication(t *testing.T) {
	for _, status := range []int{400, 401, 404, 429, 500, 503} {
		handler := mustHandler(t, Config{HTTPErrorRate: 1, HTTPErrorStatus: status, RetryAfterSeconds: 2})
		response := call(handler, requestBody(64, false))
		if response.Code != status {
			t.Fatalf("wanted %d, got %d", status, response.Code)
		}
		if (status == 429 || status == 503) && response.Header().Get("Retry-After") != "2" {
			t.Fatal("Retry-After missing")
		}
	}
	handler := mustHandler(t, Config{RequiredAPIKey: "synthetic-canary-not-a-real-key"})
	if call(handler, requestBody(64, false)).Code != 401 {
		t.Fatal("authentication not enforced")
	}
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", bytes.NewReader(requestBody(64, false)))
	request.Header.Set("Authorization", "Bearer synthetic-canary-not-a-real-key")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 200 {
		t.Fatal("correct test credential rejected")
	}
	records, _ := json.Marshal(handler.Records())
	if strings.Contains(string(records), "synthetic-canary") || strings.Contains(response.Body.String(), "synthetic-canary") {
		t.Fatal("credential leaked")
	}
}

func TestActualTransportDrop(t *testing.T) {
	server := httptest.NewServer(mustHandler(t, Config{NetworkErrorRate: 1}))
	defer server.Close()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/v1/chat/completions", bytes.NewReader(requestBody(64, false)))
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(request)
	if response != nil {
		_ = response.Body.Close()
	}
	if err == nil {
		t.Fatal("expected real transport EOF")
	}
}

func TestDelayHonorsCancellation(t *testing.T) {
	handler := mustHandler(t, Config{Delay: time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/chat/completions", bytes.NewReader(requestBody(64, false)))
	started := time.Now()
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if time.Since(started) > 200*time.Millisecond {
		t.Fatal("delay ignored cancellation")
	}
}

func TestRejectInvalidAndOversizedRequests(t *testing.T) {
	handler := mustHandler(t, Config{})
	for _, body := range [][]byte{[]byte(`{`), []byte(`null`), requestBody(0, false), requestBody(MaxOutputTokens+1, false), []byte(`{"model":"m","messages":[{"role":"user","content":"x"}],"max_tokens":1,"max_completion_tokens":1}`)} {
		if call(handler, body).Code != 400 {
			t.Fatalf("accepted %s", body)
		}
	}
	if call(handler, bytes.Repeat([]byte("a"), MaxRequestBytes+1)).Code != 413 {
		t.Fatal("request size bound missing")
	}
	for _, path := range []string{"/config", "/records", "/labels", "/scenario"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))
		if response.Code != 404 {
			t.Fatal("controller data accessible through HTTP")
		}
	}
}

func TestConfigurationBounds(t *testing.T) {
	for _, config := range []Config{
		{OverrideProbability: math.NaN()}, {HTTPErrorRate: -0.1}, {NetworkErrorRate: 2},
		{OverrideMaxTokens: MaxOutputTokens + 1}, {CapSteps: []CapStep{{128, 64}, {64, 32}}},
		{StreamMode: "arbitrary"}, {InjectInstruction: "unknown"}, {UsageMode: "bad"},
		{StreamMode: "normal|truncate"}, {UsageMode: "inflated", UsageFactor: 0.5}, {UsageMode: "deflated", UsageFactor: 2},
		{UsageFactor: math.Inf(1)}, {HTTPErrorStatus: 200}, {Delay: time.Hour}, {MaxRecords: 10001},
	} {
		if _, err := NewHandler(config); err == nil {
			t.Fatalf("accepted %+v", config)
		}
	}
}

func TestConcurrentRequests(t *testing.T) {
	handler := mustHandler(t, Config{MaxRecords: 100})
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() { response := call(handler, requestBody(64, false)); _, _ = io.Copy(io.Discard, response.Body) })
	}
	wg.Wait()
	seen := map[uint64]bool{}
	for _, record := range handler.Records() {
		if seen[record.Ordinal] {
			t.Fatal("duplicate ordinal")
		}
		seen[record.Ordinal] = true
	}
	if len(seen) != 50 {
		t.Fatal("lost records")
	}
}

func TestScenarioFilesAndOutputAliases(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("scenarios", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 11 {
		t.Fatal("required development scenarios missing")
	}
	scenarioRoot, err := os.OpenRoot("scenarios")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = scenarioRoot.Close() }()
	for _, path := range files {
		encoded, err := scenarioRoot.ReadFile(filepath.Base(path))
		if err != nil {
			t.Fatal(err)
		}
		var config Config
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if _, err := NewHandler(config); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	handler := mustHandler(t, Config{})
	alias := bytes.Replace(requestBody(64, false), []byte("max_tokens"), []byte("max_completion_tokens"), 1)
	result := decodeCompletion(t, call(handler, alias))
	if result.Usage.Completion != 64 {
		t.Fatal("completion budget alias not honored")
	}
	record := handler.Records()[0]
	if record.Request.MaxCompletionTokens == nil || record.ReceivedParameters["max_completion_tokens"] == nil || record.ReceivedParameters["max_tokens"] != nil {
		t.Fatal("original budget parameter was not retained")
	}
}
