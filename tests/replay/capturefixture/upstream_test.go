// Package capturefixture is a separate DEVELOPMENT controller. Its mock
// configuration and known interventions are never imported by the offline core.
package capturefixture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	bpe "github.com/tiktoken-go/tokenizer"
	"model-integrity-inspector.local/mii/internal/integrity/adapter/openaichat"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
	mockupstream "model-integrity-inspector.local/mii/tests/mock-upstream"
	"model-integrity-inspector.local/mii/tests/replay"
)

var errCapture = errors.New("DEVELOPMENT_CAPTURE_FAILED")

func hash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

type exchange struct {
	wire, body []byte
	headers    []replay.Header
	status     int
}
type recorder struct {
	mu            sync.Mutex
	active        bool
	failed        bool
	precheck, run http.Handler
	expected      map[string]mockupstream.Generation
	records       map[string]exchange
}

func newRecorder(t *testing.T, credential string, omitDone bool) *recorder {
	t.Helper()
	r := &recorder{expected: map[string]mockupstream.Generation{}, records: map[string]exchange{}}
	responder := func(request mockupstream.Request, _ int) (mockupstream.Generation, error) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if !r.active {
			return mockupstream.Generation{Tokens: []string{"OK"}, PromptTokens: 1, FinishReason: "stop"}, nil
		}
		data, err := json.Marshal(request)
		if err != nil {
			return mockupstream.Generation{}, errCapture
		}
		generation, found := r.expected[hash(data)]
		if !found {
			r.failed = true
			return mockupstream.Generation{}, errCapture
		}
		generation.Tokens = slices.Clone(generation.Tokens)
		return generation, nil
	}
	precheck, err := mockupstream.NewHandler(mockupstream.Config{RequiredAPIKey: credential, Responder: responder})
	if err != nil {
		t.Fatal(err)
	}
	mode := "normal"
	if omitDone {
		mode = "omit_done"
	}
	run, err := mockupstream.NewHandler(mockupstream.Config{RequiredAPIKey: credential, Responder: responder, StreamMode: mode, StreamChunkTokens: 32})
	if err != nil {
		t.Fatal(err)
	}
	r.precheck, r.run = precheck, run
	return r
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	r.mu.Lock()
	active := r.active
	r.mu.Unlock()
	if !active {
		r.precheck.ServeHTTP(w, request)
		return
	}
	wire, err := io.ReadAll(io.LimitReader(request.Body, openaichat.MaxRequestBytes+1))
	if err != nil || len(wire) > openaichat.MaxRequestBytes {
		r.mu.Lock()
		r.failed = true
		r.mu.Unlock()
		http.Error(w, "capture unavailable", http.StatusBadRequest)
		return
	}
	request.Body = io.NopCloser(bytes.NewReader(wire))
	response := &recordingWriter{ResponseWriter: w}
	r.run.ServeHTTP(response, request)
	r.mu.Lock()
	defer r.mu.Unlock()
	key := hash(wire)
	if _, exists := r.records[key]; exists || response.failed {
		r.failed = true
		return
	}
	r.records[key] = exchange{wire: bytes.Clone(wire), body: bytes.Clone(response.body), headers: response.headers, status: response.status}
}

// Preserve actual Write/Flush calls and entity bytes; do not claim these are
// client Read boundaries or TLS packets. No auth headers are retained.
type recordingWriter struct {
	http.ResponseWriter
	status  int
	body    []byte
	headers []replay.Header
	failed  bool
}

func (w *recordingWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	for _, name := range []string{"Content-Type", "Retry-After", "X-Request-Id", "Request-Id", "Openai-Processing-Ms"} {
		if values := w.Header().Values(name); len(values) > 0 {
			w.headers = append(w.headers, replay.Header{Name: name, Values: slices.Clone(values)})
		}
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *recordingWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if len(w.body)+len(data) > replay.MaxBodyBytes {
		w.failed = true
		return 0, errCapture
	}
	n, err := w.ResponseWriter.Write(data)
	w.body = append(w.body, data[:n]...)
	if err != nil {
		w.failed = true
	}
	return n, err
}
func (w *recordingWriter) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	} else {
		w.failed = true
	}
}

func (r *recorder) prepare(t *testing.T, manifest generator.Manifest, plan domain.ExecutionPlan, tokens *tokenizer.Engine) {
	t.Helper()
	codec, err := bpe.Get(bpe.O200kBase)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := openaichat.New(openaichat.Config{Endpoint: "https://controller.invalid/v1", MaxOutputParameter: plan.Target.MaxOutputParameter, Doer: noDial{}})
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]mockupstream.Generation{}
	for i, sample := range manifest.Samples {
		content := sample.Variables.Nonce
		if sample.Family == "sequence" {
			content = ""
			// A 24-character hex nonce can tokenize differently on every Run.
			// Two complete rows occupy only 54 ASCII bytes and always fit the
			// smallest 64-token fixture tier; three rows occasionally exceeded
			// that real request budget. Keep the exact tokenizer check below.
			for n := 1; n <= 2; n++ {
				content += sample.Variables.Nonce + "|" + strconv.Itoa(n) + "\n"
			}
		}
		if sample.Family == "format" && sample.Variant == 3 {
			content = `{"` + sample.Variables.Label + `":"` + sample.Variables.Nonce + `"}`
		}
		ids, pieces, err := codec.Encode(content)
		if err != nil {
			t.Fatal(err)
		}
		local, err := tokens.CountOutput(content, tokenizer.Selection{RequestedModel: plan.Target.Model})
		if err != nil || local.Quality != tokenizer.Exact || local.Tokens == nil || *local.Tokens != int64(len(ids)) || len(ids) != len(pieces) || strings.Join(pieces, "") != content || len(ids) > sample.MaxOutputTokens {
			t.Fatal("controlled exact tokenizer generation mismatch")
		}
		_, snapshot, err := adapter.BuildRequest(t.Context(), plan.Probes[i].Samples[0].Request)
		if err != nil {
			t.Fatal(err)
		}
		var request mockupstream.Request
		if json.Unmarshal(snapshot.Payload, &request) != nil {
			t.Fatal("controlled request decode")
		}
		keyBytes, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		key := hash(keyBytes)
		if _, exists := expected[key]; exists {
			t.Fatal("ambiguous controlled request identity")
		}
		expected[key] = mockupstream.Generation{Tokens: pieces, PromptTokens: 10, FinishReason: "stop"}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expected = expected
	r.active = true
}

type noDial struct{}

func (noDial) Do(*http.Request) (*http.Response, error) { return nil, errCapture }

func (r *recorder) snapshot() (map[string]exchange, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed {
		return nil, errCapture
	}
	result := make(map[string]exchange, len(r.records))
	for key, value := range r.records {
		value.wire = bytes.Clone(value.wire)
		value.body = bytes.Clone(value.body)
		result[key] = value
	}
	return result, nil
}
