package worker

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// AC-17's error-body path is deliberately tested through real TLS, dispatch,
// settlement and exact-AAD decryption, not by searching ciphertext for a key.
// This does not certify success-body redaction or hostile response headers;
// those require a separately authenticated display policy at collection time.
func TestRunWorkerUpstreamErrorBodiesNeverEnterEvidenceOrLogs(t *testing.T) {
	for _, scenario := range []struct {
		name        string
		status      int
		streams     []bool
		code        string
		streamEvent bool
		validPrefix bool
		malformed   bool
	}{
		{name: "http-400", status: 400, streams: []bool{false, true}, code: "MI_PROTOCOL_UNSUPPORTED"},
		{name: "http-401", status: 401, streams: []bool{false, true}, code: "MI_AUTH_FAILED"},
		{name: "http-200-error-object", status: 200, streams: []bool{false, true}, code: "MI_PROTOCOL_UNSUPPORTED"},
		{name: "http-200-malformed", status: 200, streams: []bool{false, true}, code: "MI_PROTOCOL_UNSUPPORTED", malformed: true},
		{name: "sse-error-event", status: 200, streams: []bool{true}, code: "MI_PROTOCOL_UNSUPPORTED", streamEvent: true},
		{name: "sse-error-after-content", status: 200, streams: []bool{true}, code: "MI_PROTOCOL_UNSUPPORTED", streamEvent: true, validPrefix: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			eachRunDatabase(t, func(t *testing.T, f runFixture) {
				var calls atomic.Int64
				var invalidRequest atomic.Bool
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					var request struct {
						Stream bool `json:"stream"`
					}
					if r.Header.Get("Authorization") != "Bearer "+workerCanary || json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&request) != nil {
						invalidRequest.Store(true)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					media := "application/json"
					if request.Stream && scenario.status == http.StatusOK {
						media = "text/event-stream"
					}
					w.Header().Set("Content-Type", media)
					w.WriteHeader(scenario.status)
					// All free-text fields intentionally echo the actual synthetic
					// outbound credential; error parsing must retain none of them.
					body := `{"error":{"message":"` + workerCanary + `","code":"` + workerCanary + `","type":"` + workerCanary + `","param":"` + workerCanary + `"},"id":"` + workerCanary + `","model":"` + workerCanary + `"}`
					if scenario.malformed {
						body = `{"invalid":"` + workerCanary + `"`
					}
					if request.Stream && scenario.status == http.StatusOK {
						if scenario.validPrefix {
							_, _ = io.WriteString(w, "data: {\"id\":\"synthetic-safe-id\",\"object\":\"chat.completion.chunk\",\"model\":\"synthetic-safe-model\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"safe-prefix\"}}]}\n\n")
						}
						if scenario.streamEvent {
							_, _ = io.WriteString(w, "event: error\n")
						}
						_, _ = io.WriteString(w, "data: "+body+"\n\n")
						return
					}
					_, _ = io.WriteString(w, body)
				})
				tenant, run, samples := f.createRun(t, scenario.streams)
				var logs executionLogBuffer
				// Registered before the Runner cleanup, so the final scan executes
				// after its goroutine has stopped and includes shutdown diagnostics.
				t.Cleanup(func() {
					if strings.Contains(logs.String(), workerCanary) {
						t.Error("upstream error credential leaked to complete Worker logs")
					}
				})
				_, cancel := startRunWorker(t, f, runTLSConfig(t, f, handler), &logs)
				finished := awaitRunClosed(t, tenant, run.ID)
				if invalidRequest.Load() || calls.Load() != int64(len(samples)) || finished.RequestCount != int64(len(samples)) || finished.ValidSampleCount != 0 || finished.ReservedTokens != 0 {
					t.Fatal("error-body fixture did not execute and settle the actual planned requests")
				}
				for _, sample := range samples {
					attempt, response := evidenceFor(t, f, tenant, sample)
					if attempt.Status != "COMPLETED" || attempt.Validity != "INVALID_PROTOCOL" || attempt.ErrorCode == nil || *attempt.ErrorCode != scenario.code || response.HTTPStatus != scenario.status || response.ParseStatus == "valid" || response.RawResponseBytes <= 0 {
						t.Fatal("upstream error was disguised as a successful response")
					}
					wantContent := ""
					if scenario.validPrefix {
						wantContent = "safe-prefix"
					}
					if response.Content != wantContent {
						t.Fatal("error text retained or preceding valid stream content changed")
					}
					encoded, err := json.Marshal(response)
					if err != nil || strings.Contains(string(encoded), workerCanary) {
						t.Fatal("upstream error credential persisted inside decrypted response evidence")
					}
					var redacted, metadata string
					if err := f.db.QueryRowContext(f.ctx, "SELECT COALESCE(response_content_redacted,''),response_meta FROM integrity_sample_attempts WHERE organization_id=$1 AND id=$2", f.orgID, attempt.ID).Scan(&redacted, &metadata); err != nil {
						t.Fatal("attempt metadata read failed")
					}
					for _, value := range []string{redacted, metadata, attempt.RequestSnapshot, *attempt.ErrorCode} {
						if strings.Contains(value, workerCanary) {
							t.Fatal("upstream error credential leaked to persisted attempt fields")
						}
					}
				}
				cancel()
				if strings.Contains(logs.String(), workerCanary) {
					t.Fatal("upstream error credential leaked to Worker logs")
				}
			})
		})
	}
}
