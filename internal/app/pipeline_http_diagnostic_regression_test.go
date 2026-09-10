package app

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPipelineHTTPDiagnosticClosedPhasesAndRedaction(t *testing.T) {
	for _, tc := range []struct {
		state pipelineHTTPDiagnosticState
		want  string
	}{
		{pipelineHTTPDiagnosticState{}, "before_transport"},
		{pipelineHTTPDiagnosticState{getConn: true}, "connection_acquisition"},
		{pipelineHTTPDiagnosticState{dnsStarted: true}, "dns"},
		{pipelineHTTPDiagnosticState{connectStarted: true}, "connect"},
		{pipelineHTTPDiagnosticState{tlsStarted: true}, "tls_handshake"},
		{pipelineHTTPDiagnosticState{gotConn: true}, "request_write"},
		{pipelineHTTPDiagnosticState{gotConn: true, wrote: true, writeFailed: true}, "request_write"},
		{pipelineHTTPDiagnosticState{wrote: true}, "awaiting_response_headers"},
		{pipelineHTTPDiagnosticState{firstByte: true}, "response_started"},
	} {
		if tc.state.phase() != tc.want {
			t.Fatal("diagnostic phase changed")
		}
	}
	d, trace := newPipelineHTTPDiagnostic()
	canary := "PRIVATE-HTTP-ADDRESS-COOKIE-ERROR-CANARY"
	trace.GetConn(canary)
	trace.ConnectStart(canary, canary)
	trace.ConnectDone(canary, canary, errors.New(canary))
	trace.DNSStart(httptrace.DNSStartInfo{Host: canary})
	trace.DNSDone(httptrace.DNSDoneInfo{Err: errors.New(canary)})
	trace.TLSHandshakeStart()
	trace.TLSHandshakeDone(tls.ConnectionState{ServerName: canary}, errors.New(canary))
	trace.GotConn(httptrace.GotConnInfo{Reused: true})
	trace.WroteRequest(httptrace.WroteRequestInfo{Err: errors.New(canary)})
	trace.GotFirstResponseByte()
	summary := d.summary()
	if strings.Contains(summary, canary) || len(summary) > 512 || !strings.Contains(summary, "connect_failed=true") || !strings.Contains(summary, "write_failed=true") {
		t.Fatal("trace emitted free-form data or lost closed error bits")
	}
	var stack pipelineStackObservation
	stack.observe("private-stack-function-" + canary)
	if stack != (pipelineStackObservation{}) {
		t.Fatal("unknown frame acquired a classification")
	}
	stack.observe("database/sql.(*DB).conn")
	stack.observe("model-integrity-inspector.local/mii/internal/integrity/api.(*control).getReport")
	if !stack.poolAcquire || !stack.reportHandler || stack.sqliteDriver {
		t.Fatal("closed stack identities differ")
	}
	if summary := observePipelineGoroutines().summary(); strings.Contains(summary, canary) || strings.Contains(summary, "goroutine ") || strings.Contains(summary, "0x") || len(summary) > 256 {
		t.Fatal("raw stack, function or PC escaped bounded observation")
	}
}

func pipelineDiagnosticAwait(t *testing.T, event <-chan struct{}) {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-event:
	case <-timer.C:
		t.Fatal("controlled HTTP diagnostic barrier not reached")
	}
}

// Real loopback HTTP blocks at a controlled handler barrier, then cancellation
// proves the observer distinguishes awaiting headers from a response-body wait.
// This tests the diagnostic, not a reproduction of the CI's five-second event.
func TestPipelineHTTPDiagnosticActualHeaderAndBodyWait(t *testing.T) {
	for _, responseStarted := range []bool{false, true} {
		t.Run(map[bool]string{false: "headers", true: "body"}[responseStarted], func(t *testing.T) {
			entered, wrote := make(chan struct{}), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if responseStarted {
					w.Header().Set("Content-Length", "2")
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
				}
				close(entered)
				<-r.Context().Done()
			}))
			defer server.Close()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			diagnostic, trace := newPipelineHTTPDiagnostic()
			original := trace.WroteRequest
			trace.WroteRequest = func(v httptrace.WroteRequestInfo) { original(v); close(wrote) }
			req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), "GET", server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			client := &http.Client{Timeout: 5 * time.Second}
			defer client.CloseIdleConnections()
			response := make(chan struct{})
			done, joined := make(chan error, 1), make(chan struct{})
			defer func() { cancel(); <-joined }()
			go func() {
				defer close(joined)
				res, err := client.Do(req)
				if err == nil {
					close(response)
					_, err = io.Copy(io.Discard, res.Body)
					_ = res.Body.Close()
				}
				done <- err
			}()
			pipelineDiagnosticAwait(t, entered)
			pipelineDiagnosticAwait(t, wrote)
			if responseStarted {
				pipelineDiagnosticAwait(t, response)
			}
			beforeCancel := diagnostic.snapshot()
			want := "awaiting_response_headers"
			if responseStarted {
				want = "response_started"
			}
			cancel()
			timer := time.NewTimer(2 * time.Second)
			defer timer.Stop()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("real controlled HTTP cancellation did not terminate wait")
				}
			case <-timer.C:
				t.Fatal("HTTP diagnostic client did not join")
			}
			if beforeCancel.phase() != want || !beforeCancel.gotConn || !beforeCancel.wrote || beforeCancel.firstByte != responseStarted {
				t.Fatal("actual transport wait was misclassified", diagnostic.summary())
			}
		})
	}
}

func TestPipelineHTTPDiagnosticSamplerStopsAndJoins(t *testing.T) {
	t.Run("fast_request_never_samples", func(t *testing.T) {
		var calls atomic.Int32
		stop := startPipelineSlowObservation(4*time.Second, func() { calls.Add(1) })
		stop()
		stop()
		if calls.Load() != 0 {
			t.Fatal("completed request triggered delayed observation")
		}
	})
	for _, mode := range []string{"during_callback", "callback_already_done"} {
		t.Run(mode, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var unblock sync.Once
			unblockSampler := func() { unblock.Do(func() { close(release) }) }
			var exited atomic.Bool
			stop := startPipelineSlowObservation(0, func() {
				defer exited.Store(true)
				close(entered)
				<-release
			})
			defer func() { unblockSampler(); stop() }()
			pipelineDiagnosticAwait(t, entered)
			if mode == "callback_already_done" {
				unblockSampler()
			}
			joining, joined := make(chan struct{}), make(chan struct{})
			go func() { close(joining); stop(); close(joined) }()
			defer func() { unblockSampler(); <-joined }()
			pipelineDiagnosticAwait(t, joining)
			if mode == "during_callback" {
				// Give the already-started cleanup goroutine an observation
				// window while the sampler is still held at its real barrier.
				// A nonblocking check here could pass before stop even runs.
				window := time.NewTimer(25 * time.Millisecond)
				select {
				case <-joined:
					window.Stop()
					t.Fatal("cleanup returned while sample callback was blocked")
				case <-window.C:
				}
			}
			unblockSampler()
			pipelineDiagnosticAwait(t, joined)
			stop()
			if !exited.Load() {
				t.Fatal("cleanup returned before sampler exit")
			}
		})
	}
}
