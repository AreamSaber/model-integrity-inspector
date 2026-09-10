package app

import (
	"crypto/tls"
	"fmt"
	"net/http/httptrace"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Test-only observations, never request/error/SQL bodies, addresses, headers,
// goroutine stack text or program counters. A missing stack frame (including
// truncation/inlining/platform differences) is unknown, not absence of a wait.
type pipelineHTTPDiagnostic struct {
	mu      sync.Mutex
	started time.Time
	state   pipelineHTTPDiagnosticState
	slow    pipelineSlowObservation
}

type pipelineSlowObservation struct {
	sampled bool
	elapsed time.Duration
	profile pipelineGoroutineObservation
}

type pipelineHTTPDiagnosticState struct {
	getConn, connectStarted, connectDone, connectFailed bool
	gotConn, reused, wrote, writeFailed, firstByte      bool
	dnsStarted, dnsDone, tlsStarted, tlsDone            bool
}

func newPipelineHTTPDiagnostic() (*pipelineHTTPDiagnostic, *httptrace.ClientTrace) {
	d := &pipelineHTTPDiagnostic{started: time.Now()}
	change := func(fn func(*pipelineHTTPDiagnosticState)) {
		d.mu.Lock()
		defer d.mu.Unlock()
		fn(&d.state)
	}
	return d, &httptrace.ClientTrace{
		GetConn: func(string) { change(func(s *pipelineHTTPDiagnosticState) { s.getConn = true }) },
		ConnectStart: func(string, string) {
			change(func(s *pipelineHTTPDiagnosticState) { s.connectStarted = true })
		},
		ConnectDone: func(_, _ string, err error) {
			change(func(s *pipelineHTTPDiagnosticState) { s.connectDone, s.connectFailed = true, err != nil })
		},
		GotConn: func(v httptrace.GotConnInfo) {
			change(func(s *pipelineHTTPDiagnosticState) { s.gotConn, s.reused = true, v.Reused })
		},
		WroteRequest: func(v httptrace.WroteRequestInfo) {
			change(func(s *pipelineHTTPDiagnosticState) { s.wrote, s.writeFailed = true, v.Err != nil })
		},
		GotFirstResponseByte: func() { change(func(s *pipelineHTTPDiagnosticState) { s.firstByte = true }) },
		DNSStart:             func(httptrace.DNSStartInfo) { change(func(s *pipelineHTTPDiagnosticState) { s.dnsStarted = true }) },
		DNSDone:              func(httptrace.DNSDoneInfo) { change(func(s *pipelineHTTPDiagnosticState) { s.dnsDone = true }) },
		TLSHandshakeStart:    func() { change(func(s *pipelineHTTPDiagnosticState) { s.tlsStarted = true }) },
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			change(func(s *pipelineHTTPDiagnosticState) { s.tlsDone = true })
		},
	}
}

func (d *pipelineHTTPDiagnostic) snapshot() pipelineHTTPDiagnosticState {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.state
}

func (s pipelineHTTPDiagnosticState) phase() string {
	switch {
	case s.firstByte:
		return "response_started"
	case s.wrote && !s.writeFailed:
		return "awaiting_response_headers"
	case s.gotConn:
		return "request_write"
	case s.tlsStarted && !s.tlsDone:
		return "tls_handshake"
	case s.connectStarted && !s.connectDone:
		return "connect"
	case s.dnsStarted && !s.dnsDone:
		return "dns"
	case s.getConn:
		return "connection_acquisition"
	default:
		return "before_transport"
	}
}

func (d *pipelineHTTPDiagnostic) summary() string {
	s := d.snapshot()
	return fmt.Sprintf("phase=%s elapsed_ms=%d get_conn=%t got_conn=%t reused=%t connect_started=%t connect_done=%t connect_failed=%t wrote_request=%t write_failed=%t first_response_byte=%t dns_started=%t dns_done=%t tls_started=%t tls_done=%t",
		s.phase(), time.Since(d.started).Milliseconds(), s.getConn, s.gotConn, s.reused, s.connectStarted, s.connectDone, s.connectFailed, s.wrote, s.writeFailed, s.firstByte, s.dnsStarted, s.dnsDone, s.tlsStarted, s.tlsDone)
}

func (d *pipelineHTTPDiagnostic) slowSummary() string {
	d.mu.Lock()
	s := d.slow
	d.mu.Unlock()
	return fmt.Sprintf("pre_cancel_sampled=%t observation_ms=%d %s", s.sampled, s.elapsed.Milliseconds(), s.profile.summary())
}

func (d *pipelineHTTPDiagnostic) startSlowObservation() func() {
	// The real fixture keeps its existing five-second Client.Timeout. Observe
	// once at four seconds, before cancellation can remove a blocked handler.
	return startPipelineSlowObservation(4*time.Second, func() {
		started := time.Now()
		profile := observePipelineGoroutines()
		observation := pipelineSlowObservation{sampled: true, elapsed: time.Since(started), profile: profile}
		d.mu.Lock()
		d.slow = observation
		d.mu.Unlock()
	})
}

// Stop and join on every exit, even if the callback has already started. The
// caller holds no diagnostic lock while joining; only the callback closes done
// once running. A second cleanup also joins completion, never consumes a result.
func startPipelineSlowObservation(delay time.Duration, sample func()) func() {
	done := make(chan struct{})
	timer := time.AfterFunc(delay, func() { defer close(done); sample() })
	var once sync.Once
	return func() {
		once.Do(func() {
			if timer.Stop() {
				close(done)
			}
		})
		<-done
	}
}

type pipelineStackObservation struct{ reportHandler, poolAcquire, sqliteDriver, worker bool }

// Only function identities compiled from these fixed packages affect counters.
// Names from runtime are consumed locally, never retained or formatted. The
// sqlite counter observes driver execution, not a proved SQLite lock wait.
func (s *pipelineStackObservation) observe(function string) {
	switch function {
	case "model-integrity-inspector.local/mii/internal/integrity/api.(*control).getReport":
		s.reportHandler = true
	case "database/sql.(*DB).conn":
		s.poolAcquire = true
	case "modernc.org/sqlite.(*conn).step", "modernc.org/sqlite.(*conn).exec", "modernc.org/sqlite.(*conn).query":
		s.sqliteDriver = true
	}
	if strings.HasPrefix(function, "model-integrity-inspector.local/mii/internal/integrity/worker.(*Runner).") {
		s.worker = true
	}
}

type pipelineGoroutineObservation struct {
	complete                                                                 bool
	observed, reportHandlers, reportPoolAcquire, reportSQLite, workerAcquire int
}

func observePipelineGoroutines() pipelineGoroutineObservation {
	// Fixed 128 KiB PC array; never retry with an allocation sized by runtime's
	// requested count and never publish a misleading partial profile.
	records := make([]runtime.StackRecord, 512)
	n, ok := runtime.GoroutineProfile(records)
	if !ok || n < 0 || n > len(records) {
		return pipelineGoroutineObservation{}
	}
	out := pipelineGoroutineObservation{complete: true, observed: n}
	for _, record := range records[:n] {
		frames := runtime.CallersFrames(record.Stack())
		var seen pipelineStackObservation
		for depth := 0; depth < 128; depth++ {
			frame, more := frames.Next()
			seen.observe(frame.Function)
			if !more {
				break
			}
			if depth == 127 {
				return pipelineGoroutineObservation{}
			}
		}
		if seen.reportHandler {
			out.reportHandlers++
			if seen.poolAcquire {
				out.reportPoolAcquire++
			}
			if seen.sqliteDriver {
				out.reportSQLite++
			}
		}
		if seen.worker && seen.poolAcquire {
			out.workerAcquire++
		}
	}
	return out
}

func (o pipelineGoroutineObservation) summary() string {
	return fmt.Sprintf("profile_complete=%t observed=%d report_handlers=%d report_pool_acquire=%d report_sqlite_driver=%d worker_pool_acquire=%d missing_frames=unknown",
		o.complete, o.observed, o.reportHandlers, o.reportPoolAcquire, o.reportSQLite, o.workerAcquire)
}
