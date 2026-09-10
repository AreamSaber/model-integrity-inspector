package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/worker"
)

// Error formatting itself is forbidden, not merely checked for a known canary.
// The wrapper still supports ordinary errors.Is/errors.As inspection.
type diagnosticOpaqueError struct{ cause error }

func (diagnosticOpaqueError) Error() string   { panic("diagnostic formatted an opaque error") }
func (e diagnosticOpaqueError) Unwrap() error { return e.cause }

type diagnosticTimeout struct{}

func (diagnosticTimeout) Error() string   { panic("diagnostic formatted timeout details") }
func (diagnosticTimeout) Timeout() bool   { return true }
func (diagnosticTimeout) Temporary() bool { return false }

func TestApplicationDiagnosticErrorClassesAreClosed(t *testing.T) {
	for _, item := range []struct {
		class string
		err   error
	}{
		{"none", nil}, {"job_lease_lost", repository.ErrJobLeaseLost}, {"consumer_lost", repository.ErrConsumerLost}, {"consumer_active", repository.ErrConsumerActive},
		{"handler_unresponsive", worker.ErrHandlerUnresponsive}, {"database_unavailable", repository.ErrUnavailable}, {"cancelled", context.Canceled}, {"deadline_exceeded", context.DeadlineExceeded},
		{"job_cancelled", repository.ErrJobCancelled}, {"job_invalid", repository.ErrJobInvalid}, {"worker_already_running", worker.ErrAlreadyRunning}, {"configuration_invalid", worker.ErrConfiguration},
		{"configuration_invalid", repository.ErrConfiguration}, {"handler_failed", worker.ErrHandlerFailed}, {"listener_closed", http.ErrServerClosed}, {"listener_closed", net.ErrClosed},
		{"unknown", diagnosticOpaqueError{}}, {"job_lease_lost", errors.Join(context.Canceled, repository.ErrJobLeaseLost)}, {"consumer_lost", errors.Join(context.Canceled, repository.ErrConsumerLost)},
		{"handler_unresponsive", errors.Join(context.Canceled, worker.ErrHandlerUnresponsive)},
	} {
		t.Run(item.class, func(t *testing.T) {
			if got := applicationFailureClass(item.err); got != item.class {
				t.Fatal("incorrect direct error class", got)
			}
			if item.err != nil && applicationFailureClass(diagnosticOpaqueError{item.err}) != item.class {
				t.Fatal("wrapped error lost its fixed class")
			}
		})
	}
}

func TestApplicationDiagnosticLogsNeverFormatErrorsOrUnknownPhase(t *testing.T) {
	const canary = "synthetic-url-dsn-sql-body-key-do-not-log-9026"
	for _, phase := range []string{"listener_exit", "worker_exit", "http_shutdown", "worker_shutdown", "worker_shutdown_deadline", canary} {
		var output bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&output, nil))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := &url.Error{Op: canary, URL: "https://" + canary, Err: diagnosticOpaqueError{repository.ErrJobLeaseLost}}
		logApplicationFailure(ctx, logger, phase, err)
		var record map[string]any
		if json.Unmarshal(output.Bytes(), &record) != nil {
			t.Fatal("diagnostic output is not structured JSON")
		}
		want := phase
		if phase == canary {
			want = "unknown"
		}
		if record["phase"] != want || record["class"] != "job_lease_lost" || record["caller_done"] != true || record["msg"] != "application component stopped" || record["level"] != "ERROR" || len(record) != 6 {
			t.Fatal("diagnostic output is not the fixed closed projection")
		}
		if bytes.Contains(output.Bytes(), []byte(canary)) {
			t.Fatal("protected error or phase details entered diagnostics")
		}
	}
	logApplicationFailure(context.Background(), nil, "worker_exit", diagnosticOpaqueError{})
}

func TestApplicationDiagnosticPipelineHTTPErrorClasses(t *testing.T) {
	const canary = "synthetic-private-request-error-5621"
	for _, item := range []struct {
		class string
		err   error
	}{
		{"none", nil}, {"cancelled", context.Canceled}, {"deadline_exceeded", context.DeadlineExceeded}, {"unexpected_eof", io.ErrUnexpectedEOF}, {"eof", io.EOF}, {"connection_closed", net.ErrClosed},
		{"timeout", diagnosticTimeout{}}, {"network_dial", &net.OpError{Op: "dial", Net: canary, Err: diagnosticOpaqueError{}}},
		{"network_read", &net.OpError{Op: "read", Net: canary, Err: diagnosticOpaqueError{}}}, {"network_write", &net.OpError{Op: "write", Net: canary, Err: diagnosticOpaqueError{}}},
		{"network_other", &net.OpError{Op: canary, Net: canary, Err: diagnosticOpaqueError{}}}, {"unknown", diagnosticOpaqueError{}},
	} {
		t.Run(item.class, func(t *testing.T) {
			if pipelineHTTPErrorClass(item.err) != item.class {
				t.Fatal("incorrect safe HTTP error category")
			}
			if item.err != nil {
				wrapped := &url.Error{Op: canary, URL: "https://" + canary, Err: diagnosticOpaqueError{item.err}}
				if pipelineHTTPErrorClass(wrapped) != item.class {
					t.Fatal("wrapped HTTP error lost its safe category")
				}
			}
		})
	}
}

func TestApplicationDiagnosticPipelineBufferBoundAndConcurrency(t *testing.T) {
	buffer := &pipelineDiagnosticBuffer{}
	var writers sync.WaitGroup
	for range 8 {
		writers.Go(func() {
			payload := bytes.Repeat([]byte("x"), 8192)
			if n, err := buffer.Write(payload); n != len(payload) || err != nil {
				t.Error("bounded diagnostic sink changed writer semantics")
			}
			_, _ = buffer.snapshot()
		})
	}
	writers.Wait()
	text, truncated := buffer.snapshot()
	if len(text) != 32<<10 || !truncated {
		t.Fatal("diagnostic buffer is not bounded")
	}
	if n, err := buffer.Write([]byte("ignored")); n != 7 || err != nil {
		t.Fatal("full diagnostic buffer disrupted its producer")
	}
	other, _ := buffer.snapshot()
	if text != other {
		t.Fatal("full diagnostic buffer retained excess data")
	}
}

type diagnosticListener struct {
	failure error
	closed  chan struct{}
	once    sync.Once
}

func (l *diagnosticListener) Accept() (net.Conn, error) {
	if l.failure != nil {
		return nil, l.failure
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *diagnosticListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (*diagnosticListener) Addr() net.Addr { return &net.TCPAddr{} }

// The actual serve state machine runs with a synthetic listener and no store,
// worker or network. It proves logging does not convert failure to success or
// make an ordinary caller cancellation fail; real DB/Worker wiring is separate.
func TestApplicationDiagnosticServePreservesListenerFailureAndCancellation(t *testing.T) {
	for _, failing := range []bool{false, true} {
		var output bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&output, nil))
		listener := &diagnosticListener{closed: make(chan struct{})}
		ctx, cancel := context.WithCancel(context.Background())
		if failing {
			listener.failure = diagnosticOpaqueError{}
		} else {
			cancel()
		}
		app := &application{handler: http.NotFoundHandler()}
		cfg, err := LoadConfig("", noEnvironment)
		if err != nil {
			t.Fatal("test configuration unavailable")
		}
		err = app.serve(ctx, cfg, listener, logger)
		cancel()
		if failing != errors.Is(err, ErrStartup) || !failing && err != nil {
			t.Fatal("diagnostic change altered listener failure/cancellation semantics")
		}
		if failing && (!strings.Contains(output.String(), `"phase":"listener_exit"`) || !strings.Contains(output.String(), `"class":"unknown"`)) {
			t.Fatal("actual listener exit did not emit safe category")
		}
		if !failing && strings.Contains(output.String(), "application component stopped") {
			t.Fatal("ordinary shutdown logged as a component failure")
		}
	}
}

func TestApplicationDiagnosticLoggerWiredIntoTrustedWorkerConstruction(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "app.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	wired := 0
	ast.Inspect(file, func(node ast.Node) bool {
		literal, ok := node.(*ast.CompositeLit)
		if !ok {
			return true
		}
		typeName, ok := literal.Type.(*ast.SelectorExpr)
		if !ok || typeName.Sel.Name != "Config" {
			return true
		}
		packageName, ok := typeName.X.(*ast.Ident)
		if !ok || packageName.Name != "worker" {
			return true
		}
		for _, element := range literal.Elts {
			field, ok := element.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := field.Key.(*ast.Ident)
			value, valueOK := field.Value.(*ast.Ident)
			if ok && key.Name == "Logger" && valueOK && value.Name == "logger" {
				wired++
			}
		}
		return true
	})
	if wired != 1 {
		t.Fatal("actual worker construction silently lost its startup diagnostic sink")
	}
}
