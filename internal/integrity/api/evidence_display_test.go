package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
)

// A full admission pool must reject before any setup/session/store access. Nil
// dependencies make an accidental access observable, not a fake authorization.
func TestEvidenceDisplayAdmissionPrecedesDatabaseReads(t *testing.T) {
	c := &control{evidenceSlots: make(chan struct{}, 4)}
	for range 4 {
		c.evidenceSlots <- struct{}{}
	}
	called := false
	handler := c.middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	for _, method := range []string{"GET", "HEAD"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequestWithContext(t.Context(), method, "/api/v1/runs/1/samples/2/attempts/3/evidence?analysis_revision=1", nil)
		handler.ServeHTTP(w, r)
		if w.Code != 429 || w.Header().Get("Retry-After") != "2" || !strings.Contains(w.Body.String(), "MI_EVIDENCE_LIMIT") || called || len(c.evidenceSlots) != 4 {
			t.Fatal("admission did not reject before protected setup/session work")
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("admission error cache/security headers absent")
		}
	}
}

type displayDeadlineWriter struct {
	*httptest.ResponseRecorder
	deadline time.Time
	err      error
	writes   int
}

func (w *displayDeadlineWriter) SetWriteDeadline(deadline time.Time) error {
	w.deadline = deadline
	return w.err
}

func (w *displayDeadlineWriter) Write(value []byte) (int, error) {
	w.writes++
	return w.ResponseRecorder.Write(value)
}

func TestEvidenceDisplayHTTPWriterBoundsDeadlineBeforeFirstByte(t *testing.T) {
	for _, scenario := range []string{"ordinary", "original_shorter", "cancelled", "deadline_error"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			if scenario == "original_shorter" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 500*time.Millisecond)
				defer stop()
			}
			if scenario == "cancelled" {
				cancel()
			}
			w := &displayDeadlineWriter{ResponseRecorder: httptest.NewRecorder()}
			if scenario == "deadline_error" {
				w.err = errors.New("synthetic-private-transport-diagnostic")
			}
			r := httptest.NewRequestWithContext(ctx, "GET", "/", nil)
			sink := &evidenceHTTPWriter{writer: w, controller: http.NewResponseController(w), request: r}
			before := time.Now()
			n, err := sink.Write([]byte(`{"synthetic":"body"}`))
			if scenario == "cancelled" || scenario == "deadline_error" {
				if n != 0 || !errors.Is(err, runservice.ErrEvidenceUnavailable) || sink.started || w.writes != 0 {
					t.Fatal("failed deadline setup attempted an output byte")
				}
				return
			}
			original, _ := ctx.Deadline()
			if err != nil || n == 0 || !sink.started || w.writes != 1 || w.deadline.After(original) || w.deadline.After(time.Now().Add(2*time.Second)) || !w.deadline.After(before) {
				t.Fatal("bounded writer did not enforce deadline before first byte")
			}
			if scenario == "original_shorter" && w.deadline != original {
				t.Fatal("writer extended the original request deadline")
			}
		})
	}
}
