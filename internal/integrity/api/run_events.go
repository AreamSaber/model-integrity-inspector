package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"model-integrity-inspector.local/mii/internal/identity"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
)

const runEventMaxBytes = 64 << 10

// Limits are per API handler/process. They are not a replacement for an ingress
// connection limit across replicas. A stream has no history-reading authority.
type runEvents struct {
	control                              *control
	mu                                   sync.Mutex
	users                                map[int64]int
	connections                          int
	poll, heartbeat, lifetime, operation time.Duration
	globalLimit, userLimit               int
}

func newRunEvents(c *control) *runEvents {
	return &runEvents{control: c, users: make(map[int64]int), poll: 2 * time.Second, heartbeat: 10 * time.Second,
		lifetime: 5 * time.Minute, operation: time.Second, globalLimit: 64, userLimit: 4}
}

func (c *control) registerRunEventRoutes(mux *http.ServeMux) {
	events := newRunEvents(c)
	mux.HandleFunc("GET /api/v1/runs/{id}/events", events.serve)
}

func (events *runEvents) acquire(user int64) bool {
	events.mu.Lock()
	defer events.mu.Unlock()
	if events.connections >= events.globalLimit || events.users[user] >= events.userLimit {
		return false
	}
	events.connections++
	events.users[user]++
	return true
}

func (events *runEvents) release(user int64) {
	events.mu.Lock()
	defer events.mu.Unlock()
	events.connections--
	events.users[user]--
	if events.users[user] == 0 {
		delete(events.users, user)
	}
}

func runEventCursor(r *http.Request, id int64) bool {
	values := r.Header.Values("Last-Event-ID")
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 || len(values[0]) > 128 {
		return false
	}
	parts := strings.Split(values[0], ":")
	if len(parts) != 2 || parts[0] != strconv.FormatInt(id, 10) {
		return false
	}
	version, err := strconv.ParseInt(parts[1], 10, 64)
	return err == nil && version > 0 && strconv.FormatInt(version, 10) == parts[1]
}

// Each periodic read obtains fresh persisted session/user/member grants, not
// merely the permission cached at the HTTP handshake. The same deadline bounds
// authorization and all database reads in that iteration.
func (events *runEvents) authorize(ctx context.Context, r *http.Request, org int64) (context.Context, int64, error) {
	c := events.control
	principal, err := c.cfg.Identity.Principal(ctx, token(r), org)
	if err != nil {
		return nil, 0, err
	}
	if err := principal.Authorize("run.read"); err != nil {
		return nil, 0, err
	}
	actor, err := audit.ActorFromContext(ctx)
	if err != nil {
		return nil, 0, err
	}
	actor.ActorID = principal.UserID
	bound, err := c.cfg.Store.BindControlAuthority(audit.WithActor(ctx, actor), digest(token(r)), org)
	return bound, principal.UserID, err
}

func runEventError(err error) (int, string) {
	switch {
	case errors.Is(err, identity.ErrSession), errors.Is(err, repository.ErrManagementSession):
		return 401, "MI_SESSION_REQUIRED"
	case errors.Is(err, identity.ErrPasswordChangeRequired), errors.Is(err, repository.ErrPasswordChangeRequired):
		return 403, "MI_PASSWORD_CHANGE_REQUIRED"
	case errors.Is(err, identity.ErrPermission), errors.Is(err, repository.ErrManagementPermission):
		return 403, "MI_PERMISSION_DENIED"
	case errors.Is(err, repository.ErrNotFound):
		return 404, "MI_NOT_FOUND"
	default:
		return 503, "MI_SERVICE_UNAVAILABLE"
	}
}

func runEventTerminal(status string) bool {
	switch status {
	case "COMPLETED", "PARTIAL", "FAILED", "REVIEW_REQUIRED", "CANCELLED":
		return true
	default:
		return false
	}
}

// Explicit allowlist mirrors the public Run response. Never marshal RunRecord:
// adding a field to that persistence type must not expand the SSE contract.
func runProgressDTO(record repository.RunRecord, q runservice.Quote, planned, completed int) map[string]any {
	versions, estimate := quoteFields(q)
	var cost *int64
	if record.CostKnown {
		cost = &record.EstimatedCostMicros
	}
	summary := []map[string]any{}
	if record.ErrorSummary != nil {
		code := "MI_SERVICE_UNAVAILABLE"
		switch *record.ErrorSummary {
		case "MI_ANALYSIS_FAILED", "MI_EXECUTION_BUDGET_EXCEEDED", "MI_EXECUTION_CANCELLED", "MI_EXECUTION_TARGET_STALE", "MI_UNCERTAIN_ATTEMPT", "MI_TIMEOUT", "MI_EXECUTION_CIRCUIT_OPEN", "MI_AUTH_FAILED", "MI_MODEL_NOT_FOUND", "MI_PROTOCOL_UNSUPPORTED", "MI_CIRCUIT_AUTH_FAILURES", "MI_CIRCUIT_MODEL_FAILURES", "MI_CIRCUIT_PROTOCOL_FAILURES":
			code = *record.ErrorSummary
		}
		summary = append(summary, map[string]any{"code": code, "count": 1})
	}
	return map[string]any{"id": strconv.FormatInt(record.ID, 10), "target_id": strconv.FormatInt(record.TargetID, 10), "created_by": strconv.FormatInt(record.CreatedBy, 10), "package": record.Package, "status": record.Status, "version": record.Version, "versions": versions, "estimate": estimate, "manifest_hash": record.ManifestHash, "request_count": record.RequestCount, "token_count": record.TokenCount, "estimated_cost_micros": cost, "valid_sample_count": record.ValidSampleCount, "planned_samples": planned, "completed_samples": completed, "created_at": record.CreatedAt, "started_at": record.StartedAt, "finished_at": record.FinishedAt, "execution_closed_at": record.ExecutionClosedAt, "error_summary": summary}
}

func (events *runEvents) snapshot(ctx context.Context, org, id int64) ([]byte, repository.RunVersion, error) {
	record, q, planned, completed, err := events.control.cfg.Runs.Get(ctx, org, id)
	if err != nil {
		return nil, repository.RunVersion{}, err
	}
	data, err := json.Marshal(runProgressDTO(record, q, planned, completed))
	if err != nil || len(data) > runEventMaxBytes {
		return nil, repository.RunVersion{}, repository.ErrConfiguration
	}
	frame := fmt.Appendf(nil, "event: progress\nid: %d:%d\ndata: %s\n\n", id, record.Version, data)
	return frame, repository.RunVersion{ID: id, Version: record.Version, Status: record.Status}, nil
}

// Set a deadline only around writes. Leaving an expired deadline armed while
// waiting for the next event would permanently poison the HTTP connection.
func (events *runEvents) write(w http.ResponseWriter, controller *http.ResponseController, frame []byte) error {
	if err := controller.SetWriteDeadline(time.Now().Add(events.operation)); err != nil {
		return err
	}
	// #nosec G705 -- Private SSE writer only: text/event-stream is set before use; frames contain fixed event names/canonical int64 IDs and encoding/json-escaped allowlisted DTOs (HTML escaping enabled), never upstream strings or HTML.
	if _, err := w.Write(frame); err != nil {
		return err
	}
	if err := controller.Flush(); err != nil {
		return err
	}
	return controller.SetWriteDeadline(time.Time{})
}

func (events *runEvents) streamError(w http.ResponseWriter, controller *http.ResponseController, r *http.Request, err error) {
	_, code := runEventError(err)
	requestID, _ := r.Context().Value(requestIDKey{}).(string)
	data, marshalErr := json.Marshal(map[string]string{"code": code, "request_id": requestID})
	if marshalErr == nil {
		_ = events.write(w, controller, fmt.Appendf(nil, "event: error\ndata: %s\n\n", data))
	}
}

func (events *runEvents) serve(w http.ResponseWriter, r *http.Request) {
	c := events.control
	id, valid := managementID(r.PathValue("id"))
	if !valid || r.URL.RawQuery != "" || !runEventCursor(r, id) || r.Method != http.MethodGet {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return
	}
	org, ok := c.managementOrganizationID(w, r, false)
	if !ok {
		return
	}
	ctx, stop := context.WithTimeout(r.Context(), events.lifetime)
	defer stop()
	readCtx, done := context.WithTimeout(ctx, events.operation)
	bound, user, err := events.authorize(readCtx, r, org)
	if err != nil {
		done()
		status, code := runEventError(err)
		c.failure(w, r, status, code)
		return
	}
	if !events.acquire(user) {
		done()
		w.Header().Set("Retry-After", "5")
		c.failure(w, r, 429, "MI_RATE_LIMITED")
		return
	}
	defer events.release(user)
	frame, current, err := events.snapshot(bound, org, id)
	done()
	if err != nil {
		c.runError(w, r, err)
		return
	}
	controller := http.NewResponseController(w)
	// Fail before committing SSE headers when the server cannot bound writes.
	if err := controller.SetWriteDeadline(time.Time{}); err != nil {
		c.failure(w, r, 503, "MI_SERVICE_UNAVAILABLE")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Cache-Control", "no-store")
	if ctx.Err() != nil || events.write(w, controller, frame) != nil || runEventTerminal(current.Status) {
		return
	}
	ticker := time.NewTicker(events.poll)
	defer ticker.Stop()
	lastWrite := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		readCtx, done := context.WithTimeout(ctx, events.operation)
		bound, _, err := events.authorize(readCtx, r, org)
		var next repository.RunVersion
		if err == nil {
			next, err = c.cfg.Runs.Version(bound, org, id)
		}
		frame = nil
		if err == nil && next.Version != current.Version {
			frame, next, err = events.snapshot(bound, org, id)
			if err == nil && next.Version < current.Version {
				err = repository.ErrConfiguration
			}
		}
		done()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			events.streamError(w, controller, r, err)
			return
		}
		if frame != nil {
			if events.write(w, controller, frame) != nil {
				return
			}
			current = next
			lastWrite = time.Now()
			if runEventTerminal(current.Status) {
				return
			}
		} else if time.Since(lastWrite) >= events.heartbeat {
			if events.write(w, controller, []byte(": heartbeat\n\n")) != nil {
				return
			}
			lastWrite = time.Now()
		}
	}
}
