package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

// Admission is process-wide and has no waiting queue or retained idle org IDs.
// These development safety limits are not a production capacity claim.
var overviewAdmission = overviewLimiter{active: map[int64]bool{}}

type overviewLimiter struct {
	mu     sync.Mutex
	active map[int64]bool
}

func (l *overviewLimiter) acquire(org int64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if org <= 0 || len(l.active) >= 2 || l.active[org] {
		return false
	}
	l.active[org] = true
	return true
}
func (l *overviewLimiter) release(org int64) { l.mu.Lock(); defer l.mu.Unlock(); delete(l.active, org) }

func (c *control) registerOverviewRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/overview", c.getOverview)
}

func (c *control) getOverview(w http.ResponseWriter, r *http.Request) {
	days, err := overviewDays(r.URL.RawQuery)
	if err != nil {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	if deadline, ok := ctx.Deadline(); ok {
		// Context cancellation alone does not interrupt a slow socket write.
		// Native HTTP servers support this; recorders may not implement it.
		if err := http.NewResponseController(w).SetWriteDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
			c.failure(w, r, 503, "MI_SERVICE_UNAVAILABLE")
			return
		}
	}
	ctx, org, ok := c.authorizeOrganization(w, r, "run.read")
	if !ok {
		return
	}
	r = r.WithContext(ctx)
	if !overviewAdmission.acquire(org) {
		w.Header().Set("Retry-After", "2")
		c.failure(w, r, 429, "MI_OVERVIEW_BUSY")
		return
	}
	defer overviewAdmission.release(org)
	data, err := c.cfg.Runs.Overview(ctx, org, days)
	if err != nil {
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			c.failure(w, r, 503, "MI_OVERVIEW_TIMEOUT")
		case errors.Is(err, repository.ErrOverviewLimit):
			c.failure(w, r, 503, "MI_OVERVIEW_LIMIT")
		case errors.Is(err, repository.ErrOverviewTimezone):
			c.failure(w, r, 503, "MI_OVERVIEW_TIMEZONE_INVALID")
		default:
			c.resultError(w, r, err)
		}
		return
	}
	if ctx.Err() != nil {
		c.failure(w, r, 503, "MI_OVERVIEW_TIMEOUT")
		return
	}
	encoded, err := json.Marshal(data)
	// Reserve room for the standard envelope and request ID. Never truncate.
	if err != nil || len(encoded) > (256<<10)-1024 {
		c.failure(w, r, 503, "MI_OVERVIEW_LIMIT")
		return
	}
	c.success(w, r, 200, json.RawMessage(encoded))
}

func overviewDays(raw string) (int, error) {
	if len(raw) > 64 {
		return 0, ErrPagination
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		return 0, ErrPagination
	}
	if len(q) == 0 {
		return 7, nil
	}
	values, ok := q["days"]
	if len(q) != 1 || !ok || len(values) != 1 {
		return 0, ErrPagination
	}
	switch values[0] {
	case "7":
		return 7, nil
	case "30":
		return 30, nil
	default:
		return 0, ErrPagination
	}
}
