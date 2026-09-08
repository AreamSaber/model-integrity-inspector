package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"
)

var systemStatusAdmission = struct {
	global chan struct{}
	mu     sync.Mutex
	orgs   map[int64]bool
}{global: make(chan struct{}, 2), orgs: make(map[int64]bool)}

func (c *control) systemStatusEntry(w http.ResponseWriter, r *http.Request) bool {
	if deadline, ok := r.Context().Deadline(); ok {
		if err := http.NewResponseController(w).SetWriteDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
			c.failure(w, r, 503, "MI_SERVICE_UNAVAILABLE")
			return false
		}
	}
	select {
	case systemStatusAdmission.global <- struct{}{}:
		return true
	default:
		w.Header().Set("Retry-After", "2")
		c.failure(w, r, 429, "MI_SYSTEM_STATUS_BUSY")
		return false
	}
}

func acquireSystemStatusOrganization(org int64) bool {
	systemStatusAdmission.mu.Lock()
	defer systemStatusAdmission.mu.Unlock()
	if systemStatusAdmission.orgs[org] {
		return false
	}
	systemStatusAdmission.orgs[org] = true
	return true
}
func releaseSystemStatusOrganization(org int64) {
	systemStatusAdmission.mu.Lock()
	defer systemStatusAdmission.mu.Unlock()
	delete(systemStatusAdmission.orgs, org)
}

func (c *control) registerSystemStatusRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/system/health", c.systemStatus)
}
func (c *control) systemStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		c.failure(w, r, 405, "MI_INVALID_REQUEST")
		return
	}
	if r.URL.RawQuery != "" || r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return
	}
	org, ok := c.managementOrganizationID(w, r, false)
	if !ok {
		return
	}
	if err := c.cfg.SystemStatus.Authorize(r.Context(), token(r), org); err != nil {
		c.error(w, r, err)
		return
	}
	if !acquireSystemStatusOrganization(org) {
		w.Header().Set("Retry-After", "2")
		c.failure(w, r, 429, "MI_SYSTEM_STATUS_BUSY")
		return
	}
	defer releaseSystemStatusOrganization(org)
	data, err := c.cfg.SystemStatus.Read(r.Context(), token(r), org)
	if err != nil {
		c.error(w, r, err)
		return
	}
	encoded, err := json.Marshal(data)
	if err != nil || len(encoded) > 31<<10 {
		c.failure(w, r, 503, "MI_SERVICE_UNAVAILABLE")
		return
	}
	c.success(w, r, 200, json.RawMessage(encoded))
}
