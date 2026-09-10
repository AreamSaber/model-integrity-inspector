package api

import (
	"net/http"
	"strconv"

	"model-integrity-inspector.local/mii/internal/integrity/target"
)

func precheckDTO(value target.PrecheckView) map[string]any {
	return map[string]any{
		"id": strconv.FormatInt(value.ID, 10), "job_id": strconv.FormatInt(value.JobID, 10), "target_id": strconv.FormatInt(value.TargetID, 10),
		"target_version": value.TargetVersion, "status": value.Status, "version": value.Version, "request_count": value.RequestCount,
		"checks": value.Checks, "error_code": value.ErrorCode, "max_output_parameter": value.MaxOutputParameter,
		"created_at": value.CreatedAt, "started_at": value.StartedAt, "checked_at": value.CheckedAt,
	}
}

func (c *control) enqueuePrecheck(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	ctx, org, ok := c.authorizeOrganization(w, r, "target.precheck")
	if !ok {
		return
	}
	id, ok := c.managementPathID(w, r, "id")
	if !ok {
		return
	}
	var body struct {
		Version int64 `json:"version"`
	}
	if !c.decode(w, r, &body) {
		return
	}
	if body.Version <= 0 || len(r.Header.Values("Idempotency-Key")) > 1 {
		c.targetError(w, r, target.ErrInvalid)
		return
	}
	result, err := c.cfg.Targets.EnqueuePrecheck(ctx, org, id, body.Version, r.Header.Get("Idempotency-Key"))
	if err != nil {
		c.targetError(w, r, err)
		return
	}
	c.success(w, r, http.StatusAccepted, precheckDTO(result))
}

func (c *control) latestPrecheck(w http.ResponseWriter, r *http.Request) { c.readPrecheck(w, r, false) }
func (c *control) getPrecheck(w http.ResponseWriter, r *http.Request)    { c.readPrecheck(w, r, true) }
func (c *control) readPrecheck(w http.ResponseWriter, r *http.Request, specific bool) {
	ctx, org, ok := c.authorizeOrganization(w, r, "target.read")
	if !ok {
		return
	}
	if r.URL.RawQuery != "" {
		c.targetError(w, r, target.ErrInvalid)
		return
	}
	id, ok := c.managementPathID(w, r, "id")
	if !ok {
		return
	}
	var precheckID int64
	if specific {
		precheckID, ok = c.managementPathID(w, r, "precheckId")
		if !ok {
			return
		}
	}
	result, err := c.cfg.Targets.GetPrecheck(ctx, org, id, precheckID)
	if err != nil {
		c.targetError(w, r, err)
		return
	}
	c.success(w, r, http.StatusOK, precheckDTO(result))
}
