package api

import (
	"errors"
	"net/http"
	"strconv"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func (c *control) registerReviewRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/runs/{id}/reviews", c.appendReview)
	mux.HandleFunc("GET /api/v1/runs/{id}/reviews", c.listReviews)
}
func (c *control) reviewError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, repository.ErrConflict) {
		c.failure(w, r, 409, "MI_REVIEW_CONFLICT")
		return
	}
	c.resultError(w, r, err)
}
func (c *control) appendReview(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	ctx, org, ok := c.authorizeOrganization(w, r, "review.write")
	if !ok {
		return
	}
	id, ok := c.managementPathID(w, r, "id")
	if !ok {
		return
	}
	keys := r.Header.Values("Idempotency-Key")
	if len(keys) != 1 {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return
	}
	var body struct {
		AnalysisRevision int     `json:"analysis_revision"`
		PreviousReviewID *string `json:"previous_review_id"`
		Conclusion       string  `json:"conclusion"`
		Explanation      string  `json:"explanation"`
	}
	if !c.decode(w, r, &body) {
		return
	}
	previous := int64(0)
	if body.PreviousReviewID != nil {
		previous, ok = managementID(*body.PreviousReviewID)
		if !ok {
			c.failure(w, r, 400, "MI_INVALID_REQUEST")
			return
		}
	}
	input := repository.ReviewInput{RunID: id, AnalysisRevision: body.AnalysisRevision, PreviousReviewID: previous, Conclusion: body.Conclusion, Explanation: body.Explanation, IdempotencyKey: keys[0]}
	view, err := c.cfg.Runs.AppendReview(ctx, org, input)
	if err != nil {
		c.reviewError(w, r, err)
		return
	}
	c.success(w, r, 201, view)
}
func (c *control) listReviews(w http.ResponseWriter, r *http.Request) {
	ctx, org, ok := c.authorizeOrganization(w, r, "run.read")
	if !ok {
		return
	}
	r = r.WithContext(ctx)
	id, ok := c.managementPathID(w, r, "id")
	if !ok {
		return
	}
	revision, _, pageRequest, err := resultRequest(r, true, false)
	if err != nil {
		c.reviewError(w, r, err)
		return
	}
	scope, err := resultScope(r, org, "runs/"+strconv.FormatInt(id, 10)+"/reviews/revision:"+strconv.Itoa(revision))
	if err != nil {
		c.reviewError(w, r, err)
		return
	}
	page, err := c.parsePage(pageRequest, scope)
	if err != nil {
		c.reviewError(w, r, err)
		return
	}
	rows, err := c.cfg.Runs.Reviews(ctx, org, id, revision, repository.ListOptions{AfterID: page.AfterID, Limit: page.Limit})
	if err != nil {
		c.reviewError(w, r, err)
		return
	}
	last := int64(0)
	if len(rows) > 0 {
		last, _ = managementID(rows[len(rows)-1].ID)
	}
	more := false
	if len(rows) == page.Limit {
		next, err := c.cfg.Runs.Reviews(ctx, org, id, revision, repository.ListOptions{AfterID: last, Limit: 1})
		if err != nil {
			c.reviewError(w, r, err)
			return
		}
		more = len(next) > 0
	}
	data, err := c.pageResult(rows, last, more, scope, "")
	if err != nil {
		c.reviewError(w, r, err)
		return
	}
	c.success(w, r, 200, data)
}
