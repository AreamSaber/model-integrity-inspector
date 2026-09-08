package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResponseRetentionStrictQueryAndMethod(t *testing.T) {
	for _, item := range []struct {
		method, query string
		valid         bool
	}{
		{"GET", "analysis_revision=1", true}, {"HEAD", "analysis_revision=1", false}, {"POST", "analysis_revision=1", false},
		{"GET", "", false}, {"GET", "analysis_revision=2", false}, {"GET", "analysis_revision=01", false},
		{"GET", "analysis_revision=1&analysis_revision=1", false}, {"GET", "analysis_revision=1&policy_days=0", false}, {"GET", "analysis_revision=%zz", false},
	} {
		r := httptest.NewRequestWithContext(t.Context(), item.method, "/api/v1/runs/1/response-retention?"+item.query, nil)
		if validResponseRetentionRequest(r) != item.valid {
			t.Fatal("strict retention request guard drifted")
		}
		if !item.valid {
			w := httptest.NewRecorder()
			(&control{}).getResponseRetention(w, r)
			if w.Code != 400 && w.Code != 405 {
				t.Fatal("invalid retention request reached dependencies")
			}
		}
	}
	r := httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/runs/1/response-retention?analysis_revision=1", strings.NewReader("{}"))
	if validResponseRetentionRequest(r) {
		t.Fatal("retention GET accepted a body")
	}
	r.ContentLength = 0
	r.TransferEncoding = []string{"chunked"}
	if validResponseRetentionRequest(r) {
		t.Fatal("retention GET accepted chunked input")
	}
}

func TestResponseRetentionAdmissionBeforeDatabaseReads(t *testing.T) {
	c := &control{retentionSlots: make(chan struct{}, 4)}
	for range 4 {
		c.retentionSlots <- struct{}{}
	}
	called := false
	handler := c.middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(t.Context(), "GET", "/api/v1/runs/1/response-retention?analysis_revision=1", nil)
	handler.ServeHTTP(w, r)
	if called || w.Code != 429 || w.Header().Get("Retry-After") != "2" || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Body.String(), "MI_RETENTION_LIMIT") || len(c.retentionSlots) != 4 {
		t.Fatal("retention read admission did not precede setup and session queries")
	}
}
