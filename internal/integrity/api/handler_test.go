package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/buildinfo"
	appruntime "model-integrity-inspector.local/mii/internal/platform/runtime"
)

func TestStatusEndpoints(t *testing.T) {
	t.Parallel()

	handler := NewStatusHandler(buildinfo.Info{Version: "test"}, appruntime.RoleWorker, func(context.Context) bool { return true })
	for _, test := range []struct {
		path string
		want string
	}{
		{"/health", `"status":"ok"`},
		{"/ready", `"role":"worker"`},
		{"/version", `"version":"test"`},
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet, test.path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d", test.path, recorder.Code)
		}
		if !strings.Contains(recorder.Body.String(), test.want) {
			t.Fatalf("GET %s body = %q, want %q", test.path, recorder.Body.String(), test.want)
		}
	}
}
