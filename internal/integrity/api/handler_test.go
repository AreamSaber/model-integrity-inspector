package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/buildinfo"
	appruntime "model-integrity-inspector.local/mii/internal/platform/runtime"
)

func TestStatusEndpoints(t *testing.T) {
	t.Parallel()

	handler := NewHandler(buildinfo.Info{Version: "test"}, appruntime.RoleServer)
	for _, test := range []struct {
		path string
		want string
	}{
		{"/health", `"status":"ok"`},
		{"/ready", `"role":"server"`},
		{"/version", `"version":"test"`},
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, test.path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d", test.path, recorder.Code)
		}
		if !strings.Contains(recorder.Body.String(), test.want) {
			t.Fatalf("GET %s body = %q, want %q", test.path, recorder.Body.String(), test.want)
		}
	}
}
