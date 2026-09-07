//go:build webassets

package webui

import (
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestBundledFrontendAndSPARoutes(t *testing.T) {
	handler := Handler()
	for _, path := range []string{"/", "/setup", "/runs/123"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), "GET", path, nil))
		if w.Code != 200 || !strings.Contains(w.Body.String(), `id="root"`) {
			t.Fatalf("SPA %s unavailable: %d", path, w.Code)
		}
	}
}

func TestAssetsNoListingNoMissingAssetFallback(t *testing.T) {
	handler := assetHandler(fstest.MapFS{"index.html": {Data: []byte("real UI")}, "assets/app.js": {Data: []byte("export{}")}, "assets/app.js.map": {Data: []byte("private source")}})
	for _, path := range []string{"/assets/missing.js", "/assets/app.js.map", "/assets/", "/.git/config"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), "GET", path, nil))
		if w.Code != 404 {
			t.Fatalf("unsafe asset route %s returned %d", path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), "GET", "/assets/app.js", nil))
	if w.Code != 200 || w.Body.String() != "export{}" {
		t.Fatal("built JS asset not served")
	}
}
