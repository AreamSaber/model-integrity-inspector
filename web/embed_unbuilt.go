//go:build !webassets

package webui

import "net/http"

// Handler makes missing build output explicit. Release builds always use the
// webassets tag after pnpm build; this variant enables backend-only unit tests.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Frontend assets are not built; run scripts/build.ps1.", http.StatusServiceUnavailable)
	})
}
