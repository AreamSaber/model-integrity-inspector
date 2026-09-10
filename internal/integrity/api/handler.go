package api

import (
	"context"
	"encoding/json"
	"net/http"

	"model-integrity-inspector.local/mii/internal/buildinfo"
	appruntime "model-integrity-inspector.local/mii/internal/platform/runtime"
)

// NewStatusHandler exposes no control routes. It serves worker health, including
// a real readiness callback; absence/failure is never reported as ready.
func NewStatusHandler(build buildinfo.Info, role appruntime.Role, readiness func(context.Context) bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		if readiness == nil || !readiness(r.Context()) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready", "role": string(role)})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready", "role": string(role)})
	})
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, build)
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
