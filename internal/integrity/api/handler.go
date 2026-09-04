package api

import (
	"encoding/json"
	"net/http"

	"model-integrity-inspector.local/mii/internal/buildinfo"
	appruntime "model-integrity-inspector.local/mii/internal/platform/runtime"
)

func NewHandler(build buildinfo.Info, role appruntime.Role) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready", "role": string(role)})
	})
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, build)
	})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"service": "model-integrity-inspector",
			"stage":   "M0-03-engineering-baseline",
		})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
