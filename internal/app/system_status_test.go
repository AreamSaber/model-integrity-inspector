package app

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/identity"
	appruntime "model-integrity-inspector.local/mii/internal/platform/runtime"
)

func TestApplicationSystemStatusRealWorkerLifecycle(t *testing.T) {
	for _, driver := range []string{"sqlite", "postgres"} {
		for _, role := range []appruntime.Role{appruntime.RoleAll, appruntime.RoleServer} {
			if driver == "sqlite" && role == appruntime.RoleServer {
				continue
			}
			t.Run(driver+"/"+string(role), func(t *testing.T) {
				cfg := pipelineDatabase(t, testConfig(t), driver)
				cfg.Role = role
				a, err := prepare(t.Context(), cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = a.close() }()
				server := httptest.NewServer(a.handler)
				defer server.Close()
				jar, err := cookiejar.New(nil)
				if err != nil {
					t.Fatal(err)
				}
				client := server.Client()
				client.Jar = jar
				client.Timeout = 5 * time.Second
				p := pipelineHTTP{client: client, endpoint: server.URL, origin: cfg.PublicOrigin}
				password := "synthetic-system-status-password-42"
				p.request(t, http.MethodPost, "/api/v1/setup/initialize", map[string]string{"organization_name": "Status", "username": "admin", "password": password}, 201, nil)
				var login struct {
					Organizations []struct {
						ID string `json:"id"`
					} `json:"organizations"`
					CSRF string `json:"csrf_token"`
				}
				p.request(t, http.MethodPost, "/api/v1/auth/login", map[string]string{"username": "admin", "password": password}, 200, &login)
				if len(login.Organizations) != 1 {
					t.Fatal("missing actual organization")
				}
				p.orgID, p.csrf = login.Organizations[0].ID, login.CSRF
				read := func() identity.SystemStatus {
					var dto identity.SystemStatus
					p.request(t, http.MethodGet, "/api/v1/system/health", nil, 200, &dto)
					return dto
				}
				before := read()
				if before.Driver != driver || before.Coverage != "partial" || before.RemoteWorkers.State != "unavailable" || before.Key.State != "startup_verified" || before.Reports.State != "startup_verified" || before.Schema.State != "ok" {
					t.Fatal("runtime observations incorrect")
				}
				if role == appruntime.RoleServer {
					if a.worker != nil || before.LocalWorker.State != "not_applicable" {
						t.Fatal("server invented a local/remote worker")
					}
					return
				}
				if before.LocalWorker.State != "error" || a.worker.Ready() {
					t.Fatal("unstarted real consumer reported healthy")
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- a.worker.Run(ctx) }()
				deadline := time.NewTimer(5 * time.Second)
				defer deadline.Stop()
				tick := time.NewTicker(10 * time.Millisecond)
				defer tick.Stop()
				for !a.worker.Ready() {
					select {
					case <-tick.C:
					case <-deadline.C:
						t.Fatal("real Worker did not acquire consumer")
					}
				}
				if read().LocalWorker.State != "ok" {
					t.Fatal("live consumer not observed")
				}
				cancel()
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(12 * time.Second):
					t.Fatal("consumer did not stop")
				}
				if read().LocalWorker.State != "error" {
					t.Fatal("stopped consumer retained healthy status")
				}
			})
		}
	}
}
