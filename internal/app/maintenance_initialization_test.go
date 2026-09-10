package app

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Exercise real prepare/close/restart and the actual HTTP initialization path.
// The isolated row is a test-only intermediate-state fixture, not a restore
// implementation or proof that an archive, Worker, or restored data was verified.
func TestApplicationMaintenanceInitializationAcrossRestart(t *testing.T) {
	for _, driver := range []string{"sqlite", "postgres"} {
		t.Run(driver, func(t *testing.T) {
			for _, isolated := range []bool{false, true} {
				name := "normal"
				if isolated {
					name = "restore_isolated"
				}
				t.Run(name, func(t *testing.T) {
					cfg := pipelineDatabase(t, testConfig(t), driver)
					initial, err := prepare(t.Context(), cfg)
					if err != nil {
						t.Fatal("initial application preparation failed")
					}
					if err := initial.close(); err != nil {
						t.Fatal("initial application close failed")
					}
					db := openPipelineDatabase(t, cfg)
					if isolated {
						result, err := db.ExecContext(t.Context(), "UPDATE system_maintenance SET mode='restore_isolated', version=2, updated_at_micros=$1 WHERE id=1 AND mode='normal' AND version=1", time.Now().UTC().UnixMicro())
						if err != nil {
							t.Fatal("isolated intermediate-state fixture failed")
						}
						if rows, err := result.RowsAffected(); err != nil || rows != 1 {
							t.Fatal("isolated fixture did not update exactly one gate")
						}
					}
					before := applicationInitializationCounts(t, db)
					for restart := range 2 {
						func() {
							restarted, err := prepare(t.Context(), cfg)
							if err != nil {
								t.Fatal("application restart failed")
							}
							defer func() {
								if err := restarted.close(); err != nil {
									t.Error("restarted application close failed")
								}
							}()
							server := httptest.NewServer(restarted.handler)
							defer server.Close()
							api := pipelineHTTP{client: &http.Client{Timeout: 5 * time.Second}, endpoint: server.URL, origin: cfg.PublicOrigin}
							status := http.StatusCreated
							code := ""
							if isolated {
								status, code = http.StatusServiceUnavailable, "MI_SERVICE_UNAVAILABLE"
							} else if restart > 0 {
								status, code = http.StatusConflict, "MI_SETUP_CLOSED"
							}
							applicationInitializeHTTP(t, &api, status, code)
							var setup struct {
								Initialized bool `json:"initialized"`
							}
							api.request(t, http.MethodGet, "/api/v1/setup/status", nil, http.StatusOK, &setup)
							if setup.Initialized == isolated {
								t.Fatal("HTTP setup state does not match the persistent gate")
							}
						}()
						if isolated && !reflect.DeepEqual(before, applicationInitializationCounts(t, db)) {
							t.Fatal("isolated HTTP initialization or restart mutated identity, bundles, or audit")
						}
					}
					var mode string
					var version int64
					if err := db.QueryRowContext(t.Context(), "SELECT mode,version FROM system_maintenance WHERE id=1").Scan(&mode, &version); err != nil {
						t.Fatal("read persistent gate after restarts failed")
					}
					if isolated && (mode != "restore_isolated" || version != 2) || !isolated && (mode != "normal" || version != 1) {
						t.Fatal("application startup or initialization changed the maintenance gate")
					}
				})
			}
		})
	}
}

func applicationInitializeHTTP(t *testing.T, api *pipelineHTTP, status int, code string) {
	t.Helper()
	const payload = `{"organization_name":"Maintenance initialization fixture","username":"admin","password":"synthetic-maintenance-initialize-422"}`
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, api.endpoint+"/api/v1/setup/initialize", strings.NewReader(payload))
	if err != nil {
		t.Fatal("create initialization request failed")
	}
	req.Header.Set("Origin", api.origin)
	req.Header.Set("Content-Type", "application/json")
	res, err := api.client.Do(req)
	if err != nil {
		t.Fatal("initialization HTTP request failed")
	}
	body, readErr := io.ReadAll(io.LimitReader(res.Body, 4097))
	closeErr := res.Body.Close()
	if readErr != nil || closeErr != nil || len(body) > 4096 || res.StatusCode != status {
		t.Fatalf("initialization HTTP response failed: status=%d expected=%d", res.StatusCode, status)
	}
	var envelope struct {
		Error struct{ Code string } `json:"error"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.Error.Code != code || strings.Contains(string(body), "synthetic-maintenance-initialize-422") {
		t.Fatal("initialization returned unexpected or unsafe public content")
	}
}

func applicationInitializationCounts(t *testing.T, db *sql.DB) map[string]int64 {
	t.Helper()
	counts := make(map[string]int64)
	for _, table := range []string{"organizations", "users", "organization_members", "roles", "permissions", "role_permissions", "member_roles", "system_settings", "integrity_rule_bundles", "integrity_template_bundles", "integrity_audit_logs", "integrity_audit_chain_heads"} {
		var count int64
		if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM "+table).Scan(&count); err != nil {
			t.Fatal("read fixed initialization table count failed")
		}
		counts[table] = count
	}
	return counts
}
