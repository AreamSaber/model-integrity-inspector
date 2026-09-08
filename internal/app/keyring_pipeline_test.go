package app

import (
	"net/http/httptest"
	"path/filepath"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

func TestApplicationHistoricalKeysPreserveAuditAcrossRotation(t *testing.T) {
	for _, driver := range []string{"sqlite", "postgres"} {
		t.Run(driver, func(t *testing.T) {
			cfg := pipelineDatabase(t, testConfig(t), driver)
			first, err := prepare(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			source := httptest.NewServer(first.handler)
			t.Cleanup(func() { source.Close(); _ = first.close() })
			client := pipelineHTTP{client: source.Client(), endpoint: source.URL, origin: cfg.PublicOrigin}
			client.request(t, "POST", "/api/v1/setup/initialize", map[string]string{"organization_name": "Historical Keys", "username": "admin", "password": "synthetic-historical-keys-password"}, 201, nil)
			if err := first.store.VerifyAllAudit(t.Context(), true); err != nil {
				t.Fatal("initial audit chain failed")
			}
			source.Close()
			if err := first.close(); err != nil {
				t.Fatal("close initial app")
			}

			previous := secret.KeyFileReference{Version: cfg.MasterKeyVersion, File: cfg.MasterKeyFile}
			cfg.MasterKeyFile = filepath.Join(filepath.Dir(cfg.MasterKeyFile), "active-two.key")
			cfg.MasterKeyVersion = "v2"
			if _, err := secret.CreateKeyFile(cfg.MasterKeyFile, cfg.MasterKeyVersion); err != nil {
				t.Fatal(err)
			}
			// A new valid active key cannot authenticate old history by itself.
			if rejected, err := prepare(t.Context(), cfg); err == nil || rejected != nil {
				if rejected != nil {
					_ = rejected.close()
				}
				t.Fatal("startup accepted old audit without its key version")
			}
			cfg.PreviousMasterKeys = []secret.KeyFileReference{previous}
			second, err := prepare(t.Context(), cfg)
			if err != nil {
				t.Fatal("active plus historical startup failed")
			}
			defer func() { _ = second.close() }()
			restarted := httptest.NewServer(second.handler)
			defer restarted.Close()
			client = pipelineHTTP{client: restarted.Client(), endpoint: restarted.URL, origin: cfg.PublicOrigin}
			client.request(t, "POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": "synthetic-historical-keys-password"}, 200, nil)
			if err := second.store.VerifyAllAudit(t.Context(), true); err != nil {
				t.Fatal("old and new signed audit failed after login")
			}
			// Independently inspect persisted versions, without loading any key or
			// audit payload bytes. The latest head must be signed by the new key.
			db := openPipelineDatabase(t, cfg)
			var activeHeads int
			if err := db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM integrity_audit_chain_heads WHERE key_version='v2'").Scan(&activeHeads); err != nil || activeHeads != 1 {
				t.Fatal("new audit did not use active key version")
			}
		})
	}
}
