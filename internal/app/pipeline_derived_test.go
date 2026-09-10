package app

import (
	"database/sql"
	"net/url"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

// The production management HTTP handler, not direct policy SQL, changes the
// retention setting. Test-only INSERT rejection then proves that zero days is
// not implemented as insert-then-delete or merely hidden HTTP output.
func configurePipelineRetention(t *testing.T, cfg Config, api *pipelineHTTP, days int) *sql.DB {
	t.Helper()
	var organization struct {
		Version int64 `json:"version"`
		Days    int   `json:"full_response_retention_days"`
	}
	api.request(t, "PATCH", "/api/v1/organizations/"+api.orgID, map[string]any{"version": 1, "full_response_retention_days": days}, 200, &organization)
	if organization.Version != 2 || organization.Days != days {
		t.Fatal("actual management policy receipt differs from requested retention")
	}
	db := openPipelineDatabase(t, cfg)
	if days != 0 {
		return db
	}
	statements := []string{
		"CREATE TRIGGER pipeline_no_raw BEFORE INSERT ON integrity_response_evidence BEGIN SELECT RAISE(ABORT, 'body retention is zero'); END",
		"CREATE TRIGGER pipeline_no_display BEFORE INSERT ON integrity_display_evidence BEGIN SELECT RAISE(ABORT, 'body retention is zero'); END",
	}
	if cfg.DatabaseDriver == "postgres" {
		statements = []string{
			"ALTER TABLE integrity_response_evidence ADD CONSTRAINT pipeline_no_raw CHECK (false) NOT VALID",
			"ALTER TABLE integrity_display_evidence ADD CONSTRAINT pipeline_no_display CHECK (false) NOT VALID",
		}
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(t.Context(), statement); err != nil {
			t.Fatal("install actual zero-day body INSERT rejection")
		}
	}
	return db
}

func openPipelineDatabase(t *testing.T, cfg Config) *sql.DB {
	t.Helper()
	driver, dsn := "sqlite", cfg.DatabasePath
	if cfg.DatabaseDriver == "postgres" {
		driver, dsn = "pgx", cfg.DatabaseDSN
	} else {
		// Config validation permits only a literal filesystem path here. Each
		// newly opened auxiliary connection needs the same safety policy as
		// repository.sqliteDSN; executing PRAGMA once on a pool is insufficient.
		if strings.ContainsAny(dsn, "?\x00") {
			t.Fatal("auxiliary SQLite path is not canonical")
		}
		query := url.Values{"_pragma": {"foreign_keys(1)", "busy_timeout(5000)", "journal_mode(WAL)", "synchronous(FULL)"}, "_txlock": {"immediate"}}
		dsn += "?" + query.Encode()
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal("open isolated pipeline database")
	}
	if driver == "sqlite" {
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func verifyPipelineDerivedStorage(t *testing.T, db *sql.DB, orgID string, days, attempts int) {
	t.Helper()
	var runs, newMode, actualAttempts, derived, recorded, raw, display int
	err := db.QueryRowContext(t.Context(), `SELECT
 (SELECT count(*) FROM integrity_runs WHERE organization_id=$1),
 (SELECT count(*) FROM integrity_runs WHERE organization_id=$1 AND analysis_source_version=$2),
 (SELECT count(*) FROM integrity_sample_attempts WHERE organization_id=$1),
 (SELECT count(*) FROM integrity_attempt_derived WHERE organization_id=$1),
 (SELECT count(*) FROM integrity_sample_attempts WHERE organization_id=$1 AND derived_receipt='derived_recorded' AND status='COMPLETED'),
 (SELECT count(*) FROM integrity_response_evidence WHERE organization_id=$1),
 (SELECT count(*) FROM integrity_display_evidence WHERE organization_id=$1)`, orgID, domain.AnalysisSourceDerivedV1).Scan(&runs, &newMode, &actualAttempts, &derived, &recorded, &raw, &display)
	if err != nil {
		t.Fatal("read actual application derived storage counts")
	}
	wantBodies := attempts
	if days == 0 {
		wantBodies = 0
	}
	if runs != 2 || newMode != runs || actualAttempts != attempts || derived != attempts || recorded != attempts || raw != wantBodies || display != wantBodies {
		t.Fatalf("actual derived storage: runs=%d new_mode=%d attempts=%d derived=%d recorded=%d raw=%d display=%d; want attempts=%d bodies=%d", runs, newMode, actualAttempts, derived, recorded, raw, display, attempts, wantBodies)
	}
	var receipts int
	state := "recorded"
	if days == 0 {
		state = "not_retained"
	}
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM integrity_sample_attempts WHERE organization_id=$1 AND response_body_receipt=$2", orgID, state).Scan(&receipts); err != nil || receipts != attempts {
		t.Fatal("actual final body receipts do not reflect organization retention")
	}
}
