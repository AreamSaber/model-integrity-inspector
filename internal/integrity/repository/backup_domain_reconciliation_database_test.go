package repository

import (
	"errors"
	"testing"
)

// The database itself suppresses UPDATE without a SQL error. This regression
// must fail when reconciliation still emits success audit after updating zero.
func TestBackupDomainAnalysisRequiresActualUpdate(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, queue, run, _, lease := analysisReadyFixture(t, s, 1)
		if err := queue.Fail(t.Context(), lease, "WORKER_HANDLER_FAILED"); err != nil {
			t.Fatal(err)
		}
		remove := backupDomainIgnoreUpdate(t, s, cfg, "integrity_runs", "OLD.status='ANALYZING' AND NEW.status='FAILED'")
		if err := queue.ReconcileAnalyses(t.Context()); !errors.Is(err, ErrAnalysisSource) {
			t.Fatal("suppressed analysis UPDATE returned false success", err)
		}
		var current RunRecord
		if err := s.db.First(&current, run.ID).Error; err != nil || current.Status != "ANALYZING" || current.Version != run.Version {
			t.Fatal("suppressed projection changed original run", err)
		}
		var events int64
		if err := s.db.Table("integrity_audit_logs").Where("action='run.analysis.fail'").Count(&events).Error; err != nil || events != 0 {
			t.Fatal("suppressed projection left success audit", err)
		}
		remove()
		if err := queue.ReconcileAnalyses(t.Context()); err != nil {
			t.Fatal("same real candidate could not settle after fault removal", err)
		}
		if err := s.db.First(&current, run.ID).Error; err != nil || current.Status != "FAILED" || current.Version != run.Version+1 {
			t.Fatal("real failure projection missing", err)
		}
		if err := s.VerifyAllAudit(tenant.ctx, true); err != nil {
			t.Fatal("authentic failure audit", err)
		}
	})
}

// Only fixed table/predicate literals in these tests reach this helper.
func backupDomainIgnoreUpdate(t *testing.T, s *Store, cfg Config, table, predicate string) func() {
	t.Helper()
	statements := []string{"CREATE TRIGGER backup_domain_ignore BEFORE UPDATE ON " + table + " WHEN " + predicate + " BEGIN SELECT RAISE(IGNORE); END"}
	if cfg.Driver == "postgres" {
		statements = []string{"CREATE FUNCTION backup_domain_ignore_update() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$", "CREATE TRIGGER backup_domain_ignore BEFORE UPDATE ON " + table + " FOR EACH ROW WHEN (" + predicate + ") EXECUTE FUNCTION backup_domain_ignore_update()"}
	}
	for _, statement := range statements {
		if err := s.db.Exec(statement).Error; err != nil {
			t.Fatal("install actual domain update suppression", err)
		}
	}
	return func() {
		t.Helper()
		drop := "DROP TRIGGER backup_domain_ignore"
		if cfg.Driver == "postgres" {
			drop += " ON " + table
		}
		if err := s.db.Exec(drop).Error; err != nil {
			t.Fatal("remove exact update suppression", err)
		}
		if cfg.Driver == "postgres" {
			if err := s.db.Exec("DROP FUNCTION backup_domain_ignore_update()").Error; err != nil {
				t.Fatal("remove exact update suppression function", err)
			}
		}
	}
}
