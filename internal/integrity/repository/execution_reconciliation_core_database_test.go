package repository

import (
	"errors"
	"testing"
)

// A real SQL trigger may suppress the row update without returning a driver
// error. Reporting Applied and appending reconciliation audit in that case is
// false progress, especially for a freeze coordinator that must drain once.
func TestExecutionReconciliationCoreRequiresActualSampleUpdate(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, _, plan, policy := executionFixture(t, s, 1)
		run, queue, samples := executionStart(t, tenant, plan, policy)
		job := mustClaim(t, queue)
		if err := queue.Fail(tenant.ctx, job, "JOB_TEST_INTERRUPTED"); err != nil {
			t.Fatal("terminal unattempted job fixture", err)
		}
		sources, err := queue.LoadExecutionReconciliations(t.Context(), 1)
		if err != nil || len(sources) != 1 {
			t.Fatal("actual frozen unattempted source", err)
		}
		statements := []string{"CREATE TRIGGER reconciliation_core_ignore BEFORE UPDATE ON integrity_logical_samples WHEN OLD.completed_at IS NULL AND NEW.completed_at IS NOT NULL BEGIN SELECT RAISE(IGNORE); END"}
		if cfg.Driver == "postgres" {
			statements = []string{"CREATE FUNCTION reconciliation_core_ignore_update() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$", "CREATE TRIGGER reconciliation_core_ignore BEFORE UPDATE ON integrity_logical_samples FOR EACH ROW WHEN (OLD.completed_at IS NULL AND NEW.completed_at IS NOT NULL) EXECUTE FUNCTION reconciliation_core_ignore_update()"}
		}
		for _, statement := range statements {
			if err := s.db.Exec(statement).Error; err != nil {
				t.Fatal("install actual suppressed-update fixture", err)
			}
		}
		got, err := queue.ReconcileExecutionWithDerived(t.Context(), sources[0], nil)
		if !errors.Is(err, ErrAnalysisSource) || got != "" {
			t.Fatal("suppressed sample UPDATE falsely reported applied", got, err)
		}
		var sample LogicalSampleRecord
		if err := s.db.Where("id=?", samples[0].ID).Take(&sample).Error; err != nil || sample.CompletedAt != nil {
			t.Fatal("failed sample settlement changed original row", err)
		}
		var events int64
		if err := s.db.Table("integrity_audit_logs").Where("action='run.sample.reconcile'").Count(&events).Error; err != nil || events != 0 {
			t.Fatal("suppressed update left a reconciliation success audit", err)
		}
		current, err := tenant.GetRun(run.ID)
		if err != nil || current.ExecutionClosedAt != nil || current.RequestCount != 0 || current.TokenCount != 0 || current.ReservedTokens != 0 {
			t.Fatal("suppressed sample update changed original run", err)
		}
		drop := "DROP TRIGGER reconciliation_core_ignore"
		if cfg.Driver == "postgres" {
			drop += " ON integrity_logical_samples"
		}
		if err := s.db.Exec(drop).Error; err != nil {
			t.Fatal("remove only actual suppressed-update fault", err)
		}
		if cfg.Driver == "postgres" {
			if err := s.db.Exec("DROP FUNCTION reconciliation_core_ignore_update()").Error; err != nil {
				t.Fatal("remove exact fixture trigger function", err)
			}
		}
		for _, want := range []ExecutionReconciliationResult{ReconciliationApplied, ReconciliationAlreadyCompleted} {
			got, err = queue.ReconcileExecutionWithDerived(t.Context(), sources[0], nil)
			if err != nil || got != want {
				t.Fatal("same original source cannot settle once after exact fault removal", got, err)
			}
		}
		if err := s.db.Table("integrity_audit_logs").Where("action='run.sample.reconcile'").Count(&events).Error; err != nil || events != 1 {
			t.Fatal("unattempted source reconciliation audit not exactly once", err)
		}
		if err := s.VerifyAllAudit(t.Context(), true); err != nil {
			t.Fatal("actual reconciliation audit chain", err)
		}
	})
}
