package repository

import (
	"reflect"
	"strconv"
	"strings"
	"testing"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

// Real driver-level suppression is not a SQL error. Each terminal projection
// must either persist all its facts or return no result and roll everything
// back. These are real repository producers, not derived MAC/TLS proofs.
func TestExecutionReconciliationRequiresEveryAtomicUpdate(t *testing.T) {
	for _, fault := range []struct {
		name, table, predicate string
		unstarted              bool
	}{
		{"attempt", "integrity_sample_attempts", "OLD.status='DISPATCHED' AND NEW.status='UNCERTAIN'", false},
		{"sample", "integrity_logical_samples", "OLD.completed_at IS NULL AND NEW.completed_at IS NOT NULL", false},
		{"budget", "integrity_runs", "NEW.token_count<>OLD.token_count", false},
		{"sequence_count", "integrity_runs", "NEW.finalized_sample_count<>OLD.finalized_sample_count", false},
		{"run_close", "integrity_runs", "OLD.execution_closed_at IS NULL AND NEW.execution_closed_at IS NOT NULL", false},
		{"probe_close", "integrity_probe_instances", "NEW.status='COMPLETED'", false},
		{"unstarted_sample", "integrity_logical_samples", "OLD.completed_at IS NULL AND NEW.completed_at IS NOT NULL", true},
		{"unstarted_probe", "integrity_probe_instances", "NEW.status='COMPLETED'", true},
		{"unstarted_run", "integrity_runs", "OLD.execution_closed_at IS NULL AND NEW.execution_closed_at IS NOT NULL", true},
		{"unstarted_sample_partial", "integrity_logical_samples", "OLD.completed_at IS NULL AND NEW.completed_at IS NOT NULL", true},
		{"unstarted_probe_partial", "integrity_probe_instances", "NEW.status='COMPLETED'", true},
	} {
		t.Run(fault.name, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
				sampleCount := 1
				partial := strings.HasSuffix(fault.name, "_partial")
				if fault.name == "budget" || partial {
					sampleCount = 2 // Another unfinished sample prevents final-close checks masking the budget fault.
				}
				tenant, _, plan, policy := executionFixture(t, s, sampleCount)
				if fault.name == "unstarted_probe_partial" {
					second := plan.Probes[0]
					second.Samples = []domain.SamplePlan{plan.Probes[0].Samples[1]}
					second.Samples[0].Ordinal = 0
					plan.Probes[0].Samples = plan.Probes[0].Samples[:1]
					plan.Probes = append(plan.Probes, second)
				}
				var queue *JobQueue
				var job JobLease
				if fault.unstarted {
					if _, err := tenant.CreateRun(plan, policy, "atomic-plan"); err != nil {
						t.Fatal(err)
					}
					var err error
					queue, err = s.OpenJobQueue(tenant.ctx)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = queue.Close(t.Context()) })
					job = mustClaim(t, queue)
				} else {
					var samples []LogicalSampleRecord
					_, queue, samples = executionStart(t, tenant, plan, policy)
					job = mustClaim(t, queue)
					reserveTestAttempt(t, tenant, queue, job, samples[0])
				}
				if err := queue.Fail(tenant.ctx, job, "JOB_TEST_INTERRUPTED"); err != nil {
					t.Fatal(err)
				}
				sources, err := queue.LoadExecutionReconciliations(t.Context(), 1)
				if err != nil || len(sources) != 1 {
					t.Fatal("original source", err)
				}
				before := reconciliationAtomicRows(t, s)
				predicate := fault.predicate
				if partial {
					var ids []int64
					if err := s.db.Table(fault.table).Order("id").Pluck("id", &ids).Error; err != nil || len(ids) != 2 {
						t.Fatal("partial-suppression requires two real producer rows", err)
					}
					predicate += " AND OLD.id=" + strconv.FormatInt(ids[0], 10)
				}
				// Only the finite code-owned table/predicate pairs above are used.
				create := []string{"CREATE TRIGGER reconciliation_atomic_ignore BEFORE UPDATE ON " + fault.table + " WHEN " + predicate + " BEGIN SELECT RAISE(IGNORE); END"}
				if cfg.Driver == "postgres" {
					create = []string{"CREATE FUNCTION reconciliation_atomic_ignore_update() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$", "CREATE TRIGGER reconciliation_atomic_ignore BEFORE UPDATE ON " + fault.table + " FOR EACH ROW WHEN (" + predicate + ") EXECUTE FUNCTION reconciliation_atomic_ignore_update()"}
				}
				for _, statement := range create {
					if err := s.db.Exec(statement).Error; err != nil {
						t.Fatal("install exact update suppression", err)
					}
				}
				got, err := queue.ReconcileExecutionWithDerived(t.Context(), sources[0], nil)
				if err == nil || got != "" {
					t.Fatal("suppressed atomic update falsely succeeded", got, err)
				}
				if !reflect.DeepEqual(before, reconciliationAtomicRows(t, s)) {
					t.Fatal("failed settlement changed original domain, queue or audit facts")
				}
				drop := "DROP TRIGGER reconciliation_atomic_ignore"
				if cfg.Driver == "postgres" {
					drop += " ON " + fault.table
				}
				if err := s.db.Exec(drop).Error; err != nil {
					t.Fatal("remove exact fault trigger", err)
				}
				if cfg.Driver == "postgres" {
					if err := s.db.Exec("DROP FUNCTION reconciliation_atomic_ignore_update()").Error; err != nil {
						t.Fatal("remove exact fault function", err)
					}
				}
				for _, want := range []ExecutionReconciliationResult{ReconciliationApplied, ReconciliationAlreadyCompleted} {
					got, err = queue.ReconcileExecutionWithDerived(t.Context(), sources[0], nil)
					if err != nil || got != want {
						t.Fatal("same source did not settle exactly once after fault removal", got, err)
					}
				}
				if err := s.VerifyAllAudit(t.Context(), true); err != nil {
					t.Fatal("final authentic audit chain", err)
				}
			})
		})
	}
}

func TestExecutionAtomicBulkUpdateAllowsEmptySet(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, s, 1)
		if _, err := tenant.CreateRun(plan, policy, "empty-update-fixture"); err != nil {
			t.Fatal(err)
		}
		before := reconciliationAtomicRows(t, s)
		if err := s.db.Transaction(func(db *gorm.DB) error {
			return executionUpdateAll(db.Model(&ProbeRecord{}).Where("organization_id=? AND id=?", tenant.orgID, -1), map[string]any{"status": "COMPLETED"})
		}); err != nil || !reflect.DeepEqual(before, reconciliationAtomicRows(t, s)) {
			t.Fatal("empty original update predicate was rejected or changed data", err)
		}
	})
}

func reconciliationAtomicRows(t *testing.T, s *Store) map[string][]map[string]any {
	t.Helper()
	rows := map[string][]map[string]any{}
	for _, table := range []string{"integrity_runs", "integrity_logical_samples", "integrity_sample_attempts", "integrity_probe_instances", "integrity_attempt_derived", "integrity_jobs", "integrity_audit_logs", "integrity_audit_chain_heads"} {
		var values []map[string]any
		order := "id"
		switch table {
		case "integrity_audit_chain_heads":
			order = "organization_id"
		case "integrity_attempt_derived":
			order = "organization_id,attempt_id"
		}
		if err := s.db.Table(table).Order(order).Find(&values).Error; err != nil {
			t.Fatal("read fixed atomic fixture tables", err)
		}
		rows[table] = values
	}
	return rows
}
