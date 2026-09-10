package repository

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func TestBackupDrainExecutionActualTwoHeadsAndIndependentWriter(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		initial, _, plan, policy := executionFixture(t, s, 1)
		auth := backupDrainTestAuthority(t, s, initial.ctx)
		roles := managementFixtureRoles()
		roles[0].Permissions = append(roles[0].Permissions, "run.create", "run.custom", "run.high-cost")
		org, err := s.ManageCreateOrganization(initial.ctx, auth, ManagedOrganizationCreate{Name: "execution second organization", Timezone: "UTC", Roles: roles})
		if err != nil {
			t.Fatal(err)
		}
		ctx := bindTargetTestSession(t, s, initial.ctx, auth.SessionID, org.ID)
		tenant, err := s.WithOrganization(ctx, org.ID)
		if err != nil {
			t.Fatal(err)
		}
		target := mustCreateTarget(t, tenant)
		plan.Target.ID, plan.Target.SecretID = target.Target.ID, target.Secret.ID
		_, queue, samples := executionStart(t, tenant, plan, policy)
		job := mustClaim(t, queue)
		reserveTestAttempt(t, tenant, queue, job, samples[0])
		if err := queue.Retry(ctx, job, "JOB_TEST_PROCESS_LOSS", time.Hour); err != nil {
			t.Fatal(err)
		}
		freeze := beginTestMaintenance(t, s, initial.ctx, auth)
		candidate, _, err := freeze.LoadBackupDrainCandidate(initial.ctx)
		if err != nil {
			t.Fatal(err)
		}
		source, err := freeze.LoadBackupExecutionSource(initial.ctx, candidate)
		if err != nil {
			t.Fatal(err)
		}
		before := reconciliationAtomicRows(t, s)
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		held, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		holdCtx, cancel := context.WithCancel(initial.ctx)
		var holdErr error
		var once sync.Once
		releaseHolder := func() { once.Do(func() { close(release) }) }
		go func() {
			defer close(done)
			holdErr = other.db.WithContext(holdCtx).Transaction(func(db *gorm.DB) error {
				// A genuine independent SQL writer has no maintenance-gate lock.
				if err := db.Exec("UPDATE integrity_audit_chain_heads SET event_count=event_count WHERE organization_id=?", org.ID).Error; err != nil {
					return err
				}
				close(held)
				select {
				case <-release:
					return nil
				case <-holdCtx.Done():
					return holdCtx.Err()
				}
			})
		}()
		defer func() { cancel(); releaseHolder(); <-done }()
		select {
		case <-held:
		case <-done:
			t.Fatal("independent writer failed", holdErr)
		case <-time.After(3 * time.Second):
			t.Fatal("independent writer did not obtain actual head")
		}
		bounded, stop := context.WithTimeout(initial.ctx, 150*time.Millisecond)
		got, err := freeze.ApplyBackupExecutionSource(bounded, source, nil)
		stop()
		if got != "" || (!errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, ErrUnavailable)) {
			t.Fatal("independent head writer ignored", got, err)
		}
		releaseHolder()
		<-done
		if holdErr != nil {
			t.Fatal(holdErr)
		}
		if !reflect.DeepEqual(before, reconciliationAtomicRows(t, s)) {
			t.Fatal("blocked two-head transaction partially settled")
		}
		ids := []int64{initial.orgID, org.ID}
		slices.Sort(ids)
		var observed []int64
		name := "backup_execution_two_head_order"
		if err := s.db.Callback().Query().After("gorm:query").Register(name, func(db *gorm.DB) {
			head, ok := db.Statement.Dest.(*auditChainHead)
			if !ok || db.Error != nil || len(observed) == 2 {
				return
			}
			if cfg.Driver == "postgres" {
				lock, ok := db.Statement.Clauses["FOR"].Expression.(clause.Locking)
				if !ok || lock.Strength != "UPDATE" {
					_ = db.AddError(errors.New("expected actual head UPDATE lock"))
					return
				}
			}
			observed = append(observed, head.OrganizationID)
		}); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.db.Callback().Query().Remove(name) }()
		if got, err := freeze.ApplyBackupExecutionSource(initial.ctx, source, nil); err != nil || got != ReconciliationApplied || !slices.Equal(observed, ids) {
			t.Fatal("two-head ascending locks", got, err)
		}
		if err := s.db.Callback().Query().Remove(name); err != nil {
			t.Fatal(err)
		}
		var events []audit.Event
		if err := s.db.Where("action IN ?", []string{"system.backup.drain.execution.uncertain", "run.attempt.finish"}).Find(&events).Error; err != nil {
			t.Fatal(err)
		}
		if len(events) != 2 {
			t.Fatal("missing independent domain/system audits", len(events))
		}
		for _, event := range events {
			want := org.ID
			if event.Action == "system.backup.drain.execution.uncertain" {
				want = initial.orgID
			}
			if event.OrganizationID != want {
				t.Fatal("domain/system anchor mixed")
			}
		}
		if err := s.VerifyAllAudit(initial.ctx, true); err != nil {
			t.Fatal(err)
		}
	})
}

func TestBackupDrainExecutionActualConcurrentReplayOnlyOnce(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, freeze, candidate, _, _, _ := backupDrainExecutionFixture(t, s, "pending", true)
		source, err := freeze.LoadBackupExecutionSource(tenant.ctx, candidate)
		if err != nil {
			t.Fatal(err)
		}
		type outcome struct {
			got ExecutionReconciliationResult
			err error
		}
		results := make(chan outcome, 2)
		start := make(chan struct{})
		for range 2 {
			go func() {
				<-start
				got, err := freeze.ApplyBackupExecutionSource(tenant.ctx, source, nil)
				results <- outcome{got, err}
			}()
		}
		close(start)
		applied, stale := 0, 0
		for range 2 {
			result := <-results
			switch {
			case result.err == nil && result.got == ReconciliationApplied:
				applied++
			case errors.Is(result.err, ErrBackupDrainStale) && result.got == "":
				stale++
			default:
				t.Fatal("concurrent outcome", result.got, result.err)
			}
		}
		if applied != 1 || stale != 1 {
			t.Fatal("concurrent source settled more than once")
		}
		var run RunRecord
		if err := s.db.Take(&run).Error; err != nil || run.RequestCount != 1 || run.TokenCount != 38 || run.ReservedTokens != 0 {
			t.Fatal("concurrent accounting", err)
		}
		if err := s.VerifyAllAudit(tenant.ctx, true); err != nil {
			t.Fatal(err)
		}
	})
}
