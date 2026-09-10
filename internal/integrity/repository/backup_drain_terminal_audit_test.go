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

func TestBackupDrainTerminalApplyTwoAuditHeadsAndExternalWriter(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		initial, auth, actorCtx := managementFixture(t, s)
		roles := managementFixtureRoles()
		roles[0].Permissions = append(roles[0].Permissions, "target.precheck")
		org, err := s.ManageCreateOrganization(actorCtx, auth, ManagedOrganizationCreate{Name: "second drain organization", Timezone: "UTC", Roles: roles})
		if err != nil {
			t.Fatal(err)
		}
		ctx := bindTargetTestSession(t, s, actorCtx, auth.SessionID, org.ID)
		tenant, err := s.WithOrganization(ctx, org.ID)
		if err != nil {
			t.Fatal(err)
		}
		target := mustCreateTarget(t, tenant)
		record, err := tenant.EnqueuePrecheck(PrecheckRecord{OrganizationID: org.ID, TargetID: target.Target.ID, TargetVersion: 1, SecretID: target.Secret.ID, SecretVersion: 1, RequestKey: "two-head-drain", SnapshotJSON: "{}"})
		if err != nil {
			t.Fatal(err)
		}
		queue, err := s.OpenJobQueue(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = queue.Close(context.Background()) }()
		job := mustClaim(t, queue)
		if err := queue.WithLease(ctx, job, func(tx *TenantTransaction) error {
			if _, err := tx.BeginPrecheck(record.ID, job.Job.ID); err != nil {
				return err
			}
			return tx.ReservePrecheckRequest(record.ID, job.Job.ID)
		}); err != nil {
			t.Fatal(err)
		}
		backupDrainTerminalExpire(t, s, job.Job.ID)
		freeze := beginTestMaintenance(t, s, actorCtx, auth)
		source := backupDrainTerminalLoad(t, freeze, actorCtx, job.Job.ID)
		before := backupDrainTerminalRows(t, s)
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		held, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		holderCtx, cancel := context.WithCancel(actorCtx)
		var holdErr error
		var once sync.Once
		releaseHolder := func() { once.Do(func() { close(release) }) }
		go func() {
			defer close(done)
			holdErr = other.db.WithContext(holderCtx).Transaction(func(db *gorm.DB) error {
				// Real audit-head writer outside the maintenance gate. It keeps the
				// authentic tail unchanged; the lock itself must still fence Apply.
				if err := db.Exec("UPDATE integrity_audit_chain_heads SET event_count=event_count WHERE organization_id=?", org.ID).Error; err != nil {
					return err
				}
				close(held)
				select {
				case <-release:
					return nil
				case <-holderCtx.Done():
					return holderCtx.Err()
				}
			})
		}()
		defer func() { cancel(); releaseHolder(); <-done }()
		select {
		case <-held:
		case <-done:
			t.Fatal("real head lock failed", holdErr)
		case <-time.After(3 * time.Second):
			t.Fatal("real head lock barrier not reached")
		}
		bounded, stop := context.WithTimeout(actorCtx, 150*time.Millisecond)
		result, err := freeze.ApplyBackupTerminalCandidate(bounded, source)
		stop()
		if (!errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, ErrUnavailable)) || result != (BackupDrainTerminalResult{}) {
			t.Fatal("external audit-head writer was ignored", result, err)
		}
		releaseHolder()
		<-done
		if holdErr != nil {
			t.Fatal("head holder did not finish normally", holdErr)
		}
		if !reflect.DeepEqual(before, backupDrainTerminalRows(t, s)) {
			t.Fatal("blocked audit transaction left partial terminal facts")
		}
		ids := []int64{initial.Organization.ID, org.ID}
		slices.Sort(ids)
		var observed []int64
		const queryCallback = "backup_terminal_first_audit_head_locks"
		if err := s.db.Callback().Query().After("gorm:query").Register(queryCallback, func(db *gorm.DB) {
			head, ok := db.Statement.Dest.(*auditChainHead)
			if !ok || db.Error != nil || len(observed) == 2 {
				return
			}
			if cfg.Driver == "postgres" {
				lock, ok := db.Statement.Clauses["FOR"].Expression.(clause.Locking)
				if !ok || lock.Strength != "UPDATE" {
					_ = db.AddError(errors.New("test expected actual row lock"))
					return
				}
			}
			observed = append(observed, head.OrganizationID)
		}); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.db.Callback().Query().Remove(queryCallback) }()
		if result, err := freeze.ApplyBackupTerminalCandidate(actorCtx, source); err != nil || !result.Applied || !slices.Equal(observed, ids) {
			t.Fatal("domain/system heads were not both prelocked in order", result, err)
		}
		if err := s.db.Callback().Query().Remove(queryCallback); err != nil {
			t.Fatal(err)
		}
		backupDrainTerminalAssertAudit(t, s, source, freeze, "precheck_uncertain", initial.User.ID, "target.precheck.reconcile")
		var events []audit.Event
		if err := s.db.Where("action IN ?", []string{"system.backup.drain.precheck_uncertain", "target.precheck.reconcile"}).Order("organization_id").Find(&events).Error; err != nil || len(events) != 2 {
			t.Fatal("separate real audit events", err)
		}
		for _, event := range events {
			want := org.ID
			if event.Action == "system.backup.drain.precheck_uncertain" {
				want = initial.Organization.ID
			}
			if event.OrganizationID != want {
				t.Fatal("domain/system audit anchor mixed")
			}
		}
	})
}
