package repository

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
)

// This is the real anonymous-login audit and settings path, not a hand-built
// imitation of their SQL. Test-only ORM observation gates impose this order:
// audit owns its chain head -> settings owns the organization policy row ->
// settings waits for the audit head -> audit inserts its organization FK.
// FOR UPDATE on the organization deadlocks here; NO KEY UPDATE must not.
func TestResponseRetentionAnonymousAuditForeignKeyDoesNotDeadlock(t *testing.T) {
	eachDatabase(t, func(t *testing.T, observer *Store, cfg Config) {
		if cfg.Driver != "postgres" {
			t.Skip("PostgreSQL row-lock/FK compatibility regression")
		}
		initial, auth, actorCtx := managementFixture(t, observer)
		anonymous, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = anonymous.Close() }()
		settings, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = settings.Close() }()
		var before auditChainHead
		if err := observer.db.Where("organization_id = ?", initial.Organization.ID).First(&before).Error; err != nil {
			t.Fatal("read initial audit head")
		}

		ctx, cancel := context.WithTimeout(actorCtx, 10*time.Second)
		defer cancel()
		anonymousCtx, cancelAnonymous := context.WithTimeout(testActorContext(t, 0), 10*time.Second)
		defer cancelAnonymous()
		auditHeadHeld := make(chan int, 1)
		policyHeld := make(chan int, 1)
		releaseInsert := make(chan struct{})
		var releaseOnce sync.Once
		release := func() { releaseOnce.Do(func() { close(releaseInsert) }) }
		defer release()
		sqlStates := make(chan string, 8)
		captureState := func(tx *gorm.DB) {
			var pgErr *pgconn.PgError
			if errors.As(tx.Error, &pgErr) {
				select {
				case sqlStates <- pgErr.Code:
				default:
				}
			}
		}
		if err := anonymous.db.Callback().Create().Before("gorm:create").Register("retention_test_hold_audit_insert", func(tx *gorm.DB) {
			if tx.Statement.Table != "integrity_audit_logs" || tx.Error != nil {
				return
			}
			var pid int
			if err := tx.Session(&gorm.Session{NewDB: true}).Raw("SELECT pg_backend_pid()").Scan(&pid).Error; err != nil {
				_ = tx.AddError(err)
				return
			}
			auditHeadHeld <- pid
			select {
			case <-releaseInsert:
			case <-anonymousCtx.Done():
				_ = tx.AddError(anonymousCtx.Err())
			}
		}); err != nil {
			t.Fatal("install anonymous observation gate")
		}
		if err := anonymous.db.Callback().Create().After("gorm:create").Register("retention_test_capture_audit_state", captureState); err != nil {
			t.Fatal("install anonymous SQL-state observation")
		}
		if err := settings.db.Callback().Query().After("gorm:query").Register("retention_test_observe_policy_lock", func(tx *gorm.DB) {
			captureState(tx)
			if tx.Statement.Table != "organizations" || tx.Error != nil {
				return
			}
			if _, locking := tx.Statement.Clauses["FOR"]; !locking {
				return
			}
			var pid int
			if err := tx.Session(&gorm.Session{NewDB: true}).Raw("SELECT pg_backend_pid()").Scan(&pid).Error; err != nil {
				_ = tx.AddError(err)
				return
			}
			policyHeld <- pid
		}); err != nil {
			t.Fatal("install policy-lock observation")
		}

		anonymousDone := make(chan error, 1)
		settingsDone := make(chan error, 1)
		go func() { anonymousDone <- anonymous.RecordAnonymousLoginFailure(anonymousCtx) }()
		var auditPID int
		select {
		case auditPID = <-auditHeadHeld:
		case err := <-anonymousDone:
			t.Fatal("anonymous audit did not reach its held head", err)
		case <-ctx.Done():
			t.Fatal("anonymous audit observation timed out")
		}
		zero := 0
		go func() {
			_, err := settings.ManageUpdateOrganization(ctx, auth, initial.Organization.ID, ManagedOrganizationPatch{ExpectedVersion: 1, FullResponseRetentionDays: &zero})
			settingsDone <- err
		}()
		var settingsPID int
		select {
		case settingsPID = <-policyHeld:
		case err := <-settingsDone:
			t.Fatal("settings did not reach its organization lock", err)
		case <-ctx.Done():
			t.Fatal("policy-lock observation timed out")
		}
		// Observe the actual PostgreSQL wait edge rather than assume that a sleep
		// means the setting transaction has reached appendAudit.
		responseRetentionWaitForBlocker(t, ctx, observer, settingsPID, auditPID)
		release()
		var anonymousErr, settingsErr error
		select {
		case anonymousErr = <-anonymousDone:
		case <-ctx.Done():
			t.Fatal("anonymous audit did not finish")
		}
		select {
		case settingsErr = <-settingsDone:
		case <-ctx.Done():
			t.Fatal("settings did not finish")
		}
		if anonymousErr != nil || settingsErr != nil {
			states := make([]string, 0, len(sqlStates))
			for len(sqlStates) > 0 {
				states = append(states, <-sqlStates)
			}
			// Fixed error classifications only: no SQL, identities or credentials.
			t.Fatalf("real audit/settings must both commit without retry: anonymous=%v settings=%v SQLSTATE=%v", anonymousErr, settingsErr, states)
		}
		org := retentionOrganization(t, observer, initial.Organization.ID)
		if org.Version != 2 || org.FullResponseRetentionDays != 0 || org.ResponseEvidenceNotBeforeMicros != org.UpdatedAt.UnixMicro() {
			t.Fatal("settings/cutoff did not commit exactly once")
		}
		var after auditChainHead
		if err := observer.db.Where("organization_id = ?", initial.Organization.ID).First(&after).Error; err != nil || after.EventCount != before.EventCount+2 {
			t.Fatal("two real operations did not append exactly two events")
		}
		for _, action := range []string{"auth.login_failed", "system.organization_update"} {
			var count int64
			if err := observer.db.Table("integrity_audit_logs").Where("organization_id = ? AND sequence > ? AND action = ?", initial.Organization.ID, before.EventCount, action).Count(&count).Error; err != nil || count != 1 {
				t.Fatal("concurrent operation audit missing or duplicated")
			}
		}
		if err := observer.VerifyAllAudit(ctx, true); err != nil {
			t.Fatal("concurrent audit chain failed full verification", err)
		}
	})
}

func responseRetentionWaitForBlocker(t *testing.T, ctx context.Context, observer *Store, blockedPID, blockerPID int) {
	t.Helper()
	if blockedPID <= 0 || blockerPID <= 0 || blockedPID == blockerPID {
		t.Fatal("invalid independent PostgreSQL backend identities")
	}
	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		if err := observer.db.WithContext(waitCtx).Raw("SELECT ? = ANY(pg_blocking_pids(?))", blockerPID, blockedPID).Scan(&blocked).Error; err != nil {
			t.Fatal("observe PostgreSQL wait relation")
		}
		if blocked {
			return
		}
		select {
		case <-ticker.C:
		case <-waitCtx.Done():
			t.Fatal("settings never waited on the held anonymous audit head")
		}
	}
}
