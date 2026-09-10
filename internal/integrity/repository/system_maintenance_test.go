package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func beginTestMaintenance(t *testing.T, s *Store, ctx context.Context, auth ManagementAuthority) *MaintenanceLease {
	t.Helper()
	state, err := s.ReadMaintenanceState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := s.BeginBackupMaintenance(ctx, auth, BackupMaintenanceRequest{ExpectedVersion: state.Version, ReasonCode: "backup.manual", MaxDuration: time.Hour})
	if err != nil {
		t.Fatal("begin maintenance", err)
	}
	return lease
}

func TestSystemMaintenanceLifecycleAuthenticatedImmutableEvents(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		initial, auth, ctx := managementFixture(t, s)
		lease := beginTestMaintenance(t, s, ctx, auth)
		if data, err := json.Marshal(lease); err == nil || len(data) != 0 {
			t.Fatal("maintenance capability serialized")
		}
		if strings.Contains(fmt.Sprintf("%+v", *lease), lease.owner) {
			t.Fatal("owner token formatting leak")
		}
		if err := lease.Renew(ctx); err != nil {
			t.Fatal("renew", err)
		}
		observation, err := lease.Observe(ctx)
		if err != nil || observation.RunningJobPresent || observation.ExpiredJobPresent || observation.UnsettledAttemptPresent {
			t.Fatal("bounded observation invented snapshot authority", observation, err)
		}
		if _, err := s.BeginBackupMaintenance(ctx, auth, BackupMaintenanceRequest{ExpectedVersion: 3, ReasonCode: "backup.manual", MaxDuration: time.Hour}); !errors.Is(err, ErrSystemMaintenance) {
			t.Fatal("concurrent active operation accepted", err)
		}
		if err := lease.Abort(ctx); err != nil {
			t.Fatal("abort", err)
		}
		if err := lease.Renew(ctx); !errors.Is(err, ErrMaintenanceLeaseLost) {
			t.Fatal("terminal capability resurrected", err)
		}
		state, err := s.ReadMaintenanceState(ctx)
		if err != nil || state.Mode != MaintenanceNormal || state.Generation != 1 || state.Version != 4 {
			t.Fatal("incorrect lifecycle state", state, err)
		}
		var events []maintenanceEvent
		if err := s.db.Where("operation_id=?", lease.operationID).Order("sequence").Find(&events).Error; err != nil || len(events) != 3 {
			t.Fatal("events missing", err)
		}
		var op maintenanceOperation
		if err := s.db.Where("id=?", lease.operationID).Take(&op).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := s.verifyMaintenanceOperation(s.db, op); err != nil {
			t.Fatal("signed operation cannot verify", err)
		}
		for _, event := range events {
			if event.Scope != "system" || len(maintenanceEventObject(event)) > 128 {
				t.Fatal("system event scope or ObjectID bound")
			}
			var signed audit.Event
			if err := s.db.Where("organization_id=? AND object_id=?", initial.Organization.ID, maintenanceEventObject(event)).Take(&signed).Error; err != nil || audit.Verify(signed, s.auditSigner) != nil {
				t.Fatal("system anchor missing or unauthenticated", err)
			}
			data, _ := json.Marshal(event)
			if strings.Contains(string(data), lease.owner) {
				t.Fatal("owner in public event facts")
			}
		}
		if err := s.db.Model(&maintenanceEvent{}).Where("operation_id=?", lease.operationID).Update("reason_code", "backup.upgrade").Error; err == nil {
			t.Fatal("immutable event updated")
		}
		if err := s.db.Where("operation_id=?", lease.operationID).Delete(&maintenanceEvent{}).Error; err == nil {
			t.Fatal("immutable event deleted")
		}
		if err := s.db.Where("id=?", lease.operationID).Delete(&maintenanceOperation{}).Error; err == nil {
			t.Fatal("operation history deleted")
		}
		if err := s.VerifyAllAudit(ctx, true); err != nil {
			t.Fatal("system audit chain", err)
		}
	})
}

func TestSystemMaintenanceRejectsForgedAuthorityAndMissingState(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		initial, auth, ctx := managementFixture(t, s)
		other := managementFixtureUser(t, s, ctx, auth, "organization-only-admin")
		otherAuth := managementSession(t, s, other)
		otherCtx := testActorContext(t, other.ID)
		request := BackupMaintenanceRequest{ExpectedVersion: 1, ReasonCode: "backup.manual", MaxDuration: time.Hour}
		if _, err := s.BeginBackupMaintenance(otherCtx, otherAuth, request); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("non-system actor accepted", err)
		}
		if _, err := s.BeginBackupMaintenance(ctx, otherAuth, request); !errors.Is(err, audit.ErrActorRequired) {
			t.Fatal("actor mismatch accepted", err)
		}
		if err := s.db.Model(&User{}).Where("id=?", other.ID).Update("is_system_admin", true).Error; err != nil {
			t.Fatal(err)
		}
		// No membership is added: system auditing must not depend on memberships.
		lease := beginTestMaintenance(t, s, otherCtx, otherAuth)
		var event audit.Event
		if err := s.db.Where("organization_id=? AND action='system.maintenance.begin'", initial.Organization.ID).Take(&event).Error; err != nil || event.ActorID == nil || *event.ActorID != other.ID {
			t.Fatal("non-member system actor lost its global audit", err)
		}
		if err := lease.Abort(otherCtx); err != nil {
			t.Fatal(err)
		}
		if err := s.db.Where("id=1").Delete(&maintenanceState{}).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := s.ReadMaintenanceState(ctx); !errors.Is(err, ErrMaintenanceSource) {
			t.Fatal("missing gate defaulted to normal", err)
		}
		if _, err := s.ManageCreateUser(ctx, auth, ManagedUserCreate{Username: "blocked-user", PasswordHash: "synthetic-only"}); !errors.Is(err, ErrMaintenanceSource) {
			t.Fatal("missing gate allowed business mutation", err)
		}
	})
}

func TestSystemMaintenanceAuditFailureAndNaturalAuthorityExpiryRollback(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		_, auth, ctx := managementFixture(t, s)
		injected := errors.New("synthetic audit failure; never returned")
		if err := s.db.Callback().Create().Before("gorm:create").Register("maintenance_test_audit_fail", func(db *gorm.DB) {
			event, ok := db.Statement.Dest.(*audit.Event)
			if ok && event.Action == "system.maintenance.begin" {
				_ = db.AddError(injected)
			}
		}); err != nil {
			t.Fatal(err)
		}
		_, err := s.BeginBackupMaintenance(ctx, auth, BackupMaintenanceRequest{ExpectedVersion: 1, ReasonCode: "backup.manual", MaxDuration: time.Hour})
		if !errors.Is(err, ErrUnavailable) {
			t.Fatal("audit failure classification", err)
		}
		if err := s.db.Callback().Create().Remove("maintenance_test_audit_fail"); err != nil {
			t.Fatal(err)
		}
		assertMaintenanceNoOperation(t, s, ctx)
		expiry := time.Now().UTC().Add(200 * time.Millisecond)
		if err := s.db.Model(&Session{}).Where("id=?", auth.SessionID).Update("expires_at", expiry).Error; err != nil {
			t.Fatal(err)
		}
		entered := false
		if err := s.db.Callback().Create().After("gorm:create").Register("maintenance_test_expiry", func(db *gorm.DB) {
			event, ok := db.Statement.Dest.(*audit.Event)
			if !ok || event.Action != "system.maintenance.begin" {
				return
			}
			entered = true
			if !expiry.After(time.Now()) {
				_ = db.AddError(errors.New("fixture did not enter before expiry"))
				return
			}
			timer := time.NewTimer(time.Until(expiry) + 20*time.Millisecond)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-db.Statement.Context.Done():
				_ = db.AddError(db.Statement.Context.Err())
			}
		}); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.db.Callback().Create().Remove("maintenance_test_expiry") }()
		_, err = s.BeginBackupMaintenance(ctx, auth, BackupMaintenanceRequest{ExpectedVersion: 1, ReasonCode: "backup.manual", MaxDuration: time.Hour})
		if !entered || !errors.Is(err, ErrManagementSession) {
			t.Fatal("natural session expiry committed freeze", entered, err)
		}
		assertMaintenanceNoOperation(t, s, ctx)
	})
}

func assertMaintenanceNoOperation(t *testing.T, s *Store, ctx context.Context) {
	t.Helper()
	state, err := s.ReadMaintenanceState(ctx)
	if err != nil || state.Mode != MaintenanceNormal || state.Version != 1 || state.Generation != 0 {
		t.Fatal("failed operation changed admission", state, err)
	}
	for _, table := range []string{"system_maintenance_operations", "system_maintenance_events"} {
		var count int64
		if err := s.db.Table(table).Count(&count).Error; err != nil || count != 0 {
			t.Fatal("failed operation left persistent rows", table, count, err)
		}
	}
}
