package repository

import (
	"errors"
	"testing"
)

// Mutation is confined to each test's disposable database. A still-valid
// operation/event must not authenticate a different current gate version/time.
func TestSystemMaintenanceCurrentStateMustMatchAuthenticatedEvent(t *testing.T) {
	for _, field := range []string{"version", "updated_at_micros"} {
		t.Run(field, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				_, auth, ctx := managementFixture(t, s)
				lease := beginTestMaintenance(t, s, ctx, auth)
				var original maintenanceState
				if err := s.db.Where("id=1").Take(&original).Error; err != nil {
					t.Fatal(err)
				}
				value := original.Version + 10
				if field == "updated_at_micros" {
					value = original.UpdatedAtMicros + 10
				}
				if err := s.db.Model(&maintenanceState{}).Where("id=1").Update(field, value).Error; err != nil {
					t.Fatal(err)
				}
				if _, err := lease.Observe(ctx); !errors.Is(err, ErrMaintenanceSource) {
					t.Fatal("changed singleton authenticated by original signed operation", field, err)
				}
				if _, err := s.ReadMaintenanceState(ctx); !errors.Is(err, ErrMaintenanceSource) {
					t.Fatal("state read accepted mismatched current event", field, err)
				}
				if _, err := s.ManageCreateUser(ctx, auth, ManagedUserCreate{Username: "invalid-freeze", PasswordHash: "synthetic-only"}); !errors.Is(err, ErrMaintenanceSource) {
					t.Fatal("business admission did not authenticate frozen state", field, err)
				}
			})
		})
	}
}

func TestSystemMaintenanceAdmissionRejectsOlderAuthenticatedState(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		_, auth, ctx := managementFixture(t, s)
		first := beginTestMaintenance(t, s, ctx, auth)
		if err := first.Abort(ctx); err != nil {
			t.Fatal(err)
		}
		var older maintenanceState
		if err := s.db.Where("id=1").Take(&older).Error; err != nil || older.OperationID == nil || *older.OperationID != first.operationID {
			t.Fatal("normal state did not retain its authenticated terminal source", err)
		}
		second := beginTestMaintenance(t, s, ctx, auth)
		if err := second.Abort(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ManageCreateUser(ctx, auth, ManagedUserCreate{Username: "genuine-reopen", PasswordHash: "synthetic-only"}); err != nil {
			t.Fatal("authenticated normal state did not reopen business admission", err)
		}
		if err := s.db.Model(&maintenanceState{}).Where("id=1").Updates(map[string]any{
			"mode": older.Mode, "version": older.Version, "generation": older.Generation,
			"operation_id": older.OperationID, "updated_at_micros": older.UpdatedAtMicros,
		}).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := s.ReadMaintenanceState(ctx); !errors.Is(err, ErrMaintenanceSource) {
			t.Fatal("older valid operation concealed newer immutable history", err)
		}
		if _, err := s.ManageCreateUser(ctx, auth, ManagedUserCreate{Username: "older-pointer", PasswordHash: "synthetic-only"}); !errors.Is(err, ErrMaintenanceSource) {
			t.Fatal("older authenticated state reopened admission", err)
		}
	})
}

func TestSystemMaintenanceAdmissionRejectsOlderAuthenticatedEvent(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		_, auth, ctx := managementFixture(t, s)
		lease := beginTestMaintenance(t, s, ctx, auth)
		var older maintenanceState
		var oldOp maintenanceOperation
		if err := s.db.Where("id=1").Take(&older).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.db.Where("id=?", lease.operationID).Take(&oldOp).Error; err != nil {
			t.Fatal(err)
		}
		if err := lease.Renew(ctx); err != nil {
			t.Fatal(err)
		}
		if err := s.db.Model(&maintenanceOperation{}).Where("id=?", lease.operationID).Updates(map[string]any{
			"event_sequence": oldOp.EventSequence, "event_digest": oldOp.EventDigest,
			"lease_until_micros": oldOp.LeaseUntilMicros, "updated_at_micros": oldOp.UpdatedAtMicros,
		}).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.db.Model(&maintenanceState{}).Where("id=1").Updates(map[string]any{
			"version": older.Version, "lease_until_micros": older.LeaseUntilMicros,
			"updated_at_micros": older.UpdatedAtMicros,
		}).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := s.ReadMaintenanceState(ctx); !errors.Is(err, ErrMaintenanceSource) {
			t.Fatal("older event pointer concealed a later immutable renewal", err)
		}
		if err := lease.Renew(ctx); !errors.Is(err, ErrMaintenanceSource) {
			t.Fatal("coordinator accepted an older authenticated event", err)
		}
	})
}

func TestSystemMaintenanceAdmissionRejectsDowngradedInitialState(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		_, auth, ctx := managementFixture(t, s)
		_ = beginTestMaintenance(t, s, ctx, auth)
		// This is deliberately the entire valid initial singleton shape. The
		// signed operation history remains, so resetting only the gate must not
		// reopen admission or report a trustworthy initial state.
		if err := s.db.Model(&maintenanceState{}).Where("id=1").Updates(map[string]any{
			"mode": MaintenanceNormal, "version": 1, "generation": 0,
			"operation_id": nil, "owner": "", "lease_until_micros": 0,
			"deadline_micros": 0, "updated_at_micros": 0,
		}).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := s.ReadMaintenanceState(ctx); !errors.Is(err, ErrMaintenanceSource) {
			t.Error("state read accepted downgraded singleton with signed history", err)
		}
		if _, err := s.ManageCreateUser(ctx, auth, ManagedUserCreate{Username: "must-stay-blocked", PasswordHash: "synthetic-only"}); !errors.Is(err, ErrMaintenanceSource) {
			t.Error("business admission accepted downgraded singleton with signed history", err)
		}
	})
}
