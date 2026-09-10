package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

func retentionOrganization(t *testing.T, s *Store, orgID int64) Organization {
	t.Helper()
	var org Organization
	if err := s.db.Where("id = ?", orgID).First(&org).Error; err != nil {
		t.Fatal("read scoped retention organization")
	}
	return org
}

func retentionPolicy(t *testing.T, s *Store, ctx context.Context, orgID int64) ResponseRetentionPolicy {
	t.Helper()
	tenant, err := s.WithOrganization(ctx, orgID)
	if err != nil {
		t.Fatal(err)
	}
	p, err := tenant.GetResponseRetentionPolicy()
	if err != nil {
		t.Fatal("read scoped retention policy", err)
	}
	return p
}

func updateRetention(t *testing.T, s *Store, ctx context.Context, auth ManagementAuthority, orgID int64, days int) Organization {
	t.Helper()
	old := retentionOrganization(t, s, orgID)
	got, err := s.ManageUpdateOrganization(ctx, auth, orgID, ManagedOrganizationPatch{ExpectedVersion: old.Version, FullResponseRetentionDays: &days})
	if err != nil || got.Version != old.Version+1 || got.FullResponseRetentionDays != days {
		t.Fatal("actual retention settings update", err)
	}
	current := retentionOrganization(t, s, orgID)
	want := max(old.ResponseEvidenceNotBeforeMicros, current.UpdatedAt.UnixMicro()-int64(old.FullResponseRetentionDays)*responseRetentionDayMicros, current.UpdatedAt.UnixMicro()-int64(days)*responseRetentionDayMicros)
	if current.ResponseEvidenceNotBeforeMicros != want {
		t.Fatal("cutoff did not use one authoritative update clock")
	}
	return current
}

func TestResponseRetentionActualSettingsNeverReviveHistoricalBody(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		initial, auth, ctx := managementFixture(t, s)
		orgID := initial.Organization.ID
		initialPolicy := retentionPolicy(t, s, ctx, orgID)
		if initialPolicy.OrganizationID() != orgID || initialPolicy.Days() != 30 || initialPolicy.Version() != 1 || initialPolicy.NotBeforeMicros() != 0 || initialPolicy.ObservedAtMicros() <= 0 {
			t.Fatal("invalid default retention observation")
		}
		recent := initialPolicy.ObservedAtMicros() - responseRetentionDayMicros
		sealedExpiry := recent + 30*responseRetentionDayMicros
		if !initialPolicy.EligibleAtObservation(recent, sealedExpiry, false) {
			t.Fatal("fresh fixed-expiry evidence unexpectedly unavailable")
		}
		zero := updateRetention(t, s, ctx, auth, orgID, 0)
		if zero.ResponseEvidenceNotBeforeMicros != zero.UpdatedAt.UnixMicro() {
			t.Fatal("zero retention did not close at its own update time")
		}
		closed := retentionPolicy(t, s, ctx, orgID)
		if closed.EligibleAtObservation(recent, sealedExpiry, false) || closed.EligibleAtObservation(closed.ObservedAtMicros(), closed.ObservedAtMicros()+responseRetentionDayMicros, false) {
			t.Fatal("zero retention still permits body")
		}
		enabled := updateRetention(t, s, ctx, auth, orgID, 30)
		if enabled.ResponseEvidenceNotBeforeMicros != enabled.UpdatedAt.UnixMicro() {
			t.Fatal("zero-to-thirty did not seal entire disabled interval")
		}
		policy := retentionPolicy(t, s, ctx, orgID)
		if policy.EligibleAtObservation(recent, sealedExpiry, false) || policy.EligibleAtObservation(zero.UpdatedAt.UnixMicro(), sealedExpiry, false) || policy.EligibleAtObservation(enabled.ResponseEvidenceNotBeforeMicros, sealedExpiry, false) {
			t.Fatal("reenabling revived pre-cutoff or same-microsecond body")
		}
		// Increasing a nonzero window cannot reduce the closed historical cutoff.
		longer := updateRetention(t, s, ctx, auth, orgID, 180)
		if longer.ResponseEvidenceNotBeforeMicros < enabled.ResponseEvidenceNotBeforeMicros {
			t.Fatal("longer retention lowered cutoff")
		}
		if retentionPolicy(t, s, ctx, orgID).EligibleAtObservation(recent, sealedExpiry, false) {
			t.Fatal("thirty-to-180 revived closed evidence")
		}
		if err := s.VerifyAllAudit(ctx, true); err != nil {
			t.Fatal("retention audit chain invalid", err)
		}
	})
}

func TestResponseRetentionShortenExtendAndNonRetentionEdit(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		initial, auth, ctx := managementFixture(t, s)
		orgID := initial.Organization.ID
		before := retentionPolicy(t, s, ctx, orgID)
		oldBody := before.ObservedAtMicros() - 8*responseRetentionDayMicros
		expiry := oldBody + 30*responseRetentionDayMicros
		if !before.EligibleAtObservation(oldBody, expiry, false) {
			t.Fatal("fixture not originally eligible")
		}
		short := updateRetention(t, s, ctx, auth, orgID, 7)
		if retentionPolicy(t, s, ctx, orgID).EligibleAtObservation(oldBody, expiry, false) {
			t.Fatal("shortened retention ignored current window")
		}
		long := updateRetention(t, s, ctx, auth, orgID, 30)
		if long.ResponseEvidenceNotBeforeMicros < short.ResponseEvidenceNotBeforeMicros || retentionPolicy(t, s, ctx, orgID).EligibleAtObservation(oldBody, expiry, false) {
			t.Fatal("longer policy revived shortened evidence")
		}
		name, zone, status := "Updated retention fixture", "Asia/Shanghai", "disabled"
		if _, err := s.ManageUpdateOrganization(ctx, auth, orgID, ManagedOrganizationPatch{ExpectedVersion: long.Version, Name: &name, Timezone: &zone, Status: &status}); err != nil {
			t.Fatal(err)
		}
		other := retentionOrganization(t, s, orgID)
		if other.ResponseEvidenceNotBeforeMicros != long.ResponseEvidenceNotBeforeMicros || other.FullResponseRetentionDays != 30 {
			t.Fatal("unrelated edit changed retention boundary")
		}
		if retentionPolicy(t, s, ctx, orgID).EligibleAtObservation(other.UpdatedAt.UnixMicro(), other.UpdatedAt.UnixMicro()+responseRetentionDayMicros, false) {
			t.Fatal("disabled organization allowed evidence")
		}
		// Explicitly reapplying the same days is still a retention operation.
		reapplied := updateRetention(t, s, ctx, auth, orgID, 30)
		if reapplied.ResponseEvidenceNotBeforeMicros < long.ResponseEvidenceNotBeforeMicros {
			t.Fatal("same-days update regressed cutoff")
		}
	})
}

func TestResponseRetentionEligibilityHasStrictIndependentBoundaries(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC).UnixMicro()
	base := ResponseRetentionPolicy{organizationID: 1, days: 30, version: 1, observedAtMicros: now, notBeforeMicros: now - 40*responseRetentionDayMicros, active: true}
	for _, test := range []struct {
		name             string
		policy           ResponseRetentionPolicy
		captured, expiry int64
		deleted, want    bool
	}{
		{"normal", base, now - 1, now + 1, false, true},
		{"captured_now", base, now, now + 1, false, true},
		{"future", base, now + 1, now + 2, false, false},
		{"zero_time", base, 0, now + 1, false, false},
		{"expired", base, now - 2, now - 1, false, false},
		{"sealed_equal_now", base, now - 1, now, false, false},
		{"current_window_equal", base, now - 30*responseRetentionDayMicros, now + responseRetentionDayMicros, false, false},
		{"inside_current_window", base, now - 30*responseRetentionDayMicros + 1, now + responseRetentionDayMicros, false, true},
		{"deleted", base, now - 1, now + 1, true, false},
		{"empty_observation", ResponseRetentionPolicy{}, now - 1, now + 1, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.policy.EligibleAtObservation(test.captured, test.expiry, test.deleted); got != test.want {
				t.Fatal("incorrect strict retention window")
			}
		})
	}
	for _, days := range []int{-1, 0, 181} {
		invalid := base
		invalid.days = days
		if invalid.EligibleAtObservation(now-1, now+1, false) {
			t.Fatal("invalid or zero day policy allowed body")
		}
	}
	cut := base
	cut.notBeforeMicros = now - 1
	if cut.EligibleAtObservation(now-1, now+1, false) || !cut.EligibleAtObservation(now, now+1, false) {
		t.Fatal("cutoff equality not strict")
	}
	long := base
	long.days = 180
	if long.EligibleAtObservation(now-1, now, false) {
		t.Fatal("long policy extended immutable expiry")
	}
	var fromHTTP ResponseRetentionPolicy
	if err := json.Unmarshal([]byte(`{"organizationID":1,"days":180,"version":1,"observedAtMicros":1,"active":true}`), &fromHTTP); !errors.Is(err, ErrConfiguration) {
		t.Fatal("HTTP policy transport was not explicitly rejected")
	}
	if _, err := json.Marshal(base); !errors.Is(err, ErrConfiguration) {
		t.Fatal("internal policy serialized as a transport object")
	}
	if fromHTTP.EligibleAtObservation(1, 2, false) || fromHTTP.OrganizationID() != 0 {
		t.Fatal("HTTP object constructed internal retention observation")
	}
}

func TestResponseRetentionDatabaseGuardCannotMoveCutoffBackward(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		initial, _, _ := managementFixture(t, s)
		orgID := initial.Organization.ID
		// These direct SQL calls test the DB guard, not a supported settings API.
		for _, cutoff := range []int64{100, 100, 101} {
			if err := s.db.Exec("UPDATE organizations SET response_evidence_not_before_micros=? WHERE id=?", cutoff, orgID).Error; err != nil {
				t.Fatal("valid monotonic DB update rejected")
			}
		}
		for _, cutoff := range []int64{100, 0, -1} {
			if err := s.db.Exec("UPDATE organizations SET response_evidence_not_before_micros=? WHERE id=?", cutoff, orgID).Error; err == nil {
				t.Fatal("direct SQL lowered protected cutoff")
			}
			if retentionOrganization(t, s, orgID).ResponseEvidenceNotBeforeMicros != 101 {
				t.Fatal("failed SQL changed cutoff")
			}
		}
	})
}

func TestResponseRetentionAuditFailureRollsBackBothOrganizationsAndPolicy(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		initial, auth, ctx := managementFixture(t, s)
		created, err := s.ManageCreateOrganization(ctx, auth, ManagedOrganizationCreate{Name: "Retention second org", Timezone: "UTC", Roles: managementFixtureRoles()})
		if err != nil {
			t.Fatal(err)
		}
		before := retentionOrganization(t, s, created.ID)
		var headsBefore []auditChainHead
		if err := s.db.Order("organization_id").Find(&headsBefore).Error; err != nil {
			t.Fatal(err)
		}
		failureOrg := max(initial.Organization.ID, created.ID)
		condition := fmt.Sprintf("action = 'system.organization_update' AND organization_id = %d", failureOrg)
		statement := "ALTER TABLE integrity_audit_logs ADD CONSTRAINT retention_fixture_audit_failure CHECK (NOT (" + condition + ")) NOT VALID"
		if cfg.Driver == "sqlite" {
			statement = fmt.Sprintf("CREATE TRIGGER retention_fixture_audit_failure BEFORE INSERT ON integrity_audit_logs WHEN NEW.action = 'system.organization_update' AND NEW.organization_id = %d BEGIN SELECT RAISE(ABORT, 'synthetic retention audit failure'); END", failureOrg)
		}
		if err := s.db.Exec(statement).Error; err != nil {
			t.Fatal("install real audit failure")
		}
		zero := 0
		if _, err := s.ManageUpdateOrganization(ctx, auth, created.ID, ManagedOrganizationPatch{ExpectedVersion: before.Version, FullResponseRetentionDays: &zero}); err == nil {
			t.Fatal("settings committed through audit SQL failure")
		}
		if !reflect.DeepEqual(before, retentionOrganization(t, s, created.ID)) {
			t.Fatal("audit failure did not roll back days/cutoff/version/time")
		}
		var headsAfter []auditChainHead
		if err := s.db.Order("organization_id").Find(&headsAfter).Error; err != nil || !reflect.DeepEqual(headsBefore, headsAfter) {
			t.Fatal("partial multi-organization audit survived failure")
		}
		var count int64
		if err := s.db.Table("integrity_audit_logs").Where("action='system.organization_update'").Count(&count).Error; err != nil || count != 0 {
			t.Fatal("failed retention change left success audit")
		}
		if err := s.VerifyAllAudit(ctx, true); err != nil {
			t.Fatal("rollback damaged audit integrity", err)
		}
	})
}

func TestResponseRetentionCASMissingRowAndRevokedPermissionDoNotAdvance(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		initial, auth, ctx := managementFixture(t, s)
		before := retentionOrganization(t, s, initial.Organization.ID)
		zero := 0
		if _, err := s.ManageUpdateOrganization(ctx, auth, initial.Organization.ID, ManagedOrganizationPatch{ExpectedVersion: before.Version + 1, FullResponseRetentionDays: &zero}); !errors.Is(err, ErrConflict) {
			t.Fatal("stale version not rejected")
		}
		for _, days := range []int{-1, 181} {
			if _, err := s.ManageUpdateOrganization(ctx, auth, initial.Organization.ID, ManagedOrganizationPatch{ExpectedVersion: before.Version, FullResponseRetentionDays: &days}); !errors.Is(err, ErrConfiguration) {
				t.Fatal("invalid days accepted")
			}
		}
		if !reflect.DeepEqual(before, retentionOrganization(t, s, initial.Organization.ID)) {
			t.Fatal("failed validation changed policy")
		}
		statement := "CREATE FUNCTION retention_fixture_ignore_update() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NULL; END;$$;"
		if cfg.Driver == "sqlite" {
			statement = "CREATE TRIGGER retention_fixture_ignore_update BEFORE UPDATE ON organizations BEGIN SELECT RAISE(IGNORE); END"
		}
		if err := s.db.Exec(statement).Error; err != nil {
			t.Fatal("install zero-row CAS fixture")
		}
		if cfg.Driver == "postgres" {
			if err := s.db.Exec("CREATE TRIGGER retention_fixture_ignore_update BEFORE UPDATE ON organizations FOR EACH ROW EXECUTE FUNCTION retention_fixture_ignore_update()").Error; err != nil {
				t.Fatal("install CAS trigger")
			}
		}
		if _, err := s.ManageUpdateOrganization(ctx, auth, initial.Organization.ID, ManagedOrganizationPatch{ExpectedVersion: before.Version, FullResponseRetentionDays: &zero}); !errors.Is(err, ErrConflict) {
			t.Fatal("RowsAffected=0 falsely reported setting success")
		}
		if !reflect.DeepEqual(before, retentionOrganization(t, s, initial.Organization.ID)) {
			t.Fatal("CAS failure changed policy")
		}
		if err := s.db.Model(&User{}).Where("id=?", auth.UserID).Update("is_system_admin", false).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := s.ManageUpdateOrganization(ctx, auth, initial.Organization.ID, ManagedOrganizationPatch{ExpectedVersion: before.Version, FullResponseRetentionDays: &zero}); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("revoked admin changed policy")
		}
		var count int64
		if err := s.db.Table("integrity_audit_logs").Where("action='system.organization_update'").Count(&count).Error; err != nil || count != 0 {
			t.Fatal("rejected change wrote success audit")
		}
	})
}

func TestResponseRetentionConcurrentCASHasOneWinner(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		initial, auth, ctx := managementFixture(t, s)
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		var wg sync.WaitGroup
		results := make(chan error, 8)
		for i := range 8 {
			wg.Go(func() {
				candidate := s
				if i%2 == 1 {
					candidate = other
				}
				days := i
				_, err := candidate.ManageUpdateOrganization(ctx, auth, initial.Organization.ID, ManagedOrganizationPatch{ExpectedVersion: 1, FullResponseRetentionDays: &days})
				results <- err
			})
		}
		wg.Wait()
		close(results)
		wins := 0
		for err := range results {
			if err == nil {
				wins++
			} else if !errors.Is(err, ErrConflict) {
				t.Fatal("unexpected policy race outcome", err)
			}
		}
		current := retentionOrganization(t, s, initial.Organization.ID)
		if wins != 1 || current.Version != 2 || current.ResponseEvidenceNotBeforeMicros != current.UpdatedAt.UnixMicro()-int64(current.FullResponseRetentionDays)*responseRetentionDayMicros {
			t.Fatal("CAS race changed cutoff more than once")
		}
		var count int64
		if err := s.db.Table("integrity_audit_logs").Where("organization_id=? AND action='system.organization_update'", initial.Organization.ID).Count(&count).Error; err != nil || count != 1 {
			t.Fatal("race wrote multiple/missing success audits")
		}
	})
}

func TestResponseRetentionReadScopeAndClosedTransactionFailClosed(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		initial, _, ctx := managementFixture(t, s)
		tenant, err := s.WithOrganization(ctx, initial.Organization.ID)
		if err != nil {
			t.Fatal(err)
		}
		var escaped *TenantTransaction
		if err := tenant.InTransaction(func(tx *TenantTransaction) error {
			escaped = tx
			p, err := tx.LockResponseRetentionPolicy()
			if err == nil && (p.OrganizationID() != initial.Organization.ID || p.Days() != 30) {
				t.Error("locked policy scope mismatch")
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := escaped.LockResponseRetentionPolicy(); !errors.Is(err, ErrTransactionClosed) {
			t.Fatal("escaped policy tx remained usable")
		}
		foreign, _ := s.WithOrganization(ctx, initial.Organization.ID+1)
		if _, err := foreign.GetResponseRetentionPolicy(); !errors.Is(err, ErrNotFound) {
			t.Fatal("scope mismatch read another organization's policy")
		}
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		bound, _ := s.WithOrganization(cancelled, initial.Organization.ID)
		if _, err := bound.GetResponseRetentionPolicy(); err == nil {
			t.Fatal("cancelled policy read succeeded")
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if p, err := tenant.GetResponseRetentionPolicy(); err == nil || p.OrganizationID() != 0 {
			t.Fatal("database outage exposed stale policy")
		}
	})
}

func TestResponseRetentionClockRollbackNeverLowersOldCutoff(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	row := responseRetentionOrganization{FullResponseRetentionDays: 30, ResponseEvidenceNotBeforeMicros: now.Add(time.Hour).UnixMicro()}
	for _, days := range []int{0, 1, 30, 180} {
		got, err := advanceResponseRetention(row, days, now)
		if err != nil || got != row.ResponseEvidenceNotBeforeMicros {
			t.Fatal("backward clock revived discarded history")
		}
	}
	row.FullResponseRetentionDays = -1
	if _, err := advanceResponseRetention(row, 30, now); !errors.Is(err, ErrConfiguration) {
		t.Fatal("invalid persisted policy accepted")
	}
}

func TestResponseRetentionLockedPolicyBlocksSettingsButAllowsPlanningSnapshot(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		initial, auth, ctx := managementFixture(t, s)
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		if cfg.Driver == "sqlite" {
			if err := other.db.Exec("PRAGMA busy_timeout=150").Error; err != nil {
				t.Fatal("bound test-only competing writer wait")
			}
		}
		tenant, err := s.WithOrganization(ctx, initial.Organization.ID)
		if err != nil {
			t.Fatal(err)
		}
		locked := make(chan ResponseRetentionPolicy, 1)
		release := make(chan struct{})
		done := make(chan error, 1)
		var once sync.Once
		releaseLock := func() { once.Do(func() { close(release) }) }
		defer releaseLock()
		go func() {
			done <- tenant.InTransaction(func(tx *TenantTransaction) error {
				p, err := tx.LockResponseRetentionPolicy()
				if err != nil {
					return err
				}
				locked <- p
				select {
				case <-release:
					return nil
				case <-t.Context().Done():
					return t.Context().Err()
				}
			})
		}()
		var before ResponseRetentionPolicy
		select {
		case before = <-locked:
		case err := <-done:
			t.Fatal("lock policy", err)
		case <-time.After(3 * time.Second):
			t.Fatal("policy lock not established")
		}
		// The first store still holds the write lock; this independent planning
		// snapshot must NOT try to acquire another SQLite writer or PG row lock.
		readCtx, stopRead := context.WithTimeout(ctx, time.Second)
		reader, _ := other.WithOrganization(readCtx, initial.Organization.ID)
		read, err := reader.GetResponseRetentionPolicy()
		stopRead()
		if err != nil || read.Version() != 1 || read.Days() != 30 {
			t.Fatal("planning read waited for policy writer", err)
		}
		updateCtx, stopUpdate := context.WithTimeout(ctx, 250*time.Millisecond)
		zero := 0
		_, err = other.ManageUpdateOrganization(updateCtx, auth, initial.Organization.ID, ManagedOrganizationPatch{ExpectedVersion: 1, FullResponseRetentionDays: &zero})
		stopUpdate()
		if err == nil {
			t.Fatal("settings bypassed held organization policy lock")
		}
		unchanged := retentionOrganization(t, other, initial.Organization.ID)
		if unchanged.Version != 1 || unchanged.FullResponseRetentionDays != 30 || unchanged.ResponseEvidenceNotBeforeMicros != 0 {
			t.Fatal("blocked mutation changed settings")
		}
		releaseLock()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal("release policy lock", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("policy transaction failed to release")
		}
		updateRetention(t, other, ctx, auth, initial.Organization.ID, 0)
		after := retentionPolicy(t, other, ctx, initial.Organization.ID)
		captured := before.ObservedAtMicros() - 1
		expiry := before.ObservedAtMicros() + responseRetentionDayMicros
		if !before.EligibleAtObservation(captured, expiry, false) || after.EligibleAtObservation(captured, expiry, false) {
			t.Fatal("fresh final policy did not invalidate a stale planning observation")
		}
	})
}
