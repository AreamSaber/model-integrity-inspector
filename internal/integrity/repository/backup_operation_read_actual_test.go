package repository

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/migrations"
)

func backupOperationReadAssertZero(t *testing.T, s *Store, ctx context.Context, auth ManagementAuthority, id int64, want error) {
	t.Helper()
	if got, err := s.ReadBackupOperation(ctx, auth, id); !errors.Is(err, want) || got != (BackupOperationView{}) {
		t.Fatal("read not closed", err)
	}
	if got, err := s.ListBackupOperations(ctx, auth, BackupOperationListRequest{Limit: 100}); !errors.Is(err, want) || !reflect.DeepEqual(got, BackupOperationPage{}) {
		t.Fatal("page not closed", err)
	}
}

func TestBackupOperationReadLifecycleTwoInstancesAndAuthentication(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		initial, auth, ctx := managementFixture(t, s)
		viewer := managementFixtureUser(t, s, ctx, auth, "backup-state-viewer")
		viewerAuth := managementSession(t, s, viewer)
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		page, err := other.ListBackupOperations(ctx, auth, BackupOperationListRequest{Limit: 100})
		if err != nil || len(page.Items) != 0 || page.NextBeforeID != 0 {
			t.Fatal("empty authorized history", err)
		}
		if value, err := other.ReadBackupOperation(ctx, auth, 1); !errors.Is(err, ErrNotFound) || value != (BackupOperationView{}) {
			t.Fatal("missing authorized lookup", err)
		}
		lease := beginTestMaintenance(t, s, ctx, auth)
		active, err := other.ReadBackupOperation(ctx, auth, lease.operationID)
		if err != nil || active.ID != lease.operationID || active.Status != BackupOperationActive || active.ManifestVersion != "" || active.Version != 1 || active.ReasonCode != "backup.manual" || active.CreatedAtMicros != lease.startedAtMicros {
			t.Fatal("active misrepresented", err)
		}
		if err := lease.Renew(ctx); err != nil {
			t.Fatal(err)
		}
		renewed, err := other.ReadBackupOperation(ctx, auth, lease.operationID)
		if err != nil || renewed.Version != 2 || renewed.CreatedAtMicros != active.CreatedAtMicros {
			t.Fatal("live instance not refreshed", err)
		}
		if err := lease.Abort(ctx); err != nil {
			t.Fatal(err)
		}
		aborted, err := other.ReadBackupOperation(ctx, auth, lease.operationID)
		if err != nil || aborted.Status != BackupOperationAborted || aborted.ManifestVersion != "" {
			t.Fatal("aborted invented readiness", err)
		}
		next := beginTestMaintenance(t, s, ctx, auth)
		receipt, err := next.CompleteBackup(ctx, testBackupPublication(t, next))
		if err != nil {
			t.Fatal(err)
		}
		completed, err := other.ReadBackupOperation(ctx, auth, next.operationID)
		if err != nil || completed.Status != BackupOperationCompleted || completed.ManifestVersion != receipt.ManifestVersion || completed.CreatedAtMicros != receipt.StartedAtMicros || completed.UpdatedAtMicros != receipt.CompletedAtMicros {
			t.Fatal("authenticated completion unavailable", err)
		}
		page, err = other.ListBackupOperations(ctx, auth, BackupOperationListRequest{Limit: 100})
		expected := []BackupOperationView{completed, aborted}
		slices.SortFunc(expected, func(a, b BackupOperationView) int {
			if a.ID > b.ID {
				return -1
			}
			if a.ID < b.ID {
				return 1
			}
			return 0
		})
		if err != nil || len(page.Items) != 2 || !reflect.DeepEqual(page.Items, expected) {
			t.Fatal("history ordering/current gate", err)
		}
		backupOperationReadAssertZero(t, other, testActorContext(t, viewer.ID), viewerAuth, next.operationID, ErrManagementPermission)
		backupOperationReadAssertZero(t, other, context.Background(), auth, next.operationID, audit.ErrActorRequired)
		backupOperationReadAssertZero(t, other, testActorContext(t, initial.User.ID+1), auth, next.operationID, audit.ErrActorRequired)
		backupOperationReadAssertZero(t, other, ctx, ManagementAuthority{UserID: auth.UserID, SessionID: viewerAuth.SessionID}, next.operationID, ErrManagementSession)
		for _, change := range []struct {
			name   string
			user   bool
			column string
			value  any
			want   error
		}{
			{"disabled", true, "status", "disabled", ErrManagementSession},
			{"demoted", true, "is_system_admin", false, ErrManagementPermission},
			{"must-change", true, "must_change_password", true, ErrPasswordChangeRequired},
			{"password-changed", true, "password_changed_at", time.Now().UTC().Add(time.Minute), ErrManagementSession},
			{"revoked", false, "revoked_at", time.Now().UTC(), ErrManagementSession},
			{"expired", false, "expires_at", time.Now().UTC().Add(-time.Second), ErrManagementSession},
		} {
			t.Run(change.name, func(t *testing.T) {
				var user User
				var session Session
				if err := s.db.Where("id=?", auth.UserID).Take(&user).Error; err != nil {
					t.Fatal(err)
				}
				if err := s.db.Where("id=?", auth.SessionID).Take(&session).Error; err != nil {
					t.Fatal(err)
				}
				q := s.db.Model(&Session{}).Where("id=?", auth.SessionID)
				if change.user {
					q = s.db.Model(&User{}).Where("id=?", auth.UserID)
				}
				if change.name == "expired" {
					change.value = session.CreatedAt.Add(time.Microsecond)
				}
				if err := q.Update(change.column, change.value).Error; err != nil {
					t.Fatal(err)
				}
				backupOperationReadAssertZero(t, other, ctx, auth, next.operationID, change.want)
				if change.user {
					if err := s.db.Model(&User{}).Where("id=?", user.ID).Updates(map[string]any{"status": user.Status, "is_system_admin": user.IsSystemAdmin, "must_change_password": user.MustChangePassword, "password_changed_at": user.PasswordChangedAt}).Error; err != nil {
						t.Fatal(err)
					}
				} else {
					if err := s.db.Model(&Session{}).Where("id=?", session.ID).Updates(map[string]any{"revoked_at": session.RevokedAt, "expires_at": session.ExpiresAt}).Error; err != nil {
						t.Fatal(err)
					}
				}
			})
		}
		fresh := beginTestMaintenance(t, s, ctx, auth)
		// A later authenticated freeze cannot be read as an old cached normal.
		if got, err := other.ReadBackupOperation(ctx, auth, fresh.operationID); err != nil || got.Status != BackupOperationActive {
			t.Fatal("cached normal", err)
		}
		if err := fresh.Abort(ctx); err != nil {
			t.Fatal(err)
		}
	})
}

func TestBackupOperationRead101HistoryKeysetAndCorruptLookahead(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		_, auth, ctx := managementFixture(t, s)
		var ids []int64
		for range 101 {
			lease := beginTestMaintenance(t, s, ctx, auth)
			ids = append(ids, lease.operationID)
			if err := lease.Abort(ctx); err != nil {
				t.Fatal(err)
			}
		}
		lastCreated := ids[len(ids)-1]
		slices.Sort(ids)
		first, err := s.ListBackupOperations(ctx, auth, BackupOperationListRequest{Limit: 100})
		if err != nil || len(first.Items) != 100 || first.NextBeforeID != ids[1] {
			t.Fatal("101 history first page", err)
		}
		for i, item := range first.Items {
			if item.ID != ids[100-i] || item.Status != BackupOperationAborted {
				t.Fatal("order/duplicate/status")
			}
		}
		last, err := s.ListBackupOperations(ctx, auth, BackupOperationListRequest{BeforeID: first.NextBeforeID, Limit: 100})
		if err != nil || len(last.Items) != 1 || last.Items[0].ID != ids[0] || last.NextBeforeID != 0 {
			t.Fatal("exclusive bound or omitted oldest", err)
		}
		empty, err := s.ListBackupOperations(ctx, auth, BackupOperationListRequest{BeforeID: ids[0], Limit: 100})
		if err != nil || len(empty.Items) != 0 || empty.NextBeforeID != 0 {
			t.Fatal("empty final page", err)
		}
		// The 101st original row is a lookahead, not returned in Items. It still
		// must authenticate before a successful first page/cursor is released.
		faultLimit, faultID := 100, ids[0]
		if faultID == lastCreated {
			faultLimit, faultID = 99, ids[1]
		}
		var event maintenanceEvent
		if err := s.db.Where("operation_id=? AND action='abort'", faultID).Take(&event).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.db.Model(&audit.Event{}).Where("object_id=?", maintenanceEventObject(event)).Update("event_hmac", strings.Repeat("f", 64)).Error; err != nil {
			t.Fatal(err)
		}
		if page, err := s.ListBackupOperations(ctx, auth, BackupOperationListRequest{Limit: faultLimit}); !errors.Is(err, audit.ErrIntegrity) || !reflect.DeepEqual(page, BackupOperationPage{}) {
			t.Fatal("damaged lookahead returned partial page", err)
		}
	})
}

func TestBackupOperationReadFinalSessionNaturalExpiryAndCancellation(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		_, auth, ctx := managementFixture(t, s)
		lease := beginTestMaintenance(t, s, ctx, auth)
		if err := lease.Abort(ctx); err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"single", "page", "cancel"} {
			t.Run(mode, func(t *testing.T) {
				expires := time.Now().UTC().Add(300 * time.Millisecond)
				if err := s.db.Model(&Session{}).Where("id=?", auth.SessionID).Update("expires_at", expires).Error; err != nil {
					t.Fatal(err)
				}
				callCtx, cancel := context.WithCancel(ctx)
				defer cancel()
				entered := false
				if err := s.db.Callback().Query().After("gorm:query").Register("backup_state_final_expiry", func(db *gorm.DB) {
					rows, ok := db.Statement.Dest.(*[]maintenanceOperation)
					if !ok || len(*rows) == 0 || entered {
						return
					}
					entered = true
					if !time.Now().Before(expires) {
						_ = db.AddError(errors.New("fixture did not start authorized"))
						return
					}
					if mode == "cancel" {
						cancel()
						return
					}
					timer := time.NewTimer(time.Until(expires) + 20*time.Millisecond)
					defer timer.Stop()
					select {
					case <-timer.C:
					case <-db.Statement.Context.Done():
						_ = db.AddError(db.Statement.Context.Err())
					}
				}); err != nil {
					t.Fatal(err)
				}
				want := ErrManagementSession
				if mode == "cancel" {
					want = ErrUnavailable
				}
				if mode == "single" {
					if value, err := s.ReadBackupOperation(callCtx, auth, lease.operationID); !errors.Is(err, want) || value != (BackupOperationView{}) {
						t.Fatal("expired single read", err)
					}
				} else {
					if value, err := s.ListBackupOperations(callCtx, auth, BackupOperationListRequest{Limit: 100}); !errors.Is(err, want) || !reflect.DeepEqual(value, BackupOperationPage{}) {
						t.Fatal("expired/canceled page", err)
					}
				}
				if err := s.db.Callback().Query().Remove("backup_state_final_expiry"); err != nil {
					t.Fatal(err)
				}
				if !entered {
					t.Fatal("final authority fixture missed")
				}
			})
		}
	})
}

func TestBackupOperationReadMigration21NaturalExpirySupersededHistory(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		set, err := migrations.ForDialect(s.driver)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.migrate(t.Context(), set[:21]); err != nil {
			t.Fatal(err)
		}
		initial := requireInitialize(t, s)
		auth := managementSession(t, s, initial.User)
		ctx := testActorContext(t, initial.User.ID)
		aborted := beginTestMaintenance(t, s, ctx, auth)
		if err := aborted.Abort(ctx); err != nil {
			t.Fatal(err)
		}
		old := beginTestMaintenance(t, s, ctx, auth)
		before, err := s.ReadBackupOperation(ctx, auth, old.operationID)
		if err != nil || before.Status != BackupOperationActive {
			t.Fatal("schema21 active", err)
		}
		if before.LeaseUntilMicros-before.CreatedAtMicros != MaintenanceLeaseDuration.Microseconds() {
			t.Fatal("production lease duration changed")
		}
		timer := time.NewTimer(time.Until(time.UnixMicro(before.LeaseUntilMicros)) + 25*time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal("natural expiry canceled")
		}
		expired, err := s.ReadBackupOperation(ctx, auth, old.operationID)
		if err != nil || expired != before || expired.Status != BackupOperationActive || expired.ManifestVersion != "" {
			t.Fatal("natural expiry invented ready/terminal", err)
		}
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		state, err := other.ReadMaintenanceState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		next, err := other.TakeOverExpiredBackup(ctx, auth, BackupMaintenanceRequest{ExpectedVersion: state.Version, ReasonCode: "backup.recovery", MaxDuration: time.Hour})
		if err != nil {
			t.Fatal("actual natural takeover", err)
		}
		superseded, err := s.ReadBackupOperation(ctx, auth, old.operationID)
		if err != nil || superseded.Status != BackupOperationSuperseded || superseded.ManifestVersion != "" {
			t.Fatal("schema21 superseded history", err)
		}
		if err := next.Abort(ctx); err != nil {
			t.Fatal(err)
		}
		if err := s.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
		page, err := s.ListBackupOperations(ctx, auth, BackupOperationListRequest{Limit: 100})
		if err != nil || len(page.Items) != 3 {
			t.Fatal("old history migration", err)
		}
		completed := beginTestMaintenance(t, s, ctx, auth)
		if _, err := completed.CompleteBackup(ctx, testBackupPublication(t, completed)); err != nil {
			t.Fatal(err)
		}
		if got, err := s.ReadBackupOperation(ctx, auth, old.operationID); err != nil || got != superseded {
			t.Fatal("old superseded changed after real completion", err)
		}
	})
}

func TestBackupOperationReadNonmemberSystemAdministrator(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		_, auth, ctx := managementFixture(t, s)
		user := managementFixtureUser(t, s, ctx, auth, "system-backup-operator")
		if err := s.db.Model(&User{}).Where("id=?", user.ID).Update("is_system_admin", true).Error; err != nil {
			t.Fatal(err)
		}
		operator := managementSession(t, s, user)
		operatorCtx := testActorContext(t, user.ID)
		var members int64
		if err := s.db.Table("organization_members").Where("user_id=?", user.ID).Count(&members).Error; err != nil || members != 0 {
			t.Fatal("nonmember fixture", err)
		}
		old := beginTestMaintenance(t, s, ctx, auth)
		if err := old.Abort(ctx); err != nil {
			t.Fatal(err)
		}
		next := beginTestMaintenance(t, s, operatorCtx, operator)
		if err := next.Abort(operatorCtx); err != nil {
			t.Fatal(err)
		}
		for _, caller := range []struct {
			ctx  context.Context
			auth ManagementAuthority
		}{{ctx, auth}, {operatorCtx, operator}} {
			page, err := s.ListBackupOperations(caller.ctx, caller.auth, BackupOperationListRequest{Limit: 100})
			if err != nil || len(page.Items) != 2 {
				t.Fatal("system history filtered by membership/owner", err)
			}
		}
		if _, err := s.ReadBackupOperation(operatorCtx, operator, old.operationID); err != nil {
			t.Fatal("historical other initiating admin hidden", err)
		}
		for _, value := range []int64{0, -1} {
			if got, err := s.ReadBackupOperation(ctx, auth, value); !errors.Is(err, ErrConfiguration) || got != (BackupOperationView{}) {
				t.Fatal("invalid id "+strconv.FormatInt(value, 10), err)
			}
		}
	})
}
