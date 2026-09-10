package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

func systemStatusFixture(t *testing.T, s *Store) (InitializationResult, ManagementAuthority) {
	t.Helper()
	initial, auth, _ := managementFixture(t, s)
	var role int64
	if err := s.db.Table("roles").Select("id").Where("organization_id=? AND name='admin'", initial.Organization.ID).Scan(&role).Error; err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"run.read", "audit.read"} {
		for _, code := range []string{p, "disabled." + p} {
			if err := s.db.Exec("INSERT INTO permissions(code,description) VALUES(?,'') ON CONFLICT(code) DO NOTHING", code).Error; err != nil {
				t.Fatal(err)
			}
		}
		if err := s.db.Exec("INSERT INTO role_permissions(organization_id,role_id,permission_code) VALUES(?,?,?)", initial.Organization.ID, role, p).Error; err != nil {
			t.Fatal(err)
		}
	}
	return initial, auth
}

func TestSystemStatusAuthorizationAndActualDiagnostics(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		initial, auth := systemStatusFixture(t, s)
		org := initial.Organization.ID
		got, err := s.ReadSystemStatus(t.Context(), auth, org)
		if err != nil || got.Driver != s.Driver() || got.Schema.State != "compatible" || got.Schema.Applied != got.Schema.Expected || got.Audit.State != "verified" || got.Audit.VerifiedCount == nil || *got.Audit.VerifiedCount > 2 || got.Jobs.Total == nil || *got.Jobs.Total != 0 {
			t.Fatal("actual diagnostic read failed", err)
		}
		if _, err := s.ReadSystemStatus(t.Context(), auth, org+1); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("cross-organization read accepted", err)
		}
		if _, err := s.ReadSystemStatus(t.Context(), ManagementAuthority{}, org); !errors.Is(err, ErrManagementSession) {
			t.Fatal("missing session accepted", err)
		}
		for _, change := range []struct {
			name, sql string
			arg       any
			want      error
		}{
			{"ordinary-admin", "UPDATE users SET is_system_admin=? WHERE id=?", false, ErrManagementPermission},
			{"disabled", "UPDATE users SET status=? WHERE id=?", "disabled", ErrManagementSession},
			{"password", "UPDATE users SET must_change_password=? WHERE id=?", true, ErrPasswordChangeRequired},
		} {
			t.Run(change.name, func(t *testing.T) {
				if err := s.db.Exec(change.sql, change.arg, auth.UserID).Error; err != nil {
					t.Fatal(err)
				}
				if _, err := s.ReadSystemStatus(t.Context(), auth, org); !errors.Is(err, change.want) {
					t.Fatal("persisted authority not enforced", err)
				}
				if err := s.db.Exec("UPDATE users SET is_system_admin=TRUE,status='active',must_change_password=FALSE WHERE id=?", auth.UserID).Error; err != nil {
					t.Fatal(err)
				}
			})
		}
		for _, permission := range []string{"run.read", "audit.read"} {
			if err := s.db.Exec("UPDATE role_permissions SET permission_code=? WHERE organization_id=? AND permission_code=?", "disabled."+permission, org, permission).Error; err != nil {
				t.Fatal(err)
			}
			if _, err := s.ReadSystemStatus(t.Context(), auth, org); !errors.Is(err, ErrManagementPermission) {
				t.Fatal("removed grant accepted", err)
			}
			if err := s.db.Exec("UPDATE role_permissions SET permission_code=? WHERE organization_id=? AND permission_code=?", permission, org, "disabled."+permission).Error; err != nil {
				t.Fatal(err)
			}
		}
		for _, table := range []string{"organizations", "organization_members"} {
			column, value := "id", org
			if table == "organization_members" {
				column = "user_id"
				value = auth.UserID
			}
			if err := s.db.Table(table).Where(column+"=?", value).Update("status", "disabled").Error; err != nil {
				t.Fatal(err)
			}
			if _, err := s.ReadSystemStatus(t.Context(), auth, org); !errors.Is(err, ErrManagementPermission) {
				t.Fatal("disabled scope accepted", err)
			}
			if err := s.db.Table(table).Where(column+"=?", value).Update("status", "active").Error; err != nil {
				t.Fatal(err)
			}
		}
		if err := s.db.Exec("UPDATE user_sessions SET revoked_at=? WHERE id=?", time.Now().UTC(), auth.SessionID).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.CheckSystemStatusAuthority(t.Context(), auth, org); !errors.Is(err, ErrManagementSession) {
			t.Fatal("revoked session accepted", err)
		}
	})
}

func TestSystemStatusReadSnapshotDoesNotLockWriter(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		initial, auth := systemStatusFixture(t, s)
		org := initial.Organization.ID
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = other.Close() })
		seen := false
		var writeErr error
		var readOnly string
		if err := s.db.Callback().Row().Before("gorm:row").Register("system_status_snapshot", func(tx *gorm.DB) {
			if seen || !strings.Contains(tx.Statement.SQL.String(), "system_status_jobs") {
				return
			}
			seen = true
			if cfg.Driver == "postgres" {
				if e := tx.Session(&gorm.Session{NewDB: true}).Raw("SHOW transaction_read_only").Scan(&readOnly).Error; e != nil {
					t.Error(e)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			writeErr = other.db.WithContext(ctx).Exec("UPDATE users SET is_system_admin=FALSE WHERE id=?", auth.UserID).Error
		}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.db.Callback().Row().Remove("system_status_snapshot") })
		if _, err := s.ReadSystemStatus(t.Context(), auth, org); err != nil || !seen || writeErr != nil {
			t.Fatal("read locked writer", err, writeErr)
		}
		if cfg.Driver == "postgres" && readOnly != "on" {
			t.Fatal("not a read-only transaction")
		}
		if err := s.CheckSystemStatusAuthority(t.Context(), auth, org); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("fresh response authorization missed concurrent revocation", err)
		}
	})
}

func TestSystemStatusCorruptionAndActiveJobBounds(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		initial, auth := systemStatusFixture(t, s)
		org := initial.Organization.ID
		now := time.Now().UTC().Add(-time.Minute)
		expired := now.Add(-time.Second)
		future := now.Add(time.Hour)
		jobs := []Job{}
		for i := range 5 {
			id, err := NewID()
			if err != nil {
				t.Fatal(err)
			}
			job := Job{ID: id, OrganizationID: org, Type: string(JobRetentionDelete), ObjectID: org, IdempotencyKey: fmt.Sprintf("status-%d", i), Status: "pending", AvailableAt: now, CreatedAt: now, UpdatedAt: now, MaxAttempts: 3}
			if i == 1 {
				job.AvailableAt = future
			}
			if i == 2 {
				job.Status = "running"
				job.LeaseUntil = &future
			}
			if i == 3 {
				job.Status = "running"
				job.LeaseUntil = &expired
			}
			if i == 4 {
				job.Status = "completed"
			}
			jobs = append(jobs, job)
		}
		if err := s.db.Create(&jobs).Error; err != nil {
			t.Fatal(err)
		}
		got, err := s.ReadSystemStatus(t.Context(), auth, org)
		if err != nil || got.Jobs.Total == nil || *got.Jobs.Total != 4 || *got.Jobs.PendingReady != 1 || *got.Jobs.PendingDelayed != 1 || *got.Jobs.RunningLeased != 1 || *got.Jobs.RunningExpired != 1 {
			t.Fatal("job partitions wrong", err)
		}
		if err := s.db.Exec("UPDATE schema_migrations SET checksum=? WHERE version=1", strings.Repeat("secret-canary", 10000)).Error; err != nil {
			t.Fatal(err)
		}
		got, err = s.ReadSystemStatus(t.Context(), auth, org)
		if err != nil || got.Schema.State != "incompatible" {
			t.Fatal("corrupt schema reported compatible", err)
		}
		if err := s.db.Exec("UPDATE integrity_audit_logs SET diff_summary=? WHERE organization_id=?", strings.Repeat("secret-canary", 10000), org).Error; err != nil {
			t.Fatal(err)
		}
		got, err = s.ReadSystemStatus(t.Context(), auth, org)
		if err != nil || got.Audit.State != "invalid" || got.Audit.VerifiedCount != nil {
			t.Fatal("corrupt audit exposed or verified", err)
		}
		rows := make([]Job, SystemStatusMaxJobs)
		for i := range rows {
			id, e := NewID()
			if e != nil {
				t.Fatal(e)
			}
			rows[i] = jobs[0]
			rows[i].ID = id
			rows[i].IdempotencyKey = fmt.Sprintf("status-cap-%d", i)
		}
		if err := s.db.CreateInBatches(rows, 100).Error; err != nil {
			t.Fatal(err)
		}
		got, err = s.ReadSystemStatus(t.Context(), auth, org)
		if err != nil || got.Jobs.State != "limit_exceeded" || got.Jobs.Total != nil {
			t.Fatal("truncated queue presented as total", err)
		}
	})
}

func TestSystemStatusCancellationLeavesConnectionReusable(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		initial, auth := systemStatusFixture(t, s)
		ctx, cancel := context.WithCancel(t.Context())
		seen := false
		if err := s.db.Callback().Row().Before("gorm:row").Register("system_status_cancel", func(tx *gorm.DB) {
			if !seen && strings.Contains(tx.Statement.SQL.String(), "system_status_jobs") {
				seen = true
				cancel()
			}
		}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cancel(); _ = s.db.Callback().Row().Remove("system_status_cancel") })
		if _, err := s.ReadSystemStatus(ctx, auth, initial.Organization.ID); err == nil || !seen {
			t.Fatal("cancellation ignored")
		}
		if _, err := s.ReadSystemStatus(t.Context(), auth, initial.Organization.ID); err != nil {
			t.Fatal("read connection retained cancelled transaction", err)
		}
	})
}
