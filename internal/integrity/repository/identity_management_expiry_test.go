package repository

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"gorm.io/gorm"
)

func managementExpirySession(t *testing.T, s *Store, auth ManagementAuthority) time.Time {
	t.Helper()
	expires := time.Now().UTC().Add(2 * time.Second).Truncate(time.Microsecond)
	if err := s.db.Model(&Session{}).Where("id = ?", auth.SessionID).Update("expires_at", expires).Error; err != nil {
		t.Fatal("set synthetic session expiry")
	}
	return expires
}

func managementExpiryWait(ctx context.Context, expires time.Time) error {
	timer := time.NewTimer(max(time.Until(expires.Add(time.Millisecond)), 0))
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// PostgreSQL must reach a real organization-row wait after identity validation;
// merely starting an already-expired request would not exercise the regression.
func managementExpiryBlockedOrganization(t *testing.T, s *Store, cfg Config, ctx context.Context, auth ManagementAuthority, org Organization) error {
	t.Helper()
	other, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal("open independent policy holder")
	}
	defer func() { _ = other.Close() }()
	blocker := other.db.WithContext(ctx).Begin()
	if blocker.Error != nil {
		t.Fatal("begin independent policy transaction")
	}
	defer func() { _ = blocker.Rollback().Error }()
	var blockerPID int
	if err := blocker.Raw("SELECT pg_backend_pid()").Scan(&blockerPID).Error; err != nil {
		t.Fatal("identify policy holder")
	}
	if err := blocker.Exec("SELECT id FROM organizations WHERE id = ? FOR UPDATE", org.ID).Error; err != nil {
		t.Fatal("hold organization row")
	}
	expires := managementExpirySession(t, s, auth)
	pids, results := make(chan int, 1), make(chan error, 1)
	go func() {
		results <- s.db.WithContext(ctx).Connection(func(db *gorm.DB) error {
			var pid int
			if err := db.Raw("SELECT pg_backend_pid()").Scan(&pid).Error; err != nil {
				return ErrUnavailable
			}
			pids <- pid
			bound := *s
			bound.db = db
			zero := 0
			_, err := bound.ManageUpdateOrganization(ctx, auth, org.ID, ManagedOrganizationPatch{ExpectedVersion: org.Version, FullResponseRetentionDays: &zero})
			return err
		})
	}()
	var managerPID int
	select {
	case managerPID = <-pids:
	case <-results:
		t.Fatal("management connection failed before organization wait")
	case <-ctx.Done():
		t.Fatal("management connection did not start")
	}
	if managerPID == blockerPID || managerPID <= 0 || blockerPID <= 0 {
		t.Fatal("policy holder and management connection not independent")
	}
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		if err := s.db.WithContext(ctx).Raw("SELECT ? = ANY(pg_blocking_pids(?))", blockerPID, managerPID).Scan(&blocked).Error; err != nil {
			t.Fatal("observe actual organization lock wait")
		}
		if blocked {
			if !expires.After(time.Now()) {
				t.Fatal("could not prove authorized organization wait before expiry")
			}
			break
		}
		select {
		case <-results:
			t.Fatal("management finished without its required organization lock wait")
		case <-ctx.Done():
			t.Fatal("organization lock wait was not observed")
		case <-ticker.C:
		}
	}
	t.Log("observed real independent organization lock wait after authority validation, before natural expiry")
	if err := managementExpiryWait(ctx, expires); err != nil {
		t.Fatal("natural-expiry wait canceled")
	}
	if err := blocker.Rollback().Error; err != nil {
		t.Fatal("release organization lock after natural expiry")
	}
	select {
	case err := <-results:
		return err
	case <-ctx.Done():
		t.Fatal("management did not settle after policy lock release")
		return ctx.Err()
	}
}

func TestManagementNaturalExpiryRollsBackAfterAuthorizedWork(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		initial, auth, actorCtx := managementFixture(t, s)
		ctx, cancel := context.WithTimeout(actorCtx, 10*time.Second)
		defer cancel()
		before := retentionOrganization(t, s, initial.Organization.ID)
		var headsBefore []auditChainHead
		if err := s.db.Order("organization_id").Find(&headsBefore).Error; err != nil {
			t.Fatal("read initial audit heads")
		}
		var err error
		if cfg.Driver == "postgres" {
			err = managementExpiryBlockedOrganization(t, s, cfg, ctx, auth, before)
		} else {
			expires := managementExpirySession(t, s, auth)
			entered := false
			err = s.managementTransaction(ctx, auth, 0, "system.organizations", true, func(tx *gorm.DB, _ User) error {
				if !expires.After(time.Now()) {
					return errors.New("fixture expired before authorized callback")
				}
				entered = true
				now := time.Now().UTC().Truncate(time.Microsecond)
				if err := tx.Model(&Organization{}).Where("id = ?", before.ID).Updates(map[string]any{
					"full_response_retention_days": 0, "response_evidence_not_before_micros": now.UnixMicro(),
					"version": gorm.Expr("version + 1"), "updated_at": now,
				}).Error; err != nil {
					return err
				}
				if err := s.auditManagement(ctx, tx, []int64{before.ID}, auditObject("system.organization_update", "organization", before.ID)); err != nil {
					return err
				}
				if !expires.After(time.Now()) {
					return errors.New("fixture expired before pending-commit barrier")
				}
				t.Log("authorized callback completed real policy and audit SQL before natural expiry; transaction still pending")
				return managementExpiryWait(ctx, expires)
			})
			if !entered {
				t.Fatal("test did not enter the authorized transaction callback")
			}
		}
		if !errors.Is(err, ErrManagementSession) {
			t.Error("management did not reject natural expiry after authorized work")
		}
		if !reflect.DeepEqual(before, retentionOrganization(t, s, before.ID)) {
			t.Error("expired management transaction committed policy/cutoff/version/time")
		}
		var headsAfter []auditChainHead
		if err := s.db.Order("organization_id").Find(&headsAfter).Error; err != nil || !reflect.DeepEqual(headsBefore, headsAfter) {
			t.Error("expired management transaction committed an audit head")
		}
		var count int64
		if err := s.db.Table("integrity_audit_logs").Where("action = ?", "system.organization_update").Count(&count).Error; err != nil || count != 0 {
			t.Error("expired management transaction committed success audit")
		}
		if err := s.VerifyAllAudit(ctx, true); err != nil {
			t.Fatal("expiry rollback damaged audit integrity")
		}
	})
}

func TestManagementExpiryCheckPreservesAuthorizedSelfRevocation(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		initial, auth, ctx := managementFixture(t, s)
		err := s.managementTransaction(ctx, auth, 0, "system.users", true, func(tx *gorm.DB, _ User) error {
			if err := revokeManagedSessions(tx, auth.UserID, time.Now().UTC()); err != nil {
				return err
			}
			return s.auditManagement(ctx, tx, []int64{initial.Organization.ID}, auditObject("auth.logout_all", "user", auth.UserID))
		})
		if err != nil {
			t.Fatal("natural-expiry check rejected intentional in-transaction self revocation")
		}
		var session Session
		if err := s.db.Where("id = ?", auth.SessionID).First(&session).Error; err != nil || session.RevokedAt == nil {
			t.Fatal("authorized revocation did not commit")
		}
		if err := s.VerifyAllAudit(ctx, true); err != nil {
			t.Fatal("authorized revocation damaged audit integrity")
		}
	})
}

func TestManagementExpiryCheckKeepsOriginalAuthorityDeadline(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		initial, auth, actorCtx := managementFixture(t, s)
		ctx, cancel := context.WithTimeout(actorCtx, 10*time.Second)
		defer cancel()
		expires := managementExpirySession(t, s, auth)
		entered := false
		err := s.managementTransaction(ctx, auth, 0, "system.users", true, func(tx *gorm.DB, _ User) error {
			entered = true
			if err := tx.Model(&Session{}).Where("id = ?", auth.SessionID).Update("expires_at", expires.Add(time.Hour)).Error; err != nil {
				return err
			}
			if err := s.auditManagement(ctx, tx, []int64{initial.Organization.ID}, auditObject("system.user_update", "user", auth.UserID)); err != nil {
				return err
			}
			return managementExpiryWait(ctx, expires)
		})
		if !entered || !errors.Is(err, ErrManagementSession) {
			t.Error("callback extended the original authority deadline")
		}
		var session Session
		if err := s.db.Where("id = ?", auth.SessionID).First(&session).Error; err != nil || !session.ExpiresAt.Equal(expires) {
			t.Error("expired callback's session extension was not rolled back")
		}
		var count int64
		if err := s.db.Table("integrity_audit_logs").Where("action = ?", "system.user_update").Count(&count).Error; err != nil || count != 0 {
			t.Error("expired callback's audit was not rolled back")
		}
	})
}
