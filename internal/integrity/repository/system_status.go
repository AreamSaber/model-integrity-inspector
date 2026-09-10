package repository

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/migrations"
)

const SystemStatusMaxJobs = 10000

// These internal projections contain no event data, paths or driver diagnostics.
type SystemStatusJobs struct {
	State                                                              string
	Total, PendingReady, PendingDelayed, RunningLeased, RunningExpired *int64
}
type SystemStatusAudit struct {
	State         string
	VerifiedCount *int64
	LastEventAt   *time.Time
}
type SystemStatusSchema struct {
	State             string
	Expected, Applied int
}
type SystemStatusRecord struct {
	ObservedAt              time.Time
	Driver                  string
	Schema                  SystemStatusSchema
	Jobs                    SystemStatusJobs
	Audit                   SystemStatusAudit
	ConfiguredRetentionDays int
}

// ReadSystemStatus never enumerates organizations or obtains a write lock.
// The system role is necessary but never substitutes for organization grants.
func (s *Store) ReadSystemStatus(ctx context.Context, auth ManagementAuthority, org int64) (SystemStatusRecord, error) {
	var out SystemStatusRecord
	err := s.systemStatusTransaction(ctx, func(tx *gorm.DB) error {
		now, err := queueTime(tx, s.driver)
		if err != nil {
			return err
		}
		if err := systemStatusAuthority(tx, auth, org, now); err != nil {
			return err
		}
		out.ObservedAt, out.Driver = now, s.driver
		if err := tx.Table("organizations").Select("full_response_retention_days").Where("id=?", org).Scan(&out.ConfiguredRetentionDays).Error; err != nil {
			return err
		}
		if out.ConfiguredRetentionDays < 0 || out.ConfiguredRetentionDays > 180 {
			return ErrConfiguration
		}
		if out.Schema, err = s.systemStatusSchema(tx); err != nil {
			return err
		}
		if out.Jobs, err = systemStatusJobs(tx, org, now); err != nil {
			return err
		}
		out.Audit, err = s.systemStatusAudit(tx, org)
		return err
	})
	if err != nil {
		return SystemStatusRecord{}, err
	}
	return out, nil
}

// A fresh transaction after collecting local-process observations detects a
// committed revocation; no authorization result is cached between HTTP reads.
func (s *Store) CheckSystemStatusAuthority(ctx context.Context, auth ManagementAuthority, org int64) error {
	return s.systemStatusTransaction(ctx, func(tx *gorm.DB) error {
		now, err := queueTime(tx, s.driver)
		if err != nil {
			return err
		}
		return systemStatusAuthority(tx, auth, org, now)
	})
}

func systemStatusAuthority(tx *gorm.DB, auth ManagementAuthority, org int64, now time.Time) error {
	if auth.UserID <= 0 || auth.SessionID <= 0 {
		return ErrManagementSession
	}
	if org <= 0 {
		return ErrOrganizationScope
	}
	var user User
	if err := tx.Select("id,is_system_admin,must_change_password,password_changed_at,"+readBoundedText(tx, "status", "status", 16)).Where("id=?", auth.UserID).Take(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrManagementSession
		}
		return err
	}
	var session Session
	if err := tx.Select("id,created_at,expires_at,revoked_at").Where("id=? AND user_id=?", auth.SessionID, auth.UserID).Take(&session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrManagementSession
		}
		return err
	}
	if user.Status != "active" || session.RevokedAt != nil || !session.ExpiresAt.After(now) || session.CreatedAt.Before(user.PasswordChangedAt) {
		return ErrManagementSession
	}
	if user.MustChangePassword {
		return ErrPasswordChangeRequired
	}
	if !user.IsSystemAdmin {
		return ErrManagementPermission
	}
	var count int
	err := tx.Raw(`SELECT COUNT(*) FROM (
	 SELECT rp.permission_code FROM role_permissions rp
	 JOIN member_roles mr ON mr.organization_id=rp.organization_id AND mr.role_id=rp.role_id
	 JOIN organization_members om ON om.organization_id=mr.organization_id AND om.id=mr.member_id
	 JOIN organizations o ON o.id=om.organization_id
	 WHERE om.organization_id=? AND om.user_id=? AND om.status='active' AND o.status='active' AND rp.permission_code IN ('run.read','audit.read')
	 UNION SELECT mp.permission_code FROM member_permissions mp
	 JOIN organization_members om ON om.organization_id=mp.organization_id AND om.id=mp.member_id
	 JOIN organizations o ON o.id=om.organization_id
	 WHERE om.organization_id=? AND om.user_id=? AND om.status='active' AND o.status='active' AND mp.permission_code IN ('run.read','audit.read')
	) system_status_grants`, org, auth.UserID, org, auth.UserID).Scan(&count).Error
	if err != nil {
		return err
	}
	if count != 2 {
		return ErrManagementPermission
	}
	return nil
}

func (s *Store) systemStatusTransaction(ctx context.Context, read func(*gorm.DB) error) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	var err error
	if s.driver == "postgres" {
		err = s.db.WithContext(ctx).Transaction(read, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	} else {
		err = s.db.WithContext(ctx).Connection(func(conn *gorm.DB) error {
			conn = conn.Session(&gorm.Session{NewDB: true})
			if err := conn.Exec("BEGIN DEFERRED").Error; err != nil {
				return err
			}
			committed := false
			defer func() {
				if !committed {
					cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
					defer cancel()
					_ = conn.WithContext(cleanup).Exec("ROLLBACK").Error
				}
			}()
			if err := read(conn); err != nil {
				return err
			}
			if err := conn.Exec("COMMIT").Error; err != nil {
				return err
			}
			committed = true
			return nil
		})
	}
	return managementError(err)
}

func (s *Store) systemStatusSchema(tx *gorm.DB) (SystemStatusSchema, error) {
	expected, err := migrations.ForDialect(s.driver)
	if err != nil {
		return SystemStatusSchema{}, ErrSchemaMismatch
	}
	out := SystemStatusSchema{State: "compatible", Expected: len(expected)}
	var applied []SchemaVersion
	cols := "version,applied_at," + readBoundedText(tx, "name", "name", 256) + "," + readBoundedText(tx, "checksum", "checksum", 64) + "," + readBoundedText(tx, "status", "status", 16)
	if err := tx.Table("schema_migrations").Select(cols).Order("version").Limit(len(expected) + 1).Find(&applied).Error; err != nil {
		return out, err
	}
	out.Applied = len(applied)
	if verifyHistory(expected, applied, true) != nil {
		out.State = "incompatible"
	}
	return out, nil
}

func systemStatusJobs(tx *gorm.DB, org int64, now time.Time) (SystemStatusJobs, error) {
	var counts struct{ Total, Ready, Delayed, Leased, Expired, Invalid int64 }
	err := tx.Raw(`SELECT COUNT(*) AS total,
	 COALESCE(SUM(CASE WHEN status='pending' AND available_at<=? THEN 1 ELSE 0 END),0) AS ready,
	 COALESCE(SUM(CASE WHEN status='pending' AND available_at>? THEN 1 ELSE 0 END),0) AS delayed,
	 COALESCE(SUM(CASE WHEN status='running' AND lease_until>? THEN 1 ELSE 0 END),0) AS leased,
	 COALESCE(SUM(CASE WHEN status='running' AND lease_until<=? THEN 1 ELSE 0 END),0) AS expired,
	 COALESCE(SUM(CASE WHEN created_at>? OR (status='running' AND lease_until IS NULL) THEN 1 ELSE 0 END),0) AS invalid
	 FROM (SELECT status,available_at,lease_until,created_at FROM integrity_jobs WHERE organization_id=? AND status IN ('pending','running') LIMIT 10001) system_status_jobs`, now, now, now, now, now, org).Scan(&counts).Error
	if err != nil {
		return SystemStatusJobs{}, err
	}
	if counts.Total > SystemStatusMaxJobs {
		return SystemStatusJobs{State: "limit_exceeded"}, nil
	}
	if counts.Invalid != 0 || counts.Total != counts.Ready+counts.Delayed+counts.Leased+counts.Expired {
		return SystemStatusJobs{State: "invalid"}, nil
	}
	return SystemStatusJobs{"observed", &counts.Total, &counts.Ready, &counts.Delayed, &counts.Leased, &counts.Expired}, nil
}

func (s *Store) systemStatusAudit(tx *gorm.DB, org int64) (SystemStatusAudit, error) {
	if s.auditSigner == nil {
		return SystemStatusAudit{State: "unavailable"}, nil
	}
	var head auditChainHead
	cols := "organization_id,event_count,updated_at," + readBoundedText(tx, "event_hash", "event_hash", 64) + "," + readBoundedText(tx, "key_version", "key_version", 128)
	if err := tx.Select(cols).Where("organization_id=?", org).Take(&head).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return SystemStatusAudit{State: "invalid"}, nil
		}
		return SystemStatusAudit{}, err
	}
	if head.EventCount < 1 {
		return SystemStatusAudit{State: "invalid"}, nil
	}
	cols = "id,organization_id,sequence,actor_id,created_at"
	for _, field := range []struct {
		name  string
		limit int
	}{{"action", 128}, {"object_type", 128}, {"object_id", 128}, {"result", 128}, {"ip_summary", 128}, {"user_agent_summary", 128}, {"diff_summary", 1024}, {"previous_hash", 64}, {"event_hmac", 64}, {"canonicalization_version", 128}, {"key_version", 128}} {
		// Unlike JSON readers, an empty audit summary can be legitimate. An
		// overflow must become a control-character sentinel that Canonical
		// rejects, never a valid original empty value with a matching HMAC.
		cols += "," + strings.Replace(readBoundedText(tx, field.name, field.name, field.limit), "ELSE ''", "ELSE '\n'", 1)
	}
	var events []audit.Event
	if err := tx.Select(cols).Where("organization_id=?", org).Order("sequence DESC").Limit(2).Find(&events).Error; err != nil {
		return SystemStatusAudit{}, err
	}
	verified, err := s.verifyAuditTailRecords(head, events)
	if errors.Is(err, audit.ErrUnavailable) {
		return SystemStatusAudit{State: "unavailable"}, nil
	}
	if err != nil || verified.LastEventAt != nil && (verified.LastEventAt.Year() < 2000 || verified.LastEventAt.Year() > 2100) {
		return SystemStatusAudit{State: "invalid"}, nil
	}
	return SystemStatusAudit{"verified", &verified.VerifiedCount, verified.LastEventAt}, nil
}
