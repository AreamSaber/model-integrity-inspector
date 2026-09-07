package repository

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

var (
	ErrManagementPermission   = errors.New("MANAGEMENT_PERMISSION_DENIED")
	ErrManagementSession      = errors.New("MANAGEMENT_SESSION_INVALID")
	ErrPasswordChangeRequired = errors.New("PASSWORD_CHANGE_REQUIRED")
	ErrLastAdministrator      = errors.New("LAST_ADMINISTRATOR")
	ErrSelfLockout            = errors.New("SELF_LOCKOUT_FORBIDDEN")
)

// ManagementAuthority is issued by the authenticated service, never decoded
// from an HTTP body. Its active session and grants are rechecked inside SQL.
type ManagementAuthority struct{ UserID, SessionID int64 }
type ManagementList struct {
	AfterID int64
	Limit   int
	Query   string
}

type UserSummary struct {
	ID                                int64
	Username, DisplayName, Status     string
	IsSystemAdmin, MustChangePassword bool
	Version                           int
	CreatedAt, UpdatedAt              time.Time
}
type OrganizationSummary struct {
	ID                                 int64
	Name, Timezone, Status             string
	FullResponseRetentionDays, Version int
	CreatedAt, UpdatedAt               time.Time
}
type MemberSummary struct {
	ID, OrganizationID, UserID int64
	Username, Status           string
	Roles, Permissions         []string `gorm:"-"`
	Version                    int
	CreatedAt, UpdatedAt       time.Time
}
type RoleSummary struct {
	Name        string
	Permissions []string
}

const userSummaryColumns = "id, username, display_name, status, is_system_admin, must_change_password, version, created_at, updated_at"
const orgSummaryColumns = "id, name, timezone, status, full_response_retention_days, version, created_at, updated_at"

func managementError(err error) error {
	for _, known := range []error{ErrManagementPermission, ErrManagementSession, ErrPasswordChangeRequired, ErrLastAdministrator, ErrSelfLockout} {
		if errors.Is(err, known) {
			return known
		}
	}
	return persistenceError(err)
}

// Every management mutation shares a short transaction lock. This serializes
// last-admin counts and role edits across API instances; no network/hash work
// occurs while held. SQLite uses the Store's BEGIN IMMEDIATE transaction policy.
func (s *Store) managementTransaction(ctx context.Context, auth ManagementAuthority, orgID int64, permission string, write bool, fn func(*gorm.DB, User) error) error {
	if auth.UserID <= 0 || auth.SessionID <= 0 {
		return ErrManagementSession
	}
	if write {
		if err := s.auditReady(ctx); err != nil {
			return err
		}
		actor, err := audit.ActorFromContext(ctx)
		if err != nil || actor.ActorID != auth.UserID {
			return audit.ErrActorRequired
		}
	}
	return managementError(s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if write && s.driver == "postgres" {
			if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", migrationLockID+100).Error; err != nil {
				return err
			}
		}
		var user User
		q := tx.Where("id = ?", auth.UserID)
		if write && s.driver == "postgres" {
			q = q.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		if err := q.First(&user).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrManagementSession
			}
			return err
		}
		var session Session
		q = tx.Where("id = ? AND user_id = ?", auth.SessionID, auth.UserID)
		if write && s.driver == "postgres" {
			q = q.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		if err := q.First(&session).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrManagementSession
			}
			return err
		}
		if user.Status != "active" || session.RevokedAt != nil || !session.ExpiresAt.After(time.Now()) || session.CreatedAt.Before(user.PasswordChangedAt) {
			return ErrManagementSession
		}
		if user.MustChangePassword {
			return ErrPasswordChangeRequired
		}
		if strings.HasPrefix(permission, "system.") {
			if !user.IsSystemAdmin {
				return ErrManagementPermission
			}
		} else if permission != "organizations.list" {
			if orgID <= 0 {
				return ErrOrganizationScope
			}
			codes, err := managementPermissions(tx, orgID, user.ID)
			if err != nil {
				return err
			}
			if !slices.Contains(codes, permission) {
				return ErrManagementPermission
			}
		}
		return fn(tx, user)
	}))
}

func managementPermissions(tx *gorm.DB, orgID, userID int64) ([]string, error) {
	var codes []string
	err := tx.Raw(`SELECT permission_code FROM (
		SELECT rp.permission_code FROM role_permissions rp
		JOIN member_roles mr ON mr.organization_id=rp.organization_id AND mr.role_id=rp.role_id
		JOIN organization_members om ON om.organization_id=mr.organization_id AND om.id=mr.member_id
		JOIN organizations o ON o.id=om.organization_id JOIN users u ON u.id=om.user_id
		WHERE om.organization_id=? AND om.user_id=? AND om.status='active' AND o.status='active' AND u.status='active'
		UNION
		SELECT mp.permission_code FROM member_permissions mp
		JOIN organization_members om ON om.organization_id=mp.organization_id AND om.id=mp.member_id
		JOIN organizations o ON o.id=om.organization_id JOIN users u ON u.id=om.user_id
		WHERE om.organization_id=? AND om.user_id=? AND om.status='active' AND o.status='active' AND u.status='active'
	) effective_permissions ORDER BY permission_code`, orgID, userID, orgID, userID).Scan(&codes).Error
	return codes, err
}

func validManagementText(value string, max int, required bool) bool {
	if !utf8.ValidString(value) || len(value) > max || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	return !required || strings.TrimSpace(value) != ""
}
func validManagementList(input ManagementList) bool {
	return input.AfterID >= 0 && input.Limit >= 1 && input.Limit <= 100 && validManagementText(input.Query, 128, false)
}
func managementLike(value string) string {
	return "%" + strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(strings.ToLower(value)) + "%"
}
func loadUserSummary(tx *gorm.DB, id int64) (UserSummary, error) {
	var result UserSummary
	err := tx.Table("users").Select(userSummaryColumns).Where("id = ?", id).Take(&result).Error
	return result, err
}
func loadOrganizationSummary(tx *gorm.DB, id int64) (OrganizationSummary, error) {
	var result OrganizationSummary
	err := tx.Table("organizations").Select(orgSummaryColumns).Where("id = ?", id).Take(&result).Error
	return result, err
}

// System mutations are anchored in the initial organization plus all affected
// organizations, in ascending lock order shared with authentication auditing.
func (s *Store) auditManagement(ctx context.Context, tx *gorm.DB, orgIDs []int64, command AuditCommand) error {
	anchor, err := initialAuditOrganization(tx)
	if err != nil {
		return err
	}
	ids := append(slices.Clone(orgIDs), anchor)
	slices.Sort(ids)
	ids = slices.Compact(ids)
	for _, id := range ids {
		if err := s.appendAudit(ctx, tx, id, command, nil); err != nil {
			return err
		}
	}
	return nil
}
func (s *Store) auditManagedUser(ctx context.Context, tx *gorm.DB, userID int64, action string) error {
	var orgIDs []int64
	if err := tx.Table("organization_members").Where("user_id = ?", userID).Pluck("organization_id", &orgIDs).Error; err != nil {
		return err
	}
	return s.auditManagement(ctx, tx, orgIDs, auditObject(action, "user", userID))
}

func builtinRoleName(name string) bool {
	return slices.Contains([]string{"admin", "operator", "auditor", "developer", "viewer"}, name)
}

func activeAdminCount(tx *gorm.DB, orgID, excludingUserID int64) (int64, error) {
	var count int64
	err := tx.Table("organization_members AS om").Distinct("om.user_id").
		Joins("JOIN users u ON u.id=om.user_id").
		Joins("JOIN member_roles mr ON mr.organization_id=om.organization_id AND mr.member_id=om.id").
		Joins("JOIN roles r ON r.organization_id=mr.organization_id AND r.id=mr.role_id").
		Where("om.organization_id=? AND om.user_id<>? AND om.status='active' AND u.status='active' AND r.name='admin'", orgID, excludingUserID).Count(&count).Error
	return count, err
}
