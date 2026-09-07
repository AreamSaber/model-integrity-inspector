package repository

import (
	"context"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type ManagedUserCreate struct {
	Username, DisplayName string
	PasswordHash          string `json:"-"`
}
type ManagedUserPatch struct {
	ExpectedVersion     int
	DisplayName, Status *string
}

func (s *Store) ManageListUsers(ctx context.Context, auth ManagementAuthority, list ManagementList) ([]UserSummary, error) {
	result := []UserSummary{}
	if !validManagementList(list) {
		return nil, ErrConfiguration
	}
	err := s.managementTransaction(ctx, auth, 0, "system.users", false, func(tx *gorm.DB, _ User) error {
		q := tx.Table("users").Select(userSummaryColumns).Where("id > ?", list.AfterID)
		if list.Query != "" {
			q = q.Where("(LOWER(username) LIKE ? ESCAPE '!' OR LOWER(display_name) LIKE ? ESCAPE '!')", managementLike(list.Query), managementLike(list.Query))
		}
		return q.Order("id").Limit(list.Limit).Scan(&result).Error
	})
	return result, err
}

func (s *Store) ManageCreateUser(ctx context.Context, auth ManagementAuthority, input ManagedUserCreate) (UserSummary, error) {
	var result UserSummary
	if !validManagementText(input.Username, 64, true) || !validManagementText(input.DisplayName, 128, false) || input.PasswordHash == "" {
		return result, ErrConfiguration
	}
	err := s.managementTransaction(ctx, auth, 0, "system.users", true, func(tx *gorm.DB, _ User) error {
		id, err := NewID()
		if err != nil {
			return err
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		user := User{ID: id, Username: strings.TrimSpace(input.Username), UsernameNormalized: NormalizeUsername(input.Username), DisplayName: input.DisplayName, PasswordHash: input.PasswordHash, Status: "active", MustChangePassword: true, Version: 1, PasswordChangedAt: now, CreatedAt: now, UpdatedAt: now}
		if err := tx.Create(&user).Error; err != nil {
			return err
		}
		if err := s.auditManagedUser(ctx, tx, id, "system.user_create"); err != nil {
			return err
		}
		result, err = loadUserSummary(tx, id)
		return err
	})
	return result, err
}

func (s *Store) lockManagedUser(tx *gorm.DB, userID int64) (User, error) {
	var user User
	q := tx.Where("id = ?", userID)
	if s.driver == "postgres" {
		q = q.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	err := q.First(&user).Error
	return user, err
}

func (s *Store) ManageUpdateUser(ctx context.Context, auth ManagementAuthority, userID int64, input ManagedUserPatch) (UserSummary, error) {
	var result UserSummary
	if userID <= 0 || input.ExpectedVersion <= 0 || (input.DisplayName == nil && input.Status == nil) {
		return result, ErrConfiguration
	}
	if input.DisplayName != nil && !validManagementText(*input.DisplayName, 128, false) {
		return result, ErrConfiguration
	}
	if input.Status != nil && *input.Status != "active" && *input.Status != "disabled" {
		return result, ErrConfiguration
	}
	err := s.managementTransaction(ctx, auth, 0, "system.users", true, func(tx *gorm.DB, _ User) error {
		user, err := s.lockManagedUser(tx, userID)
		if err != nil {
			return err
		}
		if user.Version != input.ExpectedVersion {
			return ErrConflict
		}
		if input.Status != nil && *input.Status == "disabled" {
			if user.ID == auth.UserID {
				return ErrSelfLockout
			}
			if user.Status == "active" {
				if err := protectDisabledUser(tx, user); err != nil {
					return err
				}
			}
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		updates := map[string]any{"version": gorm.Expr("version + 1"), "updated_at": now}
		if input.DisplayName != nil {
			updates["display_name"] = *input.DisplayName
		}
		if input.Status != nil {
			updates["status"] = *input.Status
		}
		if err := tx.Model(&User{}).Where("id=? AND version=?", userID, input.ExpectedVersion).Updates(updates).Error; err != nil {
			return err
		}
		if input.Status != nil && *input.Status == "disabled" {
			if err := revokeManagedSessions(tx, userID, now); err != nil {
				return err
			}
		}
		if err := s.auditManagedUser(ctx, tx, userID, "system.user_update"); err != nil {
			return err
		}
		result, err = loadUserSummary(tx, userID)
		return err
	})
	return result, err
}

func protectDisabledUser(tx *gorm.DB, user User) error {
	if user.IsSystemAdmin {
		var others int64
		if err := tx.Model(&User{}).Where("id<>? AND status='active' AND is_system_admin=?", user.ID, true).Count(&others).Error; err != nil {
			return err
		}
		if others == 0 {
			return ErrLastAdministrator
		}
	}
	var orgIDs []int64
	if err := tx.Table("organization_members om").Distinct("om.organization_id").
		Joins("JOIN member_roles mr ON mr.organization_id=om.organization_id AND mr.member_id=om.id").
		Joins("JOIN roles r ON r.organization_id=mr.organization_id AND r.id=mr.role_id").
		Where("om.user_id=? AND om.status='active' AND r.name='admin'", user.ID).Pluck("om.organization_id", &orgIDs).Error; err != nil {
		return err
	}
	for _, orgID := range orgIDs {
		count, err := activeAdminCount(tx, orgID, user.ID)
		if err != nil {
			return err
		}
		if count == 0 {
			return ErrLastAdministrator
		}
	}
	return nil
}

func revokeManagedSessions(tx *gorm.DB, userID int64, now time.Time) error {
	return tx.Model(&Session{}).Where("user_id=? AND revoked_at IS NULL", userID).Update("revoked_at", now).Error
}

func (s *Store) ManageUnlockUser(ctx context.Context, auth ManagementAuthority, userID int64, expectedVersion int) (UserSummary, error) {
	return s.manageUserSecurity(ctx, auth, userID, expectedVersion, "", false)
}

// Hashes are produced by the bounded service Argon2 worker before this call.
func (s *Store) ManageResetUserPassword(ctx context.Context, auth ManagementAuthority, userID int64, expectedVersion int, passwordHash string) (UserSummary, error) {
	if passwordHash == "" {
		return UserSummary{}, ErrConfiguration
	}
	return s.manageUserSecurity(ctx, auth, userID, expectedVersion, passwordHash, true)
}

func (s *Store) manageUserSecurity(ctx context.Context, auth ManagementAuthority, userID int64, version int, passwordHash string, reset bool) (UserSummary, error) {
	var result UserSummary
	if userID <= 0 || version <= 0 {
		return result, ErrConfiguration
	}
	err := s.managementTransaction(ctx, auth, 0, "system.users", true, func(tx *gorm.DB, _ User) error {
		user, err := s.lockManagedUser(tx, userID)
		if err != nil {
			return err
		}
		if user.Version != version {
			return ErrConflict
		}
		if reset && userID == auth.UserID {
			return ErrSelfLockout
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		updates := map[string]any{"failed_login_count": 0, "locked_until": nil, "version": gorm.Expr("version + 1"), "updated_at": now}
		action := "system.user_unlock"
		if reset {
			updates["password_hash"] = passwordHash
			updates["password_changed_at"] = now
			updates["must_change_password"] = true
			action = "system.user_password_reset"
		}
		if err := tx.Model(&User{}).Where("id=? AND version=?", userID, version).Updates(updates).Error; err != nil {
			return err
		}
		if reset {
			if err := revokeManagedSessions(tx, userID, now); err != nil {
				return err
			}
		}
		if err := s.auditManagedUser(ctx, tx, userID, action); err != nil {
			return err
		}
		result, err = loadUserSummary(tx, userID)
		return err
	})
	return result, err
}
