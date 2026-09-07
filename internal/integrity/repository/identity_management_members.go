package repository

import (
	"context"
	"slices"
	"strings"
	"time"

	"gorm.io/gorm"
)

type ManagedMemberCreate struct {
	UserID             int64
	Roles, Permissions []string
}

// Nil slices are unchanged; non-nil empty permissions explicitly clears grants.
type ManagedMemberPatch struct {
	ExpectedVersion    int
	Roles, Permissions []string
	Status             *string
}

func loadMemberSummary(tx *gorm.DB, orgID, memberID int64) (MemberSummary, error) {
	var result MemberSummary
	err := tx.Table("organization_members om").Select("om.id, om.organization_id, om.user_id, u.username, om.status, om.version, om.created_at, om.updated_at").
		Joins("JOIN users u ON u.id=om.user_id").Where("om.organization_id=? AND om.id=?", orgID, memberID).Take(&result).Error
	if err != nil {
		return result, err
	}
	result.Roles = []string{}
	result.Permissions = []string{}
	if err := tx.Table("member_roles mr").Joins("JOIN roles r ON r.organization_id=mr.organization_id AND r.id=mr.role_id").Where("mr.organization_id=? AND mr.member_id=?", orgID, memberID).Order("r.name").Pluck("r.name", &result.Roles).Error; err != nil {
		return result, err
	}
	err = tx.Table("member_permissions").Where("organization_id=? AND member_id=?", orgID, memberID).Order("permission_code").Pluck("permission_code", &result.Permissions).Error
	return result, err
}

func (s *Store) ManageListMembers(ctx context.Context, auth ManagementAuthority, orgID int64, list ManagementList) ([]MemberSummary, error) {
	result := []MemberSummary{}
	if !validManagementList(list) {
		return nil, ErrConfiguration
	}
	err := s.managementTransaction(ctx, auth, orgID, "member.read", false, func(tx *gorm.DB, _ User) error {
		var ids []int64
		q := tx.Table("organization_members om").Joins("JOIN users u ON u.id=om.user_id").Where("om.organization_id=? AND om.id>?", orgID, list.AfterID)
		if list.Query != "" {
			q = q.Where("LOWER(u.username) LIKE ? ESCAPE '!'", managementLike(list.Query))
		}
		if err := q.Order("om.id").Limit(list.Limit).Pluck("om.id", &ids).Error; err != nil {
			return err
		}
		for _, id := range ids {
			member, err := loadMemberSummary(tx, orgID, id)
			if err != nil {
				return err
			}
			result = append(result, member)
		}
		return nil
	})
	return result, err
}

func (s *Store) ManageListRoles(ctx context.Context, auth ManagementAuthority, orgID int64) ([]RoleSummary, error) {
	result := []RoleSummary{}
	err := s.managementTransaction(ctx, auth, orgID, "read", false, func(tx *gorm.DB, _ User) error {
		var roles []Role
		if err := tx.Where("organization_id=? AND is_builtin=?", orgID, true).Order("name").Find(&roles).Error; err != nil {
			return err
		}
		for _, role := range roles {
			if !builtinRoleName(role.Name) {
				continue
			}
			item := RoleSummary{Name: role.Name, Permissions: []string{}}
			if err := tx.Table("role_permissions").Where("organization_id=? AND role_id=?", orgID, role.ID).Order("permission_code").Pluck("permission_code", &item.Permissions).Error; err != nil {
				return err
			}
			result = append(result, item)
		}
		return nil
	})
	return result, err
}

func validateMemberGrants(tx *gorm.DB, orgID, actorID int64, roles, permissions []string, status string) ([]Role, error) {
	if len(roles) > 5 || len(permissions) > 100 || (status == "active" && len(roles) == 0) {
		return nil, ErrConfiguration
	}
	seen := map[string]bool{}
	for _, role := range roles {
		if !builtinRoleName(role) || seen[role] {
			return nil, ErrConfiguration
		}
		seen[role] = true
	}
	for _, p := range permissions {
		if !validManagementText(p, 128, true) || strings.HasPrefix(p, "system.") {
			return nil, ErrManagementPermission
		}
	}
	var records []Role
	if len(roles) > 0 {
		if err := tx.Where("organization_id=? AND name IN ? AND is_builtin=?", orgID, roles, true).Find(&records).Error; err != nil {
			return nil, err
		}
	}
	if len(records) != len(roles) {
		return nil, ErrConfiguration
	}
	actorGrants, err := managementPermissions(tx, orgID, actorID)
	if err != nil {
		return nil, err
	}
	canGrant := func(p string) bool {
		return slices.Contains(actorGrants, p) || (p == "run.cancel-own" && slices.Contains(actorGrants, "run.cancel-any"))
	}
	for _, role := range records {
		var effective []string
		if err := tx.Table("role_permissions").Where("organization_id=? AND role_id=?", orgID, role.ID).Pluck("permission_code", &effective).Error; err != nil {
			return nil, err
		}
		for _, p := range effective {
			if strings.HasPrefix(p, "system.") || !canGrant(p) {
				return nil, ErrManagementPermission
			}
		}
	}
	for _, p := range permissions {
		if !canGrant(p) {
			return nil, ErrManagementPermission
		}
		// Existing frozen role grants are the allowlist; the permission registry
		// alone may contain unrelated future/system codes and is not authority.
		var count int64
		if err := tx.Table("role_permissions rp").Joins("JOIN roles r ON r.organization_id=rp.organization_id AND r.id=rp.role_id").Where("rp.organization_id=? AND rp.permission_code=? AND r.is_builtin=?", orgID, p, true).Count(&count).Error; err != nil {
			return nil, err
		}
		if count == 0 {
			return nil, ErrManagementPermission
		}
	}
	return records, nil
}

func saveMemberGrants(tx *gorm.DB, orgID, memberID int64, roles []Role, permissions []string) error {
	if err := tx.Exec("DELETE FROM member_roles WHERE organization_id=? AND member_id=?", orgID, memberID).Error; err != nil {
		return err
	}
	if err := tx.Exec("DELETE FROM member_permissions WHERE organization_id=? AND member_id=?", orgID, memberID).Error; err != nil {
		return err
	}
	for _, role := range roles {
		if err := tx.Exec("INSERT INTO member_roles (organization_id,member_id,role_id) VALUES (?,?,?)", orgID, memberID, role.ID).Error; err != nil {
			return err
		}
	}
	grants := slices.Clone(permissions)
	slices.Sort(grants)
	grants = slices.Compact(grants)
	for _, p := range grants {
		if err := tx.Exec("INSERT INTO member_permissions (organization_id,member_id,permission_code) VALUES (?,?,?)", orgID, memberID, p).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ManageAddMember(ctx context.Context, auth ManagementAuthority, orgID int64, input ManagedMemberCreate) (MemberSummary, error) {
	var result MemberSummary
	if orgID <= 0 || input.UserID <= 0 {
		return result, ErrConfiguration
	}
	err := s.managementTransaction(ctx, auth, orgID, "member.write", true, func(tx *gorm.DB, _ User) error {
		user, err := s.lockManagedUser(tx, input.UserID)
		if err != nil {
			return err
		}
		if user.Status != "active" {
			return ErrConflict
		}
		roles, err := validateMemberGrants(tx, orgID, auth.UserID, input.Roles, input.Permissions, "active")
		if err != nil {
			return err
		}
		id, err := NewID()
		if err != nil {
			return err
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		member := Membership{ID: id, OrganizationID: orgID, UserID: input.UserID, Status: "active", Version: 1, CreatedAt: now, UpdatedAt: now}
		if err := tx.Create(&member).Error; err != nil {
			return err
		}
		if err := saveMemberGrants(tx, orgID, id, roles, input.Permissions); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, orgID, auditObject("organization.member_add", "member", id), nil); err != nil {
			return err
		}
		result, err = loadMemberSummary(tx, orgID, id)
		return err
	})
	return result, err
}

func (s *Store) ManageUpdateMember(ctx context.Context, auth ManagementAuthority, orgID, memberID int64, input ManagedMemberPatch) (MemberSummary, error) {
	var result MemberSummary
	if orgID <= 0 || memberID <= 0 || input.ExpectedVersion <= 0 || (input.Roles == nil && input.Permissions == nil && input.Status == nil) {
		return result, ErrConfiguration
	}
	if input.Status != nil && *input.Status != "active" && *input.Status != "disabled" {
		return result, ErrConfiguration
	}
	err := s.managementTransaction(ctx, auth, orgID, "member.write", true, func(tx *gorm.DB, _ User) error {
		old, err := loadMemberSummary(tx, orgID, memberID)
		if err != nil {
			return err
		}
		if old.Version != input.ExpectedVersion {
			return ErrConflict
		}
		user, err := s.lockManagedUser(tx, old.UserID)
		if err != nil {
			return err
		}
		status := old.Status
		if input.Status != nil {
			status = *input.Status
		}
		roles := input.Roles
		if roles == nil {
			roles = old.Roles
		}
		permissions := input.Permissions
		if permissions == nil {
			permissions = old.Permissions
		}
		if status == "active" && user.Status != "active" {
			return ErrConflict
		}
		if old.UserID == auth.UserID && (status != "active" || (slices.Contains(old.Roles, "admin") && !slices.Contains(roles, "admin"))) {
			return ErrSelfLockout
		}
		if old.Status == "active" && user.Status == "active" && slices.Contains(old.Roles, "admin") && (status != "active" || !slices.Contains(roles, "admin")) {
			count, err := activeAdminCount(tx, orgID, old.UserID)
			if err != nil {
				return err
			}
			if count == 0 {
				return ErrLastAdministrator
			}
		}
		records, err := validateMemberGrants(tx, orgID, auth.UserID, roles, permissions, status)
		if err != nil {
			return err
		}
		// Delegated member.write holders cannot accidentally strip their own
		// final management grant, even when they are not in the admin role.
		if old.UserID == auth.UserID {
			canManage := slices.Contains(permissions, "member.write")
			for _, role := range records {
				var count int64
				if err := tx.Table("role_permissions").Where("organization_id=? AND role_id=? AND permission_code='member.write'", orgID, role.ID).Count(&count).Error; err != nil {
					return err
				}
				canManage = canManage || count > 0
			}
			if !canManage {
				return ErrSelfLockout
			}
		}
		if err := tx.Model(&Membership{}).Where("organization_id=? AND id=? AND version=?", orgID, memberID, input.ExpectedVersion).Updates(map[string]any{"status": status, "version": gorm.Expr("version + 1"), "updated_at": time.Now().UTC().Truncate(time.Microsecond)}).Error; err != nil {
			return err
		}
		if err := saveMemberGrants(tx, orgID, memberID, records, permissions); err != nil {
			return err
		}
		action := "organization.member_update"
		if status == "disabled" {
			action = "organization.member_revoke"
		}
		if err := s.appendAudit(ctx, tx, orgID, auditObject(action, "member", memberID), nil); err != nil {
			return err
		}
		result, err = loadMemberSummary(tx, orgID, memberID)
		return err
	})
	return result, err
}
