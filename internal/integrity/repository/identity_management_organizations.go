package repository

import (
	"context"
	"slices"
	"strings"
	"time"

	"gorm.io/gorm"
)

type ManagedOrganizationCreate struct {
	Name, Timezone string
	Roles          []InitialRole
}
type ManagedOrganizationPatch struct {
	ExpectedVersion           int
	Name, Timezone, Status    *string
	FullResponseRetentionDays *int
}

func (s *Store) ManageListOrganizations(ctx context.Context, auth ManagementAuthority, list ManagementList) ([]OrganizationSummary, error) {
	result := []OrganizationSummary{}
	if !validManagementList(list) {
		return nil, ErrConfiguration
	}
	err := s.managementTransaction(ctx, auth, 0, "organizations.list", false, func(tx *gorm.DB, user User) error {
		q := tx.Table("organizations").Select(orgSummaryColumns).Where("id > ?", list.AfterID)
		if !user.IsSystemAdmin {
			q = q.Where("status='active' AND id IN (SELECT organization_id FROM organization_members WHERE user_id=? AND status='active')", user.ID)
		}
		if list.Query != "" {
			q = q.Where("LOWER(name) LIKE ? ESCAPE '!'", managementLike(list.Query))
		}
		return q.Order("id").Limit(list.Limit).Scan(&result).Error
	})
	return result, err
}

func (s *Store) ManageGetOrganization(ctx context.Context, auth ManagementAuthority, orgID int64) (OrganizationSummary, error) {
	var result OrganizationSummary
	err := s.managementTransaction(ctx, auth, orgID, "organization.read", false, func(tx *gorm.DB, _ User) error {
		var err error
		result, err = loadOrganizationSummary(tx, orgID)
		return err
	})
	return result, err
}

func (s *Store) ManageCreateOrganization(ctx context.Context, auth ManagementAuthority, input ManagedOrganizationCreate) (OrganizationSummary, error) {
	var result OrganizationSummary
	if !validManagementText(input.Name, 128, true) || !validManagementText(input.Timezone, 64, true) || len(input.Roles) != 5 {
		return result, ErrConfiguration
	}
	seen := map[string]bool{}
	for _, role := range input.Roles {
		if !builtinRoleName(role.Name) || seen[role.Name] || len(role.Permissions) == 0 {
			return result, ErrConfiguration
		}
		seen[role.Name] = true
		for _, p := range role.Permissions {
			if !validManagementText(p, 128, true) || strings.HasPrefix(p, "system.") {
				return result, ErrConfiguration
			}
		}
	}
	err := s.managementTransaction(ctx, auth, 0, "system.organizations", true, func(tx *gorm.DB, user User) error {
		orgID, err := NewID()
		if err != nil {
			return err
		}
		memberID, err := NewID()
		if err != nil {
			return err
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		org := Organization{ID: orgID, Name: strings.TrimSpace(input.Name), Timezone: input.Timezone, Status: "active", QuotaJSON: "{}", FullResponseRetentionDays: 30, Version: 1, CreatedAt: now, UpdatedAt: now}
		if err := tx.Create(&org).Error; err != nil {
			return err
		}
		member := Membership{ID: memberID, OrganizationID: orgID, UserID: user.ID, Status: "active", Version: 1, CreatedAt: now, UpdatedAt: now}
		if err := tx.Create(&member).Error; err != nil {
			return err
		}
		for _, spec := range input.Roles {
			roleID, err := NewID()
			if err != nil {
				return err
			}
			role := Role{ID: roleID, OrganizationID: orgID, Name: spec.Name, Description: spec.Description, IsBuiltin: true, CreatedAt: now}
			if err := tx.Create(&role).Error; err != nil {
				return err
			}
			permissions := slices.Clone(spec.Permissions)
			slices.Sort(permissions)
			permissions = slices.Compact(permissions)
			for _, p := range permissions {
				if err := tx.Exec("INSERT INTO permissions (code,description) VALUES (?,'') ON CONFLICT (code) DO NOTHING", p).Error; err != nil {
					return err
				}
				if err := tx.Exec("INSERT INTO role_permissions (organization_id,role_id,permission_code) VALUES (?,?,?)", orgID, roleID, p).Error; err != nil {
					return err
				}
			}
			if role.Name == "admin" {
				if err := tx.Exec("INSERT INTO member_roles (organization_id,member_id,role_id) VALUES (?,?,?)", orgID, memberID, roleID).Error; err != nil {
					return err
				}
			}
		}
		if err := s.auditManagement(ctx, tx, []int64{orgID}, auditObject("system.organization_create", "organization", orgID)); err != nil {
			return err
		}
		result, err = loadOrganizationSummary(tx, orgID)
		return err
	})
	return result, err
}

func (s *Store) ManageUpdateOrganization(ctx context.Context, auth ManagementAuthority, orgID int64, input ManagedOrganizationPatch) (OrganizationSummary, error) {
	var result OrganizationSummary
	if orgID <= 0 || input.ExpectedVersion <= 0 || (input.Name == nil && input.Timezone == nil && input.Status == nil && input.FullResponseRetentionDays == nil) {
		return result, ErrConfiguration
	}
	if input.Name != nil && !validManagementText(*input.Name, 128, true) {
		return result, ErrConfiguration
	}
	if input.Timezone != nil && !validManagementText(*input.Timezone, 64, true) {
		return result, ErrConfiguration
	}
	if input.Status != nil && *input.Status != "active" && *input.Status != "disabled" {
		return result, ErrConfiguration
	}
	if input.FullResponseRetentionDays != nil && (*input.FullResponseRetentionDays < 0 || *input.FullResponseRetentionDays > 180) {
		return result, ErrConfiguration
	}
	err := s.managementTransaction(ctx, auth, 0, "system.organizations", true, func(tx *gorm.DB, _ User) error {
		org, err := loadOrganizationSummary(tx, orgID)
		if err != nil {
			return err
		}
		if org.Version != input.ExpectedVersion {
			return ErrConflict
		}
		updates := map[string]any{"version": gorm.Expr("version + 1"), "updated_at": time.Now().UTC().Truncate(time.Microsecond)}
		if input.Name != nil {
			updates["name"] = strings.TrimSpace(*input.Name)
		}
		if input.Timezone != nil {
			updates["timezone"] = *input.Timezone
		}
		if input.Status != nil {
			updates["status"] = *input.Status
		}
		if input.FullResponseRetentionDays != nil {
			updates["full_response_retention_days"] = *input.FullResponseRetentionDays
		}
		if err := tx.Model(&Organization{}).Where("id=? AND version=?", orgID, input.ExpectedVersion).Updates(updates).Error; err != nil {
			return err
		}
		if err := s.auditManagement(ctx, tx, []int64{orgID}, auditObject("system.organization_update", "organization", orgID)); err != nil {
			return err
		}
		result, err = loadOrganizationSummary(tx, orgID)
		return err
	})
	return result, err
}
