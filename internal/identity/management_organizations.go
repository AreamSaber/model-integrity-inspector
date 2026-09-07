package identity

import (
	"context"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

type OrganizationCreate struct{ Name, Timezone string }
type OrganizationPatch = repository.ManagedOrganizationPatch
type MemberCreate = repository.ManagedMemberCreate
type MemberPatch = repository.ManagedMemberPatch

func (s *Service) ListOrganizations(ctx context.Context, token string, list ManagementList) ([]OrganizationSummary, error) {
	ctx, auth, err := s.managementAuthority(ctx, token, 0, "organizations.list", "")
	if err != nil {
		return nil, err
	}
	result, err := s.store.ManageListOrganizations(ctx, auth, list)
	return result, managementServiceError(err)
}
func (s *Service) GetOrganization(ctx context.Context, token string, orgID int64) (OrganizationSummary, error) {
	ctx, auth, err := s.managementAuthority(ctx, token, orgID, "organization.read", "")
	if err != nil {
		return OrganizationSummary{}, err
	}
	result, err := s.store.ManageGetOrganization(ctx, auth, orgID)
	return result, managementServiceError(err)
}
func (s *Service) CreateOrganization(ctx context.Context, token string, input OrganizationCreate) (OrganizationSummary, error) {
	ctx, auth, err := s.managementAuthority(ctx, token, 0, "system.organizations", "system.organization_create")
	if err != nil {
		return OrganizationSummary{}, err
	}
	if input.Timezone == "" {
		input.Timezone = "UTC"
	}
	if !validTimezone(input.Timezone) {
		return OrganizationSummary{}, ErrManagementValidation
	}
	roles := make([]repository.InitialRole, 0, 5)
	for name, permissions := range BuiltinPermissions() {
		roles = append(roles, repository.InitialRole{Name: name, Description: name, Permissions: permissions})
	}
	result, err := s.store.ManageCreateOrganization(ctx, auth, repository.ManagedOrganizationCreate{Name: input.Name, Timezone: input.Timezone, Roles: roles})
	return result, managementServiceError(err)
}
func (s *Service) UpdateOrganization(ctx context.Context, token string, orgID int64, input OrganizationPatch) (OrganizationSummary, error) {
	ctx, auth, err := s.managementAuthority(ctx, token, 0, "system.organizations", "system.organization_update")
	if err != nil {
		return OrganizationSummary{}, err
	}
	if input.Timezone != nil && !validTimezone(*input.Timezone) {
		return OrganizationSummary{}, ErrManagementValidation
	}
	result, err := s.store.ManageUpdateOrganization(ctx, auth, orgID, input)
	return result, managementServiceError(err)
}
func (s *Service) ListMembers(ctx context.Context, token string, orgID int64, list ManagementList) ([]MemberSummary, error) {
	ctx, auth, err := s.managementAuthority(ctx, token, orgID, "member.read", "")
	if err != nil {
		return nil, err
	}
	result, err := s.store.ManageListMembers(ctx, auth, orgID, list)
	return result, managementServiceError(err)
}
func (s *Service) AddMember(ctx context.Context, token string, orgID int64, input MemberCreate) (MemberSummary, error) {
	ctx, auth, err := s.managementAuthority(ctx, token, orgID, "member.write", "organization.member_add")
	if err != nil {
		return MemberSummary{}, err
	}
	result, err := s.store.ManageAddMember(ctx, auth, orgID, input)
	return result, managementServiceError(err)
}
func (s *Service) UpdateMember(ctx context.Context, token string, orgID, memberID int64, input MemberPatch) (MemberSummary, error) {
	ctx, auth, err := s.managementAuthority(ctx, token, orgID, "member.write", "organization.member_update")
	if err != nil {
		return MemberSummary{}, err
	}
	result, err := s.store.ManageUpdateMember(ctx, auth, orgID, memberID, input)
	return result, managementServiceError(err)
}
func (s *Service) RevokeMember(ctx context.Context, token string, orgID, memberID int64, expectedVersion int) (MemberSummary, error) {
	status := "disabled"
	return s.UpdateMember(ctx, token, orgID, memberID, MemberPatch{ExpectedVersion: expectedVersion, Status: &status})
}
func (s *Service) ListRoles(ctx context.Context, token string, orgID int64) ([]RoleSummary, error) {
	ctx, auth, err := s.managementAuthority(ctx, token, orgID, "read", "")
	if err != nil {
		return nil, err
	}
	result, err := s.store.ManageListRoles(ctx, auth, orgID)
	return result, managementServiceError(err)
}
