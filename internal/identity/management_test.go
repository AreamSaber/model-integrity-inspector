package identity

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

const managedPassword = "new-managed-password-426-synthetic"

func managedAccount(t *testing.T, s *Service, ctx context.Context, admin SessionMaterial, name string) (UserSummary, SessionMaterial) {
	t.Helper()
	user, err := s.CreateUser(ctx, admin.CookieValue(), UserCreate{Username: name, DisplayName: "Test member", Password: testPassword})
	if err != nil {
		t.Fatal(err)
	}
	temporary, err := s.Login(ctx, name, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if !temporary.User.MustChangePassword {
		t.Fatal("admin password not temporary")
	}
	if err := s.ChangePassword(ctx, temporary.CookieValue(), testPassword, managedPassword); err != nil {
		t.Fatal(err)
	}
	active, err := s.Login(ctx, name, managedPassword)
	if err != nil {
		t.Fatal(err)
	}
	user.Version = active.User.Version
	user.MustChangePassword = active.User.MustChangePassword
	return user, active
}

func TestManagementTemporaryPasswordAndSystemBoundary(t *testing.T) {
	s, ctx := initializedService(t)
	admin := loginTest(t, s, ctx)
	user, err := s.CreateUser(ctx, admin.CookieValue(), UserCreate{Username: "newUser", Password: testPassword})
	if err != nil {
		t.Fatal(err)
	}
	if user.IsSystemAdmin || !user.MustChangePassword || user.Version != 1 {
		t.Fatal("unsafe user defaults")
	}
	if _, err := s.CreateUser(ctx, admin.CookieValue(), UserCreate{Username: "NEWUSER", Password: testPassword}); !errors.Is(err, ErrManagementConflict) {
		t.Fatalf("normalized username duplicate: %v", err)
	}
	material, err := s.Login(ctx, "newuser", testPassword)
	if err != nil {
		t.Fatalf("membershipless login audit fallback: %v", err)
	}
	if len(material.Organizations) != 0 {
		t.Fatal("audit anchor granted membership")
	}
	if _, err := s.Principal(ctx, material.CookieValue(), admin.Organizations[0].ID); !errors.Is(err, ErrPasswordChangeRequired) {
		t.Fatalf("temporary password grants business access: %v", err)
	}
	if _, err := s.ListUsers(ctx, material.CookieValue(), ManagementList{Limit: 25}); !errors.Is(err, ErrPasswordChangeRequired) {
		t.Fatal("temporary password grants management access")
	}
	if err := s.ChangePassword(ctx, material.CookieValue(), testPassword, managedPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Current(ctx, material.CookieValue()); !errors.Is(err, ErrSession) {
		t.Fatal("temporary session retained after change")
	}
	material, err = s.Login(ctx, "newuser", managedPassword)
	if err != nil {
		t.Fatal(err)
	}
	if material.User.MustChangePassword {
		t.Fatal("password change flag not cleared")
	}
	if _, err := s.ListUsers(ctx, material.CookieValue(), ManagementList{Limit: 25}); !errors.Is(err, ErrPermission) {
		t.Fatal("non-system user listed accounts")
	}
	if _, err := s.CreateOrganization(ctx, material.CookieValue(), OrganizationCreate{Name: "Forbidden"}); !errors.Is(err, ErrPermission) {
		t.Fatal("non-system user created organization")
	}
	items, err := s.ListUsers(ctx, admin.CookieValue(), ManagementList{Limit: 25})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "PasswordHash") || strings.Contains(string(encoded), "argon2") || strings.Contains(string(encoded), testPassword) {
		t.Fatal("account list contains credential material")
	}
	if _, err := s.UpdateUser(ctx, admin.CookieValue(), admin.User.ID, UserPatch{ExpectedVersion: admin.User.Version, Status: ptr("disabled")}); !errors.Is(err, ErrSelfLockout) {
		t.Fatal("system administrator self-disabled")
	}
	if _, err := s.ResetUserPassword(ctx, admin.CookieValue(), admin.User.ID, admin.User.Version, testPassword); !errors.Is(err, ErrSelfLockout) {
		t.Fatal("self-reset bypassed current password")
	}
	if _, err := s.Login(ctx, "newuser", "wrong-password"); !errors.Is(err, ErrAuthentication) {
		t.Fatal("membershipless failed-login audit rejected")
	}
	if err := s.Logout(ctx, material.CookieValue()); err != nil {
		t.Fatal(err)
	}
	if err := s.store.VerifyAllAudit(ctx, true); err != nil {
		t.Fatal(err)
	}
}

func ptr[T any](value T) *T { return &value }

func TestManagementMembershipGrantsIsolationAndRevocation(t *testing.T) {
	s, ctx := initializedService(t)
	admin := loginTest(t, s, ctx)
	orgID := admin.Organizations[0].ID
	user, memberSession := managedAccount(t, s, ctx, admin, "member-one")
	member, err := s.AddMember(ctx, admin.CookieValue(), orgID, MemberCreate{UserID: user.ID, Roles: []string{"viewer"}, Permissions: []string{"member.write"}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Principal(ctx, memberSession.CookieValue(), orgID)
	if err != nil || p.Authorize("member.write") != nil {
		t.Fatal("direct grant not effective")
	}
	if _, err := s.UpdateMember(ctx, memberSession.CookieValue(), orgID, member.ID, MemberPatch{ExpectedVersion: member.Version, Roles: []string{"admin"}}); !errors.Is(err, ErrPermission) {
		t.Fatalf("delegated member.write escalated to admin: %v", err)
	}
	if _, err := s.UpdateMember(ctx, memberSession.CookieValue(), orgID, member.ID, MemberPatch{ExpectedVersion: member.Version, Permissions: []string{}}); !errors.Is(err, ErrSelfLockout) {
		t.Fatalf("self management grant removed: %v", err)
	}
	for _, bad := range [][]string{{"system.users"}, {"unknown.permission"}} {
		if _, err := s.UpdateMember(ctx, admin.CookieValue(), orgID, member.ID, MemberPatch{ExpectedVersion: member.Version, Permissions: bad}); !errors.Is(err, ErrPermission) {
			t.Fatal("invalid extra permission allowed")
		}
	}
	if _, err := s.ListUsers(ctx, memberSession.CookieValue(), ManagementList{Limit: 25}); !errors.Is(err, ErrPermission) {
		t.Fatal("organization role acquired system authority")
	}
	org2, err := s.CreateOrganization(ctx, admin.CookieValue(), OrganizationCreate{Name: "Second org", Timezone: "Asia/Shanghai"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddMember(ctx, admin.CookieValue(), org2.ID, MemberCreate{UserID: user.ID, Roles: []string{"viewer"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateMember(ctx, admin.CookieValue(), org2.ID, member.ID, MemberPatch{ExpectedVersion: member.Version, Status: ptr("disabled")}); !errors.Is(err, ErrManagementNotFound) {
		t.Fatalf("cross-org member ID accepted: %v", err)
	}
	updated, err := s.UpdateMember(ctx, admin.CookieValue(), orgID, member.ID, MemberPatch{ExpectedVersion: member.Version, Roles: []string{"operator"}, Permissions: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Version != 2 || len(updated.Permissions) != 0 || !slices.Equal(updated.Roles, []string{"operator"}) {
		t.Fatal("replacement did not clear old grants")
	}
	if _, err := s.UpdateMember(ctx, admin.CookieValue(), orgID, member.ID, MemberPatch{ExpectedVersion: 1, Roles: []string{"viewer"}}); !errors.Is(err, ErrManagementConflict) {
		t.Fatal("stale member edit accepted")
	}
	if _, err := s.RevokeMember(ctx, admin.CookieValue(), orgID, member.ID, updated.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Principal(ctx, memberSession.CookieValue(), orgID); !errors.Is(err, ErrPermission) {
		t.Fatal("revoked membership retained grants")
	}
	if _, err := s.Principal(ctx, memberSession.CookieValue(), org2.ID); err != nil {
		t.Fatal("member revocation revoked unrelated organization session")
	}
	if err := s.store.VerifyAllAudit(ctx, true); err != nil {
		t.Fatal(err)
	}
}

func TestManagementOrganizationSettingsAndLastAdmin(t *testing.T) {
	s, ctx := initializedService(t)
	admin := loginTest(t, s, ctx)
	org, err := s.CreateOrganization(ctx, admin.CookieValue(), OrganizationCreate{Name: "Managed org"})
	if err != nil {
		t.Fatal(err)
	}
	if org.Timezone != "UTC" || org.FullResponseRetentionDays != 30 || org.Version != 1 {
		t.Fatal("organization defaults incorrect")
	}
	roles, err := s.ListRoles(ctx, admin.CookieValue(), org.ID)
	if err != nil || len(roles) != 5 {
		t.Fatal("organization builtin roles not atomically seeded")
	}
	org, err = s.UpdateOrganization(ctx, admin.CookieValue(), org.ID, OrganizationPatch{ExpectedVersion: org.Version, FullResponseRetentionDays: ptr(0), Name: ptr("Updated org")})
	if err != nil || org.FullResponseRetentionDays != 0 {
		t.Fatal("zero retention was discarded")
	}
	if _, err := s.UpdateOrganization(ctx, admin.CookieValue(), org.ID, OrganizationPatch{ExpectedVersion: 1, Name: ptr("Stale")}); !errors.Is(err, ErrManagementConflict) {
		t.Fatal("stale organization edit accepted")
	}
	if _, err := s.UpdateOrganization(ctx, admin.CookieValue(), org.ID, OrganizationPatch{ExpectedVersion: org.Version, FullResponseRetentionDays: ptr(181)}); !errors.Is(err, ErrManagementValidation) {
		t.Fatal("retention bounds ignored")
	}
	if _, err := s.CreateOrganization(ctx, admin.CookieValue(), OrganizationCreate{Name: "Bad timezone", Timezone: "not/a-zone"}); !errors.Is(err, ErrManagementValidation) {
		t.Fatal("invalid timezone accepted")
	}
	user, delegated := managedAccount(t, s, ctx, admin, "delegate")
	if _, err := s.AddMember(ctx, admin.CookieValue(), org.ID, MemberCreate{UserID: user.ID, Roles: []string{"viewer"}, Permissions: []string{"member.write"}}); err != nil {
		t.Fatal(err)
	}
	members, err := s.ListMembers(ctx, admin.CookieValue(), org.ID, ManagementList{Limit: 25})
	if err != nil {
		t.Fatal(err)
	}
	var adminMember MemberSummary
	for _, m := range members {
		if m.UserID == admin.User.ID {
			adminMember = m
		}
	}
	if _, err := s.RevokeMember(ctx, delegated.CookieValue(), org.ID, adminMember.ID, adminMember.Version); !errors.Is(err, ErrLastAdministrator) {
		t.Fatalf("last organization admin removed: %v", err)
	}
	if _, err := s.RevokeMember(ctx, admin.CookieValue(), org.ID, adminMember.ID, adminMember.Version); !errors.Is(err, ErrSelfLockout) {
		t.Fatal("admin self-revoked")
	}
	if _, err := s.UpdateOrganization(ctx, delegated.CookieValue(), org.ID, OrganizationPatch{ExpectedVersion: org.Version, Name: ptr("Forbidden")}); !errors.Is(err, ErrPermission) {
		t.Fatal("org member performed global organization update")
	}
	listed, err := s.ListOrganizations(ctx, delegated.CookieValue(), ManagementList{Limit: 25})
	if err != nil || len(listed) != 1 || listed[0].ID != org.ID {
		t.Fatal("organization enumeration leaked other tenants")
	}
}

func TestManagementDisableResetUnlockAndSessionRevocation(t *testing.T) {
	s, ctx := initializedService(t)
	admin := loginTest(t, s, ctx)
	user, session := managedAccount(t, s, ctx, admin, "security-user")
	reset, err := s.ResetUserPassword(ctx, admin.CookieValue(), user.ID, user.Version, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if !reset.MustChangePassword || reset.Version != user.Version+1 {
		t.Fatal("reset did not force password change")
	}
	if _, err := s.Current(ctx, session.CookieValue()); !errors.Is(err, ErrSession) {
		t.Fatal("admin reset retained session")
	}
	for range 5 {
		if _, err := s.Login(ctx, user.Username, "wrong"); !errors.Is(err, ErrAuthentication) {
			t.Fatal(err)
		}
	}
	if _, err := s.Login(ctx, user.Username, testPassword); !errors.Is(err, ErrAuthentication) {
		t.Fatal("locked user logged in")
	}
	unlocked, err := s.UnlockUser(ctx, admin.CookieValue(), user.ID, reset.Version)
	if err != nil {
		t.Fatal(err)
	}
	session, err = s.Login(ctx, user.Username, testPassword)
	if err != nil {
		t.Fatal("unlocked user cannot login")
	}
	disabled, err := s.UpdateUser(ctx, admin.CookieValue(), user.ID, UserPatch{ExpectedVersion: unlocked.Version, Status: ptr("disabled")})
	if err != nil {
		t.Fatal(err)
	}
	if disabled.Status != "disabled" {
		t.Fatal("not disabled")
	}
	if _, err := s.Current(ctx, session.CookieValue()); !errors.Is(err, ErrSession) {
		t.Fatal("disabled user retained session")
	}
	if _, err := s.Login(ctx, user.Username, testPassword); !errors.Is(err, ErrAuthentication) {
		t.Fatal("disabled user logged in")
	}
}
