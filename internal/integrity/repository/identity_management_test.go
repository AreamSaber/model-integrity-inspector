package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func managementFixtureRoles() []InitialRole {
	return []InitialRole{
		{Name: "admin", Permissions: []string{"read", "organization.read", "member.read", "member.write", "target.read", "target.write"}},
		{Name: "operator", Permissions: []string{"read", "organization.read", "member.read", "target.read", "target.write"}},
		{Name: "auditor", Permissions: []string{"read", "organization.read", "member.read", "target.read"}},
		{Name: "developer", Permissions: []string{"read", "organization.read", "member.read", "target.read", "target.write"}},
		{Name: "viewer", Permissions: []string{"read", "organization.read", "member.read", "target.read"}},
	}
}

func managementFixture(t *testing.T, s *Store) (InitializationResult, ManagementAuthority, context.Context) {
	t.Helper()
	requireMigrate(t, s)
	initial, err := s.Initialize(testActorContext(t, 0), Initialization{OrganizationName: "Management test", Username: "root", PasswordHash: "synthetic-test-only-hash", Roles: managementFixtureRoles(), AdminRole: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := testActorContext(t, initial.User.ID)
	auth := managementSession(t, s, initial.User)
	return initial, auth, ctx
}
func managementSession(t *testing.T, s *Store, user User) ManagementAuthority {
	t.Helper()
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("synthetic-test-session-%d", id)))
	now := time.Now().UTC().Truncate(time.Microsecond)
	session := Session{UserID: user.ID, SessionHash: hex.EncodeToString(sum[:]), CSRFHash: hex.EncodeToString(sum[:]), CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := s.CreateSessionIfPasswordCurrent(testActorContext(t, user.ID), &session, user.PasswordHash, now); err != nil {
		t.Fatal(err)
	}
	return ManagementAuthority{UserID: user.ID, SessionID: session.ID}
}
func managementFixtureUser(t *testing.T, s *Store, ctx context.Context, auth ManagementAuthority, name string) User {
	t.Helper()
	created, err := s.ManageCreateUser(ctx, auth, ManagedUserCreate{Username: name, PasswordHash: "synthetic-test-only-hash"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.db.Model(&User{}).Where("id=?", created.ID).Update("must_change_password", false).Error; err != nil {
		t.Fatal(err)
	}
	user, err := s.GetUser(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func TestManagementConcurrentVersionAndRevokedAuthority(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		_, auth, ctx := managementFixture(t, s)
		user := managementFixtureUser(t, s, ctx, auth, "edit-target")
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		var wg sync.WaitGroup
		results := make(chan error, 8)
		for i := range 8 {
			wg.Go(func() {
				candidate := s
				if i%2 == 1 {
					candidate = other
				}
				name := fmt.Sprintf("Editor %d", i)
				_, err := candidate.ManageUpdateUser(ctx, auth, user.ID, ManagedUserPatch{ExpectedVersion: 1, DisplayName: &name})
				results <- err
			})
		}
		wg.Wait()
		close(results)
		success := 0
		for err := range results {
			if err == nil {
				success++
			} else if !errors.Is(err, ErrConflict) {
				t.Fatalf("unexpected edit outcome: %v", err)
			}
		}
		if success != 1 {
			t.Fatalf("concurrent version winners=%d", success)
		}
		if err := s.db.Model(&Session{}).Where("id=?", auth.SessionID).Update("revoked_at", time.Now().UTC()).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := s.ManageCreateUser(ctx, auth, ManagedUserCreate{Username: "should-not-exist", PasswordHash: "test"}); !errors.Is(err, ErrManagementSession) {
			t.Fatalf("revoked authority accepted: %v", err)
		}
		var count int64
		if err := s.db.Model(&User{}).Where("username=?", "should-not-exist").Count(&count).Error; err != nil || count != 0 {
			t.Fatal("revoked request mutated data")
		}
	})
}

func TestManagementConcurrentAdminRemovalCannotRemoveBoth(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		initial, auth, ctx := managementFixture(t, s)
		user := managementFixtureUser(t, s, ctx, auth, "second-admin")
		second, err := s.ManageAddMember(ctx, auth, initial.Organization.ID, ManagedMemberCreate{UserID: user.ID, Roles: []string{"admin"}})
		if err != nil {
			t.Fatal(err)
		}
		secondAuth := managementSession(t, s, user)
		secondCtx := testActorContext(t, user.ID)
		var first Membership
		if err := s.db.Where("organization_id=? AND user_id=?", initial.Organization.ID, initial.User.ID).First(&first).Error; err != nil {
			t.Fatal(err)
		}
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		var wg sync.WaitGroup
		results := make(chan error, 2)
		disabled := "disabled"
		wg.Go(func() {
			_, err := s.ManageUpdateMember(ctx, auth, initial.Organization.ID, second.ID, ManagedMemberPatch{ExpectedVersion: 1, Status: &disabled})
			results <- err
		})
		wg.Go(func() {
			_, err := other.ManageUpdateMember(secondCtx, secondAuth, initial.Organization.ID, first.ID, ManagedMemberPatch{ExpectedVersion: 1, Status: &disabled})
			results <- err
		})
		wg.Wait()
		close(results)
		success := 0
		for err := range results {
			if err == nil {
				success++
			} else if !errors.Is(err, ErrManagementPermission) {
				t.Fatalf("unexpected admin race result: %v", err)
			}
		}
		if success != 1 {
			t.Fatalf("admin removal winners=%d", success)
		}
		count, err := activeAdminCount(s.db, initial.Organization.ID, 0)
		if err != nil || count != 1 {
			t.Fatalf("last-admin invariant broken: count=%d err=%v", count, err)
		}
		if err := s.VerifyAllAudit(t.Context(), true); err != nil {
			t.Fatal(err)
		}
	})
}

func TestManagementAuditFailureRollsBackAllMutationKinds(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		initial, auth, ctx := managementFixture(t, s)
		user := managementFixtureUser(t, s, ctx, auth, "rollback-target")
		member, err := s.ManageAddMember(ctx, auth, initial.Organization.ID, ManagedMemberCreate{UserID: user.ID, Roles: []string{"viewer"}})
		if err != nil {
			t.Fatal(err)
		}
		userAuth := managementSession(t, s, user)
		signer := &switchAuditSigner{}
		s.auditSigner = signer
		signer.fail.Store(true)
		name := "must-roll-back"
		disabled := "disabled"
		operations := []func() error{
			func() error {
				_, e := s.ManageCreateUser(ctx, auth, ManagedUserCreate{Username: "rolledback-create", PasswordHash: "test"})
				return e
			},
			func() error {
				_, e := s.ManageUpdateUser(ctx, auth, user.ID, ManagedUserPatch{ExpectedVersion: 1, DisplayName: &name, Status: &disabled})
				return e
			},
			func() error { _, e := s.ManageUnlockUser(ctx, auth, user.ID, 1); return e },
			func() error { _, e := s.ManageResetUserPassword(ctx, auth, user.ID, 1, "replacement-hash"); return e },
			func() error {
				_, e := s.ManageCreateOrganization(ctx, auth, ManagedOrganizationCreate{Name: "rolledback-org", Timezone: "UTC", Roles: managementFixtureRoles()})
				return e
			},
			func() error {
				_, e := s.ManageUpdateOrganization(ctx, auth, initial.Organization.ID, ManagedOrganizationPatch{ExpectedVersion: 1, Name: &name})
				return e
			},
			func() error {
				_, e := s.ManageUpdateMember(ctx, auth, initial.Organization.ID, member.ID, ManagedMemberPatch{ExpectedVersion: 1, Status: &disabled})
				return e
			},
		}
		for i, op := range operations {
			if err := op(); err == nil {
				t.Fatalf("mutation %d committed despite audit failure", i)
			}
		}
		signer.fail.Store(false)
		unchanged, err := s.GetUser(ctx, user.ID)
		if err != nil || unchanged.Version != 1 || unchanged.DisplayName != "" || unchanged.Status != "active" || unchanged.PasswordHash != user.PasswordHash {
			t.Fatal("account rollback failed")
		}
		var session Session
		if err := s.db.Where("id=?", userAuth.SessionID).First(&session).Error; err != nil || session.RevokedAt != nil {
			t.Fatal("session revocation escaped failed transaction")
		}
		var orgs, users, roles int64
		if err := s.db.Model(&Organization{}).Count(&orgs).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.db.Model(&User{}).Count(&users).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.db.Model(&Role{}).Count(&roles).Error; err != nil {
			t.Fatal(err)
		}
		if orgs != 1 || users != 2 || roles != 5 {
			t.Fatal("failed create left partial objects")
		}
		unchangedMember, err := loadMemberSummary(s.db, initial.Organization.ID, member.ID)
		if err != nil || unchangedMember.Status != "active" || unchangedMember.Version != 1 {
			t.Fatal("member rollback failed")
		}
		if err := s.VerifyAllAudit(t.Context(), true); err != nil {
			t.Fatal(err)
		}
	})
}

func TestManagementDisableLastOrganizationAdminAndAuditActorGuard(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		initial, auth, ctx := managementFixture(t, s)
		user := managementFixtureUser(t, s, ctx, auth, "sole-org-admin")
		if _, err := s.ManageAddMember(ctx, auth, initial.Organization.ID, ManagedMemberCreate{UserID: user.ID, Roles: []string{"admin"}}); err != nil {
			t.Fatal(err)
		}
		// Valid persisted arrangement: the global administrator no longer belongs
		// to this tenant; the account being disabled is its only active admin.
		if err := s.db.Model(&Membership{}).Where("organization_id=? AND user_id=?", initial.Organization.ID, initial.User.ID).Update("status", "disabled").Error; err != nil {
			t.Fatal(err)
		}
		disabled := "disabled"
		if _, err := s.ManageUpdateUser(ctx, auth, user.ID, ManagedUserPatch{ExpectedVersion: 1, Status: &disabled}); !errors.Is(err, ErrLastAdministrator) {
			t.Fatalf("disabled last tenant admin: %v", err)
		}
		if _, err := s.ManageCreateUser(testActorContext(t, user.ID), auth, ManagedUserCreate{Username: "wrong-actor", PasswordHash: "test"}); !errors.Is(err, audit.ErrActorRequired) {
			t.Fatal("forged actor metadata accepted")
		}
	})
}
