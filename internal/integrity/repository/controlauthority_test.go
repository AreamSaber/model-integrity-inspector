package repository

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func controlMutationCounts(t *testing.T, s *Store, orgID int64) []int64 {
	t.Helper()
	counts := make([]int64, 5)
	for i, table := range []string{"integrity_targets", "integrity_secrets", "integrity_target_prechecks", "integrity_jobs", "integrity_audit_logs"} {
		if err := s.db.Table(table).Where("organization_id=?", orgID).Count(&counts[i]).Error; err != nil {
			t.Fatal(err)
		}
	}
	return counts
}

func TestControlAuthorityRechecksPausedWritesWithoutSideEffects(t *testing.T) {
	cases := []struct {
		name   string
		want   error
		revoke func(*Store, controlAuthority) error
	}{
		{"revoked_session", ErrManagementSession, func(s *Store, c controlAuthority) error {
			return s.db.Model(&Session{}).Where("id=?", c.identity.SessionID).Update("revoked_at", time.Now().UTC()).Error
		}},
		{"expired_session", ErrManagementSession, func(s *Store, c controlAuthority) error {
			now := time.Now().UTC()
			return s.db.Model(&Session{}).Where("id=?", c.identity.SessionID).Updates(map[string]any{"created_at": now.Add(-2 * time.Second), "expires_at": now.Add(-time.Second)}).Error
		}},
		{"disabled_account", ErrManagementSession, func(s *Store, c controlAuthority) error {
			return s.db.Model(&User{}).Where("id=?", c.identity.UserID).Update("status", "disabled").Error
		}},
		{"temporary_password", ErrPasswordChangeRequired, func(s *Store, c controlAuthority) error {
			return s.db.Model(&User{}).Where("id=?", c.identity.UserID).Update("must_change_password", true).Error
		}},
		{"password_changed", ErrManagementSession, func(s *Store, c controlAuthority) error {
			return s.db.Model(&User{}).Where("id=?", c.identity.UserID).Update("password_changed_at", time.Now().Add(time.Second).UTC()).Error
		}},
		{"disabled_membership", ErrManagementPermission, func(s *Store, c controlAuthority) error {
			return s.db.Model(&Membership{}).Where("organization_id=? AND user_id=?", c.organizationID, c.identity.UserID).Update("status", "disabled").Error
		}},
		{"removed_permissions", ErrManagementPermission, func(s *Store, c controlAuthority) error {
			return s.db.Exec("DELETE FROM role_permissions WHERE organization_id=? AND permission_code IN ('target.write','target.delete','target.precheck','secret.replace')", c.organizationID).Error
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				_, tenant := targetFixture(t, s)
				original := mustCreateTarget(t, tenant)
				capability := tenant.ctx.Value(controlAuthorityKey{}).(controlAuthority)
				rotation := encryptedFixture(t, tenant.orgID)
				rotation.ID = original.Secret.ID
				rotation.SecretVersion = 2
				creation := encryptedFixture(t, tenant.orgID)
				ready := make(chan struct{})
				resume := make(chan struct{})
				results := make(chan []error, 1)
				go func() {
					// The request has completed trusted middleware binding and may spend
					// arbitrary time preparing an immutable snapshot or encrypting input.
					close(ready)
					<-resume
					_, createErr := tenant.CreateTargetWithSecret(targetRecordFixture(), creation)
					_, updateErr := tenant.UpdateTarget(original.Target.ID, 1, targetRecordFixture())
					_, rotateErr := tenant.ReplaceTargetSecret(original.Target.ID, 1, 1, "bearer", "", rotation)
					deleteErr := tenant.DeleteTarget(original.Target.ID, 1)
					_, precheckErr := tenant.EnqueuePrecheck(PrecheckRecord{OrganizationID: tenant.orgID, TargetID: original.Target.ID, TargetVersion: 1, SecretID: original.Secret.ID, SecretVersion: 1, RequestKey: "paused-control-request", SnapshotJSON: "{}"})
					results <- []error{createErr, updateErr, rotateErr, deleteErr, precheckErr}
				}()
				<-ready
				// Direct state mutation models an independently committed account/role
				// transaction while the already-authorized request is paused.
				if err := test.revoke(s, capability); err != nil {
					close(resume)
					t.Fatal(err)
				}
				before := controlMutationCounts(t, s, tenant.orgID)
				close(resume)
				select {
				case outcomes := <-results:
					for i, err := range outcomes {
						if !errors.Is(err, test.want) {
							t.Fatalf("operation %d returned %v, want %v", i, err, test.want)
						}
					}
				case <-time.After(10 * time.Second):
					t.Fatal("paused request did not complete")
				}
				after := controlMutationCounts(t, s, tenant.orgID)
				if !slices.Equal(before, after) {
					t.Fatalf("rejected request wrote rows/audit: before=%v after=%v", before, after)
				}
				current, err := tenant.GetTarget(original.Target.ID)
				if err != nil || current.Target.Version != 1 || current.Secret.Version != 1 {
					t.Fatal("rejected mutation changed target/credential")
				}
				if err := s.VerifyAllAudit(t.Context(), true); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestControlAuthorityNoActorFallbackAndFixedOperationPermissions(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		initial, tenant := targetFixture(t, s)
		original := mustCreateTarget(t, tenant)
		without, _ := s.WithOrganization(testActorContext(t, initial.User.ID), tenant.orgID)
		if _, err := without.CreateTargetWithSecret(targetRecordFixture(), encryptedFixture(t, tenant.orgID)); !errors.Is(err, ErrManagementSession) {
			t.Fatal("trusted audit actor bypassed missing session capability")
		}
		if err := s.RequireControlAuthority(context.Background(), tenant.orgID); !errors.Is(err, ErrManagementSession) {
			t.Fatal("empty context accepted")
		}
		foreign, _ := s.WithOrganization(tenant.ctx, tenant.orgID+1)
		if err := foreign.DeleteTarget(original.Target.ID, 1); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("capability crossed organization")
		}
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		if err := other.RequireControlAuthority(tenant.ctx, tenant.orgID); !errors.Is(err, ErrManagementSession) {
			t.Fatal("capability crossed store identity")
		}
		capability := tenant.ctx.Value(controlAuthorityKey{}).(controlAuthority)
		var session Session
		if err := s.db.Where("id=?", capability.identity.SessionID).First(&session).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := s.BindControlAuthority(testActorContext(t, initial.User.ID+1), session.SessionHash, tenant.orgID); !errors.Is(err, audit.ErrActorRequired) {
			t.Fatal("session bound to forged audit actor")
		}
		if _, err := s.BindControlAuthority(tenant.ctx, "not-a-valid-session-hash", tenant.orgID); !errors.Is(err, ErrManagementSession) {
			t.Fatal("unknown session hash accepted")
		}
		if err := s.db.Exec("DELETE FROM role_permissions WHERE organization_id=? AND permission_code IN ('secret.replace','target.delete','target.precheck')", tenant.orgID).Error; err != nil {
			t.Fatal(err)
		}
		// target.write does not imply secret rotation, deletion or outbound work.
		if _, err := tenant.UpdateTarget(original.Target.ID, 1, targetRecordFixture()); err != nil {
			t.Fatal(err)
		}
		rotation := encryptedFixture(t, tenant.orgID)
		rotation.ID = original.Secret.ID
		rotation.SecretVersion = 2
		if _, err := tenant.ReplaceTargetSecret(original.Target.ID, 2, 1, "bearer", "", rotation); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("target.write granted secret.replace")
		}
		if err := tenant.DeleteTarget(original.Target.ID, 2); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("target.write granted target.delete")
		}
		if _, err := tenant.EnqueuePrecheck(PrecheckRecord{OrganizationID: tenant.orgID, TargetID: original.Target.ID, TargetVersion: 2, SecretID: original.Secret.ID, SecretVersion: 1, RequestKey: "forbidden-precheck", SnapshotJSON: "{}"}); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("target.write granted target.precheck")
		}
	})
}
