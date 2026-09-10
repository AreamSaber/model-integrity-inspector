package repository

import (
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

type switchAuditSigner struct{ fail atomic.Bool }

func (*switchAuditSigner) ActiveVersion() string { return "test-v1" }
func (s *switchAuditSigner) AuditMAC(version string, message []byte) ([]byte, error) {
	if s.fail.Load() {
		return nil, errors.New("private signer failure detail")
	}
	return testAuditSigner{}.AuditMAC(version, message)
}

func TestAuditInitializationFailsClosed(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		requireMigrate(t, store)
		if _, err := store.Initialize(t.Context(), initialState()); !errors.Is(err, audit.ErrActorRequired) {
			t.Fatalf("missing actor accepted: %v", err)
		}
		store.auditSigner = nil
		if _, err := store.Initialize(testActorContext(t, 0), initialState()); !errors.Is(err, audit.ErrUnavailable) {
			t.Fatalf("missing signer accepted: %v", err)
		}
		signer := &switchAuditSigner{}
		signer.fail.Store(true)
		store.auditSigner = signer
		if _, err := store.Initialize(testActorContext(t, 0), initialState()); !errors.Is(err, audit.ErrUnavailable) {
			t.Fatalf("failed signature accepted: %v", err)
		}
		for _, table := range []string{"organizations", "users", "organization_members", "system_settings", "integrity_audit_logs", "integrity_audit_chain_heads"} {
			var count int64
			if err := store.db.Table(table).Count(&count).Error; err != nil || count != 0 {
				t.Fatalf("failed audit left partial setup in %s", table)
			}
		}
		signer.fail.Store(false)
		initial := requireInitialize(t, store)
		tenant, _ := store.WithOrganization(t.Context(), initial.Organization.ID)
		verified, err := tenant.VerifyAuditFull()
		if err != nil || verified.EventCount != 1 || verified.VerifiedCount != 1 {
			t.Fatalf("initial audit missing: %+v %v", verified, err)
		}
	})
}

func TestAuditFailureRollsBackSensitiveMutations(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		requireMigrate(t, store)
		initial := requireInitialize(t, store)
		ctx := testActorContext(t, initial.User.ID)
		tenant, _ := store.WithOrganization(ctx, initial.Organization.ID)
		signer := &switchAuditSigner{}
		signer.fail.Store(true)
		store.auditSigner = signer
		provider := Provider{Name: "Must roll back"}
		if err := tenant.CreateProvider(&provider); !errors.Is(err, audit.ErrUnavailable) {
			t.Fatalf("catalog write ignored audit failure: %v", err)
		}
		if err := store.ChangePassword(ctx, initial.User.ID, initial.User.PasswordHash, "new-password-hash", time.Now().UTC()); !errors.Is(err, audit.ErrUnavailable) {
			t.Fatalf("password change ignored audit failure: %v", err)
		}
		now := time.Now().UTC()
		session := Session{UserID: initial.User.ID, SessionHash: strings.Repeat("c", 64), CSRFHash: strings.Repeat("d", 64), CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
		if err := store.CreateSessionIfPasswordCurrent(ctx, &session, initial.User.PasswordHash, now); !errors.Is(err, audit.ErrUnavailable) {
			t.Fatalf("login ignored audit failure: %v", err)
		}
		if err := store.RecordLoginFailure(testActorContext(t, 0), initial.User.ID, 1, now.Add(time.Hour)); !errors.Is(err, audit.ErrUnavailable) {
			t.Fatalf("failure counter ignored audit failure: %v", err)
		}
		user, err := store.FindUserForAuthentication(t.Context(), initial.User.Username)
		if err != nil || user.PasswordHash != initial.User.PasswordHash || user.FailedLoginCount != 0 || user.LockedUntil != nil {
			t.Fatal("audit failure committed changed credential/security state")
		}
		for _, table := range []string{"providers", "user_sessions"} {
			var count int64
			if err := store.db.Table(table).Count(&count).Error; err != nil || count != 0 {
				t.Fatalf("audit failure committed %s", table)
			}
		}
		signer.fail.Store(false)
		verified, err := tenant.VerifyAuditFull()
		if err != nil || verified.EventCount != 1 {
			t.Fatal("audit failure changed chain")
		}
	})
}

func TestAuditConcurrentAppendAcrossConnections(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, cfg Config) {
		requireMigrate(t, store)
		initial := requireInitialize(t, store)
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		ctx := testActorContext(t, initial.User.ID)
		var wg sync.WaitGroup
		errs := make(chan error, 20)
		for i := range 20 {
			wg.Go(func() {
				candidate := store
				if i%2 == 1 {
					candidate = other
				}
				tenant, _ := candidate.WithOrganization(ctx, initial.Organization.ID)
				errs <- tenant.AppendAudit(AuditCommand{Action: "test.append", ObjectType: "test", ObjectID: strconv.Itoa(i), Result: "success"})
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Errorf("append failed: %v", err)
			}
		}
		tenant, _ := store.WithOrganization(ctx, initial.Organization.ID)
		full, err := tenant.VerifyAuditFull()
		if err != nil || full.EventCount != 21 || full.VerifiedCount != 21 {
			t.Fatalf("concurrent chain invalid: %+v %v", full, err)
		}
		tail, err := tenant.VerifyAuditTail()
		if err != nil || tail.VerifiedCount != 2 {
			t.Fatalf("tail invalid: %+v %v", tail, err)
		}
	})
}

func TestAuditTamperingDeletionAndHeadLoss(t *testing.T) {
	for _, tamper := range []string{"content", "missing_middle", "missing_tail", "missing_head", "wrong_head"} {
		t.Run(tamper, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
				requireMigrate(t, store)
				initial := requireInitialize(t, store)
				tenant, _ := store.WithOrganization(testActorContext(t, initial.User.ID), initial.Organization.ID)
				for i := range 3 {
					if err := tenant.AppendAudit(AuditCommand{Action: "test.append", ObjectType: "test", ObjectID: strconv.Itoa(i), Result: "success"}); err != nil {
						t.Fatal(err)
					}
				}
				var err error
				switch tamper {
				case "content":
					err = store.db.Exec("UPDATE integrity_audit_logs SET action = ? WHERE organization_id = ? AND sequence = 1", "test.tamper", initial.Organization.ID).Error
				case "missing_middle":
					err = store.db.Exec("DELETE FROM integrity_audit_logs WHERE organization_id = ? AND sequence = 2", initial.Organization.ID).Error
				case "missing_tail":
					err = store.db.Exec("DELETE FROM integrity_audit_logs WHERE organization_id = ? AND sequence = 4", initial.Organization.ID).Error
				case "missing_head":
					err = store.db.Exec("DELETE FROM integrity_audit_chain_heads WHERE organization_id = ?", initial.Organization.ID).Error
				case "wrong_head":
					err = store.db.Exec("UPDATE integrity_audit_chain_heads SET event_count = ? WHERE organization_id = ?", 100, initial.Organization.ID).Error
				}
				if err != nil {
					t.Fatal(err)
				}
				if _, err := tenant.VerifyAuditFull(); !errors.Is(err, audit.ErrIntegrity) {
					t.Fatalf("tamper not detected: %v", err)
				}
				if tamper == "missing_tail" || tamper == "wrong_head" || tamper == "missing_head" {
					provider := Provider{Name: "Must not commit on corrupt audit"}
					if err := tenant.CreateProvider(&provider); !errors.Is(err, audit.ErrIntegrity) {
						t.Fatalf("corrupt audit allowed write: %v", err)
					}
				}
			})
		})
	}
}

func TestUnknownLoginAuditedWithoutSubmittedIdentity(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		requireMigrate(t, store)
		initial := requireInitialize(t, store)
		if err := store.RecordAnonymousLoginFailure(testActorContext(t, 0)); err != nil {
			t.Fatal(err)
		}
		tenant, _ := store.WithOrganization(t.Context(), initial.Organization.ID)
		events, err := tenant.ListAudit(1, 10)
		if err != nil || len(events) != 1 || events[0].ObjectID != "unknown" || events[0].ActorID != nil || events[0].Action != "auth.login_failed" || events[0].Result != "denied" {
			t.Fatalf("unknown login event: %+v %v", events, err)
		}
		if _, err := tenant.VerifyAuditFull(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestLoginSessionRechecksPasswordStatusAndLock(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		requireMigrate(t, store)
		initial := requireInitialize(t, store)
		ctx := testActorContext(t, initial.User.ID)
		now := time.Now().UTC()
		session := Session{UserID: initial.User.ID, SessionHash: strings.Repeat("e", 64), CSRFHash: strings.Repeat("f", 64), CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
		if err := store.CreateSessionIfPasswordCurrent(ctx, &session, "stale-hash", now); !errors.Is(err, ErrConflict) {
			t.Fatalf("stale password accepted: %v", err)
		}
		if err := store.db.Model(&User{}).Where("id = ?", initial.User.ID).Update("status", "disabled").Error; err != nil {
			t.Fatal(err)
		}
		if err := store.CreateSessionIfPasswordCurrent(ctx, &session, initial.User.PasswordHash, now); !errors.Is(err, ErrConflict) {
			t.Fatalf("disabled user accepted: %v", err)
		}
		if err := store.db.Model(&User{}).Where("id = ?", initial.User.ID).Updates(map[string]any{"status": "active", "locked_until": now.Add(time.Hour)}).Error; err != nil {
			t.Fatal(err)
		}
		if err := store.CreateSessionIfPasswordCurrent(ctx, &session, initial.User.PasswordHash, now); !errors.Is(err, ErrConflict) {
			t.Fatalf("locked user accepted: %v", err)
		}
		var count int64
		if err := store.db.Model(&Session{}).Count(&count).Error; err != nil || count != 0 {
			t.Fatal("rejected user gained a session")
		}
	})
}
