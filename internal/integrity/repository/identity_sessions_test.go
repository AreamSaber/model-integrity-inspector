package repository

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func ownSessionFixture(t *testing.T, store *Store, user User, marker string) Session {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	session := Session{UserID: user.ID, SessionHash: strings.Repeat(marker, 64), CSRFHash: strings.Repeat("f", 64), CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := store.CreateSessionIfPasswordCurrent(testActorContext(t, user.ID), &session, user.PasswordHash, now); err != nil {
		t.Fatal(err)
	}
	return session
}

func requireSessionRevoked(t *testing.T, store *Store, session Session, want bool) {
	t.Helper()
	var saved Session
	if err := store.db.Where("id = ?", session.ID).First(&saved).Error; err != nil {
		t.Fatal(err)
	}
	if (saved.RevokedAt != nil) != want {
		t.Fatal("unexpected persisted session revocation")
	}
}

func TestRevokeOwnSessionsIsAtomicAndSelfScoped(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		requireMigrate(t, store)
		initial := requireInitialize(t, store)
		one := ownSessionFixture(t, store, initial.User, "a")
		two := ownSessionFixture(t, store, initial.User, "b")
		other := initial.User
		id, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		other.ID, other.Username, other.UsernameNormalized, other.IsSystemAdmin = id, "other", "other", false
		if err := store.db.Create(&other).Error; err != nil {
			t.Fatal(err)
		}
		unrelated := ownSessionFixture(t, store, other, "c")
		ctx := testActorContext(t, initial.User.ID)
		auth := ManagementAuthority{UserID: initial.User.ID, SessionID: one.ID}
		before, err := store.GetUser(ctx, initial.User.ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.RevokeOwnSessions(ctx, auth); err != nil {
			t.Fatal(err)
		}
		requireSessionRevoked(t, store, one, true)
		requireSessionRevoked(t, store, two, true)
		requireSessionRevoked(t, store, unrelated, false)
		after, err := store.GetUser(ctx, initial.User.ID)
		if err != nil || before.PasswordHash != after.PasswordHash || !before.PasswordChangedAt.Equal(after.PasswordChangedAt) || before.Version != after.Version || before.Status != after.Status {
			t.Fatal("logout-all changed account credentials/state")
		}
		fresh := ownSessionFixture(t, store, initial.User, "d")
		if err := store.RevokeOwnSessions(ctx, auth); !errors.Is(err, ErrManagementSession) {
			t.Fatal("already revoked authority accepted", err)
		}
		requireSessionRevoked(t, store, fresh, false)
		var events int64
		if err := store.db.Table("integrity_audit_logs").Where("action = ?", "auth.logout_all").Count(&events).Error; err != nil || events != 1 {
			t.Fatal("logout-all audit missing or repeated")
		}
		if err := store.VerifyAllAudit(ctx, true); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRevokeOwnSessionsRevalidatesAuthority(t *testing.T) {
	for _, name := range []string{"missing-actor", "wrong-actor", "missing-user", "missing-session", "wrong-owner", "revoked", "expired", "disabled", "password-changed", "cancelled", "forced-password"} {
		t.Run(name, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
				requireMigrate(t, store)
				initial := requireInitialize(t, store)
				one := ownSessionFixture(t, store, initial.User, "a")
				two := ownSessionFixture(t, store, initial.User, "b")
				ctx := testActorContext(t, initial.User.ID)
				auth := ManagementAuthority{UserID: initial.User.ID, SessionID: one.ID}
				want := ErrManagementSession
				var setupErr error
				switch name {
				case "missing-actor":
					ctx, want = t.Context(), audit.ErrActorRequired
				case "wrong-actor":
					ctx, want = testActorContext(t, initial.User.ID-1), audit.ErrActorRequired
				case "missing-user":
					auth.UserID = 0
				case "missing-session":
					auth.SessionID = 0
				case "wrong-owner":
					id, err := NewID()
					if err != nil {
						t.Fatal(err)
					}
					other := initial.User
					other.ID, other.Username, other.UsernameNormalized = id, "other", "other"
					if err := store.db.Create(&other).Error; err != nil {
						t.Fatal(err)
					}
					auth.SessionID = ownSessionFixture(t, store, other, "c").ID
				case "revoked":
					setupErr = store.db.Model(&Session{}).Where("id = ?", one.ID).Update("revoked_at", time.Now().UTC()).Error
				case "expired":
					past := time.Now().UTC().Add(-time.Hour)
					setupErr = store.db.Model(&Session{}).Where("id = ?", one.ID).Updates(map[string]any{"created_at": past.Add(-time.Hour), "expires_at": past}).Error
				case "disabled":
					setupErr = store.db.Model(&User{}).Where("id = ?", initial.User.ID).Update("status", "disabled").Error
				case "password-changed":
					setupErr = store.db.Model(&User{}).Where("id = ?", initial.User.ID).Update("password_changed_at", one.CreatedAt.Add(time.Second)).Error
				case "cancelled":
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
					want = ErrUnavailable
				case "forced-password":
					setupErr = store.db.Model(&User{}).Where("id = ?", initial.User.ID).Updates(map[string]any{"must_change_password": true, "is_system_admin": false}).Error
					want = nil
				}
				if setupErr != nil {
					t.Fatal(setupErr)
				}
				if err := store.RevokeOwnSessions(ctx, auth); !errors.Is(err, want) {
					t.Fatal("unexpected authority result", err)
				}
				requireSessionRevoked(t, store, two, want == nil)
				var events int64
				if err := store.db.Table("integrity_audit_logs").Where("action = ?", "auth.logout_all").Count(&events).Error; err != nil || (want == nil && events != 1) || (want != nil && events != 0) {
					t.Fatal("denial committed audit or success omitted audit")
				}
			})
		})
	}
}

func TestRevokeOwnSessionsAuditInsertFailureRollsBack(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		requireMigrate(t, store)
		initial := requireInitialize(t, store)
		one := ownSessionFixture(t, store, initial.User, "a")
		two := ownSessionFixture(t, store, initial.User, "b")
		// Make the actual INSERT fail after the session UPDATE; no mocked service.
		ddl := "CREATE TRIGGER deny_logout_all BEFORE INSERT ON integrity_audit_logs WHEN NEW.action = 'auth.logout_all' BEGIN SELECT RAISE(ABORT, 'controlled'); END"
		if store.driver == "postgres" {
			ddl = "ALTER TABLE integrity_audit_logs ADD CONSTRAINT deny_logout_all CHECK (action <> 'auth.logout_all')"
		}
		if err := store.db.Exec(ddl).Error; err != nil {
			t.Fatal(err)
		}
		ctx := testActorContext(t, initial.User.ID)
		if err := store.RevokeOwnSessions(ctx, ManagementAuthority{UserID: initial.User.ID, SessionID: one.ID}); !errors.Is(err, ErrConflict) {
			t.Fatal("actual audit INSERT failure was not returned", err)
		}
		requireSessionRevoked(t, store, one, false)
		requireSessionRevoked(t, store, two, false)
		if err := store.VerifyAllAudit(ctx, true); err != nil {
			t.Fatal("rollback broke original audit chain", err)
		}
	})
}

func TestRevokeOwnSessionsConcurrentOnlyOneCommits(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		requireMigrate(t, store)
		initial := requireInitialize(t, store)
		one := ownSessionFixture(t, store, initial.User, "a")
		two := ownSessionFixture(t, store, initial.User, "b")
		start := make(chan struct{})
		results := make(chan error, 2)
		ctx := testActorContext(t, initial.User.ID)
		var wg sync.WaitGroup
		for _, session := range []Session{one, two} {
			wg.Go(func() {
				<-start
				results <- store.RevokeOwnSessions(ctx, ManagementAuthority{UserID: initial.User.ID, SessionID: session.ID})
			})
		}
		close(start)
		wg.Wait()
		close(results)
		successes, denials := 0, 0
		for err := range results {
			switch {
			case err == nil:
				successes++
			case errors.Is(err, ErrManagementSession):
				denials++
			default:
				t.Fatal("concurrent mutation failed unexpectedly", err)
			}
		}
		if successes != 1 || denials != 1 {
			t.Fatal("stale session committed a second logout-all")
		}
		requireSessionRevoked(t, store, one, true)
		requireSessionRevoked(t, store, two, true)
	})
}
