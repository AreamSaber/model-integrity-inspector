package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestLogoutAllRevokesBothSessionsAndAllowsNewLogin(t *testing.T) {
	s, ctx := initializedService(t)
	one := loginTest(t, s, ctx)
	two := loginTest(t, s, ctx)
	if err := s.LogoutAll(ctx, one.CookieValue()); err != nil {
		t.Fatal(err)
	}
	for _, session := range []SessionMaterial{one, two} {
		if _, err := s.Current(ctx, session.CookieValue()); !errors.Is(err, ErrSession) {
			t.Fatal("old session survived logout-all", err)
		}
		if err := s.CheckCSRF(ctx, session.CookieValue(), session.CSRFToken); !errors.Is(err, ErrSession) {
			t.Fatal("revoked session retained CSRF authority", err)
		}
	}
	fresh := loginTest(t, s, ctx)
	if err := s.LogoutAll(ctx, one.CookieValue()); !errors.Is(err, ErrSession) {
		t.Fatal("old session revoked a later login", err)
	}
	if _, err := s.Current(ctx, fresh.CookieValue()); err != nil {
		t.Fatal(err)
	}
	if err := s.store.VerifyAllAudit(ctx, true); err != nil {
		t.Fatal(err)
	}
}

func TestLogoutAllAllowsTemporaryMembershiplessAccountOnlySelf(t *testing.T) {
	s, ctx := initializedService(t)
	admin := loginTest(t, s, ctx)
	if _, err := s.CreateUser(ctx, admin.CookieValue(), UserCreate{Username: "temporary", Password: testPassword}); err != nil {
		t.Fatal(err)
	}
	user, err := s.Login(ctx, "temporary", testPassword)
	if err != nil || !user.User.MustChangePassword || len(user.Organizations) != 0 {
		t.Fatal("fixture must be forced-password with no membership", err)
	}
	if err := s.LogoutAll(ctx, user.CookieValue()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Current(ctx, user.CookieValue()); !errors.Is(err, ErrSession) {
		t.Fatal("temporary session survived", err)
	}
	if _, err := s.Current(ctx, admin.CookieValue()); err != nil {
		t.Fatal("self-service logout affected another account", err)
	}
}

func TestLogoutAllInvalidAndCancelledRequestsDoNotRevoke(t *testing.T) {
	s, ctx := initializedService(t)
	active := loginTest(t, s, ctx)
	for _, token := range []string{"", "invalid", strings.Repeat("%", 43)} {
		if err := s.LogoutAll(ctx, token); !errors.Is(err, ErrSession) {
			t.Fatal("invalid token accepted", err)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.LogoutAll(cancelled, active.CookieValue()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("cancelled operation did not fail closed", err)
	}
	if err := s.LogoutAll(context.Background(), active.CookieValue()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("missing audit context accepted", err)
	}
	if _, err := s.Current(ctx, active.CookieValue()); err != nil {
		t.Fatal("rejected operation revoked active session", err)
	}
}
