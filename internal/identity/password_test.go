package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPasswordHashAndVerification(t *testing.T) {
	h := NewPasswordHasher()
	const password = "synthetic-password-for-unit-tests"
	a, err := h.Hash(context.Background(), password)
	if err != nil {
		t.Fatal(err)
	}
	b, err := h.Hash(context.Background(), password)
	if err != nil {
		t.Fatal(err)
	}
	if a == b || strings.Contains(a, password) || !strings.HasPrefix(a, passwordPrefix) {
		t.Fatal("invalid salt or hash representation")
	}
	if ok, err := h.Verify(context.Background(), a, password); err != nil || !ok {
		t.Fatal("valid password failed")
	}
	if ok, err := h.Verify(context.Background(), a, "wrong-password"); err != nil || ok {
		t.Fatal("wrong password accepted")
	}
	for _, encoded := range []string{"", strings.Replace(a, "m=65536", "m=999999999", 1), a + "$extra", passwordPrefix + "%%%%$abcd", strings.Replace(a, "argon2id", "argon2i", 1)} {
		if ok, err := h.Verify(context.Background(), encoded, password); err != nil || ok {
			t.Fatal("invalid/unbounded PHC profile accepted")
		}
	}
}

func TestPasswordPolicyAndCancellation(t *testing.T) {
	h := NewPasswordHasher()
	for _, password := range []string{"short", strings.Repeat("a", 257), "123456789012\x00"} {
		if _, err := h.Hash(context.Background(), password); !errors.Is(err, ErrPasswordPolicy) {
			t.Fatal("invalid password accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.Hash(ctx, "synthetic-password"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("cancelled hash started")
	}
	h.slots <- struct{}{}
	h.slots <- struct{}{}
	if err := h.acquire(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("blocked hasher ignored cancellation")
	}
}

func TestPermissionMatrix(t *testing.T) {
	roles := BuiltinPermissions()
	for _, role := range []string{"admin", "operator", "auditor", "developer", "viewer"} {
		p := Principal{UserID: 1, OrganizationID: 2, Permissions: roles[role]}
		if p.Authorize("evidence.read") != nil {
			t.Fatalf("%s cannot view redacted evidence", role)
		}
		if p.Authorize("secret.read") == nil || p.Authorize("system.users") == nil {
			t.Fatalf("%s obtained forbidden privilege", role)
		}
		if (p.Authorize("rules.manage") == nil) != (role == "admin") {
			t.Fatal("rule permissions mismatch")
		}
		if (p.Authorize("evidence.body") == nil) != (role == "admin" || role == "auditor") {
			t.Fatal("restricted body permissions mismatch")
		}
		if (p.AuthorizeCancellation(99) == nil) != (role == "admin" || role == "auditor") {
			t.Fatal("other user's run cancellable")
		}
		if (p.AuthorizeCancellation(1) == nil) != (role != "viewer") {
			t.Fatal("own run cancellation mismatch")
		}
		p.OrganizationID = 0
		if p.Authorize("evidence.read") == nil {
			t.Fatal("unscoped authorization accepted")
		}
	}
	roles["admin"][0] = "mutated"
	if BuiltinPermissions()["admin"][0] == "mutated" {
		t.Fatal("builtin grants globally mutable")
	}
	p := Principal{UserID: 1, SystemAdmin: true}
	if p.Authorize("system.users") != nil {
		t.Fatal("system admin rejected")
	}
	if p.Authorize("evidence.read") == nil {
		t.Fatal("system admin bypassed explicit organization scope")
	}
}
