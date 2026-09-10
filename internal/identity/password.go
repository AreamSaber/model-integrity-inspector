// Package identity owns local authentication and organization permissions.
package identity

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

var (
	ErrPasswordPolicy = errors.New("MI_PASSWORD_POLICY")
	ErrAuthentication = errors.New("MI_LOGIN_FAILED")
	ErrUnavailable    = errors.New("MI_SERVICE_UNAVAILABLE")
	ErrPermission     = errors.New("MI_PERMISSION_DENIED")
)

// #nosec G101 -- Public PHC algorithm and cost parameters, not a password or key.
const passwordPrefix = "$argon2id$v=19$m=65536,t=3,p=2$"

// PasswordHasher caps concurrent Argon2 memory at 2*64 MiB per application
// instance. The API must additionally enforce persistent login throttles.
type PasswordHasher struct{ slots chan struct{} }

func NewPasswordHasher() *PasswordHasher { return &PasswordHasher{slots: make(chan struct{}, 2)} }

func validPassword(password string) bool {
	return utf8.ValidString(password) && utf8.RuneCountInString(password) >= 12 && len(password) <= 256 && !strings.ContainsRune(password, 0)
}

func (h *PasswordHasher) acquire(ctx context.Context) error {
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	select {
	case h.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ErrUnavailable
	}
}

// Hash emits a versioned PHC string. Passwords are never included in errors.
func (h *PasswordHasher) Hash(ctx context.Context, password string) (string, error) {
	if !validPassword(password) {
		return "", ErrPasswordPolicy
	}
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer func() { <-h.slots }()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", ErrUnavailable
	}
	input := []byte(password)
	defer clear(input)
	key := argon2.IDKey(input, salt, 3, 64*1024, 2, 32)
	defer clear(key)
	if ctx.Err() != nil {
		return "", ErrUnavailable
	}
	return passwordPrefix + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key), nil
}

// Verify accepts only the deployed, bounded parameter profile. Persisted data
// cannot request attacker-chosen memory/time costs during login.
func (h *PasswordHasher) Verify(ctx context.Context, encoded, password string) (bool, error) {
	if !strings.HasPrefix(encoded, passwordPrefix) || len(password) > 256 || !utf8.ValidString(password) {
		return false, nil
	}
	saltText, keyText, ok := strings.Cut(strings.TrimPrefix(encoded, passwordPrefix), "$")
	if !ok {
		return false, nil
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(saltText)
	if err != nil || len(salt) != 16 {
		return false, nil
	}
	expected, err := base64.RawStdEncoding.Strict().DecodeString(keyText)
	if err != nil || len(expected) != 32 {
		return false, nil
	}
	defer clear(expected)
	if err := h.acquire(ctx); err != nil {
		return false, err
	}
	defer func() { <-h.slots }()
	input := []byte(password)
	defer clear(input)
	actual := argon2.IDKey(input, salt, 3, 64*1024, 2, 32)
	defer clear(actual)
	if ctx.Err() != nil {
		return false, ErrUnavailable
	}
	return subtle.ConstantTimeCompare(expected, actual) == 1, nil
}
