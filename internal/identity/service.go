package identity

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

var (
	ErrSetupRequired = errors.New("MI_SETUP_REQUIRED")
	ErrSetupClosed   = errors.New("MI_SETUP_CLOSED")
	ErrSession       = errors.New("MI_SESSION_REQUIRED")
	ErrCSRF          = errors.New("MI_CSRF_INVALID")
)

const sessionLifetime = 12 * time.Hour
const loginLockDuration = 15 * time.Minute

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{3,64}$`)

type Service struct {
	store     *repository.Store
	hasher    *PasswordHasher
	dummyHash string
	now       func() time.Time
}

// SessionMaterial has no public token field and cannot be serialized or logged.
// The HTTP boundary uses CookieValue solely for Set-Cookie; public DTOs are
// constructed separately from User/Organizations/CSRFToken/ExpiresAt.
type SessionMaterial struct {
	token         string
	User          repository.User
	Organizations []repository.Organization
	CSRFToken     string
	ExpiresAt     time.Time
}

func (SessionMaterial) String() string               { return "[redacted session material]" }
func (s SessionMaterial) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, s.String()) }
func (SessionMaterial) MarshalJSON() ([]byte, error) {
	return nil, errors.New("MI_SESSION_SERIALIZATION_FORBIDDEN")
}
func (s SessionMaterial) CookieValue() string { return s.token }

func NewService(ctx context.Context, store *repository.Store) (*Service, error) {
	if store == nil {
		return nil, ErrUnavailable
	}
	h := NewPasswordHasher()
	dummy, err := h.Hash(ctx, "synthetic-dummy-account-never-authenticatable")
	if err != nil {
		return nil, ErrUnavailable
	}
	return &Service{store: store, hasher: h, dummyHash: dummy, now: time.Now}, nil
}

func (s *Service) SetupStatus(ctx context.Context) (bool, error) {
	ready, err := s.store.SetupStatus(ctx)
	if err != nil {
		return false, ErrUnavailable
	}
	return ready, nil
}

func bindActor(ctx context.Context, userID int64, reason string) (context.Context, error) {
	actor, err := audit.ActorFromContext(ctx)
	if err != nil {
		return nil, ErrUnavailable
	}
	actor.ActorID = userID
	actor.ReasonCode = reason
	return audit.WithActor(ctx, actor), nil
}

func (s *Service) Initialize(ctx context.Context, organizationName, username, password string) error {
	if !usernamePattern.MatchString(username) || strings.TrimSpace(organizationName) == "" || len(organizationName) > 128 {
		return ErrPasswordPolicy
	}
	ready, err := s.SetupStatus(ctx)
	if err != nil {
		return err
	}
	if ready {
		return ErrSetupClosed
	}
	actorCtx, err := bindActor(ctx, 0, "setup.initialize")
	if err != nil {
		return err
	}
	hash, err := s.hasher.Hash(ctx, password)
	if err != nil {
		return err
	}
	roles := make([]repository.InitialRole, 0, 5)
	for name, permissions := range BuiltinPermissions() {
		roles = append(roles, repository.InitialRole{Name: name, Description: name, Permissions: permissions})
	}
	_, err = s.store.Initialize(actorCtx, repository.Initialization{OrganizationName: organizationName, Username: username, PasswordHash: hash, Timezone: "UTC", Roles: roles, AdminRole: "admin"})
	if errors.Is(err, repository.ErrAlreadyInitialized) {
		return ErrSetupClosed
	}
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

func tokenHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func csrfForToken(token string) string {
	h := hmac.New(sha256.New, []byte(token))
	_, _ = h.Write([]byte("mii/session-csrf/v1"))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func (s *Service) Login(ctx context.Context, username, password string) (SessionMaterial, error) {
	ready, err := s.SetupStatus(ctx)
	if err != nil {
		return SessionMaterial{}, err
	}
	if !ready {
		return SessionMaterial{}, ErrSetupRequired
	}
	actorCtx, err := bindActor(ctx, 0, "auth.login_failed")
	if err != nil {
		return SessionMaterial{}, err
	}
	user, lookupErr := s.store.FindUserForAuthentication(ctx, username)
	if lookupErr != nil && !errors.Is(lookupErr, repository.ErrNotFound) {
		return SessionMaterial{}, ErrUnavailable
	}
	hash := s.dummyHash
	if lookupErr == nil {
		hash = user.PasswordHash
	}
	valid, err := s.hasher.Verify(ctx, hash, password)
	if err != nil {
		return SessionMaterial{}, ErrUnavailable
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	if lookupErr != nil || !valid || user.Status != "active" || (user.LockedUntil != nil && now.Before(*user.LockedUntil)) {
		if lookupErr != nil {
			err = s.store.RecordAnonymousLoginFailure(actorCtx)
		} else {
			actorCtx, err = bindActor(ctx, user.ID, "auth.login_failed")
			if err == nil {
				err = s.store.RecordLoginFailure(actorCtx, user.ID, 5, now.Add(loginLockDuration))
			}
		}
		if err != nil {
			return SessionMaterial{}, ErrUnavailable
		}
		return SessionMaterial{}, ErrAuthentication
	}
	actorCtx, err = bindActor(ctx, user.ID, "auth.login")
	if err != nil {
		return SessionMaterial{}, err
	}
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return SessionMaterial{}, ErrUnavailable
	}
	token := base64.RawURLEncoding.EncodeToString(buffer)
	clear(buffer)
	csrf := csrfForToken(token)
	session := repository.Session{UserID: user.ID, SessionHash: tokenHash(token), CSRFHash: tokenHash(csrf), CreatedAt: now, ExpiresAt: now.Add(sessionLifetime)}
	if err := s.store.CreateSessionIfPasswordCurrent(actorCtx, &session, user.PasswordHash, now); err != nil {
		if errors.Is(err, repository.ErrConflict) || errors.Is(err, repository.ErrNotFound) {
			return SessionMaterial{}, ErrAuthentication
		}
		return SessionMaterial{}, ErrUnavailable
	}
	material, err := s.Current(ctx, token)
	if err != nil {
		return SessionMaterial{}, err
	}
	material.token = token
	return material, nil
}

func (s *Service) authenticate(ctx context.Context, token string) (repository.User, repository.Session, error) {
	if len(token) != 43 {
		return repository.User{}, repository.Session{}, ErrSession
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) != 32 {
		return repository.User{}, repository.Session{}, ErrSession
	}
	clear(decoded)
	session, err := s.store.GetSession(ctx, tokenHash(token), s.now().UTC())
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return repository.User{}, repository.Session{}, ErrSession
		}
		return repository.User{}, repository.Session{}, ErrUnavailable
	}
	user, err := s.store.GetUser(ctx, session.UserID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return repository.User{}, repository.Session{}, ErrSession
		}
		return repository.User{}, repository.Session{}, ErrUnavailable
	}
	if session.CreatedAt.Before(user.PasswordChangedAt) {
		return repository.User{}, repository.Session{}, ErrSession
	}
	return user, session, nil
}

func (s *Service) Current(ctx context.Context, token string) (SessionMaterial, error) {
	user, session, err := s.authenticate(ctx, token)
	if err != nil {
		return SessionMaterial{}, err
	}
	csrf := csrfForToken(token)
	if subtle.ConstantTimeCompare([]byte(tokenHash(csrf)), []byte(session.CSRFHash)) != 1 {
		return SessionMaterial{}, ErrSession
	}
	memberships, err := s.store.ListUserMemberships(ctx, user.ID)
	if err != nil {
		return SessionMaterial{}, ErrUnavailable
	}
	organizations := make([]repository.Organization, 0, len(memberships))
	for _, member := range memberships {
		tenant, err := s.store.WithOrganization(ctx, member.OrganizationID)
		if err != nil {
			return SessionMaterial{}, ErrUnavailable
		}
		org, err := tenant.GetOrganization()
		if err != nil {
			return SessionMaterial{}, ErrUnavailable
		}
		if org.Status == "active" {
			organizations = append(organizations, org)
		}
	}
	return SessionMaterial{User: user, Organizations: organizations, CSRFToken: csrf, ExpiresAt: session.ExpiresAt}, nil
}

func (s *Service) CheckCSRF(ctx context.Context, token, csrf string) error {
	_, session, err := s.authenticate(ctx, token)
	if err != nil {
		return err
	}
	if len(csrf) != 43 || subtle.ConstantTimeCompare([]byte(tokenHash(csrf)), []byte(session.CSRFHash)) != 1 {
		return ErrCSRF
	}
	return nil
}

func (s *Service) Principal(ctx context.Context, token string, organizationID int64) (Principal, error) {
	user, _, err := s.authenticate(ctx, token)
	if err != nil {
		return Principal{}, err
	}
	if user.MustChangePassword {
		return Principal{}, ErrPasswordChangeRequired
	}
	p := Principal{UserID: user.ID, OrganizationID: organizationID, SystemAdmin: user.IsSystemAdmin}
	if organizationID <= 0 {
		return p, nil
	}
	tenant, err := s.store.WithOrganization(ctx, organizationID)
	if err != nil {
		return Principal{}, ErrPermission
	}
	p.Permissions, err = tenant.PermissionsForUser(user.ID)
	if err != nil {
		return Principal{}, ErrUnavailable
	}
	if len(p.Permissions) == 0 {
		return Principal{}, ErrPermission
	}
	return p, nil
}

func (s *Service) Logout(ctx context.Context, token string) error {
	user, _, err := s.authenticate(ctx, token)
	if err != nil {
		return err
	}
	actorCtx, err := bindActor(ctx, user.ID, "auth.logout")
	if err != nil {
		return err
	}
	if err := s.store.RevokeSession(actorCtx, user.ID, tokenHash(token), s.now().UTC()); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *Service) ChangePassword(ctx context.Context, token, currentPassword, newPassword string) error {
	user, _, err := s.authenticate(ctx, token)
	if err != nil {
		return err
	}
	valid, err := s.hasher.Verify(ctx, user.PasswordHash, currentPassword)
	if err != nil {
		return ErrUnavailable
	}
	if !valid {
		actorCtx, err := bindActor(ctx, user.ID, "auth.change_password_failed")
		if err != nil || s.store.RecordPasswordChangeFailure(actorCtx, user.ID) != nil {
			return ErrUnavailable
		}
		return ErrAuthentication
	}
	hash, err := s.hasher.Hash(ctx, newPassword)
	if err != nil {
		return err
	}
	actorCtx, err := bindActor(ctx, user.ID, "auth.change_password")
	if err != nil {
		return err
	}
	if err := s.store.ChangePassword(actorCtx, user.ID, user.PasswordHash, hash, s.now().UTC()); err != nil {
		return ErrUnavailable
	}
	return nil
}
