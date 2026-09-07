package repository

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

var ErrAlreadyInitialized = errors.New("SYSTEM_ALREADY_INITIALIZED")

// InitialRole defines a frozen application's permission grants, not user input.
type InitialRole struct {
	Name        string
	Description string
	Permissions []string
}

type Initialization struct {
	OrganizationName string
	Username         string
	PasswordHash     string `json:"-"`
	Timezone         string
	Roles            []InitialRole
	AdminRole        string
}

type InitializationResult struct {
	Organization Organization
	User         User
}

func NormalizeUsername(username string) string { return strings.ToLower(strings.TrimSpace(username)) }

// SetupStatus reads the singleton initialization marker, without modifying it.
func (s *Store) SetupStatus(ctx context.Context) (bool, error) {
	var count int64
	err := s.db.WithContext(ctx).Table("system_settings").Where("setting_key = ?", "initialized").Count(&count).Error
	return count == 1, persistenceError(err)
}

// Initialize atomically creates the organization, global administrator, membership,
// application-defined base roles and singleton setup marker. Credential policy and
// Argon2id hashing belong to the identity service, never to SQL or HTTP handlers.
func (s *Store) Initialize(ctx context.Context, input Initialization) (InitializationResult, error) {
	var result InitializationResult
	if err := s.auditReady(ctx); err != nil {
		return result, err
	}
	if strings.TrimSpace(input.OrganizationName) == "" || NormalizeUsername(input.Username) == "" || input.PasswordHash == "" || len(input.Roles) == 0 || input.AdminRole == "" {
		return result, ErrConfiguration
	}
	if input.Timezone == "" {
		input.Timezone = "UTC"
	}
	orgID, err := NewID()
	if err != nil {
		return result, err
	}
	userID, err := NewID()
	if err != nil {
		return result, err
	}
	memberID, err := NewID()
	if err != nil {
		return result, err
	}
	now := time.Now().UTC()
	result.Organization = Organization{ID: orgID, Name: input.OrganizationName, Status: "active", Timezone: input.Timezone, QuotaJSON: "{}", CreatedAt: now, UpdatedAt: now}
	result.User = User{ID: userID, Username: strings.TrimSpace(input.Username), UsernameNormalized: NormalizeUsername(input.Username), PasswordHash: input.PasswordHash, Status: "active", IsSystemAdmin: true, PasswordChangedAt: now, CreatedAt: now, UpdatedAt: now}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if s.driver == "postgres" {
			if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", migrationLockID+1).Error; err != nil {
				return err
			}
		}
		var existing int64
		if err := tx.Table("system_settings").Where("setting_key = ?", "initialized").Count(&existing).Error; err != nil {
			return err
		}
		if existing > 0 {
			return ErrAlreadyInitialized
		}
		if err := tx.Create(&result.Organization).Error; err != nil {
			return err
		}
		if err := tx.Create(&result.User).Error; err != nil {
			return err
		}
		member := Membership{ID: memberID, OrganizationID: orgID, UserID: userID, Status: "active", CreatedAt: now}
		if err := tx.Create(&member).Error; err != nil {
			return err
		}
		adminFound := false
		for _, initialRole := range input.Roles {
			roleID, err := NewID()
			if err != nil {
				return err
			}
			role := Role{ID: roleID, OrganizationID: orgID, Name: initialRole.Name, Description: initialRole.Description, IsBuiltin: true, CreatedAt: now}
			if err := tx.Create(&role).Error; err != nil {
				return err
			}
			for _, permission := range initialRole.Permissions {
				if permission == "" {
					return ErrConfiguration
				}
				if err := tx.Exec("INSERT INTO permissions (code, description) VALUES (?, '') ON CONFLICT (code) DO NOTHING", permission).Error; err != nil {
					return err
				}
				if err := tx.Exec("INSERT INTO role_permissions (organization_id, role_id, permission_code) VALUES (?, ?, ?)", orgID, roleID, permission).Error; err != nil {
					return err
				}
			}
			if role.Name == input.AdminRole {
				adminFound = true
				if err := tx.Exec("INSERT INTO member_roles (organization_id, member_id, role_id) VALUES (?, ?, ?)", orgID, memberID, roleID).Error; err != nil {
					return err
				}
			}
		}
		if !adminFound {
			return ErrConfiguration
		}
		if err := tx.Exec("INSERT INTO system_settings (setting_key, value_json, version, updated_at) VALUES (?, ?, ?, ?)", "initialized", "true", 1, now).Error; err != nil {
			return err
		}
		if err := tx.Exec("INSERT INTO system_settings (setting_key, value_json, version, updated_at) VALUES (?, ?, ?, ?)", "initial_organization_id", strconv.FormatInt(orgID, 10), 1, now).Error; err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, orgID, auditObject("system.initialize", "organization", orgID), &userID)
	})
	if errors.Is(err, ErrAlreadyInitialized) || errors.Is(err, ErrConfiguration) {
		return InitializationResult{}, err
	}
	if err != nil {
		return InitializationResult{}, persistenceError(err)
	}
	return result, nil
}

func (s *Store) FindUserForAuthentication(ctx context.Context, username string) (User, error) {
	var user User
	err := s.db.WithContext(ctx).Where("username_normalized = ?", NormalizeUsername(username)).First(&user).Error
	return user, persistenceError(err)
}

func (s *Store) GetUser(ctx context.Context, userID int64) (User, error) {
	var user User
	err := s.db.WithContext(ctx).Where("id = ? AND status = ?", userID, "active").First(&user).Error
	return user, persistenceError(err)
}

func createSession(tx *gorm.DB, session *Session) error {
	if session == nil || session.UserID <= 0 || len(session.SessionHash) != 64 || len(session.CSRFHash) != 64 || !session.ExpiresAt.After(session.CreatedAt) {
		return ErrConfiguration
	}
	id, err := NewID()
	if err != nil {
		return err
	}
	session.ID, session.RevokedAt = id, nil
	return persistenceError(tx.Create(session).Error)
}

// CreateSessionIfPasswordCurrent closes the verify-password -> create-session
// race by locking and rechecking the user in the same transaction as session and
// audit insertion. The caller must have already verified Argon2id outside SQL.
func (s *Store) CreateSessionIfPasswordCurrent(ctx context.Context, session *Session, expectedHash string, now time.Time) error {
	if session == nil || expectedHash == "" {
		return ErrConfiguration
	}
	if err := s.auditReady(ctx); err != nil {
		return err
	}
	return persistenceError(s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var user User
		query := tx.Where("id = ?", session.UserID)
		if s.driver == "postgres" {
			query = query.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		if err := query.First(&user).Error; err != nil {
			return err
		}
		actor, err := audit.ActorFromContext(ctx)
		if err != nil || actor.ActorID != user.ID {
			return audit.ErrActorRequired
		}
		if user.Status != "active" || user.PasswordHash != expectedHash || (user.LockedUntil != nil && user.LockedUntil.After(now)) {
			return ErrConflict
		}
		if err := createSession(tx, session); err != nil {
			return err
		}
		if err := tx.Model(&User{}).Where("id = ?", user.ID).Updates(map[string]any{"failed_login_count": 0, "locked_until": nil, "updated_at": now.UTC()}).Error; err != nil {
			return err
		}
		return s.auditUserOrganizations(ctx, tx, user.ID, auditObject("auth.login", "session", session.ID))
	}))
}

// GetSession requires a SHA-256 token hash and rejects expired/revoked sessions.
func (s *Store) GetSession(ctx context.Context, sessionHash string, now time.Time) (Session, error) {
	var session Session
	if len(sessionHash) != 64 {
		return session, ErrNotFound
	}
	err := s.db.WithContext(ctx).Where("session_hash = ? AND revoked_at IS NULL AND expires_at > ?", sessionHash, now.UTC()).First(&session).Error
	return session, persistenceError(err)
}

func (s *Store) RevokeSession(ctx context.Context, userID int64, sessionHash string, now time.Time) error {
	if err := s.auditReady(ctx); err != nil {
		return err
	}
	return persistenceError(s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var session Session
		if err := tx.Where("user_id = ? AND session_hash = ?", userID, sessionHash).First(&session).Error; err != nil {
			return err
		}
		if session.RevokedAt != nil {
			return nil
		}
		if err := tx.Model(&Session{}).Where("id = ? AND revoked_at IS NULL", session.ID).Update("revoked_at", now.UTC()).Error; err != nil {
			return err
		}
		return s.auditUserOrganizations(ctx, tx, userID, auditObject("auth.logout", "session", session.ID))
	}))
}

func (s *Store) RevokeUserSessions(ctx context.Context, userID int64, now time.Time) error {
	if err := s.auditReady(ctx); err != nil {
		return err
	}
	return persistenceError(s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&Session{}).Where("user_id = ? AND revoked_at IS NULL", userID).Update("revoked_at", now.UTC()).Error; err != nil {
			return err
		}
		return s.auditUserOrganizations(ctx, tx, userID, auditObject("auth.sessions_revoke", "user", userID))
	}))
}

func (s *Store) RecordLoginFailure(ctx context.Context, userID int64, maxFailures int, lockedUntil time.Time) error {
	if err := s.auditReady(ctx); err != nil {
		return err
	}
	if maxFailures < 1 {
		return ErrConfiguration
	}
	return persistenceError(s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var user User
		query := tx.Where("id = ?", userID)
		if s.driver == "postgres" {
			query = query.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		if err := query.First(&user).Error; err != nil {
			return err
		}
		count := user.FailedLoginCount + 1
		updates := map[string]any{"failed_login_count": count, "updated_at": time.Now().UTC()}
		if count >= maxFailures {
			updates["locked_until"] = lockedUntil.UTC()
		}
		if err := tx.Model(&User{}).Where("id = ?", userID).Updates(updates).Error; err != nil {
			return err
		}
		command := auditObject("auth.login_failed", "user", userID)
		command.Result = "denied"
		return s.auditUserOrganizations(ctx, tx, userID, command)
	}))
}

// RecordAnonymousLoginFailure never accepts or stores a submitted username. The
// initial organization is the system audit anchor for an unknown-account outcome.
func (s *Store) RecordAnonymousLoginFailure(ctx context.Context) error {
	if err := s.auditReady(ctx); err != nil {
		return err
	}
	return persistenceError(s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var value string
		if err := tx.Table("system_settings").Select("value_json").Where("setting_key = ?", "initial_organization_id").Scan(&value).Error; err != nil {
			return err
		}
		orgID, err := strconv.ParseInt(value, 10, 64)
		if err != nil || orgID <= 0 {
			return audit.ErrIntegrity
		}
		return s.appendAudit(ctx, tx, orgID, AuditCommand{Action: "auth.login_failed", ObjectType: "user", ObjectID: "unknown", Result: "denied"}, nil)
	}))
}

func (s *Store) ResetLoginFailures(ctx context.Context, userID int64) error {
	if err := s.auditReady(ctx); err != nil {
		return err
	}
	return persistenceError(s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&User{}).Where("id = ?", userID).Updates(map[string]any{"failed_login_count": 0, "locked_until": nil, "updated_at": time.Now().UTC()}).Error; err != nil {
			return err
		}
		return s.auditUserOrganizations(ctx, tx, userID, auditObject("auth.login_security_reset", "user", userID))
	}))
}

func (s *Store) ChangePassword(ctx context.Context, userID int64, expectedHash, newHash string, now time.Time) error {
	if err := s.auditReady(ctx); err != nil {
		return err
	}
	if newHash == "" || expectedHash == "" {
		return ErrConfiguration
	}
	return persistenceError(s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&User{}).Where("id = ? AND password_hash = ?", userID, expectedHash).
			Updates(map[string]any{"password_hash": newHash, "password_changed_at": now.UTC(), "updated_at": now.UTC(), "failed_login_count": 0, "locked_until": nil, "must_change_password": false, "version": gorm.Expr("version + 1")})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrConflict
		}
		if err := tx.Model(&Session{}).Where("user_id = ? AND revoked_at IS NULL", userID).Update("revoked_at", now.UTC()).Error; err != nil {
			return err
		}
		return s.auditUserOrganizations(ctx, tx, userID, auditObject("auth.password_change", "user", userID))
	}))
}

func (s *Store) ListUserMemberships(ctx context.Context, userID int64) ([]Membership, error) {
	var memberships []Membership
	err := s.db.WithContext(ctx).Where("user_id = ? AND status = ?", userID, "active").Order("organization_id").Find(&memberships).Error
	return memberships, persistenceError(err)
}

func (t *Tenant) PermissionsForUser(userID int64) ([]string, error) {
	codes, err := managementPermissions(t.store.db.WithContext(t.ctx), t.orgID, userID)
	return codes, persistenceError(err)
}

func (t *Tenant) GetOrganization() (Organization, error) {
	var organization Organization
	err := t.store.db.WithContext(t.ctx).Where("id = ?", t.orgID).First(&organization).Error
	return organization, persistenceError(err)
}
