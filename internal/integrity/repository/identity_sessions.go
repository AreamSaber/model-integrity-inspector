package repository

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

// RevokeOwnSessions is a self-service operation, not an administrative bypass.
// Authority comes from the authenticated session, never a submitted user ID.
// Lock the user before the session, as login and account management do, then
// revalidate before changing anything. Login serialized after this commit creates
// a new session normally; this operation is not an account lock/password reset.
func (s *Store) RevokeOwnSessions(ctx context.Context, auth ManagementAuthority) error {
	if auth.UserID <= 0 || auth.SessionID <= 0 {
		return ErrManagementSession
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := s.auditReady(ctx); err != nil {
		return err
	}
	actor, err := audit.ActorFromContext(ctx)
	if err != nil || actor.ActorID != auth.UserID {
		return audit.ErrActorRequired
	}
	return managementError(s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var user User
		q := tx.Where("id = ?", auth.UserID)
		if s.driver == "postgres" {
			q = q.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		if err := q.First(&user).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrManagementSession
			}
			return err
		}
		var session Session
		q = tx.Where("id = ? AND user_id = ?", auth.SessionID, auth.UserID)
		if s.driver == "postgres" {
			q = q.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		if err := q.First(&session).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrManagementSession
			}
			return err
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		if user.Status != "active" || session.RevokedAt != nil || !session.ExpiresAt.After(now) || session.CreatedAt.Before(user.PasswordChangedAt) {
			return ErrManagementSession
		}
		// Even a forced-password-change session may sign itself out everywhere.
		// Neither organization membership nor administrator status is required.
		result := tx.Model(&Session{}).Where("user_id = ? AND revoked_at IS NULL", auth.UserID).Update("revoked_at", now)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected < 1 {
			return ErrManagementSession
		}
		return s.auditUserOrganizations(ctx, tx, auth.UserID, auditObject("auth.logout_all", "user", auth.UserID))
	}))
}
