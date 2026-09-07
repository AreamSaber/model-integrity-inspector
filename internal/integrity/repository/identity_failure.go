package repository

import (
	"context"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

// RecordPasswordChangeFailure records a denied self-service action without
// persisting either password or altering login lockout counters.
func (s *Store) RecordPasswordChangeFailure(ctx context.Context, userID int64) error {
	if err := s.auditReady(ctx); err != nil {
		return err
	}
	actor, err := audit.ActorFromContext(ctx)
	if err != nil || userID <= 0 || actor.ActorID != userID {
		return audit.ErrActorRequired
	}
	return persistenceError(s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		command := auditObject("auth.password_change_failed", "user", userID)
		command.Result = "denied"
		return s.auditUserOrganizations(ctx, tx, userID, command)
	}))
}
