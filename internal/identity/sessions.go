package identity

import (
	"context"
	"errors"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

// LogoutAll revokes the caller's current and other sessions without changing the
// password or affecting another account. HTTP must also enforce Origin and CSRF.
func (s *Service) LogoutAll(ctx context.Context, token string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	user, session, err := s.authenticate(ctx, token)
	if err != nil {
		return err
	}
	actorCtx, err := bindActor(ctx, user.ID, "auth.logout_all")
	if err != nil {
		return err
	}
	err = s.store.RevokeOwnSessions(actorCtx, repository.ManagementAuthority{UserID: user.ID, SessionID: session.ID})
	if errors.Is(err, repository.ErrManagementSession) {
		return ErrSession
	}
	if err != nil {
		return ErrUnavailable
	}
	return nil
}
