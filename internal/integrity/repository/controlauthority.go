package repository

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

type controlAuthorityKey struct{}
type controlAuthority struct {
	store          *Store
	organizationID int64
	identity       ManagementAuthority
}

// BindControlAuthority derives identity exclusively from a persisted session
// hash; there is no public constructor accepting user/session IDs. The control
// handler calls this after Principal and audit-actor binding. Body fields can
// neither construct nor modify the private context capability.
func (s *Store) BindControlAuthority(ctx context.Context, sessionHash string, organizationID int64) (context.Context, error) {
	if ctx == nil || organizationID <= 0 {
		return nil, ErrManagementSession
	}
	session, err := s.GetSession(ctx, sessionHash, time.Now())
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrManagementSession
		}
		return nil, err
	}
	user, err := s.GetUser(ctx, session.UserID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrManagementSession
		}
		return nil, err
	}
	if session.CreatedAt.Before(user.PasswordChangedAt) {
		return nil, ErrManagementSession
	}
	if user.MustChangePassword {
		return nil, ErrPasswordChangeRequired
	}
	actor, err := audit.ActorFromContext(ctx)
	if err != nil || actor.ActorID != user.ID {
		return nil, audit.ErrActorRequired
	}
	value := controlAuthority{store: s, organizationID: organizationID, identity: ManagementAuthority{UserID: user.ID, SessionID: session.ID}}
	return context.WithValue(ctx, controlAuthorityKey{}, value), nil
}

// RequireControlAuthority is an early structural check, not authorization. The
// transaction still re-reads the session/user/grants at its linearization point.
// Worker lease operations do not use this capability and have no fallback here.
func (s *Store) RequireControlAuthority(ctx context.Context, organizationID int64) error {
	if organizationID <= 0 {
		return ErrOrganizationScope
	}
	if ctx == nil {
		return ErrManagementSession
	}
	value, ok := ctx.Value(controlAuthorityKey{}).(controlAuthority)
	if !ok || value.store != s {
		return ErrManagementSession
	}
	if value.organizationID != organizationID {
		return ErrManagementPermission
	}
	actor, err := audit.ActorFromContext(ctx)
	if err != nil || actor.ActorID != value.identity.UserID {
		return audit.ErrActorRequired
	}
	return nil
}

func (t *Tenant) controlTransaction(permission string, operation func(*gorm.DB) error) error {
	if err := t.store.RequireControlAuthority(t.ctx, t.orgID); err != nil {
		return err
	}
	value := t.ctx.Value(controlAuthorityKey{}).(controlAuthority)
	// The concrete repository method supplies a fixed permission. No permission
	// string from request/context is accepted as an authorization decision.
	return t.store.managementTransaction(t.ctx, value.identity, t.orgID, permission, true, func(tx *gorm.DB, _ User) error { return operation(tx) })
}

func (t *Tenant) controlTenantTransaction(permission string, operation func(*TenantTransaction) error) error {
	return t.controlTransaction(permission, func(db *gorm.DB) error {
		transaction := &TenantTransaction{store: t.store, db: db, ctx: t.ctx, orgID: t.orgID}
		defer transaction.closed.Store(true)
		return operation(transaction)
	})
}
