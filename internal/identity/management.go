package identity

import (
	"context"
	"errors"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

var (
	ErrPasswordChangeRequired = errors.New("MI_PASSWORD_CHANGE_REQUIRED")
	ErrManagementValidation   = errors.New("MI_VALIDATION")
	ErrManagementConflict     = errors.New("MI_VERSION_CONFLICT")
	ErrManagementNotFound     = errors.New("MI_NOT_FOUND")
	ErrLastAdministrator      = errors.New("MI_LAST_ADMINISTRATOR")
	ErrSelfLockout            = errors.New("MI_SELF_LOCKOUT_FORBIDDEN")
)

type UserSummary = repository.UserSummary
type OrganizationSummary = repository.OrganizationSummary
type MemberSummary = repository.MemberSummary
type RoleSummary = repository.RoleSummary
type ManagementList = repository.ManagementList

func managementServiceError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, repository.ErrManagementPermission), errors.Is(err, repository.ErrOrganizationScope):
		return ErrPermission
	case errors.Is(err, repository.ErrManagementSession):
		return ErrSession
	case errors.Is(err, repository.ErrPasswordChangeRequired):
		return ErrPasswordChangeRequired
	case errors.Is(err, repository.ErrConfiguration):
		return ErrManagementValidation
	case errors.Is(err, repository.ErrConflict):
		return ErrManagementConflict
	case errors.Is(err, repository.ErrNotFound):
		return ErrManagementNotFound
	case errors.Is(err, repository.ErrLastAdministrator):
		return ErrLastAdministrator
	case errors.Is(err, repository.ErrSelfLockout):
		return ErrSelfLockout
	default:
		return ErrUnavailable
	}
}

// Preflight limits unauthorized work (in particular Argon2 cost), while the
// repository repeats authorization inside the mutation transaction.
func (s *Service) managementAuthority(ctx context.Context, token string, orgID int64, permission, reason string) (context.Context, repository.ManagementAuthority, error) {
	user, session, err := s.authenticate(ctx, token)
	if err != nil {
		return ctx, repository.ManagementAuthority{}, err
	}
	if user.MustChangePassword {
		return ctx, repository.ManagementAuthority{}, ErrPasswordChangeRequired
	}
	p := Principal{UserID: user.ID, OrganizationID: orgID, SystemAdmin: user.IsSystemAdmin}
	if permission != "organizations.list" {
		if orgID > 0 {
			tenant, e := s.store.WithOrganization(ctx, orgID)
			if e != nil {
				return ctx, repository.ManagementAuthority{}, ErrPermission
			}
			p.Permissions, e = tenant.PermissionsForUser(user.ID)
			if e != nil {
				return ctx, repository.ManagementAuthority{}, ErrUnavailable
			}
		}
		if err := p.Authorize(permission); err != nil {
			return ctx, repository.ManagementAuthority{}, err
		}
	}
	if reason != "" {
		ctx, err = bindActor(ctx, user.ID, reason)
		if err != nil {
			return ctx, repository.ManagementAuthority{}, err
		}
	}
	return ctx, repository.ManagementAuthority{UserID: user.ID, SessionID: session.ID}, nil
}

func validTimezone(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	_, err := time.LoadLocation(value)
	return err == nil
}
