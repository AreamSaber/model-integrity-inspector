package identity

import (
	"context"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

type UserCreate struct {
	Username, DisplayName string
	Password              string `json:"-"`
}
type UserPatch = repository.ManagedUserPatch

func (s *Service) ListUsers(ctx context.Context, token string, list ManagementList) ([]UserSummary, error) {
	ctx, auth, err := s.managementAuthority(ctx, token, 0, "system.users", "")
	if err != nil {
		return nil, err
	}
	result, err := s.store.ManageListUsers(ctx, auth, list)
	return result, managementServiceError(err)
}
func (s *Service) CreateUser(ctx context.Context, token string, input UserCreate) (UserSummary, error) {
	ctx, auth, err := s.managementAuthority(ctx, token, 0, "system.users", "system.user_create")
	if err != nil {
		return UserSummary{}, err
	}
	if !usernamePattern.MatchString(input.Username) {
		return UserSummary{}, ErrManagementValidation
	}
	hash, err := s.hasher.Hash(ctx, input.Password)
	if err != nil {
		return UserSummary{}, err
	}
	result, err := s.store.ManageCreateUser(ctx, auth, repository.ManagedUserCreate{Username: input.Username, DisplayName: input.DisplayName, PasswordHash: hash})
	return result, managementServiceError(err)
}
func (s *Service) UpdateUser(ctx context.Context, token string, userID int64, input UserPatch) (UserSummary, error) {
	ctx, auth, err := s.managementAuthority(ctx, token, 0, "system.users", "system.user_update")
	if err != nil {
		return UserSummary{}, err
	}
	result, err := s.store.ManageUpdateUser(ctx, auth, userID, input)
	return result, managementServiceError(err)
}
func (s *Service) UnlockUser(ctx context.Context, token string, userID int64, expectedVersion int) (UserSummary, error) {
	ctx, auth, err := s.managementAuthority(ctx, token, 0, "system.users", "system.user_unlock")
	if err != nil {
		return UserSummary{}, err
	}
	result, err := s.store.ManageUnlockUser(ctx, auth, userID, expectedVersion)
	return result, managementServiceError(err)
}
func (s *Service) ResetUserPassword(ctx context.Context, token string, userID int64, expectedVersion int, password string) (UserSummary, error) {
	ctx, auth, err := s.managementAuthority(ctx, token, 0, "system.users", "system.user_password_reset")
	if err != nil {
		return UserSummary{}, err
	}
	if userID == auth.UserID {
		return UserSummary{}, ErrSelfLockout
	}
	hash, err := s.hasher.Hash(ctx, password)
	if err != nil {
		return UserSummary{}, err
	}
	result, err := s.store.ManageResetUserPassword(ctx, auth, userID, expectedVersion, hash)
	return result, managementServiceError(err)
}
