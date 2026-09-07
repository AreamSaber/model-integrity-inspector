package run

import (
	"context"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

// Version checks the same bound control authority as Get, but never reads the
// execution snapshot or sample bodies. Callers must revalidate live run.read
// permission: a bound context is not a long-lived session authorization.
func (s *Service) Version(ctx context.Context, organizationID, id int64) (repository.RunVersion, error) {
	tenant, err := s.tenant(ctx, organizationID)
	if err != nil {
		return repository.RunVersion{}, err
	}
	return tenant.GetRunVersion(id)
}
