package target

import (
	"context"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func (service *Service) ListFiltered(ctx context.Context, orgID int64, options repository.ListOptions, filters repository.TargetFilters) ([]View, error) {
	tenant, err := service.store.WithOrganization(ctx, orgID)
	if err != nil {
		return nil, err
	}
	states, err := tenant.ListTargetsFiltered(options, filters)
	if err != nil {
		return nil, err
	}
	result := make([]View, len(states))
	for i, state := range states {
		result[i], err = view(state)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}
