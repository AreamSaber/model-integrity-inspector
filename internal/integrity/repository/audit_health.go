package repository

import (
	"context"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

// VerifyAllAudit is an internal operational capability, not a tenant read API.
// Startup/restore use full=true; readiness uses bounded tail verification for
// every organization. Neither variant returns identifiers, hashes or event data.
func (s *Store) VerifyAllAudit(ctx context.Context, full bool) error {
	if s.auditSigner == nil {
		return audit.ErrUnavailable
	}
	var after int64
	var seen int
	for {
		var ids []int64
		if err := s.db.WithContext(ctx).Model(&Organization{}).Where("id > ?", after).Order("id").Limit(100).Pluck("id", &ids).Error; err != nil {
			return persistenceError(err)
		}
		for _, id := range ids {
			tenant, err := s.WithOrganization(ctx, id)
			if err != nil {
				return err
			}
			if _, err := tenant.verifyAudit(full); err != nil {
				return err
			}
			seen++
			after = id
		}
		if len(ids) < 100 {
			break
		}
	}
	initialized, err := s.SetupStatus(ctx)
	if err != nil {
		return err
	}
	if initialized && seen == 0 {
		return audit.ErrIntegrity
	}
	return nil
}
