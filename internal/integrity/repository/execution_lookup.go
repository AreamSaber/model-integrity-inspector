package repository

import (
	"errors"

	"gorm.io/gorm"
)

// Only a successful lookup with no matching row proves this lease-bound object
// is missing. A canceled query or driver failure proves no such thing. Preserve
// those errors inside the repository so the existing queue boundary sanitizes
// them as unavailable; never weaken the actual owner/generation predicates.
func executionLeaseLookupError(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrJobLeaseLost
	}
	return err
}
