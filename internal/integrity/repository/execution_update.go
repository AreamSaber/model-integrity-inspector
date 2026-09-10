package repository

import "gorm.io/gorm"

// A successful driver call need not have changed its intended rows: conditional
// updates and real BEFORE UPDATE triggers can affect zero (or only some) rows.
// Callers already hold the execution transaction's Run/reservation locks.
func executionChanged(result *gorm.DB, expected int64) error {
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != expected {
		return ErrConflict
	}
	return nil
}

// Bulk terminal projections may legitimately contain no rows. Count the exact
// predicate under the same locks, then require the whole set to be updated;
// checking merely RowsAffected > 0 would still accept a partial suppression.
func executionUpdateAll(query *gorm.DB, values map[string]any) error {
	var expected int64
	if err := query.Session(&gorm.Session{}).Count(&expected).Error; err != nil {
		return err
	}
	return executionChanged(query.Updates(values), expected)
}
