package repository

import (
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const responseRetentionDayMicros = int64(24 * time.Hour / time.Microsecond)

// ResponseRetentionPolicy is an internal database observation, not authority to
// disclose or persist a response. Its scope, version and clock cannot be filled
// from an HTTP DTO. Re-read under the organization lock at the final transaction
// before any plaintext release/body commit; a copied observation can be stale.
type ResponseRetentionPolicy struct {
	organizationID, notBeforeMicros, observedAtMicros int64
	days, version                                     int
	active                                            bool
}

// Policies are internal observations, never transport objects or request input.
func (ResponseRetentionPolicy) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (*ResponseRetentionPolicy) UnmarshalJSON([]byte) error  { return ErrConfiguration }

func (p ResponseRetentionPolicy) OrganizationID() int64   { return p.organizationID }
func (p ResponseRetentionPolicy) Days() int               { return p.days }
func (p ResponseRetentionPolicy) Version() int            { return p.version }
func (p ResponseRetentionPolicy) NotBeforeMicros() int64  { return p.notBeforeMicros }
func (p ResponseRetentionPolicy) ObservedAtMicros() int64 { return p.observedAtMicros }

// EligibleAtObservation intersects the immutable sealed expiry with BOTH the
// current day window and monotonic cutoff, all against this database observation.
// Exact cutoff/day/expiry boundaries reject. Nothing here authenticates the
// supplied envelope, selected history or user; those remain mandatory checks.
func (p ResponseRetentionPolicy) EligibleAtObservation(capturedAtMicros, sealedExpiryMicros int64, deleted bool) bool {
	if p.organizationID <= 0 || p.version <= 0 || !p.active || p.days < 1 || p.days > 180 || p.notBeforeMicros < 0 || p.observedAtMicros <= 0 || deleted || capturedAtMicros <= 0 || capturedAtMicros > p.observedAtMicros || sealedExpiryMicros <= p.observedAtMicros {
		return false
	}
	return capturedAtMicros > p.notBeforeMicros && capturedAtMicros > p.observedAtMicros-int64(p.days)*responseRetentionDayMicros
}

type responseRetentionOrganization struct {
	ID                              int64
	Status                          string
	FullResponseRetentionDays       int
	ResponseEvidenceNotBeforeMicros int64
	Version                         int
}

func loadResponseRetentionOrganization(db *gorm.DB, driver string, orgID int64, lock bool) (responseRetentionOrganization, error) {
	var row responseRetentionOrganization
	if orgID <= 0 {
		return row, ErrOrganizationScope
	}
	query := db.Model(&Organization{}).Select("id, status, full_response_retention_days, response_evidence_not_before_micros, version").Where("id = ?", orgID)
	if lock && driver == "postgres" {
		// Policy changes never update the organization key. NO KEY UPDATE still
		// serializes them, but admits FK KEY SHARE checks from an audit INSERT.
		// Anonymous audit already owns its chain head without the management
		// mutex; FOR UPDATE here would create org -> head -> org deadlocks.
		query = query.Clauses(clause.Locking{Strength: "NO KEY UPDATE"})
	}
	if err := query.Take(&row).Error; err != nil {
		return row, persistenceError(err)
	}
	if row.ID != orgID || row.FullResponseRetentionDays < 0 || row.FullResponseRetentionDays > 180 || row.ResponseEvidenceNotBeforeMicros < 0 || row.Version <= 0 || (row.Status != "active" && row.Status != "disabled") {
		return responseRetentionOrganization{}, ErrUnavailable
	}
	return row, nil
}

func responseRetentionObservation(row responseRetentionOrganization, db *gorm.DB, driver string) (ResponseRetentionPolicy, error) {
	// Observe only AFTER any row-lock wait, never before acquiring the policy.
	now, err := queueTime(db, driver)
	if err != nil || now.UnixMicro() <= 0 {
		return ResponseRetentionPolicy{}, ErrUnavailable
	}
	return ResponseRetentionPolicy{organizationID: row.ID, days: row.FullResponseRetentionDays, version: row.Version, notBeforeMicros: row.ResponseEvidenceNotBeforeMicros, observedAtMicros: now.UnixMicro(), active: row.Status == "active"}, nil
}

// GetResponseRetentionPolicy reads one consistent, non-writing snapshot. It is
// useful for planning only; it cannot authorize a later body commit or release.
func (t *Tenant) GetResponseRetentionPolicy() (ResponseRetentionPolicy, error) {
	if t == nil || t.store == nil || t.ctx == nil || t.orgID <= 0 {
		return ResponseRetentionPolicy{}, ErrOrganizationScope
	}
	var policy ResponseRetentionPolicy
	err := reportSnapshotTransaction(t.ctx, t.store, func(db *gorm.DB) error {
		row, err := loadResponseRetentionOrganization(db, t.store.driver, t.orgID, false)
		if err != nil {
			return err
		}
		policy, err = responseRetentionObservation(row, db, t.store.driver)
		return err
	})
	if err != nil {
		return ResponseRetentionPolicy{}, persistenceError(err)
	}
	return policy, nil
}

// LockResponseRetentionPolicy participates in an existing short transaction.
// Required future order: management mutex/user/session OR Worker Job row, THEN
// organization policy, THEN execution mutex/sample/run/target, THEN audit heads.
// In particular LoadRunAnalysis must call this BEFORE lockRun, not after it.
// Never acquire a policy lock while holding an audit head or in reverse run->org
// order. PostgreSQL policy locks are NO KEY UPDATE, compatible with the audit
// INSERT's organization FK KEY SHARE. SQLite BEGIN IMMEDIATE serializes writers.
func (tx *TenantTransaction) LockResponseRetentionPolicy() (ResponseRetentionPolicy, error) {
	if tx == nil || tx.store == nil {
		return ResponseRetentionPolicy{}, ErrConfiguration
	}
	if tx.closed.Load() {
		return ResponseRetentionPolicy{}, ErrTransactionClosed
	}
	row, err := loadResponseRetentionOrganization(tx.db, tx.store.driver, tx.orgID, true)
	if err != nil {
		return ResponseRetentionPolicy{}, err
	}
	return responseRetentionObservation(row, tx.db, tx.store.driver)
}

// advanceResponseRetention applies a setting change using the ONE observation
// taken after the organization lock. Even explicitly reapplying the same number
// advances the natural cutoff. Non-retention edits do not call this helper.
func advanceResponseRetention(row responseRetentionOrganization, newDays int, now time.Time) (int64, error) {
	if row.FullResponseRetentionDays < 0 || row.FullResponseRetentionDays > 180 || newDays < 0 || newDays > 180 || row.ResponseEvidenceNotBeforeMicros < 0 || now.UnixMicro() <= 0 {
		return 0, ErrConfiguration
	}
	return max(row.ResponseEvidenceNotBeforeMicros, now.UnixMicro()-int64(row.FullResponseRetentionDays)*responseRetentionDayMicros, now.UnixMicro()-int64(newDays)*responseRetentionDayMicros), nil
}
