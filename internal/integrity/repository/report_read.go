package repository

import (
	"errors"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func (t *Tenant) reportTransaction(operation func(*TenantTransaction) error) error {
	var businessErr error
	err := t.controlTenantTransaction("report.export", func(tx *TenantTransaction) error {
		businessErr = operation(tx)
		return businessErr
	})
	// Shared management wrappers intentionally hide unknown diagnostics. Preserve
	// only this module's fixed business sentinels after the transaction rolls back.
	for _, known := range []error{ErrReportInvalid, ErrReportNotReady, ErrReportLimit, ErrResultDocument} {
		if errors.Is(businessErr, known) {
			return known
		}
	}
	return reportError(err)
}
func (t *Tenant) reportRead(operation func(*gorm.DB) error) error {
	var businessErr error
	err := t.resultReadTransaction(true, func(tx *gorm.DB) error {
		actor, err := audit.ActorFromContext(t.ctx)
		if err != nil {
			return err
		}
		if err := reportPermissions(tx, t.orgID, actor.ActorID); err != nil {
			return err
		}
		businessErr = operation(tx)
		return businessErr
	})
	for _, known := range []error{ErrReportInvalid, ErrReportNotReady} {
		if errors.Is(businessErr, known) {
			return known
		}
	}
	return reportError(err)
}
func reportRow(tx *gorm.DB, org, id int64) (ReportRecord, error) {
	var row ReportRecord
	if err := tx.Select(reportMetadataColumns(tx)).Where("organization_id=? AND id=?", org, id).Take(&row).Error; err != nil {
		return row, err
	}
	if !validReportRecord(row, org) {
		return ReportRecord{}, ErrReportInvalid
	}
	return row, nil
}
func (t *Tenant) GetReport(id int64) (ReportRecord, error) {
	if id <= 0 {
		return ReportRecord{}, ErrNotFound
	}
	var row ReportRecord
	err := t.reportRead(func(tx *gorm.DB) error { var err error; row, err = reportRow(tx, t.orgID, id); return err })
	return row, err
}
func (t *Tenant) ListReports(runID int64, revision int, page ListOptions) ([]ReportRecord, error) {
	if runID <= 0 || revision != 1 || page.AfterID < 0 || page.Limit < 1 || page.Limit > 100 {
		return nil, ErrReportInvalid
	}
	rows := []ReportRecord{}
	err := t.reportRead(func(tx *gorm.DB) error {
		if err := publishedReviewScope(tx, t.orgID, runID, revision); err != nil {
			return err
		}
		if err := tx.Select(reportMetadataColumns(tx)).Where("organization_id=? AND run_id=? AND analysis_revision=? AND id>?", t.orgID, runID, revision, page.AfterID).Order("id").Limit(page.Limit).Find(&rows).Error; err != nil {
			return err
		}
		for _, row := range rows {
			if !validReportRecord(row, t.orgID) {
				return ErrReportInvalid
			}
		}
		return nil
	})
	return rows, err
}

// AuditReportDownload is the final authorization point after file verification
// and before sending bytes. Its receipt binds exactly the file read by service.
func (t *Tenant) AuditReportDownload(id int64, fileHash string, size int64) error {
	if id <= 0 || !executionHash.MatchString(fileHash) || size < 1 || size > reportFileLimit {
		return ErrReportInvalid
	}
	return t.reportTransaction(func(tx *TenantTransaction) error {
		actor, err := audit.ActorFromContext(tx.ctx)
		if err != nil {
			return err
		}
		if err := reportPermissions(tx.db, t.orgID, actor.ActorID); err != nil {
			return err
		}
		row, err := reportRow(tx.db, t.orgID, id)
		if err != nil {
			return err
		}
		if row.Status != "ready" {
			return ErrReportNotReady
		}
		if *row.FileHash != fileHash || *row.FileSize != size {
			return ErrReportInvalid
		}
		return t.store.appendAudit(tx.ctx, tx.db, t.orgID, auditObject("report.download", "report", id), nil)
	})
}
