package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"

	"gorm.io/gorm"
)

// Validate every supplied physical sample ID, including nested behavior IDs.
// A retained conclusion does not authorize replacing an orphan with a current
// sample. No request/response body is loaded; scalars are gated in SQL first.
func snapshotResultReferenceSamples(ctx context.Context, tx *gorm.DB, result snapshotResultReferenceRow, refs []snapshotResultSampleReference, legacy bool) (string, error) {
	h := sha256.New()
	snapshotReferenceFrame(h, struct{ Domain string }{"mii.snapshot.result-sample-source-observations.v1"})
	wanted := make(map[int64][]snapshotResultSampleReference)
	for _, ref := range refs {
		if ref.id > 0 {
			wanted[ref.id] = append(wanted[ref.id], ref)
		}
	}
	ids := make([]int64, 0, len(wanted))
	for id := range wanted {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for start := 0; start < len(ids); start += snapshotResultReferencePageSize {
		if ctx.Err() != nil {
			return "", ErrUnavailable
		}
		page := ids[start:min(start+snapshotResultReferencePageSize, len(ids))]
		var rows []struct {
			ID, OrganizationID, RunID, ProbeID, Ordinal, ExecutionOrdinal int64
			TemplateID, TemplateVersion                                   string
			Valid                                                         int
		}
		valid := ""
		for _, column := range []string{"s.id", "s.organization_id", "s.run_id", "s.probe_instance_id"} {
			if valid != "" {
				valid += " AND "
			}
			valid += snapshotKeyIntegerOK(tx, column, 1, 9223372036854775807)
		}
		for _, column := range []string{"s.ordinal", "s.execution_ordinal"} {
			valid += " AND " + snapshotKeyIntegerOK(tx, column, 0, 9223372036854775807)
		}
		valid += " AND (SELECT COUNT(*) FROM integrity_probe_instances p WHERE p.id=s.probe_instance_id)=1"
		valid += " AND " + snapshotKeyTextOK(tx, "p.template_id", 1, 128) + " AND " + snapshotKeyTextOK(tx, "p.template_version", 1, 128)
		columns := ""
		for _, item := range [][2]string{{"s.id", "id"}, {"s.organization_id", "organization_id"}, {"s.run_id", "run_id"}, {"s.probe_instance_id", "probe_id"}, {"s.ordinal", "ordinal"}, {"s.execution_ordinal", "execution_ordinal"}} {
			if columns != "" {
				columns += ","
			}
			columns += snapshotReportInteger(tx, item[0], item[1], 9223372036854775807)
		}
		for _, column := range []string{"template_id", "template_version"} {
			columns += ",CASE WHEN " + snapshotKeyTextOK(tx, "p."+column, 1, 128) + " THEN p." + column + " ELSE '' END AS " + column
		}
		columns += ",CASE WHEN " + valid + " THEN 1 ELSE 0 END AS valid"
		if err := tx.Table("integrity_logical_samples s").Joins("LEFT JOIN integrity_probe_instances p ON p.id=s.probe_instance_id AND p.organization_id=s.organization_id AND p.run_id=s.run_id").Select(columns).Where("s.id IN ?", page).Order("s.id").Limit(snapshotResultReferencePageSize + 1).Find(&rows).Error; err != nil || ctx.Err() != nil {
			return "", ErrUnavailable
		}
		if len(rows) != len(page) {
			return "", errSnapshotResultReferenceInvalid
		}
		for i, row := range rows {
			if row.Valid != 1 || row.ID != page[i] || row.OrganizationID != result.OrganizationID || row.RunID != result.RunID || !executionLabel.MatchString(row.TemplateID) || !executionLabel.MatchString(row.TemplateVersion) {
				return "", errSnapshotResultReferenceInvalid
			}
			for _, ref := range wanted[row.ID] {
				// mii.analysis.v1's feature ordinal is the global execution /
				// manifest ordinal. Legacy probe-local ordinal is retained below,
				// not reinterpreted as global merely because the source is old.
				if ref.hasOrdinal && (ref.ordinal != row.ExecutionOrdinal || !legacy && ref.ordinal != row.Ordinal) || ref.memberID != "" && ref.memberID != row.TemplateID || ref.memberVersion != "" && ref.memberVersion != row.TemplateVersion {
					return "", errSnapshotResultReferenceInvalid
				}
			}
			snapshotReferenceFrame(h, row)
		}
	}
	if ctx.Err() != nil {
		return "", ErrUnavailable
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
