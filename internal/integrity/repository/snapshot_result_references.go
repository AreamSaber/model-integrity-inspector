package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strconv"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

var (
	errSnapshotResultReferenceInvalid     = errors.New("SNAPSHOT_RESULT_REFERENCE_INVALID")
	errSnapshotResultReferenceLimit       = errors.New("SNAPSHOT_RESULT_REFERENCE_LIMIT")
	errSnapshotResultReferenceUnsupported = errors.New("SNAPSHOT_RESULT_REFERENCE_UNSUPPORTED")
)

const snapshotResultReferenceMaxBytes = 4 << 20
const snapshotResultReferencePageSize = 100

// Hash roles are separate namespaces. In particular tokenrisk is a scoring
// algorithm, NOT the tokenizer configuration, and none is a carrier-file hash.
type snapshotResultReference struct {
	organizationID                                                              int64
	versions                                                                    domain.BundleVersions
	role, version, sha256, memberID, containerVersion, containerHash, qualifier string
}

func (snapshotResultReference) String() string               { return "[private result artifact reference]" }
func (v snapshotResultReference) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, v.String()) }
func (v snapshotResultReference) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (snapshotResultReference) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (snapshotResultReference) MarshalYAML() (any, error)    { return nil, ErrConfiguration }

// This observes retained result roots, not their complete transitive artifact
// closure, authentic parameter use, calibration, publication or activation.
type snapshotResultReferences struct {
	references                                        []snapshotResultReference
	classification                                    snapshotReferenceClassification
	rows, published, unpublished, incomplete, unknown int64
	sourceSHA256                                      string
}

func (snapshotResultReferences) String() string               { return "[private result root observations]" }
func (v snapshotResultReferences) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, v.String()) }
func (v snapshotResultReferences) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (snapshotResultReferences) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (snapshotResultReferences) MarshalYAML() (any, error)    { return nil, ErrConfiguration }

type snapshotResultReferenceRow struct {
	OrganizationID, RunID, Revision int64
	Published, Valid                int
}

func snapshotResultReferenceError(err error) error {
	switch {
	case errors.Is(err, ErrUnavailable):
		return ErrUnavailable
	case errors.Is(err, errSnapshotResultReferenceLimit), errors.Is(err, errSnapshotReferenceLimit):
		return errSnapshotResultReferenceLimit
	case errors.Is(err, errSnapshotResultReferenceUnsupported), errors.Is(err, errSnapshotReferenceUnsupported):
		return errSnapshotResultReferenceUnsupported
	default:
		return errSnapshotResultReferenceInvalid
	}
}

func (s *Store) snapshotResultReferences(ctx context.Context, tx *gorm.DB) (snapshotResultReferences, error) {
	return s.snapshotResultReferencesLimited(ctx, tx, snapshotReferenceLimit)
}

// The caller owns the actual physical-RO transaction throughout. No Store
// pool, transaction control, current revision/status/TTL filter, or writes.
func (s *Store) snapshotResultReferencesLimited(ctx context.Context, tx *gorm.DB, limit int) (snapshotResultReferences, error) {
	if ctx == nil || s == nil || tx == nil || tx.Config == nil || tx.Statement == nil || tx.Error != nil || tx.Dialector == nil || tx.Name() != s.driver || limit < 1 || limit > snapshotReferenceLimit {
		return snapshotResultReferences{}, ErrConfiguration
	}
	if ctx.Err() != nil {
		return snapshotResultReferences{}, ErrUnavailable
	}
	if _, ok := ctx.Deadline(); !ok {
		return snapshotResultReferences{}, ErrConfiguration
	}
	if actual, ok := tx.Statement.ConnPool.(*sql.Tx); !ok || actual == nil {
		return snapshotResultReferences{}, ErrConfiguration
	}
	read := tx.Session(&gorm.Session{NewDB: true, Context: ctx})
	if err := auditSnapshotTransaction(read, s.driver); err != nil {
		return snapshotResultReferences{}, err
	}
	var total int64
	if err := read.Table("integrity_run_results").Count(&total).Error; err != nil {
		return snapshotResultReferences{}, ErrUnavailable
	}
	var duplicate bool
	if err := read.Raw("SELECT EXISTS(SELECT 1 FROM integrity_run_results GROUP BY organization_id,run_id,analysis_revision HAVING COUNT(*)>1)").Scan(&duplicate).Error; err != nil {
		return snapshotResultReferences{}, ErrUnavailable
	}
	if total < 0 || duplicate {
		return snapshotResultReferences{}, errSnapshotResultReferenceInvalid
	}
	result := snapshotResultReferences{classification: snapshotReferenceObserved}
	refs := make(map[snapshotResultReference]struct{})
	h := sha256.New()
	snapshotReferenceFrame(h, struct{ Domain string }{"mii.snapshot.result-root-observations.v1"})
	var org, run int64
	var revision int64
	for {
		if ctx.Err() != nil {
			return snapshotResultReferences{}, ErrUnavailable
		}
		var rows []snapshotResultReferenceRow
		if err := read.Table("integrity_run_results q").Select(snapshotResultReferenceColumns(read)).Where("q.organization_id>? OR (q.organization_id=? AND (q.run_id>? OR (q.run_id=? AND q.analysis_revision>?)))", org, org, run, run, revision).Order("q.organization_id,q.run_id,q.analysis_revision").Limit(snapshotResultReferencePageSize).Find(&rows).Error; err != nil {
			return snapshotResultReferences{}, ErrUnavailable
		}
		for _, row := range rows {
			if ctx.Err() != nil {
				return snapshotResultReferences{}, ErrUnavailable
			}
			if row.Valid != 1 || row.OrganizationID < 1 || row.RunID < 1 || row.Revision < 1 || row.OrganizationID < org || row.OrganizationID == org && (row.RunID < run || row.RunID == run && row.Revision <= revision) || result.rows >= total {
				return snapshotResultReferences{}, errSnapshotResultReferenceInvalid
			}
			originalRun, source, runHash, err := snapshotResultReferenceRun(ctx, read, row)
			if err != nil {
				return snapshotResultReferences{}, snapshotResultReferenceError(err)
			}
			body, err := snapshotResultReferenceBody(ctx, read, row)
			if err != nil {
				return snapshotResultReferences{}, err
			}
			bodyHash := baselineHash(body)
			observation, err := snapshotResultReferenceDocument(ctx, row, originalRun, source, body, limit)
			clear(body)
			if err != nil {
				return snapshotResultReferences{}, snapshotResultReferenceError(err)
			}
			sampleHash, err := snapshotResultReferenceSamples(ctx, read, row, observation.samples, source.legacy)
			if err != nil {
				return snapshotResultReferences{}, err
			}
			for ref := range observation.refs {
				if _, present := refs[ref]; !present && len(refs) >= limit {
					return snapshotResultReferences{}, errSnapshotResultReferenceLimit
				}
				refs[ref] = struct{}{}
			}
			if row.Published == 1 {
				result.published++
			} else {
				result.unpublished++
			}
			if observation.incomplete {
				result.incomplete++
				result.classification = snapshotReferenceLegacyIncomplete
			}
			if observation.unknown {
				result.unknown++
			}
			// Framing binds the real SQL revision (not a made-up JSON revision),
			// original source bytes, schema label, and explicit evidence gaps.
			snapshotReferenceFrame(h, struct {
				Row                                                       snapshotResultReferenceRow
				Source                                                    snapshotReferenceRow
				ResultBodySHA256, RunBodySHA256, SampleRowsSHA256, Schema string
				Incomplete, Unknown                                       bool
			}{row, originalRun, bodyHash, runHash, sampleHash, observation.schema, observation.incomplete, observation.unknown})
			result.rows++
			org, run, revision = row.OrganizationID, row.RunID, row.Revision
		}
		if len(rows) < snapshotResultReferencePageSize {
			break
		}
	}
	var finalCount int64
	if err := read.Table("integrity_run_results").Count(&finalCount).Error; err != nil || ctx.Err() != nil {
		return snapshotResultReferences{}, ErrUnavailable
	}
	if result.rows != total || finalCount != total {
		return snapshotResultReferences{}, errSnapshotResultReferenceInvalid
	}
	snapshotReferenceFrame(h, struct{ Rows, Published, Unpublished, Incomplete, Unknown int64 }{result.rows, result.published, result.unpublished, result.incomplete, result.unknown})
	result.sourceSHA256 = hex.EncodeToString(h.Sum(nil))
	for ref := range refs {
		result.references = append(result.references, ref)
	}
	slices.SortFunc(result.references, func(a, b snapshotResultReference) int {
		return slices.Compare(snapshotResultReferenceIdentity(a), snapshotResultReferenceIdentity(b))
	})
	if ctx.Err() != nil {
		return snapshotResultReferences{}, ErrUnavailable
	}
	return result, nil
}

func snapshotResultReferenceIdentity(v snapshotResultReference) []string {
	return []string{strconv.FormatInt(v.organizationID, 10), v.versions.Rule, v.versions.Template, v.versions.Scoring, v.versions.Tokenizer, v.role, v.version, v.sha256, v.memberID, v.containerVersion, v.containerHash, v.qualifier}
}

func snapshotResultReferenceColumns(tx *gorm.DB) string {
	valid := snapshotKeyIntegerOK(tx, "q.organization_id", 1, 9223372036854775807) + " AND " + snapshotKeyIntegerOK(tx, "q.run_id", 1, 9223372036854775807) + " AND " + snapshotKeyIntegerOK(tx, "q.analysis_revision", 1, 9223372036854775807) + " AND " + snapshotKeyTextOK(tx, "q.conclusion_json", 1, snapshotResultReferenceMaxBytes)
	valid += " AND (SELECT COUNT(*) FROM organizations o WHERE o.id=q.organization_id)=1 AND (SELECT COUNT(*) FROM integrity_runs r WHERE r.organization_id=q.organization_id AND r.id=q.run_id)=1"
	if tx.Name() == "sqlite" {
		valid += " AND typeof(q.is_published)='integer' AND q.is_published IN (0,1)"
	} else {
		valid += " AND q.is_published IS NOT NULL"
	}
	return snapshotReportInteger(tx, "q.organization_id", "organization_id", 9223372036854775807) + "," + snapshotReportInteger(tx, "q.run_id", "run_id", 9223372036854775807) + "," + snapshotReportInteger(tx, "q.analysis_revision", "revision", 9223372036854775807) + ",CASE WHEN q.is_published THEN 1 ELSE 0 END AS published,CASE WHEN " + valid + " THEN 1 ELSE 0 END AS valid"
}

func snapshotResultReferenceRun(ctx context.Context, tx *gorm.DB, row snapshotResultReferenceRow) (snapshotReferenceRow, snapshotReferenceObservation, string, error) {
	source := snapshotReferenceSources()[0]
	var runs []snapshotReferenceRow
	if err := tx.Table(source.table+" r").Select(snapshotReferenceColumns(tx, source)).Where("r.organization_id=? AND r.id=?", row.OrganizationID, row.RunID).Limit(2).Find(&runs).Error; err != nil {
		return snapshotReferenceRow{}, snapshotReferenceObservation{}, "", ErrUnavailable
	}
	if len(runs) != 1 || runs[0].Valid != 1 {
		return snapshotReferenceRow{}, snapshotReferenceObservation{}, "", errSnapshotResultReferenceInvalid
	}
	body, err := snapshotReferenceBody(ctx, tx, source, row.OrganizationID, row.RunID)
	if err != nil {
		return snapshotReferenceRow{}, snapshotReferenceObservation{}, "", err
	}
	defer clear(body)
	observation, err := snapshotReferencePlan(ctx, runs[0], body, false)
	if err != nil {
		return snapshotReferenceRow{}, snapshotReferenceObservation{}, "", err
	}
	return runs[0], observation, baselineHash(body), nil
}

func snapshotResultReferenceBody(ctx context.Context, tx *gorm.DB, row snapshotResultReferenceRow) ([]byte, error) {
	var rows []struct{ Body []byte }
	projection := "CASE WHEN " + snapshotKeyTextOK(tx, "conclusion_json", 1, snapshotResultReferenceMaxBytes) + " THEN conclusion_json ELSE NULL END AS body"
	err := tx.Table("integrity_run_results").Select(projection).Where("organization_id=? AND run_id=? AND analysis_revision=?", row.OrganizationID, row.RunID, row.Revision).Limit(2).Find(&rows).Error
	if err != nil || ctx.Err() != nil {
		for _, r := range rows {
			clear(r.Body)
		}
		return nil, ErrUnavailable
	}
	if len(rows) != 1 || len(rows[0].Body) == 0 {
		for _, r := range rows {
			clear(r.Body)
		}
		return nil, errSnapshotResultReferenceInvalid
	}
	return rows[0].Body, nil
}
