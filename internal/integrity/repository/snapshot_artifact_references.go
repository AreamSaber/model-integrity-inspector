package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"slices"
	"strconv"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/backupmanifest"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

var (
	errSnapshotReferenceInvalid     = errors.New("SNAPSHOT_ARTIFACT_REFERENCE_INVALID")
	errSnapshotReferenceLimit       = errors.New("SNAPSHOT_ARTIFACT_REFERENCE_LIMIT")
	errSnapshotReferenceUnsupported = errors.New("SNAPSHOT_ARTIFACT_REFERENCE_UNSUPPORTED")
)

const snapshotReferenceLimit = backupmanifest.MaxEntries - 3
const snapshotReferencePageSize = 100

// This is an observation of three historical root sources, NOT the complete
// artifact closure, a verified MAC, availability receipt, or activation grant.
// In particular rule/scoring versions do not contain their parameter hashes.
type snapshotArtifactReference struct {
	organizationID                                        int64
	category, version, sha256, containerVersion, memberID string
}

func (snapshotArtifactReference) String() string               { return "[private snapshot artifact reference]" }
func (v snapshotArtifactReference) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, v.String()) }
func (v snapshotArtifactReference) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (snapshotArtifactReference) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (snapshotArtifactReference) MarshalYAML() (any, error)    { return nil, ErrConfiguration }

type snapshotReferenceClassification uint8

const (
	snapshotReferenceUnverified snapshotReferenceClassification = iota
	snapshotReferenceObserved
	snapshotReferenceLegacyIncomplete
)

type snapshotArtifactReferences struct {
	references       []snapshotArtifactReference
	classification   snapshotReferenceClassification
	observed, legacy [3]int64 // Run, Estimate, Baseline; never filtered by status/TTL.
	inputIncomplete  [3]int64 // Rows whose original input tokenizer identity is missing or not understood.
	sourceSHA256     [3]string
}

func (snapshotArtifactReferences) String() string {
	return "[private snapshot artifact root observations]"
}
func (v snapshotArtifactReferences) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, v.String()) }
func (v snapshotArtifactReferences) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (snapshotArtifactReferences) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (snapshotArtifactReferences) MarshalYAML() (any, error)    { return nil, ErrConfiguration }

type snapshotReferenceSource struct {
	table, body, kind string
	maxBytes          int
}

func snapshotReferenceSources() [3]snapshotReferenceSource {
	return [3]snapshotReferenceSource{
		{"integrity_runs", "config_snapshot", "run", 8 << 20},
		{"integrity_run_estimates", "snapshot_json", "estimate", 8 << 20},
		{"integrity_baselines", "snapshot_json", "baseline", 200 << 10},
	}
}

// Only fixed bounded SQL projections inhabit this transient row. It has no
// source body. Do not format even these private identities and digests.
type snapshotReferenceRow struct {
	OrganizationID, ID, TargetID, RunID                                    int64
	Revision                                                               int64
	Valid, Unsigned                                                        int
	Rule, Template, Scoring, Tokenizer                                     string
	ManifestHash, AnalysisSource, SnapshotHash, ResultHash, ParametersHash string
	Model, Protocol                                                        string
}

func (snapshotReferenceRow) String() string               { return "[private snapshot reference row]" }
func (v snapshotReferenceRow) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, v.String()) }

type snapshotReferenceObservation struct {
	versions                                     domain.BundleVersions
	templateHash, tokenizerHash                  string
	targetModel, targetProtocol, targetParameter string
	members                                      []snapshotReferenceMember
	legacy                                       bool
	inputTokenizers                              []snapshotReferenceInputTokenizer
	inputIncomplete                              bool
}
type snapshotReferenceMember struct{ ID, Version string }

// The actual physical read-only transaction is continuously owned by the
// caller. SQLite native RO must be checked before BeginTx. No Store pool,
// transaction creation/end, callbacks, artifact resolution or mutation occurs.
func (s *Store) snapshotArtifactReferences(ctx context.Context, tx *gorm.DB) (snapshotArtifactReferences, error) {
	return s.snapshotArtifactReferencesLimited(ctx, tx, snapshotReferenceLimit)
}

func (s *Store) snapshotArtifactReferencesLimited(ctx context.Context, tx *gorm.DB, limit int) (snapshotArtifactReferences, error) {
	if ctx == nil || s == nil || tx == nil || tx.Config == nil || tx.Statement == nil || tx.Error != nil || tx.Dialector == nil || tx.Name() != s.driver || limit < 1 || limit > snapshotReferenceLimit {
		return snapshotArtifactReferences{}, ErrConfiguration
	}
	if ctx.Err() != nil {
		return snapshotArtifactReferences{}, ErrUnavailable
	}
	if _, ok := ctx.Deadline(); !ok {
		return snapshotArtifactReferences{}, ErrConfiguration
	}
	if actual, ok := tx.Statement.ConnPool.(*sql.Tx); !ok || actual == nil {
		return snapshotArtifactReferences{}, ErrConfiguration
	}
	read := tx.Session(&gorm.Session{NewDB: true, Context: ctx})
	if err := auditSnapshotTransaction(read, s.driver); err != nil {
		return snapshotArtifactReferences{}, err
	}
	result := snapshotArtifactReferences{classification: snapshotReferenceObserved}
	refs := make(map[snapshotArtifactReference]struct{})
	for index, source := range snapshotReferenceSources() {
		if err := result.scan(ctx, read, source, index, limit, refs); err != nil {
			return snapshotArtifactReferences{}, err
		}
	}
	for ref := range refs {
		result.references = append(result.references, ref)
	}
	slices.SortFunc(result.references, func(a, b snapshotArtifactReference) int {
		return slices.Compare(snapshotReferenceIdentity(a), snapshotReferenceIdentity(b))
	})
	if ctx.Err() != nil {
		return snapshotArtifactReferences{}, ErrUnavailable
	}
	return result, nil
}

// Explicit typed, length-framed JSON avoids ambiguous string concatenation.
// SHA256 is an observation digest, not a signing key or rule-parameter hash.
func snapshotReferenceFrame(h hash.Hash, value any) {
	raw, _ := json.Marshal(value) // closed structs, finite integers/strings only
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(raw)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(raw)
}
func snapshotReferenceIdentity(v snapshotArtifactReference) []string {
	return []string{strconv.FormatInt(v.organizationID, 10), v.category, v.version, v.sha256, v.containerVersion, v.memberID}
}

func (v *snapshotArtifactReferences) scan(ctx context.Context, tx *gorm.DB, source snapshotReferenceSource, index, limit int, refs map[snapshotArtifactReference]struct{}) error {
	var total int64
	if err := tx.Table(source.table).Count(&total).Error; err != nil {
		return ErrUnavailable
	}
	if total < 0 {
		return errSnapshotReferenceInvalid
	}
	var duplicate bool
	if err := tx.Raw("SELECT EXISTS(SELECT 1 FROM " + source.table + " GROUP BY id HAVING COUNT(*)>1)").Scan(&duplicate).Error; err != nil {
		return ErrUnavailable
	}
	if duplicate {
		return errSnapshotReferenceInvalid
	}
	h := sha256.New()
	snapshotReferenceFrame(h, struct{ Domain, Source string }{"mii.snapshot.artifact-root-observations.v1", source.kind})
	var org, id, seen int64
	for {
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		var rows []snapshotReferenceRow
		if err := tx.Table(source.table+" r").Select(snapshotReferenceColumns(tx, source)).Where("r.organization_id>? OR (r.organization_id=? AND r.id>?)", org, org, id).Order("r.organization_id,r.id").Limit(snapshotReferencePageSize).Find(&rows).Error; err != nil {
			return ErrUnavailable
		}
		for _, row := range rows {
			if ctx.Err() != nil {
				return ErrUnavailable
			}
			if row.Valid != 1 || row.OrganizationID <= 0 || row.ID <= 0 || row.OrganizationID < org || (row.OrganizationID == org && row.ID <= id) || seen >= total {
				return errSnapshotReferenceInvalid
			}
			body, err := snapshotReferenceBody(ctx, tx, source, row.OrganizationID, row.ID)
			if err != nil {
				return err
			}
			bodyHash := baselineHash(body)
			observation, err := snapshotReferenceRead(ctx, tx, source, row, body)
			clear(body)
			if err != nil {
				return err
			}
			if err := snapshotReferenceAccumulate(refs, row.OrganizationID, observation, limit); err != nil {
				return err
			}
			if observation.legacy {
				v.classification = snapshotReferenceLegacyIncomplete
				v.legacy[index]++
			}
			if observation.inputIncomplete {
				v.classification = snapshotReferenceLegacyIncomplete
				v.inputIncomplete[index]++
			}
			// Preserve original columns and exact body digest, including unknown
			// legacy bodies. Never canonicalize history into today's representation.
			snapshotReferenceFrame(h, struct {
				Kind       string
				Row        snapshotReferenceRow
				BodySHA256 string
				Legacy     bool
			}{source.kind, row, bodyHash, observation.legacy})
			org, id = row.OrganizationID, row.ID
			seen++
		}
		if len(rows) < snapshotReferencePageSize {
			break
		}
	}
	// Query the same physical view after the last body/decoder has completed.
	// A rollback after a successful final SELECT must not yield a successful
	// observation. Commit/publication after return still belongs to the caller.
	var finalTotal int64
	if err := tx.Table(source.table).Count(&finalTotal).Error; err != nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	// Closes NULL/nonpositive-key gaps and duplicate keys crossing page 100.
	if seen != total || finalTotal != total {
		return errSnapshotReferenceInvalid
	}
	snapshotReferenceFrame(h, struct{ Rows, Legacy int64 }{seen, v.legacy[index]})
	v.observed[index], v.sourceSHA256[index] = seen, hex.EncodeToString(h.Sum(nil))
	return nil
}

func snapshotReferenceAccumulate(refs map[snapshotArtifactReference]struct{}, org int64, observation snapshotReferenceObservation, limit int) error {
	add := func(ref snapshotArtifactReference) error {
		if _, found := refs[ref]; !found && len(refs) >= limit {
			return errSnapshotReferenceLimit
		}
		refs[ref] = struct{}{}
		return nil
	}
	versions := observation.versions
	for _, ref := range []snapshotArtifactReference{
		{organizationID: org, category: "rule", version: versions.Rule},
		{organizationID: org, category: "template", version: versions.Template, sha256: observation.templateHash},
		{organizationID: org, category: "scoring", version: versions.Scoring},
		{organizationID: org, category: "tokenizer", version: versions.Tokenizer, sha256: observation.tokenizerHash},
	} {
		if ref.version != "" {
			if err := add(ref); err != nil {
				return err
			}
		}
	}
	for _, member := range observation.members {
		if err := add(snapshotArtifactReference{org, "template_member", member.Version, observation.templateHash, versions.Template, member.ID}); err != nil {
			return err
		}
	}
	for _, input := range observation.inputTokenizers {
		if err := add(snapshotArtifactReference{org, "input_tokenizer_implementation", input.implementation, input.configurationHash, input.configurationVersion, input.encoding}); err != nil {
			return err
		}
	}
	return nil
}

func snapshotReferenceColumns(tx *gorm.DB, source snapshotReferenceSource) string {
	positive := func(field string) string { return snapshotKeyIntegerOK(tx, field, 1, 9223372036854775807) }
	textOK := func(field string, minBytes, maxBytes int) string {
		return snapshotKeyTextOK(tx, "r."+field, minBytes, maxBytes)
	}
	text := func(field, alias string, maxBytes int) string {
		return snapshotReportText(tx, "r."+field, alias, maxBytes, false)
	}
	integer := func(field, alias string, maximum int64) string {
		return snapshotReportInteger(tx, "r."+field, alias, maximum)
	}
	valid := positive("r.id") + " AND " + positive("r.organization_id") + " AND (SELECT COUNT(*) FROM organizations o WHERE o.id=r.organization_id)=1 AND " + textOK(source.body, 1, source.maxBytes)
	columns := integer("organization_id", "organization_id", 9223372036854775807) + "," + integer("id", "id", 9223372036854775807)
	if source.kind == "baseline" {
		// Foundation INTEGER is native int64 on SQLite; PostgreSQL already
		// enforces its own int32 column range. Never impose PG's range on
		// legitimate retained SQLite revisions or narrow them while scanning.
		valid += " AND " + positive("r.run_id") + " AND " + positive("r.analysis_revision") + " AND (SELECT COUNT(*) FROM integrity_runs p WHERE p.organization_id=r.organization_id AND p.id=r.run_id)=1 AND (SELECT COUNT(*) FROM integrity_run_results q WHERE q.organization_id=r.organization_id AND q.run_id=r.run_id AND q.analysis_revision=r.analysis_revision)=1"
		valid += " AND ((r.approval_key_version IS NULL AND r.approval_mac IS NULL) OR (" + textOK("approval_key_version", 1, 64) + " AND " + textOK("approval_mac", 64, 64) + "))"
		columns += "," + integer("run_id", "run_id", 9223372036854775807) + "," + integer("analysis_revision", "revision", 9223372036854775807) + ",CASE WHEN r.approval_key_version IS NULL AND r.approval_mac IS NULL THEN 1 ELSE 0 END AS unsigned"
		for _, field := range []struct {
			column, alias string
			limit         int
		}{{"source_manifest_hash", "manifest_hash", 64}, {"source_result_hash", "result_hash", 64}, {"parameters_hash", "parameters_hash", 64}, {"snapshot_hash", "snapshot_hash", 64}, {"model", "model", snapshotReferenceModelMaxBytes}, {"protocol", "protocol", 32}} {
			valid += " AND " + textOK(field.column, 0, field.limit)
			columns += "," + text(field.column, field.alias, field.limit)
		}
	} else {
		valid += " AND " + positive("r.target_id") + " AND (SELECT COUNT(*) FROM integrity_targets t WHERE t.organization_id=r.organization_id AND t.id=r.target_id)=1 AND " + textOK("manifest_hash", 0, 64)
		columns += "," + integer("target_id", "target_id", 9223372036854775807) + "," + text("manifest_hash", "manifest_hash", 64)
		if source.kind == "run" {
			valid += " AND " + textOK("analysis_source_version", 1, 64)
			columns += "," + text("analysis_source_version", "analysis_source", 64)
			for _, field := range []struct{ column, alias string }{{"rule_bundle_version", "rule"}, {"template_bundle_version", "template"}, {"scoring_version", "scoring"}, {"tokenizer_bundle_version", "tokenizer"}} {
				valid += " AND " + textOK(field.column, 1, 128)
				columns += "," + text(field.column, field.alias, 128)
			}
		}
	}
	return columns + ",CASE WHEN " + valid + " THEN 1 ELSE 0 END AS valid"
}

func snapshotReferenceBody(ctx context.Context, tx *gorm.DB, source snapshotReferenceSource, org, id int64) ([]byte, error) {
	var rows []struct{ Body []byte }
	projection := "CASE WHEN " + snapshotKeyTextOK(tx, source.body, 1, source.maxBytes) + " THEN " + source.body + " ELSE NULL END AS body"
	if err := tx.Table(source.table).Select(projection).Where("organization_id=? AND id=?", org, id).Limit(2).Find(&rows).Error; err != nil {
		for _, row := range rows {
			clear(row.Body)
		}
		return nil, ErrUnavailable
	}
	if ctx.Err() != nil {
		for _, row := range rows {
			clear(row.Body)
		}
		return nil, ErrUnavailable
	}
	if len(rows) != 1 || len(rows[0].Body) == 0 {
		for _, row := range rows {
			clear(row.Body)
		}
		return nil, errSnapshotReferenceInvalid
	}
	return rows[0].Body, nil
}

func snapshotReferenceRead(ctx context.Context, tx *gorm.DB, source snapshotReferenceSource, row snapshotReferenceRow, raw []byte) (snapshotReferenceObservation, error) {
	if source.kind == "baseline" {
		return snapshotReferenceBaseline(ctx, tx, row, raw)
	}
	return snapshotReferencePlan(ctx, row, raw, source.kind == "estimate")
}
