package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strconv"

	"gorm.io/gorm"
)

var (
	errSnapshotKeyInvalid     = errors.New("SNAPSHOT_KEY_INVALID")
	errSnapshotKeyLimit       = errors.New("SNAPSHOT_KEY_LIMIT")
	errSnapshotKeyUnsupported = errors.New("SNAPSHOT_KEY_UNSUPPORTED")
)

const snapshotKeyMaxVersions = 64 // backupmanifest's complete root-key union limit
const snapshotKeyPageSize = 100

type snapshotKeyClassification uint8

const (
	snapshotKeyUnverified snapshotKeyClassification = iota
	snapshotKeyCurrentReferences
	snapshotKeyLegacyIncomplete
)

// An owned observation of required root versions, NOT a key-availability,
// authentication, decryption, complete backup or activation capability. The
// archive sealer's explicit version must be unioned by the final coordinator.
type snapshotKeyInventory struct {
	versions                                                        []string
	classification                                                  snapshotKeyClassification
	observed                                                        [9]int64
	legacyUnsignedBaselines, legacyUnverifiedRuns, destroyedSecrets int64
}

func (snapshotKeyInventory) String() string               { return "[private snapshot key inventory]" }
func (v snapshotKeyInventory) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, v.String()) }
func (v snapshotKeyInventory) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (snapshotKeyInventory) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (snapshotKeyInventory) MarshalYAML() (any, error)    { return nil, ErrConfiguration }

// The caller continuously owns the actual read-only transaction and must have
// checked SQLite native physical RO before BeginTx. query_only is supplemental.
// No live Store pool, current organization/TTL filter, locks, writes or Tx end.
func (s *Store) snapshotKeyInventory(ctx context.Context, tx *gorm.DB) (snapshotKeyInventory, error) {
	return s.snapshotKeyInventoryLimited(ctx, tx, snapshotKeyMaxVersions)
}

func (s *Store) snapshotKeyInventoryLimited(ctx context.Context, tx *gorm.DB, limit int) (snapshotKeyInventory, error) {
	if ctx == nil || s == nil || tx == nil || tx.Config == nil || tx.Error != nil || tx.Statement == nil || tx.Dialector == nil || tx.Name() != s.driver || limit < 1 || limit > snapshotKeyMaxVersions {
		return snapshotKeyInventory{}, ErrConfiguration
	}
	if ctx.Err() != nil {
		return snapshotKeyInventory{}, ErrUnavailable
	}
	if _, ok := ctx.Deadline(); !ok {
		return snapshotKeyInventory{}, ErrConfiguration
	}
	if actual, ok := tx.Statement.ConnPool.(*sql.Tx); !ok || actual == nil {
		return snapshotKeyInventory{}, ErrConfiguration
	}
	read := tx.Session(&gorm.Session{NewDB: true, Context: ctx})
	if err := auditSnapshotTransaction(read, s.driver); err != nil {
		return snapshotKeyInventory{}, err
	}
	result := snapshotKeyInventory{classification: snapshotKeyCurrentReferences, versions: make([]string, 0, limit)}
	for index, source := range snapshotKeySources() {
		if err := result.scan(ctx, read, source, index, limit); err != nil {
			return snapshotKeyInventory{}, err
		}
	}
	// These foundation carriers have no implemented versioned codec/closure.
	// Do not guess their key from an active version, or omit retained bytes.
	var unsupported bool
	if err := read.Raw(`SELECT EXISTS(SELECT 1 FROM integrity_audit_segments)
 OR EXISTS(SELECT 1 FROM integrity_sample_attempts WHERE response_content_enc IS NOT NULL AND length(response_content_enc)>0)
 OR EXISTS(SELECT 1 FROM integrity_gateway_evidence WHERE signature IS NULL OR length(signature)>0)`).Scan(&unsupported).Error; err != nil {
		return snapshotKeyInventory{}, ErrUnavailable
	}
	if ctx.Err() != nil {
		return snapshotKeyInventory{}, ErrUnavailable
	}
	if unsupported {
		return snapshotKeyInventory{}, errSnapshotKeyUnsupported
	}
	slices.Sort(result.versions)
	return result, nil
}

type snapshotKeySource struct{ table, id, kind string }

func snapshotKeySources() []snapshotKeySource {
	return []snapshotKeySource{
		{"integrity_secrets", "id", "secret"},
		{"integrity_audit_logs", "id", "audit"},
		{"integrity_audit_chain_heads", "organization_id", "head"},
		{"integrity_baselines", "id", "baseline"},
		{"integrity_response_evidence", "attempt_id", "response"},
		{"integrity_display_evidence", "attempt_id", "display"},
		{"integrity_attempt_derived", "attempt_id", "derived"},
		{"integrity_runs", "id", "run"},
		{"integrity_run_estimates", "id", "estimate"},
	}
}

type snapshotKeyRow struct {
	OrganizationID, ID                                       int64
	Valid, Mode                                              int
	KeyVersion, PayloadVersion, ManifestHash, AnalysisSource string
}

func (v *snapshotKeyInventory) scan(ctx context.Context, tx *gorm.DB, source snapshotKeySource, index, limit int) error {
	var total int64
	if err := tx.Table(source.table).Count(&total).Error; err != nil {
		return ErrUnavailable
	}
	var org, id, seen int64
	for {
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		var rows []snapshotKeyRow
		if err := tx.Table(source.table+" k").Select(snapshotKeyColumns(tx, source)).
			Where("k.organization_id>? OR (k.organization_id=? AND k."+source.id+">?)", org, org, id).
			Order("k.organization_id,k." + source.id).Limit(snapshotKeyPageSize).Find(&rows).Error; err != nil {
			return ErrUnavailable
		}
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		for _, row := range rows {
			if row.Valid != 1 || row.OrganizationID <= 0 || row.ID <= 0 || row.OrganizationID < org || (row.OrganizationID == org && row.ID <= id) || seen >= total {
				return errSnapshotKeyInvalid
			}
			key, mode, err := snapshotKeyVerify(ctx, tx, source, row)
			if err != nil {
				return err
			}
			switch mode {
			case 1:
				if !responseEvidenceVersion.MatchString(key) {
					return errSnapshotKeyInvalid
				}
				if !slices.Contains(v.versions, key) {
					if len(v.versions) >= limit {
						return errSnapshotKeyLimit
					}
					v.versions = append(v.versions, key)
				}
			case 2:
				v.classification = snapshotKeyLegacyIncomplete
				if source.kind == "baseline" {
					v.legacyUnsignedBaselines++
				} else {
					v.legacyUnverifiedRuns++
				}
			case 3:
				v.destroyedSecrets++
			case 4: // Explicit unavailable display record, no envelope or key.
			case 5: // Empty audit chain with an explicitly empty key label.
			default:
				return errSnapshotKeyInvalid
			}
			org, id = row.OrganizationID, row.ID
			seen++
		}
		if len(rows) < snapshotKeyPageSize {
			break
		}
	}
	// Counts close keyset gaps, including NULL/nonpositive IDs, duplicate keys
	// split exactly at a page boundary, and offline missing constraints. No cap
	// on historical row count; only at most 64 unique key labels are retained.
	if seen != total {
		return errSnapshotKeyInvalid
	}
	v.observed[index] = seen
	return nil
}

// SQL identifiers below come only from the closed source literals above.
func snapshotKeyTextOK(tx *gorm.DB, field string, minBytes, maxBytes int) string {
	typed, length := field+" IS NOT NULL", "octet_length("+field+")"
	if tx.Name() == "sqlite" {
		typed = "typeof(" + field + ")='text'"
		length = "length(CAST(" + field + " AS BLOB))"
	}
	return "(" + typed + " AND " + length + " BETWEEN " + strconv.Itoa(minBytes) + " AND " + strconv.Itoa(maxBytes) + ")"
}
func snapshotKeyBlobOK(tx *gorm.DB, field string, minBytes, maxBytes int) string {
	typed, length := field+" IS NOT NULL", "octet_length("+field+")"
	if tx.Name() == "sqlite" {
		typed = "typeof(" + field + ")='blob'"
		length = "length(" + field + ")"
	}
	return "(" + typed + " AND " + length + " BETWEEN " + strconv.Itoa(minBytes) + " AND " + strconv.Itoa(maxBytes) + ")"
}
func snapshotKeyIntegerOK(tx *gorm.DB, field string, minValue, maxValue int64) string {
	check := field + " BETWEEN " + strconv.FormatInt(minValue, 10) + " AND " + strconv.FormatInt(maxValue, 10)
	if tx.Name() == "sqlite" {
		check = "typeof(" + field + ")='integer' AND " + check
	}
	return "(" + check + ")"
}
func snapshotKeyColumns(tx *gorm.DB, source snapshotKeySource) string {
	positive := func(field string) string { return snapshotKeyIntegerOK(tx, field, 1, 9223372036854775807) }
	text := func(field string, minBytes, maxBytes int) string {
		return snapshotKeyTextOK(tx, "k."+field, minBytes, maxBytes)
	}
	blob := func(field string, minBytes, maxBytes int) string {
		return snapshotKeyBlobOK(tx, "k."+field, minBytes, maxBytes)
	}
	number := func(field string, minValue, maxValue int64) string {
		return snapshotKeyIntegerOK(tx, "k."+field, minValue, maxValue)
	}
	valid := positive("k.organization_id") + " AND " + positive("k."+source.id) + " AND (SELECT COUNT(*) FROM organizations o WHERE o.id=k.organization_id)=1"
	keyField := "key_version"
	mode := "1"
	extra := ""
	switch source.kind {
	case "secret":
		full := blob("encrypted_data_key", 1, 1024) + " AND " + blob("nonce", 12, 12) + " AND " + blob("ciphertext", 16, 65552) + " AND " + text("fingerprint", 64, 64) + " AND " + text("last_four", 0, 16)
		erased := blob("encrypted_data_key", 0, 0) + " AND " + blob("nonce", 0, 0) + " AND " + blob("ciphertext", 0, 0) + " AND " + text("fingerprint", 0, 0) + " AND " + text("last_four", 0, 0) + " AND k.deleted_at IS NOT NULL"
		valid += " AND " + number("secret_version", 1, 2147483647) + " AND " + text("payload_key_version", 1, 64) + " AND ((" + full + ") OR (" + erased + "))"
		mode = "CASE WHEN " + erased + " THEN 3 ELSE 1 END"
		extra = "," + snapshotReportText(tx, "k.payload_key_version", "payload_version", 64, false)
	case "baseline":
		keyField = "approval_key_version"
		valid += " AND ((k.approval_key_version IS NULL AND k.approval_mac IS NULL) OR (" + text("approval_key_version", 1, 64) + " AND " + text("approval_mac", 64, 64) + "))"
		mode = "CASE WHEN k.approval_key_version IS NULL AND k.approval_mac IS NULL THEN 2 ELSE 1 END"
	case "head":
		valid += " AND " + number("event_count", 0, 9223372036854775807) + " AND " + text("key_version", 0, 64) +
			" AND ((k.event_count=0 AND " + text("event_hash", 0, 0) + " AND NOT EXISTS(SELECT 1 FROM integrity_audit_logs e WHERE e.organization_id=k.organization_id)) OR (k.event_count>0 AND " + text("event_hash", 64, 64) + " AND " + text("key_version", 1, 64) + "))"
		mode = "CASE WHEN k.key_version='' THEN 5 ELSE 1 END"
	case "response", "display", "derived":
		valid += " AND " + positive("k.run_id") + " AND " + positive("k.logical_sample_id") + " AND " + text("request_hash", 64, 64) + `
 AND (SELECT COUNT(*) FROM integrity_runs r WHERE r.organization_id=k.organization_id AND r.id=k.run_id)=1
 AND (SELECT COUNT(*) FROM integrity_logical_samples s WHERE s.organization_id=k.organization_id AND s.run_id=k.run_id AND s.id=k.logical_sample_id)=1
 AND (SELECT COUNT(*) FROM integrity_sample_attempts a WHERE a.organization_id=k.organization_id AND a.logical_sample_id=k.logical_sample_id AND a.id=k.attempt_id AND a.request_hash=k.request_hash AND (a.run_id=k.run_id OR a.run_id IS NULL))=1`
		switch source.kind {
		case "derived":
			valid += " AND " + text("version", 1, 64) + " AND k.version='mii.derived-s1.v1' AND " + blob("payload", 1, 32768) + " AND " + blob("mac", 32, 32)
		case "response":
			valid += " AND " + blob("nonce", 12, 12) + " AND " + blob("ciphertext", 17, 1048592) + " AND " + number("plaintext_bytes", 1, 1048576) + " AND length(k.ciphertext)=k.plaintext_bytes+16 AND " + text("content_hash", 64, 64)
		case "display":
			captured := "k.state='captured' AND " + text("source_hash", 64, 64) + " AND " + number("version", 1, 1) + " AND " + text("key_version", 1, 64) + " AND " + blob("nonce", 12, 12) + " AND " + blob("ciphertext", 17, 4194320) + " AND " + number("plaintext_bytes", 1, 4194304) + " AND length(k.ciphertext)=k.plaintext_bytes+16 AND " + text("payload_hash", 64, 64) + " AND " + positive("k.captured_at_micros") + " AND " + positive("k.expires_at_micros") + " AND k.expires_at_micros>k.captured_at_micros"
			unavailable := "k.state IN ('unavailable_redaction_policy','unavailable_safety_limit','unavailable_source_invalid','unavailable_cancelled','unavailable_capture','unavailable_seal') AND " + text("source_hash", 0, 0) + " AND " + number("version", 0, 0) + " AND " + text("key_version", 0, 0) + " AND k.nonce IS NULL AND k.ciphertext IS NULL AND " + number("plaintext_bytes", 0, 0) + " AND " + text("payload_hash", 0, 0) + " AND " + number("captured_at_micros", 0, 0) + " AND " + number("expires_at_micros", 0, 0)
			valid += " AND " + text("policy", 1, 64) + " AND k.policy='display-redaction-v1' AND " + text("state", 1, 64) + " AND ((" + captured + ") OR (" + unavailable + "))"
			mode = "CASE WHEN k.state='captured' THEN 1 ELSE 4 END"
		}
	case "run", "estimate":
		field := "config_snapshot"
		if source.kind == "estimate" {
			field = "snapshot_json"
		}
		valid += " AND " + text(field, 1, 8<<20) + " AND " + text("manifest_hash", 0, 64)
		keyField = "manifest_hash" // the version is read only from the original body
		extra = "," + snapshotReportText(tx, "k.manifest_hash", "manifest_hash", 64, false)
		if source.kind == "run" {
			valid += " AND " + text("analysis_source_version", 1, 64)
			extra += "," + snapshotReportText(tx, "k.analysis_source_version", "analysis_source", 64, false)
		}
	}
	if source.kind != "run" && source.kind != "estimate" && source.kind != "baseline" && source.kind != "display" && source.kind != "head" {
		valid += " AND " + text(keyField, 1, 64)
	}
	return snapshotReportInteger(tx, "k.organization_id", "organization_id", 9223372036854775807) + "," + snapshotReportInteger(tx, "k."+source.id, "id", 9223372036854775807) +
		",CASE WHEN " + valid + " THEN 1 ELSE 0 END AS valid," + mode + " AS mode," + snapshotReportText(tx, "k."+keyField, "key_version", 64, false) + extra
}

func snapshotKeyVerify(ctx context.Context, tx *gorm.DB, source snapshotKeySource, row snapshotKeyRow) (string, int, error) {
	if ctx.Err() != nil {
		return "", 0, ErrUnavailable
	}
	if source.kind == "secret" && !responseEvidenceVersion.MatchString(row.PayloadVersion) {
		return "", 0, errSnapshotKeyInvalid
	}
	if source.kind != "run" && source.kind != "estimate" && (source.kind != "secret" || row.Mode == 3) {
		return row.KeyVersion, row.Mode, nil
	}
	field := "config_snapshot"
	maxBytes := 8 << 20
	if source.kind == "estimate" {
		field = "snapshot_json"
	}
	if source.kind == "secret" {
		field = "encrypted_data_key"
		maxBytes = 1024
	}
	condition := snapshotKeyTextOK(tx, field, 1, maxBytes)
	if source.kind == "secret" {
		condition = snapshotKeyBlobOK(tx, field, 1, maxBytes)
	}
	var bodies []struct{ Body []byte }
	projection := "CASE WHEN " + condition + " THEN " + field + " ELSE NULL END AS body"
	if err := tx.Table(source.table).Select(projection).Where("organization_id=? AND "+source.id+"=?", row.OrganizationID, row.ID).Limit(2).Find(&bodies).Error; err != nil {
		return "", 0, ErrUnavailable
	}
	if ctx.Err() != nil {
		return "", 0, ErrUnavailable
	}
	if len(bodies) != 1 || len(bodies[0].Body) == 0 {
		return "", 0, errSnapshotKeyInvalid
	}
	defer clear(bodies[0].Body)
	if source.kind == "secret" {
		if err := snapshotKeyEnvelope(ctx, bodies[0].Body, row.KeyVersion); err != nil {
			return "", 0, err
		}
		return row.KeyVersion, 1, nil
	}
	return snapshotKeyManifest(ctx, bodies[0].Body, row, source.kind == "estimate")
}
