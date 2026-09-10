package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

func snapshotKeyTestUnconstrained(t *testing.T, s *Store, table string) string {
	t.Helper()
	original := "snapshot_key_original"
	for _, sql := range []string{"ALTER TABLE " + table + " RENAME TO " + original, "CREATE TABLE " + table + " AS SELECT * FROM " + original} {
		if err := s.db.Exec(sql).Error; err != nil {
			t.Fatal("test-owned offline copy", err)
		}
	}
	t.Cleanup(func() {
		for _, sql := range []string{"DROP TABLE " + table, "ALTER TABLE " + original + " RENAME TO " + table} {
			if err := s.db.Exec(sql).Error; err != nil {
				t.Error("restore exact test-owned table", err)
			}
		}
	})
	return original
}

func TestSnapshotKeyInventorySQLCorruptionNeverPartial(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, _ := snapshotKeyTestFixture(t, s)
		for _, source := range snapshotKeySources() {
			t.Run(source.kind, func(t *testing.T) {
				original := snapshotKeyTestUnconstrained(t, s, source.table)
				var faults []map[string]any
				faults = append(faults, map[string]any{"organization_id": nil}, map[string]any{"organization_id": int64(-1)}, map[string]any{"organization_id": tenant.orgID + 1}, map[string]any{source.id: nil}, map[string]any{source.id: int64(0)})
				keyField := "key_version"
				if source.kind == "baseline" {
					keyField = "approval_key_version"
				}
				if source.kind != "run" && source.kind != "estimate" {
					faults = append(faults, map[string]any{keyField: nil}, map[string]any{keyField: strings.Repeat("a", 65)}, map[string]any{keyField: "bad\nversion"})
				}
				switch source.kind {
				case "secret":
					faults = append(faults, map[string]any{"encrypted_data_key": nil}, map[string]any{"encrypted_data_key": bytes.Repeat([]byte{1}, 1025)}, map[string]any{"encrypted_data_key": snapshotKeyTestWrap(t, "other")}, map[string]any{"nonce": []byte{}}, map[string]any{"ciphertext": bytes.Repeat([]byte{1}, 65553)}, map[string]any{"deleted_at": time.Now(), "ciphertext": []byte{}}, map[string]any{"payload_key_version": nil})
				case "baseline":
					faults = append(faults, map[string]any{"approval_mac": nil}, map[string]any{"approval_mac": ""})
				case "response":
					faults = append(faults, map[string]any{"nonce": nil}, map[string]any{"ciphertext": nil}, map[string]any{"plaintext_bytes": -1}, map[string]any{"run_id": int64(999)}, map[string]any{"request_hash": strings.Repeat("f", 64)})
				case "display":
					faults = append(faults, map[string]any{"policy": "unknown"}, map[string]any{"state": "unknown"}, map[string]any{"state": DisplayUnavailableSeal}, map[string]any{"state": DisplayCaptured}, map[string]any{"plaintext_bytes": -1}, map[string]any{"run_id": int64(999)})
				case "derived":
					faults = append(faults, map[string]any{"payload": bytes.Repeat([]byte{1}, 32769)}, map[string]any{"mac": nil}, map[string]any{"version": "unknown"}, map[string]any{"logical_sample_id": int64(999)})
				case "run", "estimate":
					body := "config_snapshot"
					if source.kind == "estimate" {
						body = "snapshot_json"
					}
					faults = append(faults, map[string]any{body: nil}, map[string]any{body: strings.Repeat("a", 8<<20+1)}, map[string]any{body: "{}"}, map[string]any{body: `{"plan":null}`}, map[string]any{"manifest_hash": strings.Repeat("0", 64)})
				}
				for i, values := range faults {
					if err := s.db.Table(source.table).Where("1=1").Updates(values).Error; err != nil {
						t.Fatal("corrupt unconstrained source", i, err)
					}
					snapshotKeyTestObserve(t, s, cfg, errSnapshotKeyInvalid)
					for _, sql := range []string{"DELETE FROM " + source.table, "INSERT INTO " + source.table + " SELECT * FROM " + original} {
						if err := s.db.Exec(sql).Error; err != nil {
							t.Fatal(err)
						}
					}
				}
				// Duplicates must not be merged by DISTINCT or skipped by keyset.
				if err := s.db.Exec("INSERT INTO " + source.table + " SELECT * FROM " + original).Error; err != nil {
					t.Fatal(err)
				}
				snapshotKeyTestObserve(t, s, cfg, errSnapshotKeyInvalid)
			})
		}
	})
}

func TestSnapshotKeyInventoryLegacyUnsignedBaselineAndUnsupported(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, run := snapshotKeyTestFixture(t, s)
		snapshotKeyTestUpdate(t, s, "integrity_baselines", map[string]any{"approval_key_version": nil, "approval_mac": nil})
		got := snapshotKeyTestObserve(t, s, cfg, nil)
		if got.classification != snapshotKeyLegacyIncomplete || got.legacyUnsignedBaselines != 3 || slicesHavePrefix(got.versions, "old-baseline") {
			t.Fatal("legal migration12 unsigned history was fabricated or discarded")
		}
		stamp := time.Now().UTC().Truncate(time.Microsecond)
		snapshotJobTestInsert(t, s, "integrity_gateway_evidence", map[string]any{"id": int64(40), "organization_id": tenant.orgID, "run_id": run.ID, "inbound_hash": "a", "outbound_hash": "b", "changes_json": "{}", "signature": "legacy-opaque-signature", "created_at": stamp})
		snapshotKeyTestObserve(t, s, cfg, errSnapshotKeyUnsupported)
		if err := s.db.Exec("DELETE FROM integrity_gateway_evidence WHERE id=40").Error; err != nil {
			t.Fatal(err)
		}
		snapshotJobTestInsert(t, s, "integrity_audit_segments", map[string]any{"id": int64(41), "organization_id": tenant.orgID, "first_sequence": 1, "last_sequence": 1, "first_hash": "a", "last_hash": "b", "event_count": 1, "first_event_at": stamp, "last_event_at": stamp, "sealed_at": stamp, "canonicalization_version": "legacy", "key_version": "unique-segment-old"})
		snapshotKeyTestObserve(t, s, cfg, errSnapshotKeyUnsupported)
		if err := s.db.Exec("DELETE FROM integrity_audit_segments WHERE id=41").Error; err != nil {
			t.Fatal(err)
		}
		if err := s.db.Table("integrity_sample_attempts").Where("run_id=?", run.ID).Update("response_content_enc", []byte("legacy-opaque-encrypted-content")).Error; err != nil {
			t.Fatal(err)
		}
		snapshotKeyTestObserve(t, s, cfg, errSnapshotKeyUnsupported)
	})
}

func slicesHavePrefix(values []string, prefix string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func TestSnapshotKeyInventoryDuplicatePageBoundaryAndLateCancellation(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		requireMigrate(t, s)
		ids := snapshotJobTestOrganizations(t, s, 101)
		for _, id := range ids {
			if err := s.db.Create(&auditChainHead{OrganizationID: id, KeyVersion: "retained-key", UpdatedAt: time.Now().UTC()}).Error; err != nil {
				t.Fatal(err)
			}
		}
		t.Run("duplicate_boundary", func(t *testing.T) {
			snapshotKeyTestUnconstrained(t, s, "integrity_audit_chain_heads")
			if err := s.db.Exec("INSERT INTO integrity_audit_chain_heads SELECT * FROM integrity_audit_chain_heads WHERE organization_id=100").Error; err != nil {
				t.Fatal(err)
			}
			snapshotKeyTestObserve(t, s, cfg, errSnapshotKeyInvalid)
		})
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		canceled, cancel := context.WithCancel(ctx)
		defer cancel()
		fired := false
		if err := tx.Callback().Query().After("gorm:query").Register("snapshot_key_cancel_page", func(q *gorm.DB) {
			if rows, ok := q.Statement.Dest.(*[]snapshotKeyRow); ok && strings.Contains(q.Statement.SQL.String(), "integrity_audit_chain_heads") && len(*rows) == 1 {
				fired = true
				cancel()
			}
		}); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Callback().Query().Remove("snapshot_key_cancel_page") }()
		got, err := s.snapshotKeyInventory(canceled, tx)
		if !fired || !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(got, snapshotKeyInventory{}) {
			t.Fatal("late page cancellation returned earlier keys", err)
		}
	})
}

func TestSnapshotKeyInventoryStrictNestedJSONAndHash(t *testing.T) {
	ctx := t.Context()
	manifest, hash := snapshotKeyTestManifest(t, 123, "old-key")
	row := snapshotKeyRow{OrganizationID: 123, ManifestHash: hash, AnalysisSource: AnalysisSourceLegacyV1}
	good := snapshotKeyTestSnapshot(t, manifest, hash)
	if key, mode, err := snapshotKeyManifest(ctx, []byte(good), row, false); err != nil || key != "old-key" || mode != 1 {
		t.Fatal("valid nested metadata", err)
	}
	for _, raw := range []string{
		`{"plan":{},"plan":{}}`, `{"plan":{},"Plan":{}}`, `{"Plan":{}}`, `{"plan":{"Manifest":{}}}`, `{"plan":{"manifest":null}}`,
		`{"plan":{"manifest_hash":"a","manifest_hash":"b"}}`, `{"outer":{"key_version":"a","Key_Version":"b"}}`,
		`{"plan":{}} {}`, `null`, `[]`, strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34),
		strings.Replace(good, "old-key", "bad-key", 1), strings.Replace(good, `"manifest_hash":`, `"Manifest_Hash":`, 1),
	} {
		if key, mode, err := snapshotKeyManifest(ctx, []byte(raw), row, false); err == nil || key != "" || mode != 0 {
			t.Fatal("ambiguous/hash-unbound JSON accepted")
		}
	}
	for _, mutate := range []func(map[string]json.RawMessage){
		func(m map[string]json.RawMessage) { m["key_version"] = json.RawMessage(`null`) },
		func(m map[string]json.RawMessage) {
			delete(m, "key_version")
			m["Key_Version"] = json.RawMessage(`"hidden"`)
		},
		func(m map[string]json.RawMessage) { m["unknown"] = json.RawMessage(`"hidden"`) },
		func(m map[string]json.RawMessage) { m["options"] = json.RawMessage(`{"organization_id":"124"}`) },
		func(m map[string]json.RawMessage) { m["options"] = json.RawMessage(`{"Organization_ID":"123"}`) },
		func(m map[string]json.RawMessage) { m["integrity"] = json.RawMessage(`"not-an-authentication-tag"`) },
	} {
		var m map[string]json.RawMessage
		if json.Unmarshal(manifest, &m) != nil {
			t.Fatal("decode fixture")
		}
		mutate(m)
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(raw)
		changed := row
		changed.ManifestHash = hex.EncodeToString(digest[:])
		if key, mode, err := snapshotKeyManifest(ctx, []byte(snapshotKeyTestSnapshot(t, raw, changed.ManifestHash)), changed, false); !errors.Is(err, errSnapshotKeyInvalid) || key != "" || mode != 0 {
			t.Fatal("rehashed invalid metadata accepted", err)
		}
	}
	unknown := bytes.Replace(manifest, []byte("1.0.0-dev.1"), []byte("9.0.0-history"), 1)
	digest := sha256.Sum256(unknown)
	changed := row
	changed.ManifestHash = hex.EncodeToString(digest[:])
	if key, mode, err := snapshotKeyManifest(ctx, []byte(snapshotKeyTestSnapshot(t, unknown, changed.ManifestHash)), changed, false); !errors.Is(err, errSnapshotKeyUnsupported) || key != "" || mode != 0 {
		t.Fatal("unknown generator defaulted to current")
	}
	if key, mode, err := snapshotKeyManifest(ctx, []byte(`{"legacy_fixture":true}`), row, true); !errors.Is(err, errSnapshotKeyInvalid) || key != "" || mode != 0 {
		t.Fatal("estimates never admitted missing manifests")
	}
	wrapped := snapshotKeyTestWrap(t, "old-key")
	for _, raw := range [][]byte{bytes.Replace(wrapped, []byte(`"key_version":`), []byte(`"Key_Version":`), 1), append(bytes.Clone(wrapped), []byte(`{}`)...), []byte(`{"version":1,"version":1}`), bytes.Replace(wrapped, []byte("old-key"), []byte("other-key"), 1)} {
		if err := snapshotKeyEnvelope(ctx, raw, "old-key"); err == nil {
			t.Fatal("malformed envelope accepted")
		}
	}
}

type snapshotKeyCancelContext struct {
	context.Context
	cancel    context.CancelFunc
	remaining int
}

func (c *snapshotKeyCancelContext) Err() error {
	c.remaining--
	if c.remaining == 0 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestSnapshotKeyInventoryNestedParseCancellation(t *testing.T) {
	base, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	ctx := &snapshotKeyCancelContext{Context: base, cancel: cancel, remaining: 20}
	manifest, hash := snapshotKeyTestManifest(t, 123, "old-key")
	if key, mode, err := snapshotKeyManifest(ctx, []byte(snapshotKeyTestSnapshot(t, manifest, hash)), snapshotKeyRow{OrganizationID: 123, ManifestHash: hash, AnalysisSource: AnalysisSourceLegacyV1}, false); !errors.Is(err, ErrUnavailable) || key != "" || mode != 0 {
		t.Fatal("mid-parse cancellation released root inventory")
	}
}

func TestSnapshotKeyInventoryEnvelopeOriginalFormatting(t *testing.T) {
	raw := snapshotKeyTestWrap(t, "original-root")
	var indented bytes.Buffer
	if err := json.Indent(&indented, raw, "", "  "); err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	reordered, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range [][]byte{indented.Bytes(), reordered} {
		original := bytes.Clone(body)
		if err := snapshotKeyEnvelope(t.Context(), body, "original-root"); err != nil {
			t.Fatal("unambiguous supported envelope formatting rejected", err)
		}
		if !bytes.Equal(body, original) {
			t.Fatal("observer canonicalized original envelope")
		}
	}
}

func TestSnapshotKeyInventoryUnicodeFoldAliases(t *testing.T) {
	for _, raw := range []string{`{"outer":{"s":1,"\u017f":2}}`, `{"outer":{"k":1,"\u212a":2}}`, `{"outer":{"Σ":1,"ς":2}}`, `{"outer":{"ſ":1,"S":2}}`} {
		if err := snapshotKeyStrictJSON(t.Context(), []byte(raw)); !errors.Is(err, errSnapshotKeyInvalid) {
			t.Fatal("Unicode encoding/json-equivalent duplicate admitted", err)
		}
	}
}

func TestSnapshotKeyInventoryEmptyAuditHead(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		requireMigrate(t, s)
		initial := requireInitialize(t, s)
		if err := s.db.Exec("DELETE FROM integrity_audit_logs").Error; err != nil {
			t.Fatal(err)
		}
		snapshotKeyTestUpdate(t, s, "integrity_audit_chain_heads", map[string]any{"event_count": int64(0), "event_hash": "", "key_version": ""})
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		anchor, err := s.verifyAuditSnapshot(ctx, tx, initial.Organization.ID)
		if err != nil || anchor.eventCount != 0 || anchor.endHash != "" || anchor.keyVersion != "" {
			t.Fatal("existing actual empty-head semantics", err)
		}
		got, err := s.snapshotKeyInventory(ctx, tx)
		closeView()
		if err != nil || len(got.versions) != 0 || got.observed[2] != 1 || got.classification != snapshotKeyCurrentReferences {
			t.Fatal("legal empty-head invented a root dependency", err)
		}
		var after auditChainHead
		if err := s.db.Take(&after).Error; err != nil || after.KeyVersion != "" || after.EventHash != "" || after.EventCount != 0 {
			t.Fatal("empty-head original fields mutated")
		}
		snapshotKeyTestUpdate(t, s, "integrity_audit_chain_heads", map[string]any{"key_version": "empty-but-explicit-old"})
		if got := snapshotKeyTestObserve(t, s, cfg, nil); !reflect.DeepEqual(got.versions, []string{"empty-but-explicit-old"}) {
			t.Fatal("explicit empty-chain key was omitted")
		}
		for _, values := range []map[string]any{{"key_version": "", "event_count": int64(1), "event_hash": strings.Repeat("a", 64)}, {"key_version": "", "event_count": int64(0), "event_hash": "bad"}, {"key_version": "", "event_count": int64(-1), "event_hash": ""}} {
			snapshotKeyTestUpdate(t, s, "integrity_audit_chain_heads", values)
			snapshotKeyTestObserve(t, s, cfg, errSnapshotKeyInvalid)
		}
	})
}
