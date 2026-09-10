package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/scheduler"
	"model-integrity-inspector.local/mii/migrations"
)

func snapshotKeyTestObserve(t *testing.T, s *Store, cfg Config, want error) snapshotKeyInventory {
	t.Helper()
	ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
	defer closeView()
	got, err := (&Store{driver: s.driver}).snapshotKeyInventory(ctx, tx)
	if !errors.Is(err, want) || (want != nil && (!reflect.DeepEqual(got, snapshotKeyInventory{}) || err.Error() != want.Error())) {
		t.Fatalf("closed inventory error/zero: %v", err)
	}
	return got
}

// Structural fixtures intentionally do not claim cryptographic authenticity.
// Real KeyRing.Rewrap and generated-manifest tests use the external test bridge.
func snapshotKeyTestWrap(t *testing.T, key string) []byte {
	t.Helper()
	data, err := json.Marshal(struct {
		Version    int    `json:"version"`
		Algorithm  string `json:"algorithm"`
		KeyVersion string `json:"key_version"`
		Nonce      []byte `json:"nonce"`
		Ciphertext []byte `json:"ciphertext"`
	}{1, "AES-256-GCM", key, bytes.Repeat([]byte{1}, 12), bytes.Repeat([]byte{2}, 48)})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func snapshotKeyTestManifest(t *testing.T, org int64, key string) ([]byte, string) {
	t.Helper()
	data, err := json.Marshal(map[string]any{"generator_version": "1.0.0-dev.1", "options": map[string]any{"organization_id": strconv.FormatInt(org, 10)}, "run_nonce": "fixture", "key_version": key, "template_version": "1", "template_hash": strings.Repeat("a", 64), "tokenizer_version": "1", "tokenizer_hash": strings.Repeat("b", 64), "samples": []any{}, "omissions": []any{}, "warnings": []string{}, "completeness": "PARTIAL", "projection": map[string]any{}, "integrity": strings.Repeat("c", 64)})
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	return data, hex.EncodeToString(hash[:])
}

func snapshotKeyTestSnapshot(t *testing.T, manifest []byte, hash string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"plan": map[string]any{"manifest": json.RawMessage(manifest), "manifest_hash": hash}})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func snapshotKeyTestUpdate(t *testing.T, s *Store, table string, values map[string]any) {
	t.Helper()
	if err := s.db.Table(table).Where("1=1").Updates(values).Error; err != nil {
		t.Fatalf("update test-owned %s: %v", table, err)
	}
}

func snapshotKeyTestFixture(t *testing.T, s *Store) (*Tenant, RunRecord) {
	t.Helper()
	tenant, queue, run := reportFixture(t, s)
	// Actual derived planning/reservation/completion obeys migration18's guards.
	// The unrelated legacy report fixture cannot be retroactively made derived.
	var frozen executionSnapshot
	if json.Unmarshal([]byte(run.ConfigSnapshot), &frozen) != nil {
		t.Fatal("original plan fixture")
	}
	frozen.Plan.AnalysisSourceVersion = domain.AnalysisSourceDerivedV1
	frozen.Plan.Probes = frozen.Plan.Probes[:1]
	frozen.Plan.Probes[0].Samples = frozen.Plan.Probes[0].Samples[:1]
	rawManifest, _ := snapshotKeyTestManifest(t, tenant.orgID, "old-run")
	var manifestFields map[string]any
	if json.Unmarshal(rawManifest, &manifestFields) != nil {
		t.Fatal("manifest fixture")
	}
	manifestFields["options"].(map[string]any)["analysis_source_version"] = domain.AnalysisSourceDerivedV1
	encodedManifest, err := json.Marshal(manifestFields)
	if err != nil {
		t.Fatal(err)
	}
	frozen.Plan.Manifest = encodedManifest
	digest := sha256.Sum256(encodedManifest)
	frozen.Plan.ManifestHash = hex.EncodeToString(digest[:])
	policy, err := scheduler.NewPolicy(scheduler.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	dRun, err := tenant.CreateRun(frozen.Plan, policy, "key-inventory-derived")
	if err != nil {
		t.Fatal(err)
	}
	start := mustClaim(t, queue)
	if err := queue.CompleteWith(tenant.ctx, start, func(tx *TenantTransaction) error { return tx.StartRunWithDerivedSource(dRun.ID) }); err != nil {
		t.Fatal(err)
	}
	dSamples, err := tenant.ListExecutionSamples(dRun.ID)
	if err != nil || len(dSamples) != 1 {
		t.Fatal("derived sample", err)
	}
	dLease := mustClaim(t, queue)
	dAttempt := reserveTestAttempt(t, tenant, queue, dLease, dSamples[0])
	candidates := derivedFixtureCandidates(dRun, dSamples[0], dAttempt, successOutcome())
	for i := range candidates.Items {
		candidates.Items[i].Record.KeyVersion = "old-derived"
	}
	dBody := derivedFixtureBody(t, tenant, queue, dLease, dSamples[0], dAttempt)
	if err := queue.CompleteWith(tenant.ctx, dLease, func(tx *TenantTransaction) error {
		return tx.FinishAttemptWithDerived(dSamples[0].ID, dAttempt.ID, successOutcome(), 0, candidates, dBody)
	}); err != nil {
		t.Fatal(err)
	}
	snapshotKeyTestUpdate(t, s, "integrity_secrets", map[string]any{"key_version": "old-secret", "payload_key_version": "retired-aad-not-required", "encrypted_data_key": snapshotKeyTestWrap(t, "old-secret")})
	snapshotKeyTestUpdate(t, s, "integrity_audit_logs", map[string]any{"key_version": "old-audit"})
	snapshotKeyTestUpdate(t, s, "integrity_audit_chain_heads", map[string]any{"key_version": "old-head"})
	manifest, hash := snapshotKeyTestManifest(t, tenant.orgID, "old-run")
	if err := s.db.Table("integrity_runs").Where("id=?", run.ID).Updates(map[string]any{"config_snapshot": snapshotKeyTestSnapshot(t, manifest, hash), "manifest_hash": hash}).Error; err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC().Add(-40 * 24 * time.Hour).Truncate(time.Microsecond)
	snapshotKeyTestUpdate(t, s, "integrity_response_evidence", map[string]any{"key_version": "old-response", "created_at": stamp, "expires_at": stamp.Add(30 * 24 * time.Hour)})
	var attempts []AttemptRecord
	if err := s.db.Where("run_id=?", run.ID).Order("id").Find(&attempts).Error; err != nil || len(attempts) != 2 {
		t.Fatal("two real completed attempts", err)
	}
	a := attempts[0]
	if err := s.db.Model(&DisplayEvidenceRecord{}).Where("attempt_id=?", a.ID).Updates(map[string]any{"state": DisplayCaptured, "source_hash": strings.Repeat("d", 64), "version": 1, "key_version": "old-display", "nonce": bytes.Repeat([]byte{1}, 12), "ciphertext": bytes.Repeat([]byte{2}, 48), "plaintext_bytes": 32, "payload_hash": strings.Repeat("e", 64), "captured_at_micros": stamp.UnixMicro(), "expires_at_micros": stamp.Add(30 * 24 * time.Hour).UnixMicro()}).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Table("integrity_display_evidence").Where("attempt_id=?", dAttempt.ID).Update("key_version", "old-display").Error; err != nil {
		t.Fatal(err)
	}
	for i, state := range []string{"draft", "approved", "retired"} {
		snapshotJobTestInsert(t, s, "integrity_baselines", map[string]any{"id": int64(21 + i), "organization_id": tenant.orgID, "run_id": run.ID, "analysis_revision": 1, "name": "historical", "model": "model", "protocol": "openai_chat", "status": state, "applicable_scope_json": "{}", "created_at": stamp, "expires_at": stamp.Add(time.Hour), "approval_key_version": "old-baseline-" + state, "approval_mac": strings.Repeat("f", 64)})
	}
	manifest, hash = snapshotKeyTestManifest(t, tenant.orgID, "old-estimate")
	snapshotJobTestInsert(t, s, "integrity_run_estimates", map[string]any{"id": int64(31), "organization_id": tenant.orgID, "target_id": run.TargetID, "target_version": 1, "created_by": run.CreatedBy, "manifest_hash": hash, "snapshot_json": snapshotKeyTestSnapshot(t, manifest, hash), "created_at": stamp, "expires_at": stamp.Add(time.Minute)})
	return tenant, run
}

func TestSnapshotKeyInventoryEveryHistoricalSource(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, _ := snapshotKeyTestFixture(t, s)
		snapshotKeyTestUpdate(t, s, "organizations", map[string]any{"status": "disabled"})
		got := snapshotKeyTestObserve(t, s, cfg, nil)
		want := []string{"old-audit", "old-baseline-approved", "old-baseline-draft", "old-baseline-retired", "old-derived", "old-display", "old-estimate", "old-head", "old-response", "old-run", "old-secret"}
		if !reflect.DeepEqual(got.versions, want) || got.classification != snapshotKeyCurrentReferences || got.observed[0] != 1 || got.observed[3] != 3 || got.observed[4] != 3 || got.observed[5] != 3 || got.observed[6] != 1 || got.observed[7] != 2 || got.observed[8] != 1 {
			t.Fatal("omitted/added root reference or wrong complete counts")
		}
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		limited, err := s.snapshotKeyInventoryLimited(ctx, tx, len(want)-1)
		closeView()
		if !errors.Is(err, errSnapshotKeyLimit) || !reflect.DeepEqual(limited, snapshotKeyInventory{}) {
			t.Fatal("union cap incorrectly applied independently to each source")
		}
		// Body retention deletes S2 only. Retained S1 still needs its MAC key.
		if err := s.db.Where("organization_id=?", tenant.orgID).Delete(&ResponseEvidenceRecord{}).Error; err != nil {
			t.Fatal(err)
		}
		after := snapshotKeyTestObserve(t, s, cfg, nil)
		if slices.Contains(after.versions, "old-response") || !slices.Contains(after.versions, "old-derived") {
			t.Fatal("body cleanup incorrectly removed derived root dependency")
		}
	})
}

func TestSnapshotKeyInventoryPagesUnionOwnedAndSameView(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		requireMigrate(t, s)
		ids := snapshotJobTestOrganizations(t, s, 101)
		stamp := time.Now().UTC().Truncate(time.Microsecond)
		for i, org := range ids {
			key := "old-page"
			if i == 100 {
				key = "unique-late"
			}
			if err := s.db.Create(&auditChainHead{OrganizationID: org, KeyVersion: key, UpdatedAt: stamp}).Error; err != nil {
				t.Fatal(err)
			}
		}
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		var pages []int
		if err := tx.Callback().Query().After("gorm:query").Register("snapshot_key_pages", func(q *gorm.DB) {
			if rows, ok := q.Statement.Dest.(*[]snapshotKeyRow); ok && strings.Contains(q.Statement.SQL.String(), "integrity_audit_chain_heads") {
				pages = append(pages, len(*rows))
			}
		}); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Callback().Query().Remove("snapshot_key_pages") }()
		poolless := &Store{driver: cfg.Driver}
		got, err := poolless.snapshotKeyInventory(ctx, tx.Where("1=0").Select("id").Limit(1).Order("id DESC"))
		if err != nil || !reflect.DeepEqual(got.versions, []string{"old-page", "unique-late"}) || !reflect.DeepEqual(pages, []int{100, 1}) || got.observed[2] != 101 {
			t.Fatalf("actual pages/late key: %v %v", pages, err)
		}
		owned := slices.Clone(got.versions)
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		if err := other.db.Table("integrity_audit_chain_heads").Where("organization_id=101").Update("key_version", "new-live").Error; err != nil {
			t.Fatal(err)
		}
		got.versions[0] = "owned-canary"
		again, err := poolless.snapshotKeyInventory(ctx, tx)
		if err != nil || !reflect.DeepEqual(again.versions, owned) {
			t.Fatal("snapshot drift or aliased result")
		}
		for _, limit := range []int{1, 2} {
			limited, err := poolless.snapshotKeyInventoryLimited(ctx, tx, limit)
			if limit == 1 && (!errors.Is(err, errSnapshotKeyLimit) || !reflect.DeepEqual(limited, snapshotKeyInventory{})) {
				t.Fatal("union limit partial result")
			}
			if limit == 2 && err != nil {
				t.Fatal("exact limit rejected", err)
			}
		}
		var one int
		if tx.Raw("SELECT 1").Scan(&one).Error != nil || one != 1 {
			t.Fatal("caller transaction ended")
		}
		closeView()
		live := snapshotKeyTestObserve(t, s, cfg, nil)
		if !slices.Contains(live.versions, "new-live") || slices.Contains(live.versions, "unique-late") {
			t.Fatal("new snapshot missing committed writer")
		}
		for i := 1; i <= 64; i++ {
			if err := s.db.Table("integrity_audit_chain_heads").Where("organization_id=?", i).Update("key_version", fmt.Sprintf("key-%02d", i)).Error; err != nil {
				t.Fatal(err)
			}
		}
		if err := s.db.Table("integrity_audit_chain_heads").Where("organization_id>64").Update("key_version", "key-01").Error; err != nil {
			t.Fatal(err)
		}
		if got := snapshotKeyTestObserve(t, s, cfg, nil); len(got.versions) != 64 {
			t.Fatal("exact64 union rejected")
		}
		if err := s.db.Table("integrity_audit_chain_heads").Where("organization_id=101").Update("key_version", "key-65").Error; err != nil {
			t.Fatal(err)
		}
		snapshotKeyTestObserve(t, s, cfg, errSnapshotKeyLimit)
	})
}

func TestSnapshotKeyInventoryLegacyAndTombstone(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		set, err := migrations.ForDialect(cfg.Driver)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.migrate(t.Context(), set[:17]); err != nil {
			t.Fatal(err)
		}
		org := derivedUpgradeLegacyRows(t, s)
		// The old shared test helper's opaque string is not an actual codec.
		// Install a structurally correct old envelope BEFORE the real migration.
		snapshotKeyTestUpdate(t, s, "integrity_secrets", map[string]any{"encrypted_data_key": snapshotKeyTestWrap(t, "v1")})
		var before []struct {
			ID                           int64
			ConfigSnapshot, ManifestHash string
		}
		if err := s.db.Table("integrity_runs").Select("id,config_snapshot,manifest_hash").Order("id").Find(&before).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
		got := snapshotKeyTestObserve(t, s, cfg, nil)
		if got.classification != snapshotKeyLegacyIncomplete || got.legacyUnverifiedRuns != 2 || !reflect.DeepEqual(got.versions, []string{"legacy", "test-v1", "v1"}) {
			t.Fatal("legal historical bodies/runs omitted or promoted")
		}
		var after []struct {
			ID                           int64
			ConfigSnapshot, ManifestHash string
		}
		if err := s.db.Table("integrity_runs").Select("id,config_snapshot,manifest_hash").Order("id").Find(&after).Error; err != nil {
			t.Fatal(err)
		}
		for i := range before {
			if before[i].ConfigSnapshot != after[i].ConfigSnapshot || before[i].ManifestHash != after[i].ManifestHash {
				t.Fatal("legacy snapshot was rewritten/resigned")
			}
		}
		stamp := time.Now().UTC()
		snapshotKeyTestUpdate(t, s, "integrity_secrets", map[string]any{"deleted_at": stamp})
		if got := snapshotKeyTestObserve(t, s, cfg, nil); !slices.Contains(got.versions, "v1") {
			t.Fatal("old soft-delete erased live envelope dependency")
		}
		snapshotKeyTestUpdate(t, s, "integrity_secrets", map[string]any{"encrypted_data_key": []byte{}, "nonce": []byte{}, "ciphertext": []byte{}, "fingerprint": "", "last_four": ""})
		got = snapshotKeyTestObserve(t, s, cfg, nil)
		if got.destroyedSecrets != 1 || slices.Contains(got.versions, "v1") {
			t.Fatal("complete erased tombstone requires old root")
		}
		if key, mode, err := snapshotKeyManifest(t.Context(), []byte(`{"legacy_fixture":true}`), snapshotKeyRow{OrganizationID: org, AnalysisSource: domain.AnalysisSourceDerivedV1}, false); !errors.Is(err, errSnapshotKeyInvalid) || key != "" || mode != 0 {
			t.Fatal("derived missing manifest promoted to legacy")
		}
	})
}

func TestSnapshotKeyInventoryTransactionCancellationAndLateError(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		requireMigrate(t, s)
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		typedNil := tx.Session(&gorm.Session{NewDB: true, Initialized: true})
		typedNil.Statement.ConnPool = (*sql.Tx)(nil)
		for _, tc := range []struct {
			ctx context.Context
			tx  *gorm.DB
		}{{ctx, s.db}, {ctx, nil}, {nil, tx}, {context.Background(), tx}, {ctx, typedNil}} {
			got, err := s.snapshotKeyInventory(tc.ctx, tc.tx)
			if !errors.Is(err, ErrConfiguration) || !reflect.DeepEqual(got, snapshotKeyInventory{}) {
				t.Fatal("invalid transaction/context accepted", err)
			}
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if got, err := s.snapshotKeyInventory(canceled, tx); !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(got, snapshotKeyInventory{}) {
			t.Fatal("cancelled snapshot produced candidate")
		}
		if err := tx.Callback().Raw().After("gorm:raw").Register("snapshot_key_late", func(q *gorm.DB) {
			if strings.Contains(q.Statement.SQL.String(), "integrity_gateway_evidence") {
				_ = q.AddError(errors.New("private-late-canary"))
			}
		}); err != nil {
			t.Fatal(err)
		}
		// Raw SELECT uses Row callbacks in GORM, not mutation Raw callbacks.
		if err := tx.Callback().Row().After("gorm:row").Register("snapshot_key_late_row", func(q *gorm.DB) {
			if strings.Contains(q.Statement.SQL.String(), "integrity_gateway_evidence") {
				_ = q.AddError(errors.New("private-late-canary"))
			}
		}); err != nil {
			t.Fatal(err)
		}
		got, err := s.snapshotKeyInventory(ctx, tx)
		_ = tx.Callback().Raw().Remove("snapshot_key_late")
		_ = tx.Callback().Row().Remove("snapshot_key_late_row")
		if !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(got, snapshotKeyInventory{}) {
			t.Fatal("late SQL failure was not zero/closed", err)
		}
		closeView()
		if got, err := s.snapshotKeyInventory(ctx, tx); err == nil || !reflect.DeepEqual(got, snapshotKeyInventory{}) {
			t.Fatal("closed transaction accepted")
		}
	})
}

func TestSnapshotKeyInventoryFormatting(t *testing.T) {
	v := snapshotKeyInventory{versions: []string{"sensitive-version-canary"}, classification: snapshotKeyCurrentReferences}
	for _, item := range []any{v, &v} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if fmt.Sprintf(format, item) != "[private snapshot key inventory]" {
				t.Fatal("format leaked")
			}
		}
		if _, err := json.Marshal(item); err == nil {
			t.Fatal("JSON leaked")
		}
		if _, err := yaml.Marshal(item); err == nil {
			t.Fatal("YAML leaked")
		}
		var out bytes.Buffer
		slog.New(slog.NewJSONHandler(&out, nil)).Info("value", "value", item)
		if strings.Contains(out.String(), "sensitive-version-canary") {
			t.Fatal("slog leaked")
		}
	}
}

// Test-only bridge permits external-package tests to use the real secret and
// generator packages without a repository -> secret import cycle. Nothing is
// exported in a production build, and no caller obtains our private inventory.
func SnapshotKeyInventoryCryptoBridge(t *testing.T, records func(int64, int64) (SecretRecord, SecretRecord, func(SecretRecord) error)) {
	t.Helper()
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		_, tenant := targetFixture(t, s)
		id, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		old, next, open := records(tenant.orgID, id)
		state, err := tenant.CreateTargetWithSecret(targetRecordFixture(), old)
		if err != nil {
			t.Fatal(err)
		}
		got := snapshotKeyTestObserve(t, s, cfg, nil)
		if !slices.Contains(got.versions, "actual-old") || slices.Contains(got.versions, "actual-new") {
			t.Fatal("original live envelope root lost")
		}
		if err := open(old); err == nil {
			t.Fatal("new-only KeyRing unexpectedly opened old root")
		}
		// Rewrap changes exactly the DEK envelope/root label, never payload AAD.
		if err := s.db.Model(&SecretRecord{}).Where("id=?", id).Updates(map[string]any{"key_version": next.KeyVersion, "encrypted_data_key": next.EncryptedDataKey}).Error; err != nil {
			t.Fatal(err)
		}
		var persisted SecretRecord
		if err := s.db.Where("id=?", id).Take(&persisted).Error; err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(old.Ciphertext, persisted.Ciphertext) || !bytes.Equal(old.Nonce, persisted.Nonce) || persisted.PayloadKeyVersion != "actual-old" || open(persisted) != nil {
			t.Fatal("actual persisted rewrap failed with new-only root")
		}
		got = snapshotKeyTestObserve(t, s, cfg, nil)
		if !slices.Contains(got.versions, "actual-new") || slices.Contains(got.versions, "actual-old") {
			t.Fatal("immutable payload AAD label incorrectly requires retired master")
		}
		var formatted bytes.Buffer
		if err := json.Indent(&formatted, persisted.EncryptedDataKey, "", "  "); err != nil {
			t.Fatal(err)
		}
		persisted.EncryptedDataKey = bytes.Clone(formatted.Bytes())
		if open(persisted) != nil {
			t.Fatal("actual codec rejected harmless original formatting")
		}
		if err := s.db.Model(&SecretRecord{}).Where("id=?", id).Update("encrypted_data_key", persisted.EncryptedDataKey).Error; err != nil {
			t.Fatal(err)
		}
		formattedInventory := snapshotKeyTestObserve(t, s, cfg, nil)
		if !reflect.DeepEqual(formattedInventory.versions, got.versions) {
			t.Fatal("valid original envelope whitespace changed required roots")
		}
		if err := tenant.DeleteTarget(state.Target.ID, state.Target.Version); err != nil {
			t.Fatal("actual target deletion", err)
		}
		got = snapshotKeyTestObserve(t, s, cfg, nil)
		if got.destroyedSecrets != 1 || slices.Contains(got.versions, "actual-new") || slices.Contains(got.versions, "actual-old") {
			t.Fatal("actual DeleteTarget tombstone demands erased secret root")
		}
	})
}

func SnapshotKeyInventoryGeneratorBridge(t *testing.T, compile func(int64, TargetState) domain.ExecutionPlan) {
	t.Helper()
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, target, _, policy := executionFixture(t, s, 1)
		snapshotKeyTestUpdate(t, s, "integrity_secrets", map[string]any{"encrypted_data_key": snapshotKeyTestWrap(t, "v1")})
		plan := compile(tenant.orgID, target)
		estimate, err := tenant.SaveRunEstimate(plan, policy)
		if err != nil {
			t.Fatal("actual generated estimate writer", err)
		}
		run, err := tenant.CreateRun(plan, policy, "key-real-generator")
		if err != nil {
			t.Fatal("actual generated Run writer", err)
		}
		if estimate.ManifestHash != plan.ManifestHash || run.ManifestHash != plan.ManifestHash {
			t.Fatal("writer changed original manifest hash")
		}
		if err := s.db.Model(&RunEstimateRecord{}).Where("id=?", estimate.ID).Update("expires_at", time.Now().Add(-time.Hour)).Error; err != nil {
			t.Fatal(err)
		}
		got := snapshotKeyTestObserve(t, s, cfg, nil)
		if !slices.Contains(got.versions, "actual-plan-old") || got.classification != snapshotKeyCurrentReferences || got.observed[7] != 1 || got.observed[8] != 1 {
			t.Fatal("real current manifest original bytes/version not inventoried")
		}
	})
}
