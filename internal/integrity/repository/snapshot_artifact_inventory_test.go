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
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/backupmanifest"
)

func snapshotArtifactTestFixture(t *testing.T, cfg Config) (*Store, InitializationResult, ManagementAuthority, context.Context) {
	t.Helper()
	s := bootstrapTestStore(t, cfg)
	initial, authority, ctx := managementFixture(t, s)
	return s, initial, authority, ctx
}

// Only additional opaque history is inserted directly. The base organization,
// memberships, current bundles and creator all come from actual normal writers.
// This proves preservation of schema-valid retained data, not that a particular
// released historical writer produced these deliberately undecodable bytes.
func snapshotArtifactTestHistory(t *testing.T, s *Store, org, creator int64, version, body string) RuleBundleRecord {
	t.Helper()
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	replay := "opaque replay history; never runtime-decoded"
	row := RuleBundleRecord{ID: id, OrganizationID: org, Version: version, Status: "retired", ContentHash: snapshotArtifactTestHash([]byte(body)), ContentJSON: body, ReplayMetricsJSON: &replay, CreatedBy: creator, CreatedAt: time.Now().UTC().Truncate(time.Microsecond)}
	if err := s.db.Create(&row).Error; err != nil {
		t.Fatal("insert schema-valid opaque history", err)
	}
	return row
}

func snapshotArtifactTestDiscard(_ context.Context, _ snapshotArtifactDescriptor, copy snapshotArtifactCopy) error {
	return copy(io.Discard)
}

func TestSnapshotArtifactInventoryAllHistoryPagedSameView(t *testing.T) {
	eachDatabase(t, func(t *testing.T, _ *Store, cfg Config) {
		s, initial, auth, actor := snapshotArtifactTestFixture(t, cfg)
		second, err := s.ManageCreateOrganization(actor, auth, ManagedOrganizationCreate{Name: "Historical org", Timezone: "UTC", Roles: managementFixtureRoles()})
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 100; i++ {
			snapshotArtifactTestHistory(t, s, initial.Organization.ID, initial.User.ID, fmt.Sprintf("opaque.%03d", i), fmt.Sprintf("not-json\r\n历史 version %d", i))
		}
		last := snapshotArtifactTestHistory(t, s, second.ID, initial.User.ID, "opaque.000", "same version in another tenant has different original bytes")
		private := TemplateBundleRecord{ID: last.ID, OrganizationID: second.ID, Version: "private.legacy", Sensitivity: "private", ContentHash: snapshotArtifactTestHash([]byte("opaque private template\r\n")), ContentJSON: "opaque private template\r\n", CreatedAt: time.Now().UTC()}
		if err := s.db.Create(&private).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.db.Table("organizations").Where("id=?", second.ID).Update("status", "disabled").Error; err != nil {
			t.Fatal(err)
		}
		var rules []RuleBundleRecord
		var templates []TemplateBundleRecord
		if err := s.db.Order("id").Find(&rules).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.db.Order("id").Find(&templates).Error; err != nil {
			t.Fatal(err)
		}
		want := make([]snapshotArtifactDescriptor, 0, len(rules)+len(templates))
		bodies := map[string]string{}
		for _, row := range rules {
			want = append(want, snapshotArtifactDescriptor{"rule", row.Version, row.ContentHash, row.OrganizationID, row.ID, int64(len(row.ContentJSON))})
			bodies[fmt.Sprintf("rule:%d", row.ID)] = row.ContentJSON
		}
		for _, row := range templates {
			want = append(want, snapshotArtifactDescriptor{"template", row.Version, row.ContentHash, row.OrganizationID, row.ID, int64(len(row.ContentJSON))})
			bodies[fmt.Sprintf("template:%d", row.ID)] = row.ContentJSON
		}
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		pages := []int{}
		if err := tx.Callback().Query().After("gorm:query").Register("artifact_pages", func(q *gorm.DB) {
			if page, ok := q.Statement.Dest.(*[]snapshotArtifactRow); ok {
				pages = append(pages, len(*page))
			}
		}); err != nil {
			t.Fatal(err)
		}
		poolless := &Store{driver: cfg.Driver}
		got, err := poolless.snapshotArtifactInventory(ctx, tx.Where("1=0").Select("a.id").Limit(1).Order("a.id DESC"), func(_ context.Context, d snapshotArtifactDescriptor, copy snapshotArtifactCopy) error {
			var out bytes.Buffer
			if err := copy(&out); err != nil {
				return err
			}
			if out.String() != bodies[fmt.Sprintf("%s:%d", d.category, d.id)] {
				t.Error("original bytes changed")
			}
			return nil
		})
		if err != nil || !reflect.DeepEqual(got.entries, want) || !reflect.DeepEqual(pages, []int{100, 3, 3}) {
			t.Fatalf("complete original history: %v count=%d pages=%v", err, len(got.entries), pages)
		}
		owned := slices.Clone(got.entries)
		got.entries[0].version = "caller-owned-change"
		bootstrap := bootstrapTestArtifacts(t)
		otherCfg := cfg
		otherCfg.Bootstrap = &bootstrap
		other, err := Open(t.Context(), otherCfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		otherAuth := managementSession(t, other, initial.User)
		_, err = other.ManageCreateOrganization(actor, otherAuth, ManagedOrganizationCreate{Name: "After snapshot", Timezone: "UTC", Roles: managementFixtureRoles()})
		if err != nil {
			t.Fatal("actual other connection organization/seed transaction", err)
		}
		changed := "updated opaque bytes on another connection"
		if err := other.db.Model(&RuleBundleRecord{}).Where("id=?", last.ID).Updates(map[string]any{"content_json": changed, "content_hash": snapshotArtifactTestHash([]byte(changed))}).Error; err != nil {
			t.Fatal(err)
		}
		again, err := poolless.snapshotArtifactInventory(ctx, tx, snapshotArtifactTestDiscard)
		if err != nil || !reflect.DeepEqual(again.entries, owned) {
			t.Fatal("old actual snapshot changed or aliased", err)
		}
		var one int
		if err := tx.Raw("SELECT 1").Scan(&one).Error; err != nil || one != 1 {
			t.Fatal("caller transaction ended")
		}
		closeView()
		ctx, tx, closeNew := auditSnapshotTestTransaction(t, cfg, nil, true)
		latest, err := poolless.snapshotArtifactInventory(ctx, tx, snapshotArtifactTestDiscard)
		if err != nil || len(latest.entries) != len(want)+2 {
			t.Fatal("new view missing committed history", err)
		}
		found := false
		for _, d := range latest.entries {
			if d.category == "rule" && d.id == last.ID {
				found = d.sha256 == snapshotArtifactTestHash([]byte(changed))
			}
		}
		if !found {
			t.Fatal("new view retained stale source bytes")
		}
		closeNew()
		// Failure on a later template occurs after more than one full metadata
		// page and successfully staged files. The owned result is still zero.
		if err := s.db.Model(&TemplateBundleRecord{}).Where("id=?", private.ID).Update("content_hash", strings.Repeat("0", 64)).Error; err != nil {
			t.Fatal(err)
		}
		ctx, tx, closeDamaged := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeDamaged()
		staged := 0
		partial, err := s.snapshotArtifactInventory(ctx, tx, func(c context.Context, d snapshotArtifactDescriptor, copy snapshotArtifactCopy) error {
			staged++
			return snapshotArtifactTestDiscard(c, d, copy)
		})
		if !errors.Is(err, errSnapshotArtifactInvalid) || partial.entries != nil || staged < 100 {
			t.Fatal("late failure returned publishable inventory", err, staged)
		}
	})
}

func TestSnapshotArtifactInventoryLargeOpaqueSQLChunks(t *testing.T) {
	eachDatabase(t, func(t *testing.T, _ *Store, cfg Config) {
		s, initial, _, _ := snapshotArtifactTestFixture(t, cfg)
		body := strings.Repeat("不可执行 opaque\r\n", 250000) + "tail" // Far above normal writer's 1 MiB parse limit.
		row := snapshotArtifactTestHistory(t, s, initial.Organization.ID, initial.User.ID, "opaque.large", body)
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		writes := 0
		got, err := s.snapshotArtifactInventory(ctx, tx, func(_ context.Context, d snapshotArtifactDescriptor, copy snapshotArtifactCopy) error {
			hash := sha256.New()
			var total int64
			err := copy(snapshotArtifactWriterFunc(func(p []byte) (int, error) {
				if len(p) > snapshotArtifactChunkBytes {
					t.Error("unbounded SQL chunk")
				}
				if d.id == row.ID && d.category == "rule" {
					writes++
				}
				total += int64(len(p))
				return hash.Write(p)
			}))
			if err == nil && (total != d.bytes || hex.EncodeToString(hash.Sum(nil)) != d.sha256) {
				t.Error("actual copy evidence mismatch")
			}
			return err
		})
		if err != nil || len(got.entries) != 3 || writes < 64 {
			t.Fatal("opaque historical body constrained by current decoder", err, writes)
		}
		var after RuleBundleRecord
		if err := s.db.First(&after, "id=?", row.ID).Error; err != nil || !reflect.DeepEqual(after, row) {
			t.Fatal("history mutated", err)
		}
	})
}

func snapshotArtifactTestCorruptible(t *testing.T, s *Store) {
	t.Helper()
	for _, table := range []string{"integrity_rule_bundles", "integrity_template_bundles"} {
		for _, statement := range []string{"ALTER TABLE " + table + " RENAME TO artifact_original_" + table, "CREATE TABLE " + table + " AS SELECT * FROM artifact_original_" + table} {
			if err := s.db.Exec(statement).Error; err != nil {
				t.Fatal("isolated corruption table", err)
			}
		}
	}
	t.Cleanup(func() {
		for _, table := range []string{"integrity_rule_bundles", "integrity_template_bundles"} {
			for _, statement := range []string{"DROP TABLE " + table, "ALTER TABLE artifact_original_" + table + " RENAME TO " + table} {
				if err := s.db.Exec(statement).Error; err != nil {
					t.Error("restore isolated corruption table", err)
				}
			}
		}
	})
}

func TestSnapshotArtifactInventoryCorruptionUnsupportedAndLimits(t *testing.T) {
	eachDatabase(t, func(t *testing.T, _ *Store, cfg Config) {
		s, _, _, _ := snapshotArtifactTestFixture(t, cfg)
		snapshotArtifactTestCorruptible(t, s)
		for _, test := range []struct {
			name, sql  string
			args       []any
			want       error
			sqliteOnly bool
		}{
			{"null-id", "UPDATE integrity_rule_bundles SET id=NULL", nil, errSnapshotArtifactInvalid, false},
			{"zero-id", "UPDATE integrity_rule_bundles SET id=0", nil, errSnapshotArtifactInvalid, false},
			{"null-org", "UPDATE integrity_rule_bundles SET organization_id=NULL", nil, errSnapshotArtifactInvalid, false},
			{"foreign-org", "UPDATE integrity_rule_bundles SET organization_id=1", nil, errSnapshotArtifactInvalid, false},
			{"null-creator", "UPDATE integrity_rule_bundles SET created_by=NULL", nil, errSnapshotArtifactInvalid, false},
			{"null-body", "UPDATE integrity_rule_bundles SET content_json=NULL", nil, errSnapshotArtifactInvalid, false},
			{"null-version", "UPDATE integrity_rule_bundles SET version=NULL", nil, errSnapshotArtifactInvalid, false},
			{"huge-version", "UPDATE integrity_rule_bundles SET version=?", []any{strings.Repeat("v", 1<<20)}, errSnapshotArtifactUnsupported, false},
			{"opaque-version", "UPDATE integrity_rule_bundles SET version=?", []any{"旧版 1"}, errSnapshotArtifactUnsupported, false},
			{"empty-body", "UPDATE integrity_rule_bundles SET content_json='',content_hash=?", []any{snapshotArtifactTestHash(nil)}, errSnapshotArtifactUnsupported, false},
			{"null-hash", "UPDATE integrity_rule_bundles SET content_hash=NULL", nil, errSnapshotArtifactInvalid, false},
			{"huge-hash", "UPDATE integrity_rule_bundles SET content_hash=?", []any{strings.Repeat("a", 1<<20)}, errSnapshotArtifactInvalid, false},
			{"wrong-hash", "UPDATE integrity_rule_bundles SET content_hash=?", []any{strings.Repeat("f", 64)}, errSnapshotArtifactInvalid, false},
			{"duplicate-id", "INSERT INTO integrity_rule_bundles SELECT * FROM integrity_rule_bundles", nil, errSnapshotArtifactInvalid, false},
			{"duplicate-tenant-version", "INSERT INTO integrity_rule_bundles SELECT id+1,organization_id,version,status,content_hash,content_json,replay_metrics_json,created_by,created_at,published_at FROM integrity_rule_bundles", nil, errSnapshotArtifactInvalid, false},
			{"blob-body", "UPDATE integrity_rule_bundles SET content_json=X'6162'", nil, errSnapshotArtifactInvalid, true},
			{"blob-version", "UPDATE integrity_rule_bundles SET version=X'6162'", nil, errSnapshotArtifactInvalid, true},
			{"text-id", "UPDATE integrity_rule_bundles SET id='not-an-id'", nil, errSnapshotArtifactInvalid, true},
		} {
			t.Run(test.name, func(t *testing.T) {
				if test.sqliteOnly && cfg.Driver != "sqlite" {
					t.Skip("SQLite dynamic typing only")
				}
				if err := s.db.Exec("DELETE FROM integrity_rule_bundles").Error; err != nil {
					t.Fatal(err)
				}
				if err := s.db.Exec("INSERT INTO integrity_rule_bundles SELECT * FROM artifact_original_integrity_rule_bundles").Error; err != nil {
					t.Fatal(err)
				}
				if err := s.db.Exec(test.sql, test.args...).Error; err != nil {
					t.Fatal("prepare corruption", err)
				}
				ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
				defer closeView()
				got, err := s.snapshotArtifactInventory(ctx, tx, snapshotArtifactTestDiscard)
				if !errors.Is(err, test.want) || got.entries != nil {
					t.Fatal("corruption/unsupported escaped", err, test.want)
				}
			})
		}
		if err := s.db.Exec("DELETE FROM integrity_rule_bundles").Error; err != nil {
			t.Fatal(err)
		}
		if err := s.db.Exec("INSERT INTO integrity_rule_bundles SELECT * FROM artifact_original_integrity_rule_bundles").Error; err != nil {
			t.Fatal(err)
		}
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		for _, bounds := range []struct {
			count int
			bytes int64
		}{{1, backupmanifest.MaxFileBytes}, {snapshotArtifactMaxEntries, 1}} {
			got, err := s.snapshotArtifactInventoryLimited(ctx, tx, snapshotArtifactTestDiscard, bounds.count, bounds.bytes)
			if !errors.Is(err, errSnapshotArtifactLimit) || got.entries != nil {
				t.Fatal("limit yielded prefix", err)
			}
		}
	})
}

func TestSnapshotArtifactInventoryGuardsCancellationAndSinkFailures(t *testing.T) {
	eachDatabase(t, func(t *testing.T, _ *Store, cfg Config) {
		s, _, _, _ := snapshotArtifactTestFixture(t, cfg)
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		for _, test := range []struct {
			ctx  context.Context
			s    *Store
			tx   *gorm.DB
			sink snapshotArtifactSink
		}{
			{nil, s, tx, snapshotArtifactTestDiscard}, {context.Background(), s, tx, snapshotArtifactTestDiscard}, {ctx, nil, tx, snapshotArtifactTestDiscard}, {ctx, s, nil, snapshotArtifactTestDiscard}, {ctx, s, s.db, snapshotArtifactTestDiscard}, {ctx, s, tx, nil}, {ctx, &Store{driver: "other"}, tx, snapshotArtifactTestDiscard},
		} {
			got, err := test.s.snapshotArtifactInventory(test.ctx, test.tx, test.sink)
			if !errors.Is(err, ErrConfiguration) || got.entries != nil {
				t.Fatal("invalid actual snapshot request", err)
			}
		}
		for _, sink := range []snapshotArtifactSink{
			func(context.Context, snapshotArtifactDescriptor, snapshotArtifactCopy) error { return nil },
			func(context.Context, snapshotArtifactDescriptor, snapshotArtifactCopy) error { panic("private canary") },
			func(_ context.Context, _ snapshotArtifactDescriptor, copy snapshotArtifactCopy) error {
				_ = copy(nil)
				return nil
			},
		} {
			got, err := s.snapshotArtifactInventory(ctx, tx, sink)
			if err == nil || got.entries != nil || strings.Contains(err.Error(), "canary") {
				t.Fatal("sink failure escaped", err)
			}
		}
		cancelCtx, cancel := context.WithCancel(ctx)
		count := 0
		got, err := s.snapshotArtifactInventory(cancelCtx, tx, func(_ context.Context, _ snapshotArtifactDescriptor, copy snapshotArtifactCopy) error {
			count++
			err := copy(io.Discard)
			cancel()
			return err
		})
		if !errors.Is(err, ErrUnavailable) || got.entries != nil || count != 1 {
			t.Fatal("late cancellation returned prefix", err, count)
		}
		closeView()
		if cfg.Driver == "postgres" {
			for _, options := range []*sql.TxOptions{{Isolation: sql.LevelReadCommitted, ReadOnly: true}, {Isolation: sql.LevelRepeatableRead}} {
				ctx, bad, closeBad := auditSnapshotTestTransaction(t, cfg, options, false)
				got, err := s.snapshotArtifactInventory(ctx, bad, snapshotArtifactTestDiscard)
				closeBad()
				if !errors.Is(err, ErrConfiguration) || got.entries != nil {
					t.Fatal("wrong actual isolation/access mode admitted", err)
				}
			}
		}
	})
}

func TestSnapshotArtifactInventoryRepresentationAndManifestIdentity(t *testing.T) {
	d := snapshotArtifactDescriptor{"rule", "private-canary", "hash-canary", 1234, 5678, 4321}
	for _, value := range []any{d, snapshotArtifactInventory{[]snapshotArtifactDescriptor{d}}, snapshotArtifactCopy(func(io.Writer) error { return nil }), &snapshotArtifactStream{descriptor: d}} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if out := fmt.Sprintf(format, value); strings.Contains(out, "canary") || strings.Contains(out, "1234") || !strings.Contains(out, "private snapshot artifact") {
				t.Fatal("fmt leaked")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("JSON accepted")
		}
		if _, err := yaml.Marshal(value); err == nil {
			t.Fatal("YAML accepted")
		}
		out := snapshotInventoryLogText(t, value)
		if strings.Contains(out, "canary") || strings.Contains(out, "1234") || !strings.HasPrefix(out, "[private snapshot artifact ") {
			t.Fatal("slog leaked")
		}
	}
	file := func(id string) backupmanifest.File {
		return backupmanifest.File{EntryID: id, Bytes: 17, SHA256: strings.Repeat("a", 64)}
	}
	manifest := backupmanifest.Manifest{SchemaVersion: backupmanifest.VersionV2, BackupID: 91, StartedAtMicros: 1788840000000000, SnapshotAtMicros: 1788840001000000, ApplicationVersion: "0.1.0-dev", SourceCommit: strings.Repeat("c", 40), Database: backupmanifest.Database{Driver: "sqlite", ServerVersion: "3.52.0", SnapshotMethod: "sqlite_online_backup", File: file("database-snapshot")}, Migrations: []backupmanifest.Migration{{Version: 1, Name: "foundation", SHA256: strings.Repeat("b", 64)}}, KeyVersions: []string{"key-v1"}, AuditHistory: "complete", AuditAnchors: []backupmanifest.AuditAnchor{{OrganizationID: 5, CanonicalizationVersion: "mii.audit.v1"}, {OrganizationID: 9, CanonicalizationVersion: "mii.audit.v1"}}, Jobs: []backupmanifest.JobSummary{{OrganizationID: 5}, {OrganizationID: 9}}, ConfigTemplate: file("config-template")}
	for i, d := range []snapshotArtifactDescriptor{{"rule", "opaque.1", strings.Repeat("a", 64), 5, 12, 17}, {"rule", "opaque.1", strings.Repeat("b", 64), 9, 13, 18}, {"template", "opaque.1", strings.Repeat("c", 64), 5, 12, 19}} {
		manifest.Artifacts = append(manifest.Artifacts, backupmanifest.Artifact{Category: d.category, Scope: "organization", OrganizationID: d.organizationID, ID: d.id, Version: d.version, File: backupmanifest.File{EntryID: fmt.Sprintf("artifact-%d", i), Bytes: d.bytes, SHA256: d.sha256}})
	}
	for _, category := range []string{"scoring", "tokenizer"} {
		manifest.Artifacts = append(manifest.Artifacts, backupmanifest.Artifact{Category: category, Scope: "installed", Version: "opaque.1", File: file(category)})
	}
	if _, _, err := backupmanifest.Encode(manifest); err != nil {
		t.Fatal("v2 rejected exact category/tenant/source identity", err)
	}
	manifest.Artifacts[1].ID = 12
	if _, _, err := backupmanifest.Encode(manifest); !errors.Is(err, backupmanifest.ErrInvalid) {
		t.Fatal("v2 permitted same-table row ID collision")
	}
}

func TestSnapshotArtifactInventorySQLLateFailureAndExactMetadataBoundary(t *testing.T) {
	eachDatabase(t, func(t *testing.T, _ *Store, cfg Config) {
		s, initial, _, _ := snapshotArtifactTestFixture(t, cfg)
		version := "v" + strings.Repeat("x", 121) + "._:/-z"
		if len(version) != 128 {
			t.Fatal("version fixture boundary")
		}
		row := snapshotArtifactTestHistory(t, s, initial.Organization.ID, initial.User.ID, version, "opaque boundary bytes")
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		got, err := s.snapshotArtifactInventory(ctx, tx, snapshotArtifactTestDiscard)
		if err != nil || len(got.entries) != 3 {
			t.Fatal("manifest-compatible 128-byte version rejected", err)
		}
		found := false
		for _, d := range got.entries {
			found = found || d.category == "rule" && d.id == row.ID && d.version == version
		}
		if !found {
			t.Fatal("version altered")
		}
		closeView()
		ctx, tx, closeDamaged := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeDamaged()
		actual := tx.Statement.ConnPool.(*sql.Tx)
		staged := 0
		got, err = s.snapshotArtifactInventory(ctx, tx, func(_ context.Context, _ snapshotArtifactDescriptor, copy snapshotArtifactCopy) error {
			err := copy(io.Discard)
			staged++
			if staged == 1 {
				if rollbackErr := actual.Rollback(); rollbackErr != nil {
					t.Error("inject caller transaction termination", rollbackErr)
				}
			}
			return err
		})
		if !errors.Is(err, ErrUnavailable) || got.entries != nil || staged < 1 {
			t.Fatal("late actual SQL failure returned prefix", err, staged)
		}
	})
}
