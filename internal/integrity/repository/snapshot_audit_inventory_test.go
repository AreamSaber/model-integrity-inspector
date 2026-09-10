package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/backupmanifest"
)

func snapshotAuditInventoryTestOrganizations(t *testing.T, s *Store, initial InitializationResult, count int) []int64 {
	t.Helper()
	ids := make([]int64, 0, count)
	ctx := testActorContext(t, initial.User.ID)
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for range count {
			org := initial.Organization
			var err error
			org.ID, err = NewID()
			if err != nil {
				return err
			}
			// Disabled organizations remain part of a full backup inventory.
			org.Status = "disabled"
			if err := tx.Create(&org).Error; err != nil {
				return err
			}
			if err := s.appendAudit(ctx, tx, org.ID, auditObject("test.organization_create", "organization", org.ID), nil); err != nil {
				return err
			}
			ids = append(ids, org.ID)
		}
		return nil
	}); err != nil {
		t.Fatal("create real organizations and signed chains in isolated fixture")
	}
	return ids
}

func snapshotAuditInventoryTestFailure(t *testing.T, s *Store, cfg Config, want error) {
	t.Helper()
	ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
	defer closeView()
	got, err := s.snapshotAuditInventory(ctx, tx)
	if !errors.Is(err, want) || got.anchors != nil {
		t.Fatalf("inventory failure exposed partial anchors or wrong closed error: %v", err)
	}
}

func TestSnapshotAuditInventoryPagesOwnedAndSameView(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		requireMigrate(t, s)
		initial := requireInitialize(t, s)
		ids := snapshotAuditInventoryTestOrganizations(t, s, initial, snapshotAuditOrganizationPage)
		ids = append(ids, initial.Organization.ID)
		slices.Sort(ids)
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		var pages []int
		if err := tx.Callback().Query().After("gorm:query").Register("snapshot_audit_inventory_pages", func(q *gorm.DB) {
			if page, ok := q.Statement.Dest.(*[]int64); ok && q.Statement.Table == "organizations" && q.Error == nil {
				pages = append(pages, len(*page))
			}
		}); err != nil {
			t.Fatal("observe actual organization cursor pages")
		}
		got, err := s.snapshotAuditInventory(ctx, tx.Where("1=0").Limit(1))
		if err != nil || len(got.anchors) != 101 || !reflect.DeepEqual(pages, []int{100, 1}) {
			t.Fatalf("all-organization snapshot pages: %v; actual pages %v", err, pages)
		}
		for i, anchor := range got.anchors {
			if anchor.organizationID != ids[i] || anchor.eventCount != 1 || anchor.keyVersion != "test-v1" || anchor.endHash == "" {
				t.Fatal("organization was omitted, mixed or not fully authenticated")
			}
		}
		original := slices.Clone(got.anchors)
		pages = nil
		limited, err := s.snapshotAuditInventoryLimited(ctx, tx, snapshotAuditOrganizationPage)
		if !errors.Is(err, errSnapshotAuditLimit) || limited.anchors != nil || !reflect.DeepEqual(pages, []int{100, 1}) {
			t.Fatal("second-page cap failure leaked first 100 already verified organization anchors")
		}
		snapshotAuditInventoryTestOrganizations(t, s, initial, 1)
		auditSnapshotTestAppend(t, s, initial.Organization.ID, initial.User.ID, 1)
		got.anchors[0].keyVersion = "mutated-owned-result"
		again, err := s.snapshotAuditInventory(ctx, tx)
		if err != nil || !reflect.DeepEqual(again.anchors, original) {
			t.Fatal("snapshot drifted to concurrent organization/event or aliased prior result")
		}
		closeView()
		ctx, fresh, closeFresh := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeFresh()
		live, err := s.snapshotAuditInventory(ctx, fresh)
		if err != nil || len(live.anchors) != 102 {
			t.Fatal("new snapshot failed to observe the independently committed organization")
		}
		found := false
		for _, anchor := range live.anchors {
			if anchor.organizationID == initial.Organization.ID {
				found = anchor.eventCount == 2
			}
		}
		if !found {
			t.Fatal("new snapshot failed to observe independently committed audit event")
		}
	})
}

func TestSnapshotAuditInventoryRealOrganizationLimit(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		requireMigrate(t, s)
		initial := requireInitialize(t, s)
		snapshotAuditInventoryTestOrganizations(t, s, initial, 2)
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		for _, limit := range []int{1, 2} {
			got, err := s.snapshotAuditInventoryLimited(ctx, tx, limit)
			if !errors.Is(err, errSnapshotAuditLimit) || got.anchors != nil {
				t.Fatal("real SQL row count exceeding stricter resource cap was truncated or accepted")
			}
		}
		got, err := s.snapshotAuditInventoryLimited(ctx, tx, 3)
		if err != nil || len(got.anchors) != 3 {
			t.Fatal("exact real organization cap refused")
		}
		for _, limit := range []int{0, -1, backupmanifest.MaxOrganizations + 1} {
			got, err := s.snapshotAuditInventoryLimited(ctx, tx, limit)
			if !errors.Is(err, ErrConfiguration) || got.anchors != nil {
				t.Fatal("invalid private cap bypassed fixed production hard limit")
			}
		}
	})
}

type snapshotAuditInventorySigner struct {
	calls       int
	cancelAfter int
	cancel      context.CancelFunc
}

func (*snapshotAuditInventorySigner) ActiveVersion() string { return "test-v1" }
func (s *snapshotAuditInventorySigner) AuditMAC(version string, message []byte) ([]byte, error) {
	s.calls++
	if s.cancel != nil && s.calls == s.cancelAfter {
		s.cancel()
	}
	return testAuditSigner{}.AuditMAC(version, message)
}

func TestSnapshotAuditInventorySecondOrganizationFailureAndCancellation(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		requireMigrate(t, s)
		initial := requireInitialize(t, s)
		ids := append(snapshotAuditInventoryTestOrganizations(t, s, initial, 2), initial.Organization.ID)
		slices.Sort(ids)
		var event audit.Event
		if err := s.db.Where("organization_id=? AND sequence=1", ids[1]).First(&event).Error; err != nil {
			t.Fatal("load original second organization signed event")
		}
		changed := s.db.Model(&audit.Event{}).Where("id=?", event.ID).Update("action", "test.second_organization_tamper")
		if changed.Error != nil || changed.RowsAffected != 1 {
			t.Fatal("tamper actual second organization event")
		}
		originalSigner := s.auditSigner
		counter := &snapshotAuditInventorySigner{}
		s.auditSigner = counter
		snapshotAuditInventoryTestFailure(t, s, cfg, audit.ErrIntegrity)
		if counter.calls != 3 {
			t.Fatal("second organization corruption was not reached after first valid chain")
		}
		if err := s.db.Model(&audit.Event{}).Where("id=?", event.ID).Update("action", event.Action).Error; err != nil {
			t.Fatal("restore genuine second organization event")
		}
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		child, cancel := context.WithCancel(ctx)
		defer cancel()
		counter = &snapshotAuditInventorySigner{cancelAfter: 3, cancel: cancel}
		s.auditSigner = counter
		got, err := s.snapshotAuditInventory(child, tx)
		s.auditSigner = originalSigner
		if !errors.Is(err, ErrUnavailable) || got.anchors != nil || counter.calls < 3 {
			t.Fatal("second organization cancellation returned success or earlier partial anchor")
		}
	})
}

func TestSnapshotAuditInventoryInitializationAndSegments(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		requireMigrate(t, s)
		snapshotAuditInventoryTestFailure(t, s, cfg, errSnapshotAuditNotInitialized)
		initial := requireInitialize(t, s)
		initialID := strconv.FormatInt(initial.Organization.ID, 10)
		for _, tc := range []struct{ name, key, value string }{
			{"missing_marker_with_organization", "initialized", ""},
			{"false_marker", "initialized", "false"},
			{"quoted_marker", "initialized", `"true"`},
			{"oversized_marker", "initialized", strings.Repeat("x", 1<<20)},
			{"missing_initial_id", "initial_organization_id", ""},
			{"zero_initial_id", "initial_organization_id", "0"},
			{"plus_initial_id", "initial_organization_id", "+" + initialID},
			{"leading_zero_initial_id", "initial_organization_id", "0" + initialID},
			{"missing_initial_organization", "initial_organization_id", "1"},
			{"oversized_initial_id", "initial_organization_id", strings.Repeat("1", 1<<20)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if tc.value == "" {
					if err := s.db.Exec("DELETE FROM system_settings WHERE setting_key=?", tc.key).Error; err != nil {
						t.Fatal("remove isolated initialization setting")
					}
				} else if err := s.db.Exec("UPDATE system_settings SET value_json=? WHERE setting_key=?", tc.value, tc.key).Error; err != nil {
					t.Fatal("corrupt isolated initialization setting")
				}
				defer func() {
					value := initialID
					if tc.key == "initialized" {
						value = "true"
					}
					if err := s.db.Exec("INSERT INTO system_settings(setting_key,value_json,version,updated_at) VALUES(?,?,1,?) ON CONFLICT(setting_key) DO UPDATE SET value_json=excluded.value_json", tc.key, value, time.Now().UTC()).Error; err != nil {
						t.Error("restore original initialization setting")
					}
				}()
				want := audit.ErrIntegrity
				if tc.name == "missing_marker_with_organization" {
					want = errSnapshotAuditNotInitialized
				}
				snapshotAuditInventoryTestFailure(t, s, cfg, want)
				if strings.HasPrefix(tc.name, "oversized_") {
					ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
					defer closeView()
					maxBytes := 19
					if tc.key == "initialized" {
						maxBytes = 4
					}
					bounded, present, err := snapshotAuditSetting(tx.WithContext(ctx), tc.key, maxBytes)
					if err != nil || !present || bounded != "\n" {
						t.Fatalf("oversized setting projection: error=%v present=%t returned_bytes=%d", err, present, len(bounded))
					}
				}
			})
		}
		id, err := NewID()
		if err != nil {
			t.Fatal("allocate segment fixture id")
		}
		if err := s.db.Exec(`INSERT INTO integrity_audit_segments(id,organization_id,first_sequence,last_sequence,first_hash,last_hash,event_count,first_event_at,last_event_at,sealed_at,canonicalization_version,key_version)
VALUES(?,?,1,1,?,?,1,?,?,?,?,?)`, id, initial.Organization.ID, strings.Repeat("a", 64), strings.Repeat("b", 64), time.Now().UTC(), time.Now().UTC(), time.Now().UTC(), audit.CanonicalizationVersion, "test-v1").Error; err != nil {
			t.Fatal("insert real retained segment marker")
		}
		snapshotAuditInventoryTestFailure(t, s, cfg, errSnapshotAuditSegments)
	})
}

func TestSnapshotAuditInventoryCanonicalInitialOrganization(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		requireMigrate(t, s)
		initial := requireInitialize(t, s)
		// A genuine small-ID organization makes +7/07 fit the SQL byte cap and
		// reference an existing organization. Thus only canonical parsing rejects
		// those cases, not overflow or a missing-organization negative control.
		org := initial.Organization
		org.ID = 7
		if err := s.db.Create(&org).Error; err != nil {
			t.Fatal("create small-ID canonical parsing fixture")
		}
		auditSnapshotTestAppend(t, s, org.ID, initial.User.ID, 1)
		for _, value := range []string{"7", "+7", "07", " 7", "7 ", "7e0"} {
			if err := s.db.Exec("UPDATE system_settings SET value_json=? WHERE setting_key='initial_organization_id'", value).Error; err != nil {
				t.Fatal("set isolated canonical initial-organization fixture")
			}
			if value != "7" {
				snapshotAuditInventoryTestFailure(t, s, cfg, audit.ErrIntegrity)
				continue
			}
			ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
			got, err := s.snapshotAuditInventory(ctx, tx)
			closeView()
			if err != nil || len(got.anchors) != 2 {
				t.Fatal("canonical small initial-organization binding refused")
			}
		}
	})
}

func TestSnapshotAuditInventoryMissingHeadAndOfflineOrphans(t *testing.T) {
	for _, mode := range []string{"missing_head", "orphan_head", "orphan_event", "zero_organization", "negative_organization"} {
		t.Run(mode, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
				requireMigrate(t, s)
				initial := requireInitialize(t, s)
				if mode == "missing_head" {
					if err := s.db.Where("organization_id=?", initial.Organization.ID).Delete(&auditChainHead{}).Error; err != nil {
						t.Fatal("delete actual organization chain head")
					}
				} else {
					snapshotAuditInventoryTestOfflineCorruption(t, s, initial, mode)
					if cfg.Driver == "sqlite" {
						var foreignKeys, ignoredChecks int
						if s.db.Raw("PRAGMA foreign_keys").Scan(&foreignKeys).Error != nil || s.db.Raw("PRAGMA ignore_check_constraints").Scan(&ignoredChecks).Error != nil || foreignKeys != 1 || ignoredChecks != 0 {
							t.Fatal("offline-corruption fixture left SQLite constraints disabled")
						}
					}
				}
				counter := &snapshotAuditInventorySigner{}
				s.auditSigner = counter
				snapshotAuditInventoryTestFailure(t, s, cfg, audit.ErrIntegrity)
				if counter.calls != 0 {
					t.Fatal("invalid organization relationship reached chain MAC verification")
				}
			})
		})
	}
}

// All bypasses are confined to eachDatabase's disposable schema/file. First
// prove the genuine constraint rejects the row, then construct actual offline
// corruption. No production connection setting or application API is relaxed.
func snapshotAuditInventoryTestOfflineCorruption(t *testing.T, s *Store, initial InitializationResult, mode string) {
	t.Helper()
	var row any
	table, constraint := "organizations", "organizations_id_check"
	switch mode {
	case "zero_organization", "negative_organization":
		org := initial.Organization
		org.ID = 0
		if mode == "negative_organization" {
			org.ID = -1
		}
		// A struct zero primary key is omitted by GORM; use explicit fixed
		// columns so this really inserts id=0, not a NOT NULL failure fixture.
		row = map[string]any{"id": org.ID, "name": org.Name, "status": org.Status,
			"timezone": org.Timezone, "quota_json": org.QuotaJSON,
			"created_at": org.CreatedAt, "updated_at": org.UpdatedAt}
	case "orphan_head":
		table, constraint = "integrity_audit_chain_heads", "integrity_audit_chain_heads_organization_id_fkey"
		row = &auditChainHead{OrganizationID: 1, EventCount: 0, KeyVersion: "test-v1", UpdatedAt: time.Now().UTC()}
	default:
		table, constraint = "integrity_audit_logs", "integrity_audit_logs_organization_id_fkey"
		var event audit.Event
		if err := s.db.Where("organization_id=?", initial.Organization.ID).First(&event).Error; err != nil {
			t.Fatal("load event to construct orphan negative control")
		}
		var err error
		event.ID, err = NewID()
		if err != nil {
			t.Fatal("allocate orphan event id")
		}
		event.OrganizationID = 1
		row = &event
	}
	if err := s.db.Table(table).Create(row).Error; err == nil {
		t.Fatal("actual positive-ID/organization FK constraint unexpectedly accepted corruption")
	}
	if s.driver == "postgres" {
		// Names are fixed above, not read from user input; current schema is the
		// isolated schema created and owned by this exact eachDatabase fixture.
		if err := s.db.Exec("ALTER TABLE " + table + " DROP CONSTRAINT " + constraint).Error; err != nil {
			t.Fatal("bypass one constraint only in disposable PostgreSQL schema")
		}
	} else {
		pragma := "PRAGMA foreign_keys"
		if table == "organizations" {
			pragma = "PRAGMA ignore_check_constraints"
		}
		value, restore := "OFF", "ON"
		if table == "organizations" {
			value, restore = "ON", "OFF"
		}
		if err := s.db.Exec(pragma + "=" + value).Error; err != nil {
			t.Fatal("prepare isolated SQLite offline-corruption fixture")
		}
		defer func() {
			if err := s.db.Exec(pragma + "=" + restore).Error; err != nil {
				t.Error("restore SQLite constraint enforcement after fixture")
			}
		}()
	}
	if err := s.db.Table(table).Create(row).Error; err != nil {
		t.Fatal("insert actual isolated orphan/nonpositive organization")
	}
}

func TestSnapshotAuditInventoryTransactionAndRepresentationGuards(t *testing.T) {
	value := snapshotAuditInventory{anchors: []auditSnapshotAnchor{{organizationID: 1234, endHash: "private-inventory-canary"}}}
	for _, input := range []any{value, &value} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if got := fmt.Sprintf(format, input); got != "[private snapshot audit inventory]" {
				t.Fatal("inventory formatting exposed owned anchors")
			}
		}
		if _, err := json.Marshal(input); err == nil {
			t.Fatal("inventory allowed JSON serialization")
		}
		if _, err := yaml.Marshal(input); err == nil {
			t.Fatal("inventory allowed YAML serialization")
		}
		output := snapshotInventoryLogText(t, input)
		if output != "[private snapshot audit inventory]" {
			t.Fatal("inventory log exposed private fields")
		}
	}
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		requireMigrate(t, s)
		requireInitialize(t, s)
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		typedNil := tx.Session(&gorm.Session{NewDB: true, Initialized: true})
		typedNil.Statement.ConnPool = (*sql.Tx)(nil)
		for _, invalid := range []*gorm.DB{nil, s.db, typedNil} {
			got, err := s.snapshotAuditInventory(ctx, invalid)
			if !errors.Is(err, ErrConfiguration) || got.anchors != nil {
				t.Fatal("inventory accepted a missing actual transaction")
			}
		}
		t.Run("bare_connection", func(t *testing.T) {
			conn, err := s.sql.Conn(ctx)
			if err != nil {
				t.Fatal("acquire actual bare inventory test connection")
			}
			defer func() { _ = conn.Close() }()
			bare := tx.Session(&gorm.Session{NewDB: true, Initialized: true})
			bare.Statement.ConnPool = conn
			if got, err := s.snapshotAuditInventory(ctx, bare); !errors.Is(err, ErrConfiguration) || got.anchors != nil {
				t.Fatal("inventory accepted bare connection as transaction")
			}
		})
		for _, missing := range []context.Context{nil, context.Background()} {
			got, err := s.snapshotAuditInventory(missing, tx)
			if !errors.Is(err, ErrConfiguration) || got.anchors != nil {
				t.Fatal("inventory accepted missing context/deadline")
			}
		}
		closeView()
		if cfg.Driver == "sqlite" {
			ctx, weak, closeWeak := auditSnapshotTestTransaction(t, cfg, nil, false)
			defer closeWeak()
			if got, err := s.snapshotAuditInventory(ctx, weak); !errors.Is(err, ErrConfiguration) || got.anchors != nil {
				t.Fatal("SQLite missing supplemental query_only accepted")
			}
		} else {
			for _, options := range []sql.TxOptions{{ReadOnly: true, Isolation: sql.LevelReadCommitted}, {ReadOnly: false, Isolation: sql.LevelRepeatableRead}} {
				ctx, weak, closeWeak := auditSnapshotTestTransaction(t, cfg, &options, true)
				got, err := s.snapshotAuditInventory(ctx, weak)
				closeWeak()
				if !errors.Is(err, ErrConfiguration) || got.anchors != nil {
					t.Fatal("PG weak isolation or writable inventory accepted")
				}
			}
		}
	})
}

func TestSnapshotAuditInventoryPostgresOuterErrorClasses(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		if cfg.Driver != "postgres" {
			return // PostgreSQL wrapper only; inventory itself has dual-database tests above.
		}
		requireMigrate(t, s)
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()
		err := s.withPostgresSnapshot(ctx, func(view *postgresSnapshot) error {
			return view.use(func(tx *gorm.DB, _ string, _ postgresSnapshotMetadata) error {
				result, err := s.snapshotAuditInventory(ctx, tx)
				if result.anchors != nil {
					t.Fatal("uninitialized database returned an audit inventory")
				}
				return err
			})
		})
		if !errors.Is(err, errSnapshotAuditNotInitialized) {
			t.Fatalf("real uninitialized inventory error lost at exported snapshot boundary: %v", err)
		}
		for _, known := range []error{errSnapshotAuditNotInitialized, errSnapshotAuditLimit, errSnapshotAuditSegments} {
			for _, throughUse := range []bool{false, true} {
				err := s.withPostgresSnapshot(ctx, func(view *postgresSnapshot) error {
					wrapped := fmt.Errorf("private-error-wrapper-canary: %w", known)
					if !throughUse {
						return wrapped
					}
					_ = view.use(func(*gorm.DB, string, postgresSnapshotMetadata) error { return wrapped })
					return nil // Consuming the error cannot clear the sticky failure.
				})
				if !errors.Is(err, known) || err.Error() != known.Error() {
					t.Fatal("closed inventory failure was lost or leaked a private wrapper")
				}
			}
		}
	})
}
