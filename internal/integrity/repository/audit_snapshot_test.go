package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func TestAuditSnapshotSameViewAndBoundedPages(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		requireMigrate(t, s)
		initial := requireInitialize(t, s)
		auditSnapshotTestAppend(t, s, initial.Organization.ID, initial.User.ID, 501)
		other := initial.Organization
		var err error
		other.ID, err = NewID()
		if err != nil {
			t.Fatal("allocate second snapshot organization")
		}
		other.Name = "Second snapshot organization"
		if err := s.db.Create(&other).Error; err != nil {
			t.Fatal("create second snapshot organization")
		}
		auditSnapshotTestAppend(t, s, other.ID, initial.User.ID, 1)
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		var pageSizes []int
		if err := tx.Callback().Query().After("gorm:query").Register("snapshot_observe_bounded_pages", func(q *gorm.DB) {
			if events, ok := q.Statement.Dest.(*[]audit.Event); ok && q.Error == nil {
				pageSizes = append(pageSizes, len(*events))
			}
		}); err != nil {
			t.Fatal("register actual page observer")
		}
		// Foreign caller clauses must not contaminate the internal full-chain read.
		anchor, err := s.verifyAuditSnapshot(ctx, tx.Where("1=0").Limit(1), initial.Organization.ID)
		if err != nil || anchor.eventCount != 502 || anchor.organizationID != initial.Organization.ID || anchor.canonicalizationVersion != audit.CanonicalizationVersion || anchor.keyVersion != "test-v1" {
			t.Fatalf("snapshot full chain: %v", err)
		}
		if !reflect.DeepEqual(pageSizes, []int{2, 500, 2}) {
			t.Fatalf("actual tail/full page sizes: %v", pageSizes)
		}
		var head auditChainHead
		if err := tx.Where("organization_id=?", initial.Organization.ID).First(&head).Error; err != nil || anchor.endHash != head.EventHash {
			t.Fatal("returned anchor differs from the same snapshot head")
		}
		second, err := s.verifyAuditSnapshot(ctx, tx, other.ID)
		if err != nil || second.eventCount != 1 || second.organizationID != other.ID || second.endHash == anchor.endHash {
			t.Fatal("second organization was mixed with first chain")
		}
		// This independent live connection must append while the RO view is held:
		// a PG SHARE head lock would fail, and reading the Store pool would drift.
		auditSnapshotTestAppend(t, s, initial.Organization.ID, initial.User.ID, 1)
		after, err := s.verifyAuditSnapshot(ctx, tx, initial.Organization.ID)
		if err != nil || after != anchor {
			t.Fatal("snapshot followed a live append instead of its established head")
		}
		tenant, _ := s.WithOrganization(t.Context(), initial.Organization.ID)
		live, err := tenant.VerifyAuditFull()
		if err != nil || live.EventCount != 503 || live.VerifiedCount != 503 {
			t.Fatal("original public full verification did not see the independent append")
		}
		tail, err := tenant.VerifyAuditTail()
		if err != nil || tail.VerifiedCount != 2 || tail.EventCount != 503 {
			t.Fatal("original public tail behavior changed")
		}
		var count int64
		if err := tx.Table("integrity_audit_logs").Where("organization_id=?", initial.Organization.ID).Count(&count).Error; err != nil || count != 502 {
			t.Fatal("validator ended caller transaction or changed its read view")
		}
		closeView()
		if got, err := s.verifyAuditSnapshot(ctx, tx, initial.Organization.ID); err == nil || got != (auditSnapshotAnchor{}) {
			t.Fatal("closed snapshot returned an anchor")
		}
	})
}

func TestAuditSnapshotActualReadOnlyAndTransactionGuards(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		requireMigrate(t, s)
		initial := requireInitialize(t, s)
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		if err := tx.WithContext(ctx).Exec("UPDATE integrity_audit_chain_heads SET event_count=event_count WHERE organization_id=?", initial.Organization.ID).Error; err == nil {
			t.Fatal("genuine read-only snapshot accepted an actual write")
		}
		closeView() // PG's real RO rejection aborts this transaction.
		ctx, tx, closeView = auditSnapshotTestTransaction(t, cfg, nil, true)
		if anchor, err := s.verifyAuditSnapshot(ctx, tx, initial.Organization.ID); err != nil || anchor.eventCount != 1 {
			t.Fatal("valid native read-only snapshot refused")
		}
		typedNil := tx.Session(&gorm.Session{NewDB: true, Initialized: true})
		typedNil.Statement.ConnPool = (*sql.Tx)(nil)
		cases := []struct {
			name string
			ctx  context.Context
			tx   *gorm.DB
			org  int64
			want error
		}{
			{"pool", ctx, s.db, initial.Organization.ID, ErrConfiguration},
			{"typed_nil_sql_transaction", ctx, typedNil, initial.Organization.ID, ErrConfiguration},
			{"nil_tx", ctx, nil, initial.Organization.ID, ErrConfiguration},
			{"nil_context", nil, tx, initial.Organization.ID, ErrConfiguration},
			{"no_deadline", context.Background(), tx, initial.Organization.ID, ErrConfiguration},
			{"invalid_org", ctx, tx, 0, ErrOrganizationScope},
			{"missing_org", ctx, tx, -1, ErrOrganizationScope},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				anchor, err := s.verifyAuditSnapshot(tc.ctx, tc.tx, tc.org)
				if !errors.Is(err, tc.want) || anchor != (auditSnapshotAnchor{}) {
					t.Fatalf("guard returned anchor or wrong closed error: %v", err)
				}
			})
		}
		t.Run("bare_connection", func(t *testing.T) {
			conn, err := s.sql.Conn(ctx)
			if err != nil {
				t.Fatal("acquire actual bare connection for transaction guard")
			}
			defer func() {
				if err := conn.Close(); err != nil {
					t.Error("release bare connection guard fixture")
				}
			}()
			bare := tx.Session(&gorm.Session{NewDB: true, Initialized: true})
			bare.Statement.ConnPool = conn
			anchor, err := s.verifyAuditSnapshot(ctx, bare, initial.Organization.ID)
			if !errors.Is(err, ErrConfiguration) || anchor != (auditSnapshotAnchor{}) {
				t.Fatal("actual bare sql.Conn accepted as stable caller transaction")
			}
		})
		wrong := *s
		wrong.driver = "wrong"
		if anchor, err := wrong.verifyAuditSnapshot(ctx, tx, initial.Organization.ID); !errors.Is(err, ErrConfiguration) || anchor != (auditSnapshotAnchor{}) {
			t.Fatal("wrong dialect accepted")
		}
		closeView()
		if cfg.Driver == "sqlite" {
			ctx, tx, closeView = auditSnapshotTestTransaction(t, cfg, nil, false)
			if anchor, err := s.verifyAuditSnapshot(ctx, tx, initial.Organization.ID); !errors.Is(err, ErrConfiguration) || anchor != (auditSnapshotAnchor{}) {
				t.Fatal("missing query_only supplemental guard accepted")
			}
			closeView()
		} else {
			for _, options := range []sql.TxOptions{{ReadOnly: true, Isolation: sql.LevelReadCommitted}, {ReadOnly: false, Isolation: sql.LevelRepeatableRead}} {
				ctx, tx, closeView = auditSnapshotTestTransaction(t, cfg, &options, true)
				if anchor, err := s.verifyAuditSnapshot(ctx, tx, initial.Organization.ID); !errors.Is(err, ErrConfiguration) || anchor != (auditSnapshotAnchor{}) {
					t.Fatal("PG weak isolation or writable transaction accepted")
				}
				closeView()
			}
			ctx, tx, closeView = auditSnapshotTestTransaction(t, cfg, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelSerializable}, true)
			if anchor, err := s.verifyAuditSnapshot(ctx, tx, initial.Organization.ID); err != nil || anchor.eventCount != 1 {
				t.Fatal("PG genuine serializable read-only transaction refused")
			}
			// Executing the former public head-lock query in this actual RO view
			// is a negative control: merely reusing VerifyAuditFull is not viable.
			if err := tx.Exec("SELECT organization_id FROM integrity_audit_chain_heads WHERE organization_id=? FOR SHARE", initial.Organization.ID).Error; err == nil {
				t.Fatal("PG read-only negative-control SHARE query unexpectedly allowed")
			}
			closeView()
		}
	})
}

func TestAuditSnapshotSecondPageTamperPreservesPublicPartialResult(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		requireMigrate(t, s)
		initial := requireInitialize(t, s)
		auditSnapshotTestAppend(t, s, initial.Organization.ID, initial.User.ID, 504)
		tenant, _ := s.WithOrganization(t.Context(), initial.Organization.ID)
		before, err := tenant.VerifyAuditFull()
		if err != nil || before.EventCount != 505 || before.VerifiedCount != 505 || before.LastEventAt == nil {
			t.Fatal("genuine 505-event chain failed original public verification")
		}
		changed := s.db.Model(&audit.Event{}).Where("organization_id=? AND sequence=501", initial.Organization.ID).Update("action", "test.second_page_tamper")
		if changed.Error != nil || changed.RowsAffected != 1 {
			t.Fatal("corrupt exactly the first event in the second 500-event page")
		}
		// Negative control: the last two records are genuine and therefore the
		// original tail-only algorithm cannot detect this older corruption.
		tail, err := tenant.VerifyAuditTail()
		if err != nil || tail.EventCount != 505 || tail.VerifiedCount != 2 || tail.LastEventAt == nil || !tail.LastEventAt.Equal(*before.LastEventAt) {
			t.Fatal("second-page negative control unexpectedly affected the tail")
		}
		full, err := tenant.VerifyAuditFull()
		if !errors.Is(err, audit.ErrIntegrity) || full.OrganizationID != initial.Organization.ID || full.EventCount != 505 || full.VerifiedCount != 500 || full.LastEventAt == nil || !full.LastEventAt.Equal(*before.LastEventAt) {
			t.Fatal("public full-chain failure lost its existing partial diagnostic semantics")
		}
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		var pageSizes []int
		if err := tx.Callback().Query().After("gorm:query").Register("snapshot_observe_second_page_tamper", func(q *gorm.DB) {
			if events, ok := q.Statement.Dest.(*[]audit.Event); ok && q.Error == nil {
				pageSizes = append(pageSizes, len(*events))
			}
		}); err != nil {
			t.Fatal("register second-page observer")
		}
		anchor, err := s.verifyAuditSnapshot(ctx, tx, initial.Organization.ID)
		if !errors.Is(err, audit.ErrIntegrity) || anchor != (auditSnapshotAnchor{}) || !reflect.DeepEqual(pageSizes, []int{2, 500, 5}) {
			t.Fatalf("snapshot failed to reject actual second-page corruption: %v; page sizes %v", err, pageSizes)
		}
	})
}

func TestAuditSnapshotTamperingZeroAnchor(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		requireMigrate(t, s)
		initial := requireInitialize(t, s)
		auditSnapshotTestAppend(t, s, initial.Organization.ID, initial.User.ID, 3)
		var head auditChainHead
		var events []audit.Event
		if s.db.Where("organization_id=?", initial.Organization.ID).First(&head).Error != nil || s.db.Where("organization_id=?", initial.Organization.ID).Order("sequence").Find(&events).Error != nil || len(events) != 4 {
			t.Fatal("load signed tamper fixture")
		}
		for _, mode := range []string{"middle_content", "middle_missing", "tail_missing", "head_missing", "head_hash", "head_key", "previous_hash", "canonical", "oversized_action", "oversized_head"} {
			t.Run(mode, func(t *testing.T) {
				var err error
				switch mode {
				case "middle_missing":
					err = s.db.Delete(&events[0]).Error
				case "tail_missing":
					err = s.db.Delete(&events[3]).Error
				case "head_missing":
					err = s.db.Where("organization_id=?", initial.Organization.ID).Delete(&auditChainHead{}).Error
				case "head_hash":
					err = s.db.Model(&auditChainHead{}).Where("organization_id=?", initial.Organization.ID).Update("event_hash", strings.Repeat("0", 64)).Error
				case "head_key":
					err = s.db.Model(&auditChainHead{}).Where("organization_id=?", initial.Organization.ID).Update("key_version", "missing-history").Error
				case "oversized_head":
					err = s.db.Model(&auditChainHead{}).Where("organization_id=?", initial.Organization.ID).Update("event_hash", strings.Repeat("x", 1<<20)).Error
				default:
					column, value := "action", "test.tamper"
					if mode == "previous_hash" {
						column, value = "previous_hash", strings.Repeat("f", 64)
					}
					if mode == "canonical" {
						column, value = "canonicalization_version", "unsupported-version"
					}
					if mode == "oversized_action" {
						value = strings.Repeat("x", 1<<20)
					}
					err = s.db.Model(&audit.Event{}).Where("id=?", events[0].ID).Update(column, value).Error
				}
				if err != nil {
					t.Fatal("apply isolated test audit corruption")
				}
				defer func() {
					if s.db.Where("organization_id=?", initial.Organization.ID).Delete(&audit.Event{}).Error != nil || s.db.Create(&events).Error != nil || s.db.Where("organization_id=?", initial.Organization.ID).Delete(&auditChainHead{}).Error != nil || s.db.Create(&head).Error != nil {
						t.Error("restore signed audit fixture")
					}
				}()
				ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
				defer closeView()
				if got, err := s.verifyAuditSnapshot(ctx, tx, initial.Organization.ID); !errors.Is(err, audit.ErrIntegrity) || got != (auditSnapshotAnchor{}) {
					t.Fatalf("corrupt chain returned anchor or unexpected error: %v", err)
				}
			})
		}
	})
}

type auditSnapshotCancelSigner struct {
	calls   int
	cancel  context.CancelFunc
	missing bool
}

func (*auditSnapshotCancelSigner) ActiveVersion() string { return "new-active-not-the-original-key" }
func (s *auditSnapshotCancelSigner) AuditMAC(version string, message []byte) ([]byte, error) {
	s.calls++
	if s.missing {
		return nil, errors.New("private-history-key-canary")
	}
	if s.calls == 503 && s.cancel != nil {
		s.cancel()
	}
	return testAuditSigner{}.AuditMAC(version, message)
}

func TestAuditSnapshotCancellationSignerAndEmptyChain(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		requireMigrate(t, s)
		initial := requireInitialize(t, s)
		auditSnapshotTestAppend(t, s, initial.Organization.ID, initial.User.ID, 501)
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		original := s.auditSigner
		defer func() { s.auditSigner = original }()
		for _, signer := range []audit.MAC{nil, &auditSnapshotCancelSigner{missing: true}} {
			s.auditSigner = signer
			got, err := s.verifyAuditSnapshot(ctx, tx, initial.Organization.ID)
			if !errors.Is(err, audit.ErrUnavailable) || got != (auditSnapshotAnchor{}) || strings.Contains(fmt.Sprint(err), "canary") {
				t.Fatal("missing signing capability exposed anchor or private detail")
			}
		}
		// Historical head key is retained, never replaced by ActiveVersion.
		s.auditSigner = &auditSnapshotCancelSigner{}
		got, err := s.verifyAuditSnapshot(ctx, tx, initial.Organization.ID)
		if err != nil || got.keyVersion != "test-v1" {
			t.Fatal("verified snapshot rewrote the historical head key")
		}
		cancelCtx, cancel := context.WithCancel(ctx)
		signer := &auditSnapshotCancelSigner{cancel: cancel}
		s.auditSigner = signer
		got, err = s.verifyAuditSnapshot(cancelCtx, tx, initial.Organization.ID)
		cancel()
		if !errors.Is(err, ErrUnavailable) || got != (auditSnapshotAnchor{}) || signer.calls < 503 {
			t.Fatal("cancel during second page returned success or partial anchor")
		}
		s.auditSigner = original
		got, err = s.verifyAuditSnapshot(ctx, tx, initial.Organization.ID)
		if err != nil || got.eventCount != 502 {
			t.Fatal("child cancellation closed the caller-owned transaction")
		}
		closeView()
		if s.db.Where("organization_id=?", initial.Organization.ID).Delete(&audit.Event{}).Error != nil || s.db.Model(&auditChainHead{}).Where("organization_id=?", initial.Organization.ID).Updates(map[string]any{"event_count": 0, "event_hash": "", "key_version": "test-v1"}).Error != nil {
			t.Fatal("construct actual empty-chain fixture")
		}
		ctx, tx, closeView = auditSnapshotTestTransaction(t, cfg, nil, true)
		got, err = s.verifyAuditSnapshot(ctx, tx, initial.Organization.ID)
		if err != nil || got.eventCount != 0 || got.endHash != "" || got.keyVersion != "test-v1" || got.canonicalizationVersion != audit.CanonicalizationVersion {
			t.Fatal("empty chain changed existing semantics or invented an observed event")
		}
		closeView()
	})
}

func TestAuditSnapshotAnchorProtectedRepresentations(t *testing.T) {
	anchor := auditSnapshotAnchor{organizationID: 1234, eventCount: 5678, endHash: "private-anchor-canary", keyVersion: "private-key-canary", canonicalizationVersion: audit.CanonicalizationVersion}
	for _, value := range []any{anchor, &anchor} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if got := fmt.Sprintf(format, value); got != "[private audit snapshot anchor]" {
				t.Fatal("anchor format exposed fields")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("anchor serialized to JSON")
		}
		if _, err := yaml.Marshal(value); err == nil {
			t.Fatal("anchor serialized to YAML")
		}
		var buf bytes.Buffer
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("test", "anchor", value)
		if strings.Contains(buf.String(), "canary") || strings.Contains(buf.String(), "1234") || !strings.Contains(buf.String(), "private audit snapshot anchor") {
			t.Fatal("anchor logged private fields")
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	var s *Store
	if anchor, err := s.verifyAuditSnapshot(ctx, nil, 1); !errors.Is(err, ErrConfiguration) || anchor != (auditSnapshotAnchor{}) {
		t.Fatal("nil receiver did not fail closed")
	}
}
