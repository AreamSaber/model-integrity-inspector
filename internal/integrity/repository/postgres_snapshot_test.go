package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"go.yaml.in/yaml/v3"
	"gorm.io/gorm"
)

func TestPostgresSnapshotExportSameViewAndLifetime(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		if cfg.Driver != "postgres" {
			called := false
			err := s.withPostgresSnapshot(ctx, func(*postgresSnapshot) error { called = true; return nil })
			if !errors.Is(err, ErrConfiguration) || called {
				t.Fatal("PostgreSQL-only primitive accepted SQLite")
			}
			return
		}
		requireMigrate(t, s)
		initial := requireInitialize(t, s)
		var retained *postgresSnapshot
		var exported string
		err := s.withPostgresSnapshot(ctx, func(view *postgresSnapshot) error {
			retained = view
			return view.use(func(tx *gorm.DB, id string, metadata postgresSnapshotMetadata) error {
				exported = id
				if !validPostgresSnapshotID(id) || metadata.ServerVersion <= 0 || metadata.TransactionStartedAtMicros <= 0 {
					t.Fatal("invalid snapshot metadata")
				}
				anchor, err := s.verifyAuditSnapshot(ctx, tx, initial.Organization.ID)
				if err != nil || anchor.eventCount != 1 {
					t.Fatal("export transaction cannot verify its original audit head")
				}
				var bounded bool
				if err := tx.Raw("SELECT current_setting('statement_timeout')::interval > interval '0 seconds' AND current_setting('statement_timeout')::interval <= interval '30 seconds' AND current_setting('lock_timeout')=current_setting('statement_timeout')").Scan(&bounded).Error; err != nil || !bounded {
					t.Fatal("actual snapshot transaction lacks bounded local timeouts")
				}
				// Commit a real signed event through a distinct live connection AFTER
				// the exported read view has been established.
				auditSnapshotTestAppend(t, s, initial.Organization.ID, initial.User.ID, 1)
				after, err := s.verifyAuditSnapshot(ctx, tx, initial.Organization.ID)
				if err != nil || after != anchor {
					t.Fatal("export transaction drifted to the later audit head")
				}
				imported, err := s.sql.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
				if err != nil {
					t.Fatal("begin independent importing transaction")
				}
				defer func() { _ = imported.Rollback() }()
				// SET TRANSACTION SNAPSHOT requires a literal, not a bind parameter.
				// Only the independently validated server-generated hex token is
				// interpolated; this is a test-only importer, never caller input.
				if _, err := imported.ExecContext(ctx, postgresSnapshotImportTestSQL(t, id)); err != nil {
					t.Fatal("import live PostgreSQL snapshot")
				}
				var count int64
				var hash string
				if err := imported.QueryRowContext(ctx, "SELECT event_count,event_hash FROM integrity_audit_chain_heads WHERE organization_id=$1", initial.Organization.ID).Scan(&count, &hash); err != nil || count != anchor.eventCount || hash != anchor.endHash {
					t.Fatal("independent importer did not preserve snapshot audit identity")
				}
				if err := imported.QueryRowContext(ctx, "SELECT count(*) FROM integrity_audit_logs WHERE organization_id=$1", initial.Organization.ID).Scan(&count); err != nil || count != 1 {
					t.Fatal("independent importer read later events")
				}
				if err := imported.Commit(); err != nil {
					t.Fatal("close independent importing transaction")
				}
				return nil
			})
		})
		if err != nil {
			t.Fatalf("valid exported snapshot failed: %v", err)
		}
		postgresSnapshotTestClosed(t, retained)
		postgresSnapshotTestExpired(t, s, exported)
		tenant, _ := s.WithOrganization(ctx, initial.Organization.ID)
		live, err := tenant.VerifyAuditFull()
		if err != nil || live.EventCount != 2 || live.VerifiedCount != 2 {
			t.Fatal("snapshot handling altered the independently committed live chain")
		}
	})
}

func postgresSnapshotImportTestSQL(t *testing.T, id string) string {
	t.Helper()
	if !validPostgresSnapshotID(id) {
		t.Fatal("unsafe snapshot test token")
	}
	return "SET TRANSACTION SNAPSHOT '" + id + "'"
}

func postgresSnapshotTestClosed(t *testing.T, view *postgresSnapshot) {
	t.Helper()
	if view == nil || view.active || view.tx != nil || view.id != "" || view.metadata != (postgresSnapshotMetadata{}) {
		t.Fatal("snapshot retained transaction or export metadata after return")
	}
	called := false
	if err := view.use(func(*gorm.DB, string, postgresSnapshotMetadata) error { called = true; return nil }); !errors.Is(err, errPostgresSnapshotClosed) || called {
		t.Fatal("retained snapshot callback remained usable")
	}
}

// A canceled database/sql transaction can roll back asynchronously. Observe
// the SERVER until it explicitly rejects the export, with a separate bounded
// context; a canceled query/connection failure is not evidence of invalidation.
func postgresSnapshotTestExpired(t *testing.T, s *Store, id string) {
	t.Helper()
	statement := postgresSnapshotImportTestSQL(t, id)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		late, err := s.sql.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
		if err != nil {
			t.Fatal("begin actual late import observation")
		}
		_, importErr := late.ExecContext(ctx, statement)
		if err := late.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			t.Fatal("close late import observation")
		}
		if importErr != nil {
			var pgErr *pgconn.PgError
			// PostgreSQL 18 ImportSnapshot reports UNDEFINED_OBJECT (42704)
			// for a well-formed identifier whose export file no longer exists;
			// INVALID_PARAMETER_VALUE (22023) would only prove bad input syntax.
			if !errors.As(importErr, &pgErr) || pgErr.Code != "42704" {
				if pgErr != nil && len(pgErr.Code) == 5 && strings.IndexFunc(pgErr.Code, func(r rune) bool { return (r < '0' || r > '9') && (r < 'A' || r > 'Z') }) == -1 {
					t.Fatalf("late import rejected with unexpected SQLSTATE %s", pgErr.Code)
				}
				t.Fatal("late import failed without server invalid-snapshot evidence")
			}
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("export remained importable after bounded transaction cleanup")
		case <-tick.C:
		}
	}
}

func TestPostgresSnapshotFailureCleanupAndReadOnly(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		if cfg.Driver != "postgres" {
			return // SQLite rejection is asserted by ExportSameViewAndLifetime.
		}
		requireMigrate(t, s)
		initial := requireInitialize(t, s)
		for _, mode := range []string{"callback_error", "swallowed_use_error", "nil_use", "write_rejected", "early_rollback", "cancel", "panic"} {
			t.Run(mode, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				var retained *postgresSnapshot
				var exported string
				var err error
				panicked := false
				func() {
					defer func() {
						if recovered := recover(); recovered != nil {
							if recovered != "test-snapshot-panic" {
								panic(recovered)
							}
							panicked = true
						}
					}()
					err = s.withPostgresSnapshot(ctx, func(view *postgresSnapshot) error {
						retained = view
						if err := view.use(func(_ *gorm.DB, id string, _ postgresSnapshotMetadata) error { exported = id; return nil }); err != nil {
							return err
						}
						switch mode {
						case "callback_error":
							return errors.New("private-callback-canary")
						case "swallowed_use_error":
							_ = view.use(func(*gorm.DB, string, postgresSnapshotMetadata) error { return ErrConflict })
							called := false
							if got := view.use(func(*gorm.DB, string, postgresSnapshotMetadata) error { called = true; return nil }); !errors.Is(got, ErrConflict) || called {
								t.Fatal("failed snapshot resumed consumption")
							}
						case "nil_use":
							_ = view.use(nil)
						case "write_rejected":
							return view.use(func(tx *gorm.DB, _ string, _ postgresSnapshotMetadata) error {
								if got := tx.Exec("UPDATE integrity_audit_chain_heads SET event_count=99 WHERE organization_id=?", initial.Organization.ID).Error; got == nil {
									t.Fatal("exporting transaction accepted actual business write")
								}
								return nil // Aborted transaction must still fail outer Commit.
							})
						case "early_rollback":
							return view.use(func(tx *gorm.DB, _ string, _ postgresSnapshotMetadata) error { return tx.Rollback().Error })
						case "cancel":
							cancel()
							_ = view.use(func(*gorm.DB, string, postgresSnapshotMetadata) error {
								t.Fatal("canceled view invoked callback")
								return nil
							})
						case "panic":
							panic("test-snapshot-panic")
						}
						return nil
					})
				}()
				if mode == "panic" {
					if !panicked {
						t.Fatal("callback panic was swallowed")
					}
				} else {
					want := ErrUnavailable
					switch mode {
					case "swallowed_use_error":
						want = ErrConflict
					case "nil_use":
						want = ErrConfiguration
					case "cancel":
						want = errPostgresSnapshotCanceled
					}
					if !errors.Is(err, want) || strings.Contains(fmt.Sprint(err), "canary") {
						t.Fatalf("failure did not propagate a closed error: %v", err)
					}
				}
				postgresSnapshotTestClosed(t, retained)
				postgresSnapshotTestExpired(t, s, exported)
				var count int64
				if got := s.db.Raw("SELECT event_count FROM integrity_audit_chain_heads WHERE organization_id=?", initial.Organization.ID).Scan(&count).Error; got != nil || count != 1 {
					t.Fatal("failed snapshot changed live data or leaked an active transaction")
				}
			})
		}
	})
}

func TestPostgresSnapshotRequestAndRepresentationGuards(t *testing.T) {
	for _, id := range []string{"0-0-1", "00000003-0000001B-1", "abc-DEF-123"} {
		if !validPostgresSnapshotID(id) {
			t.Fatal("valid bounded server token refused")
		}
	}
	for _, id := range []string{"", "a-b", "a-b-c-d", "-a-b", "a--b", "a-b-", "a-b-z", "a-b-'", "a-b-1\n", "a-b-1;", "a-b-1/", strings.Repeat("a", 125) + "-b-c"} {
		if validPostgresSnapshotID(id) {
			t.Fatal("unsafe or oversized server token accepted")
		}
	}
	view := &postgresSnapshot{id: "private-snapshot-canary"}
	for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
		if got := fmt.Sprintf(format, view); got != "[private PostgreSQL snapshot]" {
			t.Fatal("snapshot formatting exposed metadata")
		}
	}
	if _, err := json.Marshal(view); err == nil {
		t.Fatal("snapshot allowed JSON serialization")
	}
	if _, err := yaml.Marshal(view); err == nil {
		t.Fatal("snapshot allowed YAML serialization")
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("test", "snapshot", view)
	if strings.Contains(buf.String(), "canary") || !strings.Contains(buf.String(), "private PostgreSQL snapshot") {
		t.Fatal("snapshot logging exposed metadata")
	}
	var absent *postgresSnapshot
	if !errors.Is(absent.use(nil), errPostgresSnapshotClosed) || !errors.Is(view.use(nil), errPostgresSnapshotClosed) {
		t.Fatal("nil/inactive view did not reject consumption")
	}
	var s *Store
	if !errors.Is(s.withPostgresSnapshot(t.Context(), nil), ErrConfiguration) {
		t.Fatal("nil snapshot request not rejected")
	}
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		if cfg.Driver != "postgres" {
			return
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		long, longCancel := context.WithTimeout(t.Context(), maxMaintenanceDuration+time.Hour)
		defer longCancel()
		canceled, stop := context.WithCancel(ctx)
		stop()
		for _, tc := range []struct {
			ctx  context.Context
			want error
		}{{nil, ErrConfiguration}, {context.Background(), ErrConfiguration}, {long, ErrConfiguration}, {canceled, errPostgresSnapshotCanceled}} {
			called := false
			if err := s.withPostgresSnapshot(tc.ctx, func(*postgresSnapshot) error { called = true; return nil }); !errors.Is(err, tc.want) || called {
				t.Fatal("invalid request reached consumer")
			}
		}
		if !errors.Is(s.withPostgresSnapshot(ctx, nil), ErrConfiguration) {
			t.Fatal("nil consumer accepted")
		}
	})
}

func TestPostgresSnapshotLocalSettingsAndPoolDeadline(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		if cfg.Driver != "postgres" {
			return
		}
		s.sql.SetMaxOpenConns(1)
		s.sql.SetMaxIdleConns(1)
		type settings struct {
			PID                                                int
			StatementTimeout, LockTimeout, Isolation, ReadOnly string
		}
		const query = "SELECT pg_backend_pid() AS pid,current_setting('statement_timeout') AS statement_timeout,current_setting('lock_timeout') AS lock_timeout,current_setting('transaction_isolation') AS isolation,current_setting('transaction_read_only') AS read_only"
		var before, after settings
		if err := s.db.Raw(query).Scan(&before).Error; err != nil {
			t.Fatal("read baseline connection settings")
		}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		if err := s.withPostgresSnapshot(ctx, func(view *postgresSnapshot) error {
			return view.use(func(tx *gorm.DB, _ string, _ postgresSnapshotMetadata) error {
				var actual settings
				if err := tx.Raw(query).Scan(&actual).Error; err != nil || actual.PID != before.PID || actual.Isolation != "repeatable read" || actual.ReadOnly != "on" {
					t.Fatal("snapshot did not use the controlled connection with actual RR/RO settings")
				}
				return nil
			})
		}); err != nil {
			t.Fatalf("local settings snapshot: %v", err)
		}
		if err := s.db.Raw(query).Scan(&after).Error; err != nil || after != before {
			t.Fatal("snapshot leaked settings beyond its transaction on the SAME physical connection")
		}
		// Hold the only actual pool connection: a bounded request must fail
		// while acquiring a connection, without invoking an export consumer.
		held, err := s.sql.Conn(ctx)
		if err != nil {
			t.Fatal("acquire pool exhaustion fixture")
		}
		defer func() { _ = held.Close() }()
		short, stop := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer stop()
		started, called := time.Now(), false
		err = s.withPostgresSnapshot(short, func(*postgresSnapshot) error { called = true; return nil })
		if !errors.Is(err, errPostgresSnapshotCanceled) || called || time.Since(started) > 2*time.Second {
			t.Fatal("pool acquisition ignored deadline or invoked consumer")
		}
	})
}

func TestPostgresSnapshotCancelsActualInFlightQuery(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		if cfg.Driver != "postgres" {
			return
		}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		var retained *postgresSnapshot
		observed := false
		err := s.withPostgresSnapshot(ctx, func(view *postgresSnapshot) error {
			retained = view
			return view.use(func(tx *gorm.DB, _ string, _ postgresSnapshotMetadata) error {
				var pid int
				if err := tx.Raw("SELECT pg_backend_pid()").Scan(&pid).Error; err != nil {
					t.Fatal("obtain snapshot test backend identity")
				}
				watchCtx, stop := context.WithTimeout(t.Context(), 3*time.Second)
				defer stop()
				ready := make(chan bool, 1)
				go func() {
					tick := time.NewTicker(5 * time.Millisecond)
					defer tick.Stop()
					for {
						var sleeping bool
						err := s.sql.QueryRowContext(watchCtx, "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE pid=$1 AND wait_event='PgSleep')", pid).Scan(&sleeping)
						if err == nil && sleeping {
							cancel() // Cancel only AFTER the server is executing the query.
							ready <- true
							return
						}
						select {
						case <-watchCtx.Done():
							cancel()
							ready <- false
							return
						case <-tick.C:
						}
					}
				}()
				started := time.Now()
				queryErr := tx.Exec("SELECT pg_catalog.pg_sleep(10)").Error
				observed = <-ready
				if queryErr == nil || !observed || time.Since(started) > 2*time.Second {
					t.Fatal("cancel did not interrupt the observed live query within bound")
				}
				return queryErr
			})
		})
		if !errors.Is(err, errPostgresSnapshotCanceled) || !observed {
			t.Fatalf("actual canceled query did not return closed cancellation: %v", err)
		}
		postgresSnapshotTestClosed(t, retained)
	})
}
