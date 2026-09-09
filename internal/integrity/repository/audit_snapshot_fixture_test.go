package repository

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// This fixture opens a NEW dedicated connection; it never changes the live
// Store pool's pragmas. SQLite native RO is checked before this exact BeginTx.
func auditSnapshotTestTransaction(t *testing.T, cfg Config, options *sql.TxOptions, queryOnly bool) (context.Context, *gorm.DB, func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	driver, dsn := "pgx", cfg.DSN
	if cfg.Driver == "sqlite" {
		driver = "sqlite"
		path := filepath.ToSlash(cfg.DSN)
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		u := url.URL{Scheme: "file", Path: path}
		q := url.Values{"mode": {"ro"}, "_pragma": {"busy_timeout(0)"}}
		if queryOnly {
			q.Add("_pragma", "query_only(1)")
		}
		u.RawQuery = q.Encode()
		dsn = u.String()
	}
	pool, err := sql.Open(driver, dsn)
	if err != nil {
		cancel()
		t.Fatal("open dedicated audit snapshot test pool")
	}
	pool.SetMaxOpenConns(1)
	pool.SetMaxIdleConns(1)
	t.Cleanup(func() { _ = pool.Close(); cancel() })
	conn, err := pool.Conn(ctx)
	if err != nil {
		t.Fatal("acquire dedicated audit snapshot connection")
	}
	t.Cleanup(func() { _ = conn.Close() })
	if cfg.Driver == "sqlite" {
		err = conn.Raw(func(raw any) error {
			actual, ok := raw.(interface{ IsReadOnly(string) (bool, error) })
			if !ok {
				return ErrConfiguration
			}
			readOnly, err := actual.IsReadOnly("main")
			if err != nil || !readOnly {
				return ErrConfiguration
			}
			return nil
		})
		if err != nil {
			t.Fatal("SQLite snapshot fixture is not physically read-only")
		}
	}
	if options == nil {
		options = &sql.TxOptions{ReadOnly: true}
		if cfg.Driver == "postgres" {
			options.Isolation = sql.LevelRepeatableRead
		}
	}
	actual, err := conn.BeginTx(ctx, options)
	if err != nil {
		t.Fatal("begin actual audit snapshot transaction")
	}
	t.Cleanup(func() { _ = actual.Rollback() })
	dialector := postgres.New(postgres.Config{Conn: actual})
	if cfg.Driver == "sqlite" {
		dialector = sqlite.New(sqlite.Config{DriverName: "sqlite", Conn: actual})
	}
	tx, err := gorm.Open(dialector, &gorm.Config{DisableAutomaticPing: true, SkipDefaultTransaction: true, Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal("adapt caller-owned audit snapshot transaction")
	}
	closed := false
	closeView := func() {
		if closed {
			return
		}
		closed = true
		if err := actual.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			t.Error("rollback caller-owned audit snapshot transaction")
		}
		if err := conn.Close(); err != nil {
			t.Error("close dedicated audit snapshot connection")
		}
		if err := pool.Close(); err != nil {
			t.Error("close dedicated audit snapshot pool")
		}
		cancel()
	}
	t.Cleanup(closeView)
	return ctx, tx, closeView
}

func auditSnapshotTestAppend(t *testing.T, s *Store, orgID, userID int64, count int) {
	t.Helper()
	ctx := testActorContext(t, userID)
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for range count {
			if err := s.appendAudit(ctx, tx, orgID, AuditCommand{Action: "test.snapshot", ObjectType: "test", ObjectID: "snapshot", Result: "success"}, nil); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal("append real signed snapshot audit fixture")
	}
}
