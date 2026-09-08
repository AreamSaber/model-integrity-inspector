package repository

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strconv"
	"time"

	"gorm.io/gorm"
)

// Only maintenance coordinator calls use this adapter. Ordinary admission,
// queue, and business transactions retain the Store's original 5000ms policy.
// SQLite's native busy handler can keep sleeping after sqlite3_interrupt, so
// a two-second coordinator context alone does not bound BEGIN IMMEDIATE.
func (s *Store) maintenanceTransaction(ctx context.Context, operation func(*gorm.DB) error) (result error) {
	if ctx == nil || operation == nil {
		return ErrConfiguration
	}
	if s.driver != "sqlite" {
		return s.db.WithContext(ctx).Transaction(operation)
	}
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return ErrConfiguration
	}
	conn, err := s.sql.Conn(ctx)
	if err != nil {
		return err
	}
	// Session copies Config and, because Context is supplied, invokes the real
	// Statement.clone(). Never copy Statement by value: it contains a sync.Map.
	// Keep an explicit private Config too; neither Store ConnPool may change.
	tx := s.db.Session(&gorm.Session{NewDB: true, Context: ctx})
	privateConfig := *tx.Config
	tx.Config = &privateConfig
	tx.ConnPool, tx.Statement.ConnPool, tx.Statement.DB = conn, conn, tx
	defer func() {
		// This context is exclusively cleanup after Transaction has returned.
		// No business work or new attempt is continued after cancellation.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		cleanDB := tx.Session(&gorm.Session{NewDB: true, Context: cleanup})
		if err := cleanDB.Exec("PRAGMA busy_timeout = 5000").Error; err != nil {
			// Never return a modified connection to the pool. Raw's ErrBadConn
			// contract physically discards it, even if logical Close follows.
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			result = ErrUnavailable
		}
		if err := conn.Close(); err != nil && !errors.Is(err, sql.ErrConnDone) {
			result = ErrUnavailable
		}
	}()
	var original int64
	if err := tx.Raw("PRAGMA busy_timeout").Scan(&original).Error; err != nil {
		return err
	}
	if original != 5000 {
		return ErrUnavailable
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return context.DeadlineExceeded
	}
	// Integer-only, capped by the original coordinator deadline; never a
	// caller-supplied SQL fragment or a global/pool setting.
	waitMillis := min(int64(2000), remaining.Milliseconds())
	if waitMillis < 1 {
		return context.DeadlineExceeded
	}
	// #nosec G202 -- validated integer in [1,2000], no external SQL input.
	if err := tx.Exec("PRAGMA busy_timeout = " + strconv.FormatInt(waitMillis, 10)).Error; err != nil {
		return err
	}
	return tx.Transaction(operation) // Existing DSN still enforces BEGIN IMMEDIATE.
}
