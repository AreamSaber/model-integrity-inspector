package repository

import (
	"context"
	"errors"
	"strings"
	"testing"

	"gorm.io/gorm"
)

func TestRunVersionNarrowScopedAndCurrent(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 1)
		record, err := tenant.CreateRun(plan, policy, "version-test")
		if err != nil {
			t.Fatal(err)
		}
		// Inspect the actual GORM query, not just an output DTO that could hide
		// an unnecessarily loaded S2 snapshot. The query is never printed.
		queried, narrow := false, true
		callback := "test:run_version_narrow"
		if err := store.db.Callback().Query().After("gorm:query").Register(callback, func(tx *gorm.DB) {
			queried = true
			sql := strings.ToLower(tx.Statement.SQL.String())
			narrow = narrow && len(tx.Statement.Selects) == 3 && !strings.Contains(sql, "config_snapshot") && !strings.Contains(sql, "request_key") && !strings.Contains(sql, "select *")
		}); err != nil {
			t.Fatal(err)
		}
		got, err := tenant.GetRunVersion(record.ID)
		if err := store.db.Callback().Query().Remove(callback); err != nil {
			t.Fatal(err)
		}
		if err != nil || got.ID != record.ID || got.Version != 1 || got.Status != "QUEUED" || !queried || !narrow {
			t.Fatal("version was not a narrow current query")
		}
		foreign, err := store.WithOrganization(t.Context(), tenant.orgID+1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := foreign.GetRunVersion(record.ID); !errors.Is(err, ErrNotFound) {
			t.Fatal("version crossed tenant scope")
		}
		for _, id := range []int64{0, -1, record.ID + 1} {
			if _, err := tenant.GetRunVersion(id); !errors.Is(err, ErrNotFound) {
				t.Fatal("unknown version was disclosed")
			}
		}
		changed, err := tenant.CancelRun(record.ID, 1)
		if err != nil {
			t.Fatal(err)
		}
		got, err = tenant.GetRunVersion(record.ID)
		if err != nil || got.Version != changed.Version || got.Version <= 1 || got.Status != changed.Status {
			t.Fatal("version did not follow persisted cancellation")
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		cancelled, err := store.WithOrganization(ctx, tenant.orgID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cancelled.GetRunVersion(record.ID); err == nil {
			t.Fatal("cancelled read continued")
		}
	})
}
