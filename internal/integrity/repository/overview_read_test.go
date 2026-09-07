package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestOverviewSnapshotAuthorizationRevocationAndReadOnly(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, cfg Config) {
		tenant, run := overviewFixture(t, store)
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = other.Close() })
		if cfg.Driver == "sqlite" {
			if err := other.db.Exec("PRAGMA busy_timeout=150").Error; err != nil {
				t.Fatal(err)
			}
		}
		seen := false
		var writeErr error
		var readOnly string
		callback := func(db *gorm.DB) {
			if seen || !strings.Contains(db.Statement.SQL.String(), "current_targets") {
				return
			}
			seen = true
			if cfg.Driver == "postgres" {
				if err := db.Session(&gorm.Session{NewDB: true}).Raw("SHOW transaction_read_only").Scan(&readOnly).Error; err != nil {
					t.Error(err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			writeErr = other.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
				if err := tx.Model(&RunRecord{}).Where("id=?", run.ID).Update("status", "FAILED").Error; err != nil {
					return err
				}
				if err := tx.Model(&TargetRecord{}).Where("id=?", run.TargetID).Update("status", "disabled").Error; err != nil {
					return err
				}
				return tx.Exec("DELETE FROM role_permissions WHERE organization_id=? AND permission_code='target.read'", tenant.orgID).Error
			})
		}
		if err := store.db.Callback().Row().Before("gorm:row").Register("overview_snapshot", callback); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.db.Callback().Row().Remove("overview_snapshot") })
		got, err := tenant.Overview(7)
		if err != nil || !seen || writeErr != nil {
			t.Fatal("read blocked writer or failed", err, writeErr)
		}
		if got.Targets.Active != 1 || len(got.Runs) != 1 || got.Runs[0].Status != "QUEUED" {
			t.Fatal("mixed snapshots", got)
		}
		if cfg.Driver == "postgres" && readOnly != "on" {
			t.Fatal("not read-only")
		}
		if _, err := tenant.Overview(7); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("target.read revocation ignored", err)
		}
		var role int64
		if err := store.db.Table("roles").Select("id").Where("organization_id=? AND name='administrator'", tenant.orgID).Scan(&role).Error; err != nil {
			t.Fatal(err)
		}
		if err := store.db.Exec("INSERT INTO role_permissions(organization_id,role_id,permission_code) VALUES (?,?,'target.read')", tenant.orgID, role).Error; err != nil {
			t.Fatal(err)
		}
		if err := store.db.Exec("DELETE FROM role_permissions WHERE organization_id=? AND permission_code='run.read'", tenant.orgID).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.Overview(7); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("run.read revocation ignored", err)
		}
		unbound, _ := store.WithOrganization(t.Context(), tenant.orgID)
		if _, err := unbound.Overview(7); !errors.Is(err, ErrManagementSession) {
			t.Fatal("unbound capability accepted", err)
		}
	})
}

func TestOverviewCancellationRollsBackAndPreservesNextRead(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _ := overviewFixture(t, store)
		ctx, cancel := context.WithCancel(tenant.ctx)
		cancelled, _ := store.WithOrganization(ctx, tenant.orgID)
		seen := false
		if err := store.db.Callback().Row().Before("gorm:row").Register("overview_cancel", func(db *gorm.DB) {
			if !seen && strings.Contains(db.Statement.SQL.String(), "current_targets") {
				seen = true
				cancel()
			}
		}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cancel(); _ = store.db.Callback().Row().Remove("overview_cancel") })
		if _, err := cancelled.Overview(7); err == nil || !seen {
			t.Fatal("cancelled aggregate succeeded", err)
		}
		if _, err := tenant.Overview(7); err != nil {
			t.Fatal("connection retained open transaction", err)
		}
	})
}

func TestOverviewSQLLimitsRejectWholeAggregateAndIndexes(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, run := overviewFixture(t, store)
		rows := make([]RunRecord, OverviewMaxRows)
		for i := range rows {
			rows[i] = run
			rows[i].ID = run.ID + int64(i) + 1
			rows[i].RequestKey = fmt.Sprintf("overview-cap-%d", i)
			rows[i].PlanJobID = nil
		}
		if err := store.db.CreateInBatches(&rows, 100).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.Overview(7); !errors.Is(err, ErrOverviewLimit) {
			t.Fatal("cap+1 became truncated success", err)
		}
		if err := store.db.Model(&RunRecord{}).Where("id=?", rows[0].ID).Update("created_at", time.Now().UTC().AddDate(0, 0, -40)).Error; err != nil {
			t.Fatal(err)
		}
		got, err := tenant.Overview(7)
		if err != nil || got.RunCount != OverviewMaxRows {
			t.Fatal("exact cap not covered", err)
		}
		if err := store.db.Model(&RunRecord{}).Where("organization_id=?", tenant.orgID).Updates(map[string]any{"cost_known": true, "estimated_cost_micros": OverviewMaxInteger}).Error; err != nil {
			t.Fatal(err)
		}
		got, err = tenant.Overview(7)
		if err != nil || len(got.Runs) != 1 || got.Runs[0].CostQuotient != (OverviewMaxInteger/10000)*OverviewMaxRows || got.Runs[0].CostRemainder != (OverviewMaxInteger%10000)*OverviewMaxRows {
			t.Fatal("integer aggregation overflowed or rounded before projection", err)
		}
		// Test the actual range query's plan on representative data, without
		// forcing PostgreSQL enable_seqscan or SQLite INDEXED BY overrides.
		if err := store.db.Exec("ANALYZE integrity_runs").Error; err != nil {
			t.Fatal(err)
		}
		query := "SELECT id FROM integrity_runs WHERE organization_id=? AND created_at>=? AND created_at<? LIMIT 10001"
		start := time.Now().UTC().AddDate(0, 0, -50)
		end := time.Now().UTC().AddDate(0, 0, -30)
		plan := overviewExplain(t, store, query, tenant.orgID, start, end)
		if !strings.Contains(plan, "idx_runs_org_created") {
			t.Fatal("time range index absent", plan)
		}
		var original TargetRecord
		if err := store.db.Where("id=?", run.TargetID).Take(&original).Error; err != nil {
			t.Fatal(err)
		}
		targets := make([]TargetRecord, OverviewMaxRows)
		for i := range targets {
			targets[i] = original
			targets[i].ID = run.ID + int64(i) + 1
			targets[i].Name = fmt.Sprintf("overview-target-%d", i)
		}
		if err := store.db.CreateInBatches(&targets, 100).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.Overview(7); !errors.Is(err, ErrOverviewLimit) {
			t.Fatal("target cap ignored", err)
		}
		// Soft-deleted history must not inflate counts or prevent the partial
		// index from bounding a small current directory.
		if err := store.db.Model(&TargetRecord{}).Where("organization_id=? AND id!=?", tenant.orgID, run.TargetID).Update("deleted_at", time.Now().UTC()).Error; err != nil {
			t.Fatal(err)
		}
		if err := store.db.Exec("ANALYZE integrity_targets").Error; err != nil {
			t.Fatal(err)
		}
		plan = overviewExplain(t, store, "SELECT status FROM integrity_targets WHERE organization_id=? AND deleted_at IS NULL LIMIT 10001", tenant.orgID)
		if !strings.Contains(plan, "idx_targets_current_org_status") {
			t.Fatal("current-target partial index absent", plan)
		}
		got, err = tenant.Overview(7)
		if err != nil || got.Targets.Total != 1 {
			t.Fatal("deleted history counted", err)
		}
	})
}

func overviewExplain(t *testing.T, store *Store, query string, args ...any) string {
	t.Helper()
	prefix := "EXPLAIN "
	if store.driver == "sqlite" {
		prefix = "EXPLAIN QUERY PLAN "
	}
	rows, err := store.db.Raw(prefix+query, args...).Rows()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var parts []string
	for rows.Next() {
		if store.driver == "sqlite" {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatal(err)
			}
			parts = append(parts, detail)
		} else {
			var detail string
			if err := rows.Scan(&detail); err != nil {
				t.Fatal(err)
			}
			parts = append(parts, detail)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return strings.Join(parts, "\n")
}
