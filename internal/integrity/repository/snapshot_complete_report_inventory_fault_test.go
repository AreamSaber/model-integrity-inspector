package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/backupmanifest"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/scheduler"
)

func TestSnapshotCompleteReportInventoryEveryOrganization(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, queue, firstRun := snapshotReportTestFixture(t, s)
		first := snapshotReportTestPublish(t, tenant, queue, firstRun, "csv", 1)
		authority := tenant.ctx.Value(controlAuthorityKey{}).(controlAuthority)
		roles := managementFixtureRoles()
		roles[0].Permissions = append(roles[0].Permissions, "run.create", "run.custom", "run.high-cost")
		org, err := s.ManageCreateOrganization(tenant.ctx, authority.identity, ManagedOrganizationCreate{Name: "Complete historical organization", Timezone: "UTC", Roles: roles})
		if err != nil {
			t.Fatal(err)
		}
		ctx := bindTargetTestSession(t, s, tenant.ctx, authority.identity.SessionID, org.ID)
		second, err := s.WithOrganization(ctx, org.ID)
		if err != nil {
			t.Fatal(err)
		}
		target := mustCreateTarget(t, second)
		var frozen executionSnapshot
		if err := json.Unmarshal([]byte(firstRun.ConfigSnapshot), &frozen); err != nil {
			t.Fatal(err)
		}
		plan := frozen.Plan
		plan.Target = domain.ExecutionTarget{ID: target.Target.ID, Version: 1, SecretID: target.Secret.ID, SecretVersion: 1, Endpoint: target.Target.Endpoint, Model: target.Target.Model, Protocol: target.Target.Protocol, MaxOutputParameter: "max_tokens"}
		policy, err := scheduler.NewPolicy(scheduler.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		if err := queue.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
		run, q, samples := executionStart(t, second, plan, policy)
		for _, sample := range samples {
			lease := mustClaim(t, q)
			attempt := reserveTestAttempt(t, second, q, lease, sample)
			body := responseFixtureBody(t, second, q, lease, sample, attempt)
			if err := q.CompleteWith(t.Context(), lease, func(tx *TenantTransaction) error {
				return tx.FinishLegacyAttemptWithCapture(sample.ID, attempt.ID, successOutcome(), 0, body)
			}); err != nil {
				t.Fatal(err)
			}
		}
		lease := mustClaim(t, q)
		source, err := q.LoadRunAnalysis(t.Context(), lease)
		if err != nil {
			t.Fatal(err)
		}
		if err := q.CompleteWith(t.Context(), lease, func(tx *TenantTransaction) error {
			return tx.PublishRunAnalysis(source, analysisPublicationFixture(t, run, samples))
		}); err != nil {
			t.Fatal(err)
		}
		row := snapshotCompleteTestLegacy(t, s, run, 1)
		snapshotCompleteTestInsert(t, s, row)
		if err := s.db.Table("organizations").Where("id=?", org.ID).Update("status", "disabled").Error; err != nil {
			t.Fatal(err)
		}
		got := snapshotCompleteTestObserve(t, s, cfg, nil)
		if len(got.modern) != 1 || len(got.legacy) != 1 || got.modern[0].id != first.ID || got.modern[0].organizationID != first.OrganizationID || got.legacy[0].row.organizationID != org.ID || got.legacy[0].row.rowSHA256 != snapshotLegacyReportExpected(t, cfg.Driver, row) {
			t.Fatal("global inventory lost active or disabled organization")
		}
	})
}

func TestSnapshotCompleteReportInventoryUnionBudgetAndOriginalCorruption(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, q, run := snapshotReportTestFixture(t, s)
		modern := snapshotReportTestPublish(t, tenant, q, run, "html", 1)
		for id := int64(1); id <= 2; id++ {
			snapshotCompleteTestInsert(t, s, snapshotCompleteTestLegacy(t, s, run, id))
		}
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		for _, limit := range []int{1, 2, 3} {
			got, err := s.snapshotCompleteReportInventoryLimited(ctx, tx, limit, backupmanifest.MaxFileBytes)
			if limit < 3 {
				if !errors.Is(err, errSnapshotReportLimit) || !reflect.DeepEqual(got, snapshotCompleteReportInventory{}) {
					t.Fatal("union count permitted a valid prefix", err)
				}
			} else if err != nil || len(got.modern)+len(got.legacy) != 3 {
				t.Fatal("exact union cap rejected", err)
			}
		}
		if got, err := s.snapshotCompleteReportInventoryLimited(ctx, tx, 3, 1); !errors.Is(err, errSnapshotLegacyReportLimit) || !reflect.DeepEqual(got, snapshotCompleteReportInventory{}) {
			t.Fatal("per-row original framing budget ignored", err)
		}
		closeView()
		snapshotLegacyReportCorruptible(t, s, modern.ID)
		for _, fault := range []struct {
			field string
			value any
			want  error
		}{
			{"id", nil, errSnapshotReportInvalid}, {"id", int64(0), errSnapshotReportInvalid}, {"id", int64(-1), errSnapshotReportInvalid},
			{"organization_id", nil, errSnapshotLegacyReportInvalid}, {"run_id", int64(999999), errSnapshotLegacyReportInvalid},
			{"format", nil, errSnapshotLegacyReportInvalid}, {"created_by", int64(999999), errSnapshotLegacyReportInvalid},
			{"analysis_revision", int64(0), errSnapshotLegacyReportInvalid},
		} {
			snapshotLegacyReportResetCopy(t, s)
			if err := s.db.Exec("UPDATE integrity_reports SET "+fault.field+"=? WHERE id=2", fault.value).Error; err != nil {
				t.Fatal(err)
			}
			snapshotCompleteTestObserve(t, s, cfg, fault.want)
		}
		snapshotLegacyReportResetCopy(t, s)
		if err := s.db.Exec("INSERT INTO integrity_reports SELECT * FROM legacy_row_original WHERE id=1").Error; err != nil {
			t.Fatal(err)
		}
		snapshotCompleteTestObserve(t, s, cfg, errSnapshotLegacyReportInvalid)
		snapshotLegacyReportResetCopy(t, s)
		if err := s.db.Exec("ALTER TABLE integrity_reports ADD COLUMN future_report_fact TEXT").Error; err != nil {
			t.Fatal(err)
		}
		snapshotCompleteTestObserve(t, s, cfg, errSnapshotLegacyReportUnsupported)
	})
}

func TestSnapshotCompleteReportInventoryLateFailuresNeverReturnPrefix(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, q, run := snapshotReportTestFixture(t, s)
		snapshotReportTestPublish(t, tenant, q, run, "json", 1)
		for id := int64(1); id <= 100; id++ {
			row := snapshotCompleteTestLegacy(t, s, run, id)
			if id == 100 {
				row["source_json"] = strings.Repeat("late private complete body ", 6000)
			}
			snapshotCompleteTestInsert(t, s, row)
		}
		for _, mode := range []string{"late_source_sql", "late_source_cancel", "second_page_sql", "second_page_cancel", "final_count_sql", "final_count_cancel", "final_count_rollback"} {
			t.Run(mode, func(t *testing.T) {
				ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
				defer closeView()
				child, cancel := context.WithCancel(ctx)
				defer cancel()
				pages, sources, counts := 0, 0, 0
				reached := false
				inject := func(query *gorm.DB) {
					reached = true
					switch {
					case strings.HasSuffix(mode, "_cancel"):
						cancel()
					case strings.HasSuffix(mode, "_rollback"):
						if err := tx.Statement.ConnPool.(*sql.Tx).Rollback(); err != nil {
							t.Error("actual last-query rollback", err)
						}
					default:
						query.Statement.SQL.Reset()
						query.Statement.SQL.WriteString("SELECT private_complete_missing_column FROM integrity_reports")
						query.Statement.Vars = nil
					}
				}
				if err := tx.Callback().Row().Before("gorm:row").Register("complete_late_row", func(query *gorm.DB) {
					sql := query.Statement.SQL.String()
					if strings.Contains(sql, " AS data FROM integrity_reports") && strings.Contains(sql, "r.source_json") {
						sources++
						if sources == 2 && strings.HasPrefix(mode, "late_source_") {
							inject(query)
						}
					}
					if strings.Contains(sql, "complete_inventory_reports") {
						counts++
						if counts == 2 && strings.HasPrefix(mode, "final_count_") {
							inject(query)
						}
					}
				}); err != nil {
					t.Fatal(err)
				}
				if err := tx.Callback().Query().Before("gorm:query").Register("complete_late_page", func(query *gorm.DB) {
					if _, ok := query.Statement.Dest.(*[]snapshotReportRow); ok {
						pages++
						if pages == 2 && strings.HasPrefix(mode, "second_page_") {
							if strings.HasSuffix(mode, "_sql") {
								query.Statement.Selects = []string{"private_complete_missing_column"}
								reached = true
							} else {
								inject(query)
							}
						}
					}
				}); err != nil {
					t.Fatal(err)
				}
				got, err := s.snapshotCompleteReportInventory(child, tx)
				if !reached || !errors.Is(err, ErrUnavailable) || err.Error() != ErrUnavailable.Error() || !reflect.DeepEqual(got, snapshotCompleteReportInventory{}) {
					t.Fatal("late fault not reached or prefix escaped", err, reached)
				}
				if strings.HasPrefix(mode, "final_count_") && (pages != 2 || sources < 3) {
					t.Fatal("final fault occurred before both complete pages and original body")
				}
			})
		}
	})
}
