package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

func trendRead(t *testing.T, tenant *Tenant, run RunRecord) AttemptTrendRecord {
	t.Helper()
	page, err := tenant.ListRunTrends(ListOptions{Limit: 25}, RunFilters{TargetID: run.TargetID})
	if err != nil || len(page.Items) != 1 || page.HasMore || page.Items[0].Run.ID != run.ID {
		t.Fatal("trend projection unavailable", err)
	}
	return page.Items[0].Attempts
}

func TestRunTrendsActualDispatchRetriesUnknownAndLatencyDenominators(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 5)
		readPermissions(t, tenant)
		run, q, samples := executionStart(t, tenant, plan, policy)
		if a := trendRead(t, tenant, run); a.Dispatched != 0 || a.LatencyMinMS != nil || a.LatencyMaxMS != nil {
			t.Fatal("unattempted samples masqueraded as calls")
		}
		leases := make([]JobLease, len(samples))
		for i := range samples {
			lease, err := q.Claim(tenant.ctx)
			if err != nil || lease == nil || lease.Job.ObjectID != samples[i].ID {
				t.Fatal("claim sample", err)
			}
			leases[i] = *lease
		}
		finish := func(lease JobLease, sample LogicalSampleRecord, outcome domain.AttemptOutcome) AttemptRecord {
			t.Helper()
			a := reserveTestAttempt(t, tenant, q, lease, sample)
			if err := q.CompleteWith(tenant.ctx, lease, func(tx *TenantTransaction) error { return tx.FinishAttempt(sample.ID, a.ID, outcome, 0) }); err != nil {
				t.Fatal(err)
			}
			return a
		}
		finish(leases[0], samples[0], domain.AttemptOutcome{Validity: "INVALID_RETRYABLE", ErrorCode: "MI_RATE_LIMITED", HTTPStatus: 429, DurationMillis: 20})
		if err := store.db.Model(&Job{}).Where("organization_id=? AND status='pending'", tenant.orgID).Update("available_at", time.Now().UTC().Add(-time.Second)).Error; err != nil {
			t.Fatal(err)
		}
		retry, err := q.Claim(tenant.ctx)
		if err != nil || retry == nil || retry.Job.ObjectID != samples[0].ID {
			t.Fatal("retry unavailable", err)
		}
		zero := successOutcome()
		zero.Validity, zero.DurationMillis = "VALID_WITH_WARNING", 0
		finish(*retry, samples[0], zero)
		finish(leases[1], samples[1], domain.AttemptOutcome{Validity: "INVALID_PROTOCOL", ErrorCode: "MI_PROTOCOL_UNSUPPORTED", HTTPStatus: 200, DurationMillis: 30})
		missing := finish(leases[2], samples[2], successOutcome())
		// A persisted missing observation must remain missing, not become 0.
		if err := store.db.Model(&AttemptRecord{}).Where("id=?", missing.ID).Update("duration_ms", nil).Error; err != nil {
			t.Fatal(err)
		}
		reserveTestAttempt(t, tenant, q, leases[3], samples[3])
		if err := store.db.Model(&Job{}).Where("id=?", leases[3].Job.ID).Update("lease_until", time.Now().UTC().Add(-time.Second)).Error; err != nil {
			t.Fatal(err)
		}
		fresh, err := q.Claim(tenant.ctx)
		if err != nil || fresh == nil || fresh.Job.ID != leases[3].Job.ID {
			t.Fatal("recovery claim unavailable", err)
		}
		if err := q.CompleteWith(tenant.ctx, *fresh, func(tx *TenantTransaction) error { return tx.RecoverInterruptedSample(samples[3].ID) }); err != nil {
			t.Fatal(err)
		}
		reserveTestAttempt(t, tenant, q, leases[4], samples[4])
		a := trendRead(t, tenant, run)
		if a.Dispatched != 6 || a.LogicalSamples != 5 || a.RetryAttempts != 1 || a.Succeeded != 2 || a.Failed != 2 || a.Uncertain != 1 || a.InFlight != 1 || a.LatencySamples != 3 || a.LatencyTotalMS != 50 || a.LatencyMinMS == nil || *a.LatencyMinMS != 0 || a.LatencyMaxMS == nil || *a.LatencyMaxMS != 30 {
			t.Fatalf("wrong dispatch/latency denominators: %+v", a)
		}
		current, err := tenant.GetRun(run.ID)
		if err != nil || current.ValidSampleCount != 2 || current.RequestCount != 6 || current.Status != "RUNNING" {
			t.Fatal("test must keep real in-flight state", err)
		}
	})
}

func TestRunTrendsRejectDamagedAttemptMetadataAndCounters(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, run, samples, _ := analysisReadyFixture(t, store, 1)
		readPermissions(t, tenant)
		attempts, err := tenant.ListAttempts(samples[0].ID)
		if err != nil || len(attempts) != 1 {
			t.Fatal(err)
		}
		original := attempts[0]
		changes := []struct {
			name, field string
			value       any
		}{
			{"negative duration", "duration_ms", -1}, {"oversized duration", "duration_ms", int64(86400001)},
			{"unknown status", "status", strings.Repeat("PRIVATE_ATTEMPT_CANARY", 40)},
			{"unknown validity", "validity", "NEW_UNVERIFIED_STATE"}, {"invalid success HTTP", "http_status", 500},
			{"success error", "error_code", "MI_AUTH_FAILED"}, {"missing start", "started_at", nil},
			{"missing finish", "finished_at", nil}, {"backwards time", "finished_at", original.StartedAt.Add(-time.Second)},
		}
		for _, tc := range changes {
			t.Run(tc.name, func(t *testing.T) {
				if err := store.db.Model(&AttemptRecord{}).Where("id=?", original.ID).Update(tc.field, tc.value).Error; err != nil {
					t.Fatal(err)
				}
				if _, err := tenant.ListRunTrends(ListOptions{Limit: 1}, RunFilters{TargetID: run.TargetID}); !errors.Is(err, ErrResultDocument) {
					t.Fatal("damaged metadata accepted", err)
				}
				if err := store.db.Model(&AttemptRecord{}).Where("id=?", original.ID).Select("*").Updates(original).Error; err != nil {
					t.Fatal(err)
				}
			})
		}
		if err := store.db.Model(&RunRecord{}).Where("id=?", run.ID).Update("request_count", 2).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.ListRunTrends(ListOptions{Limit: 1}, RunFilters{TargetID: run.TargetID}); !errors.Is(err, ErrResultDocument) {
			t.Fatal("invented counter accepted", err)
		}
		if err := store.db.Model(&RunRecord{}).Where("id=?", run.ID).Update("request_count", 1).Error; err != nil {
			t.Fatal(err)
		}
		// The FK binds a sample to org, not to attempts.run_id. Corrupting run_id
		// must not transfer a successful observation into a different Run.
		copyRun := run
		copyRun.ID, _ = NewID()
		copyRun.RequestKey = "trend-corrupt-other-run"
		copyRun.PlanJobID = nil
		if err := store.db.Create(&copyRun).Error; err != nil {
			t.Fatal(err)
		}
		if err := store.db.Model(&AttemptRecord{}).Where("id=?", original.ID).Update("run_id", copyRun.ID).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.ListRunTrends(ListOptions{Limit: 25}, RunFilters{TargetID: run.TargetID}); !errors.Is(err, ErrResultDocument) {
			t.Fatal("cross-run attempt accepted", err)
		}
	})
}

func TestRunTrendsSnapshotPermissionsPaginationAndSelectedPageOnly(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, target, plan, policy := executionFixture(t, store, 1)
		for i := range 3 {
			if _, err := tenant.CreateRun(plan, policy, fmt.Sprintf("trend-%d", i)); err != nil {
				t.Fatal(err)
			}
		}
		filter := RunFilters{TargetID: target.Target.ID, Status: "QUEUED"}
		if _, err := tenant.ListRunTrends(ListOptions{Limit: 1}, filter); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("missing grant", err)
		}
		readPermissions(t, tenant)
		first, err := tenant.ListRunTrends(ListOptions{Limit: 1}, filter)
		if err != nil || len(first.Items) != 1 || !first.HasMore {
			t.Fatal("first trend page", err)
		}
		anchor := first.Items[0].Run
		if _, err := tenant.CancelRun(anchor.ID, anchor.Version); err != nil {
			t.Fatal(err)
		}
		next, err := tenant.ListRunTrends(ListOptions{Limit: 1, AfterID: anchor.ID}, filter)
		if err != nil || len(next.Items) != 1 || !next.HasMore || next.Items[0].Run.ID == anchor.ID {
			t.Fatal("mutable cursor anchor lost", err)
		}
		last, err := tenant.ListRunTrends(ListOptions{Limit: 1, AfterID: next.Items[0].Run.ID}, filter)
		if err != nil || len(last.Items) != 1 || last.HasMore {
			t.Fatal("end of trend page", err)
		}
		// A corrupt older run must not be aggregated as part of the first page.
		if err := store.db.Model(&RunRecord{}).Where("id=?", last.Items[0].Run.ID).Update("request_count", 1).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.ListRunTrends(ListOptions{Limit: 1}, RunFilters{TargetID: target.Target.ID}); err != nil {
			t.Fatal("off-page run aggregated", err)
		}
		if _, err := tenant.ListRunTrends(ListOptions{Limit: 25}, RunFilters{TargetID: target.Target.ID}); !errors.Is(err, ErrResultDocument) {
			t.Fatal("visible damaged counter ignored", err)
		}
		for _, f := range []RunFilters{{}, {TargetID: -1}, {TargetID: target.Target.ID, Status: "unknown"}} {
			if _, err := tenant.ListRunTrends(ListOptions{Limit: 25}, f); !errors.Is(err, ErrConfiguration) {
				t.Fatal("bad trend filter", err)
			}
		}
		for _, p := range []ListOptions{{Limit: 0}, {Limit: 101}, {Limit: 1, AfterID: -1}, {Limit: 1, AfterID: 1}} {
			if _, err := tenant.ListRunTrends(p, filter); !errors.Is(err, ErrConfiguration) {
				t.Fatal("bad page", err)
			}
		}
		foreign, _ := store.WithOrganization(tenant.ctx, tenant.orgID+1)
		if _, err := foreign.ListRunTrends(ListOptions{Limit: 1}, filter); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("cross tenant capability", err)
		}
		if err := store.db.Exec("DELETE FROM role_permissions WHERE organization_id=? AND permission_code='run.read'", tenant.orgID).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.ListRunTrends(ListOptions{Limit: 1}, filter); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("revoked permission", err)
		}
		if err := store.db.Model(&Session{}).Where("user_id=?", anchor.CreatedBy).Update("revoked_at", time.Now().UTC()).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.ListRunTrends(ListOptions{Limit: 1}, filter); !errors.Is(err, ErrManagementSession) {
			t.Fatal("revoked session", err)
		}
	})
}

func TestRunTrendsDatabaseFailureAndCancelledContext(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, target, _, _ := executionFixture(t, store, 1)
		readPermissions(t, tenant)
		ctx, cancel := context.WithCancel(tenant.ctx)
		cancelled, err := store.WithOrganization(ctx, tenant.orgID)
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		if _, err := cancelled.ListRunTrends(ListOptions{Limit: 1}, RunFilters{TargetID: target.Target.ID}); err == nil {
			t.Fatal("cancelled read succeeded")
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.ListRunTrends(ListOptions{Limit: 1}, RunFilters{TargetID: target.Target.ID}); !errors.Is(err, ErrUnavailable) {
			t.Fatal("closed database became empty trend", err)
		}
	})
}

func TestRunTrendsOneSnapshotAndNoS2Select(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, cfg Config) {
		tenant, _, run, samples, _ := analysisReadyFixture(t, store, 1)
		readPermissions(t, tenant)
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
		triggered, aggregateQueries := false, 0
		var writerErr error
		callback := "test:trend-snapshot"
		if err := store.db.Callback().Row().After("gorm:row").Register(callback, func(tx *gorm.DB) {
			query := tx.Statement.SQL.String()
			for _, field := range []string{"config_snapshot", "request_snapshot", "request_plan", "response_meta", "response_content", "ciphertext", "conclusion_json", "error_detail"} {
				if strings.Contains(query, field) {
					t.Errorf("trend selected S2 field: %s", field)
				}
			}
			if strings.Contains(query, "AS latency_samples") {
				aggregateQueries++
				if !strings.Contains(query, "a.organization_id=? AND a.run_id=? LIMIT 3001") && !strings.Contains(query, "a.organization_id=$1 AND a.run_id=$2 LIMIT 3001") {
					t.Error("aggregate lost inner row/org/run bound")
				}
			}
			if triggered || !strings.Contains(query, "AS planned_samples") {
				return
			}
			triggered = true
			// Commit a concurrent counter/latency update and permission revocation
			// after history SELECT but before the attempt SELECT. The open read
			// must retain one coherent authorized snapshot, without writer locks.
			writerErr = other.db.WithContext(t.Context()).Transaction(func(write *gorm.DB) error {
				if err := write.Model(&RunRecord{}).Where("id=?", run.ID).Update("request_count", 2).Error; err != nil {
					return err
				}
				if err := write.Model(&AttemptRecord{}).Where("logical_sample_id=?", samples[0].ID).Update("duration_ms", 999).Error; err != nil {
					return err
				}
				return write.Exec("DELETE FROM role_permissions WHERE organization_id=? AND permission_code='run.read'", tenant.orgID).Error
			})
		}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.db.Callback().Row().Remove(callback) })
		page, err := tenant.ListRunTrends(ListOptions{Limit: 1}, RunFilters{TargetID: run.TargetID})
		if err != nil || writerErr != nil || !triggered || aggregateQueries != 1 || len(page.Items) != 1 || page.Items[0].Attempts.Dispatched != 1 || page.Items[0].Attempts.LatencyTotalMS != 10 {
			t.Fatal("mixed snapshots or writer blocked", err, writerErr)
		}
		if _, err := tenant.ListRunTrends(ListOptions{Limit: 1}, RunFilters{TargetID: run.TargetID}); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("next snapshot ignored revocation", err)
		}
	})
}

func TestRunTrendsMaxPageLookaheadAndDeletedTarget(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, target, plan, policy := executionFixture(t, store, 1)
		readPermissions(t, tenant)
		run, err := tenant.CreateRun(plan, policy, "trend-page-base")
		if err != nil {
			t.Fatal(err)
		}
		// Only bounded row fixtures, no Jobs or extra requests are dispatched.
		rows := make([]RunRecord, 100)
		for i := range rows {
			rows[i] = run
			rows[i].ID, err = NewID()
			if err != nil {
				t.Fatal(err)
			}
			rows[i].RequestKey = fmt.Sprintf("trend-page-%d", i)
			rows[i].PlanJobID = nil
			rows[i].CreatedAt = run.CreatedAt.Add(time.Duration(i+1) * time.Second)
		}
		if err := store.db.CreateInBatches(rows, 25).Error; err != nil {
			t.Fatal(err)
		}
		if err := store.db.Model(&TargetRecord{}).Where("id=?", target.Target.ID).Update("deleted_at", time.Now().UTC()).Error; err != nil {
			t.Fatal(err)
		}
		first, err := tenant.ListRunTrends(ListOptions{Limit: 100}, RunFilters{TargetID: run.TargetID})
		if err != nil || len(first.Items) != 100 || !first.HasMore || first.Items[0].Run.CurrentTargetName != nil {
			t.Fatal("max page and target retention", err)
		}
		next, err := tenant.ListRunTrends(ListOptions{Limit: 100, AfterID: first.Items[99].Run.ID}, RunFilters{TargetID: run.TargetID})
		if err != nil || len(next.Items) != 1 || next.HasMore || next.Items[0].Run.ID != run.ID {
			t.Fatal("lookahead lost final row", err)
		}
	})
}
