package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/scheduler"
)

func estimateFixturePlan(plan domain.ExecutionPlan) domain.ExecutionPlan {
	// The service applies policy before signing. Repository fixtures freeze the
	// same known-price ceiling instead of relying on formerly unbounded nil.
	ceiling := scheduler.DefaultLimits().MaxCostMicros
	plan.Budget.MaxCostMicros = &ceiling
	plan.Manifest = json.RawMessage(`{"development_fixture":"synthetic-reproduction-canary"}`)
	hash := sha256.Sum256(plan.Manifest)
	plan.ManifestHash = hex.EncodeToString(hash[:])
	return plan
}

func TestRunEstimateDoesNotDispatchAndConfirmIsAtomicIdempotent(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 3)
		plan = estimateFixturePlan(plan)
		estimate, err := tenant.SaveRunEstimate(plan, policy)
		if err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{"integrity_runs", "integrity_jobs", "integrity_logical_samples", "integrity_sample_attempts"} {
			var count int64
			if err := store.db.Table(table).Where("organization_id = ?", tenant.orgID).Count(&count).Error; err != nil || count != 0 {
				t.Fatal("estimate dispatched work", table, count, err)
			}
		}
		read, err := tenant.GetRunEstimate(estimate.ID)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeRunEstimate(read)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.ManifestHash != plan.ManifestHash || read.CreatedBy == 0 || !read.ExpiresAt.Equal(read.CreatedAt.Add(RunEstimateLifetime)) {
			t.Fatal("estimate identity/expiry drift")
		}
		outputs := make(chan int64, 8)
		failures := make(chan error, 8)
		var group sync.WaitGroup
		for range 8 {
			group.Go(func() {
				run, err := tenant.ConfirmRunEstimate(estimate.ID, decoded, policy)
				if err != nil {
					failures <- err
				} else {
					outputs <- run.ID
				}
			})
		}
		group.Wait()
		close(outputs)
		close(failures)
		for err := range failures {
			t.Error(err)
		}
		var runID int64
		for id := range outputs {
			if runID != 0 && id != runID {
				t.Fatal("one estimate created multiple runs")
			}
			runID = id
		}
		var count int64
		if err := store.db.Model(&RunRecord{}).Where("organization_id = ?", tenant.orgID).Count(&count).Error; err != nil || count != 1 {
			t.Fatal("duplicate run", count, err)
		}
		if err := store.db.Model(&Job{}).Where("organization_id = ?", tenant.orgID).Count(&count).Error; err != nil || count != 1 {
			t.Fatal("duplicate planning job", count, err)
		}
		if err := store.db.Model(&RunEstimateRecord{}).Where("organization_id = ? AND id = ?", tenant.orgID, estimate.ID).Update("expires_at", time.Now().UTC().Add(-time.Minute)).Error; err != nil {
			t.Fatal(err)
		}
		again, err := tenant.ConfirmRunEstimate(estimate.ID, decoded, policy)
		if err != nil || again.ID != runID {
			t.Fatal("expired receipt recovery duplicated/lost run", err)
		}
		audits, err := tenant.ListAudit(0, 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range audits {
			raw, _ := json.Marshal(event)
			if strings.Contains(string(raw), "synthetic-reproduction-canary") {
				t.Fatal("S2 entered audit")
			}
		}
	})
}

func TestRunEstimateExpiryTamperAndPermissionFailClosed(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 1)
		plan = estimateFixturePlan(plan)
		draft, err := tenant.SaveRunEstimate(plan, policy)
		if err != nil {
			t.Fatal(err)
		}
		changed := plan
		changed.Target.SecretVersion++
		if _, err := tenant.ConfirmRunEstimate(draft.ID, changed, policy); !errors.Is(err, ErrEstimateStale) {
			t.Fatal("changed quote accepted", err)
		}
		if err := store.db.Model(&RunEstimateRecord{}).Where("id = ?", draft.ID).Update("expires_at", time.Now().UTC().Add(-time.Minute)).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.ConfirmRunEstimate(draft.ID, plan, policy); !errors.Is(err, ErrEstimateExpired) {
			t.Fatal("expired quote accepted", err)
		}
		var count int64
		if err := store.db.Model(&RunRecord{}).Where("organization_id = ?", tenant.orgID).Count(&count).Error; err != nil || count != 0 {
			t.Fatal("failed confirmation created run", err)
		}
		fresh, err := tenant.SaveRunEstimate(plan, policy)
		if err != nil {
			t.Fatal(err)
		}
		actor, err := tenant.targetActor()
		if err != nil {
			t.Fatal(err)
		}
		if err := store.db.Model(&User{}).Where("id = ?", actor).Update("status", "disabled").Error; err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.ConfirmRunEstimate(fresh.ID, plan, policy); err == nil {
			t.Fatal("revoked actor confirmed draft")
		}
	})
}

func TestRunEstimateAuthorityScopeAndBoundedActiveDrafts(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 1)
		plan = estimateFixturePlan(plan)
		draft, err := tenant.SaveRunEstimate(plan, policy)
		if err != nil {
			t.Fatal(err)
		}
		other, _ := store.WithOrganization(tenant.ctx, tenant.orgID+1)
		if _, err := other.GetRunEstimate(draft.ID); err == nil {
			t.Fatal("cross-org draft exposed")
		}
		unbound, _ := store.WithOrganization(t.Context(), tenant.orgID)
		if _, err := unbound.GetRunEstimate(draft.ID); err == nil {
			t.Fatal("draft read without authority")
		}
		for range maxActiveEstimates - 1 {
			if _, err := tenant.SaveRunEstimate(plan, policy); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := tenant.SaveRunEstimate(plan, policy); !errors.Is(err, ErrEstimateLimit) {
			t.Fatal("draft storage not bounded", err)
		}
		plan.Manifest = nil
		if _, err := tenant.SaveRunEstimate(plan, policy); !errors.Is(err, ErrConfiguration) {
			t.Fatal("estimate lacks reproduction artifact", err)
		}
	})
}
