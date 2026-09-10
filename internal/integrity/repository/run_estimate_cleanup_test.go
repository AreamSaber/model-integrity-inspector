package repository

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRunEstimateCleanupRetainsActiveDraftAndConfirmedReceipt(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 1)
		plan = estimateFixturePlan(plan)
		drafts := make([]RunEstimateRecord, 3)
		for i := range drafts {
			var err error
			drafts[i], err = tenant.SaveRunEstimate(plan, policy)
			if err != nil {
				t.Fatal(err)
			}
		}
		run, err := tenant.ConfirmRunEstimate(drafts[0].ID, plan, policy)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.db.Model(&RunEstimateRecord{}).Where("organization_id = ? AND id IN ?", tenant.orgID, []int64{drafts[0].ID, drafts[1].ID}).Update("expires_at", time.Now().UTC().Add(-time.Minute)).Error; err != nil {
			t.Fatal(err)
		}
		queue, err := store.OpenJobQueue(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = queue.Close(context.Background()) }()
		if err := queue.ExpireRunEstimates(context.Background()); err != nil {
			t.Fatal(err)
		}
		for _, draft := range drafts[:2] {
			if _, err := tenant.GetRunEstimate(draft.ID); !errors.Is(err, ErrNotFound) {
				t.Fatal("expired S2 retained", err)
			}
		}
		if _, err := tenant.GetRunEstimate(drafts[2].ID); err != nil {
			t.Fatal("active quote removed", err)
		}
		receipt, err := tenant.FindConfirmedEstimate(drafts[0].ID, plan.ManifestHash)
		if err != nil || receipt.ID != run.ID {
			t.Fatal("cleanup erased receipt", err)
		}
		if _, err := tenant.FindConfirmedEstimate(drafts[1].ID, plan.ManifestHash); !errors.Is(err, ErrNotFound) {
			t.Fatal("unconfirmed draft acquired receipt", err)
		}
		if _, err := tenant.FindConfirmedEstimate(drafts[0].ID, "wrong-hash"); !errors.Is(err, ErrNotFound) {
			t.Fatal("receipt not hash bound", err)
		}
		if err := store.VerifyAllAudit(t.Context(), true); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRunEstimateCleanupAuditFailureRollsBackAndClosedConsumerDenied(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 1)
		plan = estimateFixturePlan(plan)
		draft, err := tenant.SaveRunEstimate(plan, policy)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.db.Model(&RunEstimateRecord{}).Where("id = ?", draft.ID).Update("expires_at", time.Now().UTC().Add(-time.Minute)).Error; err != nil {
			t.Fatal(err)
		}
		queue, err := store.OpenJobQueue(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = queue.Close(context.Background()) }()
		original := store.auditSigner
		broken := &switchAuditSigner{}
		broken.fail.Store(true)
		store.auditSigner = broken
		err = queue.ExpireRunEstimates(context.Background())
		store.auditSigner = original
		if err == nil {
			t.Fatal("cleanup ignored audit failure")
		}
		if _, err := tenant.GetRunEstimate(draft.ID); err != nil {
			t.Fatal("cleanup deletion escaped rollback", err)
		}
		if err := queue.ExpireRunEstimates(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := queue.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := queue.ExpireRunEstimates(context.Background()); err == nil {
			t.Fatal("closed consumer performed maintenance")
		}
	})
}

func TestRunEstimateOwnExpiryPrunesWithoutWorker(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 1)
		plan = estimateFixturePlan(plan)
		for range maxActiveEstimates {
			if _, err := tenant.SaveRunEstimate(plan, policy); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.db.Model(&RunEstimateRecord{}).Where("organization_id = ?", tenant.orgID).Update("expires_at", time.Now().UTC().Add(-time.Minute)).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.SaveRunEstimate(plan, policy); err != nil {
			t.Fatal(err)
		}
		var count int64
		if err := store.db.Model(&RunEstimateRecord{}).Where("organization_id = ?", tenant.orgID).Count(&count).Error; err != nil || count != 1 {
			t.Fatal("expired payloads accumulated", count, err)
		}
		if err := store.db.Model(&Job{}).Where("organization_id = ?", tenant.orgID).Count(&count).Error; err != nil || count != 0 {
			t.Fatal("expiry created work", err)
		}
		if err := store.VerifyAllAudit(t.Context(), true); err != nil {
			t.Fatal(err)
		}
	})
}
