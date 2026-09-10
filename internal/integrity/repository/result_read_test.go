package repository

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func readPermissions(t *testing.T, tenant *Tenant) {
	t.Helper()
	var roleID int64
	if err := tenant.scoped().Table("roles").Select("id").Where("name=?", "administrator").Scan(&roleID).Error; err != nil || roleID == 0 {
		t.Fatal("role fixture", err)
	}
	for _, permission := range []string{"run.read", "evidence.read"} {
		if err := tenant.store.db.Exec("INSERT INTO permissions (code) VALUES (?) ON CONFLICT (code) DO NOTHING", permission).Error; err != nil {
			t.Fatal(err)
		}
		if err := tenant.store.db.Exec("INSERT INTO role_permissions (organization_id,role_id,permission_code) VALUES (?,?,?)", tenant.orgID, roleID, permission).Error; err != nil {
			t.Fatal(err)
		}
	}
}

func TestResultReadHistoryPermissionsScopesAndBounds(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, queue, run, samples, lease := analysisReadyFixture(t, store, 2)
		if _, err := tenant.ListRunHistory(ListOptions{Limit: 25}, RunFilters{}); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("missing read permission", err)
		}
		readPermissions(t, tenant)
		rows, err := tenant.ListRunHistory(ListOptions{Limit: 1}, RunFilters{})
		if err != nil || len(rows) != 1 || rows[0].ID != run.ID || rows[0].PlannedSamples != 2 || rows[0].CompletedSamples != 2 || rows[0].AnalysisRevision != nil {
			t.Fatal("history non-S2 projection", err)
		}
		for _, filters := range []RunFilters{{TargetID: run.TargetID}, {Status: "ANALYZING"}, {Package: run.Package}, {Query: "target"}} {
			if _, err := tenant.ListRunHistory(ListOptions{Limit: 25}, filters); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := tenant.ReadPublishedResult(run.ID, 1, false, 0); !errors.Is(err, ErrNotFound) {
			t.Fatal("unpublished result visible", err)
		}
		source, err := queue.LoadRunAnalysis(t.Context(), lease)
		if err != nil {
			t.Fatal(err)
		}
		publication := analysisPublicationFixture(t, run, samples)
		if err := queue.CompleteWith(t.Context(), lease, func(tx *TenantTransaction) error { return tx.PublishRunAnalysis(source, publication) }); err != nil {
			t.Fatal(err)
		}
		data, err := tenant.ReadPublishedResult(run.ID, 1, true, samples[0].ID)
		if err != nil || data.Result.AnalysisRevision != 1 || len(data.Samples) != 2 || len(data.Findings) != 1 || len(data.Attempts) != 1 || data.Findings[0].Title != "" || data.Findings[0].Summary != "" {
			t.Fatal("read projection", err)
		}
		if _, err := tenant.ReadPublishedResult(run.ID, 2, false, 0); !errors.Is(err, ErrNotFound) {
			t.Fatal("revision isolation", err)
		}
		if _, err := tenant.ReadPublishedResult(run.ID, 1, true, samples[0].ID+999); !errors.Is(err, ErrNotFound) {
			t.Fatal("sample scope", err)
		}
		unbound, _ := store.WithOrganization(t.Context(), tenant.orgID)
		if _, err := unbound.ListRunHistory(ListOptions{Limit: 25}, RunFilters{}); !errors.Is(err, ErrManagementSession) {
			t.Fatal("unbound history", err)
		}
		foreign, _ := store.WithOrganization(tenant.ctx, tenant.orgID+1)
		if _, err := foreign.ReadPublishedResult(run.ID, 1, true, 0); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("cross-tenant capability", err)
		}
		if err := store.db.Exec("DELETE FROM role_permissions WHERE organization_id=? AND permission_code=?", tenant.orgID, "evidence.read").Error; err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.ReadPublishedResult(run.ID, 1, true, 0); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("revoked evidence read", err)
		}
		if _, err := tenant.ReadPublishedResult(run.ID, 1, false, 0); err != nil {
			t.Fatal("summary needs only run.read", err)
		}
		if err := store.db.Model(&RunResultRecord{}).Where("organization_id=? AND run_id=?", tenant.orgID, run.ID).Update("conclusion_json", strings.Repeat("x", (4<<20)+1)).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.ReadPublishedResult(run.ID, 1, false, 0); !errors.Is(err, ErrResultDocument) {
			t.Fatal("oversized document not blocked at SQL boundary", err)
		}
		if err := store.db.Model(&Session{}).Where("user_id=?", run.CreatedBy).Update("revoked_at", time.Now()).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.ListRunHistory(ListOptions{Limit: 25}, RunFilters{}); !errors.Is(err, ErrManagementSession) {
			t.Fatal("revoked session reused private cap", err)
		}
	})
}

func TestRunHistoryPaginationFiltersAndDeletedTarget(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, target, plan, policy := executionFixture(t, store, 1)
		readPermissions(t, tenant)
		for _, key := range []string{"history-1", "history-2", "history-3"} {
			if _, err := tenant.CreateRun(plan, policy, key); err != nil {
				t.Fatal(err)
			}
		}
		first, err := tenant.ListRunHistory(ListOptions{Limit: 2}, RunFilters{})
		if err != nil || len(first) != 2 || first[0].CreatedAt.Before(first[1].CreatedAt) {
			t.Fatal("first page", err)
		}
		next, err := tenant.ListRunHistory(ListOptions{AfterID: first[1].ID, Limit: 2}, RunFilters{})
		if err != nil || len(next) != 1 || next[0].CreatedAt.After(first[1].CreatedAt) || next[0].ID == first[0].ID || next[0].ID == first[1].ID {
			t.Fatal("next page", err)
		}
		for _, page := range []ListOptions{{Limit: 0}, {Limit: 101}, {Limit: 1, AfterID: -1}} {
			if _, err := tenant.ListRunHistory(page, RunFilters{}); !errors.Is(err, ErrConfiguration) {
				t.Fatal("bad page")
			}
		}
		for _, f := range []RunFilters{{Status: "DROP"}, {RiskLevel: "critical"}, {Query: strings.Repeat("x", 129)}, {TargetID: -1}} {
			if _, err := tenant.ListRunHistory(ListOptions{Limit: 25}, f); !errors.Is(err, ErrConfiguration) {
				t.Fatal("bad filter")
			}
		}
		if err := store.db.Model(&TargetRecord{}).Where("organization_id=? AND id=?", tenant.orgID, target.Target.ID).Update("deleted_at", time.Now()).Error; err != nil {
			t.Fatal(err)
		}
		rows, err := tenant.ListRunHistory(ListOptions{Limit: 25}, RunFilters{TargetID: target.Target.ID})
		if err != nil || len(rows) != 3 || rows[0].TargetID != target.Target.ID || rows[0].CurrentTargetName != nil {
			t.Fatal("deleted target erased history", err)
		}
	})
}

func TestRunHistoryStableDescendingTieAndNewInsert(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 1)
		readPermissions(t, tenant)
		ids := []int64{}
		tie := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
		for _, key := range []string{"tie-a", "tie-b", "tie-c", "tie-d"} {
			r, err := tenant.CreateRun(plan, policy, key)
			if err != nil {
				t.Fatal(err)
			}
			ids = append(ids, r.ID)
			if err := store.db.Model(&RunRecord{}).Where("organization_id=? AND id=?", tenant.orgID, r.ID).Update("created_at", tie).Error; err != nil {
				t.Fatal(err)
			}
		}
		slices.Sort(ids)
		slices.Reverse(ids)
		first, err := tenant.ListRunHistory(ListOptions{Limit: 2}, RunFilters{})
		if err != nil || len(first) != 2 || first[0].ID != ids[0] || first[1].ID != ids[1] {
			t.Fatal("descending timestamp tie", err)
		}
		newRun, err := tenant.CreateRun(plan, policy, "after-first-page")
		if err != nil {
			t.Fatal(err)
		}
		next, err := tenant.ListRunHistory(ListOptions{Limit: 2, AfterID: first[1].ID}, RunFilters{})
		if err != nil || len(next) != 2 || next[0].ID != ids[2] || next[1].ID != ids[3] {
			t.Fatal("insert changed existing second page", err)
		}
		end, err := tenant.ListRunHistory(ListOptions{Limit: 2, AfterID: next[1].ID}, RunFilters{})
		if err != nil || len(end) != 0 {
			t.Fatal("unexpected repeated rows", err)
		}
		refreshed, err := tenant.ListRunHistory(ListOptions{Limit: 1}, RunFilters{})
		if err != nil || len(refreshed) != 1 || refreshed[0].ID != newRun.ID {
			t.Fatal("newest run missing", err)
		}
		if _, err := tenant.ListRunHistory(ListOptions{Limit: 1, AfterID: 1}, RunFilters{}); !errors.Is(err, ErrConfiguration) {
			t.Fatal("unknown anchor accepted", err)
		}
	})
}
