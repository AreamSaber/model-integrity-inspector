package repository

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

type baselineTestSigner struct{ fail atomic.Bool }

func (*baselineTestSigner) ActiveVersion() string { return "test-v1" }
func (s *baselineTestSigner) BaselineMAC(v string, data []byte) ([]byte, error) {
	if s.fail.Load() {
		return nil, errors.New("private-signing-canary")
	}
	return testAuditSigner{}.AuditMAC(v, append([]byte("baseline-test-only:"), data...))
}

// Repository-only synthetic fixture, not a real generated/approved baseline.
// The service/API integration separately verifies a real signed manifest and
// actual production analysis; this fixture isolates CAS/audit/snapshot storage.
func baselineRepositoryFixture(t *testing.T, store *Store) (*BaselineRepository, *Tenant, *BaselineSource, BaselineScope, *baselineTestSigner) {
	t.Helper()
	tenant, queue, run, samples, lease := analysisReadyFixture(t, store, 6)
	readPermissions(t, tenant)
	var role int64
	if err := tenant.scoped().Table("roles").Select("id").Where("name=?", "administrator").Scan(&role).Error; err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"baseline.read", "baseline.write", "baseline.approve"} {
		if err := store.db.Exec("INSERT INTO permissions(code) VALUES(?) ON CONFLICT(code) DO NOTHING", code).Error; err != nil {
			t.Fatal(err)
		}
		if err := store.db.Exec("INSERT INTO role_permissions(organization_id,role_id,permission_code) VALUES(?,?,?)", tenant.orgID, role, code).Error; err != nil {
			t.Fatal(err)
		}
	}
	analysis, err := queue.LoadRunAnalysis(t.Context(), lease)
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.CompleteWith(t.Context(), lease, func(tx *TenantTransaction) error {
		return tx.PublishRunAnalysis(analysis, analysisPublicationFixture(t, run, samples))
	}); err != nil {
		t.Fatal(err)
	}
	var current RunRecord
	if err := store.db.Where("id=?", run.ID).Take(&current).Error; err != nil {
		t.Fatal(err)
	}
	var frozen executionSnapshot
	if json.Unmarshal([]byte(current.ConfigSnapshot), &frozen) != nil {
		t.Fatal("fixture snapshot")
	}
	frozen.Plan.Manifest = json.RawMessage(`{}`)
	frozen.Plan.ManifestHash = baselineHash(frozen.Plan.Manifest)
	raw, err := json.Marshal(frozen)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.db.Model(&RunRecord{}).Where("id=?", run.ID).Updates(map[string]any{"config_snapshot": string(raw), "manifest_hash": frozen.Plan.ManifestHash}).Error; err != nil {
		t.Fatal(err)
	}
	signer := &baselineTestSigner{}
	repo, err := NewBaselineRepository(store, signer)
	if err != nil {
		t.Fatal(err)
	}
	source, err := repo.Source(tenant.ctx, tenant.orgID, run.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	risk := 10.0
	scope := BaselineScope{SchemaVersion: "baseline.scope.v1", OrganizationID: tenant.orgID, RunID: run.ID, TargetID: run.TargetID, AnalysisRevision: 1, Model: frozen.Plan.Target.Model, Protocol: frozen.Plan.Target.Protocol, Versions: frozen.Plan.Versions, ManifestHash: source.plan.ManifestHash, ResultHash: source.resultHash, ParametersHash: strings.Repeat("a", 64), ExpectedSamples: 6, ValidSamples: 6, OverallRisk: &risk, Completeness: "PARTIAL", SampledAt: source.createdAt}
	return repo, tenant, source, scope, signer
}
func baselineMutation() BaselineMutation {
	return BaselineMutation{Name: "Synthetic reviewed reference", Source: "historical", Region: "declared-test-region", ExpiresAt: time.Now().UTC().Add(24 * time.Hour)}
}
func baselineApproval(version int) BaselineApproval {
	return BaselineApproval{Version: version, Reason: "Explicit synthetic reviewer action", AcknowledgeDevelopmentLimits: true}
}

func TestBaselineRepositoryLifecycleCASAndTenant(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		repo, tenant, source, scope, _ := baselineRepositoryFixture(t, store)
		r, err := repo.Create(tenant.ctx, tenant.orgID, source, scope, baselineMutation())
		if err != nil {
			t.Fatal(err)
		}
		read, err := repo.Get(tenant.ctx, tenant.orgID, r.ID)
		if err != nil || read.Version != 1 || read.Status != "draft" || read.ReviewedBy != nil {
			t.Fatal("draft read", err)
		}
		if _, err := repo.Get(tenant.ctx, tenant.orgID+1, r.ID); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("tenant boundary", err)
		}
		if _, err := repo.Get(t.Context(), tenant.orgID, r.ID); !errors.Is(err, ErrManagementSession) {
			t.Fatal("cap required", err)
		}
		name := "renamed draft"
		r, err = repo.Update(tenant.ctx, tenant.orgID, r.ID, 1, &name, nil)
		if err != nil || r.Version != 2 {
			t.Fatal(err)
		}
		if _, err := repo.Update(tenant.ctx, tenant.orgID, r.ID, 1, &name, nil); !errors.Is(err, ErrConflict) {
			t.Fatal("stale edit", err)
		}
		var wg sync.WaitGroup
		results := make(chan error, 2)
		for range 2 {
			wg.Go(func() {
				_, e := repo.Approve(tenant.ctx, tenant.orgID, r.ID, source, scope, baselineApproval(2))
				results <- e
			})
		}
		wg.Wait()
		close(results)
		wins, conflicts := 0, 0
		for err := range results {
			if err == nil {
				wins++
			} else if errors.Is(err, ErrConflict) {
				conflicts++
			} else {
				t.Fatal(err)
			}
		}
		if wins != 1 || conflicts != 1 {
			t.Fatal("approval CAS", wins, conflicts)
		}
		r, err = repo.Get(tenant.ctx, tenant.orgID, r.ID)
		if err != nil || r.Version != 3 || r.ReviewedBy == nil || r.Status != "approved" {
			t.Fatal(err)
		}
		if _, err := repo.Update(tenant.ctx, tenant.orgID, r.ID, 3, &name, nil); !errors.Is(err, ErrBaselineState) {
			t.Fatal("approved record overwritten", err)
		}
		reviewExplanation := r.ReviewExplanation
		r, err = repo.Retire(tenant.ctx, tenant.orgID, r.ID, 3, "reference retired by explicit test action")
		if err != nil || r.Status != "retired" || r.Version != 4 || r.RetirementReason != "reference retired by explicit test action" || r.ReviewExplanation != reviewExplanation {
			t.Fatal(err)
		}
		if _, err := repo.Approve(tenant.ctx, tenant.orgID, r.ID, source, scope, baselineApproval(4)); !errors.Is(err, ErrBaselineState) {
			t.Fatal("retired reapproved", err)
		}
		if err := store.VerifyAllAudit(t.Context(), true); err != nil {
			t.Fatal(err)
		}
	})
}

func TestBaselineRepositoryAuditSignerSourceAndAuthorityFailClosed(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		repo, tenant, source, scope, signer := baselineRepositoryFixture(t, store)
		signer.fail.Store(true)
		if _, err := repo.Create(tenant.ctx, tenant.orgID, source, scope, baselineMutation()); !errors.Is(err, ErrBaselineIntegrity) {
			t.Fatal("signer failure", err)
		}
		signer.fail.Store(false)
		var count int64
		if err := store.db.Model(&BaselineRecord{}).Count(&count).Error; err != nil || count != 0 {
			t.Fatal("failed signer committed row", err)
		}
		brokenAudit := &switchAuditSigner{}
		brokenAudit.fail.Store(true)
		store.auditSigner = brokenAudit
		if _, err := repo.Create(tenant.ctx, tenant.orgID, source, scope, baselineMutation()); !errors.Is(err, audit.ErrUnavailable) {
			t.Fatal("audit failure", err)
		}
		store.auditSigner = testAuditSigner{}
		if err := store.db.Model(&BaselineRecord{}).Count(&count).Error; err != nil || count != 0 {
			t.Fatal("failed audit committed row", err)
		}
		r, err := repo.Create(tenant.ctx, tenant.orgID, source, scope, baselineMutation())
		if err != nil {
			t.Fatal(err)
		}
		old := source.result.Result.ConclusionJSON
		if err := store.db.Model(&RunResultRecord{}).Where("organization_id=? AND run_id=?", tenant.orgID, source.runID).Update("conclusion_json", old+" ").Error; err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Approve(tenant.ctx, tenant.orgID, r.ID, source, scope, baselineApproval(1)); !errors.Is(err, ErrBaselineSource) {
			t.Fatal("source changed between prepare and approval", err)
		}
		if err := store.db.Model(&RunResultRecord{}).Where("organization_id=? AND run_id=?", tenant.orgID, source.runID).Update("conclusion_json", old).Error; err != nil {
			t.Fatal(err)
		}
		if err := store.db.Exec("DELETE FROM role_permissions WHERE organization_id=? AND permission_code='baseline.approve'", tenant.orgID).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Approve(tenant.ctx, tenant.orgID, r.ID, source, scope, baselineApproval(1)); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("revoked permission", err)
		}
		read, err := repo.Get(tenant.ctx, tenant.orgID, r.ID)
		if err != nil || read.Version != 1 || read.Status != "draft" {
			t.Fatal("denied write mutated", err)
		}
		if err := store.db.Model(&Session{}).Where("user_id=?", *r.CreatedBy).Update("revoked_at", time.Now()).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := repo.Get(tenant.ctx, tenant.orgID, r.ID); !errors.Is(err, ErrManagementSession) {
			t.Fatal("revoked session retained", err)
		}
	})
}

func TestBaselineRepositoryAdmissionTamperAndTextBounds(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		repo, tenant, source, scope, _ := baselineRepositoryFixture(t, store)
		r, err := repo.Create(tenant.ctx, tenant.orgID, source, scope, baselineMutation())
		if err != nil {
			t.Fatal(err)
		}
		input := baselineApproval(1)
		input.AcknowledgeDevelopmentLimits = false
		if _, err := repo.Approve(tenant.ctx, tenant.orgID, r.ID, source, scope, input); !errors.Is(err, ErrBaselineInvalid) {
			t.Fatal("missing explicit acknowledgement", err)
		}
		invalid := scope
		invalid.ValidSamples = 0
		if _, err := repo.Approve(tenant.ctx, tenant.orgID, r.ID, source, invalid, baselineApproval(1)); !errors.Is(err, ErrBaselineSource) {
			t.Fatal("zero valid admitted", err)
		}
		invalid = scope
		invalid.Completeness = "INSUFFICIENT"
		if _, err := repo.Approve(tenant.ctx, tenant.orgID, r.ID, source, invalid, baselineApproval(1)); !errors.Is(err, ErrBaselineSource) {
			t.Fatal("insufficient admitted", err)
		}
		high := 50.0
		invalid = scope
		invalid.OverallRisk = &high
		if _, err := repo.Approve(tenant.ctx, tenant.orgID, r.ID, source, invalid, baselineApproval(1)); !errors.Is(err, ErrBaselineInvalid) {
			t.Fatal("high risk without business review", err)
		}
		for _, field := range []string{"name", "approval_mac", "source_result_hash", "snapshot_json"} {
			if err := store.db.Model(&BaselineRecord{}).Where("id=?", r.ID).Update(field, strings.Repeat("private-canary", 100000)).Error; err != nil {
				t.Fatal(err)
			}
			if _, err := repo.Get(tenant.ctx, tenant.orgID, r.ID); !errors.Is(err, ErrBaselineIntegrity) {
				t.Fatal("tamper accepted", field, err)
			}
			if err := store.db.Session(&gorm.Session{SkipHooks: true}).Model(&BaselineRecord{}).Where("id=?", r.ID).Select("*").Updates(&r).Error; err != nil {
				t.Fatal(err)
			}
			if _, err := repo.Get(tenant.ctx, tenant.orgID, r.ID); err != nil {
				t.Fatal("fixture restore lost its MAC", err)
			}
		}
		for _, p := range []BaselineList{{Limit: 0}, {Limit: 101}, {Limit: 1, AfterID: -1}, {Limit: 1, Status: "fake"}} {
			if _, err := repo.List(tenant.ctx, tenant.orgID, p); !errors.Is(err, ErrBaselineInvalid) {
				t.Fatal("unbounded list", err)
			}
		}
	})
}
