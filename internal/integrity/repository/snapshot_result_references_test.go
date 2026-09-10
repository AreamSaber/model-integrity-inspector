package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

func snapshotResultTestObserve(t *testing.T, s *Store, cfg Config, limit int, want error) snapshotResultReferences {
	t.Helper()
	ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
	defer closeView()
	got, err := (&Store{driver: s.driver}).snapshotResultReferencesLimited(ctx, tx.Where("1=0").Limit(1), limit)
	if !errors.Is(err, want) || want != nil && !reflect.DeepEqual(got, snapshotResultReferences{}) {
		t.Fatal("result inventory not closed", err)
	}
	return got
}

func snapshotResultTestFixture(t *testing.T, s *Store, counts ...int) (*Tenant, RunRecord, []LogicalSampleRecord, map[string]any) {
	t.Helper()
	count := 2
	if len(counts) > 0 {
		count = counts[0]
	}
	tenant, _, plan, policy := executionFixture(t, s, count)
	if count > 50 {
		plan.Budget.MaxRequests = int64(count * 3)
	}
	plan, _, err := policy.Apply(plan)
	if err != nil {
		t.Fatal(err)
	}
	plan = snapshotReferenceTestAttachManifest(t, tenant.orgID, plan)
	run, err := tenant.CreateRun(plan, policy, "result-reference-current")
	if err != nil {
		t.Fatal(err)
	}
	samples, err := tenant.ListExecutionSamples(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, body := snapshotResultTestWire(t)
	features := body["features"].(map[string]any)
	features["organization_id"], features["run_id"], features["manifest_hash"] = strconv.FormatInt(tenant.orgID, 10), strconv.FormatInt(run.ID, 10), run.ManifestHash
	var members []any
	for _, sample := range samples {
		members = append(members, map[string]any{"sample_id": strconv.FormatInt(sample.ID, 10), "ordinal": sample.ExecutionOrdinal, "template_id": plan.Probes[0].TemplateID, "template_version": plan.Probes[0].TemplateVersion})
	}
	features["samples"] = members
	body["scores"].(map[string]any)["Version"] = run.ScoringVersion
	body["tokens"].(map[string]any)["Series"] = []any{}
	body["behavior"].(map[string]any)["samples"] = []any{}
	stamp := time.Now().UTC().Truncate(time.Microsecond)
	result := RunResultRecord{OrganizationID: tenant.orgID, RunID: run.ID, AnalysisRevision: 1, RiskLevel: "insufficient", EvidenceGrade: "D", Completeness: "INSUFFICIENT", ConclusionJSON: string(snapshotReferenceTestJSON(t, body)), CreatedAt: stamp, IsPublished: true}
	if err := s.db.Create(&result).Error; err != nil {
		t.Fatal(err)
	}
	return tenant, run, samples, body
}

func SnapshotResultReferencesPureProducerBridge(t *testing.T, plan domain.ExecutionPlan, org, runID int64, body []byte) {
	t.Helper()
	run := snapshotReferenceRow{OrganizationID: org, ID: runID, TargetID: plan.Target.ID, Valid: 1, ManifestHash: plan.ManifestHash, Rule: plan.Versions.Rule, Template: plan.Versions.Template, Scoring: plan.Versions.Scoring, Tokenizer: plan.Versions.Tokenizer, AnalysisSource: AnalysisSourceLegacyV1}
	if plan.AnalysisSourceVersion != "" {
		run.AnalysisSource = plan.AnalysisSourceVersion
	}
	source, err := snapshotReferencePlan(t.Context(), run, snapshotReferenceTestJSON(t, executionSnapshot{Plan: plan}), false)
	if err != nil {
		t.Fatal(err)
	}
	row := snapshotResultReferenceRow{OrganizationID: org, RunID: runID, Revision: 1, Published: 1, Valid: 1}
	got, err := snapshotResultReferenceDocument(t.Context(), row, run, source, body, snapshotReferenceLimit)
	if err != nil || got.incomplete || got.unknown || len(got.refs) < 5 {
		t.Fatal("real producer rejected or downgraded", err)
	}
}

func SnapshotResultReferencesActualProducerBridge(t *testing.T, compile func(int64, TargetState) domain.ExecutionPlan, produce func(int64, int64, domain.ExecutionPlan, []LogicalSampleRecord) []byte) {
	t.Helper()
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, target, _, policy := executionFixture(t, s, 2)
		plan := compile(tenant.orgID, target)
		run, err := tenant.CreateRun(plan, policy, "actual-result-producer")
		if err != nil {
			t.Fatal(err)
		}
		samples, err := tenant.ListExecutionSamples(run.ID)
		if err != nil {
			t.Fatal(err)
		}
		body := produce(tenant.orgID, run.ID, plan, samples)
		result := RunResultRecord{OrganizationID: tenant.orgID, RunID: run.ID, AnalysisRevision: 7, RiskLevel: "insufficient", EvidenceGrade: "D", Completeness: "INSUFFICIENT", ConclusionJSON: string(body), CreatedAt: time.Now().UTC()}
		if err := s.db.Create(&result).Error; err != nil {
			t.Fatal(err)
		}
		got := snapshotResultTestObserve(t, s, cfg, snapshotReferenceLimit, nil)
		if got.rows != 1 || got.unpublished != 1 || got.incomplete != 0 || got.unknown != 0 {
			t.Fatal("actual retained analyzer result")
		}
	})
}

func TestSnapshotResultReferencesAllRevisionsPaginationAndSameView(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, run, _, body := snapshotResultTestFixture(t, s)
		if err := s.db.Table("organizations").Where("id=?", tenant.orgID).Update("status", "disabled").Error; err != nil {
			t.Fatal(err)
		}
		for revision := 2; revision <= 102; revision++ {
			raw := snapshotReferenceTestJSON(t, body)
			if revision == 102 {
				raw = []byte(`{"schema_version":"future.analysis.v2","retained":"original"}`)
			}
			result := RunResultRecord{OrganizationID: tenant.orgID, RunID: run.ID, AnalysisRevision: revision, RiskLevel: "insufficient", EvidenceGrade: "D", Completeness: "INSUFFICIENT", ConclusionJSON: string(raw), CreatedAt: time.Now().UTC()}
			if err := s.db.Create(&result).Error; err != nil {
				t.Fatal(err)
			}
		}
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		first, err := (&Store{driver: s.driver}).snapshotResultReferences(ctx, tx.Where("1=0").Limit(1))
		if err != nil || first.rows != 102 || first.published != 1 || first.unpublished != 101 || first.incomplete != 1 || first.unknown != 1 {
			t.Fatal("all revisions/disabled or keyset", err)
		}
		if err := s.db.Table("integrity_run_results").Where("analysis_revision=102").Update("conclusion_json", `{"schema_version":"another.future.v3"}`).Error; err != nil {
			t.Fatal("independent committed update", err)
		}
		again, err := s.snapshotResultReferences(ctx, tx)
		if err != nil || !reflect.DeepEqual(first, again) {
			t.Fatal("same snapshot drift", err)
		}
		closeView()
		fresh := snapshotResultTestObserve(t, s, cfg, snapshotReferenceLimit, nil)
		if fresh.sourceSHA256 == first.sourceSHA256 {
			t.Fatal("original unknown bytes not bound")
		}
	})
}

func TestSnapshotResultReferencesActualStorageWriterIncomplete(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		_, queue, run, samples, lease := analysisReadyFixture(t, s, 2)
		source, err := queue.LoadRunAnalysis(context.Background(), lease)
		if err != nil {
			t.Fatal(err)
		}
		publication := analysisPublicationFixture(t, run, samples)
		if err := queue.CompleteWith(context.Background(), lease, func(tx *TenantTransaction) error { return tx.PublishRunAnalysis(source, publication) }); err != nil {
			t.Fatal("actual original publication", err)
		}
		got := snapshotResultTestObserve(t, s, cfg, snapshotReferenceLimit, nil)
		if got.rows != 1 || got.published != 1 || got.incomplete != 1 || got.unknown != 0 {
			t.Fatal("writer allowed incomplete was erased/upgraded")
		}
	})
}

func TestSnapshotResultReferencesDistinctUnionLimitAndOriginalHashes(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		_, run, _, body := snapshotResultTestFixture(t, s)
		first := snapshotResultTestObserve(t, s, cfg, snapshotReferenceLimit, nil)
		if len(first.references) < 1 {
			t.Fatal("fixture")
		}
		snapshotResultTestObserve(t, s, cfg, len(first.references), nil)
		body["scores"].(map[string]any)["RulesHash"] = strings.Repeat("e", 64)
		result := RunResultRecord{OrganizationID: run.OrganizationID, RunID: run.ID, AnalysisRevision: 2, RiskLevel: "insufficient", EvidenceGrade: "D", Completeness: "INSUFFICIENT", ConclusionJSON: string(snapshotReferenceTestJSON(t, body)), CreatedAt: time.Now().UTC()}
		if err := s.db.Create(&result).Error; err != nil {
			t.Fatal(err)
		}
		snapshotResultTestObserve(t, s, cfg, len(first.references), errSnapshotResultReferenceLimit)
		got := snapshotResultTestObserve(t, s, cfg, len(first.references)+1, nil)
		if len(got.references) != len(first.references)+1 || got.sourceSHA256 == first.sourceSHA256 {
			t.Fatal("same version different original parameters collapsed")
		}
	})
}

func TestSnapshotResultReferencesTransactionConfigurationAndLateRollback(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		snapshotResultTestFixture(t, s)
		ctx, tx, closeView := auditSnapshotTestTransaction(t, cfg, nil, true)
		defer closeView()
		for _, input := range []struct {
			ctx   context.Context
			tx    *gorm.DB
			limit int
			want  error
		}{{nil, tx, 1, ErrConfiguration}, {context.Background(), tx, 1, ErrConfiguration}, {ctx, s.db, 1, ErrConfiguration}, {ctx, tx, 0, ErrConfiguration}, {ctx, tx, snapshotReferenceLimit + 1, ErrConfiguration}} {
			got, err := s.snapshotResultReferencesLimited(input.ctx, input.tx, input.limit)
			if !errors.Is(err, input.want) || !reflect.DeepEqual(got, snapshotResultReferences{}) {
				t.Fatal("configuration", err)
			}
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if got, err := s.snapshotResultReferences(canceled, tx); !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(got, snapshotResultReferences{}) {
			t.Fatal("cancel", err)
		}
		rolled := false
		if err := tx.Callback().Query().After("gorm:query").Register("result_last_read_rollback", func(db *gorm.DB) {
			if !rolled && strings.Contains(db.Statement.SQL.String(), "FROM integrity_logical_samples s") {
				rolled = true
				if err := db.Statement.ConnPool.(*sql.Tx).Rollback(); err != nil {
					t.Error(err)
				}
			}
		}); err != nil {
			t.Fatal(err)
		}
		got, err := s.snapshotResultReferences(ctx, tx)
		if removeErr := tx.Callback().Query().Remove("result_last_read_rollback"); removeErr != nil {
			t.Fatal(removeErr)
		}
		if !rolled || !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(got, snapshotResultReferences{}) {
			t.Fatal("last read rollback returned observation", err)
		}
	})
}

func TestSnapshotResultReferencesPureErrorMapping(t *testing.T) {
	for _, tc := range []struct{ err, want error }{{ErrUnavailable, ErrUnavailable}, {errSnapshotReferenceLimit, errSnapshotResultReferenceLimit}, {errSnapshotReferenceUnsupported, errSnapshotResultReferenceUnsupported}, {errSnapshotResultReferenceInvalid, errSnapshotResultReferenceInvalid}} {
		if got := snapshotResultReferenceError(tc.err); !errors.Is(got, tc.want) {
			t.Fatal("error not closed")
		}
	}
	// JSON encoding remains closed even when an observation has references.
	if _, err := json.Marshal(snapshotResultReferences{references: []snapshotResultReference{{version: "retained"}}}); err == nil {
		t.Fatal("private reference escaped")
	}
}
