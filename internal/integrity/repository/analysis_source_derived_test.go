package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/adapter/openaichat"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

func TestAnalysisDerivedSQLRawJSONMeasurement(t *testing.T) {
	if analysisDerivedBatchBytes != features.MaxBatchBytes || analysisDerivedRequestBytes != openaichat.MaxRequestBytes || MaxAttemptDerivedBytes != features.MaxDerivedBytes {
		t.Fatal("repository SQL byte contracts drifted from actual feature/adapter contracts")
	}
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		if err := s.db.Exec("CREATE TABLE analysis_json_size_fixture (encoded TEXT NOT NULL)").Error; err != nil {
			t.Fatal("create raw JSON byte fixture")
		}
		for _, tc := range []struct {
			name, outer string
			invalid     bool
		}{
			{"utf8-escaped", `{"payload":{"a":"中文","b":"\u003c","c":1}}`, false},
			{"spaces-inside-string", `{"payload":{"a":"  keep  "}}`, false},
			{"whitespace", `{"payload":{ "a" : [ 1, 2 ] }}`, s.driver == "sqlite"},
			{"duplicate", `{"payload":{},"payload":{"large":"never-under-count"}}`, true},
			{"missing", `{}`, true}, {"not-object", `{"payload":"invalid"}`, true},
			{"invalid-json", `{"payload":`, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if err := s.db.Exec("DELETE FROM analysis_json_size_fixture").Error; err != nil {
					t.Fatal("clear byte fixture")
				}
				if err := s.db.Exec("INSERT INTO analysis_json_size_fixture(encoded) VALUES (?)", tc.outer).Error; err != nil {
					t.Fatal("insert byte fixture")
				}
				measured, err := analysisJSONPayloadBytes(s.db.Table("analysis_json_size_fixture"), s.driver, "encoded", []string{"payload"}, analysisDerivedRequestBytes)
				if tc.invalid {
					if !errors.Is(err, ErrAnalysisSource) {
						t.Fatal("ambiguous/non-canonical source was not rejected before fetch")
					}
					return
				}
				var raw struct {
					Payload json.RawMessage `json:"payload"`
				}
				if json.Unmarshal([]byte(tc.outer), &raw) != nil {
					t.Fatal("decode size fixture")
				}
				if err != nil || int64(len(raw.Payload)) != measured {
					t.Fatal("SQL byte count differs from feature RawMessage byte count")
				}
			})
		}
	})
}

func TestAnalysisDerivedCombinedBudgetRejectsBeforeAnySourceFetch(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		// This real execution/SQL fixture uses opaque repository S1, not a valid
		// signed compiler Manifest or a production-capacity acceptance claim.
		tenant, _, plan, policy := executionFixture(t, s, 4)
		plan.AnalysisSourceVersion = domain.AnalysisSourceDerivedV1
		plan.Manifest = []byte(`{"size_fixture":"` + strings.Repeat("m", (2<<20)-1024) + `"}`)
		hash := sha256.Sum256(plan.Manifest)
		plan.ManifestHash = hex.EncodeToString(hash[:])
		for i := range plan.Probes[0].Samples {
			plan.Probes[0].Samples[i].Request.Messages[0].Content = strings.Repeat("w", 768<<10)
		}
		run, err := tenant.CreateRun(plan, policy, "analysis-combined-budget")
		if err != nil {
			t.Fatal("create source budget fixture", err)
		}
		queue, err := s.OpenJobQueue(tenant.ctx)
		if err != nil {
			t.Fatal("open source budget queue")
		}
		t.Cleanup(func() { _ = queue.Close(t.Context()) })
		start, err := queue.Claim(tenant.ctx)
		if err != nil || start == nil {
			t.Fatal("claim source budget plan")
		}
		if err := queue.CompleteWith(tenant.ctx, *start, func(tx *TenantTransaction) error { return tx.StartRunWithDerivedSource(run.ID) }); err != nil {
			t.Fatal("start source budget plan", err)
		}
		for completed := 0; completed < 8; completed++ {
			if err := s.db.Model(&Job{}).Where("organization_id = ? AND status = 'pending' AND type = ?", tenant.orgID, string(JobSampleExecute)).Update("available_at", time.Now().UTC().Add(-time.Second)).Error; err != nil {
				t.Fatal("make source budget sample available")
			}
			lease, err := queue.Claim(tenant.ctx)
			if err != nil || lease == nil || JobType(lease.Job.Type) != JobSampleExecute {
				t.Fatal("claim source budget attempt")
			}
			samples, err := tenant.ListExecutionSamples(run.ID)
			if err != nil {
				t.Fatal("read source budget samples")
			}
			var sample LogicalSampleRecord
			for _, candidate := range samples {
				if candidate.ID == lease.Job.ObjectID {
					sample = candidate
				}
			}
			attempt := reserveTestAttempt(t, tenant, queue, *lease, sample)
			outcome := successOutcome()
			if attempt.AttemptNo == 1 {
				outcome.Validity, outcome.ErrorCode, outcome.HTTPStatus = "INVALID_RETRYABLE", "MI_TIMEOUT", 408
			}
			candidates := derivedFixtureCandidates(run, sample, attempt, outcome)
			for i := range candidates.Items {
				candidates.Items[i].Record.Payload = bytes.Repeat([]byte{'s'}, MaxAttemptDerivedBytes)
			}
			if err := queue.CompleteWith(tenant.ctx, *lease, func(tx *TenantTransaction) error {
				return tx.FinishAttemptWithDerived(sample.ID, attempt.ID, outcome, 0, candidates, nil)
			}); err != nil {
				t.Fatal("settle source budget attempt", err)
			}
		}
		lease, err := queue.Claim(tenant.ctx)
		if err != nil || lease == nil || JobType(lease.Job.Type) != JobRunAnalyze {
			t.Fatal("claim source budget analysis")
		}
		const callback = "analysis_reject_source_payload_fetch"
		guard := func(db *gorm.DB) {
			switch db.Statement.Table {
			case "integrity_runs", "integrity_attempt_derived":
				if len(db.Statement.Selects) == 1 && (db.Statement.Selects[0] == "id" || db.Statement.Selects[0] == "attempt_id" || db.Statement.Selects[0] == "analysis_source_version") {
					return
				}
			case "integrity_logical_samples", "integrity_attempts":
			default:
				return
			}
			t.Error("cumulative source budget was not checked before S2/S1 payload fetch")
			_ = db.AddError(ErrAnalysisSource)
		}
		if err := s.db.Callback().Query().Before("gorm:query").Register(callback, guard); err != nil {
			t.Fatal("install prefetch prohibition")
		}
		t.Cleanup(func() { _ = s.db.Callback().Query().Remove(callback) })
		if source, err := queue.LoadRunAnalysis(tenant.ctx, *lease); source != nil || !errors.Is(err, ErrAnalysisLimit) {
			t.Fatal("combined source over 8 MiB was not refused before fetch", err)
		}
		if err := s.db.Callback().Query().Remove(callback); err != nil {
			t.Fatal("remove prefetch prohibition for exact boundary control")
		}
		// At exactly the actual feature budget the duplicated JSON wrappers must
		// not create a false rejection. Only synthetic opaque S1 sizes change.
		wireBytes, err := analysisJSONPayloadBytes(s.db.Model(&AttemptRecord{}).Where("run_id = ?", run.ID), s.driver, "request_snapshot", []string{"payload"}, analysisDerivedRequestBytes)
		if err != nil {
			t.Fatal("measure exact source boundary")
		}
		s1Bytes := analysisDerivedBatchBytes - int64(len(plan.Manifest)) - wireBytes
		var ids []int64
		if err := s.db.Model(&AttemptDerivedRecord{}).Where("run_id = ?", run.ID).Order("attempt_id").Pluck("attempt_id", &ids).Error; err != nil || len(ids) != 8 || s1Bytes < 8 || s1Bytes-7 > MaxAttemptDerivedBytes {
			t.Fatal("exact source boundary fixture does not fit row contracts")
		}
		for i, id := range ids {
			size := int64(1)
			if i == len(ids)-1 {
				size = s1Bytes - 7
			}
			if err := s.db.Model(&AttemptDerivedRecord{}).Where("attempt_id = ?", id).Update("payload", bytes.Repeat([]byte{'s'}, int(size))).Error; err != nil {
				t.Fatal("set exact source byte boundary")
			}
		}
		exact, err := queue.LoadRunAnalysis(tenant.ctx, *lease)
		if err != nil || exact == nil {
			t.Fatal("exact 8 MiB logical source rejected due to duplicate JSON representation", err)
		}
		if err := exact.Use(func(data AnalysisData) error {
			represented := len(data.Run.ConfigSnapshot)
			for _, a := range data.Attempts {
				represented += len(a.RequestSnapshot)
			}
			if int64(represented) <= analysisDerivedBatchBytes {
				t.Fatal("fixture did not exercise repeated encodings above the logical source budget")
			}
			return nil
		}); err != nil {
			t.Fatal("inspect exact boundary receipt")
		}
		if err := s.db.Model(&AttemptDerivedRecord{}).Where("attempt_id = ?", ids[len(ids)-1]).Update("payload", bytes.Repeat([]byte{'s'}, int(s1Bytes-6))).Error; err != nil {
			t.Fatal("install one-byte source overflow")
		}
		if err := s.db.Callback().Query().Before("gorm:query").Register(callback, guard); err != nil {
			t.Fatal("restore prefetch prohibition")
		}
		if source, err := queue.LoadRunAnalysis(tenant.ctx, *lease); source != nil || !errors.Is(err, ErrAnalysisLimit) {
			t.Fatal("one-byte cumulative overflow was not rejected before fetch", err)
		}
	})
}

// Repository-only opaque S1 fixtures exercise SQL provenance and publication
// receipts. Real signatures, TLS and complete scoring are Worker test concerns.
func derivedAnalysisReady(t *testing.T, s *Store, retry, body bool) (*Tenant, *JobQueue, RunRecord, []LogicalSampleRecord, JobLease) {
	t.Helper()
	tenant, run, queue, sample, attempt, lease := derivedExecutionFixture(t, s)
	finish := func(outcome domain.AttemptOutcome) {
		var capture *AttemptBodyCapture
		if body {
			capture = derivedFixtureBody(t, tenant, queue, lease, sample, attempt)
		}
		candidates := derivedFixtureCandidates(run, sample, attempt, outcome)
		if err := queue.CompleteWith(tenant.ctx, lease, func(tx *TenantTransaction) error {
			return tx.FinishAttemptWithDerived(sample.ID, attempt.ID, outcome, 0, candidates, capture)
		}); err != nil {
			t.Fatal("complete derived analysis fixture", err)
		}
	}
	if retry {
		outcome := successOutcome()
		outcome.Validity, outcome.ErrorCode = "INVALID_RETRYABLE", "MI_TIMEOUT"
		outcome.HTTPStatus = 408
		finish(outcome)
		if err := s.db.Model(&Job{}).Where("organization_id = ? AND type = ? AND status = 'pending'", tenant.orgID, string(JobSampleExecute)).Update("available_at", time.Now().UTC().Add(-time.Second)).Error; err != nil {
			t.Fatal("make real queued retry available")
		}
		next, err := queue.Claim(tenant.ctx)
		if err != nil || next == nil || JobType(next.Job.Type) != JobSampleExecute {
			t.Fatal("claim real retry", err)
		}
		lease = *next
		samples, err := tenant.ListExecutionSamples(run.ID)
		if err != nil || len(samples) != 1 {
			t.Fatal("read retry sample")
		}
		sample = samples[0]
		attempt = reserveTestAttempt(t, tenant, queue, lease, sample)
	}
	finish(successOutcome())
	analysis, err := queue.Claim(tenant.ctx)
	if err != nil || analysis == nil || JobType(analysis.Job.Type) != JobRunAnalyze {
		t.Fatal("claim derived analysis", err)
	}
	run, err = tenant.GetRun(run.ID)
	if err != nil {
		t.Fatal("read closed derived run")
	}
	samples, err := tenant.ListExecutionSamples(run.ID)
	if err != nil {
		t.Fatal("read closed derived samples")
	}
	return tenant, queue, run, samples, *analysis
}

func TestAnalysisDerivedSourceAllAttemptsNeverLoadsRaw(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, queue, run, _, lease := derivedAnalysisReady(t, s, true, true)
		for _, callback := range []string{"analysis_no_raw_query", "analysis_no_raw_row"} {
			guard := func(tx *gorm.DB) {
				if tx.Statement.Table == "integrity_response_evidence" || tx.Statement.Table == "integrity_display_evidence" {
					_ = tx.AddError(ErrAnalysisSource)
					t.Error("derived loader accessed a raw/display body table")
				}
			}
			if callback == "analysis_no_raw_query" {
				if err := s.db.Callback().Query().Before("gorm:query").Register(callback, guard); err != nil {
					t.Fatal("register raw read prohibition")
				}
				t.Cleanup(func() { _ = s.db.Callback().Query().Remove(callback) })
			} else {
				if err := s.db.Callback().Row().Before("gorm:row").Register(callback, guard); err != nil {
					t.Fatal("register raw row prohibition")
				}
				t.Cleanup(func() { _ = s.db.Callback().Row().Remove(callback) })
			}
		}
		source, err := queue.LoadRunAnalysis(tenant.ctx, lease)
		if err != nil {
			t.Fatal("load all derived attempts", err)
		}
		if err := source.Use(func(data AnalysisData) error {
			if data.Run.ID != run.ID || len(data.Derived) != 2 || len(data.Attempts) != 2 || len(data.Evidence) != 0 || data.Attempts[0].AttemptNo != 1 || data.Attempts[1].AttemptNo != 2 {
				t.Fatal("derived source lost all-attempt provenance")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		cancelCtx, cancel := context.WithCancel(tenant.ctx)
		cancel()
		if got, err := queue.LoadRunAnalysis(cancelCtx, lease); err == nil || got != nil {
			t.Fatal("canceled source read succeeded")
		}
		for _, change := range []func(*JobLease){func(v *JobLease) { v.Generation++ }, func(v *JobLease) { v.Job.OrganizationID++ }, func(v *JobLease) { v.Job.ObjectID++ }} {
			wrong := lease
			change(&wrong)
			if got, err := queue.LoadRunAnalysis(tenant.ctx, wrong); err == nil || got != nil {
				t.Fatal("forged derived source fence accepted")
			}
		}
	})
}

func TestAnalysisDerivedMissingRecordsCannotFallbackEvenWithRaw(t *testing.T) {
	for _, mode := range []string{"retry", "final", "all"} {
		t.Run(mode, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				tenant, queue, run, samples, lease := derivedAnalysisReady(t, s, true, true)
				query := s.db.Where("organization_id = ? AND run_id = ?", tenant.orgID, run.ID)
				switch mode {
				case "retry":
					query = query.Where("attempt_id <> ?", *samples[0].FinalAttemptID)
				case "final":
					query = query.Where("attempt_id = ?", *samples[0].FinalAttemptID)
				}
				if err := query.Delete(&AttemptDerivedRecord{}).Error; err != nil {
					t.Fatal("delete isolated S1 fixture")
				}
				var rawCount int64
				if err := s.db.Model(&ResponseEvidenceRecord{}).Count(&rawCount).Error; err != nil || rawCount != 2 {
					t.Fatal("fallback counterexample lost its raw bodies")
				}
				if got, err := queue.LoadRunAnalysis(tenant.ctx, lease); !errors.Is(err, ErrAnalysisSource) || got != nil {
					t.Fatal("missing S1 accepted as unavailable response or raw fallback", err)
				}
			})
		})
	}
}

func TestAnalysisDerivedRecoveryRequiresItsExplicitSignedObservation(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, run, queue, sample, attempt, old := derivedExecutionFixture(t, s)
		if err := s.db.Model(&Job{}).Where("id = ?", old.Job.ID).Update("lease_until", time.Now().UTC().Add(-time.Second)).Error; err != nil {
			t.Fatal("expire old fixture lease")
		}
		fresh, err := queue.Claim(tenant.ctx)
		if err != nil || fresh == nil || fresh.Generation <= old.Generation {
			t.Fatal("claim actual recovery generation")
		}
		candidates := AttemptDerivedCandidates{Scope: derivedScopeFor(run, sample, attempt), Items: []AttemptDerivedCandidate{{Status: "UNCERTAIN", Validity: "INVALID_RETRYABLE", ErrorCode: "MI_UNCERTAIN_ATTEMPT", Record: DerivedRecord{Version: domain.AnalysisSourceDerivedV1, KeyVersion: "fixture", Payload: []byte("explicit-recovery-observation"), MAC: bytes.Repeat([]byte{3}, 32)}}}}
		if err := queue.CompleteWith(tenant.ctx, *fresh, func(tx *TenantTransaction) error {
			return tx.RecoverInterruptedSampleWithDerived(sample.ID, attempt.ID, candidates)
		}); err != nil {
			t.Fatal("persist real recovered source", err)
		}
		lease, err := queue.Claim(tenant.ctx)
		if err != nil || lease == nil || JobType(lease.Job.Type) != JobRunAnalyze {
			t.Fatal("claim recovered analysis")
		}
		source, err := queue.LoadRunAnalysis(tenant.ctx, *lease)
		if err != nil {
			t.Fatal("read explicit recovered S1", err)
		}
		if err := source.Use(func(data AnalysisData) error {
			if len(data.Derived) != 1 || len(data.Attempts) != 1 || data.Attempts[0].DerivedReceipt != DerivedRecovered || data.Derived[0].Status != "UNCERTAIN" || len(data.Evidence) != 0 {
				t.Fatal("recovery receipt became missing or normal response")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := s.db.Where("organization_id = ? AND attempt_id = ?", tenant.orgID, attempt.ID).Delete(&AttemptDerivedRecord{}).Error; err != nil {
			t.Fatal("remove isolated recovered observation")
		}
		if got, err := queue.LoadRunAnalysis(tenant.ctx, *lease); !errors.Is(err, ErrAnalysisSource) || got != nil {
			t.Fatal("missing recovery S1 treated as legitimate no-response")
		}
	})
}

func TestAnalysisDerivedGenuinelyUnattemptedRunNeedsNoInventedRecord(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, s, 1)
		plan.AnalysisSourceVersion = domain.AnalysisSourceDerivedV1
		plan.Manifest = []byte(`{"fixture":"unattempted-repository-only"}`)
		digest := sha256.Sum256(plan.Manifest)
		plan.ManifestHash = hex.EncodeToString(digest[:])
		run, err := tenant.CreateRun(plan, policy, "unattempted-derived")
		if err != nil {
			t.Fatal("create unattempted derived fixture")
		}
		queue, err := s.OpenJobQueue(tenant.ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = queue.Close(t.Context()) })
		start, err := queue.Claim(tenant.ctx)
		if err != nil || start == nil {
			t.Fatal("claim unattempted plan")
		}
		if err := queue.CompleteWith(tenant.ctx, *start, func(tx *TenantTransaction) error { return tx.StartRunWithDerivedSource(run.ID) }); err != nil {
			t.Fatal("start unattempted derived run")
		}
		sample, err := queue.Claim(tenant.ctx)
		if err != nil || sample == nil {
			t.Fatal("claim unattempted sample")
		}
		if err := queue.CompleteWith(tenant.ctx, *sample, func(tx *TenantTransaction) error {
			return tx.FailUnattemptedSample(sample.Job.ObjectID, "MI_SECRET_UNAVAILABLE")
		}); err != nil {
			t.Fatal("close genuine pre-dispatch failure")
		}
		lease, err := queue.Claim(tenant.ctx)
		if err != nil || lease == nil || JobType(lease.Job.Type) != JobRunAnalyze {
			t.Fatal("claim actual unattempted analysis")
		}
		source, err := queue.LoadRunAnalysis(tenant.ctx, *lease)
		if err != nil {
			t.Fatal("unattempted Run incorrectly required a fabricated S1", err)
		}
		if err := source.Use(func(data AnalysisData) error {
			if len(data.Samples) != 1 || data.Samples[0].AttemptCount != 0 || data.Samples[0].FinalAttemptID != nil || data.Samples[0].Validity != "NOT_APPLICABLE" || len(data.Attempts) != 0 || len(data.Derived) != 0 || len(data.Evidence) != 0 {
				t.Fatal("pre-dispatch failure invented attempt/evidence")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestAnalysisLegacyPolicyCannotReviveBodyAndNeverUpgradesMode(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, queue, _, _, lease := analysisReadyFixture(t, s, 1)
		for _, days := range []int{0, 180} {
			derivedFixtureRetention(t, tenant, days)
			source, err := queue.LoadRunAnalysis(tenant.ctx, lease)
			if err != nil {
				t.Fatal("read policy-limited legacy source", err)
			}
			if err := source.Use(func(data AnalysisData) error {
				if data.Run.AnalysisSourceVersion != AnalysisSourceLegacyV1 || len(data.Attempts) != 1 || data.Attempts[0].DerivedReceipt != DerivedLegacy || len(data.Evidence) != 0 || len(data.Derived) != 0 {
					t.Fatal("policy change revived legacy body or synthesized S1")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestAnalysisDerivedMirrorsReceiptsAndOrphansFailClosed(t *testing.T) {
	for _, mode := range []string{"outcome", "created", "key", "pending", "plan-mode", "orphan"} {
		t.Run(mode, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				tenant, queue, run, samples, lease := derivedAnalysisReady(t, s, false, false)
				query := s.db.Model(&AttemptDerivedRecord{}).Where("organization_id = ? AND attempt_id = ?", tenant.orgID, *samples[0].FinalAttemptID)
				var err error
				switch mode {
				case "outcome":
					err = query.Update("error_code", "MI_TIMEOUT").Error
				case "created":
					err = query.Update("created_at", time.Now().UTC().Add(time.Hour)).Error
				case "key":
					err = query.Update("key_version", "invalid/key").Error
				case "pending":
					err = s.db.Model(&AttemptRecord{}).Where("id = ?", *samples[0].FinalAttemptID).Updates(map[string]any{"status": "DISPATCHED", "derived_receipt": DerivedPending}).Error
					if err != nil {
						t.Log("receipt downgrade blocked by the real migration guard")
						return
					}
				case "plan-mode":
					changed := strings.Replace(run.ConfigSnapshot, `"analysis_source_version":"mii.derived-s1.v1"`, `"analysis_source_version":""`, 1)
					if changed == run.ConfigSnapshot {
						t.Fatal("mode mutation did not change frozen projection")
					}
					err = s.db.Model(&RunRecord{}).Where("id = ?", run.ID).Update("config_snapshot", changed).Error
				case "orphan":
					// The real composite FK is the first defense. Do not disable it
					// just to make a malformed source enter the loader.
					if err := query.Update("attempt_id", *samples[0].FinalAttemptID+1).Error; err == nil {
						t.Fatal("database allowed an orphan derived row")
					}
					return
				}
				if err != nil {
					t.Fatal("install isolated invalid source projection")
				}
				if got, err := queue.LoadRunAnalysis(tenant.ctx, lease); err == nil || got != nil {
					t.Fatal("invalid derived source projection accepted")
				}
			})
		})
	}
}

func TestAnalysisDerivedPublicationRechecksEveryS1ByteAndReceipt(t *testing.T) {
	for _, mode := range []string{"retry-payload", "final-mac", "key-version", "receipt", "body-cleanup", "unchanged"} {
		t.Run(mode, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				tenant, queue, run, samples, lease := derivedAnalysisReady(t, s, true, true)
				source, err := queue.LoadRunAnalysis(tenant.ctx, lease)
				if err != nil {
					t.Fatal("mint derived source receipt", err)
				}
				var records []AttemptDerivedRecord
				if err := s.db.Order("attempt_id").Find(&records).Error; err != nil || len(records) != 2 {
					t.Fatal("read receipt mutation fixture")
				}
				switch mode {
				case "retry-payload":
					err = s.db.Model(&AttemptDerivedRecord{}).Where("attempt_id = ?", records[0].AttemptID).Update("payload", []byte("changed-retry-source")).Error
				case "final-mac":
					err = s.db.Model(&AttemptDerivedRecord{}).Where("attempt_id = ?", records[1].AttemptID).Update("mac", bytes.Repeat([]byte{9}, 32)).Error
				case "key-version":
					err = s.db.Model(&AttemptDerivedRecord{}).Where("attempt_id = ?", records[0].AttemptID).Update("key_version", "other.version").Error
				case "receipt":
					err = s.db.Model(&AttemptRecord{}).Where("id = ?", records[0].AttemptID).Updates(map[string]any{"status": "DISPATCHED", "derived_receipt": DerivedPending}).Error
					if err != nil {
						// Current migrations prevent this mutation before publication.
						// Independently assert that the private digest still binds the
						// receipt, without disabling the database defense for a test.
						changed := source.data
						changed.Attempts = append([]AttemptRecord(nil), changed.Attempts...)
						changed.Attempts[0].DerivedReceipt = DerivedPending
						digest, digestErr := analysisDerivedDigest(changed)
						if digestErr != nil || digest == source.sourceDigest {
							t.Fatal("derived receipt missing from source digest")
						}
						t.Log("receipt downgrade blocked by the real migration guard; receipt digest differs")
						return
					}
				case "body-cleanup":
					err = s.db.Where("organization_id = ? AND run_id = ?", tenant.orgID, run.ID).Delete(&ResponseEvidenceRecord{}).Error
					if err == nil {
						err = s.db.Model(&AttemptRecord{}).Where("organization_id = ? AND run_id = ?", tenant.orgID, run.ID).Update("response_body_receipt", BodyNotRetained).Error
					}
				}
				if err != nil {
					t.Fatal("mutate source after fenced load")
				}
				p := analysisPublicationFixture(t, run, samples)
				publish := func(tx *TenantTransaction) error { return tx.PublishRunAnalysis(source, p) }
				err = queue.CompleteWith(tenant.ctx, lease, publish)
				if mode == "unchanged" || mode == "body-cleanup" {
					if err != nil {
						t.Fatal("unchanged S1 receipt rejected", err)
					}
					if err := queue.CompleteWith(tenant.ctx, lease, publish); !errors.Is(err, ErrJobLeaseLost) {
						t.Fatal("duplicate derived publication accepted", err)
					}
				} else {
					if !errors.Is(err, ErrAnalysisSource) {
						t.Fatal("read-after-change receipt published", err)
					}
					var count int64
					if err := s.db.Model(&RunResultRecord{}).Count(&count).Error; err != nil || count != 0 {
						t.Fatal("changed S1 left a published revision")
					}
					if err := s.db.Model(&FindingRecord{}).Count(&count).Error; err != nil || count != 0 {
						t.Fatal("changed S1 left findings")
					}
					if err := s.db.Table("integrity_audit_logs").Where("action = ?", "run.analysis.publish").Count(&count).Error; err != nil || count != 0 {
						t.Fatal("changed S1 left success audit")
					}
					job, _ := tenant.GetJob(lease.Job.ID)
					current, _ := tenant.GetRun(run.ID)
					if job.Status != "running" || current.Status != "ANALYZING" || current.Version != run.Version {
						t.Fatal("changed S1 finalized Run or job")
					}
				}
				if err := s.VerifyAllAudit(tenant.ctx, true); err != nil {
					t.Fatal("derived publication changed audit integrity")
				}
			})
		})
	}
}

func TestAnalysisDerivedSQLByteBoundsBeforePayloadFetch(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		// Exercise the exact production SQL guard against real dialect engines;
		// this is a size-query fixture, not a fabricated valid execution graph.
		if err := s.db.Exec("CREATE TABLE analysis_size_fixture (payload BYTEA NOT NULL)").Error; err != nil {
			t.Fatal("create bounded size-query fixture")
		}
		for _, tc := range []struct {
			name        string
			rows, bytes int
			want        error
		}{{"exact-row", 1, MaxAttemptDerivedBytes, nil}, {"single-row", 1, MaxAttemptDerivedBytes + 1, ErrAnalysisLimit}, {"total", 257, MaxAttemptDerivedBytes, ErrAnalysisLimit}, {"count", 451, 1, ErrAnalysisLimit}} {
			t.Run(tc.name, func(t *testing.T) {
				if err := s.db.Exec("DELETE FROM analysis_size_fixture").Error; err != nil {
					t.Fatal("clear synthetic size rows")
				}
				type row struct{ Payload []byte }
				rows := make([]row, tc.rows)
				for i := range rows {
					rows[i].Payload = bytes.Repeat([]byte{1}, tc.bytes)
				}
				if err := s.db.Table("analysis_size_fixture").CreateInBatches(rows, 100).Error; err != nil {
					t.Fatal("insert synthetic bounded size rows")
				}
				err := analysisBoundedRowSizes(s.db.Table("analysis_size_fixture"), s.driver, "payload", 450, 8<<20, MaxAttemptDerivedBytes)
				if !errors.Is(err, tc.want) {
					t.Fatal("SQL byte guard accepted an oversized source", err)
				}
			})
		}
	})
}

func TestAnalysisDerivedPostgresS1LocksPersistUntilCommitOrCancel(t *testing.T) {
	for _, mode := range []string{"update", "delete", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
				if cfg.Driver != "postgres" {
					return // PostgreSQL row-lock proof; SQLite uses BEGIN IMMEDIATE.
				}
				tenant, queue, run, samples, lease := derivedAnalysisReady(t, s, false, false)
				source, err := queue.LoadRunAnalysis(tenant.ctx, lease)
				if err != nil {
					t.Fatal("read S1 for final-lock proof")
				}
				ctx, cancel := context.WithTimeout(tenant.ctx, 10*time.Second)
				defer cancel()
				publishCtx, cancelPublication := context.WithCancel(ctx)
				defer cancelPublication()
				gate, entered := make(chan struct{}), make(chan int, 1)
				const callback = "analysis_derived_after_final_digest"
				if err := s.db.Callback().Create().Before("gorm:create").Register(callback, func(tx *gorm.DB) {
					if tx.Statement.Table != "integrity_run_results" {
						return
					}
					var pid int
					if err := tx.Session(&gorm.Session{NewDB: true}).Raw("SELECT pg_backend_pid()").Scan(&pid).Error; err != nil {
						_ = tx.AddError(ErrUnavailable)
						return
					}
					entered <- pid
					select {
					case <-gate:
					case <-tx.Statement.Context.Done():
						_ = tx.AddError(tx.Statement.Context.Err())
					}
				}); err != nil {
					t.Fatal("install post-digest publication barrier")
				}
				t.Cleanup(func() { _ = s.db.Callback().Create().Remove(callback) })
				publication := analysisPublicationFixture(t, run, samples)
				published := make(chan error, 1)
				go func() {
					published <- queue.CompleteWith(publishCtx, lease, func(tx *TenantTransaction) error { return tx.PublishRunAnalysis(source, publication) })
				}()
				var publisherPID int
				select {
				case publisherPID = <-entered:
				case <-published:
					t.Fatal("publication failed before final-digest barrier")
				case <-ctx.Done():
					t.Fatal("publication did not reach final-digest barrier")
				}
				other, err := Open(ctx, cfg)
				if err != nil {
					t.Fatal("open independent S1 mutator")
				}
				defer func() { _ = other.Close() }()
				writers, written := make(chan int, 1), make(chan error, 1)
				go func() {
					written <- other.db.WithContext(ctx).Connection(func(db *gorm.DB) error {
						var pid int
						if err := db.Raw("SELECT pg_backend_pid()").Scan(&pid).Error; err != nil {
							return ErrUnavailable
						}
						writers <- pid
						query := db.Where("organization_id = ? AND attempt_id = ?", tenant.orgID, *samples[0].FinalAttemptID)
						if mode == "delete" {
							return query.Delete(&AttemptDerivedRecord{}).Error
						}
						return query.Model(&AttemptDerivedRecord{}).Update("payload", []byte("post-publication-only-change")).Error
					})
				}()
				var writerPID int
				select {
				case writerPID = <-writers:
				case <-written:
					t.Fatal("independent S1 writer failed to start")
				case <-ctx.Done():
					t.Fatal("independent S1 writer did not start")
				}
				if writerPID == publisherPID || writerPID <= 0 || publisherPID <= 0 {
					t.Fatal("final-lock proof did not use independent connections")
				}
				ticker := time.NewTicker(5 * time.Millisecond)
				defer ticker.Stop()
				for {
					var blocked bool
					if err := s.db.WithContext(ctx).Raw("SELECT ? = ANY(pg_blocking_pids(?))", publisherPID, writerPID).Scan(&blocked).Error; err != nil {
						t.Fatal("observe final S1 lock wait")
					}
					if blocked {
						break
					}
					select {
					case <-written:
						t.Fatal("S1 changed after final digest before publication settled")
					case <-ctx.Done():
						t.Fatal("actual S1 writer blocking was not observed")
					case <-ticker.C:
					}
				}
				t.Log("observed independent S1 writer blocked by publication after final digest")
				if mode == "cancel" {
					cancelPublication()
				} else {
					close(gate)
				}
				select {
				case err := <-published:
					if (mode == "cancel") != (err != nil) {
						t.Fatal("unexpected publication settlement at S1 barrier")
					}
				case <-ctx.Done():
					t.Fatal("publication did not settle or release S1 locks")
				}
				select {
				case err := <-written:
					if err != nil {
						t.Fatal("S1 locks were not released on commit/cancel")
					}
				case <-ctx.Done():
					t.Fatal("S1 writer remained blocked after publication settled")
				}
				var count int64
				if err := s.db.Model(&RunResultRecord{}).Count(&count).Error; err != nil || (mode == "cancel" && count != 0) || (mode != "cancel" && count != 1) {
					t.Fatal("publication rows disagree with final commit/cancel")
				}
			})
		})
	}
}
