package repository

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

func backupDomainPreservationProof(t *testing.T, s *Store, kind JobType, id int64) func(time.Time) {
	t.Helper()
	switch kind {
	case JobRunAnalyze:
		var before RunRecord
		if err := s.db.First(&before, id).Error; err != nil {
			t.Fatal(err)
		}
		return func(stamp time.Time) {
			var after RunRecord
			if err := s.db.First(&after, id).Error; err != nil || after.Status != "FAILED" || after.Version != before.Version+1 || after.ErrorSummary == nil || *after.ErrorSummary != "MI_ANALYSIS_FAILED" || after.FinishedAt == nil || !after.FinishedAt.Equal(stamp) {
				t.Fatal("analysis did not preserve original failure projection", err)
			}
			after.Status, after.Version, after.ErrorSummary, after.FinishedAt = before.Status, before.Version, before.ErrorSummary, before.FinishedAt
			if !reflect.DeepEqual(before, after) {
				t.Fatal("analysis changed unrelated original fields")
			}
		}
	case JobReportGenerate:
		var before ReportRecord
		if err := s.db.First(&before, id).Error; err != nil {
			t.Fatal(err)
		}
		return func(stamp time.Time) {
			var after ReportRecord
			if err := s.db.First(&after, id).Error; err != nil || after.Status != "failed" || after.ErrorCode == nil || *after.ErrorCode != "MI_REPORT_GENERATION_FAILED" || after.CompletedAt == nil || !after.CompletedAt.Equal(stamp) {
				t.Fatal("report did not preserve original failure projection", err)
			}
			after.Status, after.ErrorCode, after.CompletedAt = before.Status, before.ErrorCode, before.CompletedAt
			if !reflect.DeepEqual(before, after) {
				t.Fatal("report changed frozen source or other original fields")
			}
		}
	default:
		var before PrecheckRecord
		if err := s.db.First(&before, id).Error; err != nil {
			t.Fatal(err)
		}
		return func(stamp time.Time) {
			var after PrecheckRecord
			if err := s.db.First(&after, id).Error; err != nil || after.Status != "failed" || after.Version != before.Version+1 || after.ErrorCode != "MI_UNCERTAIN_ATTEMPT" || after.ResultJSON != "[]" || after.FinishedAt == nil || !after.FinishedAt.Equal(stamp) {
				t.Fatal("precheck did not preserve original failure projection", err)
			}
			after.Status, after.Version, after.ErrorCode, after.ResultJSON, after.FinishedAt = before.Status, before.Version, before.ErrorCode, before.ResultJSON, before.FinishedAt
			if !reflect.DeepEqual(before, after) {
				t.Fatal("precheck changed request count/start time/original fields")
			}
		}
	}
}

func TestBackupDomainAnalysisBindingAndPublishedPreservation(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		_, queue, run, samples, lease := analysisReadyFixture(t, s, 1)
		source, err := queue.LoadRunAnalysis(t.Context(), lease)
		if err != nil {
			t.Fatal(err)
		}
		publication := analysisPublicationFixture(t, run, samples)
		if err := queue.CompleteWith(t.Context(), lease, func(tx *TenantTransaction) error { return tx.PublishRunAnalysis(source, publication) }); err != nil {
			t.Fatal(err)
		}
		job := lease.Job
		job.Status = "failed"
		// A synthetic contradictory terminal-job input to the private core is
		// not a valid maintenance source. It must never downgrade real results.
		before := backupDomainRows(t, s)
		err = s.db.WithContext(t.Context()).Transaction(func(db *gorm.DB) error {
			now, err := queueTime(db, s.driver)
			if err != nil {
				return err
			}
			got, err := s.reconcileAnalysisDomain(db, job, now)
			if err != nil || got != domainProjectionNone {
				t.Fatal("published completed Run was downgraded", got, err)
			}
			return nil
		})
		if err != nil || !reflect.DeepEqual(before, backupDomainRows(t, s)) {
			t.Fatal("completed analysis facts changed", err)
		}
		// Real retained publication + contradictory ANALYZING is corruption,
		// not permission to overwrite the publication with a failure summary.
		if err := s.db.Model(&RunRecord{}).Where("id=?", run.ID).UpdateColumn("status", "ANALYZING").Error; err != nil {
			t.Fatal(err)
		}
		before = backupDomainRows(t, s)
		for _, variant := range []string{"published", "wrong-key", "other-organization"} {
			t.Run(variant, func(t *testing.T) {
				candidate := job
				switch variant {
				case "wrong-key":
					candidate.IdempotencyKey = "unrelated-key"
				case "other-organization":
					candidate.OrganizationID++
				}
				var got domainProjectionResult
				err := s.db.WithContext(t.Context()).Transaction(func(db *gorm.DB) error {
					now, err := queueTime(db, s.driver)
					if err != nil {
						return err
					}
					got, err = s.reconcileAnalysisDomain(db, candidate, now)
					return err
				})
				if variant == "published" && (!errors.Is(err, ErrAnalysisSource) || got != "") || variant == "wrong-key" && (err != nil || got != domainProjectionNone) || variant == "other-organization" && (err == nil || got != "") || !reflect.DeepEqual(before, backupDomainRows(t, s)) {
					t.Fatal("analysis binding/publication boundary changed", got, err)
				}
			})
		}
	})
}

func TestBackupDomainReportBindingAndReadyPreservation(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		fixture := newBackupDomainFixture(t, s, JobReportGenerate, 0)
		job := fixture.lease.Job
		job.Status = "failed"
		for _, variant := range []string{"wrong-key", "other-organization", "wrong-job-pointer"} {
			t.Run(variant, func(t *testing.T) {
				candidate := job
				switch variant {
				case "wrong-key":
					candidate.IdempotencyKey = "unrelated-key"
				case "other-organization":
					candidate.OrganizationID++
				case "wrong-job-pointer":
					candidate.ID++
				}
				before := backupDomainRows(t, s)
				err := s.db.WithContext(t.Context()).Transaction(func(db *gorm.DB) error {
					now, err := queueTime(db, s.driver)
					if err != nil {
						return err
					}
					got, err := s.reconcileReportDomain(db, candidate, now)
					if err != nil || got != domainProjectionNone {
						t.Fatal("wrong report binding acquired projection", got, err)
					}
					return nil
				})
				if err != nil || !reflect.DeepEqual(before, backupDomainRows(t, s)) {
					t.Fatal("wrong report binding changed facts", err)
				}
			})
		}
		source, err := fixture.queue.LoadReportSource(t.Context(), fixture.lease)
		if err != nil {
			t.Fatal(err)
		}
		encoded := []byte(`{"synthetic_s1":true}`)
		publication := ReportPublication{ContentHash: "sha256:" + strings.Repeat("a", 64), FileHash: strings.Repeat("b", 64), FileSize: 128}
		if err := fixture.queue.CompleteWith(t.Context(), fixture.lease, func(tx *TenantTransaction) error { return tx.PublishReport(source, reportDigest(encoded), publication) }); err != nil {
			t.Fatal(err)
		}
		before := backupDomainRows(t, s)
		got, _, err := backupDomainTransaction(fixture, t.Context(), false, "failed", "JOB_TEST")
		if err != nil || got != domainProjectionNone || !reflect.DeepEqual(before, backupDomainRows(t, s)) {
			t.Fatal("ready report was downgraded by contradictory terminal input", got, err)
		}
	})
}

func TestBackupDomainPrecheckMissingBindingIsNoProjection(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		fixture := newBackupDomainFixture(t, s, JobTargetPrecheck, 1)
		before := backupDomainRows(t, s)
		for _, field := range []string{"job", "organization", "object", "non-precheck"} {
			candidate := fixture.lease.Job
			switch field {
			case "job":
				candidate.ID++
			case "organization":
				candidate.OrganizationID++
			case "object":
				candidate.ObjectID++
			case "non-precheck":
				candidate.Type = string(JobRetentionDelete)
			}
			err := s.db.WithContext(t.Context()).Transaction(func(db *gorm.DB) error {
				now, err := queueTime(db, s.driver)
				if err != nil {
					return err
				}
				got, err := s.reconcilePrecheckDomain(db, candidate, "failed", "JOB_ATTEMPTS_EXHAUSTED", now)
				if err != nil || got != domainProjectionNone {
					t.Fatal("unmatched precheck was not original no-op", field, got, err)
				}
				return nil
			})
			if err != nil || !reflect.DeepEqual(before, backupDomainRows(t, s)) {
				t.Fatal("unmatched precheck changed original facts", err)
			}
		}
	})
}

func TestBackupDomainReadsOnlyFixedMetadata(t *testing.T) {
	backupDomainMetadataOnly(t, JobRunAnalyze, "integrity_runs", "config_snapshot")
}

func TestBackupDomainPrecheckReadsOnlyFixedMetadata(t *testing.T) {
	backupDomainMetadataOnly(t, JobTargetPrecheck, "integrity_target_prechecks", "snapshot_json")
}

func backupDomainMetadataOnly(t *testing.T, kind JobType, table, bodyColumn string) {
	t.Helper()
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		fixture := newBackupDomainFixture(t, s, kind, 0)
		if err := s.db.Table(table).Where("id=?", fixture.lease.Job.ObjectID).UpdateColumn(bodyColumn, strings.Repeat("invalid-opaque-original", 10000)).Error; err != nil {
			t.Fatal(err)
		}
		const callback = "backup_domain_reject_body_projection"
		reads := 0
		if err := s.db.Callback().Query().Before("gorm:query").Register(callback, func(db *gorm.DB) {
			if db.Statement.Table != table {
				return
			}
			reads++
			selected := strings.Join(db.Statement.Selects, ",")
			if selected == "" || strings.Contains(selected, bodyColumn) || strings.Contains(selected, "result_json") || strings.Contains(selected, "manifest_json") || strings.Contains(selected, "*") {
				_ = db.AddError(errors.New("fixed-body-projection-denied"))
			}
		}); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.db.Callback().Query().Remove(callback) }()
		got, _, err := backupDomainTransaction(fixture, t.Context(), true, "failed", "JOB_TEST")
		if err != nil || got != domainProjectionApplied || reads == 0 {
			t.Fatal("opaque original body was read/parsed to record failure", got, err)
		}
	})
}
