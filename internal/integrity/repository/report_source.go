package repository

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"time"

	"gorm.io/gorm"
)

// ReportScope is minted from the persisted report, never request-supplied actor
// metadata. A queued export survives logout, but not creator disable/revocation.
type ReportScope struct {
	ReportID, OrganizationID, RunID, CreatedBy int64
	AnalysisRevision                           int
	Format                                     string
	GeneratedAt                                time.Time
}
type ReportSource struct {
	store                  *Store
	jobID, reportID, orgID int64
	generation             int
	scope                  ReportScope
	data                   PublishedRead
	frozen                 []byte
	frozenHash             string
}

func (*ReportSource) String() string               { return "[protected report job source]" }
func (s *ReportSource) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }
func (*ReportSource) MarshalJSON() ([]byte, error) { return nil, ErrReportInvalid }
func (s *ReportSource) LogValue() slog.Value       { return slog.StringValue(s.String()) }
func (s *ReportSource) Scope() ReportScope {
	if s == nil {
		return ReportScope{}
	}
	return s.scope
}
func (s *ReportSource) Use(fn func(PublishedRead, []byte) error) error {
	if s == nil || s.store == nil || fn == nil {
		return ErrReportInvalid
	}
	return fn(s.data, append([]byte(nil), s.frozen...))
}

func reportSnapshotTransaction(ctx context.Context, store *Store, read func(*gorm.DB) error) error {
	if store.driver == "postgres" {
		return store.db.WithContext(ctx).Transaction(read, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	}
	return store.db.WithContext(ctx).Connection(func(conn *gorm.DB) error {
		conn = conn.Session(&gorm.Session{NewDB: true})
		if err := conn.Exec("BEGIN DEFERRED").Error; err != nil {
			return err
		}
		committed := false
		defer func() {
			if !committed {
				cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
				defer cancel()
				_ = conn.WithContext(cleanup).Exec("ROLLBACK").Error
			}
		}()
		if err := read(conn); err != nil {
			return err
		}
		if err := conn.Exec("COMMIT").Error; err != nil {
			return err
		}
		committed = true
		return nil
	})
}

// LoadReportSource performs ONE bounded consistent read, under the existing
// consumer/job-generation fence. It never calls per-sample service readers.
func (q *JobQueue) LoadReportSource(ctx context.Context, lease JobLease) (*ReportSource, error) {
	if q == nil || q.store == nil || JobType(lease.Job.Type) != JobReportGenerate {
		return nil, ErrJobInvalid
	}
	var source *ReportSource
	err := reportSnapshotTransaction(ctx, q.store, func(tx *gorm.DB) error {
		now, err := queueTime(tx, q.store.driver)
		if err != nil {
			return err
		}
		if err := q.guardConsumer(tx, now, false); err != nil {
			return err
		}
		var count int64
		if err := q.fenced(tx, lease, now).Count(&count).Error; err != nil {
			return err
		}
		if count != 1 {
			return ErrJobLeaseLost
		}
		var job Job
		if err := tx.Select("id,organization_id,object_id,"+readBoundedText(tx, "type", "type", 64)+","+readBoundedText(tx, "idempotency_key", "idempotency_key", 128)).Where("organization_id=? AND id=?", lease.Job.OrganizationID, lease.Job.ID).Take(&job).Error; err != nil {
			return err
		}
		if job.Type != string(JobReportGenerate) || job.ObjectID != lease.Job.ObjectID || job.IdempotencyKey != "report:"+strconv.FormatInt(job.ObjectID, 10) {
			return ErrJobInvalid
		}
		row, err := reportRow(tx, job.OrganizationID, job.ObjectID)
		if err != nil {
			return err
		}
		if *row.JobID != job.ID || row.Status != "queued" && row.Status != "generating" {
			return ErrReportInvalid
		}
		if err := reportPermissions(tx, row.OrganizationID, *row.CreatedBy); err != nil {
			return err
		}
		source = &ReportSource{store: q.store, orgID: row.OrganizationID, reportID: row.ID, jobID: job.ID, generation: lease.Generation, scope: ReportScope{row.ID, row.OrganizationID, row.RunID, *row.CreatedBy, row.AnalysisRevision, row.FormatName, row.CreatedAt}}
		var frozen struct{ SourceJSON *string }
		if err := tx.Model(&ReportRecord{}).Select(readBoundedText(tx, "source_json", "source_json", reportInputLimit)).Where("organization_id=? AND id=?", row.OrganizationID, row.ID).Take(&frozen).Error; err != nil {
			return err
		}
		if frozen.SourceJSON != nil {
			if len(*frozen.SourceJSON) == 0 || row.SourceHash == nil || reportDigest([]byte(*frozen.SourceJSON)) != *row.SourceHash || row.FrozenAt == nil {
				return ErrReportInvalid
			}
			source.frozen = []byte(*frozen.SourceJSON)
			source.frozenHash = *row.SourceHash
			return nil
		}
		if row.SourceHash != nil || row.FrozenAt != nil {
			return ErrReportInvalid
		}
		source.data, err = readReportPublished(tx, row.OrganizationID, row.RunID, row.AnalysisRevision)
		return err
	})
	if err != nil {
		return nil, reportError(err)
	}
	return source, nil
}

func readReportPublished(tx *gorm.DB, org, runID int64, revision int) (PublishedRead, error) {
	out := PublishedRead{Samples: []ResultSampleRecord{}, Findings: []FindingRecord{}, Attempts: []ResultAttemptRecord{}}
	if err := historyQuery(tx, org).Where("r.id=?", runID).Take(&out.Run).Error; err != nil {
		return out, err
	}
	columns := `organization_id,run_id,analysis_revision,prompt_risk,token_risk,response_risk,evidence_risk,overall_risk,confidence,is_published,created_at,` + readBoundedText(tx, "conclusion_json", "conclusion_json", 4<<20)
	for _, f := range []struct {
		name  string
		limit int
	}{{"risk_level", 64}, {"evidence_grade", 1}, {"completeness", 16}} {
		columns += "," + readBoundedText(tx, f.name, f.name, f.limit)
	}
	if err := tx.Select(columns).Where("organization_id=? AND run_id=? AND analysis_revision=? AND is_published=?", org, runID, revision, true).Take(&out.Result).Error; err != nil {
		return out, err
	}
	if out.Result.ConclusionJSON == "" {
		return out, ErrResultDocument
	}
	if err := tx.Table("integrity_logical_samples").Select("id,organization_id,run_id,probe_instance_id,ordinal,attempt_count,final_attempt_id,completed_at,"+readBoundedText(tx, "validity", "validity", 32)).Where("organization_id=? AND run_id=?", org, runID).Order("ordinal,id").Limit(513).Scan(&out.Samples).Error; err != nil {
		return out, err
	}
	if len(out.Samples) > 512 || len(out.Samples) == 0 {
		return out, ErrResultDocument
	}
	query := tx.Model(&FindingRecord{}).Where("organization_id=? AND run_id=? AND analysis_revision=?", org, runID, revision)
	for _, field := range []string{"statistics_json", "alternative_explanations", "sample_refs"} {
		if err := analysisBoundedRows(query, tx.Name(), field, 256, 1<<20); err != nil {
			return out, ErrResultDocument
		}
	}
	columns = "id,organization_id,run_id,analysis_revision,risk_score,confidence,created_at"
	for _, f := range []struct {
		name  string
		limit int
	}{{"category", 32}, {"type", 64}, {"severity", 16}, {"evidence_grade", 1}, {"rule_id", 128}, {"rule_version", 128}, {"statistics_json", 65536}, {"alternative_explanations", 65536}, {"sample_refs", 65536}} {
		columns += "," + readBoundedText(tx, f.name, f.name, f.limit)
	}
	if err := query.Select(columns).Order("id").Limit(257).Find(&out.Findings).Error; err != nil {
		return out, err
	}
	if len(out.Findings) > 256 {
		return out, ErrResultDocument
	}
	columns = "id,organization_id,run_id,logical_sample_id,attempt_no,http_status,prompt_tokens,completion_tokens,total_tokens,local_completion_tokens,duration_ms,started_at,finished_at"
	for _, f := range []struct {
		name  string
		limit int
	}{{"status", 32}, {"validity", 32}, {"error_code", 128}} {
		columns += "," + readBoundedText(tx, f.name, f.name, f.limit)
	}
	if err := tx.Table("integrity_sample_attempts").Select(columns).Where("organization_id=? AND run_id=?", org, runID).Order("logical_sample_id,attempt_no").Limit(1537).Scan(&out.Attempts).Error; err != nil {
		return out, err
	}
	if len(out.Attempts) > 1536 {
		return out, ErrResultDocument
	}
	return out, nil
}

// FreezeReportSource persists the validated S1 projection before filesystem
// effects. Only the exact leased source receipt can freeze its report.
func (q *JobQueue) FreezeReportSource(ctx context.Context, lease JobLease, source *ReportSource, encoded []byte) error {
	if q == nil || source == nil || source.store != q.store || source.jobID != lease.Job.ID || source.generation != lease.Generation || len(encoded) < 2 || len(encoded) > reportInputLimit {
		return ErrReportInvalid
	}
	hash := reportDigest(encoded)
	if len(source.frozen) > 0 && hash != source.frozenHash {
		return ErrReportInvalid
	}
	var businessErr error
	err := q.WithLease(ctx, lease, func(tx *TenantTransaction) error {
		businessErr = tx.freezeReportSource(source, encoded, hash)
		return businessErr
	})
	if businessErr != nil {
		return reportError(businessErr)
	}
	return reportError(err)
}
func (tx *TenantTransaction) reportLease(source *ReportSource) (ReportRecord, error) {
	if source == nil || source.store != tx.store || source.orgID != tx.orgID || source.jobID != tx.leaseJobID || source.generation != tx.leaseGeneration {
		return ReportRecord{}, ErrReportInvalid
	}
	job, err := tx.executionJob(JobReportGenerate, source.reportID, tx.completing)
	if err != nil {
		return ReportRecord{}, err
	}
	if job.IdempotencyKey != "report:"+strconv.FormatInt(source.reportID, 10) {
		return ReportRecord{}, ErrJobInvalid
	}
	row, err := reportRow(tx.db, tx.orgID, source.reportID)
	if err != nil {
		return row, err
	}
	if *row.JobID != job.ID || *row.CreatedBy != source.scope.CreatedBy || row.RunID != source.scope.RunID || row.AnalysisRevision != source.scope.AnalysisRevision || row.FormatName != source.scope.Format || !row.CreatedAt.Equal(source.scope.GeneratedAt) {
		return row, ErrReportInvalid
	}
	// Serialize final authorization with all current membership/role mutations.
	if tx.store.driver == "postgres" {
		if err := tx.db.Exec("SELECT pg_advisory_xact_lock(?)", migrationLockID+100).Error; err != nil {
			return row, err
		}
	}
	if err := reportPermissions(tx.db, tx.orgID, *row.CreatedBy); err != nil {
		return row, err
	}
	return row, nil
}
func (tx *TenantTransaction) freezeReportSource(source *ReportSource, encoded []byte, hash string) error {
	row, err := tx.reportLease(source)
	if err != nil {
		return err
	}
	if row.Status != "queued" && row.Status != "generating" {
		return ErrReportInvalid
	}
	if row.SourceHash != nil {
		if *row.SourceHash != hash {
			return ErrReportInvalid
		}
		return nil
	}
	now, err := queueTime(tx.db, tx.store.driver)
	if err != nil {
		return err
	}
	if err := tx.db.Model(&ReportRecord{}).Where("organization_id=? AND id=? AND source_json IS NULL", tx.orgID, row.ID).Updates(map[string]any{"source_json": string(encoded), "source_hash": hash, "frozen_at": now, "status": "generating"}).Error; err != nil {
		return err
	}
	return tx.store.appendAudit(tx.ctx, tx.db, tx.orgID, auditObject("report.freeze", "report", row.ID), nil)
}

type ReportPublication struct {
	ContentHash, FileHash string
	FileSize              int64
}

func (tx *TenantTransaction) PublishReport(source *ReportSource, inputHash string, p ReportPublication) error {
	if !tx.completing || !executionHash.MatchString(inputHash) || len(p.ContentHash) != 71 || p.ContentHash[:7] != "sha256:" || !executionHash.MatchString(p.ContentHash[7:]) || !executionHash.MatchString(p.FileHash) || p.FileSize < 1 || p.FileSize > reportFileLimit {
		return ErrReportInvalid
	}
	row, err := tx.reportLease(source)
	if err != nil {
		return err
	}
	if row.Status != "generating" || row.SourceHash == nil || *row.SourceHash != inputHash {
		return ErrReportInvalid
	}
	now, err := queueTime(tx.db, tx.store.driver)
	if err != nil {
		return err
	}
	if err := tx.db.Model(&ReportRecord{}).Where("organization_id=? AND id=? AND status='generating'", tx.orgID, row.ID).Updates(map[string]any{"status": "ready", "content_hash": p.ContentHash, "file_hash": p.FileHash, "file_size": p.FileSize, "storage_path": ReportObjectName(tx.orgID, p.FileHash, row.FormatName), "completed_at": now, "error_code": nil}).Error; err != nil {
		return err
	}
	return tx.store.appendAudit(tx.ctx, tx.db, tx.orgID, auditObject("report.publish", "report", row.ID), nil)
}
